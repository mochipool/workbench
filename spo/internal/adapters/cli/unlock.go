package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// useFactors decides, from the slot table alone (no key), whether this command
// unlocks through FIDO2 factors, and refuses before any prompt when it must and
// the binary cannot reach a factor source (ADR 0008 capability typing).
func (a *app) useFactors() (bool, error) { return a.useFactorsFor(a.workspaceFile()) }

// useFactorsFor is useFactors for the workspace or backup file at path: the
// file's own slot table decides.
func (a *app) useFactorsFor(path string) (bool, error) {
	switch a.unlock {
	case "", "passphrase", "fido2", "recovery-composite":
	default:
		return false, fmt.Errorf("--unlock %q: use passphrase, fido2 or recovery-composite", a.unlock)
	}
	if a.d.Sealed.Describe == nil {
		if a.unlock == "fido2" || a.unlock == "recovery-composite" {
			return false, errors.New("--unlock fido2 is not available in this build")
		}
		return false, nil
	}
	info, err := a.d.Sealed.Describe(path)
	if err != nil {
		return false, err
	}
	hasPass := false
	for _, s := range info.Slots {
		if s.Kind == "passphrase" {
			hasPass = true
		}
	}
	want := a.unlock == "fido2" || a.unlock == "recovery-composite" || (a.unlock == "" && !hasPass)
	if a.unlock == "passphrase" && !hasPass {
		return false, fmt.Errorf("this workspace has the policy %s and no passphrase slot: nothing opens from a passphrase alone; use --unlock fido2", info.Policy)
	}
	if want && a.d.Factors == nil {
		return false, errors.New("this workspace unlocks through a FIDO2 authenticator, and this binary has no FIDO2 factor source (the libfido2 tools fido2-token, fido2-cred and fido2-assert must be in the toolchain manifest): nothing was asked")
	}
	return want, nil
}

// destroyPINs wipes every authenticator PIN this command read.
func (a *app) destroyPINs() {
	a.destroyCold()
	if a.recText != nil {
		a.recText.Destroy()
		a.recText = nil
	}
	for k, p := range a.pins {
		p.Destroy()
		delete(a.pins, k)
	}
}

// pinCallback returns the PIN callback of one authenticator role. The PIN is read
// once per command and role: from fd when it is >= 0, else from a prompt that
// names the device and the role (an empty answer means "no PIN": the
// authenticator verifies the user itself). The PIN is held in guarded memory in
// a.pins; every call returns a fresh copy that the caller destroys. fresh makes
// a prompt (no descriptor) ask again every time instead of using the held PIN:
// the re-authentication before a signature, which never takes a PIN from a
// descriptor: a PIN that was given on --fido2-pin-fd at start does not satisfy a
// fresh presentation, so the gate needs a terminal.
func (a *app) pinCallback(role string, device func() string, fd func() int, fresh bool) func(ctx context.Context) (*secret.Buffer, error) {
	return func(ctx context.Context) (*secret.Buffer, error) {
		if a.pins == nil {
			a.pins = map[string]*secret.Buffer{}
		}
		held, have := a.pins[role]
		if have && fresh {
			held.Destroy()
			delete(a.pins, role)
			have = false
		}
		if !have {
			var p *secret.Buffer
			var err error
			if f := fd(); f >= 0 && !fresh {
				what := "the authenticator PIN"
				if role == "recovery" {
					what = "the recovery authenticator PIN"
				}
				p, err = readFDSecret(f, what)
			} else {
				dev := device()
				if dev == "" {
					dev = "the only connected authenticator"
				}
				p, err = a.term.ReadSecret(ctx, fmt.Sprintf("PIN of the %s authenticator (%s; empty if it has none): ", role, dev))
				if errors.Is(err, ErrNoTerminal) {
					flag := "--fido2-pin-fd N"
					switch role {
					case "recovery":
						flag = "--recovery-pin-fd N"
					case "new-daily":
						flag = "--new-fido2-pin-fd N"
					case "checkpoint":
						flag = "--checkpoint-pin-fd N"
					case "old-checkpoint":
						flag = "--old-checkpoint-pin-fd N"
					}
					return nil, fmt.Errorf("no terminal to ask for the %s authenticator PIN on; give it on a file descriptor with %s", role, flag)
				}
			}
			if err != nil {
				return nil, err
			}
			if p.Len() == 0 {
				p.Destroy()
				p = nil
			}
			a.pins[role] = p
			held = p
		}
		if held == nil {
			return nil, nil
		}
		return secret.Fill(held.Len(), func(dst []byte) error {
			return held.Use(func(b []byte) error { copy(dst, b); return nil })
		})
	}
}

// factorOpen is what this command can present to the slots: the daily
// authenticator named by --fido2-device with the PIN of --fido2-pin-fd.
func (a *app) factorOpen() FactorOpen { return a.factorOpenFor(false) }

func (a *app) factorOpenFor(fresh bool) FactorOpen {
	return FactorOpen{
		Source: a.d.Factors, Device: a.fido2Device,
		PIN:        a.pinCallback("daily", func() string { return a.fido2Device }, func() int { return a.fido2PinFD }, fresh),
		Passphrase: a.factorPassphrase(),
		Recovery:   a.factorRecovery(),
		Notify:     func(m string) { fmt.Fprintln(a.d.Err, m) },
	}
}

// reauthOpen is what the approval gate presents of a factor session: the daily
// authenticator again, with a PIN prompt of its own when the PIN did not come on
// a descriptor.
func (a *app) reauthOpen() FactorOpen { return a.factorOpenFor(true) }

func (a *app) workspaceSlotCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "slot",
		Short: "The unlock slots of the workspace (ADR 0011)",
	}
	c.AddCommand(a.slotList(), a.slotAddFIDO2(), a.slotRemove())
	return c
}

func slotDetail(s Slot) string {
	d := ""
	for i, f := range s.Factors {
		if i > 0 {
			d += " + "
		}
		d += f
		if i < len(s.Touch) && s.Touch[i] != "" {
			d += " (" + s.Touch[i] + ")"
		}
	}
	if s.Legacy {
		d += " legacy (rekey to bind policy)"
	}
	return d
}

func (a *app) slotList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the policy and the slots (kinds, ids, factors; nothing secret)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.d.Sealed.Describe == nil {
				return errors.New("slot list is not available in this build")
			}
			if !exists(a.workspaceFile()) {
				return fmt.Errorf("no workspace in %s", a.workspace)
			}
			info, err := a.d.Sealed.Describe(a.workspaceFile())
			if err != nil {
				return err
			}
			w := a.d.Out
			fmt.Fprintf(w, "policy: %s\n", info.Policy)
			for _, s := range info.Slots {
				fmt.Fprintf(w, "%-10s %x  %s\n", s.Kind, s.ID, slotDetail(s))
			}
			if info.Policy == "standard" {
				fmt.Fprintln(w, "note: under standard a passphrase slot and a recovery slot open the workspace alone, so a FIDO2 slot is a convenience, not a strengthening. Keep a standard workspace on this machine.")
			}
			return nil
		},
	}
}

func (a *app) slotAddFIDO2() *cobra.Command {
	return &cobra.Command{
		Use:   "add-fido2",
		Short: "Enrol an authenticator and add a fido2-hmac slot (--fido2-device, --fido2-pin-fd)",
		Long: `Opens the workspace with its current factors, makes a FIDO2 credential on the
authenticator (credProtect 3, hmac-secret, user verification) and wraps the
workspace key under it. Under standard this is a convenience, not a
strengthening. A workspace migrated from format 2 needs a rekey first (it binds no
recovery public key yet). Removing a slot is a rotation: spo workspace rotate.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if a.d.Factors == nil {
				return errors.New("this binary has no FIDO2 factor source (the libfido2 tools are not in the toolchain manifest): nothing was asked")
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			adm, ok := s.Sealed.(SlotAdmin)
			if !ok {
				return errors.New("this workspace handle cannot change its slots")
			}
			id, err := adm.AddFIDO2Slot(cmd.Context(), a.factorOpen())
			if err != nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "added fido2-hmac slot %x\n", id)
			return nil
		},
	}
}

var _ = ports.NeedsOfSlot

func (a *app) workspacePolicyCommand() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "The unlock policy (standard, hardware or strict); a change is a rotation: spo workspace rotate"}
	c.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Print the unlock policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.d.Sealed.Describe == nil || !exists(a.workspaceFile()) {
				return errors.New("no workspace here, or this build cannot read one")
			}
			info, err := a.d.Sealed.Describe(a.workspaceFile())
			if err != nil {
				return err
			}
			fmt.Fprintln(a.d.Out, info.Policy)
			return nil
		},
	}, a.workspacePolicySet())
	return c
}

func (a *app) workspaceRotateCommand() *cobra.Command {
	var policy, recDevice, curRecDevice, newDevice, keepCopy string
	var yes bool
	var yesRemove, leave []string
	rkFD, recPinFD, curRecPinFD, recKeyInFD, newPinFD, newPassFD := -1, -1, -1, -1, -1, -1
	cmd := &cobra.Command{
		Use:   "rotate --policy standard|hardware|strict [--recovery-device PATH]",
		Short: "Replace the workspace key and every data key, and write a new slot table under a policy",
		Long: `Rotation draws a new workspace key and a fresh data key for every record,
re-encrypts every payload, writes the slot table of the chosen policy and commits
in one transaction. It is how a slot or factor is removed and how the policy
changes. It makes no copy of the file: a copy opens with the credentials the
rotation revokes. --keep-copy FILE makes one on request (never overwriting a
file, mode 0600); it is removed again when the rotation fails, and you destroy it
yourself once the new factors are confirmed.

A rotation of a workspace that has a recovery path (standard or hardware)
replaces the recovery key, so it first asks for the CURRENT recovery credential
(the recovery key, from --recovery-key-in-fd or a prompt, and under hardware the
recovery authenticator --current-recovery-device, default --recovery-device, with
its PIN from --old-recovery-pin-fd or --recovery-pin-fd) and checks it
against the recovery public key hash bound in the slots. The daily credential
alone cannot rotate. A strict workspace has no recovery path, needs none, and
cannot be rotated to a weaker policy.

  standard  a new passphrase (asked twice) and a new recovery key.
  hardware  the new daily authenticator in a fido2-hmac slot (--new-fido2-device,
            default --fido2-device; its PIN from --new-fido2-pin-fd, or from
            --fido2-pin-fd when it is the session device) and a recovery
            composite: a new recovery key AND a second authenticator
            (--recovery-device, PIN from --recovery-pin-fd). Two authenticators
            are required, each with its own PIN (or a prompt for each, naming
            the device). Both PINs are checked before any credential is made on
            either.

Recovering after the daily authenticator is lost (hardware workspace): open the
session with the recovery composite and name a new daily authenticator,

  spo --unlock recovery-composite --fido2-device RECOVERY-DEVICE workspace rotate \
      --policy hardware --new-fido2-device NEW-DAILY --recovery-device NEW-RECOVERY

In that session --fido2-device is the CURRENT recovery authenticator (its PIN is
--fido2-pin-fd), --new-fido2-device is required, and the recovery key typed to
open the session is presented again as the proof. The lost authenticator's slot
is removed and nothing is enrolled on it.

Cold-role keys are sealed again under the new factor: through their recovery
wrap, with a check against their key identity, when the recovery credential is
present, and with the old cold factor otherwise. A cold record that neither can
open is NOT left behind: the rotation is refused with the record named, unless
you accept leaving it with --leave-unreachable KIND/LABEL (one per record,
recovery credential presented); it then keeps its old cold factor and
"spo store verify" lists it until it is re-established.
  strict    one authenticator and no recovery key at all: losing it loses the
            workspace. Needs --yes-strict.

What a rotation cannot delete: backups, snapshots, remnants on the medium and any
copy a removed party already holds. Hot keys (KES, VRF), tokens and party
identities that the removed factor could read must be rotated by you as well;
payment, stake and cold keys cannot be rotated without moving funds.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			switch policy {
			case "standard", "hardware", "strict":
			default:
				return errors.New("--policy is required: standard, hardware or strict")
			}
			if a.d.Sealed.Describe == nil {
				return errors.New("this build cannot read the slot table")
			}
			info, err := a.d.Sealed.Describe(a.workspaceFile())
			if err != nil {
				return err
			}
			if (policy != "standard" || info.Policy == "hardware") && a.d.Factors == nil {
				return errors.New("this binary has no FIDO2 factor source (the libfido2 tools are not in the toolchain manifest): nothing was asked")
			}
			if info.Policy == "strict" && policy != "strict" {
				return errors.New("a strict workspace has no recovery credential to authorise a weaker policy, and this tool does not loosen it: nothing was asked")
			}
			recSession := a.unlock == "recovery-composite"
			a.keepRecovery = recSession
			a.recoveryFD = recKeyInFD
			// The new daily authenticator: --new-fido2-device, else the session device. In a
			// recovery-composite session the session device is the recovery token, which is
			// never a daily authenticator, so it must be named.
			newDaily := newDevice
			if newDaily == "" && !recSession {
				newDaily = a.fido2Device
			}
			if policy != "standard" && recSession && newDaily == "" {
				return errors.New("in a recovery-composite session --fido2-device is the CURRENT recovery authenticator; name the new daily authenticator with --new-fido2-device (a device path as fido2-token -L prints it): nothing was asked")
			}
			if policy == "hardware" && recDevice == "" {
				return errors.New("hardware needs a second authenticator for the recovery composite: give --recovery-device (the device path of fido2-token -L), and --new-fido2-device (or --fido2-device) for the daily one")
			}
			if policy == "hardware" && recDevice == newDaily {
				return errors.New("the recovery authenticator must be a different device from the daily authenticator (the check is by device path and credential only: use two physically separate tokens)")
			}
			if policy == "strict" && !yes {
				return errors.New("strict has no recovery key: if the authenticator is lost the workspace is lost. Add --yes-strict to go on")
			}
			if info.Policy == "strict" {
				// One daily factor rewrites a strict table: every slot it replaces may be
				// another holder's authenticator, so each is named and confirmed.
				have := map[string]bool{}
				for _, id := range yesRemove {
					have[strings.ToLower(id)] = true
				}
				for _, sl := range info.Slots {
					fmt.Fprintf(a.d.Err, "warning: this rotation removes %s slot %x and every authenticator in it\n", sl.Kind, sl.ID)
					if !have[fmt.Sprintf("%x", sl.ID)] {
						return fmt.Errorf("a strict rotation removes every existing slot; confirm each with --yes-remove %x (slot %s). Nothing was changed", sl.ID, sl.Kind)
					}
				}
			}
			if info.Policy == "hardware" && recSession {
				// the session device is the recovery authenticator the proof presents
				if curRecDevice != "" && curRecDevice != a.fido2Device {
					return errors.New("in a recovery-composite session --fido2-device is the current recovery authenticator; --current-recovery-device must not name another")
				}
				curRecDevice = a.fido2Device
			}
			if info.Policy == "hardware" && curRecDevice == "" {
				curRecDevice = recDevice
			}
			if info.Policy == "hardware" && curRecDevice == "" {
				return errors.New("this workspace is under hardware: give --current-recovery-device (or --recovery-device), the authenticator of its recovery composite")
			}
			if info.Policy == "hardware" && !recSession && curRecDevice == a.fido2Device {
				return errors.New("the current recovery authenticator must be a different device from the daily authenticator")
			}
			if info.Policy == "hardware" && policy != "standard" && newDaily == curRecDevice {
				return errors.New("the new daily authenticator is the device of the current recovery composite: the recovery authenticator is kept apart from the daily one; name another device with --new-fido2-device")
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			adm, ok := s.Sealed.(SlotAdmin)
			if !ok {
				return errors.New("this workspace handle cannot change its slots")
			}
			req := RotateRequest{Policy: policy, Daily: a.factorOpen(), KeepCopy: keepCopy, YesRemove: yesRemove, ColdPassphrase: a.newColdPassphrase, LeaveUnreachable: leave}
			if newDaily != "" && (recSession || newDaily != a.fido2Device) {
				// a new daily authenticator other than the session device: its own device and PIN
				req.Daily.Device = newDaily
				req.Daily.PIN = a.pinCallback("new-daily", func() string { return newDaily }, func() int { return newPinFD }, false)
			}
			req.Recovery, req.CurrentRecovery = a.recoveryOpens(info.Policy, recDevice, curRecDevice, recPinFD, curRecPinFD, recKeyInFD)
			if recSession && info.Policy == "hardware" {
				// the session already asked this authenticator's PIN: the proof reuses it
				req.CurrentRecovery.PIN = a.pinCallback("daily", func() string { return a.fido2Device }, func() int { return a.fido2PinFD }, false)
			}
			if policy == "standard" {
				if req.Passphrase, err = a.newPassphrase(cmd.Context(), newPassFD, "--new-passphrase-fd"); err != nil {
					return err
				}
				defer req.Passphrase.Destroy()
			}
			rec, copyPath, err := adm.Rotate(cmd.Context(), req)
			if rec != nil {
				defer rec.Destroy()
			}
			if err != nil && rec == nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "rotated: policy %s\n", policy)
			if copyPath != "" {
				fmt.Fprintf(a.d.Out, "A copy of the file from before the rotation is %s. It opens with the OLD credentials, which this rotation revoked. Destroy it once you have confirmed the new factors.\n", copyPath)
			}
			if rec != nil {
				unknown := err != nil
				if derr := a.deliverRecoveryKeyMode(cmd.Context(), rec, rkFD, unknown); derr != nil {
					return derr
				}
				fmt.Fprintln(a.d.Out, rekeyNote)
			}
			return err
		},
	}
	markRecoveryComposite(cmd)
	cmd.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the new recovery key to this file descriptor instead of showing it")
	cmd.Flags().IntVar(&recKeyInFD, "recovery-key-in-fd", -1, "read the CURRENT recovery key from this file descriptor instead of prompting")
	cmd.Flags().IntVar(&recPinFD, "recovery-pin-fd", -1, "read the PIN of the recovery authenticator (--recovery-device) from this file descriptor; never the daily PIN")
	cmd.Flags().IntVar(&curRecPinFD, "old-recovery-pin-fd", -1, "read the PIN of the current recovery authenticator from this file descriptor when it is not --recovery-device")
	cmd.Flags().StringVar(&policy, "policy", "", "standard, hardware or strict")
	cmd.Flags().IntVar(&newPassFD, "new-passphrase-fd", -1, "read the NEW workspace passphrase of a standard table from this file descriptor instead of prompting (twice)")
	cmd.Flags().IntVar(&newPinFD, "new-fido2-pin-fd", -1, "read the PIN of the NEW daily authenticator (--new-fido2-device) from this file descriptor")
	cmd.Flags().StringVar(&newDevice, "new-fido2-device", "", "the NEW daily authenticator of the table (hardware, strict); default --fido2-device, and required in a --unlock recovery-composite session, where --fido2-device is the current recovery authenticator")
	cmd.Flags().StringSliceVar(&leave, "leave-unreachable", nil, "accept leaving this cold record (KIND/LABEL, as the refusal names it) under its old cold factor instead of re-establishing it; needs the recovery credential; repeat per record")
	cmd.Flags().StringVar(&recDevice, "recovery-device", "", "the second authenticator of the recovery composite (hardware)")
	cmd.Flags().StringVar(&curRecDevice, "current-recovery-device", "", "the authenticator of the CURRENT recovery composite (hardware workspace); default --recovery-device, or the session device with --unlock recovery-composite")
	cmd.Flags().StringVar(&keepCopy, "keep-copy", "", "also write a copy of the file from before the rotation to FILE (never overwritten, mode 0600); it opens with the OLD credentials: destroy it after the new factors are confirmed")
	cmd.Flags().StringSliceVar(&yesRemove, "yes-remove", nil, "confirm the removal of this slot id (strict workspace: one flag per existing slot; see workspace slot list)")
	cmd.Flags().BoolVar(&yes, "yes-strict", false, "accept that a strict workspace has no recovery key")
	return cmd
}

// recoveryOpens builds what a rotation or a slot removal presents of the
// recovery path: the authenticator of the NEW recovery composite (newRec: its
// own device and PIN) and the CURRENT recovery credential (cur: the recovery key
// from --recovery-key-in-fd or a prompt and, under a hardware workspace, the
// second authenticator with its own PIN). A strict workspace has no current
// recovery credential: cur is empty.
func (a *app) recoveryOpens(curPolicy, recDevice, curRecDevice string, recPinFD, curRecPinFD, recKeyInFD int) (newRec, cur FactorOpen) {
	notify := func(m string) { fmt.Fprintln(a.d.Err, m) }
	recPin := a.pinCallback("recovery", func() string { return recDevice }, func() int { return recPinFD }, false)
	newRec = FactorOpen{Source: a.d.Factors, Device: recDevice, PIN: recPin, Notify: notify}
	if curPolicy == "strict" {
		return newRec, cur
	}
	cur = FactorOpen{Source: a.d.Factors, Device: curRecDevice, Notify: notify,
		Recovery: func(ctx context.Context) (*secret.Buffer, error) {
			if a.recText != nil { // the recovery session was opened with it: used once, for the proof
				text := a.recText
				a.recText = nil
				defer text.Destroy()
				return secret.Fill(text.Len(), func(dst []byte) error {
					return text.Use(func(b []byte) error { copy(dst, b); return nil })
				})
			}
			if recKeyInFD >= 0 {
				return readFDSecret(recKeyInFD, "the current recovery key")
			}
			t, err := a.term.ReadSecret(ctx, "Current recovery key: ")
			if errors.Is(err, ErrNoTerminal) {
				return nil, errors.New("no terminal to ask for the current recovery key on; give it on a file descriptor with --recovery-key-in-fd N")
			}
			return t, err
		}}
	if curRecDevice == recDevice {
		cur.PIN = recPin
	} else {
		cur.PIN = a.pinCallback("current-recovery", func() string { return curRecDevice }, func() int { return curRecPinFD }, false)
	}
	return newRec, cur
}

// slotByPrefix finds the one slot whose id starts with the hex text given.
func slotByPrefix(info WorkspaceInfo, prefix string) (Slot, error) {
	var found []Slot
	for _, s := range info.Slots {
		if prefix != "" && strings.HasPrefix(fmt.Sprintf("%x", s.ID), strings.ToLower(prefix)) {
			found = append(found, s)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return Slot{}, fmt.Errorf("no slot has an id starting with %q; see: spo workspace slot list", prefix)
	}
	return Slot{}, fmt.Errorf("%d slots have an id starting with %q; give more of it", len(found), prefix)
}

func (a *app) slotRemove() *cobra.Command {
	var recDevice, curRecDevice, keepCopy string
	rkFD, recPinFD, curRecPinFD, recKeyInFD := -1, -1, -1, -1
	cmd := &cobra.Command{
		Use:   "remove <slot id or its first characters>",
		Short: "Remove a slot (a rotation: the workspace key and every data key are replaced)",
		Long: `Removing a slot revokes nothing unless the workspace key changes, so this is a
rotation: a new workspace key, a fresh data key for every record, and every
other slot re-created, which needs the factors of every slot that stays (the
passphrase of a passphrase slot, the authenticator of a FIDO2 slot, the recovery
authenticator of a hardware workspace). It asks for the CURRENT recovery
credential as workspace rotate does, and refuses to remove the last slot the
policy needs (the last passphrase or recovery slot of standard, the last
slot besides the recovery composite of hardware or strict). A recovery slot or
composite that stays gets a NEW recovery key. It makes no copy of the file
(--keep-copy FILE asks for one that opens with the OLD credentials). The removal
is written to the audit chain. What it cannot delete: backups, snapshots and any
copy the removed factor's holder already has.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if a.d.Sealed.Describe == nil {
				return errors.New("this build cannot read the slot table")
			}
			info, err := a.d.Sealed.Describe(a.workspaceFile())
			if err != nil {
				return err
			}
			slot, err := slotByPrefix(info, args[0])
			if err != nil {
				return err
			}
			if info.Policy == "hardware" && curRecDevice == "" {
				curRecDevice = recDevice
			}
			if info.Policy == "hardware" && curRecDevice == "" {
				return errors.New("this workspace is under hardware: give --recovery-device, the authenticator of its recovery composite")
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			adm, ok := s.Sealed.(SlotAdmin)
			if !ok {
				return errors.New("this workspace handle cannot change its slots")
			}
			req := RemoveSlotRequest{ID: slot.ID, Daily: a.factorOpen(), KeepCopy: keepCopy}
			if !s.factorSession && s.Pass != nil {
				pass := s.Pass
				req.Daily.Passphrase = func(context.Context) (*secret.Buffer, error) {
					return secret.Fill(pass.Len(), func(dst []byte) error { return pass.Use(func(b []byte) error { copy(dst, b); return nil }) })
				}
			}
			_, req.CurrentRecovery = a.recoveryOpens(info.Policy, recDevice, curRecDevice, recPinFD, curRecPinFD, recKeyInFD)
			rec, copyPath, err := adm.RemoveSlot(cmd.Context(), req)
			if rec != nil {
				defer rec.Destroy()
			}
			if err != nil && rec == nil {
				return err
			}
			fmt.Fprintf(a.d.Out, "removed %s slot %x; the workspace key and every data key were replaced.\n", slot.Kind, slot.ID)
			if copyPath != "" {
				fmt.Fprintf(a.d.Out, "A copy of the file from before the removal is %s. It opens with the OLD credentials, including the removed one. Destroy it once you have confirmed the remaining factors.\n", copyPath)
			}
			if rec != nil {
				if derr := a.deliverRecoveryKeyMode(cmd.Context(), rec, rkFD, err != nil); derr != nil {
					return derr
				}
				fmt.Fprintln(a.d.Out, rekeyNote)
			}
			return err
		},
	}
	cmd.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the new recovery key to this file descriptor instead of showing it")
	cmd.Flags().IntVar(&recKeyInFD, "recovery-key-in-fd", -1, "read the CURRENT recovery key from this file descriptor instead of prompting")
	cmd.Flags().IntVar(&recPinFD, "recovery-pin-fd", -1, "read the PIN of the recovery authenticator (--recovery-device) from this file descriptor")
	cmd.Flags().IntVar(&curRecPinFD, "old-recovery-pin-fd", -1, "read the PIN of the current recovery authenticator from this file descriptor when it is not --recovery-device")
	cmd.Flags().StringVar(&recDevice, "recovery-device", "", "the authenticator of the recovery composite (hardware workspace)")
	cmd.Flags().StringVar(&curRecDevice, "current-recovery-device", "", "the authenticator of the CURRENT recovery composite when it is not --recovery-device")
	cmd.Flags().StringVar(&keepCopy, "keep-copy", "", "also write a copy of the file from before the removal to FILE (never overwritten, mode 0600); it opens with the OLD credentials")
	return cmd
}

// workspacePolicySet is `workspace policy set`: the same operation as
// `workspace rotate --policy`, whose rules (the recovery credential presented,
// no loosening of strict) it inherits unchanged.
func (a *app) workspacePolicySet() *cobra.Command {
	c := a.workspaceRotateCommand()
	c.Use = "set --policy standard|hardware|strict [--recovery-device PATH]"
	c.Short = "Change the unlock policy (the same operation as workspace rotate --policy)"
	c.Long = "Changing the policy is a rotation and follows every rule of `spo workspace rotate` (run `spo workspace rotate --help`): the current recovery credential is presented first, the workspace key and every data key are replaced, and a strict workspace cannot be loosened.\n\n" + c.Long
	return c
}

// factorPassphrase offers the passphrase to a composite slot only when the
// operator gave one (--passphrase-fd): a prompt for a slot the operator did not
// choose would be a prompt for nothing.
func (a *app) factorPassphrase() func(context.Context) (*secret.Buffer, error) {
	if !a.passphraseFDSet() {
		return nil
	}
	return a.readPassphrase
}

// factorRecovery offers the recovery key to a recovery composite only under
// --unlock recovery-composite.
func (a *app) factorRecovery() func(context.Context) (*secret.Buffer, error) {
	if a.unlock != "recovery-composite" {
		return nil
	}
	return func(ctx context.Context) (*secret.Buffer, error) {
		var t *secret.Buffer
		var err error
		if a.recoveryFD >= 0 {
			t, err = readFDSecret(a.recoveryFD, "the recovery key")
		} else {
			t, err = a.term.ReadSecret(ctx, "Recovery key: ")
			if errors.Is(err, ErrNoTerminal) {
				err = errors.New("no terminal to ask for the recovery key on; give it on a file descriptor with --recovery-key-in-fd N")
			}
		}
		if err != nil {
			return nil, err
		}
		// kept only for the rotation that recovers the workspace, which presents the same
		// recovery key again as its proof (and destroys the copy when it has)
		if !a.keepRecovery {
			return t, nil
		}
		if a.recText != nil {
			a.recText.Destroy()
		}
		if a.recText, err = secret.Fill(t.Len(), func(dst []byte) error {
			return t.Use(func(b []byte) error { copy(dst, b); return nil })
		}); err != nil {
			t.Destroy()
			return nil, err
		}
		return t, nil
	}
}

// recoveryCompositeAnnotation marks the commands that accept --unlock recovery-composite.
const recoveryCompositeAnnotation = "spo/recovery-composite"

// recoveryCompositeCommands are the commands the recovery procedure uses: the rotation
// that re-establishes the workspace (and its alias, workspace policy set) and the
// read-only listing of the slots.
const recoveryCompositeCommands = "workspace rotate, workspace policy set, store slots"

// checkUnlockScope refuses --unlock recovery-composite for a command that does not need
// it, before any prompt: a long-running command (party serve) would otherwise hold the
// recovery key for its lifetime.
func (a *app) checkUnlockScope(cmd *cobra.Command) error {
	if a.unlock != "recovery-composite" || cmd.Annotations[recoveryCompositeAnnotation] == "true" {
		return nil
	}
	return fmt.Errorf("--unlock recovery-composite is accepted only by %s; %q does not need the recovery credential: nothing was asked", recoveryCompositeCommands, cmd.CommandPath())
}

func markRecoveryComposite(c *cobra.Command) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[recoveryCompositeAnnotation] = "true"
}

// cleanupAfterEveryCommand wraps every runnable command so that, whatever way it ends,
// the PINs, cold-key passphrases and recovery text this command read are destroyed (the
// per-command defers stay).
func (a *app) cleanupAfterEveryCommand(root *cobra.Command) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if run := c.RunE; run != nil {
			c.RunE = func(cmd *cobra.Command, args []string) error {
				defer a.destroyPINs()
				return run(cmd, args)
			}
		} else if run := c.Run; run != nil {
			c.Run = func(cmd *cobra.Command, args []string) {
				defer a.destroyPINs()
				run(cmd, args)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}
