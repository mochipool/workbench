package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func (a *app) initCommand() *cobra.Command {
	var (
		network          string
		mode             string
		rkFD             int
		yes              bool
		policy           string
		recDev           string
		recPin           = -1
		yesStr           bool
		removeUnfinished bool
	)
	cmd := &cobra.Command{
		Use:   "init --network <mainnet|preprod|preview> [--mode online|light|offline]",
		Short: "Create a sealed workspace in the workspace directory",
		Long: `Create workspace.spo (the sealed store) and spo.toml (non-secret settings).

The passphrase is asked for twice without echo, or read from --passphrase-fd.
A recovery key is shown once: write it down, then type back its last group.
With --passphrase-fd and --recovery-key-fd the key is written to that
descriptor instead and nothing is shown.

--policy hardware or strict creates the workspace under that unlock policy at
once (ADR 0011): no passphrase is asked, authenticators are enrolled instead
(--fido2-device, and for hardware --recovery-device, each with its own PIN:
--fido2-pin-fd, --recovery-pin-fd). The workspace is first created with a random
passphrase and recovery key that exist only in this process and are destroyed
when the rotation to the policy has committed; if anything fails the files
created by this run are removed. While it runs, the file workspace.spo.init-pending
marks the workspace as unfinished. A run that was killed before the rotation
committed leaves an unopenable workspace.spo (its passphrase is gone): the next
init finds the marker and removes the leftover only after you confirm
(--remove-unfinished, or answer y).

Mode light names Koios, a third-party service, as the chain provider and asks
you to confirm that first. Mode offline configures no provider.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if a.upstream {
				return errors.New("init creates a sealed workspace; --upstream-layout does not apply")
			}
			if network == "" {
				return errors.New("--network is required (mainnet, preprod or preview)")
			}
			preset, err := a.requirePreset(network)
			if err != nil {
				return err
			}
			switch mode {
			case ModeOnline, ModeLight, ModeOffline:
			default:
				return fmt.Errorf("--mode %q is not one of online, light, offline", mode)
			}
			switch policy {
			case "", "standard":
				policy = "standard"
			case "hardware", "strict":
				if a.d.Factors == nil {
					return errors.New("this binary has no FIDO2 factor source (the libfido2 tools are not in the toolchain manifest): nothing was asked")
				}
				if policy == "hardware" && (recDev == "" || recDev == a.fido2Device) {
					return errors.New("--policy hardware needs two different authenticators: --fido2-device for the daily one and --recovery-device for the recovery composite")
				}
				if policy == "strict" && !yesStr {
					return errors.New("strict has no recovery key: if the authenticator is lost the workspace is lost. Add --yes-strict to go on")
				}
			default:
				return fmt.Errorf("--policy %q is not one of standard, hardware, strict", policy)
			}
			if cmd.Flags().Changed("recovery-key-fd") {
				if policy == "standard" && !a.passphraseFDSet() {
					return errors.New("--recovery-key-fd needs --passphrase-fd: the recovery key is only taken off the terminal for non-interactive use")
				}
			} else {
				rkFD = -1
			}
			if exists(a.initPendingPath()) {
				if err := a.clearUnfinishedInit(ctx, removeUnfinished); err != nil {
					return err
				}
			}
			if exists(a.workspaceFile()) || exists(a.configPath()) {
				return fmt.Errorf("%s already holds a workspace (%s or %s exists); init never replaces one", a.workspace, WorkspaceFile, configFile)
			}

			cfg := WorkspaceConfig{Network: preset.Name, Mode: mode}
			if mode == ModeLight {
				ok, err := a.confirmProvider(cmd, "koios", preset.KoiosURL, yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("no provider was confirmed, so no light-mode workspace was created; use --mode offline, or run init again and answer y")
				}
				cfg.Koios = &KoiosConfig{URL: preset.KoiosURL}
			}

			var pass *secret.Buffer
			if policy == "standard" {
				pass, err = a.newPassphrase(ctx, a.passFD, "--passphrase-fd")
			} else {
				// the workspace starts with a random passphrase nobody sees; the rotation
				// below replaces every slot
				pass, err = secret.Fill(32, func(dst []byte) error { _, e := rand.Read(dst); return e })
				if err == nil {
					defer a.destroyPINs()
				}
			}
			if err != nil {
				return err
			}
			defer pass.Destroy()

			if err := os.MkdirAll(a.workspace, 0o700); err != nil {
				return err
			}
			if err := a.d.Config.Create(a.workspace, cfg); err != nil {
				return err
			}
			recovery, err := a.d.Sealed.Init(a.workspaceFile(), pass)
			if err != nil {
				os.Remove(a.configPath())
				os.Remove(a.initPendingPath())
				return err
			}
			defer recovery.Destroy()
			if policy != "standard" {
				// Right after Init and before the rotation: the marker names this
				// file by its workspace id, so a marker can only ever point at it.
				if err := a.writeInitPending(policy); err != nil {
					for _, p := range []string{a.workspaceFile(), a.workspaceFile() + ".head", a.workspaceFile() + ".head.lock", a.workspaceFile() + "-wal", a.workspaceFile() + "-shm", a.workspaceFile() + "-journal", a.configPath()} {
						os.Remove(p)
					}
					return err
				}
				removeAll := func() {
					for _, p := range []string{a.workspaceFile(), a.workspaceFile() + ".head", a.workspaceFile() + ".head.lock", a.workspaceFile() + "-wal", a.workspaceFile() + "-shm", a.workspaceFile() + "-journal", a.configPath(), a.initPendingPath()} {
						os.Remove(p)
					}
				}
				newKey, rerr := a.initUnderPolicy(ctx, policy, pass, recovery, recDev, recPin)
				var held bool // the rotation's outcome was unknown and could not be settled
				if rerr != nil && errors.Is(rerr, ErrOutcomeUnknown) {
					// The commit may or may not have happened. Settle it from the file
					// (the policy is readable without a key), as the rotation command
					// settles it: if the policy took effect the recovery key is valid
					// and is delivered; if not, the file is the unopenable first
					// workspace and is removed; if the file cannot be read, nothing is
					// removed and the key is delivered marked as valid only if the
					// rotation took effect.
					switch got, derr := a.filePolicy(); {
					case derr == nil && got == policy:
						rerr = nil
					case derr == nil:
						if newKey != nil {
							newKey.Destroy()
						}
						removeAll()
						// not wrapped: ErrOutcomeUnknown would be explained as an open question
						return fmt.Errorf("the rotation to %s did not take effect (its outcome was unknown, and the file is still %s); the workspace created by this run was removed: run init again", policy, got)
					default:
						held = true
					}
				}
				if held {
					if newKey != nil {
						defer newKey.Destroy()
					}
					fmt.Fprintln(a.d.Out, "WARNING: the workspace could not confirm whether the policy change was stored. The recovery key below is valid ONLY IF it took effect.")
					var derr error
					if newKey != nil {
						derr = a.deliverRecoveryKeyMode(ctx, newKey, rkFD, true)
					}
					msg := "the outcome of creating the workspace under policy " + policy + " is unknown, and the file was kept (with " + filepath.Base(a.initPendingPath()) + "). Run `spo workspace policy show`: if it says " + policy + ", the workspace is complete and the key just shown is its recovery key; if it says standard, run init again and confirm the removal of the unfinished file"
					if derr != nil {
						msg += " (" + derr.Error() + ")"
					}
					return &explained{msg: msg, err: rerr}
				}
				if rerr != nil {
					if newKey != nil {
						newKey.Destroy()
					}
					removeAll()
					return fmt.Errorf("%w. The workspace created by this run was removed", rerr)
				}
				os.Remove(a.initPendingPath()) // the rotation committed: the workspace is complete
				fmt.Fprintf(a.d.Out, "Created workspace in %s: network %s, mode %s, policy %s.\n", a.workspace, cfg.Network, cfg.Mode, policy)
				if newKey != nil {
					defer newKey.Destroy()
					if derr := a.deliverRecoveryKey(ctx, newKey, rkFD); derr != nil {
						removeAll()
						return fmt.Errorf("%w. The workspace created by this run was removed because its recovery key was not delivered; run init again", derr)
					}
				}
				return nil
			}
			fmt.Fprintf(a.d.Out, "Created workspace in %s: network %s, mode %s.\n", a.workspace, cfg.Network, cfg.Mode)
			if derr := a.deliverRecoveryKey(ctx, recovery, rkFD); derr != nil {
				if rkFD >= 0 {
					// The key went nowhere and nothing else can open the workspace
					// if the passphrase is lost: take back what this run created.
					for _, p := range []string{a.workspaceFile(), a.workspaceFile() + ".head", a.workspaceFile() + ".head.lock", a.workspaceFile() + "-wal", a.workspaceFile() + "-shm", a.workspaceFile() + "-journal", a.configPath()} {
						os.Remove(p)
					}
					return fmt.Errorf("%w. The workspace created by this run was removed because its recovery key was not delivered; run init again", derr)
				}
				return derr
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "mainnet, preprod or preview")
	cmd.Flags().StringVar(&mode, "mode", ModeOffline, "online (a node socket: spo provider set node), light (Koios) or offline")
	cmd.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the recovery key to this inherited pipe or socket (never a file) instead of showing it (needs --passphrase-fd)")
	cmd.Flags().StringVar(&policy, "policy", "standard", "unlock policy: standard (passphrase and recovery key), hardware (FIDO2 authenticators; needs --fido2-device and --recovery-device) or strict (one authenticator, no recovery key)")
	cmd.Flags().StringVar(&recDev, "recovery-device", "", "the second authenticator of the recovery composite (--policy hardware)")
	cmd.Flags().IntVar(&recPin, "recovery-pin-fd", -1, "read the PIN of the recovery authenticator from this file descriptor")
	cmd.Flags().BoolVar(&yesStr, "yes-strict", false, "accept that a strict workspace has no recovery key")
	cmd.Flags().BoolVar(&removeUnfinished, "remove-unfinished", false, "confirm the removal of the unfinished workspace an interrupted `init --policy hardware|strict` left (see the marker "+initPendingFile+")")
	cmd.Flags().BoolVar(&yes, "yes", false, "answer yes to the provider confirmation (the statement is still printed)")
	return cmd
}

// initUnderPolicy turns the workspace Init just made (random passphrase,
// recovery key known only here) into one under policy, by the rotation every
// policy change is, and returns the new recovery key (nil under strict).
func (a *app) initUnderPolicy(ctx context.Context, policy string, pass, recovery *secret.Buffer, recDev string, recPinFD int) (*secret.Buffer, error) {
	st, err := a.d.Sealed.Open(a.workspaceFile(), pass, OpenOptions{})
	if err != nil {
		return nil, err
	}
	defer st.Close()
	adm, ok := st.(SlotAdmin)
	if !ok {
		return nil, errors.New("this workspace handle cannot change its slots")
	}
	req := RotateRequest{Policy: policy, Daily: a.factorOpen()}
	req.Recovery = FactorOpen{Source: a.d.Factors, Device: recDev, Notify: func(m string) { fmt.Fprintln(a.d.Err, m) },
		PIN: a.pinCallback("recovery", func() string { return recDev }, func() int { return recPinFD }, false)}
	req.CurrentRecovery = FactorOpen{Recovery: func(context.Context) (*secret.Buffer, error) {
		return secret.Fill(recovery.Len(), func(dst []byte) error { return recovery.Use(func(b []byte) error { copy(dst, b); return nil }) })
	}}
	key, _, err := adm.Rotate(ctx, req)
	return key, err
}

// initPendingFile marks a policy init that has not committed its rotation yet.
const initPendingFile = "workspace.spo.init-pending"

func (a *app) initPendingPath() string { return filepath.Join(a.workspace, initPendingFile) }

// writeInitPending creates the marker, exclusively, mode 0600. It holds no
// secret: the policy being created and the time.
func (a *app) writeInitPending(policy string) error {
	if a.d.Sealed.Describe == nil {
		return errors.New("this build cannot read the workspace id")
	}
	info, err := a.d.Sealed.Describe(a.workspaceFile())
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.initPendingPath(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, "{\"policy\":%q,\"started\":%q,\"id\":%q}\n", policy, time.Now().UTC().Format(time.RFC3339), hex.EncodeToString(info.ID))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(a.initPendingPath())
	}
	return werr
}

// filePolicy reads the policy of the workspace file without a key.
func (a *app) filePolicy() (string, error) {
	if a.d.Sealed.Describe == nil {
		return "", errors.New("this build cannot read the slot table")
	}
	info, err := a.d.Sealed.Describe(a.workspaceFile())
	if err != nil {
		return "", err
	}
	return info.Policy, nil
}

// clearUnfinishedInit deals with the marker of an interrupted policy init. The
// leftover is removed only after an explicit confirmation, and only when the file
// is still a standard workspace (the throwaway first workspace, which nothing can
// open): a file that has the policy of its marker is a finished workspace and is
// never touched.
func (a *app) clearUnfinishedInit(ctx context.Context, confirmed bool) error {
	leftovers := []string{a.workspaceFile(), a.workspaceFile() + ".head", a.workspaceFile() + ".head.lock", a.workspaceFile() + "-wal", a.workspaceFile() + "-shm", a.workspaceFile() + "-journal", a.configPath(), a.initPendingPath()}
	if exists(a.workspaceFile()) {
		// The marker is evidence only if it names THIS file and the file is exactly
		// what Init leaves: nothing else is removed, whatever the operator answers.
		var mk struct {
			ID string `json:"id"`
		}
		raw, rerr := os.ReadFile(a.initPendingPath())
		if rerr != nil || json.Unmarshal(raw, &mk) != nil || mk.ID == "" {
			return fmt.Errorf("%s exists beside %s but does not name that file: nothing was removed. If %s is not a workspace you want, delete %s by hand", initPendingFile, WorkspaceFile, WorkspaceFile, initPendingFile)
		}
		if a.d.Sealed.Describe == nil {
			return errors.New("this build cannot read the slot table")
		}
		info, err := a.d.Sealed.Describe(a.workspaceFile())
		switch {
		case err != nil:
			return fmt.Errorf("%s exists beside %s, and it cannot be read (%v): nothing was removed. Delete %s by hand if it is stale", WorkspaceFile, initPendingFile, err, initPendingFile)
		case info.Policy != "standard":
			os.Remove(a.initPendingPath())
			return fmt.Errorf("%s is a complete workspace (policy %s); the stale marker %s was removed and nothing else was touched. init never replaces a workspace", WorkspaceFile, info.Policy, initPendingFile)
		}
		fresh := hex.EncodeToString(info.ID) == mk.ID && info.Records == 0 && info.AuditRows == 1 && len(info.Slots) == 2
		kinds := map[string]int{}
		for _, sl := range info.Slots {
			kinds[sl.Kind]++
		}
		if !fresh || kinds["passphrase"] != 1 || kinds["recovery"] != 1 {
			return fmt.Errorf("%s is not the unfinished workspace the marker %s names (another workspace id, or it holds records, more history or other slots than a new one): nothing was removed. Delete %s by hand if it is stale", WorkspaceFile, initPendingFile, initPendingFile)
		}
		ok, err := a.confirm(ctx, fmt.Sprintf("An earlier `init --policy hardware|strict` in %s was interrupted before it finished: %s is its unfinished first workspace, made with a random passphrase that no longer exists, so nothing can open it and it holds no keys. Remove it and start again?", a.workspace, WorkspaceFile), confirmed)
		if err != nil {
			return fmt.Errorf("%w (an interrupted init left %s; to remove it pass --remove-unfinished)", err, WorkspaceFile)
		}
		if !ok {
			return fmt.Errorf("an interrupted init left an unfinished %s in %s; nothing was removed", WorkspaceFile, a.workspace)
		}
	}
	if !exists(a.workspaceFile()) {
		// a marker with no file beside it is stale: only the marker goes
		os.Remove(a.initPendingPath())
		return nil
	}
	for _, p := range leftovers {
		os.Remove(p)
	}
	return nil
}

func (a *app) configPath() string { return a.workspace + string(os.PathSeparator) + configFile }

// providerStatement says what a chain provider learns (ADR 0006).
func providerStatement(name, url string) string {
	return fmt.Sprintf(`Provider: %s at %s

This is a third-party service, not run by you. With it configured, every
query tells it which pools, addresses and stake addresses you are interested
in, every transaction you submit through it, and the network address your
requests come from. It never receives your keys or your passphrase.

Its answers cannot be checked here. The tool treats a failed or unreadable
answer as "unknown", never as "nothing found", and stops where a wrong answer
could do harm.
`, name, url)
}

// confirmProvider prints the privacy statement and asks the operator to
// confirm. The default is no.
func (a *app) confirmProvider(cmd *cobra.Command, name, url string, yes bool) (bool, error) {
	fmt.Fprint(a.d.Out, providerStatement(name, url))
	return a.confirm(cmd.Context(), fmt.Sprintf("Use %s for this workspace?", name), yes)
}
