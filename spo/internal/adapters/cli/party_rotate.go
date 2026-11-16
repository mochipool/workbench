package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- rotate: replace this workspace's own identity -----------------------------------

const rotateWarning = `This replaces the party identity of this workspace. What happens, in one step:
  - a new identity is made (new signing and encryption keys; the tailcat node key stays);
  - the old private keys are REPLACED by the new ones in this workspace (a backup of the workspace made earlier
    still holds them): an envelope sealed to the old identity can no longer be opened here;
  - everything waiting in the outbox is dropped (it was sealed by the old identity; the command refuses while the
    announcements of an EARLIER rotation are still undelivered), requests waiting for your
    decision are closed, and requests of collections you coordinate must be made again;
  - one announcement, signed by the old and the new key, is sealed for each enrolled party and queued in the outbox.
No peer changes anything by itself. Each peer must confirm the new identity at its own terminal, by typing the
first four groups of the new fingerprint that you read out to them over a separate channel.`

func (a *app) partyRotateCommand() *cobra.Command {
	var label string
	var yes bool
	cmd := &cobra.Command{
		Use:   "rotate [--label TEXT] [--yes]",
		Short: "Replace this workspace's party identity and announce the new one to the enrolled parties",
		Long: rotateWarning + `

Carry the announcements to your peers with: spo party outbox export DIR (a file for each
peer; over tailcat a rotated party cannot connect until the peer has accepted the rotation).
Each peer runs: spo party rotation list, then spo party rotation accept NAME.

The announcements are sealed and kept for 7 days (spo party outbox export DIR --resend-rotation writes
them again, for a file that was lost). After 7 days they cannot be made again, because the old private key is
gone: a peer that never got one must enroll your new identity from scratch. Do not rotate again before every
peer has accepted the first rotation: a peer that has not would not know the second identity either.

If the old private key is lost there is no rotation, because the statement has to be signed
by the old key. Make a new identity (spo party init in a workspace without one) and have every
peer enroll it from scratch: spo party enroll.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				l, err := r.kit().Kit.Local(ctx)
				if err != nil {
					if strings.Contains(err.Error(), "no party identity") {
						return partyIdentityErr(err)
					}
					return fmt.Errorf("%w: %v", multisig.ErrOldKeyUnavailable, err)
				}
				old := l.Identity()
				l.Destroy()
				w := a.d.Out
				fmt.Fprintf(w, "%s\n\nthis identity  %s (label %s)\n", rotateWarning, old.Fingerprint(), strconv.Quote(old.Label))
				ok, err := a.confirm(ctx, "Replace this identity?", yes)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("not rotated: the identity is unchanged")
				}
				done, err := r.node().RotateIdentity(ctx, label)
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "Rotated.\n  old fingerprint  %s\n  new fingerprint  %s\n", done.Old, done.New)
				fmt.Fprintf(w, "  announcements sealed for %d peer(s): %s\n", len(done.Announced), strings.Join(quoteAll(done.Announced), ", "))
				if done.Dropped > 0 || done.ClosedRequests > 0 || done.VoidedSlots > 0 {
					fmt.Fprintf(w, "  dropped %d queued envelope(s), closed %d request(s) waiting for you, voided %d outstanding request(s) of your collections: they must be requested again\n",
						done.Dropped, done.ClosedRequests, done.VoidedSlots)
				}
				switch {
				case done.CheckpointErr != nil:
					fmt.Fprintf(a.d.Err, "WARNING: the replaced old keys may still be in the store's write-ahead log (%v). Close every spo process on this workspace and open it once more to fold it.\n", done.CheckpointErr)
				case done.Checkpointed:
					fmt.Fprintln(w, "  the store's write-ahead log was folded, so the replaced keys are not left in it; a backup made BEFORE this still holds them")
				}
				fmt.Fprintf(w, "\nRead the FIRST FOUR groups of the new fingerprint to each peer over a separate channel. They type them to accept.\nCarry the announcements with: spo party outbox export DIR\n")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&label, "label", "", "the label peers see for the new identity (default: the old label)")
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask whether to replace the identity")
	return cmd
}

func quoteAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strconv.Quote(x)
	}
	return out
}

// ---- rotation: what a peer does with an announcement -----------------------------------

func (a *app) partyRotationCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "rotation",
		Short: "Announcements that an enrolled party replaced its identity: list, accept, reject",
		Long: `A peer that ran spo party rotate sends an announcement, signed by its old and its new
key. Receiving it (by file or over tailcat) only stores it: nothing about the enrollment
changes until you accept it here, with the first four groups of the new fingerprint as the
peer reads them out over a separate channel (SPO-Xparty-PR-006).`,
	}
	c.AddCommand(a.partyRotationListCommand(), a.partyRotationAcceptCommand(), a.partyRotationRejectCommand())
	return c
}

func (a *app) partyRotationListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the announcements that wait for your confirmation",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				pend, err := r.node().PendingRotations(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				if len(pend) == 0 {
					fmt.Fprintln(w, "No rotation announcement is waiting.")
					return nil
				}
				for _, p := range pend {
					fmt.Fprintf(w, "%s  announces a new identity\n  old fingerprint  %s\n  new label        %s (chosen by its owner; not trusted)\n  last four groups of the new fingerprint  %s\n  arrived by %s; the statement is valid until %s\n",
						strconv.Quote(p.Name), p.Old, strconv.Quote(p.New.Label), p.New.Fingerprint().Tail(), p.Via, p.Expires.UTC().Format("2006-01-02 15:04 MST"))
				}
				fmt.Fprintln(w, "Confirm one with: spo party rotation accept NAME")
				return nil
			})
		},
	}
}

func (a *app) partyRotationAcceptCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "accept NAME",
		Short: "Replace an enrolled party's identity by the one it announced, after you confirm the new fingerprint",
		Long: `Show the announcement of NAME and ask for the first four groups of the NEW fingerprint,
which NAME's operator reads out over a separate channel and which are never on the screen,
then whether the scope recorded for NAME carries over to the new identity (default No: the
new identity then has a scope that allows nothing, and you set one with spo party scope).
There is no flag that answers either, and with no terminal nothing changes.

In one step the old identity is revoked (kept, under a name that cannot be an enrollment
name, so it can never be enrolled again) and the new one is enrolled under NAME with the
same roles. Requests that were sent to the old identity are void and must be made again.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				node := r.node()
				pr, err := node.RotationOf(ctx, args[0])
				if err != nil {
					return rotationErr(err, args[0])
				}
				w := a.d.Out
				fmt.Fprintf(w, "%s announces a new identity.\n  old fingerprint  %s\n  new label        %s (chosen by its owner; not trusted)\n  last four groups of the new fingerprint  %s\n  roles it keeps   %v\n  scope now        %s\n",
					strconv.Quote(pr.Name), pr.Old, strconv.Quote(pr.New.Label), pr.New.Fingerprint().Tail(), pr.Roles, scopeText(pr.Scope))
				fmt.Fprintf(w, "The other operator reads you the FIRST %d groups of the NEW fingerprint over a separate channel (not this announcement, not a message that came with it).\n", party.ConfirmGroups)
				typed, err := a.term.ReadLine(ctx, fmt.Sprintf("Type the first %d groups of the new fingerprint: ", party.ConfirmGroups))
				if errors.Is(err, ErrNoTerminal) {
					return errors.New("no terminal: the first four groups of the new fingerprint are typed by the operator from what the other party reads out, and there is no flag for them. Nothing changed")
				}
				if err != nil {
					return err
				}
				if !party.ConfirmPrefix(pr.New.Fingerprint(), typed) {
					return errors.New("the groups you typed are not the first four groups of the new fingerprint: nothing changed. If the other operator read them out correctly, this announcement is not theirs")
				}
				carry := false
				if !pr.Scope.Empty() {
					carry, err = a.askYes(ctx, "Carry the scope over to the new identity ("+scopeText(pr.Scope)+")?")
					if err != nil {
						return err
					}
				}
				res, err := node.AcceptRotation(ctx, args[0], party.RotationAcceptance{Confirmation: typed, CarryScope: carry})
				if err != nil {
					return rotationErr(err, args[0])
				}
				revokeLive(res.Retired)
				allowLive(res.Party)
				fmt.Fprintf(w, "Accepted. %s is now the identity %s.\n  the old identity %s is revoked: its envelopes are refused from now on\n",
					strconv.Quote(res.Party.Name), res.Party.Fingerprint, res.Retired.Fingerprint)
				if carry {
					fmt.Fprintf(w, "  scope carried over: %s\n", scopeText(res.Party.Scope))
				} else if res.Party.HasRole(party.RoleCoordinator) {
					fmt.Fprintf(w, "  scope: nothing. Give it one with: spo party scope %s --key-role R --pool P\n", res.Party.Name)
				}
				if res.VoidedSlots+res.DroppedEnvelopes+res.ClosedRequests > 0 {
					fmt.Fprintf(w, "  %d request(s) sent to the old identity are void and must be requested again; %d queued envelope(s) dropped; %d request(s) from it closed\n",
						res.VoidedSlots, res.DroppedEnvelopes, res.ClosedRequests)
				}
				return nil
			})
		},
	}
}

func (a *app) partyRotationRejectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reject NAME",
		Short: "Drop an announcement; the enrollment stays as it is",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.party(cmd, nil, []Need{CapClock}, func(ctx context.Context, r *partyRun) error {
				if err := r.node().RejectRotation(ctx, args[0]); err != nil {
					return rotationErr(err, args[0])
				}
				fmt.Fprintf(a.d.Out, "Dropped the announcement of %s. Its enrollment is unchanged.\n", strconv.Quote(args[0]))
				return nil
			})
		},
	}
}

func rotationErr(err error, name string) error {
	switch {
	case errors.Is(err, multisig.ErrNoRotation):
		return fmt.Errorf("no announcement is waiting for %q: see spo party rotation list", name)
	case errors.Is(err, ports.ErrNotFound):
		return fmt.Errorf("no party named %q: see spo party list", name)
	}
	return err
}
