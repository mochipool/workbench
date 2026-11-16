package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Explain wraps err so that it prints as msg and still unwraps to err. The
// composition root uses it for the typed errors of adapters, which this
// package does not import (Deps.MapError).
func Explain(err error, msg string) error {
	if err == nil {
		return nil
	}
	var ex *explained
	if errors.As(err, &ex) {
		return err
	}
	return &explained{msg: msg, err: err}
}

// explained is an error whose message says what happened and what to do. It
// still unwraps to the sentinel, so errors.Is keeps working.
type explained struct {
	msg string
	err error
}

func (e *explained) Error() string { return e.msg }
func (e *explained) Unwrap() error { return e.err }

// ErrOutcomeUnknown: a write may or may not have been stored (the sealed store
// could not read the file back after a failed COMMIT).
var ErrOutcomeUnknown = errors.New("the outcome of the write is unknown")

// MemlockAdvice is the one message for a locked-memory shortage, used by the
// command tree and by main.
const MemlockAdvice = "spo could not lock memory for its secrets. Raise the locked-memory limit and run again: `ulimit -l unlimited` in the shell (or a larger value in KiB), or RLIMIT_MEMLOCK / LimitMEMLOCK in the service or limits.conf that starts spo"

// explain turns the sealed store's sentinel errors into one sentence each.
func explain(err error) error {
	if err == nil {
		return nil
	}
	var ex *explained
	if errors.As(err, &ex) {
		return err // already has its own advice
	}
	var msg string
	switch {
	case errors.Is(err, ErrOutcomeUnknown):
		msg = "the write may or may not have been stored. Run `spo store verify` and check the result before retrying: repeating an operation that did take effect (such as issuing an operational certificate) would apply it twice"
	case errors.Is(err, secret.ErrMemoryLimit):
		msg = MemlockAdvice
	case errors.Is(err, ErrRolledBack):
		msg = "the workspace file is older than the last state recorded for it (workspace.spo.head): it may have been replaced by an older copy, which would silently drop later changes. If you restored an older backup on purpose, run the command again with --accept-rollback (the file's own state is then recorded as the new head). If you did not, do not use this file; restore your newest backup"
	case errors.Is(err, ErrHeadMismatch):
		msg = "the head file (workspace.spo.head) belongs to a different workspace or cannot be read, so the file cannot be checked against its recorded state. If you put a different workspace into this directory on purpose, run the command again with --accept-rollback; otherwise restore the right files together"
	case errors.Is(err, ErrLocked):
		msg = "the workspace is open in another spo process, or is being replaced. Wait for that to finish and run the command again"
	case errors.Is(err, ErrOtherWorkspace):
		msg = "the backup is of a different workspace than the one in this directory; restoring it would replace this workspace with an unrelated one. If that is really what you want, add --allow-other-workspace (this destroys the current workspace; keep a backup of it first)"
	case errors.Is(err, ErrOlderBackup):
		msg = "the backup is older than the workspace, or has diverged from it; restoring it would discard changes made since. If you want that, add --allow-older"
	case errors.Is(err, ErrWrongRecoveryKey):
		msg = "that recovery key does not open this workspace (it may be an older one: every passphrase change or new recovery key revokes the previous key)"
	case errors.Is(err, ErrBadRecoveryKey):
		msg = "that is not a recovery key: it is 14 groups of 4 characters (letters A-Z and digits 2-7), as printed when it was made; dashes and spaces are accepted"
	default:
		return explainHardware(err)
	}
	return &explained{msg: msg, err: err}
}

// explainHardware turns the errors of the hardware path that app and ports
// declare into what to do next. The ones the hardware adapter declares are
// mapped in the composition root (Deps.MapError).
func explainHardware(err error) error {
	var notCanon *ports.ErrNotHardwareCanonical
	var msg string
	switch {
	case errors.Is(err, txflow.ErrNoCanonicalizer), errors.Is(err, ports.ErrNoHardwareSigner):
		msg = err.Error() + "\nThis build cannot drive a hardware wallet: its release set has no cardano-hw-cli (see `spo capabilities`, hardware-wallet). Run the packaged binary (nix run .#spo), or use keys held in the workspace. Nothing was signed, submitted or queued"
	case errors.Is(err, txflow.ErrMixedHolders):
		msg = err.Error() + "\nUse a paying address whose key is on the same device, or keep every key of this transaction in the workspace. Nothing was signed, submitted or queued"
	case errors.Is(err, governance.ErrUnrestrictedNeeded):
		msg = err.Error() + "\nTo allow it, enable expert mode in the device's Cardano app, then run the command again with --allow-unrestricted: you are asked to confirm, and the flag alone does not allow anything. Nothing was signed, submitted or queued"
	case errors.As(err, &notCanon):
		msg = err.Error() + "\nThis is a fault in spo, not something you did wrong: nothing was signed, submitted or queued. Run the command again, and report it (with `spo version`) if it repeats"
	default:
		return err
	}
	return &explained{msg: msg, err: err}
}

// explainAll wraps the RunE of every command under c so each error leaves
// the command tree explained. mapErr, when set, first maps the errors that
// only the composition root can name.
func explainAll(c *cobra.Command, mapErr func(error) error) {
	if c.RunE != nil {
		run := c.RunE
		c.RunE = func(cmd *cobra.Command, args []string) error {
			err := run(cmd, args)
			if err != nil && mapErr != nil {
				err = mapErr(err)
			}
			return explain(err)
		}
	}
	for _, sub := range c.Commands() {
		explainAll(sub, mapErr)
	}
}
