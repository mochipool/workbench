package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// hardwareUntested is said in the help of every command that can use a device.
const hardwareUntested = "The hardware wallet path has been tested only against a stand-in tool, not a real Ledger, Trezor or Keystone: see docs/development/hardware-device-checklist.md before relying on it."

// unrestrictedHelp is the help of --allow-unrestricted.
const unrestrictedHelp = "ask to let the hardware wallet sign in unrestricted mode, in which the device cannot check what a certificate or vote does for its own keys (a hardware key paying for a DRep or vote it does not own). The flag allows nothing by itself: you are asked to confirm at the terminal (default No), and --yes does not answer that question"

type hwOpt int

const (
	hwAccount hwOpt = 1 << iota
	hwIndex
	hwMultisig
	hwHybrid
)

// hardwareFlags are the flags of a key-generation command that can put the key
// on a hardware wallet. Nothing is on by default.
type hardwareFlags struct {
	on       bool
	account  uint32
	index    uint32
	multisig bool
	hybrid   bool
	opts     hwOpt
}

func (h *hardwareFlags) add(cmd *cobra.Command, opts hwOpt) {
	h.opts = opts
	f := cmd.Flags()
	f.BoolVar(&h.on, "hardware", false, "make the key on a hardware wallet (Ledger, Trezor or Keystone, as the device allows); only its public key and path are stored")
	if opts&hwAccount != 0 && f.Lookup("account") == nil {
		f.Uint32Var(&h.account, "account", 0, "account number of the hardware derivation path")
	}
	if opts&hwIndex != 0 && f.Lookup("index") == nil {
		f.Uint32Var(&h.index, "index", 0, "index of the hardware derivation path")
	}
	if opts&hwMultisig != 0 {
		f.BoolVar(&h.multisig, "multisig", false, "use the multi-signature purpose (1854H) for the hardware payment key")
	}
	if opts&hwHybrid != 0 {
		f.BoolVar(&h.hybrid, "hybrid", false, "hardware payment key with a stake key kept in the workspace (needs --stake)")
	}
}

func (h *hardwareFlags) holder() custody.Holder {
	if h.on {
		return custody.HolderHardware
	}
	return ""
}

// validate refuses a hardware-only flag given without --hardware. The names
// are the flags the command registered itself, which it checks separately.
func (h *hardwareFlags) validate(cmd *cobra.Command, shared ...string) error {
	if h.on {
		return nil
	}
	var bad []string
	for _, n := range []string{"multisig", "hybrid"} {
		if f := cmd.Flags().Lookup(n); f != nil && f.Changed {
			bad = append(bad, "--"+n)
		}
	}
	for _, n := range shared {
		if f := cmd.Flags().Lookup(n); f != nil && f.Changed {
			bad = append(bad, "--"+n)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s select a hardware key: add --hardware", strings.Join(bad, ", "))
	}
	return nil
}

// noteDevice tells the operator the next step is on the device.
func (a *app) noteDevice() {
	fmt.Fprintln(a.d.Err, "Using the hardware wallet: confirm on the device when it asks.")
}

// ErrUnrestrictedDeclined: the operator did not allow unrestricted mode.
var ErrUnrestrictedDeclined = errors.New("unrestricted mode was not allowed")

// unrestrictedConsent turns the flag into consent only when the operator
// answers yes to a question that says what the mode means (default No). It is
// asked once the needs are met and before the use case runs, and nothing else
// (--yes included) answers it. Without the flag it is never asked and the
// request never carries the consent.
func (a *app) unrestrictedConsent(ctx context.Context, flag bool) (bool, error) {
	if !flag {
		return false, nil
	}
	fmt.Fprintln(a.d.Out, "Unrestricted mode: the hardware wallet will sign a transaction whose certificates or votes it cannot check against its own keys,\n"+
		"so the device cannot tell you whether they do what you intend. Only the amounts and addresses it can parse are checked on its screen.\n"+
		"Allow it only if you have read the summary of this transaction yourself.")
	ans, err := a.term.ReadLine(ctx, "Allow unrestricted mode for this transaction? [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on: unrestricted mode is never allowed by a flag or --yes alone, answer at the terminal")
	}
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans == "y" || ans == "yes" {
		return true, nil
	}
	return false, fmt.Errorf("%w: nothing was signed, submitted or queued", ErrUnrestrictedDeclined)
}
