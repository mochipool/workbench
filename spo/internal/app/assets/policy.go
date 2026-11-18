// Package assets holds the use cases of native assets: minting policies, and
// the mint and burn of tokens under them. The use cases share the transaction
// pipeline of txflow.
package assets

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the policy use cases.
var (
	// ErrPolicyExists: an artefact of the policy is already stored
	// (SPO-10-PRE-001).
	ErrPolicyExists = errors.New("artefacts of this policy already exist")
	// ErrBadPolicyName: the policy name is not a plain label.
	ErrBadPolicyName = errors.New("the policy name must be a plain name, letters, digits, '-', '_' and dots")
	// ErrMisconfigured: the composition is wrong (a programming error).
	ErrMisconfigured = errors.New("the asset use case is not wired correctly")
)

// GeneratePolicy creates a minting policy: a payment-type key pair, the
// native script that requires its signature (and optionally a time lock) and
// the policy id (upstream 10_genPolicy). The signing key goes into the store.
// A hardware holder (`hw`) is planned against the device profile and exported
// at 1855H/1815H/0H through Hardware; with no Hardware wired it is refused up
// front by the generation plan. When PolicyIDer is wired the policy id of a
// hardware policy is the device's answer (SPO-10-EXT-005), checked against the
// id computed from the script. The four artefacts are written together or not at all (SPO-10-INV-005
// upstream leaves a half-written policy that blocks the name).
type GeneratePolicy struct {
	Store    ports.NamedStore
	KeyGen   ports.PaymentKeyGenerator
	Policies ports.PolicyIDCalculator
	// Tip is read only for a policy with a lifetime.
	Tip ports.TipReader
	// Hardware exports the key of a hardware holder; nil keeps the upfront refusal.
	Hardware ports.HardwareKeyExporter
	// PolicyIDer asks the device for the policy id of a hardware policy; nil
	// uses the id computed from the script.
	PolicyIDer ports.HardwarePolicyIDer
}

// GeneratePolicyRequest names the policy. Lifetime is in slots; zero means
// unlimited (SPO-10-IF-003).
type GeneratePolicyRequest struct {
	Name     string
	Place    custody.Placement // empty means the vault
	Lifetime uint64
}

// PolicyGenerated is the result. It carries no signing key.
type PolicyGenerated struct {
	Name     string
	PolicyID string // hex
	KeyHash  string // hex
	Script   []byte
	// Expiry is the slot of the time lock; Limited is false for an unlimited policy.
	Expiry  uint64
	Limited bool
}

// PolicyName checks a policy name: a plain label with no directory part (a
// store name, hazard H7; upstream allowed `assets/mypolicy`).
func PolicyName(s string) (string, error) {
	ref := ports.NamedRef{Name: s, Kind: ports.PolicyVKey}
	if err := ref.Validate(); err != nil {
		return "", fmt.Errorf("%w: %q", ErrBadPolicyName, s)
	}
	return s, nil
}

// Run creates the policy.
//
// spec: SPO-10-IF-001, SPO-10-IF-003, SPO-10-INV-002, SPO-10-PRE-001, SPO-10-EXT-001, SPO-10-OUT-002,
// spec: SPO-10-EXT-003, SPO-10-OUT-005, SPO-10-EXT-004, SPO-10-OUT-006, SPO-10-INV-005, SPO-10-MODE-001
func (uc GeneratePolicy) Run(ctx context.Context, req GeneratePolicyRequest) (PolicyGenerated, error) {
	name, err := PolicyName(req.Name)
	if err != nil {
		return PolicyGenerated{}, err
	}
	// Hardware (and any other non-vault holder) is refused before anything
	// is read or written (ADR 0008).
	onDevice := req.Place == custody.PlaceHardware
	if _, err := hwkeys.Plan(uc.Hardware, req.Place, custody.RolePolicy); err != nil {
		return PolicyGenerated{}, err
	}
	// The expiry is computed before any side effect, and a failed tip read
	// aborts (upstream goes on with the bare lifetime as the slot,
	// SPO-10-INV-002).
	var expiry uint64
	limited := req.Lifetime > 0
	if limited {
		if uc.Tip == nil {
			return PolicyGenerated{}, fmt.Errorf("%w: a policy with a lifetime needs the current slot", ErrMisconfigured)
		}
		tip, err := uc.Tip.Tip(ctx)
		if err != nil {
			return PolicyGenerated{}, fmt.Errorf("current slot: %w", err)
		}
		if tip.Slot > ^uint64(0)-req.Lifetime {
			return PolicyGenerated{}, txbuild.ErrOverflow
		}
		expiry = tip.Slot + req.Lifetime
	}
	check := func(r ports.NamedReader) error {
		for _, k := range []ports.Kind{ports.PolicyVKey, ports.PolicySKey, ports.PolicyHwsFile, ports.PolicyScript, ports.PolicyID} {
			ref := ports.NamedRef{Name: name, Kind: k}
			ok, err := r.Exists(ref)
			if err != nil {
				return err
			}
			if ok {
				return fmt.Errorf("%w: %s", ErrPolicyExists, ref)
			}
		}
		return nil
	}
	if err := uc.Store.View(ctx, check); err != nil {
		return PolicyGenerated{}, err
	}
	var pair ports.KeyPair
	var hwsfile []byte
	if onDevice {
		// spec: SPO-10-EXT-002, SPO-10-OUT-004
		hk, err := hwkeys.Export(ctx, uc.Hardware, custody.RolePolicy, hwkeys.Options{})
		if err != nil {
			return PolicyGenerated{}, err
		}
		pair.VKey, hwsfile = hk.VKey, hk.SigningFile
	} else {
		var err error
		if pair, err = uc.KeyGen.GeneratePayment(ctx); err != nil {
			return PolicyGenerated{}, fmt.Errorf("generate the policy key: %w", err)
		}
		defer pair.SKey.Destroy()
	}
	env, err := pool.ParseEnvelope(pair.VKey)
	if err != nil {
		return PolicyGenerated{}, err
	}
	raw, err := env.Key32()
	if err != nil {
		return PolicyGenerated{}, err
	}
	hash := txbuild.HashKey(raw)
	hashHex := hex.EncodeToString(hash[:])
	script := assets.PolicyScript(hashHex, expiry, limited)
	id, err := uc.Policies.PolicyID(script)
	if err != nil {
		return PolicyGenerated{}, fmt.Errorf("the policy id: %w", err)
	}
	idHex := hex.EncodeToString(id[:])
	askDevice := onDevice && uc.PolicyIDer != nil
	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		if err := check(w); err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: name, Kind: ports.PolicyVKey}, pair.VKey); err != nil {
			return err
		}
		if onDevice {
			if err := w.Put(ports.NamedRef{Name: name, Kind: ports.PolicyHwsFile}, hwsfile); err != nil {
				return err
			}
		} else if err := w.PutSecret(ports.NamedRef{Name: name, Kind: ports.PolicySKey}, pair.SKey); err != nil {
			return err
		}
		if err := w.Put(ports.NamedRef{Name: name, Kind: ports.PolicyScript}, script); err != nil {
			return err
		}
		if askDevice {
			return nil // the id file follows the device's answer
		}
		return w.Put(ports.NamedRef{Name: name, Kind: ports.PolicyID}, []byte(idHex+"\n"))
	})
	if err != nil {
		return PolicyGenerated{}, err
	}
	if askDevice {
		// spec: SPO-10-EXT-005. The device reads the signing file and the script
		// from the store, so it can only be asked once they are stored; a
		// disagreement or a failure takes the artefacts away again, so no
		// half-written policy blocks the name.
		undo := func() {
			_ = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
				for _, k := range []ports.Kind{ports.PolicyVKey, ports.PolicyHwsFile, ports.PolicyScript} {
					_ = w.Delete(ports.NamedRef{Name: name, Kind: k})
				}
				return nil
			})
		}
		kh, perr := ports.IdentityOfVKey(custody.RolePolicy, pair.VKey)
		if perr != nil {
			undo()
			return PolicyGenerated{}, perr
		}
		pk, perr := custody.As[custody.Policy](custody.KeyRef{Role: custody.RolePolicy, Identity: kh})
		if perr != nil {
			undo()
			return PolicyGenerated{}, perr
		}
		devID, derr := uc.PolicyIDer.PolicyID(ctx, pk, script)
		if derr != nil {
			undo()
			return PolicyGenerated{}, fmt.Errorf("the device's policy id: %w", derr)
		}
		if devID != idHex {
			undo()
			return PolicyGenerated{}, fmt.Errorf("the device answered policy id %s, the script's is %s: nothing was stored", devID, idHex)
		}
		if err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: name, Kind: ports.PolicyID}, []byte(devID+"\n"))
		}); err != nil {
			return PolicyGenerated{}, err
		}
	}
	return PolicyGenerated{Name: name, PolicyID: idHex, KeyHash: hashHex, Script: script, Expiry: expiry, Limited: limited}, nil
}
