// Package assets holds the use cases of native assets: minting policies, and
// the mint and burn of tokens under them. The use cases share the transaction
// pipeline of txflow.
package assets

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

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
// the policy id (upstream 10_genPolicy, software keys). The signing key goes
// into the store; a hardware holder is refused up front by the generation
// plan. The four artefacts are written together or not at all (SPO-10-INV-005
// upstream leaves a half-written policy that blocks the name).
type GeneratePolicy struct {
	Store    ports.Store
	KeyGen   ports.PaymentKeyGenerator
	Policies ports.PolicyIDCalculator
	// Tip is read only for a policy with a lifetime.
	Tip ports.TipReader
}

// GeneratePolicyRequest names the policy. Lifetime is in slots; zero means
// unlimited (SPO-10-IF-003).
type GeneratePolicyRequest struct {
	Name     string
	Holder   custody.Holder // empty means the vault
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
	ref := ports.Ref{Name: s, Kind: ports.PolicyVKey}
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
	if _, err := custody.PlanGeneration(custody.KeyRef{Role: custody.RolePolicy, Holder: req.Holder, Owner: name}); err != nil {
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
	check := func(r ports.Reader) error {
		for _, k := range []ports.Kind{ports.PolicyVKey, ports.PolicySKey, ports.PolicyHwsFile, ports.PolicyScript, ports.PolicyID} {
			ref := ports.Ref{Name: name, Kind: k}
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
	pair, err := uc.KeyGen.GeneratePayment(ctx)
	if err != nil {
		return PolicyGenerated{}, fmt.Errorf("generate the policy key: %w", err)
	}
	defer pair.SKey.Destroy()
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
	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := check(w); err != nil {
			return err
		}
		if err := w.Put(ports.Ref{Name: name, Kind: ports.PolicyVKey}, pair.VKey); err != nil {
			return err
		}
		if err := w.PutSecret(ports.Ref{Name: name, Kind: ports.PolicySKey}, pair.SKey); err != nil {
			return err
		}
		if err := w.Put(ports.Ref{Name: name, Kind: ports.PolicyScript}, script); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: name, Kind: ports.PolicyID}, []byte(idHex+"\n"))
	})
	if err != nil {
		return PolicyGenerated{}, err
	}
	return PolicyGenerated{Name: name, PolicyID: idHex, KeyHash: hashHex, Script: script, Expiry: expiry, Limited: limited}, nil
}
