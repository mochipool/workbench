package txflow

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type poolSigner struct{ profile custody.Profile }

func (s poolSigner) Profile() custody.Profile { return s.profile }
func (s poolSigner) Witness(_ context.Context, k custody.KeyRef, b txbuild.TxBody) (txbuild.Witness, error) {
	var w txbuild.Witness
	w.VKey[0], w.Signature[0] = k.Identity.Hash()[0], b.ID[0]
	return w, nil
}

// tkey is a key reference whose identity says, in its first byte, which test
// signer answers: unservedTag is a key no connected signer holds.
func tkey(role custody.Role, tag byte) custody.KeyRef {
	h := make([]byte, 28)
	h[0] = tag
	id, err := identity.NewRef(identity.KindKeyHash, h)
	if err != nil {
		panic(err)
	}
	return custody.KeyRef{Role: role, Identity: id}
}

const unservedTag = 0xee

func unserved(k custody.KeyRef) bool {
	h := k.Identity.Hash()
	return len(h) > 0 && h[0] == unservedTag
}

type pdir struct{ s poolSigner }

func (d pdir) SignerFor(k custody.KeyRef) (ports.Signer, error) {
	if unserved(k) {
		return nil, errors.New("no signer for " + k.String())
	}
	return d.s, nil
}

// Connected implements ports.SignerDirectory.
func (d pdir) Connected(k custody.KeyRef) ([]ports.ConnectedSigner, error) {
	return ports.ConnectedVia(d, k)
}

func poolDraft() txbuild.Draft {
	return txbuild.Draft{Certificates: []stake.Certificate{{Spec: stake.Spec{Kind: stake.CertPoolRegistration, Deposit: 5}}}}
}

// A pool registration is witnessed by the operator and by the owners, and a
// device signs those in different modes, so the draft reports both features
// and each slot demands its own. A pool certificate names no stake key of its
// own.
//
// spec: SPO-Ptx-INV-006, SPO-Xparty-PRE-003
func TestPreparePartialLeavesRemoteSlotsPending(t *testing.T) {
	deviceOnlyOwner := custody.NewProfile("device").AllowTx(custody.RoleStake, custody.FeatPoolRegistrationOwner)
	vault := custody.NewProfile("vault").
		Allow(custody.RolePoolCold, custody.OpWitnessTx).Allow(custody.RolePayment, custody.OpWitnessTx).Allow(custody.RoleStake, custody.OpWitnessTx)
	_ = deviceOnlyOwner
	p := Pipeline{Signers: pdir{poolSigner{profile: vault}}}
	feats, err := poolDraft().Features()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := feats[custody.FeatPoolRegistrationOper]; !ok {
		t.Error("operator feature")
	}
	if _, ok := feats[custody.FeatPoolRegistrationOwner]; !ok {
		t.Error("owner feature")
	}
	if got := poolDraft().RequiredStakeKeys(); len(got) != 0 {
		t.Errorf("a pool certificate requires no stake key: %v", got)
	}
	slots := []Slot{
		{Label: "cold", Key: tkey(custody.RolePoolCold, 1)},
		{Label: "pay", Key: tkey(custody.RolePayment, 2)},
		{Label: "owner", Key: tkey(custody.RoleStake, unservedTag), Party: party.Fingerprint{9}},
	}
	// A key no connected signer holds refuses up front without PreparePartial...
	if _, err := p.Prepare(poolDraft(), slots, 3); err == nil {
		t.Fatal("a key with no signer was planned")
	}
	// ...and is pending with it. The witness count is the fee's, not the local count.
	prep, err := p.PreparePartial(poolDraft(), slots, 3, true)
	if err != nil || len(prep.Pending) != 1 || prep.Pending[0].Label != "owner" {
		t.Fatalf("%+v %v", prep, err)
	}
	if _, err := p.PreparePartial(poolDraft(), slots, 2, false); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("the count must be the fee's: %v", err)
	}
	// Only the local slots are signed.
	sws, err := prep.Sign(context.Background(), txbuild.TxBody{ID: chain.TxID{7}})
	if err != nil || len(sws) != 2 || sws[0].Slot.Label != "cold" || sws[1].Slot.Label != "pay" {
		t.Errorf("%v %v", sws, err)
	}
	// All remote: no plan, nothing to sign.
	none, err := p.PreparePartial(poolDraft(), slots[2:], 1, true)
	if err != nil || len(none.Pending) != 1 {
		t.Fatalf("%v", err)
	}
	if sws, err := none.Sign(context.Background(), txbuild.TxBody{}); err != nil || len(sws) != 0 {
		t.Errorf("%v %v", sws, err)
	}
	// A slot's own features replace the draft's: a signer that can only do the owner mode serves the owner slot.
	ownerOnly := custody.NewProfile("o").AllowTx(custody.RoleStake, custody.FeatPoolRegistrationOwner)
	po := Pipeline{Signers: pdir{poolSigner{profile: ownerOnly}}}
	s := []Slot{{Label: "owner", Key: tkey(custody.RoleStake, 3),
		Features: custody.NewFeatures(custody.FeatPoolRegistrationOwner)}}
	if _, err := po.Prepare(poolDraft(), s, 1); err != nil {
		t.Errorf("the owner slot asks for the owner mode only: %v", err)
	}
	s[0].Features = nil
	if _, err := po.Prepare(poolDraft(), s, 1); err == nil {
		t.Error("the owner-only signer cannot take the operator feature of the full draft")
	}
}

// spec: SPO-Ptx-PR-002, SPO-Ptx-PR-003, SPO-Ptx-PRE-007
func TestConfirmAndDeliverAreTheTwoHalvesOfExecute(t *testing.T) {
	p := Pipeline{Approval: ApprovalSkip}
	if skipped, err := p.Confirm(context.Background(), Input{}, Built{}); err != nil || !skipped {
		t.Errorf("skip: %v %v", skipped, err)
	}
	p.Approval = ApprovalAsk
	if _, err := p.Confirm(context.Background(), Input{}, Built{}); !errors.Is(err, ErrNoConfirmer) {
		t.Errorf("%v", err)
	}
	p.Approval = 9
	if _, err := p.Confirm(context.Background(), Input{}, Built{}); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("%v", err)
	}
	if _, err := (Pipeline{}).Deliver(context.Background(), Input{}, txbuild.TxBody{}, nil, nil, false); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("an unwired pipeline: %v", err)
	}
	var _ ports.TxWitnesser = poolSigner{}
}

// A device witness is told only change keys that are on a device: a vault payer
// key beside a device signer is not declared (it has no hardware file there).
//
// spec: SPO-Ptx-INV-009
func TestDeviceChangeKeysSkipVaultKeys(t *testing.T) {
	vaultKey, deviceKey := tkey(custody.RolePayment, 1), tkey(custody.RolePayment, 2)
	dir := ports.SignerFunc(func(k custody.KeyRef) (ports.Signer, error) {
		if k == deviceKey {
			return hwStub{}, nil
		}
		return poolSigner{}, nil
	})
	p := Pipeline{Signers: dir}
	in := Input{HardwareChangeKeys: []custody.KeyRef{vaultKey, deviceKey}}
	two := txbuild.BodySpec{Outputs: make([]txbuild.Output, 2)}
	if got := p.DeviceChangeKeys(in, two); len(got) != 1 || got[0] != deviceKey {
		t.Errorf("change keys %v, want only the device key", got)
	}
	if got := p.DeviceChangeKeys(in, txbuild.BodySpec{Outputs: make([]txbuild.Output, 1)}); len(got) != 0 {
		t.Errorf("one output declares none: %v", got)
	}
}

// hwStub is a signer that takes the options of a device witness.
type hwStub struct{ poolSigner }

func (hwStub) WitnessWith(context.Context, custody.KeyRef, txbuild.TxBody, ports.HardwareTxOptions) (txbuild.Witness, error) {
	return txbuild.Witness{}, nil
}
