package txflow

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type signer struct{ profile custody.Profile }

func (s signer) Profile() custody.Profile { return s.profile }

type dir struct{ s signer }

func (d dir) SignerFor(k custody.KeyRef) (ports.Signer, error) {
	if k.Holder == custody.HolderHardware {
		return nil, errors.New("no hardware signer")
	}
	return d.s, nil
}

func draft(k stake.KeyHash) txbuild.Draft {
	return txbuild.Draft{Certificates: []stake.Certificate{{Spec: stake.Spec{Kind: stake.CertPoolDelegation, Stake: k}}}}
}

// The plan is made before the body: the count of signatures must be the
// workflow's fixed witness count, every stake key the ledger requires needs a
// slot, and a holder without a signer (hardware today) is refused. A signer
// that cannot witness transactions (it has no TxWitnesser) is refused too.
//
// spec: SPO-Ptx-INV-006, SPO-Ptx-PRE-006
func TestPrepareChecksTheSlots(t *testing.T) {
	var k, other stake.KeyHash
	k[0], other[0] = 1, 2
	prof := custody.NewProfile("fake").AllowTx(custody.RolePayment, custody.FeatStakeDelegation).AllowTx(custody.RoleStake, custody.FeatStakeDelegation)
	p := Pipeline{Signers: dir{signer{prof}}}
	pay := Slot{Label: "payment", Key: custody.KeyRef{Role: custody.RolePayment, Holder: custody.HolderVault, Owner: "w"}}
	stk := Slot{Label: "stake", Key: custody.KeyRef{Role: custody.RoleStake, Holder: custody.HolderVault, Owner: "w"}, Hash: txbuild.KeyHash(k)}

	// A plan whose signers cannot witness (no TxWitnesser): refused as such.
	if _, err := p.Prepare(draft(k), []Slot{pay, stk}, 2); !errors.Is(err, ErrNoSigner) {
		t.Errorf("%v", err)
	}
	for name, c := range map[string]struct {
		slots []Slot
		n     uint
		want  error
	}{
		"one slot for two witnesses":                   {[]Slot{pay}, 2, ErrMisconfigured},
		"no slot for the required stake key":           {[]Slot{pay, {Label: "stake", Key: stk.Key, Hash: txbuild.KeyHash(other)}}, 2, ErrMisconfigured},
		"a payment slot standing in for the stake key": {[]Slot{pay, {Label: "x", Key: pay.Key, Hash: txbuild.KeyHash(k)}}, 2, ErrMisconfigured},
	} {
		if _, err := p.Prepare(draft(k), c.slots, c.n); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	hw := stk
	hw.Key.Holder = custody.HolderHardware
	if _, err := p.Prepare(draft(k), []Slot{pay, hw}, 2); err == nil {
		t.Error("a hardware holder was planned")
	}
}

// Exactly one route, and the ports a transaction needs.
func TestPipelineCheck(t *testing.T) {
	if err := (Pipeline{}).Check(); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("%v", err)
	}
	if (Pipeline{Queue: noQueue{}}).Route() != "queue" || (Pipeline{}).Route() != "submit" {
		t.Error("route")
	}
}

type noQueue struct{}

func (noQueue) Enqueue(context.Context, ports.QueuedTx) error { return nil }
