package txbuild

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

func poolCerts(deposit chain.Lovelace) []stake.Certificate {
	return []stake.Certificate{
		{Spec: stake.Spec{Kind: stake.CertPoolRegistration, Pool: chain.PoolID{1}, Deposit: deposit}, CBOR: []byte{1}},
		{Spec: stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash{5}, Pool: chain.PoolID{1}}, CBOR: []byte{2}},
	}
}

// A registration draft pays the pool deposit out of the change, reports both
// pool features, requires the owner's stake key through its delegation
// certificate only, and describes itself for the operator.
//
// spec: SPO-05c-INV-009, SPO-05c-INV-017, SPO-Ptx-INV-007, SPO-07b-INV-002
func TestPoolRegistrationDraft(t *testing.T) {
	inputs := []chain.Utxo{{Lovelace: 1_000_000_000}}
	d, err := NewCertificateDraft("addr", inputs, poolCerts(500_000_000), nil)
	if err != nil {
		t.Fatal(err)
	}
	if dep, _ := d.Deposits(); dep != 500_000_000 {
		t.Errorf("deposit %d", dep)
	}
	outs, err := d.layout(200_000, func(Output) (chain.Lovelace, error) { return 1_000_000, nil }, true)
	if err != nil || len(outs) != 1 || outs[0].Lovelace != 1_000_000_000-500_000_000-200_000 {
		t.Errorf("%+v %v", outs, err)
	}
	fs, _ := d.Features()
	for _, f := range []custody.Feature{custody.FeatPoolRegistrationOper, custody.FeatPoolRegistrationOwner, custody.FeatStakeDelegation} {
		if _, ok := fs[f]; !ok {
			t.Errorf("missing feature %s", f)
		}
	}
	if keys := d.RequiredStakeKeys(); len(keys) != 1 || keys[0] != (stake.KeyHash{5}) {
		t.Errorf("%v", keys)
	}
	lines := d.AttachmentLines()
	if len(lines) != 2 || !strings.Contains(lines[0], "pool registration") || !strings.Contains(lines[0], "500000000") {
		t.Errorf("%v", lines)
	}
	// An update pays nothing and says so.
	d, _ = NewCertificateDraft("addr", inputs, poolCerts(0), nil)
	if dep, _ := d.Deposits(); dep != 0 || !strings.Contains(d.AttachmentLines()[0], "re-registration") {
		t.Errorf("%v", d.AttachmentLines())
	}
	// A retirement has its own feature and line, and no balance effect.
	ret := []stake.Certificate{{Spec: stake.Spec{Kind: stake.CertPoolRetirement, Pool: chain.PoolID{1}, Epoch: 12}, CBOR: []byte{3}}}
	d, _ = NewCertificateDraft("addr", inputs, ret, nil)
	fs, _ = d.Features()
	if _, ok := fs[custody.FeatPoolRetirement]; !ok || len(d.RequiredStakeKeys()) != 0 || !strings.Contains(d.AttachmentLines()[0], "epoch 12") {
		t.Errorf("%v %v", fs, d.AttachmentLines())
	}
}
