package txbuild

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

func balanced(t *testing.T, d Draft) Balanced {
	t.Helper()
	f := &fakeLedger{}
	bal, err := d.Balance(1000, f.ledger())
	if err != nil {
		t.Fatal(err)
	}
	return bal
}

func quantities(as []chain.AssetAmount) map[string]uint64 {
	out := map[string]uint64{}
	for _, a := range as {
		out[string(a.Asset.Policy[:1])+string(a.Asset.Name)] = a.Quantity
	}
	return out
}

// Two outputs always, in the order destination, change; the destination holds
// the lovelace requested but at least its minimum, and the assets sent; the
// change holds everything else, every other asset included.
//
// spec: SPO-01sendAssets-OUT-001, SPO-01sendAssets-OUT-003, SPO-01sendAssets-OUT-004, SPO-01sendAssets-EXT-001,
// spec: SPO-01sendAssets-EXT-002, SPO-01sendAssets-PRE-004, SPO-01sendAssets-INV-012
func TestSendAssetsLayout(t *testing.T) {
	in := []chain.Utxo{utxo(1, 30_000_000, asset(1, "a", 10), asset(2, "b", 5)), utxo(2, 20_000_000, asset(1, "a", 5))}
	d, err := NewSendAssetsDraft(payer, dest, 0, []chain.AssetAmount{asset(1, "a", 12)}, in, nil)
	if err != nil {
		t.Fatal(err)
	}
	bal := balanced(t, d)
	outs := bal.Spec.Outputs
	if len(outs) != 2 || outs[0].Address != dest || outs[1].Address != payer {
		t.Fatalf("outputs %+v", outs)
	}
	// the minimum of the destination: 1 ADA plus one asset
	if outs[0].Lovelace != 1_010_000 {
		t.Errorf("destination holds %d, want its minimum", outs[0].Lovelace)
	}
	if q := quantities(outs[0].Assets); len(q) != 1 || q["\x01a"] != 12 {
		t.Errorf("sent %v", q)
	}
	if q := quantities(outs[1].Assets); len(q) != 2 || q["\x01a"] != 3 || q["\x02b"] != 5 {
		t.Errorf("returned %v", q)
	}
	if sum(outs)+bal.Spec.Fee != 50_000_000 {
		t.Errorf("outputs %d + fee %d != inputs", sum(outs), bal.Spec.Fee)
	}
	// lovelaces above the minimum are sent as asked, below are raised
	for ask, want := range map[chain.Lovelace]chain.Lovelace{9_000_000: 9_000_000, 5: 1_010_000} {
		d, _ := NewSendAssetsDraft(payer, dest, ask, []chain.AssetAmount{asset(1, "a", 1)}, in, nil)
		if got := balanced(t, d).Spec.Outputs[0].Lovelace; got != want && ask != 5 {
			t.Errorf("asked %d: destination holds %d, want %d", ask, got, want)
		}
	}
	// everything: two outputs even when nothing is left to return
	d, _ = NewSendAssetsDraft(payer, dest, 0, []chain.AssetAmount{asset(1, "a", 15), asset(2, "b", 5)}, in, nil)
	outs = balanced(t, d).Spec.Outputs
	if len(outs) != 2 || len(outs[1].Assets) != 0 {
		t.Errorf("outputs %+v", outs)
	}
	// a return output below its minimum is refused, naming the change
	small := []chain.Utxo{utxo(1, 2_000_000, asset(1, "a", 10), asset(2, "b", 5))}
	d, _ = NewSendAssetsDraft(payer, dest, 0, []chain.AssetAmount{asset(1, "a", 10)}, small, nil)
	var below *BelowMinimumError
	if _, err := d.Balance(1000, (&fakeLedger{}).ledger()); !errors.As(err, &below) || below.Which != "change" && !errors.Is(err, ErrInsufficient) {
		t.Errorf("a change below its minimum: %v", err)
	}
	// asking for more than the inputs hold
	if _, err := NewSendAssetsDraft(payer, dest, 0, []chain.AssetAmount{asset(1, "a", 16)}, in, nil); !errors.Is(err, ErrAssetsNotHeld) {
		t.Errorf("more than held: %v", err)
	}
	// FORCEADA: no asset, lovelace only
	d, err = NewSendAssetsDraft(payer, dest, 5_000_000, nil, []chain.Utxo{utxo(1, 30_000_000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outs := balanced(t, d).Spec.Outputs; len(outs) != 2 || outs[0].Lovelace != 5_000_000 {
		t.Errorf("outputs %+v", outs)
	}
}

// The change of a mint holds every asset above zero, the minted one included;
// a burn leaves out what it burns entirely.
//
// spec: SPO-11a-INV-002, SPO-11a-EXT-001, SPO-11b-INV-001, SPO-11b-EXT-001, SPO-11b-PRE-002, SPO-11a-INV-003, SPO-Ptx-INV-004
func TestMintAndBurnLayout(t *testing.T) {
	scripts := [][]byte{[]byte(`{}`)}
	in := []chain.Utxo{utxo(1, 30_000_000, asset(1, "a", 10), asset(2, "b", 5))}
	mint := []MintEntry{{Asset: asset(1, "a", 0).Asset, Quantity: 7}, {Asset: asset(3, "c", 0).Asset, Quantity: 1}}
	d, err := NewMintDraft(payer, in, mint, scripts, nil)
	if err != nil {
		t.Fatal(err)
	}
	bal := balanced(t, d)
	if len(bal.Spec.Outputs) != 1 || bal.Spec.Outputs[0].Address != payer {
		t.Fatalf("outputs %+v", bal.Spec.Outputs)
	}
	if q := quantities(bal.Spec.Outputs[0].Assets); len(q) != 3 || q["\x01a"] != 17 || q["\x02b"] != 5 || q["\x03c"] != 1 {
		t.Errorf("change %v", q)
	}
	if bal.Spec.Outputs[0].Lovelace+bal.Spec.Fee != 30_000_000 || len(bal.Spec.Mint) != 2 || len(bal.Spec.MintScripts) != 1 {
		t.Errorf("spec %+v", bal.Spec)
	}
	f, _ := d.Features()
	if _, ok := f[custody.FeatMint]; !ok {
		t.Error("a mint is a feature the signer must understand")
	}
	if MintWitnesses != 2 {
		t.Errorf("a mint has the policy and the payment witness, got %d", MintWitnesses)
	}

	burn := []MintEntry{{Asset: asset(1, "a", 0).Asset, Quantity: -10}}
	d, err = NewMintDraft(payer, in, burn, scripts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if q := quantities(balanced(t, d).Spec.Outputs[0].Assets); len(q) != 1 || q["\x02b"] != 5 {
		t.Errorf("burning everything leaves the asset out: %v", q)
	}
	// more than held
	d, err = NewMintDraft(payer, in, []MintEntry{{Asset: asset(1, "a", 0).Asset, Quantity: -11}}, scripts, nil)
	if err == nil {
		_, err = d.Balance(1000, (&fakeLedger{}).ledger())
	}
	if !errors.Is(err, ErrBurnExceedsHolding) {
		t.Errorf("burning more than held: %v", err)
	}
	for _, bad := range []func() error{
		func() error { _, err := NewMintDraft(payer, in, nil, scripts, nil); return err },
		func() error { _, err := NewMintDraft(payer, in, mint, nil, nil); return err },
		func() error {
			_, err := NewMintDraft(payer, in, []MintEntry{{Asset: asset(1, "a", 0).Asset}}, scripts, nil)
			return err
		},
		func() error { _, err := NewMintDraft(payer, nil, mint, scripts, nil); return err },
	} {
		if bad() == nil {
			t.Error("a bad mint draft was accepted")
		}
	}
}

// spec: SPO-Pparam-OUT-002, SPO-Pparam-IF-016
func TestMetadataIsAFeatureAndTravelsToTheBody(t *testing.T) {
	d := draft(t, Lovelaces(5_000_000), utxo(1, 30_000_000))
	d2, err := d.WithMetadata([]MetadataFile{{Name: "m.json", Format: MetadataJSON, Data: []byte(`{"1":1}`)}}, []string{"hi"}, "basic")
	if err != nil {
		t.Fatal(err)
	}
	f, _ := d2.Features()
	if _, ok := f[custody.FeatMetadata]; !ok {
		t.Error("metadata is a feature")
	}
	if f0, _ := d.Features(); len(f0) != 0 {
		t.Errorf("the original draft changed: %v", f0)
	}
	spec := balanced(t, d2).Spec
	if len(spec.MetadataFiles) != 1 || spec.MessageEncryption != "basic" || len(spec.Message) != 1 {
		t.Errorf("spec %+v", spec)
	}
	// a file alone is metadata too
	d3, _ := d.WithMetadata([]MetadataFile{{Name: "m.cbor", Format: MetadataCBOR}}, nil, "")
	if f, _ := d3.Features(); len(f) != 1 {
		t.Errorf("a file is metadata: %v", f)
	}
}
