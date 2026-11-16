package txbuild

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

const (
	payer chain.Address = "addr_test_payer"
	dest  chain.Address = "addr_test_dest"
)

func asset(b byte, name string, q uint64) chain.AssetAmount {
	var p [28]byte
	p[0] = b
	return chain.AssetAmount{Asset: chain.AssetID{Policy: p, Name: []byte(name)}, Quantity: q}
}

func utxo(i byte, lovelace uint64, assets ...chain.AssetAmount) chain.Utxo {
	var id chain.TxID
	id[0] = i
	return chain.Utxo{TxID: id, Index: uint32(i), Lovelace: chain.Lovelace(lovelace), Assets: assets}
}

// fakeLedger stands in for the ledger adapter. The minimum output is
// 1 ADA plus 0.01 ADA per asset; the fee is 1000 per CBOR-ish byte so that
// it depends on the size of the body, which the JSON rendering stands for.
type fakeLedger struct{ builds int }

func (f *fakeLedger) ledger() Ledger {
	return Ledger{
		MinOutput: func(o Output) (chain.Lovelace, error) {
			return 1_000_000 + chain.Lovelace(len(o.Assets))*10_000, nil
		},
		Fee: func(b TxBody) (chain.Lovelace, error) { return chain.Lovelace(150_000 + len(b.CBOR)*10), nil },
		Build: func(s BodySpec) (TxBody, error) {
			f.builds++
			b, _ := json.Marshal(s)
			return TxBody{CBOR: b, ID: sha256.Sum256(b)}, nil
		},
	}
}

func draft(t *testing.T, amount Amount, utxos ...chain.Utxo) Draft {
	t.Helper()
	d, err := NewDraft(payer, dest, amount, utxos, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func sum(outs []Output) (n chain.Lovelace) {
	for _, o := range outs {
		n += o.Lovelace
	}
	return
}

// spec: SPO-01sendLovelaces-IF-002
func TestParseAmount(t *testing.T) {
	ok := map[string]Amount{"ALL": All(), "all": All(), "Min": Min(), "allfunds": AllFunds(), "0": Lovelaces(0),
		"5000000": Lovelaces(5_000_000), "18446744073709551615": Lovelaces(math.MaxUint64)}
	for in, want := range ok {
		got, err := ParseAmount(in)
		if err != nil || got != want {
			t.Errorf("ParseAmount(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	// The word is refused before any file or network access: a sign, a
	// decimal point, digit grouping, a blank, whitespace, a Unicode digit.
	for _, in := range []string{"", "-1", "+1", "1.5", "1,000", "1_000", " 1", "1 ", "٣", "ALL ", "everything", "18446744073709551616"} {
		if _, err := ParseAmount(in); !errors.Is(err, ErrBadAmount) {
			t.Errorf("ParseAmount(%q) = %v, want ErrBadAmount", in, err)
		}
	}
	// Decision (IF-002 quirk): upstream reads `010` as octal in its balance
	// and passes the same text to build-raw as decimal. The port refuses a
	// zero-padded amount instead of choosing a base.
	for _, in := range []string{"010", "08", "00"} {
		if _, err := ParseAmount(in); !errors.Is(err, ErrBadAmount) {
			t.Errorf("zero-padded %q accepted: %v", in, err)
		}
	}
}

// spec: SPO-Ptx-INV-002, SPO-Ptx-PRE-001
func TestSelectAllSpendsEveryUtxo(t *testing.T) {
	cands := []chain.Utxo{utxo(1, 5), utxo(2, 6), utxo(3, 7)}
	got, err := SelectAll.Select(cands)
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	got[0].Lovelace = 99
	if cands[0].Lovelace == 99 {
		t.Error("the selection aliases the candidates")
	}
	if _, err := SelectAll.Select(nil); !errors.Is(err, ErrNoFunds) {
		t.Errorf("empty set: %v", err)
	}
	// Hazard H4: the strategy is a value, and only "all" exists.
	if _, err := SelectionStrategy("largest-first").Select(cands); !errors.Is(err, ErrStrategyUnsupported) {
		t.Errorf("unknown strategy: %v", err)
	}
}

// spec: SPO-Ptx-INV-003, SPO-Ptx-INV-004
func TestTotalsMergeAssetsAndCheckOverflow(t *testing.T) {
	tot, err := TotalOf([]chain.Utxo{
		utxo(1, 5, asset(2, "b", 3), asset(1, "a", 4)),
		utxo(2, 6, asset(1, "a", 5), asset(2, "", 0)),
	})
	if err != nil || tot.Lovelace != 11 || len(tot.Assets) != 2 {
		t.Fatalf("%+v %v", tot, err)
	}
	// Ascending by policy; a zero quantity is dropped; equal ids are summed.
	if tot.Assets[0].Asset.Policy[0] != 1 || tot.Assets[0].Quantity != 9 || tot.Assets[1].Quantity != 3 {
		t.Errorf("assets %+v", tot.Assets)
	}
	if _, err := TotalOf([]chain.Utxo{utxo(1, math.MaxUint64), utxo(2, 1)}); !errors.Is(err, ErrOverflow) {
		t.Errorf("lovelace overflow: %v", err)
	}
	if _, err := TotalOf([]chain.Utxo{utxo(1, 1, asset(1, "a", math.MaxUint64)), utxo(2, 1, asset(1, "a", 1))}); !errors.Is(err, ErrOverflow) {
		t.Errorf("asset overflow: %v", err)
	}
}

// spec: SPO-Ptx-INV-001, SPO-Cchain-INV-009
func TestTTL(t *testing.T) {
	if got, err := TTL(chain.Tip{Slot: 128163045}, 0); err != nil || got != 128263045 {
		t.Errorf("default: %d %v", got, err)
	}
	if got, _ := TTL(chain.Tip{Slot: 10}, 5); got != 15 {
		t.Errorf("custom defTTL: %d", got)
	}
	if _, err := TTL(chain.Tip{Slot: math.MaxUint64 - 1}, 100000); !errors.Is(err, ErrOverflow) {
		t.Errorf("overflow: %v", err)
	}
}

// spec: SPO-Ptx-PRE-007
func TestCheckSize(t *testing.T) {
	if err := CheckSize(16384, 16384); err != nil {
		t.Error(err)
	}
	if err := CheckSize(16385, 16384); err == nil {
		t.Error("an oversize transaction was accepted")
	}
}

// spec: SPO-Ptx-INV-004
func TestFeatures(t *testing.T) {
	plain, _ := draft(t, Lovelaces(1), utxo(1, 10_000_000)).Features()
	if len(plain) != 0 {
		t.Errorf("plain payment features: %v", plain)
	}
	d, err := NewDraft(payer, dest, Min(), []chain.Utxo{utxo(1, 10_000_000, asset(1, "a", 1))}, []string{"hi"})
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := d.Features()
	if _, ok := fs[custody.FeatMultiAssetOutput]; !ok {
		t.Error("assets in the inputs need the multi-asset feature, in every amount form")
	}
	if _, ok := fs[custody.FeatMetadata]; !ok {
		t.Error("a message needs the metadata feature")
	}
}

// spec: SPO-Pparam-PRE-001
func TestMessageLimitIsBytesNotCharacters(t *testing.T) {
	line64 := ""
	for i := 0; i < 32; i++ {
		line64 += "é" // 2 bytes each: 32 characters, 64 bytes
	}
	if err := ValidateMessage([]string{line64}); err != nil {
		t.Error(err)
	}
	if err := ValidateMessage([]string{line64 + "a"}); !errors.Is(err, ErrBadMessage) {
		t.Errorf("65 bytes accepted: %v", err)
	}
	if err := ValidateMessage([]string{"\xff"}); !errors.Is(err, ErrBadMessage) {
		t.Errorf("invalid UTF-8 accepted: %v", err)
	}
}

func balance(t *testing.T, d Draft) (Balanced, *fakeLedger, error) {
	t.Helper()
	f := &fakeLedger{}
	b, err := d.Balance(1000, f.ledger())
	return b, f, err
}

// Every amount form: the layout, the fee and the invariant inputs = outputs + fee.
//
// spec: SPO-01sendLovelaces-OUT-001, SPO-01sendLovelaces-OUT-002, SPO-01sendLovelaces-OUT-003, SPO-01sendLovelaces-OUT-004,
// spec: SPO-01sendLovelaces-OUT-005, SPO-01sendLovelaces-OUT-006, SPO-01sendLovelaces-INV-001, SPO-Ptx-INV-004, SPO-Ptx-INV-007
func TestLayouts(t *testing.T) {
	assets := []chain.AssetAmount{asset(1, "a", 5), asset(2, "b", 6)}
	withAssets := []chain.Utxo{utxo(1, 30_000_000, assets[0]), utxo(2, 20_000_000, assets[1])}
	plain := []chain.Utxo{utxo(1, 30_000_000), utxo(2, 20_000_000)}

	type want struct {
		outs       int
		destFirst  chain.Lovelace // 0: not fixed
		destAssets int
		chgAssets  int
	}
	cases := []struct {
		name   string
		amount Amount
		in     []chain.Utxo
		want   want
	}{
		{"ALLFUNDS moves every asset to the destination (OUT-001)", AllFunds(), withAssets, want{1, 0, 2, 0}},
		{"ALL without assets is one output (OUT-002)", All(), plain, want{1, 0, 0, 0}},
		{"ALL with assets returns them to the source (OUT-003)", All(), withAssets, want{2, 0, 0, 2}},
		{"MIN gives the destination the minimum (OUT-004)", Min(), withAssets, want{2, 1_000_000, 0, 2}},
		{"N lovelace (OUT-005)", Lovelaces(7_000_000), withAssets, want{2, 7_000_000, 0, 2}},
		{"N lovelace, no assets", Lovelaces(7_000_000), plain, want{2, 7_000_000, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, err := balance(t, draft(t, tc.amount, tc.in...))
			if err != nil {
				t.Fatal(err)
			}
			outs := b.Spec.Outputs
			if len(outs) != tc.want.outs {
				t.Fatalf("%d outputs: %+v", len(outs), outs)
			}
			// OUT-006: destination first, the source second.
			if outs[0].Address != dest || (len(outs) == 2 && outs[1].Address != payer) {
				t.Errorf("output order: %+v", outs)
			}
			if tc.want.destFirst != 0 && outs[0].Lovelace != tc.want.destFirst {
				t.Errorf("destination holds %d, want %d", outs[0].Lovelace, tc.want.destFirst)
			}
			if len(outs[0].Assets) != tc.want.destAssets {
				t.Errorf("destination has %d assets, want %d", len(outs[0].Assets), tc.want.destAssets)
			}
			if len(outs) == 2 && len(outs[1].Assets) != tc.want.chgAssets {
				t.Errorf("change has %d assets, want %d", len(outs[1].Assets), tc.want.chgAssets)
			}
			// INV-001: inputs = outputs + fee.
			if in := chain.Lovelace(50_000_000); sum(outs)+b.Spec.Fee != in {
				t.Errorf("outputs %d + fee %d != inputs %d", sum(outs), b.Spec.Fee, in)
			}
			// SPO-Ptx-INV-004: every asset ends up in exactly one output.
			var total []chain.AssetAmount
			for _, o := range outs {
				total = append(total, o.Assets...)
			}
			got, _ := SortAssets(total)
			want, _ := TotalOf(tc.in)
			if fmt.Sprint(got) != fmt.Sprint(want.Assets) {
				t.Errorf("assets out %v, in %v", got, want.Assets)
			}
			if b.Spec.TTL != 1000 {
				t.Errorf("ttl %d", b.Spec.TTL)
			}
		})
	}
}

// The ALL with assets case: the destination gets total - fee - R where R is
// the minimum of the source's return output.
//
// spec: SPO-01sendLovelaces-OUT-003
func TestAllWithAssetsReturnsTheMinimumToTheSource(t *testing.T) {
	b, _, err := balance(t, draft(t, All(), utxo(1, 10_000_000, asset(1, "a", 1), asset(2, "b", 1))))
	if err != nil {
		t.Fatal(err)
	}
	if r := b.Spec.Outputs[1].Lovelace; r != 1_020_000 {
		t.Errorf("R = %d, want the minimum of 1 ADA plus two assets", r)
	}
}

// Refusals. Every one is an error (hazard H3): upstream exits 0 in the
// pipeline scripts other than 01_sendLovelaces and 01_sendAssets, and the
// port never does.
//
// spec: SPO-Ptx-PRE-002, SPO-Ptx-PRE-003, SPO-Ptx-PRE-004, SPO-01sendLovelaces-PRE-002, SPO-01sendLovelaces-PRE-003,
// spec: SPO-01sendLovelaces-PRE-004, SPO-01sendLovelaces-PRE-005, SPO-01sendLovelaces-PRE-006
func TestRefusals(t *testing.T) {
	asset1 := asset(1, "a", 1)
	cases := []struct {
		name       string
		amount     Amount
		in         []chain.Utxo
		wantBelow  string // BelowMinimumError.Which
		wantTooLow bool   // ErrInsufficient
	}{
		{"ALLFUNDS below the minimum (PRE-002, PRE-004)", AllFunds(), []chain.Utxo{utxo(1, 1_100_000, asset1)}, "destination", false},
		{"ALL without assets below the minimum (PRE-002)", All(), []chain.Utxo{utxo(1, 1_100_000)}, "destination", false},
		{"inputs below the fee", AllFunds(), []chain.Utxo{utxo(1, 100_000)}, "", true},
		{"amount below the minimum (PRE-004)", Lovelaces(500_000), []chain.Utxo{utxo(1, 20_000_000)}, "destination", false},
		{"zero is refused by the minimum (PRE-004)", Lovelaces(0), []chain.Utxo{utxo(1, 20_000_000)}, "destination", false},
		{"MIN leaves a remainder below the minimum (PRE-005)", Min(), []chain.Utxo{utxo(1, 2_100_000, asset1)}, "change", false},
		{"MIN and no funds left (PRE-005)", Min(), []chain.Utxo{utxo(1, 1_000_000)}, "", true},
		{"amount leaves change below the minimum (PRE-006)", Lovelaces(18_000_000), []chain.Utxo{utxo(1, 19_000_000)}, "change", false},
		{"amount above the inputs (PRE-006)", Lovelaces(90_000_000), []chain.Utxo{utxo(1, 20_000_000)}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, err := balance(t, draft(t, tc.amount, tc.in...))
			if err == nil {
				t.Fatalf("accepted: %+v", b.Spec.Outputs)
			}
			var below *BelowMinimumError
			switch {
			case tc.wantTooLow && !errors.Is(err, ErrInsufficient):
				t.Errorf("want ErrInsufficient, got %v", err)
			case tc.wantBelow != "" && (!errors.As(err, &below) || below.Which != tc.wantBelow):
				t.Errorf("want a %s below-minimum refusal, got %v", tc.wantBelow, err)
			}
		})
	}

	// The advice of PRE-005 and PRE-006: an amount not below the total points at ALL.
	_, _, err := balance(t, draft(t, Lovelaces(90_000_000), utxo(1, 20_000_000)))
	if err == nil || !contains(err.Error(), "ALL") {
		t.Errorf("no advice to use ALL: %v", err)
	}
}

// Decision (PRE-003 quirk): upstream compares the asset-free destination
// output with the minimum of the source's return output (which holds the
// assets), so it refuses `ALL` when total - fee - R < R. The port compares
// each output with its own minimum: here the destination holds 1.005 ADA,
// above its own minimum of 1 ADA and below R = 1.01 ADA, and is accepted.
//
// spec: SPO-Ptx-PRE-003, SPO-01sendLovelaces-PRE-003
func TestAllWithAssetsComparesEachOutputWithItsOwnMinimum(t *testing.T) {
	l := Ledger{
		MinOutput: func(o Output) (chain.Lovelace, error) { return 1_000_000 + chain.Lovelace(len(o.Assets))*10_000, nil },
		Fee:       func(TxBody) (chain.Lovelace, error) { return 170_000, nil },
		Build:     func(BodySpec) (TxBody, error) { return TxBody{CBOR: []byte{1}}, nil }}
	b, err := draft(t, All(), utxo(1, 2_185_000, asset(1, "a", 1))).Balance(1, l)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if d, r := b.Spec.Outputs[0].Lovelace, b.Spec.Outputs[1].Lovelace; d != 1_005_000 || r != 1_010_000 || d >= r {
		t.Errorf("destination %d, return %d", d, r)
	}
	// One lovelace less and the destination is below its own minimum.
	_, err = draft(t, All(), utxo(1, 2_179_999, asset(1, "a", 1))).Balance(1, l)
	var below *BelowMinimumError
	if !errors.As(err, &below) || below.Which != "destination" {
		t.Errorf("%v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// The fee loop settles on the fee of the body that is built, with the
// fixed witness count carried by the Fee function, and the final body
// carries that fee.
//
// spec: SPO-Ptx-EXT-002, SPO-Ptx-INV-005, SPO-Ptx-INV-006, SPO-Ptx-EXT-004
func TestFeeLoopSettles(t *testing.T) {
	b, f, err := balance(t, draft(t, Lovelaces(5_000_000), utxo(1, 30_000_000)))
	if err != nil {
		t.Fatal(err)
	}
	est := chain.Lovelace(150_000 + len(b.Body.CBOR)*10)
	if b.Spec.Fee < est {
		t.Errorf("fee %d does not pay for the body (%d)", b.Spec.Fee, est)
	}
	if f.builds < 2 {
		t.Errorf("the body was built %d times; the placeholder pass and the final pass are two", f.builds)
	}
	// SPO-Ptx-INV-005: the placeholder has the same CBOR width as any real fee.
	if PlaceholderFee < 65536 || PlaceholderFee > math.MaxUint32 {
		t.Errorf("placeholder fee %d leaves the five-byte class", PlaceholderFee)
	}
	if SendWitnesses != 1 {
		t.Errorf("a payment is signed once, not %d times", SendWitnesses)
	}

	// A fee estimate that never settles is an error, not an endless loop.
	n := 0
	l := Ledger{MinOutput: func(Output) (chain.Lovelace, error) { return 1, nil },
		Fee:   func(TxBody) (chain.Lovelace, error) { n++; return chain.Lovelace(100_000 + n*100_000), nil },
		Build: func(BodySpec) (TxBody, error) { return TxBody{}, nil }}
	if _, err := draft(t, Lovelaces(5_000_000), utxo(1, 30_000_000)).Balance(1, l); !errors.Is(err, ErrFeeDiverged) {
		t.Errorf("a diverging fee: %v", err)
	}
}

// spec: SPO-Ptx-INV-005
func TestFeeLoopStartsAboveTheRealFeeAndConvergesDown(t *testing.T) {
	// The real fee (170000) is below the placeholder (200000): the loop
	// must end on 170000, not stay on the placeholder.
	l := Ledger{MinOutput: func(Output) (chain.Lovelace, error) { return 1_000_000, nil },
		Fee:   func(TxBody) (chain.Lovelace, error) { return 170_000, nil },
		Build: func(s BodySpec) (TxBody, error) { return TxBody{CBOR: []byte{1}}, nil }}
	b, err := draft(t, Lovelaces(5_000_000), utxo(1, 30_000_000)).Balance(1, l)
	if err != nil || b.Spec.Fee != 170_000 {
		t.Errorf("fee %d, %v", b.Spec.Fee, err)
	}
}

// A small wallet is not refused at the placeholder fee: the checks run with
// the real fee.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-PRE-002
func TestSmallWalletIsNotRefusedAtThePlaceholderFee(t *testing.T) {
	// 1.17 ADA: below minimum + placeholder fee (1.2), above minimum + real fee.
	l := Ledger{MinOutput: func(Output) (chain.Lovelace, error) { return 1_000_000, nil },
		Fee:   func(TxBody) (chain.Lovelace, error) { return 170_000, nil },
		Build: func(s BodySpec) (TxBody, error) { return TxBody{CBOR: []byte{1}}, nil }}
	b, err := draft(t, AllFunds(), utxo(1, 1_170_000)).Balance(1, l)
	if err != nil || b.Spec.Outputs[0].Lovelace != 1_000_000 {
		t.Errorf("%+v %v", b.Spec, err)
	}
}

// spec: SPO-Ptx-INV-010
func TestWitnessVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	var body TxBody
	body.ID = sha256.Sum256([]byte("body"))
	mk := func(k ed25519.PrivateKey, msg []byte) Witness {
		var w Witness
		copy(w.VKey[:], k.Public().(ed25519.PublicKey))
		copy(w.Signature[:], ed25519.Sign(k, msg))
		return w
	}
	want := HashKey(pub)
	if err := VerifyWitness(body, mk(priv, body.ID[:]), want); err != nil {
		t.Errorf("a good witness: %v", err)
	}
	// A witness by another key is refused, though its signature is valid.
	if err := VerifyWitness(body, mk(other, body.ID[:]), want); !errors.Is(err, ErrWitnessKey) {
		t.Errorf("wrong key: %v", err)
	}
	// A witness over another body is refused.
	if err := VerifyWitness(body, mk(priv, []byte("another body, not 32 bytes")), want); !errors.Is(err, ErrWitnessSignature) {
		t.Errorf("wrong message: %v", err)
	}
}

func TestNewDraftRefusals(t *testing.T) {
	if _, err := NewDraft("", dest, All(), []chain.Utxo{utxo(1, 1)}, nil); err == nil {
		t.Error("no payer")
	}
	if _, err := NewDraft(payer, dest, Amount{}, []chain.Utxo{utxo(1, 1)}, nil); !errors.Is(err, ErrBadAmount) {
		t.Error("no amount")
	}
	if _, err := NewDraft(payer, dest, All(), nil, nil); !errors.Is(err, ErrNoFunds) {
		t.Error("no inputs")
	}
}
