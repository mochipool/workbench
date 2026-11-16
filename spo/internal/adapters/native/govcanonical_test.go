package native

import (
	"encoding/hex"
	"strings"
	"testing"
)

func canonEnvelope(t *testing.T, raw []byte) []byte {
	t.Helper()
	env, err := textEnvelope(actionEnvelopeType, "Governance action", hex.EncodeToString(raw), "    ")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// acct is a testnet reward account, 29 bytes, key credential.
func acct(b byte) []byte {
	a := make([]byte, 29)
	a[0] = 0xe0
	for i := 1; i < 29; i++ {
		a[i] = b
	}
	return a
}

// action writes [deposit, account, <action built by f>, anchor] by hand.
func rawAction(deposit func([]byte) []byte, f func([]byte) []byte) []byte {
	var b []byte
	b = cborArray(b, 4)
	b = deposit(b)
	b = cborBytes(b, acct(1))
	b = f(b)
	return gAnchor(b, "https://example.com/a.json", [32]byte{9}, true)
}

func plainDeposit(b []byte) []byte { return cborUint(b, 500) }

// An action file is read only when it is the file the builder writes for what
// it says: what the operator is shown is then what the file carries. Each case
// is a file the displayed action would not describe.
//
// spec: SPO-25b-PRE-004, SPO-25b-PRE-005, SPO-25b-PRE-006
func TestDecodeActionFileRefusesWhatIsNotCanonical(t *testing.T) {
	info := func(b []byte) []byte { b = cborArray(b, 1); return cborUint(b, actTagInfo) }
	// the control: the same files in canonical form load
	if _, err := (Ledger{}).DecodeActionFile(canonEnvelope(t, rawAction(plainDeposit, info))); err != nil {
		t.Fatalf("the canonical info action: %v", err)
	}
	treasury := func(accounts ...[]byte) func([]byte) []byte {
		return func(b []byte) []byte {
			b = cborArray(b, 3)
			b = cborUint(b, actTagTreasury)
			b = cborMap(b, len(accounts))
			for i, a := range accounts {
				b = cborBytes(b, a)
				b = cborUint(b, uint64(i+1))
			}
			return append(b, 0xf6)
		}
	}
	if _, err := (Ledger{}).DecodeActionFile(canonEnvelope(t, rawAction(plainDeposit, treasury(acct(2), acct(3))))); err != nil {
		t.Fatalf("the canonical treasury withdrawal: %v", err)
	}
	costModels := func(keys ...uint64) func([]byte) []byte {
		return func(b []byte) []byte {
			b = cborArray(b, 4)
			b = cborUint(b, actTagParameters)
			b = append(b, 0xf6)
			b = cborMap(b, 1)
			b = cborUint(b, 18)
			b = cborMap(b, len(keys))
			for _, k := range keys {
				b = cborUint(b, k)
				b = append(b, 0x9f, 0x01, 0x02, 0xff) // an indefinite array, as cardano-cli writes it
			}
			return append(b, 0xf6)
		}
	}
	// cardano-cli's indefinite cost-model arrays are the one leniency
	got, err := (Ledger{}).DecodeActionFile(canonEnvelope(t, rawAction(plainDeposit, costModels(0, 1))))
	if err != nil || len(got.Action.Params) != 1 || got.Action.Params[0].Name != "cost-models" {
		t.Fatalf("an indefinite cost model, as cardano-cli writes it: %v %+v", err, got.Action.Params)
	}
	for name, tc := range map[string]struct {
		raw  []byte
		want string
	}{
		"duplicate cost-model language": {rawAction(plainDeposit, costModels(1, 1)), "given twice"},
		"duplicate treasury account":    {rawAction(plainDeposit, treasury(acct(2), acct(2))), "twice"},
		"unsorted treasury accounts":    {rawAction(plainDeposit, treasury(acct(3), acct(2))), "canonical"},
		"a text string as the tag": {rawAction(plainDeposit, func(b []byte) []byte {
			b = cborArray(b, 1)
			return append(b, 0x61, '6') // "6", not 6
		}), "tag is not an unsigned integer"},
		"a non-minimal integer": {rawAction(func(b []byte) []byte { return append(b, 0x1a, 0, 0, 0x01, 0xf4) }, info), "canonical"},
		"an indefinite array outside the cost models": {rawAction(plainDeposit, func(b []byte) []byte {
			return append(b, 0x9f, byte(actTagInfo), 0xff)
		}), "canonical"},
	} {
		_, err := (Ledger{}).DecodeActionFile(canonEnvelope(t, tc.raw))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
}

// Only the action-file reader reads indefinite-length arrays; the readers of
// votes and certificates refuse them.
func TestIndefiniteArraysAreReadOnlyForActionFiles(t *testing.T) {
	in := []byte{0x9f, 0x01, 0xff}
	if _, err := gparseAll(in); err == nil {
		t.Error("the strict reader accepted an indefinite array")
	}
	if _, err := gparseAllIndefinite(in); err != nil {
		t.Error(err)
	}
	// nested, as a vote or certificate file could carry it
	if _, err := gparseAll([]byte{0x82, 0x01, 0x9f, 0xff}); err == nil {
		t.Error("the strict reader accepted a nested indefinite array")
	}
}

// A parameter value wider than the ledger's type is refused when a file is read.
//
// spec: SPO-25b-PRE-004
func TestDecodeActionFileRefusesAParameterWiderThanItsType(t *testing.T) {
	update := func(v uint64) []byte {
		return rawAction(plainDeposit, func(b []byte) []byte {
			b = cborArray(b, 4)
			b = cborUint(b, actTagParameters)
			b = append(b, 0xf6)
			b = cborMap(b, 1)
			b = cborUint(b, 27) // min-committee-size, a Word16
			b = cborUint(b, v)
			return append(b, 0xf6)
		})
	}
	if _, err := (Ledger{}).DecodeActionFile(canonEnvelope(t, update(65535))); err != nil {
		t.Fatalf("at the width: %v", err)
	}
	if _, err := (Ledger{}).DecodeActionFile(canonEnvelope(t, update(65536))); err == nil || !strings.Contains(err.Error(), "ledger type") {
		t.Errorf("past the width: %v", err)
	}
}
