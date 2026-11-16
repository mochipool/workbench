package governance

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

const cconvHash = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"

// A governance action id `<txid>#<index>` becomes `gov_action1...` of the 32
// id bytes and the index; the inverse reads it back. The index is plain
// decimal (upstream evaluates it as a shell number, so `08` is an error
// there; the port reads decimal digits). The id of upstream's minimum
// number of whole bytes for an index above 255 (`0100`) is not CIP-129,
// whose index is one byte: the port refuses to spell it (decision: fix).
//
// spec: SPO-Cconv-OUT-017, SPO-Cconv-OUT-018, SPO-Cconv-IF-002
func TestActionIDConversions(t *testing.T) {
	for _, idx := range []uint32{0, 7, 255} {
		a, err := ParseActionID(strings.ToUpper(cconvHash) + "#" + map[uint32]string{0: "0", 7: "07", 255: "255"}[idx])
		if err != nil || a.Index != idx {
			t.Fatalf("index %d: %+v %v", idx, a, err)
		}
		bech, err := a.CIP129()
		if err != nil || !strings.HasPrefix(bech, "gov_action1") {
			t.Fatalf("index %d: %q %v", idx, bech, err)
		}
		_, data, _ := chain.Bech32Decode(bech)
		if hex.EncodeToString(data[:32]) != cconvHash || len(data) != 33 || uint32(data[32]) != idx {
			t.Errorf("index %d: data %x", idx, data)
		}
		back, err := ParseActionID(bech)
		if err != nil || back.Hex() != cconvHash+"#"+map[uint32]string{0: "0", 7: "7", 255: "255"}[idx] {
			t.Errorf("round trip of %d: %q %v", idx, back.Hex(), err)
		}
	}
	a := ActionID{Index: 256}
	if _, err := a.CIP129(); err == nil {
		t.Error("an index of 256 does not fit CIP-129 and must be refused")
	}
	for _, bad := range []string{cconvHash, cconvHash + "#", cconvHash + "#x1", "abc#1", cconvHash[:63] + "#1", "drep1abc"} {
		if _, err := ParseActionID(bad); err == nil {
			t.Errorf("%q was accepted as an action id", bad)
		}
	}
}

// The six legacy-to-CIP-129 rows of the table: header byte and the two
// human-readable parts. The reverse direction reads the header byte and
// gives back the hash and the credential type.
//
// spec: SPO-Cconv-OUT-019, SPO-Cconv-OUT-020
func TestLegacyAndCIP129IDsFollowTheHeaderTable(t *testing.T) {
	h, _ := ParseHash28(cconvHash[:56])
	for _, c := range []struct {
		script         bool
		hot            bool
		legacy, header string
		cipHRP         string
	}{
		{false, true, "cc_hot1", "02", "cc_hot"},
		{true, true, "cc_hot_script1", "03", "cc_hot"},
		{false, false, "cc_cold1", "12", "cc_cold"},
		{true, false, "cc_cold_script1", "13", "cc_cold"},
	} {
		ids, err := CommitteeIDsOf(Credential{Script: c.script, Hash: h}, c.hot)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(ids.Legacy, c.legacy) {
			t.Errorf("legacy %q lacks the prefix %q", ids.Legacy, c.legacy)
		}
		hrp, data, err := chain.Bech32Decode(ids.CIP129)
		if err != nil || hrp != c.cipHRP || hex.EncodeToString(data[:1]) != c.header || hex.EncodeToString(data[1:]) != hex.EncodeToString(h[:]) {
			t.Errorf("CIP-129 %q: %s %x %v", ids.CIP129, hrp, data, err)
		}
		back, isID, err := ParseCommitteeWord(ids.CIP129)
		if err != nil || !isID || back.Hash != h || back.Script != c.script {
			t.Errorf("reading %q back: %+v %v %v", ids.CIP129, back, isID, err)
		}
	}
	for _, c := range []struct {
		script         bool
		legacy, header string
	}{{false, "drep1", "22"}, {true, "drep_script1", "23"}} {
		ids, err := DRepIDsOf(Credential{Script: c.script, Hash: h})
		if err != nil {
			t.Fatal(err)
		}
		hrp, data, _ := chain.Bech32Decode(ids.CIP129)
		if !strings.HasPrefix(ids.Legacy, c.legacy) || hrp != "drep" || hex.EncodeToString(data[:1]) != c.header {
			t.Errorf("drep %v: %q %q %x", c.script, ids.Legacy, ids.CIP129, data)
		}
	}
}

// An id that matches no row of the table is refused with an error value, not
// with an error text in place of the result (upstream prints it on stdout and
// exits 1; pool ids are not handled by either).
//
// spec: SPO-Cconv-PRE-003
func TestIDsOutsideTheTableAreRefused(t *testing.T) {
	h, _ := ParseHash28(cconvHash[:56])
	ids, _ := DRepIDsOf(Credential{Hash: h})
	for _, bad := range []string{"", "pool1abc", ids.Legacy, "cc_cold1qqqq"} {
		if _, isID, err := ParseCommitteeWord(bad); err == nil && isID {
			t.Errorf("%q was accepted as a committee id", bad)
		}
	}
}
