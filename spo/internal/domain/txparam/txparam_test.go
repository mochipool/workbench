package txparam

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

const (
	policyA = "aa0000000000000000000000000000000000000000000000000000aa"
	policyB = "bb0000000000000000000000000000000000000000000000000000bb"
	hash1   = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	hash2   = "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
)

func must(t *testing.T, words []string, acc Accepts) Extras {
	t.Helper()
	ex, err := Parse(words, acc)
	if err != nil {
		t.Fatalf("%v: %v", words, err)
	}
	return ex
}

// spec: SPO-Pparam-IF-001, SPO-Pparam-IF-002, SPO-Pparam-IF-008, SPO-Pparam-IF-009, SPO-Pparam-OUT-001
func TestMessagesAreSplitAndAccumulated(t *testing.T) {
	ex := must(t, []string{"MSG:  one|two ", "Msg: three", "msg:", "msg:   ", "msg:a||b", "msg:c|"}, ForSendLovelaces)
	want := []string{"one", "two", "three", "a", "", "b", "c"}
	if fmt.Sprint(ex.Messages) != fmt.Sprint(want) {
		t.Errorf("messages %q, want %q", ex.Messages, want)
	}
	if got := SplitMessages("|"); len(got) != 1 || got[0] != "" {
		t.Errorf("a lone | is one empty line, got %q", got)
	}
	if got := SplitMessages(" a | b "); len(got) != 2 || got[0] != "a " || got[1] != " b" {
		t.Errorf("the pieces are not trimmed: %q", got)
	}
	if string(MessageJSON(ex.Messages[:1], "")) != "{\n  \"674\": {\n    \"msg\": [\n      \"one\"\n    ]\n  }\n}" {
		t.Errorf("message json: %s", MessageJSON(ex.Messages[:1], ""))
	}
	if MessageJSON(nil, "") != nil {
		t.Error("no lines, no metadata")
	}
}

// spec: SPO-Pparam-PRE-001, SPO-Pparam-PRE-002
func TestMessageLimitsAreInBytes(t *testing.T) {
	if _, err := Parse([]string{"msg:" + strings.Repeat("é", 32)}, ForMint); err != nil {
		t.Errorf("64 bytes: %v", err)
	}
	if _, err := Parse([]string{"msg:" + strings.Repeat("é", 33)}, ForMint); !errors.Is(err, ErrBadMessage) {
		t.Errorf("66 bytes: %v", err)
	}
	// A double quote is a character like any other: the line is a JSON string
	// value, not text spliced into a jq program. Upstream refuses it.
	ex := must(t, []string{`msg:say "hi" \ and $(x)`}, ForMint)
	if len(ex.Messages) != 1 || ex.Messages[0] != `say "hi" \ and $(x)` {
		t.Errorf("messages %q", ex.Messages)
	}
	if err := CheckMessages([]string{"\xff"}); !errors.Is(err, ErrBadMessage) {
		t.Errorf("invalid UTF-8: %v", err)
	}
}

// spec: SPO-Pparam-IF-011, SPO-Pparam-IF-012, SPO-Pparam-IF-013, SPO-Pparam-INV-001, SPO-Pparam-PRE-003, SPO-Pparam-SEC-001
func TestEncryptionModeAndPassphrase(t *testing.T) {
	ex := must(t, []string{"msg:x", "ENC: Basic ", "pass: a pass "}, ForSendLovelaces)
	if ex.Encryption != "basic" || !ex.HasPassphrase() {
		t.Fatalf("%+v", ex)
	}
	// The passphrase is not trimmed, and leaves the value only through TakePassphrase.
	if s := fmt.Sprintf("%v %+v %#v %s", ex, ex, ex, ex); strings.Contains(s, "a pass") {
		t.Errorf("the passphrase is shown: %s", s)
	}
	p := ex.TakePassphrase()
	if string(p) != " a pass " || ex.HasPassphrase() || ex.TakePassphrase() != nil {
		t.Errorf("passphrase %q, kept %v", p, ex.HasPassphrase())
	}
	// A typo is refused in every script, including the five where upstream
	// sends the message in clear.
	for _, acc := range []Accepts{ForSendLovelaces, ForSendAssets, ForMint, ForCertificate} {
		if _, err := Parse([]string{"msg:x", "enc:basci"}, acc); !errors.Is(err, ErrBadEncryption) {
			t.Errorf("enc:basci accepted: %v", err)
		}
	}
	// enc: without a message has no effect and no error.
	ex = must(t, []string{"enc:whatever"}, ForSendLovelaces)
	if ex.Encryption != "" {
		t.Errorf("enc without a message: %q", ex.Encryption)
	}
	// An empty enc: value is no mode.
	if ex = must(t, []string{"msg:x", "enc:"}, ForSendLovelaces); ex.Encryption != "" {
		t.Errorf("empty enc: %q", ex.Encryption)
	}
}

// spec: SPO-Pparam-IF-003, SPO-Pparam-IF-004, SPO-Pparam-IF-005, SPO-Pparam-IF-006, SPO-Pparam-IF-007, SPO-Pparam-IF-015, SPO-Pparam-IF-016
func TestClassificationOfWords(t *testing.T) {
	ex := must(t, []string{"a.json", "B.JSON", "c.cbor", "", "12345", "dir/d.Cbor"}, ForSendLovelaces)
	if len(ex.MetadataFiles) != 4 || ex.MetadataFiles[0].Format != FileJSON || ex.MetadataFiles[1].Path != "B.JSON" ||
		ex.MetadataFiles[2].Format != FileCBOR || ex.MetadataFiles[3].Path != "dir/d.Cbor" || ex.MetadataFiles[3].Format != FileCBOR {
		t.Errorf("files %+v", ex.MetadataFiles)
	}
	if ex.HasLovelaces {
		t.Error("a numeric word is not an amount here (SPO-Pparam-IF-006)")
	}
	// Purely numeric words are never files; the lovelace word of 01_sendAssets
	// is the last one, and zero-padded numbers are refused (octal upstream).
	ex = must(t, []string{"5000000", "msg:x", "7000000"}, ForSendAssets)
	if !ex.HasLovelaces || ex.Lovelaces != 7_000_000 {
		t.Errorf("lovelaces %d %v", ex.Lovelaces, ex.HasLovelaces)
	}
	for _, bad := range []string{"010", "99999999999999999999"} {
		if _, err := Parse([]string{bad}, ForSendAssets); !errors.Is(err, ErrBadLovelaces) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// An unknown keyed word, and a sibling's token, are refused, not taken as a file name.
	for _, w := range []string{"mesage:hi", "type:REG"} {
		if _, err := Parse([]string{w}, ForSendLovelaces); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%s: %v", w, err)
		}
	}
	for _, w := range []string{"utxolimit:3", "skiputxowithasset:" + policyA, "onlyutxowithasset:" + policyA, "keeppolicy:" + policyA} {
		if _, err := Parse([]string{w}, ForMint); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("11a takes no %s: %v", w, err)
		}
	}
	if _, err := Parse([]string{"keeppolicy:" + policyA}, ForSendLovelaces); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("keeppolicy is 01_sendAssets only: %v", err)
	}
	// A file word with another extension, or none.
	for _, w := range []string{"x.txt", "noext", "x.json.bak"} {
		if _, err := Parse([]string{w}, ForSendLovelaces); !errors.Is(err, ErrBadMetadataFile) {
			t.Errorf("%s: %v", w, err)
		}
	}
	// The certificate scripts recognise the list and the filters and ignore them.
	ex = must(t, []string{"utxolimit:3", "skiputxowithasset:" + policyA, "onlyutxowithasset:" + policyB, hash1 + "#0", "msg:ok"}, ForCertificate)
	if ex.HasFilters() || len(ex.Messages) != 1 {
		t.Errorf("ignored tokens had an effect: %+v", ex)
	}
	if _, err := Parse([]string{"utxolimit:0"}, ForCertificate); !errors.Is(err, ErrBadUtxoLimit) {
		t.Errorf("an ignored token is still checked: %v", err)
	}
}

// spec: SPO-Pparam-IF-019, SPO-Pparam-IF-020, SPO-Pparam-IF-021, SPO-Pparam-IF-023
func TestInputTokens(t *testing.T) {
	ex := must(t, []string{hash1 + "#0", hash2 + "#3|" + strings.ToUpper(hash1) + "#12",
		"SkipUtxoWithAsset:" + strings.ToUpper(policyA) + "|" + policyB + "746f6b", "onlyutxowithasset:" + policyB}, ForSendAssets)
	if len(ex.Inputs) != 2 || ex.Inputs[0].Index != 3 || ex.Inputs[1].Index != 12 {
		t.Errorf("the later list replaces the earlier: %v", ex.Inputs)
	}
	ex = must(t, []string{"UTXOLIMIT: 4 "}, ForSendAssets)
	if ex.UtxoLimit != 4 {
		t.Errorf("limit %d", ex.UtxoLimit)
	}
	ex = must(t, []string{"skiputxowithasset:" + strings.ToUpper(policyA) + "|" + policyB + "746f6b", "keeppolicy:" + policyA + "|" + policyB}, ForSendAssets)
	if len(ex.Skip) != 2 || ex.Skip[0].HasName || !ex.Skip[1].HasName || string(ex.Skip[1].Name) != "tok" || len(ex.KeepPolicies) != 2 {
		t.Errorf("skip %+v keep %v", ex.Skip, ex.KeepPolicies)
	}
	for _, w := range []string{"utxolimit:0", "utxolimit:-1", "utxolimit:abc", "utxolimit:"} {
		if _, err := Parse([]string{w}, ForSendLovelaces); !errors.Is(err, ErrBadUtxoLimit) {
			t.Errorf("%s: %v", w, err)
		}
	}
	for _, w := range []string{"onlyutxowithasset:zz", "onlyutxowithasset:" + policyA[:54], "skiputxowithasset:" + policyA + "|", "skiputxowithasset:" + policyA + strings.Repeat("00", 33)} {
		if _, err := Parse([]string{w}, ForSendLovelaces); !errors.Is(err, ErrBadAssetFilter) {
			t.Errorf("%s: %v", w, err)
		}
	}
	for _, w := range []string{"keeppolicy:" + policyA + "00", "keeppolicy:abc"} {
		if _, err := Parse([]string{w}, ForSendAssets); !errors.Is(err, ErrBadKeepPolicy) {
			t.Errorf("%s: %v", w, err)
		}
	}
	// A list needs full transaction ids and `|` between references.
	for _, w := range []string{"abc#1", hash1 + "#1" + hash2 + "#2", hash1 + "#99999999999"} {
		if _, err := Parse([]string{w}, ForSendLovelaces); !errors.Is(err, ErrBadUtxoRef) {
			t.Errorf("%s: %v", w, err)
		}
	}
	if _, err := Parse([]string{hash1 + "#1"}, Accepts{}); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("a list where none is taken: %v", err)
	}
}

func utxo(hash string, idx uint32, assets ...chain.AssetAmount) chain.Utxo {
	id, _ := chain.ParseTxID(hash)
	return chain.Utxo{TxID: id, Index: idx, Lovelace: 1_000_000, Assets: assets}
}

func asset(policyHex string, name string, q uint64) chain.AssetAmount {
	var id chain.AssetID
	for i := 0; i < 28; i++ {
		fmt.Sscanf(policyHex[2*i:2*i+2], "%02x", &id.Policy[i])
	}
	id.Name = []byte(name)
	return chain.AssetAmount{Asset: id, Quantity: q}
}

// spec: SPO-Pparam-IF-019, SPO-Pparam-IF-020, SPO-Pparam-IF-022, SPO-Cutxo-OUT-004, SPO-Cutxo-INV-003
func TestFilterUtxos(t *testing.T) {
	u1 := utxo(hash1, 0, asset(policyA, "x", 1))
	u2 := utxo(hash2, 3, asset(policyB, "tok", 1), asset(policyA, "", 2))
	u3 := utxo(hash1, 1)
	in := []chain.Utxo{u1, u2, u3}
	ids := func(us []chain.Utxo) string {
		var s []string
		for _, u := range us {
			s = append(s, fmt.Sprintf("%s#%d", u.TxID.String()[:2], u.Index))
		}
		return strings.Join(s, ",")
	}
	for _, tc := range []struct {
		name  string
		words []string
		want  string
	}{
		{"no filter keeps all, in cardano-cli order", nil, "0b#3,6b#0,6b#1"},
		{"limit keeps the first n in that order", []string{"utxolimit:2"}, "0b#3,6b#0"},
		{"skip a policy", []string{"skiputxowithasset:" + policyA}, "6b#1"},
		{"skip an exact asset", []string{"skiputxowithasset:" + policyB + "746f6b"}, "6b#0,6b#1"},
		{"a name that is only a prefix does not match", []string{"skiputxowithasset:" + policyB + "74"}, "0b#3,6b#0,6b#1"},
		{"only a policy", []string{"onlyutxowithasset:" + policyA}, "0b#3,6b#0"},
		{"only matching nothing leaves nothing", []string{"onlyutxowithasset:" + strings.Repeat("cc", 28)}, ""},
		{"skip, then only, then limit", []string{"skiputxowithasset:" + policyB, "onlyutxowithasset:" + policyA, "utxolimit:1"}, "6b#0"},
		{"explicit list, unknown references dropped", []string{hash1 + "#1|" + hash2 + "#9|" + hash2 + "#3"}, "6b#1,0b#3"},
		{"list after the limit", []string{"utxolimit:1", hash1 + "#1"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := must(t, tc.words, ForSendAssets)
			if got := ids(FilterUtxos(in, ex)); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
	if ids(in) != "6b#0,0b#3,6b#1" {
		t.Error("the input slice was reordered")
	}
}

// spec: SPO-Pparam-IF-014, SPO-Pparam-PRE-005
func TestCheckMetadataJSON(t *testing.T) {
	for _, ok := range []string{`{"721": {"a": 1}}`, `{"0": 1}`, `{"65535": [1], "x": 2}`, ` {"007": 1} `} {
		if err := CheckMetadataJSON("f.json", []byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{``, `{`, `[1]`, `{}`, `{"abc": 1}`, `{"-1": 1}`, `{"65536": 1}`, `{"1": 1} x`, `{"abc": 1, "5": 2}`, `"x"`, `{"1": 1`} {
		if err := CheckMetadataJSON("f.json", []byte(bad)); !errors.Is(err, ErrBadMetadataFile) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// Only the first key, in file order, is checked.
	if err := CheckMetadataJSON("f.json", []byte(`{"5": 1, "abc": 2}`)); err != nil {
		t.Errorf("only the first key is checked: %v", err)
	}
}

// A front end that holds the message lines outside the words gives them as
// options: the encryption mode then survives without a msg: word, and the
// lines are checked, kept verbatim and not added to the extras.
func TestParseWithOptions(t *testing.T) {
	ex, err := ParseWith([]string{"x.json"}, ForCertificate, Options{Messages: []string{"a|b"}, Encryption: "basic"})
	if err != nil || ex.Encryption != "basic" || len(ex.Messages) != 0 || len(ex.MetadataFiles) != 1 {
		t.Fatalf("%v %+v", err, ex)
	}
	// Without a message anywhere the mode has no effect (IF-013).
	if ex, err = ParseWith(nil, ForCertificate, Options{Encryption: "basic"}); err != nil || ex.Encryption != "" {
		t.Errorf("no message: %v %+v", err, ex)
	}
	// A message word counts as a message too, and an enc: word wins.
	if ex, err = ParseWith([]string{"msg:hi", "enc:basic"}, ForCertificate, Options{}); err != nil || ex.Encryption != "basic" || len(ex.Messages) != 1 {
		t.Errorf("word input: %v %+v", err, ex)
	}
	// An unsupported mode and a bad line are refused.
	if _, err = ParseWith(nil, ForCertificate, Options{Messages: []string{"x"}, Encryption: "aes"}); !errors.Is(err, ErrBadEncryption) {
		t.Errorf("mode: %v", err)
	}
	if _, err = ParseWith(nil, ForCertificate, Options{Messages: []string{strings.Repeat("x", 65)}}); !errors.Is(err, ErrBadMessage) {
		t.Errorf("line: %v", err)
	}
	// Parse is ParseWith with no options.
	a, _ := Parse([]string{"msg:hi", "enc:basic"}, ForCertificate)
	b, _ := ParseWith([]string{"msg:hi", "enc:basic"}, ForCertificate, Options{})
	if a.String() != b.String() {
		t.Error("Parse differs from ParseWith")
	}
}
