package checkpoint

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
)

func h(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func goodStatement() Statement {
	return Statement{WorkspaceID: h(1)[:16], Seq: 42, HeadMAC: h(2), SlotTable: h(3), SHA256: h(4), Size: 1 << 20,
		Time: time.Date(2026, 11, 18, 10, 11, 12, 0, time.UTC), KeyHash: h(5)}
}

// spec: SPO-Xbackup-OUT-011
func TestStatementRoundTripAndShape(t *testing.T) {
	s := goodStatement()
	text := s.Encode()
	want := "spo/checkpoint/v1\nworkspace 01010101010101010101010101010101\nsequence 42\n"
	if !strings.HasPrefix(string(text), want) {
		t.Fatalf("%s", text)
	}
	back, err := ParseStatement(text)
	if err != nil || !bytes.Equal(back.Encode(), text) || back.Seq != 42 || back.Size != 1<<20 || !back.Time.Equal(s.Time) {
		t.Fatalf("%v %+v", err, back)
	}
}

// Every malformed form is refused.
//
// spec: SPO-Xbackup-OUT-011
func TestStatementIsParsedStrictly(t *testing.T) {
	good := string(goodStatement().Encode())
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")
	join := func(l []string) string { return strings.Join(l, "\n") + "\n" }
	swap := func(i, j int) string {
		l := append([]string(nil), lines...)
		l[i], l[j] = l[j], l[i]
		return join(l)
	}
	repl := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	cases := map[string]string{
		"no final line feed":      strings.TrimSuffix(good, "\n"),
		"a wrong tag":             repl("spo/checkpoint/v1", "spo/checkpoint/v2"),
		"another domain tag":      repl("spo/checkpoint/v1", "spo/location/v1"),
		"a missing line":          join(lines[:len(lines)-1]),
		"an extra line":           good + "extra 1\n",
		"an extra blank line":     good + "\n",
		"keys out of order":       swap(2, 3),
		"a duplicate key":         join(append(append([]string(nil), lines[:3]...), lines[2:]...)),
		"upper-case hex":          repl(hex.EncodeToString(h(2)), strings.Repeat("0A", 32)),
		"a short hash":            repl(hex.EncodeToString(h(3)), hex.EncodeToString(h(3))[2:]),
		"odd-length hex":          repl("workspace 0101", "workspace 010"),
		"a leading zero number":   repl("sequence 42", "sequence 042"),
		"a signed number":         repl("sequence 42", "sequence +42"),
		"a negative number":       repl("sequence 42", "sequence -42"),
		"an overflowing number":   repl("sequence 42", "sequence 18446744073709551616"),
		"a hex number":            repl("size 1048576", "size 0x100000"),
		"a time with an offset":   repl("2026-11-18T10:11:12Z", "2026-11-18T10:11:12+00:00"),
		"a time with a fraction":  repl("2026-11-18T10:11:12Z", "2026-11-18T10:11:12.5Z"),
		"a time not in UTC":       repl("2026-11-18T10:11:12Z", "2026-11-18T11:11:12+01:00"),
		"an impossible date":      repl("2026-11-18T10:11:12Z", "2026-13-18T10:11:12Z"),
		"two spaces":              repl("sequence 42", "sequence  42"),
		"a tab":                   repl("sequence 42", "sequence\t42"),
		"carriage returns":        strings.ReplaceAll(good, "\n", "\r\n"),
		"a value with a space":    repl("size 1048576", "size 1048576 "),
		"an empty value":          repl("sequence 42", "sequence "),
		"a NUL":                   repl("sequence 42", "sequence 4\x002"),
		"larger than the bound":   good + strings.Repeat("x", MaxStatementSize),
		"a key with another case": repl("sequence", "Sequence"),
	}
	for name, text := range cases {
		if _, err := ParseStatement([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseStatement(nil); err == nil {
		t.Error("empty accepted")
	}
}

func TestLongPin(t *testing.T) {
	ws, kh := h(7)[:16], h(8)
	p := LongPin{WorkspaceID: ws, KeyHash: kh}
	if got := p.String(); got != hex.EncodeToString(ws)+":ck:"+hex.EncodeToString(kh) {
		t.Fatal(got)
	}
	if got := p.WithMin(12).String(); !strings.HasSuffix(got, ":12") {
		t.Fatal(got)
	}
	for _, s := range []string{p.String(), p.WithMin(0).String(), p.WithMin(99).String()} {
		back, err := ParseLongPin(s)
		if err != nil || back.String() != s {
			t.Fatalf("%q: %v", s, err)
		}
	}
	for name, s := range map[string]string{
		"upper hex":     strings.ToUpper(p.String()),
		"no ck":         hex.EncodeToString(ws) + ":cx:" + hex.EncodeToString(kh),
		"short key":     hex.EncodeToString(ws) + ":ck:" + hex.EncodeToString(kh)[2:],
		"leading zero":  p.String() + ":007",
		"negative":      p.String() + ":-1",
		"extra field":   p.WithMin(1).String() + ":1",
		"exact pin":     hex.EncodeToString(ws) + ":5:" + hex.EncodeToString(h(1)) + ":" + hex.EncodeToString(h(2)),
		"no workspace":  ":ck:" + hex.EncodeToString(kh),
		"empty minimum": p.String() + ":",
	} {
		if _, err := ParseLongPin(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if !IsLongPin(p.String()) || IsLongPin(hex.EncodeToString(ws)+":5:"+hex.EncodeToString(h(1))+":"+hex.EncodeToString(h(2))) {
		t.Error("IsLongPin")
	}
}

type soft struct {
	priv *ecdsa.PrivateKey
	key  sshsig.Key
}

func newSoft(t *testing.T) soft {
	t.Helper()
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	q, _ := p.PublicKey.Bytes()
	return soft{p, sshsig.Key{Q: q, Application: Application}}
}

// sign makes the armored SSHSIG of text under namespace, as an authenticator
// with both flags would.
func (s soft) sign(t *testing.T, ns string, text []byte, flags byte) []byte {
	t.Helper()
	sd, err := sshsig.SignedData(ns, sshsig.SHA512, text)
	if err != nil {
		t.Fatal(err)
	}
	app := sha256.Sum256([]byte(Application))
	data := append(append([]byte(nil), app[:]...), flags, 0, 0, 0, 1)
	data = append(data, sshsig.ClientDataHash(sd)...)
	d := sha256.Sum256(data)
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, d[:])
	if err != nil {
		t.Fatal(err)
	}
	blob, err := sshsig.Encode(s.key, ns, sshsig.SHA512, sshsig.Assertion{Flags: flags, Counter: 1, Signature: der})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(sshsig.Armor(blob))
}

// spec: SPO-Xbackup-OUT-012
func TestSignedObjectVerifiesAgainstThePinnedKeyOnly(t *testing.T) {
	k, other := newSoft(t), newSoft(t)
	st := goodStatement()
	st.KeyHash = k.key.Hash()
	text := st.Encode()
	obj := Signed{Statement: text, Armored: k.sign(t, TagCheckpoint, text, 5)}.EncodeObject()
	parsed, err := ParseObject(obj)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := parsed.Verify(k.key.Hash())
	if err != nil || got.Seq != 42 {
		t.Fatalf("%v", err)
	}
	// the key that signed travels in the signature; a different hash is refused
	if _, _, err := parsed.Verify(other.key.Hash()); err == nil {
		t.Error("accepted under another key hash")
	}
	// a statement naming another key than the one that signed it
	st2 := st
	st2.KeyHash = other.key.Hash()
	text2 := st2.Encode()
	if _, _, err := (Signed{Statement: text2, Armored: k.sign(t, TagCheckpoint, text2, 5)}).Verify(k.key.Hash()); err == nil || !strings.Contains(err.Error(), "another key") {
		t.Errorf("%v", err)
	}
	// a signature in the replacement namespace is not a checkpoint signature
	if _, _, err := (Signed{Statement: text, Armored: k.sign(t, TagReplace, text, 5)}).Verify(k.key.Hash()); err == nil {
		t.Error("a signature of another namespace was accepted")
	}
	if _, err := ParseObject(append(obj, bytes.Repeat([]byte("x"), MaxObjectSize)...)); err == nil {
		t.Error("an oversized object was parsed")
	}
	if _, err := ParseObject(text); err == nil {
		t.Error("an object with no signature was parsed")
	}
}

func TestKeyRecordRoundTrip(t *testing.T) {
	k := newSoft(t)
	r := KeyRecord{Key: k.key, CredentialID: h(9), Enrolled: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	back, err := ParseKeyRecord(r.Encode())
	if err != nil || !bytes.Equal(back.Hash(), k.key.Hash()) || !bytes.Equal(back.CredentialID, h(9)) {
		t.Fatalf("%v", err)
	}
	bad := strings.Replace(string(r.Encode()), "key-hash "+hex.EncodeToString(k.key.Hash()), "key-hash "+hex.EncodeToString(h(1)), 1)
	if _, err := ParseKeyRecord([]byte(bad)); err == nil {
		t.Error("a record whose hash is not its key's hash was accepted")
	}
}

// spec: SPO-Xbackup-PRE-017
func TestReplacementStatement(t *testing.T) {
	k, n := newSoft(t), newSoft(t)
	old := KeyRecord{Key: k.key, CredentialID: h(1), Enrolled: time.Now().UTC().Truncate(time.Second)}
	ws := h(6)[:16]
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	r := Replacement{WorkspaceID: ws, OldKeyHash: old.Hash(), NewKeyHash: n.key.Hash(), Time: now}
	text := r.Encode()
	if back, err := ParseReplacement(text); err != nil || !bytes.Equal(back.NewKeyHash, n.key.Hash()) {
		t.Fatal(err)
	}
	sig := k.sign(t, TagReplace, text, 5)
	if err := VerifyReplacement(text, sig, old, ws, n.key.Hash(), now.Add(time.Minute), 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func() error{
		"another new key": func() error { return VerifyReplacement(text, sig, old, ws, h(1), now, time.Hour) },
		"another workspace": func() error {
			return VerifyReplacement(text, sig, old, h(7)[:16], n.key.Hash(), now, time.Hour)
		},
		"too old": func() error {
			return VerifyReplacement(text, sig, old, ws, n.key.Hash(), now.Add(time.Hour), time.Minute)
		},
		"signed by the new key": func() error {
			return VerifyReplacement(text, n.sign(t, TagReplace, text, 5), old, ws, n.key.Hash(), now, time.Hour)
		},
		"the checkpoint namespace": func() error {
			return VerifyReplacement(text, k.sign(t, TagCheckpoint, text, 5), old, ws, n.key.Hash(), now, time.Hour)
		},
		"a removal statement for a replacement": func() error {
			rm := Replacement{WorkspaceID: ws, OldKeyHash: old.Hash(), Time: now}.Encode()
			return VerifyReplacement(rm, k.sign(t, TagReplace, rm, 5), old, ws, n.key.Hash(), now, time.Hour)
		},
		"no user verification": func() error {
			return VerifyReplacement(text, k.sign(t, TagReplace, text, 1), old, ws, n.key.Hash(), now, time.Hour)
		},
	} {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rm := Replacement{WorkspaceID: ws, OldKeyHash: old.Hash(), Time: now}.Encode()
	if err := VerifyReplacement(rm, k.sign(t, TagReplace, rm, 5), old, ws, nil, now, time.Hour); err != nil {
		t.Errorf("a removal: %v", err)
	}
	if !strings.Contains(string(rm), "new-key-hash none") {
		t.Errorf("%s", rm)
	}
}
