package seal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func f2keys(t *testing.T) *Keys {
	t.Helper()
	master, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Destroy(); master.Destroy() })
	return k
}

func f2meta(anchor byte, num uint64) RecordMeta {
	a := append([]byte{29, 1}, bytes.Repeat([]byte{anchor}, 28)...) // length byte, kind, hash
	return RecordMeta{WorkspaceID: bytes.Repeat([]byte{1}, IDSize), RecordID: bytes.Repeat([]byte{2}, IDSize), Kind: "kes.vkey",
		Anchor: a, Num: num, Class: ClassSensitive, Version: 3}
}

// A record of the identity-keyed format binds its anchor identity and number into
// the associated data and holds them in the owner blob; a name is in neither (ADR
// 0010, Amends ADR 0003).
//
// spec: SPO-Xidentity-INV-017
func TestFormat2BindsTheAnchorAndTheNumber(t *testing.T) {
	k := f2keys(t)
	m := f2meta(0xaa, 7)
	if m.format() != RecordFormat {
		t.Fatalf("format %d", m.format())
	}
	sealed, err := k.SealRecord(m, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k.OpenRecord(m, sealed); err != nil || string(pt) != "payload" {
		t.Fatalf("open: %q %v", pt, err)
	}
	for name, other := range map[string]RecordMeta{"another anchor": f2meta(0xbb, 7), "another number": f2meta(0xaa, 8)} {
		if _, err := k.OpenRecord(other, sealed); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the owner blob holds the anchor, the kind and the number
	anchor, num, err := k.OpenOwnerRef(m.WorkspaceID, m.RecordID, m.Kind, sealed)
	if err != nil || !bytes.Equal(anchor, m.Anchor) || num != 7 {
		t.Fatalf("owner blob: %x %d %v", anchor, num, err)
	}
	// the owner blob of format 2 is not an owner string of format 1
	if s, err := k.OpenOwner(m.WorkspaceID, m.RecordID, m.Kind, sealed); err == nil {
		t.Errorf("the format 1 reading of a format 2 owner blob opened: %q", s)
	}
	// the AD is the canonical CBOR [format, workspace, record, kind, anchor, number, class, version, payload format]
	ad, _ := m.AD()
	want, _ := EncodeCanonical([]any{RecordFormat, m.WorkspaceID, m.RecordID, m.Kind, m.Anchor, uint64(7), m.Class, uint64(3), PayloadFormat})
	if !bytes.Equal(ad, want) {
		t.Errorf("AD %x, want %x", ad, want)
	}
	// a format 2 record with an owner name is refused
	bad := m
	bad.Owner = "alice#0"
	if _, err := bad.AD(); !errors.Is(err, ErrFormat) {
		t.Errorf("a name in a format 2 record: %v", err)
	}
}

// Reseal moves a record from format 1 to format 2 under the same keys: the payload
// is the same, the nonce is fresh, the data key is re-wrapped and the owner blob
// is rewritten; a secret stays a framed secret.
//
// spec: SPO-Xidentity-INV-024
func TestResealFromFormat1KeepsThePayloadAndRenewsTheRest(t *testing.T) {
	k := f2keys(t)
	old := RecordMeta{WorkspaceID: bytes.Repeat([]byte{1}, IDSize), RecordID: bytes.Repeat([]byte{2}, IDSize), Kind: "kes.vkey",
		Owner: "pool#3", Class: ClassSensitive, Version: 4}
	sealed, err := k.SealRecord(old, []byte("a verification key"))
	if err != nil {
		t.Fatal(err)
	}
	nm := f2meta(0xcc, 3)
	nm.Version = 5
	re, err := k.Reseal(old, nm, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(re.Nonce, sealed.Nonce) || bytes.Equal(re.Owner, sealed.Owner) || bytes.Equal(re.WrappedKey, sealed.WrappedKey) || bytes.Equal(re.Ciphertext, sealed.Ciphertext) {
		t.Error("a part of the record was not renewed")
	}
	if pt, err := k.OpenRecord(nm, re); err != nil || string(pt) != "a verification key" {
		t.Fatalf("the resealed record: %q %v", pt, err)
	}
	if _, err := k.OpenRecord(old, re); err == nil {
		t.Error("the resealed record still opens under the old associated data")
	}
	// a secret
	so := old
	so.Kind, so.Class = "kes.skey", ClassSecret
	ss, err := k.SealSecret(so, secret.Take([]byte("a signing key")))
	if err != nil {
		t.Fatal(err)
	}
	sn := f2meta(0xcc, 3)
	sn.Kind, sn.Class, sn.Version = "kes.skey", ClassSecret, 5
	rs, err := k.Reseal(so, sn, ss)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := k.OpenSecret(sn, rs)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	buf.Use(func(b []byte) error {
		if string(b) != "a signing key" {
			t.Errorf("secret %q", b)
		}
		return nil
	})
	// reseal does not change the class or the kind
	bad := nm
	bad.Kind = "kes.counter"
	if _, err := k.Reseal(old, bad, sealed); !errors.Is(err, ErrFormat) {
		t.Errorf("a reseal that changes the kind: %v", err)
	}
}
