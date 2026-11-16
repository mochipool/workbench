package seal

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

var smallKDF = KDFParams{MemoryKiB: 64, Passes: 1, Lanes: 1}

func buf(s string) *secret.Buffer { return secret.Take([]byte(s)) }

func fixtureKeys(t *testing.T) (*secret.Buffer, *Keys) {
	t.Helper()
	m, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := DeriveKeys(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Destroy(); k.Destroy() })
	return m, k
}

func meta() RecordMeta {
	ws := bytes.Repeat([]byte{1}, IDSize)
	id := bytes.Repeat([]byte{2}, IDSize)
	return RecordMeta{WorkspaceID: ws, RecordID: id, Kind: "kes.skey", Owner: "pool#7", Class: ClassSecret, Version: 3}
}

func TestRecordRoundTrip(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr, err := k.SealRecord(m, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.OpenRecord(m, sr)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	got.Use(func(b []byte) error {
		if string(b) != "payload" {
			t.Errorf("got %q", b)
		}
		return nil
	})
	// Bytes / ParseSealed round trip.
	p, err := ParseSealed(sr.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	g2, err := k.OpenRecord(m, p)
	if err != nil {
		t.Fatal(err)
	}
	g2.Destroy()
	if _, err := k.SealRecord(m, nil); err == nil {
		t.Error("empty payload accepted")
	}
}

func TestEveryADFieldIsBound(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr, err := k.SealRecord(m, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	alter := map[string]func(RecordMeta) RecordMeta{
		"workspace": func(m RecordMeta) RecordMeta { m.WorkspaceID = bytes.Repeat([]byte{9}, IDSize); return m },
		"record id": func(m RecordMeta) RecordMeta { m.RecordID = bytes.Repeat([]byte{9}, IDSize); return m },
		"kind":      func(m RecordMeta) RecordMeta { m.Kind = "kes.vkey"; return m },
		"owner":     func(m RecordMeta) RecordMeta { m.Owner = "pool#8"; return m },
		"class":     func(m RecordMeta) RecordMeta { m.Class = ClassSensitive; return m },
		"version":   func(m RecordMeta) RecordMeta { m.Version = 4; return m },
	}
	for name, f := range alter {
		if _, err := k.OpenRecord(f(m), sr); !errors.Is(err, ErrAuth) {
			t.Errorf("%s altered: %v", name, err)
		}
	}
}

func TestRecordTamper(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr, _ := k.SealRecord(m, []byte("payload"))
	flip := func(b []byte) []byte { c := append([]byte(nil), b...); c[0] ^= 1; return c }
	cases := map[string]SealedRecord{
		"nonce":       {flip(sr.Nonce), sr.WrappedKey, sr.Ciphertext},
		"wrapped key": {sr.Nonce, flip(sr.WrappedKey), sr.Ciphertext},
		"wrap nonce":  {sr.Nonce, append(flip(sr.WrappedKey[:1]), sr.WrappedKey[1:]...), sr.Ciphertext},
		"ciphertext":  {sr.Nonce, sr.WrappedKey, flip(sr.Ciphertext)},
		"tag":         {sr.Nonce, sr.WrappedKey, append(append([]byte(nil), sr.Ciphertext[:len(sr.Ciphertext)-1]...), sr.Ciphertext[len(sr.Ciphertext)-1]^1)},
	}
	for name, c := range cases {
		if _, err := k.OpenRecord(m, c); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A different workspace key cannot open it.
	_, other := fixtureKeys(t)
	if _, err := other.OpenRecord(m, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("other key: %v", err)
	}
	if _, err := k.OpenRecord(m, SealedRecord{}); !errors.Is(err, ErrFormat) {
		t.Errorf("empty: %v", err)
	}
}

func TestPassphraseSlot(t *testing.T) {
	master, _ := fixtureKeys(t)
	ws, _ := NewID()
	sid, _ := NewID()
	pw := buf("correct horse")
	slot, err := NewPassphraseSlot(ws, sid, master, pw, smallKDF)
	if err != nil {
		t.Fatal(err)
	}
	got, err := slot.Unwrap(ws, pw)
	if err != nil {
		t.Fatal(err)
	}
	sameKey(t, master, got)
	if _, err := slot.Unwrap(ws, buf("wrong")); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong passphrase: %v", err)
	}
	other, _ := NewID()
	if _, err := slot.Unwrap(other, pw); !errors.Is(err, ErrAuth) {
		t.Errorf("other workspace: %v", err)
	}
	// Every slot field is bound.
	mods := map[string]func(Slot) Slot{
		"id":      func(s Slot) Slot { s.ID = other; return s },
		"kind":    func(s Slot) Slot { s.Kind = SlotRecovery; return s },
		"memory":  func(s Slot) Slot { s.KDF.MemoryKiB *= 2; return s },
		"passes":  func(s Slot) Slot { s.KDF.Passes++; return s },
		"lanes":   func(s Slot) Slot { s.KDF.Lanes++; return s },
		"salt":    func(s Slot) Slot { s.Salt = other; return s },
		"nonce":   func(s Slot) Slot { n := append([]byte(nil), s.Nonce...); n[0] ^= 1; s.Nonce = n; return s },
		"wrapped": func(s Slot) Slot { n := append([]byte(nil), s.Wrapped...); n[0] ^= 1; s.Wrapped = n; return s },
	}
	for name, f := range mods {
		if _, err := f(slot).Unwrap(ws, pw); err == nil {
			t.Errorf("slot %s altered: opened", name)
		}
	}
	if _, err := NewPassphraseSlot(ws, sid, master, buf(""), smallKDF); err == nil {
		t.Error("empty passphrase accepted")
	}
}

func sameKey(t *testing.T, a, b *secret.Buffer) {
	t.Helper()
	a.Use(func(x []byte) error {
		return b.Use(func(y []byte) error {
			if !bytes.Equal(x, y) {
				t.Error("keys differ")
			}
			return nil
		})
	})
}

func TestWeakKDFRefused(t *testing.T) {
	withProductionFloor(t)
	master, _ := fixtureKeys(t)
	ws, _ := NewID()
	sid, _ := NewID()
	pw := buf("pw")
	good := MinKDF()
	slot, err := NewPassphraseSlot(ws, sid, master, pw, good)
	if err != nil {
		t.Fatal(err)
	}
	weak := map[string]KDFParams{
		"memory": {MemoryKiB: good.MemoryKiB - 1, Passes: good.Passes, Lanes: 1},
		"passes": {MemoryKiB: good.MemoryKiB, Passes: good.Passes - 1, Lanes: 1},
		"lanes":  {MemoryKiB: good.MemoryKiB, Passes: good.Passes, Lanes: 0},
		"huge":   {MemoryKiB: maxKDFMemoryKiB + 1, Passes: good.Passes, Lanes: 1},
	}
	for name, p := range weak {
		s := slot
		s.KDF = p
		if _, err := s.Unwrap(ws, pw); !errors.Is(err, ErrWeakKDF) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := NewPassphraseSlot(ws, sid, master, pw, p); !errors.Is(err, ErrWeakKDF) {
			t.Errorf("create %s: %v", name, err)
		}
	}
	if err := DefaultKDF().validate(); err != nil {
		t.Errorf("default refused: %v", err)
	}
}

func TestRecoverySlot(t *testing.T) {
	master, _ := fixtureKeys(t)
	ws, _ := NewID()
	sid, _ := NewID()
	slot, rk, err := NewRecoverySlot(ws, sid, master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := slot.Unwrap(ws, rk)
	if err != nil {
		t.Fatal(err)
	}
	sameKey(t, master, got)
	wrong := secret.New(KeySize)
	if _, err := slot.Unwrap(ws, wrong); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := slot.Unwrap(ws, buf("short")); !errors.Is(err, ErrFormat) {
		t.Errorf("short key: %v", err)
	}
}

func TestRecoveryKeyText(t *testing.T) {
	// A fixed key keeps the exhaustive typo check below deterministic: a
	// truncated hash detects a given typo with probability 1 - 2^-24, not 1.
	fixed := make([]byte, KeySize)
	for i := range fixed {
		fixed[i] = byte(7*i + 3)
	}
	rk := secret.Take(fixed)
	txt, err := EncodeRecoveryKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	var s string
	txt.Use(func(b []byte) error { s = string(b); return nil })
	if len(s) != 56+13 || strings.Count(s, "-") != 13 {
		t.Fatalf("shape: %q", s)
	}
	back, err := DecodeRecoveryKey(txt)
	if err != nil {
		t.Fatal(err)
	}
	sameKey(t, rk, back)
	// Lower case, spaces and missing dashes are accepted.
	loose := buf(strings.ToLower(strings.ReplaceAll(s, "-", " ")))
	if b2, err := DecodeRecoveryKey(loose); err != nil {
		t.Errorf("loose: %v", err)
	} else {
		sameKey(t, rk, b2)
	}
	// Every single-character substitution is detected (checksum or format).
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	undetected := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		for _, c := range []byte(alpha) {
			if c == s[i] {
				continue
			}
			mut := []byte(s)
			mut[i] = c
			// Destroy each buffer: guarded memory is locked, and the
			// process may lock only a limited amount.
			in := secret.Take(mut)
			if out, err := DecodeRecoveryKey(in); err == nil {
				undetected++
				out.Destroy()
			}
			in.Destroy()
		}
	}
	if undetected != 0 {
		t.Errorf("%d single-character typos went undetected", undetected)
	}
	// Transposed neighbours.
	mut := []byte(s)
	mut[0], mut[1] = mut[1], mut[0]
	if mut[0] != s[0] {
		if _, err := DecodeRecoveryKey(secret.Take(mut)); err == nil {
			t.Error("transposition undetected")
		}
	}
	if _, err := DecodeRecoveryKey(buf(s[:20])); !errors.Is(err, ErrRecoveryFormat) {
		t.Errorf("short: %v", err)
	}
	if _, err := DecodeRecoveryKey(buf("1" + s[1:])); !errors.Is(err, ErrRecoveryFormat) {
		t.Errorf("bad char: %v", err)
	}
}

func TestIndexTagSeparation(t *testing.T) {
	_, k := fixtureKeys(t)
	tag := func(ns string, parts ...string) string {
		var bs [][]byte
		for _, p := range parts {
			bs = append(bs, []byte(p))
		}
		b, err := k.Index.Tag(ns, bs...)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != MACSize {
			t.Fatal("tag size")
		}
		return string(b)
	}
	if tag("n", "a", "bc") == tag("n", "ab", "c") {
		t.Error("a|bc == ab|c")
	}
	if tag("n", "a") == tag("m", "a") {
		t.Error("namespaces collide")
	}
	if tag("n", "a", "") == tag("n", "a") || tag("n", "", "a") == tag("n", "a") {
		t.Error("empty parts collide")
	}
	if tag("n", "a") != tag("n", "a") {
		t.Error("not deterministic")
	}
	_, k2 := fixtureKeys(t)
	b, _ := k2.Index.Tag("n", []byte("a"))
	if string(b) == tag("n", "a") {
		t.Error("tag does not depend on the key")
	}
}

func TestAuditMAC(t *testing.T) {
	_, k := fixtureKeys(t)
	prev := make([]byte, MACSize)
	row, _ := EncodeCanonical([]any{1, "x"})
	mac, err := k.Audit.MAC(prev, row)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := k.Audit.Check(prev, row, mac); !ok {
		t.Error("good mac rejected")
	}
	row2, _ := EncodeCanonical([]any{1, "y"})
	prev2 := append([]byte(nil), prev...)
	prev2[0] ^= 1
	if ok, _ := k.Audit.Check(prev, row2, mac); ok {
		t.Error("row change accepted")
	}
	if ok, _ := k.Audit.Check(prev2, row, mac); ok {
		t.Error("prev change accepted")
	}
	// Length prefix: moving a byte between prev and row changes the MAC.
	a, _ := k.Audit.MAC([]byte("ab"), []byte("c"))
	b, _ := k.Audit.MAC([]byte("a"), []byte("bc"))
	if bytes.Equal(a, b) {
		t.Error("prev|row boundary ambiguous")
	}
}

func TestSubkeysDistinct(t *testing.T) {
	m, k := fixtureKeys(t)
	seen := map[string]bool{}
	for _, l := range []string{labelRecordWrap, labelIndex, labelAudit, labelRecoverySlot} {
		kk, err := hkdfKey(m, l)
		if err != nil {
			t.Fatal(err)
		}
		kk.Use(func(b []byte) error {
			if seen[string(b)] {
				t.Errorf("label %s repeats a key", l)
			}
			seen[string(b)] = true
			return nil
		})
	}
	_ = k
}
