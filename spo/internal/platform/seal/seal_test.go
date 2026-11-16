package seal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

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

func sensitiveMeta() RecordMeta {
	m := meta()
	m.Kind, m.Class = "kes.vkey", ClassSensitive
	return m
}

func sealSecretBytes(t *testing.T, k *Keys, m RecordMeta, pt string) SealedRecord {
	t.Helper()
	src := buf(pt)
	defer src.Destroy()
	sr, err := k.SealSecret(m, src)
	if err != nil {
		t.Fatal(err)
	}
	return sr
}

func secretString(t *testing.T, b *secret.Buffer) string {
	t.Helper()
	var s string
	if err := b.Use(func(x []byte) error { s = string(x); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRecordRoundTrip(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr := sealSecretBytes(t, k, m, "payload")
	got, err := k.OpenSecret(m, sr)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	if s := secretString(t, got); s != "payload" {
		t.Errorf("got %q", s)
	}
	// Bytes / ParseSealed round trip.
	p, err := ParseSealed(sr.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	g2, err := k.OpenSecret(m, p)
	if err != nil {
		t.Fatal(err)
	}
	g2.Destroy()
	if _, err := k.SealSecret(m, secret.New(1)); err != nil {
		t.Errorf("one-byte secret: %v", err)
	}
	// Sensitive records may be empty.
	sm := sensitiveMeta()
	e, err := k.SealRecord(sm, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k.OpenRecord(sm, e); err != nil || len(pt) != 0 {
		t.Errorf("empty sensitive record: %q %v", pt, err)
	}
	// The class selects the API.
	if _, err := k.SealRecord(m, []byte("x")); !errors.Is(err, ErrFormat) {
		t.Errorf("SealRecord with a secret class: %v", err)
	}
	if _, err := k.SealSecret(sm, buf("x")); !errors.Is(err, ErrFormat) {
		t.Errorf("SealSecret with a sensitive class: %v", err)
	}
	if _, err := k.OpenSecret(sm, e); !errors.Is(err, ErrFormat) {
		t.Errorf("OpenSecret with a sensitive class: %v", err)
	}
}

func TestEveryADFieldIsBound(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr := sealSecretBytes(t, k, m, "payload")
	alter := map[string]func(RecordMeta) RecordMeta{
		"workspace": func(m RecordMeta) RecordMeta { m.WorkspaceID = bytes.Repeat([]byte{9}, IDSize); return m },
		"record id": func(m RecordMeta) RecordMeta { m.RecordID = bytes.Repeat([]byte{9}, IDSize); return m },
		"kind":      func(m RecordMeta) RecordMeta { m.Kind = "kes.vkey"; return m },
		"owner":     func(m RecordMeta) RecordMeta { m.Owner = "pool#8"; return m },
		"version":   func(m RecordMeta) RecordMeta { m.Version = 4; return m },
	}
	for name, f := range alter {
		if _, err := k.OpenSecret(f(m), sr); !errors.Is(err, ErrAuth) {
			t.Errorf("%s altered: %v", name, err)
		}
	}
	// The class is in the AD too: the same bytes under the other class' AD.
	other := m
	other.Class = ClassSensitive
	a1, _ := m.AD()
	a2, _ := other.AD()
	if bytes.Equal(a1, a2) {
		t.Error("class is not in the associated data")
	}
	// So is the payload framing version.
	var ad []any
	if err := cbor.Unmarshal(a1, &ad); err != nil || len(ad) != 8 || ad[7] != uint64(PayloadFormat) {
		t.Errorf("AD %v: payload format not last (%v)", ad, err)
	}
}

// A ciphertext moved to another workspace fails even when every other field
// (record id, kind, owner, version) and the master key are identical.
func TestCiphertextMovedBetweenWorkspaces(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr := sealSecretBytes(t, k, m, "payload")
	m2 := m
	m2.WorkspaceID = bytes.Repeat([]byte{7}, IDSize)
	if _, err := k.OpenSecret(m2, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("secret: %v", err)
	}
	sm := sensitiveMeta()
	e, _ := k.SealRecord(sm, []byte("x"))
	sm2 := sm
	sm2.WorkspaceID = m2.WorkspaceID
	if _, err := k.OpenRecord(sm2, e); !errors.Is(err, ErrAuth) {
		t.Errorf("sensitive: %v", err)
	}
	if _, err := k.OpenOwner(m2.WorkspaceID, m.RecordID, m.Kind, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("owner blob: %v", err)
	}
}

func TestRecordTamper(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sr := sealSecretBytes(t, k, m, "payload")
	flip := func(b []byte) []byte { c := append([]byte(nil), b...); c[0] ^= 1; return c }
	cases := map[string]SealedRecord{
		"nonce":       {flip(sr.Nonce), sr.WrappedKey, sr.Owner, sr.Ciphertext},
		"wrapped key": {sr.Nonce, flip(sr.WrappedKey), sr.Owner, sr.Ciphertext},
		"wrap nonce":  {sr.Nonce, append(flip(sr.WrappedKey[:1]), sr.WrappedKey[1:]...), sr.Owner, sr.Ciphertext},
		"ciphertext":  {sr.Nonce, sr.WrappedKey, sr.Owner, flip(sr.Ciphertext)},
		"tag":         {sr.Nonce, sr.WrappedKey, sr.Owner, append(append([]byte(nil), sr.Ciphertext[:len(sr.Ciphertext)-1]...), sr.Ciphertext[len(sr.Ciphertext)-1]^1)},
	}
	for name, c := range cases {
		if _, err := k.OpenSecret(m, c); !errors.Is(err, ErrAuth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := k.OpenOwner(m.WorkspaceID, m.RecordID, m.Kind, SealedRecord{sr.Nonce, sr.WrappedKey, flip(sr.Owner), sr.Ciphertext}); !errors.Is(err, ErrAuth) {
		t.Errorf("owner: %v", err)
	}
	// A different workspace key cannot open it.
	_, other := fixtureKeys(t)
	if _, err := other.OpenSecret(m, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("other key: %v", err)
	}
	if _, err := k.OpenSecret(m, SealedRecord{}); !errors.Is(err, ErrFormat) {
		t.Errorf("empty: %v", err)
	}
}

// M2: size padding of secret payloads.
func TestSecretPadding(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	for n, want := range map[int]int{1: 256, 64: 256, 252: 256, 253: 512, 508: 512, 509: 1024, 1000: 1024, 1021: 2048} {
		if got := paddedLen(n); got != want {
			t.Errorf("paddedLen(%d) = %d, want %d", n, got, want)
		}
		sr := sealSecretBytes(t, k, m, strings.Repeat("x", n))
		if len(sr.Ciphertext) != want+tagSize {
			t.Errorf("payload of %d bytes: ciphertext %d, want %d", n, len(sr.Ciphertext), want+tagSize)
		}
	}
	// A 12-word and a 24-word mnemonic are indistinguishable.
	a := sealSecretBytes(t, k, m, strings.Repeat("abandon ", 12))
	b := sealSecretBytes(t, k, m, strings.Repeat("abandon ", 24))
	if len(a.Ciphertext) != len(b.Ciphertext) {
		t.Errorf("12 and 24 words differ in size: %d, %d", len(a.Ciphertext), len(b.Ciphertext))
	}
	// Sensitive payloads are not padded.
	e, _ := k.SealRecord(sensitiveMeta(), []byte("abc"))
	if len(e.Ciphertext) != 3+tagSize {
		t.Errorf("sensitive ciphertext %d", len(e.Ciphertext))
	}
	if _, err := k.SealSecret(m, secret.New(MaxSecret+1)); !errors.Is(err, ErrFormat) {
		t.Errorf("oversize: %v", err)
	}
}

// Non-canonical framing authenticates (the sealer is trusted) but is refused
// on open, so a bad writer cannot smuggle data in the padding.
func TestOpenRefusesBadFraming(t *testing.T) {
	_, k := fixtureKeys(t)
	m := meta()
	sealRaw := func(plain []byte) SealedRecord {
		sr, err := defaultSealer.sealRecord(k, m, func(fn func([]byte) error) error { return fn(plain) })
		if err != nil {
			t.Fatal(err)
		}
		return sr
	}
	frame := func(n uint32, size int) []byte {
		b := make([]byte, size)
		binary.BigEndian.PutUint32(b, n)
		return b
	}
	cases := map[string][]byte{
		"non-zero padding":     append(frame(3, 256)[:100], append([]byte{1}, make([]byte, 155)...)...),
		"length past the end":  frame(300, 256),
		"zero length":          frame(0, 256),
		"not the right bucket": frame(3, 512),
		"too short":            {0, 0},
	}
	for name, plain := range cases {
		if _, err := k.OpenSecret(m, sealRaw(plain)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := k.OpenSecret(m, sealRaw(frame(3, 256))); err != nil {
		t.Errorf("canonical framing refused: %v", err)
	}
}

func TestRewrap(t *testing.T) {
	_, old := fixtureKeys(t)
	_, fresh := fixtureKeys(t)
	m := meta()
	sr := sealSecretBytes(t, old, m, "payload")
	owner, err := old.OpenOwner(m.WorkspaceID, m.RecordID, m.Kind, sr)
	if err != nil || owner != m.Owner {
		t.Fatalf("owner %q %v", owner, err)
	}
	re, err := old.Rewrap(fresh, m, sr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(re.Nonce, sr.Nonce) || !bytes.Equal(re.Ciphertext, sr.Ciphertext) {
		t.Error("rewrap changed the ciphertext")
	}
	if bytes.Equal(re.WrappedKey, sr.WrappedKey) || bytes.Equal(re.Owner, sr.Owner) {
		t.Error("rewrap kept the old wrapping")
	}
	got, err := fresh.OpenSecret(m, re)
	if err != nil {
		t.Fatal(err)
	}
	if secretString(t, got) != "payload" {
		t.Error("payload changed")
	}
	if _, err := old.OpenSecret(m, re); !errors.Is(err, ErrAuth) {
		t.Errorf("old keys still open the rewrapped record: %v", err)
	}
	if o, err := fresh.OpenOwner(m.WorkspaceID, m.RecordID, m.Kind, re); err != nil || o != m.Owner {
		t.Errorf("owner after rewrap %q %v", o, err)
	}
	wrong := m
	wrong.Owner = "other#1"
	if _, err := old.Rewrap(fresh, wrong, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("rewrap with a wrong owner: %v", err)
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
		"commit":  func(s Slot) Slot { n := append([]byte(nil), s.Commit...); n[0] ^= 1; s.Commit = n; return s },
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

// M3: every guarded buffer made by seal is destroyed on every path, success
// or failure.
func TestNoBufferLeaks(t *testing.T) {
	_, k := fixtureKeys(t)
	_, other := fixtureKeys(t)
	before := secret.Budget().Live
	m := meta()
	src := buf("payload")
	for i := 0; i < 20; i++ {
		sr, err := k.SealSecret(m, src)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := k.OpenSecret(m, sr)
		if err != nil {
			t.Fatal(err)
		}
		pt.Destroy()
		// Failure paths.
		if _, err := other.OpenSecret(m, sr); err == nil {
			t.Fatal("opened under another key")
		}
		bad := sr
		bad.Ciphertext = append([]byte(nil), sr.Ciphertext...)
		bad.Ciphertext[0] ^= 1
		if _, err := k.OpenSecret(m, bad); err == nil {
			t.Fatal("tampered opened")
		}
		re, err := k.Rewrap(other, m, sr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.Rewrap(other, m, re); err == nil {
			t.Fatal("rewrapped under the wrong keys")
		}
	}
	src.Destroy()
	if got := secret.Budget().Live; got != before {
		t.Errorf("live buffers %d, started with %d", got, before)
	}
}

func TestKDFCeiling(t *testing.T) {
	withProductionFloor(t)
	if err := MaxKDF().Validate(); err != nil {
		t.Errorf("maximum refused: %v", err)
	}
	over := MaxKDF()
	over.Passes++
	if err := over.Validate(); !errors.Is(err, ErrWeakKDF) {
		t.Errorf("11 passes: %v", err)
	}
	over = MaxKDF()
	over.MemoryKiB++
	if err := over.Validate(); !errors.Is(err, ErrWeakKDF) {
		t.Errorf("over 1 GiB: %v", err)
	}
}

// Finding 13: the owner blob has one length whatever the name.
func TestOwnerBlobLengthDoesNotRevealTheName(t *testing.T) {
	_, k := fixtureKeys(t)
	var want int
	for _, owner := range []string{"", "a#0", "pool#7", strings.Repeat("n", 128) + "#12345678901234567890"} {
		m := sensitiveMeta()
		m.Owner = owner
		sr, err := k.SealRecord(m, []byte("x"))
		if err != nil {
			t.Fatalf("owner %q: %v", owner, err)
		}
		if want == 0 {
			want = len(sr.Owner)
		}
		if len(sr.Owner) != want || want != NonceSize+ownerBucket+tagSize {
			t.Errorf("owner of %d bytes sealed to %d bytes, want %d", len(owner), len(sr.Owner), NonceSize+ownerBucket+tagSize)
		}
		if got, err := k.OpenOwner(m.WorkspaceID, m.RecordID, m.Kind, sr); err != nil || got != owner {
			t.Errorf("owner %q came back as %q (%v)", owner, got, err)
		}
	}
	m := sensitiveMeta()
	m.Owner = strings.Repeat("n", maxOwner+1)
	if _, err := k.SealRecord(m, []byte("x")); !errors.Is(err, ErrFormat) {
		t.Errorf("an owner longer than %d bytes: %v", maxOwner, err)
	}
	// Padding that is not zero, or a length field out of range, is refused.
	for name, b := range map[string][]byte{
		"short":    make([]byte, ownerBucket-1),
		"length":   append([]byte{0xff, 0xff}, make([]byte, ownerBucket-2)...),
		"padding":  append([]byte{0, 1, 'a', 1}, make([]byte, ownerBucket-4)...),
		"too long": make([]byte, ownerBucket+1),
	} {
		if _, err := unpadOwner(b); err == nil {
			t.Errorf("%s: unpadOwner accepted it", name)
		}
	}
}

// Finding 1: the epoch MAC binds the audit key, the workspace and the epoch.
func TestEpochMAC(t *testing.T) {
	_, k := fixtureKeys(t)
	_, other := fixtureKeys(t)
	ws := bytes.Repeat([]byte{1}, IDSize)
	ep, err := NewEpoch()
	if err != nil {
		t.Fatal(err)
	}
	mac, err := k.Audit.EpochMAC(ws, ep)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := k.Audit.CheckEpoch(ws, ep, mac); !ok {
		t.Error("the epoch MAC does not check under its own key")
	}
	ep2 := append([]byte(nil), ep...)
	ep2[0] ^= 1
	ws2 := append([]byte(nil), ws...)
	ws2[0] ^= 1
	mac2 := append([]byte(nil), mac...)
	mac2[31] ^= 1
	for name, ok := range map[string]func() (bool, error){
		"other key":       func() (bool, error) { return other.Audit.CheckEpoch(ws, ep, mac) },
		"other epoch":     func() (bool, error) { return k.Audit.CheckEpoch(ws, ep2, mac) },
		"other workspace": func() (bool, error) { return k.Audit.CheckEpoch(ws2, ep, mac) },
		"flipped MAC":     func() (bool, error) { return k.Audit.CheckEpoch(ws, ep, mac2) },
	} {
		if got, err := ok(); err != nil || got {
			t.Errorf("%s: accepted (%v, %v)", name, got, err)
		}
	}
	if _, err := k.Audit.EpochMAC(ws, ep[:8]); !errors.Is(err, ErrFormat) {
		t.Errorf("a short epoch: %v", err)
	}
}

// Input longer than any valid text is refused before it is copied, so the
// cleaned copy never outgrows its first allocation.
func TestDecodeRecoveryKeyRefusesLongInputUpFront(t *testing.T) {
	long := strings.Repeat("A", recoveryChars+1)
	if _, err := DecodeRecoveryKey(buf(long)); !errors.Is(err, ErrRecoveryFormat) {
		t.Errorf("one character too many: %v", err)
	}
	// Separators do not count, however many there are.
	raw := secret.New(KeySize)
	defer raw.Destroy()
	txt, err := EncodeRecoveryKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer txt.Destroy()
	var s string
	txt.Use(func(b []byte) error { s = strings.ReplaceAll(string(b), "-", " - \t\n"); return nil })
	if out, err := DecodeRecoveryKey(buf(s)); err != nil {
		t.Errorf("a valid key with many separators: %v", err)
	} else {
		out.Destroy()
	}
}
