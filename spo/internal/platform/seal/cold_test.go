package seal

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func coldMeta() RecordMeta { m := meta(); m.Class = ClassSecretCold; return m }

func coldSub(t *testing.T, seed byte, id []byte) *secret.Buffer {
	t.Helper()
	out := secret.Take(bytes.Repeat([]byte{seed}, KeySize))
	defer out.Destroy()
	sub, err := DeriveColdSubKey(out, bytes.Repeat([]byte{1}, IDSize), uint32(StoreFormat), id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sub.Destroy)
	return sub
}

func passHeader() ColdHeader {
	return ColdHeader{Kind: ColdPassphrase, KDF: smallKDF, Salt: bytes.Repeat([]byte{9}, SaltSize)}
}

func fidoHeader() ColdHeader {
	return ColdHeader{Kind: ColdFIDO2, Credential: []byte("credential"), Salt: bytes.Repeat([]byte{7}, 32), Next: bytes.Repeat([]byte{8}, 32)}
}

func recPair(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	p, err := ecdh.X25519().GenerateKey(rngForTest{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type rngForTest struct{}

func (rngForTest) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return len(b), nil
}

var coldID = bytes.Repeat([]byte{0xab}, 28)

// spec: SPO-Xcustody-INV-009
func TestColdRecordOpensOnlyWithTheSubKey(t *testing.T) {
	_, k := fixtureKeys(t)
	m := coldMeta()
	sub := coldSub(t, 5, coldID)
	src := buf("a cold signing key")
	defer src.Destroy()
	r, err := k.SealSecretCold(m, src, ColdSeal{Sub: sub, Header: passHeader()})
	if err != nil {
		t.Fatal(err)
	}
	if !IsColdSealed(r) {
		t.Fatal("a cold record has the hot wrapped-key form")
	}
	// the ordinary data key (the master key's record-wrapping key) alone opens nothing
	if _, err := k.OpenSecret(meta(), r); err == nil {
		t.Fatal("the hot opener opened a cold record")
	}
	if _, err := k.OpenSecret(m, r); err == nil {
		t.Fatal("the hot opener opened a cold record under the cold class")
	}
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		t.Fatalf("the outer layer must open with the master key: %v", err)
	}
	if _, err := oc.OpenSecret(coldSub(t, 6, coldID)); !errors.Is(err, ErrAuth) {
		t.Fatalf("another sub-key opened the record: %v", err)
	}
	if _, err := oc.OpenSecret(coldSub(t, 5, bytes.Repeat([]byte{0xac}, 28))); !errors.Is(err, ErrAuth) {
		t.Fatalf("a sub-key of another identity opened the record: %v", err)
	}
	got, err := oc.OpenSecret(sub)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	if secretString(t, got) != "a cold signing key" {
		t.Fatal("round trip")
	}
	// a hot record is not opened as cold
	hot := sealSecretBytes(t, k, meta(), "hot")
	if _, err := k.OpenColdOuter(m, hot); err == nil {
		t.Fatal("a hot record opened as cold")
	}
}

// spec: SPO-Xcustody-INV-010
func TestColdClassAndEveryFieldAreAuthenticated(t *testing.T) {
	_, k := fixtureKeys(t)
	m := coldMeta()
	sub := coldSub(t, 5, coldID)
	src := buf("payload")
	defer src.Destroy()
	r, err := k.SealSecretCold(m, src, ColdSeal{Sub: sub, Header: fidoHeader(), Recovery: &ColdRecovery{Pub: recPair(t).PublicKey().Bytes(), Identity: coldID}})
	if err != nil {
		t.Fatal(err)
	}
	for name, mm := range map[string]func(RecordMeta) RecordMeta{
		"class hot": func(x RecordMeta) RecordMeta { x.Class = ClassSecret; return x },
		"version":   func(x RecordMeta) RecordMeta { x.Version++; return x },
		"kind":      func(x RecordMeta) RecordMeta { x.Kind = "node.skey"; return x },
		"record id": func(x RecordMeta) RecordMeta { x.RecordID = bytes.Repeat([]byte{3}, IDSize); return x },
		"workspace": func(x RecordMeta) RecordMeta { x.WorkspaceID = bytes.Repeat([]byte{4}, IDSize); return x },
	} {
		if _, err := k.OpenColdOuter(mm(m), r); err == nil {
			t.Errorf("%s: the cold record opened under changed associated data", name)
		}
	}
	flip := func(name string, edit func(*SealedRecord)) {
		c := SealedRecord{Nonce: append([]byte(nil), r.Nonce...), WrappedKey: append([]byte(nil), r.WrappedKey...), Owner: r.Owner, Ciphertext: append([]byte(nil), r.Ciphertext...)}
		edit(&c)
		oc, err := k.OpenColdOuter(m, c)
		if err == nil {
			_, err = oc.OpenSecret(sub)
		}
		if err == nil {
			t.Errorf("%s: an edited cold record opened", name)
		}
	}
	for i := range r.WrappedKey {
		i := i
		flip("wrapped key byte", func(c *SealedRecord) { c.WrappedKey[i] ^= 1 })
	}
	flip("payload", func(c *SealedRecord) { c.Ciphertext[0] ^= 1 })
	flip("nonce", func(c *SealedRecord) { c.Nonce[0] ^= 1 })
	// a hot-sized wrapped key is not a cold record, and a cold one is not hot
	flip("truncated to the hot form", func(c *SealedRecord) { c.WrappedKey = c.WrappedKey[:wrappedKeyLen] })
}

// spec: SPO-Xcustody-INV-011
func TestColdHeaderRoundTripAndValidation(t *testing.T) {
	for _, h := range []ColdHeader{passHeader(), fidoHeader(), prevHeader()} {
		b, err := h.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeColdHeader(b)
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := got.Encode(); !bytes.Equal(again, b) {
			t.Fatal("header does not round trip")
		}
		if _, err := DecodeColdHeader(append(append([]byte(nil), b...), 0)); err == nil {
			t.Fatal("trailing bytes accepted")
		}
	}
	bad := []ColdHeader{
		{Kind: ColdPassphrase, KDF: smallKDF, Salt: make([]byte, 8)},
		{Kind: ColdPassphrase, KDF: KDFParams{MemoryKiB: 1, Passes: 1, Lanes: 1}, Salt: make([]byte, SaltSize)}, // below the floor
		{Kind: ColdFIDO2, Credential: nil, Salt: make([]byte, 32), Next: make([]byte, 32)},
		{Kind: ColdFIDO2, Credential: []byte("c"), Salt: make([]byte, 31), Next: make([]byte, 32)},
		{Kind: 9},
	}
	for i, h := range bad {
		if _, err := h.Encode(); err == nil {
			t.Errorf("bad header %d accepted", i)
		}
	}
}

// spec: SPO-Xcustody-INV-012
func TestRewrapColdChangesOnlyTheOuterLayer(t *testing.T) {
	_, k := fixtureKeys(t)
	_, k2 := fixtureKeys(t)
	m := coldMeta()
	sub := coldSub(t, 5, coldID)
	src := buf("rewrapped")
	defer src.Destroy()
	r, err := k.SealSecretCold(m, src, ColdSeal{Sub: sub, Header: passHeader()})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := k.RewrapCold(k2, m, r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r2.Ciphertext, r.Ciphertext) || !bytes.Equal(r2.Nonce, r.Nonce) || bytes.Equal(r2.WrappedKey, r.WrappedKey) {
		t.Fatal("a rewrap must keep the payload and change the wrapped key")
	}
	if _, err := k.OpenColdOuter(m, r2); err == nil {
		t.Fatal("the old keys open a rewrapped record")
	}
	oc, err := k2.OpenColdOuter(m, r2)
	if err != nil {
		t.Fatal(err)
	}
	got, err := oc.OpenSecret(sub)
	if err != nil {
		t.Fatal(err)
	}
	got.Destroy()
}

// RFC 9180 Appendix A.2 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
// ChaCha20-Poly1305, base mode), sequence number 0, through the opener that the
// recovery path uses. The vector is the one in the Go standard library's
// crypto/hpke testdata (rfc9180.json), where its keys are given.
//
// spec: SPO-Xcustody-INV-013, SPO-Xcustody-EXT-003
func TestHPKEKnownAnswerRFC9180A2(t *testing.T) {
	unhex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sk := unhex("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
	pk := unhex("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
	enc := unhex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
	info := unhex("4f6465206f6e2061204772656369616e2055726e")
	aad := unhex("436f756e742d30")
	pt := unhex("4265617574792069732074727574682c20747275746820626561757479")
	ct := unhex("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28")
	priv, err := ecdh.X25519().NewPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), pk) {
		t.Fatal("the vector's public key is not the one of its private key")
	}
	got, err := hpkeOpenBase(priv, info, aad, append(append([]byte(nil), enc...), ct...))
	if err != nil {
		t.Fatalf("the RFC 9180 A.2 ciphertext does not open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("plaintext differs from the RFC 9180 A.2 vector")
	}
	// the sealing side of the same code path round trips, with the same suite
	w, err := hpkeSealBase(priv.PublicKey(), info, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 32+len(pt)+16 {
		t.Fatalf("wrap length %d", len(w))
	}
	back, err := hpkeOpenBase(priv, info, aad, w)
	if err != nil || !bytes.Equal(back, pt) {
		t.Fatalf("round trip: %v", err)
	}
	for name, c := range map[string]struct{ info, aad []byte }{"info": {append(append([]byte(nil), info...), 0), aad}, "aad": {info, append(append([]byte(nil), aad...), 0)}} {
		if _, err := hpkeOpenBase(priv, c.info, c.aad, w); err == nil {
			t.Errorf("a wrap opened with another %s", name)
		}
	}
}

// spec: SPO-Xcustody-INV-014
func TestRecoveryWrapBindsItsContext(t *testing.T) {
	_, k := fixtureKeys(t)
	priv := recPair(t)
	m := coldMeta()
	sub := coldSub(t, 5, coldID)
	src := buf("planted?")
	defer src.Destroy()
	seal := func(mm RecordMeta, rec *ColdRecovery) SealedRecord {
		r, err := k.SealSecretCold(mm, src, ColdSeal{Sub: sub, Header: passHeader(), Recovery: rec})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := seal(m, &ColdRecovery{Pub: priv.PublicKey().Bytes(), Identity: coldID})
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := oc.RecoverDataKey(priv, coldID)
	if err != nil {
		t.Fatalf("recovery unwrap: %v", err)
	}
	pt, err := oc.OpenSecretWithDataKey(dk)
	dk.Destroy()
	if err != nil || secretString(t, pt) != "planted?" {
		t.Fatalf("recovery open: %v", err)
	}
	// wrong identity, another recovery key
	if _, err := oc.RecoverDataKey(priv, bytes.Repeat([]byte{0xac}, 28)); err == nil {
		t.Error("a wrap opened for another record identity")
	}
	if _, err := oc.RecoverDataKey(recPairSeed(t, 9), coldID); err == nil {
		t.Error("a wrap opened with another recovery private key")
	}
	// the wrap of another record or an older version of this one does not open for this record
	other := m
	other.RecordID = bytes.Repeat([]byte{3}, IDSize)
	ro := seal(other, &ColdRecovery{Pub: priv.PublicKey().Bytes(), Identity: coldID})
	oo, _ := k.OpenColdOuter(other, ro)
	older := m
	older.Version--
	rv := seal(older, &ColdRecovery{Pub: priv.PublicKey().Bytes(), Identity: coldID})
	ov, _ := k.OpenColdOuter(older, rv)
	// graft those wraps into this record's outer layer by re-sealing it (a master-key holder can)
	for name, wrap := range map[string][]byte{"another record": oo.RecoveryWrap(), "an older version": ov.RecoveryWrap()} {
		forged := forgeWrap(t, k, m, r, wrap)
		fo, err := k.OpenColdOuter(m, forged)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := fo.RecoverDataKey(priv, coldID); err == nil {
			t.Errorf("the wrap of %s opened for this record", name)
		}
	}
	// another workspace
	otherWS := m
	otherWS.WorkspaceID = bytes.Repeat([]byte{4}, IDSize)
	rw := seal(otherWS, &ColdRecovery{Pub: priv.PublicKey().Bytes(), Identity: coldID})
	ow, _ := k.OpenColdOuter(otherWS, rw)
	if _, err := forgeOpen(t, k, m, r, ow.RecoveryWrap()).RecoverDataKey(priv, coldID); err == nil {
		t.Error("the wrap of another workspace opened for this record")
	}
	// a record without a recovery path has no wrap to open
	rn := seal(m, nil)
	on, _ := k.OpenColdOuter(m, rn)
	if len(on.RecoveryWrap()) != 0 {
		t.Error("a record sealed without a recovery key carries a wrap")
	}
	if _, err := on.RecoverDataKey(priv, coldID); !errors.Is(err, ErrNoRecoveryWrap) {
		t.Errorf("no wrap: %v", err)
	}
}

func recPairSeed(t *testing.T, seed byte) *ecdh.PrivateKey {
	t.Helper()
	p, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// forgeWrap rebuilds the outer layer of r around another recovery wrap, as the
// holder of the master key can (the outer layer is under the record-wrapping
// key); the inner wrap and the payload are unchanged.
func forgeWrap(t *testing.T, k *Keys, m RecordMeta, r SealedRecord, wrap []byte) SealedRecord {
	t.Helper()
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		t.Fatal(err)
	}
	rh := hashOf(wrap)
	outerAD, _ := coldAD(labelColdOuter, oc.ad, oc.hdr, rh)
	nonce := bytes.Repeat([]byte{5}, NonceSize)
	var outer []byte
	k.wrap.Use(func(wk []byte) error {
		w, e := aeadSeal(wk, nonce, oc.outerPlain(), outerAD)
		outer = append(nonce, w...)
		return e
	})
	blob, err := coldBlob{hdr: oc.hdr, outer: outer, rec: wrap}.encode()
	if err != nil {
		t.Fatal(err)
	}
	r.WrappedKey = blob
	return r
}

func forgeOpen(t *testing.T, k *Keys, m RecordMeta, r SealedRecord, wrap []byte) *ColdOuter {
	t.Helper()
	oc, err := k.OpenColdOuter(m, forgeWrap(t, k, m, r, wrap))
	if err != nil {
		t.Fatal(err)
	}
	return oc
}

// A pinned cold record (no recovery wrap: the HPKE ephemeral key is drawn from
// crypto/rand), so a change to any byte of the form is a format change.
//
// spec: SPO-Xcustody-OUT-009
func TestColdRecordVector(t *testing.T) {
	master := secret.Take(pattern(0x10, KeySize))
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	m := RecordMeta{WorkspaceID: pattern(0x01, IDSize), RecordID: pattern(0x21, IDSize), Kind: "node.skey", Anchor: append([]byte{0x00}, pattern(0x40, 28)...), Class: ClassSecretCold, Version: 4, Format: RecordFormat}
	ident := pattern(0x60, 28)
	sub, err := DeriveColdSubKey(secret.Take(pattern(0x70, KeySize)), m.WorkspaceID, uint32(StoreFormat), ident)
	if err != nil {
		t.Fatal(err)
	}
	src := secret.Take([]byte("pinned cold signing key"))
	padded, err := frameSecret(src)
	if err != nil {
		t.Fatal(err)
	}
	rng := &scripted{t: t, chunks: [][]byte{pattern(0x80, NonceSize), pattern(0x90, NonceSize), pattern(0xa0, NonceSize), pattern(0xb0, NonceSize)}}
	hdr := ColdHeader{Kind: ColdPassphrase, KDF: smallKDF, Salt: pattern(0xc0, SaltSize)}
	r, err := sealer{rand: rng}.sealColdWith(keys, m, padded, secret.Take(pattern(0xd0, KeySize)), ColdSeal{Sub: sub, Header: hdr})
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	got := hex.EncodeToString(r.WrappedKey) + "|" + hex.EncodeToString(r.Ciphertext) + "|" + hex.EncodeToString(r.Owner)
	const want = "847173706f2f636f6c642d7265636f72642f315785010118400150c0c1c2c3c4c5c6c7c8c9cacbcccdcecf5870a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7ea488ccee5eb3b5d7a263d36a40eb08d1dfc745c14e113147752c756dd26fa1b86b8f4f34c0ca70ab776bef633a163c45ea5605dbf130c62400981c0a04c6761ce0cd897edb2b3f47f290389b82b82d2c3ac9016570bfc0540|b89fb4989f85f748d247b8673b511e48a95fc00af38fc21377c85565ad70b21ceb14f52877707dee0357240f38656891355a47163492f732c9815863788658166ce59399589debe9ec3f528346670d00469bd0639f73787306c1966c38ac5cbc4b1e820dca6e0ed1862bc7573b15e165ebdeef69b7387102bd5ebfdc270c4cfcafb2d1b14aebdd7342d1186a5b05445cbd073430855b6ffc1b06819e33bc124897d5e67ffaadd9a32bfb5511cc71c1ad5df447601d93e2aea15913302af5f0d96393fdcd99819cae8eb76462c0dad338dbe1d31f55e8e86152183df1715226acb5a02df04d7c2daafe39593ed46ea76cf9f3194b4b2139bbd0f04412cf0498f96b94826b4bd4db49ebfd1e53542b3df4|b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7fc703afa23ca63332a03e877712bfc0fab4bd0a7e3ab6d3a263e63721af5d7a44b1162105bdbc76aa2de35ac79eedb0d25c827005199c7783423b7ed8ec381c13c37f51deda3556808246ec6791610d39d099bb690afae08fe4800a30a35e2f927c8bb230ac6753a27cdf97e79884e0689751522732a615452b7684d9ef2db4f66f5e3076265a7a5b832d529a994caae590fa99c8cfb9a87a8d3d5d080ba0731b031b871bd7c5d1346a9701925db659d"
	if got != want {
		t.Fatalf("cold record bytes changed:\n%s", got)
	}
	oc, err := keys.OpenColdOuter(m, r)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := oc.OpenSecret(sub)
	if err != nil || secretString(t, pt) != "pinned cold signing key" {
		t.Fatal(err)
	}
}

// The recovery wrap and the sub-key bind the version of the cold record form, not
// the store format: a later store format does not strand a cold record.
//
// spec: SPO-Xcustody-INV-018
func TestColdBindingsUseTheColdRecordFormatNotTheStoreFormat(t *testing.T) {
	info, err := RecoveryWrapInfo([]byte("nonce"), []byte("hash"), []byte("ident"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := EncodeCanonical([]any{ColdWrapLabel, uint64(1), []byte("nonce"), []byte("hash"), []byte("ident")})
	if !bytes.Equal(info, want) {
		t.Errorf("the HPKE info is not bound to cold-record/1: %x", info)
	}
}

// ---- the previous inner wrap (an hmac-secret salt rotation that is not yet proved) ----

func prevHeader() ColdHeader {
	h := fidoHeader()
	h.Prev = bytes.Repeat([]byte{6}, 32)
	h.Fallbacks = 3
	return h
}

// spec: SPO-Xcustody-INV-020
func TestColdRecordOpensWithTheCurrentOrThePreviousWrapOnly(t *testing.T) {
	_, k := fixtureKeys(t)
	m := coldMeta()
	cur, prev := coldSub(t, 5, coldID), coldSub(t, 4, coldID)
	src := buf("two wraps")
	defer src.Destroy()
	r, err := k.SealSecretCold(m, src, ColdSeal{Sub: cur, Prev: prev, Header: prevHeader()})
	if err != nil {
		t.Fatal(err)
	}
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		t.Fatal(err)
	}
	if !oc.HasPrevious() {
		t.Fatal("the previous wrap is not reported")
	}
	for name, open := range map[string]func() (*secret.Buffer, error){
		"current": func() (*secret.Buffer, error) { return oc.OpenSecret(cur) },
		"previous": func() (*secret.Buffer, error) {
			dk, e := oc.OpenDataKeyPrevious(prev)
			if e != nil {
				return nil, e
			}
			defer dk.Destroy()
			return oc.OpenSecretWithDataKey(dk)
		},
	} {
		pt, err := open()
		if err != nil || secretString(t, pt) != "two wraps" {
			t.Fatalf("%s: %v", name, err)
		}
		pt.Destroy()
	}
	// each wrap opens only under its own sub-key
	if _, err := oc.OpenDataKey(prev); !errors.Is(err, ErrAuth) {
		t.Fatalf("the previous sub-key opened the current wrap: %v", err)
	}
	if _, err := oc.OpenDataKeyPrevious(cur); !errors.Is(err, ErrAuth) {
		t.Fatalf("the current sub-key opened the previous wrap: %v", err)
	}
	// a record without a previous wrap has none to open
	r0, err := k.SealSecretCold(m, src, ColdSeal{Sub: cur, Header: fidoHeader()})
	if err != nil {
		t.Fatal(err)
	}
	o0, err := k.OpenColdOuter(m, r0)
	if err != nil || o0.HasPrevious() {
		t.Fatalf("a record with no previous salt: %v", err)
	}
	if _, err := o0.OpenDataKeyPrevious(prev); err == nil {
		t.Fatal("a previous wrap opened on a record that has none")
	}
	// the header and the sub-key set must agree
	if _, err := k.SealSecretCold(m, src, ColdSeal{Sub: cur, Header: prevHeader()}); err == nil {
		t.Error("a header with a previous salt was sealed without a previous sub-key")
	}
	if _, err := k.SealSecretCold(m, src, ColdSeal{Sub: cur, Prev: prev, Header: fidoHeader()}); err == nil {
		t.Error("a previous sub-key was sealed under a header with no previous salt")
	}
	// the rewrap and the recovery rewrap carry the previous wrap
	_, k2 := fixtureKeys(t)
	rr, err := k.RewrapCold(k2, m, r)
	if err != nil {
		t.Fatal(err)
	}
	o2, err := k2.OpenColdOuter(m, rr)
	if err != nil || !o2.HasPrevious() {
		t.Fatalf("rewrap lost the previous wrap: %v", err)
	}
	dk, err := o2.OpenDataKeyPrevious(prev)
	if err != nil {
		t.Fatal(err)
	}
	dk.Destroy()
}

// spec: SPO-Xcustody-INV-020
func TestColdPreviousWrapCannotBeDroppedOrSwappedByAFileEditor(t *testing.T) {
	_, k := fixtureKeys(t)
	m := coldMeta()
	cur, prev := coldSub(t, 5, coldID), coldSub(t, 4, coldID)
	src := buf("payload")
	defer src.Destroy()
	r, err := k.SealSecretCold(m, src, ColdSeal{Sub: cur, Prev: prev, Header: prevHeader()})
	if err != nil {
		t.Fatal(err)
	}
	// any single-byte edit of the wrapped-key column is refused (outer layer, header, wrap hash)
	for i := range r.WrappedKey {
		c := r
		c.WrappedKey = append([]byte(nil), r.WrappedKey...)
		c.WrappedKey[i] ^= 1
		if _, err := k.OpenColdOuter(m, c); err == nil {
			t.Fatalf("byte %d of an edited cold record was accepted", i)
		}
	}
	// dropping the previous wrap: the same blob with the header's previous salt cleared
	b, _ := parseColdBlob(r.WrappedKey)
	h, _ := DecodeColdHeader(b.hdr)
	h.Prev = nil
	nh, _ := h.Encode()
	dropped, _ := coldBlob{hdr: nh, outer: b.outer, rec: b.rec}.encode()
	c := r
	c.WrappedKey = dropped
	if _, err := k.OpenColdOuter(m, c); err == nil {
		t.Fatal("a record whose previous salt was dropped from the header opened")
	}
	// the previous wraps of another record and of another version, grafted in by
	// someone who holds the master key, do not open
	oc, _ := k.OpenColdOuter(m, r)
	other := m
	other.RecordID = bytes.Repeat([]byte{3}, IDSize)
	older := m
	older.Version--
	for name, mm := range map[string]RecordMeta{"another record": other, "an older version": older} {
		ro, err := k.SealSecretCold(mm, src, ColdSeal{Sub: cur, Prev: prev, Header: prevHeader()})
		if err != nil {
			t.Fatal(err)
		}
		oo, err := k.OpenColdOuter(mm, ro)
		if err != nil {
			t.Fatal(err)
		}
		plain := append(append([]byte(nil), oc.inner...), oo.prev...)
		forged := reSealOuter(t, k, m, r, plain)
		fo, err := k.OpenColdOuter(m, forged)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := fo.OpenDataKeyPrevious(prev); !errors.Is(err, ErrAuth) {
			t.Errorf("the previous wrap of %s opened for this record: %v", name, err)
		}
		// and the current wrap of the other record in the current place
		plain = append(append([]byte(nil), oo.inner...), oc.prev...)
		fo, err = k.OpenColdOuter(m, reSealOuter(t, k, m, r, plain))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fo.OpenDataKey(cur); !errors.Is(err, ErrAuth) {
			t.Errorf("the current wrap of %s opened for this record: %v", name, err)
		}
	}
	// the previous wrap in the current place, and the reverse (swap)
	swapped := append(append([]byte(nil), oc.prev...), oc.inner...)
	fo, err := k.OpenColdOuter(m, reSealOuter(t, k, m, r, swapped))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fo.OpenDataKey(prev); err == nil {
		t.Error("the previous wrap opened in the current place")
	}
	if _, err := fo.OpenDataKeyPrevious(cur); err == nil {
		t.Error("the current wrap opened in the previous place")
	}
	// a previous wrap the header does not name
	if _, err := k.OpenColdOuter(m, reSealOuter(t, k, m, r, oc.inner)); err == nil {
		t.Error("a record whose header names a previous salt but holds no previous wrap opened")
	}
}

// reSealOuter rebuilds the outer layer of r around another plaintext, as the
// holder of the master key can.
func reSealOuter(t *testing.T, k *Keys, m RecordMeta, r SealedRecord, plain []byte) SealedRecord {
	t.Helper()
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		t.Fatal(err)
	}
	outerAD, _ := coldAD(labelColdOuter, oc.ad, oc.hdr, hashOf(oc.rec))
	nonce := bytes.Repeat([]byte{5}, NonceSize)
	var outer []byte
	k.wrap.Use(func(wk []byte) error {
		w, e := aeadSeal(wk, nonce, plain, outerAD)
		outer = append(nonce, w...)
		return e
	})
	blob, err := coldBlob{hdr: oc.hdr, outer: outer, rec: oc.rec}.encode()
	if err != nil {
		t.Fatal(err)
	}
	r.WrappedKey = blob
	return r
}

// A pinned cold record with a previous wrap (hmac-secret header).
//
// spec: SPO-Xcustody-OUT-009
func TestColdRecordWithPreviousWrapVector(t *testing.T) {
	master := secret.Take(pattern(0x10, KeySize))
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	m := RecordMeta{WorkspaceID: pattern(0x01, IDSize), RecordID: pattern(0x21, IDSize), Kind: "node.skey", Anchor: append([]byte{0x00}, pattern(0x40, 28)...), Class: ClassSecretCold, Version: 4, Format: RecordFormat}
	ident := pattern(0x60, 28)
	sub, err := DeriveColdSubKey(secret.Take(pattern(0x70, KeySize)), m.WorkspaceID, uint32(StoreFormat), ident)
	if err != nil {
		t.Fatal(err)
	}
	psub, err := DeriveColdSubKey(secret.Take(pattern(0x71, KeySize)), m.WorkspaceID, uint32(StoreFormat), ident)
	if err != nil {
		t.Fatal(err)
	}
	src := secret.Take([]byte("pinned cold signing key"))
	padded, err := frameSecret(src)
	if err != nil {
		t.Fatal(err)
	}
	rng := &scripted{t: t, chunks: [][]byte{pattern(0x80, NonceSize), pattern(0x90, NonceSize), pattern(0xa0, NonceSize), pattern(0xb0, NonceSize), pattern(0xe0, NonceSize)}}
	hdr := ColdHeader{Kind: ColdFIDO2, Credential: pattern(0xc0, 16), Salt: pattern(0xc1, 32), Next: pattern(0xc2, 32), Prev: pattern(0xc3, 32), Fallbacks: 2}
	r, err := sealer{rand: rng}.sealColdWith(keys, m, padded, secret.Take(pattern(0xd0, KeySize)), ColdSeal{Sub: sub, Prev: psub, Header: hdr})
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	got := hex.EncodeToString(r.WrappedKey) + "|" + hex.EncodeToString(r.Ciphertext) + "|" + hex.EncodeToString(r.Owner)
	const want = "847173706f2f636f6c642d7265636f72642f31587a860250c0c1c2c3c4c5c6c7c8c9cacbcccdcecf5820c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe05820c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e15820c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e20258b8a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7ea488ccee5eb3b5d7a263d36a40eb08d1dfc745c14e113147752c756dd26fa1b86b8f4f34c0ca70ab776bef633a163c45ea5605dbf130c62e3ad8e8049291e623eb01254197cdb3cb30d77cfdc3d7dbffda461806a2ce6e2f0b378d463fe5c0786c64568f662999b0be640172da5cebc91dec6bf7f721f7f53707a0f44d4bc25b960d77aa1cbf1df65b4e0ad393edf11f81fa0364afea34d95ec54d8803e61a340|b89fb4989f85f748d247b8673b511e48a95fc00af38fc21377c85565ad70b21ceb14f52877707dee0357240f38656891355a47163492f732c9815863788658166ce59399589debe9ec3f528346670d00469bd0639f73787306c1966c38ac5cbc4b1e820dca6e0ed1862bc7573b15e165ebdeef69b7387102bd5ebfdc270c4cfcafb2d1b14aebdd7342d1186a5b05445cbd073430855b6ffc1b06819e33bc124897d5e67ffaadd9a32bfb5511cc71c1ad5df447601d93e2aea15913302af5f0d96393fdcd99819cae8eb76462c0dad338dbe1d31f55e8e86152183df1715226acb5a02df04d7c2daafe39593ed46ea76cf9f3194b4b2139bbd0f04412cf0498f96b94826b4bd4db49ebfd1e53542b3df4|e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7a951a6dbfcb64dacea71320a5993df829b043de130a58dacbaffb10db473cbc93eba067f3b60adf9a060c417894ee2b127201c6036c778a437fcab67169d7efb73799b513baca5b0835b8109784d40c6d5bee7419fd216d19038cf9f05900b44436f304fc4d2a9380e30f69087e6497844f61beb0913b5b087a8af63ffc1e766410378af6c92713cfdcf7869ff7cdb41716ed51b37726cca71ef5a37c3657ffa8066f04ec66f584df44cd0d025fe00a5"
	if got != want {
		t.Fatalf("cold record bytes changed:\n%s", got)
	}
}
