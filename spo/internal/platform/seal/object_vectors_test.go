package seal

// Test vectors of the object envelope (ADR 0012 stage 3).
//
// Two committed files are produced here and one is read:
//
//	../../domain/layout/testdata/records.json   written by TestRecordFixtures:
//	    four sealed records (a hot Sensitive, a hot Secret, a cold-role
//	    passphrase and a cold-role FIDO2 record with a previous wrap and the
//	    left mark), made with the real seal functions, fixed keys and a
//	    deterministic randomness stream. The layout's tests build their
//	    objects from it.
//	../../domain/layout/testdata/vectors.json   read by TestObjectVectors: the
//	    layout's canonical CBOR for every object kind.
//	testdata/object_vectors.json                written by TestObjectVectors:
//	    those bodies and the bucket-edge bodies, framed and sealed with a fixed
//	    nonce, with the stored bytes, name and path. testdata/check_vectors.py
//	    (in domain/layout) recomputes these with a separate implementation.
//
// The recovery wrap of a cold record is not in the fixtures: the HPKE
// ephemeral key comes from crypto/rand and cannot be pinned (the same
// restriction as TestColdRecordVector).
//
// Regenerate deliberately, in this order (each step needs the file before it):
//
//	go test ./internal/platform/seal -run TestRecordFixtures -update
//	go test ./internal/domain/layout -run TestVectors -update
//	go test ./internal/platform/seal -run TestObjectVectors -update

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"testing/cryptotest"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

const (
	recordsPath       = "../../domain/layout/testdata/records.json"
	recoveryPath      = "../../domain/layout/testdata/records_recovery.json"
	layoutVectorsPath = "../../domain/layout/testdata/vectors.json"
	objectVectorsPath = "testdata/object_vectors.json"
)

// detRand is a deterministic randomness stream: SHA-256 of a seed and a
// counter, block after block. The order and sizes of the reads are part of
// what the fixtures pin.
type detRand struct {
	seed string
	n    uint64
	buf  []byte
}

func (d *detRand) Read(p []byte) (int, error) {
	for len(d.buf) < len(p) {
		h := sha256.Sum256(binary.BigEndian.AppendUint64([]byte(d.seed), d.n))
		d.n++
		d.buf = append(d.buf, h[:]...)
	}
	copy(p, d.buf)
	d.buf = d.buf[len(p):]
	return len(p), nil
}

type recordFixture struct {
	Name       string `json:"name"`
	Cold       bool   `json:"cold"`
	Class      string `json:"class"`
	Kind       string `json:"kind"`
	RecordID   hx     `json:"record_id"`
	Anchor     hx     `json:"anchor"`
	Num        uint64 `json:"num"`
	Version    uint64 `json:"version"`
	Format     uint64 `json:"format"`
	UpdatedAt  int64  `json:"updated_at"`
	PayloadLen int    `json:"payload_len"`
	Nonce      hx     `json:"nonce"`
	WrappedKey hx     `json:"wrapped_key"`
	Owner      hx     `json:"owner"`
	Ciphertext hx     `json:"ciphertext"`
}

type recordFixtures struct {
	Comment     string          `json:"_comment"`
	MasterKey   hx              `json:"master_key"`
	WorkspaceID hx              `json:"workspace_id"`
	KeyEpoch    hx              `json:"key_epoch"`
	Records     []recordFixture `json:"records"`
}

func layoutFixtureKeys(t *testing.T, master []byte) *Keys {
	t.Helper()
	k, err := DeriveKeys(secret.Take(append([]byte(nil), master...)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func generateRecordFixtures(t *testing.T) []byte {
	t.Helper()
	var f recordFixtures
	f.Comment = "Sealed records for the layout's vectors, from the real seal functions with a deterministic randomness stream. Regenerate with: go test ./internal/platform/seal -run TestRecordFixtures -update"
	f.MasterKey, f.WorkspaceID, f.KeyEpoch = pattern(0x10, 32), pattern(0x20, 16), pattern(0xf0, EpochSize)
	keys := layoutFixtureKeys(t, f.MasterKey)
	defer keys.Destroy()
	rng := &detRand{seed: "spo/layout/record-fixtures/1"}
	anchor := append([]byte{0x00}, pattern(0x40, 28)...)
	ident := pattern(0x60, 28)
	meta := func(kind, class string, id byte, num, version uint64) RecordMeta {
		return RecordMeta{WorkspaceID: f.WorkspaceID, RecordID: pattern(id, 16), Kind: kind, Anchor: anchor, Num: num, Class: class, Version: version, Format: RecordFormat}
	}
	add := func(name string, cold bool, m RecordMeta, class string, plen int, r SealedRecord) {
		f.Records = append(f.Records, recordFixture{Name: name, Cold: cold, Class: class, Kind: m.Kind, RecordID: m.RecordID, Anchor: m.Anchor, Num: m.Num,
			Version: m.Version, Format: m.Format, UpdatedAt: 1700000000 + int64(len(f.Records)), PayloadLen: plen,
			Nonce: r.Nonce, WrappedKey: r.WrappedKey, Owner: r.Owner, Ciphertext: r.Ciphertext})
	}
	payload := func(n int) []byte { return pattern(0x01, n) }

	// hot Sensitive
	m := meta("kes.vkey", ClassSensitive, 0xa0, 2, 1)
	r, err := sealer{rand: rng}.sealRecord(keys, m, func(fn func([]byte) error) error { return fn(payload(120)) })
	if err != nil {
		t.Fatal(err)
	}
	add("hot-sensitive", false, m, "sensitive", 120, r)

	// hot Secret, and the two cold-role forms of the same payload size
	const plen = 64
	m = meta("node.skey", ClassSecret, 0xa1, 0, 4)
	padded, err := frameSecret(secret.Take(payload(plen)))
	if err != nil {
		t.Fatal(err)
	}
	r, err = sealer{rand: rng}.sealRecord(keys, m, padded.Use)
	padded.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	add("hot-secret", false, m, "secret", plen, r)

	sub, err := DeriveColdSubKey(secret.Take(pattern(0x70, KeySize)), f.WorkspaceID, uint32(StoreFormat), ident)
	if err != nil {
		t.Fatal(err)
	}
	psub, err := DeriveColdSubKey(secret.Take(pattern(0x71, KeySize)), f.WorkspaceID, uint32(StoreFormat), ident)
	if err != nil {
		t.Fatal(err)
	}
	cm := meta("node.skey", ClassSecretCold, 0xa2, 0, 4)
	padded, err = frameSecret(secret.Take(payload(plen)))
	if err != nil {
		t.Fatal(err)
	}
	hdr := ColdHeader{Kind: ColdPassphrase, KDF: KDFParams{MemoryKiB: 64 * 1024, Passes: 3, Lanes: 1}, Salt: pattern(0xc0, SaltSize)}
	r, err = sealer{rand: rng}.sealColdWith(keys, cm, padded, secret.Take(pattern(0xd0, KeySize)), ColdSeal{Sub: sub, Header: hdr})
	padded.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	add("cold-passphrase", true, cm, "secret", plen, r)

	cm = meta("node.skey", ClassSecretCold, 0xa3, 0, 5)
	padded, err = frameSecret(secret.Take(payload(plen)))
	if err != nil {
		t.Fatal(err)
	}
	hdr = ColdHeader{Kind: ColdFIDO2, Credential: pattern(0xc0, 64), Salt: pattern(0xc1, 32), Next: pattern(0xc2, 32), Prev: pattern(0xc3, 32), Fallbacks: 2}
	r, err = sealer{rand: rng}.sealColdWith(keys, cm, padded, secret.Take(pattern(0xd1, KeySize)), ColdSeal{Sub: sub, Prev: psub, Header: hdr, Left: true})
	padded.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	add("cold-fido2-previous-left", true, cm, "secret", plen, r)

	out, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// recoveryFixture is a cold-role FIDO2 record WITH an HPKE recovery wrap. The
// HPKE ephemeral key is drawn through the standard library, which
// testing/cryptotest.SetGlobalRandom makes deterministic, but how the
// library uses randomness is not specified and may change with the Go
// version, so this vector is OPEN-ONLY: the committed bytes are never compared
// with a regeneration; the test opens them (outer layer with the master-derived
// keys, the recovery wrap with the committed test recovery private key, the
// payload with the data key it yields). -update rewrites it.
type recoveryFixture struct {
	Comment            string          `json:"_comment"`
	MasterKey          hx              `json:"master_key"`
	WorkspaceID        hx              `json:"workspace_id"`
	KeyEpoch           hx              `json:"key_epoch"`
	RecoveryPrivateKey hx              `json:"recovery_private_key"`
	RecoveryIdentity   hx              `json:"recovery_identity"`
	Payload            hx              `json:"payload"`
	Records            []recordFixture `json:"records"`
}

func generateRecoveryFixture(t *testing.T) []byte {
	t.Helper()
	cryptotest.SetGlobalRandom(t, 7)
	var f recoveryFixture
	f.Comment = "OPEN-ONLY vector: a cold-role FIDO2 record with an HPKE recovery wrap, a previous wrap and the left mark. Not compared with a regeneration (see object_vectors_test.go). Rewrite with: go test ./internal/platform/seal -run TestRecoveryRecordFixture -update"
	f.MasterKey, f.WorkspaceID, f.KeyEpoch = pattern(0x10, 32), pattern(0x20, 16), pattern(0xf0, EpochSize)
	f.RecoveryPrivateKey, f.RecoveryIdentity = pattern(0x80, 32), pattern(0x60, 28)
	f.Payload = pattern(0x01, 64)
	keys := layoutFixtureKeys(t, f.MasterKey)
	defer keys.Destroy()
	priv, err := ecdh.X25519().NewPrivateKey(f.RecoveryPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := DeriveColdSubKey(secret.Take(pattern(0x70, KeySize)), f.WorkspaceID, uint32(StoreFormat), f.RecoveryIdentity)
	if err != nil {
		t.Fatal(err)
	}
	psub, err := DeriveColdSubKey(secret.Take(pattern(0x71, KeySize)), f.WorkspaceID, uint32(StoreFormat), f.RecoveryIdentity)
	if err != nil {
		t.Fatal(err)
	}
	m := RecordMeta{WorkspaceID: f.WorkspaceID, RecordID: pattern(0xa4, 16), Kind: "node.skey", Anchor: append([]byte{0x00}, pattern(0x40, 28)...), Num: 0, Class: ClassSecretCold, Version: 6, Format: RecordFormat}
	padded, err := frameSecret(secret.Take(append([]byte(nil), f.Payload...)))
	if err != nil {
		t.Fatal(err)
	}
	defer padded.Destroy()
	hdr := ColdHeader{Kind: ColdFIDO2, Credential: pattern(0xc0, 64), Salt: pattern(0xc1, 32), Next: pattern(0xc2, 32), Prev: pattern(0xc3, 32), Fallbacks: 2}
	r, err := sealer{rand: &detRand{seed: "spo/layout/recovery-fixture/1"}}.sealColdWith(keys, m, padded, secret.Take(pattern(0xd2, KeySize)),
		ColdSeal{Sub: sub, Prev: psub, Header: hdr, Left: true, Recovery: &ColdRecovery{Pub: priv.PublicKey().Bytes(), Identity: f.RecoveryIdentity}})
	if err != nil {
		t.Fatal(err)
	}
	f.Records = []recordFixture{{Name: "cold-fido2-recovery-wrap", Cold: true, Class: "secret", Kind: m.Kind, RecordID: m.RecordID, Anchor: m.Anchor, Num: m.Num,
		Version: m.Version, Format: m.Format, UpdatedAt: 1700000009, PayloadLen: len(f.Payload), Nonce: r.Nonce, WrappedKey: r.WrappedKey, Owner: r.Owner, Ciphertext: r.Ciphertext}}
	out, err := json.MarshalIndent(&f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// spec: SPO-Xlayout-OUT-013
func TestRecoveryRecordFixture(t *testing.T) {
	if *update {
		if err := os.WriteFile(recoveryPath, generateRecoveryFixture(t), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(recoveryPath)
	if err != nil {
		t.Fatalf("%v (generate it with -update)", err)
	}
	var f recoveryFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	rec := f.Records[0]
	keys := layoutFixtureKeys(t, f.MasterKey)
	defer keys.Destroy()
	m := RecordMeta{WorkspaceID: f.WorkspaceID, RecordID: rec.RecordID, Kind: rec.Kind, Anchor: rec.Anchor, Num: rec.Num, Class: ClassSecretCold, Version: rec.Version, Format: rec.Format}
	r := SealedRecord{Nonce: rec.Nonce, WrappedKey: rec.WrappedKey, Owner: rec.Owner, Ciphertext: rec.Ciphertext}
	oc, err := keys.OpenColdOuter(m, r)
	if err != nil {
		t.Fatalf("the outer layer does not open with the master-derived keys: %v", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(f.RecoveryPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dk, err := oc.RecoverDataKey(priv, f.RecoveryIdentity)
	if err != nil {
		t.Fatalf("the recovery wrap does not open with the committed recovery private key: %v", err)
	}
	defer dk.Destroy()
	pt, err := oc.OpenSecretWithDataKey(dk)
	if err != nil {
		t.Fatal(err)
	}
	defer pt.Destroy()
	var got []byte
	pt.Use(func(b []byte) error { got = append([]byte(nil), b...); return nil })
	if !bytes.Equal(got, f.Payload) {
		t.Fatalf("the payload recovered through the recovery wrap is not the payload: %d bytes %x", len(got), got[:8])
	}
}

func compareOrUpdate(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate it: see the comment at the top of object_vectors_test.go)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from what the code produces now: a change to the format. Regenerate it only for a deliberate format change.", path)
	}
}

// spec: SPO-Xlayout-OUT-013
func TestRecordFixtures(t *testing.T) {
	compareOrUpdate(t, recordsPath, generateRecordFixtures(t))
}

type objectVector struct {
	Name         string `json:"name"`
	Refused      string `json:"refused,omitempty"`
	CBORLen      int    `json:"cbor_len"`
	PatternStart *int   `json:"pattern_start,omitempty"` // the CBOR is a byte string filled with start, start+1, ...
	CBOR         hx     `json:"cbor,omitempty"`
	Nonce        hx     `json:"nonce,omitempty"`
	Body         hx     `json:"body,omitempty"`
	StoredLen    int    `json:"stored_len,omitempty"`
	Stored       hx     `json:"stored,omitempty"`
	Header       hx     `json:"header,omitempty"`
	Name256      string `json:"object_name,omitempty"`
	Path         string `json:"path,omitempty"`
}

type objectVectors struct {
	Comment     string         `json:"_comment"`
	MasterKey   hx             `json:"master_key"`
	WorkspaceID hx             `json:"workspace_id"`
	KeyEpoch    hx             `json:"key_epoch"`
	KeyLabel    string         `json:"object_key_label"`
	KeyDerive   string         `json:"object_key_derivation"`
	ObjectKey   hx             `json:"object_key"`
	NonceKey    hx             `json:"nonce_key"`
	Vectors     []objectVector `json:"vectors"`
}

// bstrOf is the canonical CBOR byte string of n filler bytes, total length c.
func bstrOf(c int, start byte) []byte {
	hdr := 3
	if c-hdr >= 65536 {
		hdr = 5
	}
	n := c - hdr
	var out []byte
	if hdr == 3 {
		out = []byte{0x59, byte(n >> 8), byte(n)}
	} else {
		out = binary.BigEndian.AppendUint32([]byte{0x5a}, uint32(n))
	}
	return append(out, pattern(start, n)...)
}

// spec: SPO-Xlayout-OUT-013
func TestObjectVectors(t *testing.T) {
	var lv struct {
		Objects []struct {
			Name string `json:"name"`
			CBOR string `json:"cbor"`
		} `json:"objects"`
	}
	raw, err := os.ReadFile(layoutVectorsPath)
	if err != nil {
		t.Fatalf("%v (generate it first: see the comment at the top of object_vectors_test.go)", err)
	}
	if err := json.Unmarshal(raw, &lv); err != nil {
		t.Fatal(err)
	}
	var v objectVectors
	v.Comment = "Pins the object envelope. Regenerate only for a deliberate format change (see object_vectors_test.go). Independently checked by internal/domain/layout/testdata/check_vectors.py."
	v.MasterKey, v.WorkspaceID, v.KeyEpoch = pattern(0x10, 32), pattern(0x20, 16), pattern(0xf0, EpochSize)
	v.KeyLabel = labelObject
	v.KeyDerive = "HKDF-Expand(HMAC-SHA256, PRK = the index key, info = label, 32 bytes) for the object key (spo/object-envelope/1) and the nonce key (spo/object-nonce/1); the index key is HKDF-SHA256(master, no salt, info spo-workbench/seal/v1/index); the object nonce is HMAC-SHA256(nonce key, AD || body)[:24]"
	keys := layoutFixtureKeys(t, v.MasterKey)
	defer keys.Destroy()
	for _, c := range []struct {
		label string
		dst   *hx
	}{{labelObject, &v.ObjectKey}, {labelObjectNonce, &v.NonceKey}} {
		ok, err := hkdfExpandKey(keys.Index.k, c.label)
		if err != nil {
			t.Fatal(err)
		}
		ok.Use(func(b []byte) error { *c.dst = append([]byte(nil), b...); return nil })
		ok.Destroy()
	}

	seal := func(name string, cbor []byte, start *int) {
		ov := objectVector{Name: name, CBORLen: len(cbor), PatternStart: start}
		if start == nil || len(cbor) <= 16384 {
			ov.CBOR = cbor
		}
		body, err := layout.FrameBody(cbor)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		stored, err := keys.SealObject(v.KeyEpoch, v.WorkspaceID, body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ov.Nonce = stored[ObjectHeaderSize : ObjectHeaderSize+NonceSize]
		back, err := keys.OpenObject(stored, v.WorkspaceID, v.KeyEpoch)
		if err != nil || !bytes.Equal(back, body) {
			t.Fatalf("%s: does not open: %v", name, err)
		}
		if h, err := layout.ParseHeader(stored); err != nil || h.Format != layout.FormatSealed {
			t.Fatalf("%s: %v", name, err)
		}
		ov.StoredLen = len(stored)
		ov.Header = stored[:ObjectHeaderSize]
		if len(stored) <= 8192 {
			ov.Stored = stored
		}
		ov.Name256 = layout.ObjectName(stored)
		ov.Path, err = layout.ObjectPath(ov.Name256)
		if err != nil {
			t.Fatal(err)
		}
		v.Vectors = append(v.Vectors, ov)
	}
	for _, c := range []int{4034, 4035, 4036} {
		s := 0x30
		seal("edge-cbor-"+strconv.Itoa(c), bstrOf(c, byte(s)), &s)
	}
	s := 0x31
	seal("largest-bucket", bstrOf(4<<20-61, byte(s)), &s)
	over := objectVector{Name: "one-over-largest", CBORLen: 4<<20 - 60, Refused: "needs a stored object of 4194305 bytes"}
	if _, err := layout.FrameBody(make([]byte, over.CBORLen)); err == nil {
		t.Fatal("one byte over the largest bucket was framed")
	}
	v.Vectors = append(v.Vectors, over)
	for _, o := range lv.Objects {
		c, err := hex.DecodeString(o.CBOR)
		if err != nil {
			t.Fatal(err)
		}
		seal(o.Name, c, nil)
	}
	out, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	compareOrUpdate(t, objectVectorsPath, append(out, '\n'))
}

// UnmarshalJSON reads the hex text MarshalJSON writes.
func (h *hx) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	*h = d
	return err
}
