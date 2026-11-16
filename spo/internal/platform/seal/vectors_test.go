package seal

// These tests pin the on-disk format. testdata/vectors.json holds fixed
// inputs (keys, nonces, salts, ids) and the outputs the format must produce
// from them. TestVectors regenerates the file in memory and compares it with
// the committed one byte for byte. Any difference is a format change: bump
// FormatVersion, add new vectors, and keep the old ones passing.
//
// Rewrite the file deliberately with:
//
//	go test ./internal/platform/seal -run TestVectors -update

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

// scripted is a randomness source that returns fixed chunks in order and
// fails if asked for more or for a different size than scripted. The order
// chunks are consumed in is part of the pinned format.
type scripted struct {
	t      *testing.T
	chunks [][]byte
}

func (s *scripted) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		s.t.Fatalf("randomness over-read (%d bytes)", len(p))
	}
	c := s.chunks[0]
	if len(c) != len(p) {
		// Callers read exactly the size they need; LimitReader may ask for
		// more than remains, so serve what is left of the chunk.
		if len(p) > len(c) {
			s.chunks = s.chunks[1:]
			return copy(p, c), nil
		}
		s.t.Fatalf("randomness read of %d bytes, chunk is %d", len(p), len(c))
	}
	s.chunks = s.chunks[1:]
	return copy(p, c), nil
}

func (s *scripted) done() {
	if len(s.chunks) != 0 {
		s.t.Fatalf("%d randomness chunks unused", len(s.chunks))
	}
}

// pattern returns n bytes start, start+1, ...
func pattern(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

type hx []byte

func (h hx) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

type vectors struct {
	Comment string `json:"_comment"`
	Format  int    `json:"format_version"`

	Inputs struct {
		MasterKey      hx     `json:"master_key"`
		WorkspaceID    hx     `json:"workspace_id"`
		SlotID         hx     `json:"slot_id"`
		RecoverySlotID hx     `json:"recovery_slot_id"`
		RecoveryKey    hx     `json:"recovery_key"`
		Passphrase     string `json:"passphrase"`
		KDFMemoryKiB   uint32 `json:"kdf_memory_kib"`
		KDFPasses      uint32 `json:"kdf_passes"`
		KDFLanes       uint8  `json:"kdf_lanes"`
		Salt           hx     `json:"salt"`
		SlotNonce      hx     `json:"slot_nonce"`
		RecoveryNonce  hx     `json:"recovery_slot_nonce"`
		RecordID       hx     `json:"record_id"`
		Kind           string `json:"kind"`
		Owner          string `json:"owner"`
		Class          string `json:"class"`
		RecordVersion  uint64 `json:"record_version"`
		DataKey        hx     `json:"data_key"`
		PayloadNonce   hx     `json:"payload_nonce"`
		WrapNonce      hx     `json:"wrap_nonce"`
		Plaintext      hx     `json:"plaintext"`
		TagNamespace   string `json:"tag_namespace"`
		TagParts       []hx   `json:"tag_parts"`
		AuditPrev      hx     `json:"audit_prev_mac"`
		AuditRow       []any  `json:"audit_row"`
	} `json:"inputs"`

	Outputs struct {
		RecordWrapKey   hx `json:"hkdf_record_wrap_key"`
		IndexKey        hx `json:"hkdf_index_key"`
		AuditKey        hx `json:"hkdf_audit_key"`
		RecoverySlotKey hx `json:"hkdf_recovery_slot_key"`

		PassphraseSlotAD      hx     `json:"passphrase_slot_ad"`
		PassphraseSlotWrapped hx     `json:"passphrase_slot_wrapped"`
		RecoverySlotAD        hx     `json:"recovery_slot_ad"`
		RecoverySlotWrapped   hx     `json:"recovery_slot_wrapped"`
		RecoveryKeyText       string `json:"recovery_key_text"`

		RecordAD         hx `json:"record_ad"`
		RecordNonce      hx `json:"record_nonce"`
		RecordWrappedKey hx `json:"record_wrapped_key"`
		RecordCiphertext hx `json:"record_ciphertext"`

		IndexTag     hx `json:"index_tag"`
		AuditRowCBOR hx `json:"audit_row_cbor"`
		AuditMAC     hx `json:"audit_mac"`
	} `json:"outputs"`
}

func generateVectors(t *testing.T) []byte {
	t.Helper()
	var v vectors
	v.Comment = "Pins the seal format. Regenerate only for a deliberate format change: go test ./internal/platform/seal -run TestVectors -update"
	v.Format = FormatVersion
	in := &v.Inputs
	in.MasterKey = pattern(0x10, 32)
	in.WorkspaceID = pattern(0x20, 16)
	in.SlotID = pattern(0x30, 16)
	in.RecoverySlotID = pattern(0x40, 16)
	in.RecoveryKey = pattern(0x50, 32)
	in.Passphrase = "correct horse battery staple"
	// The production floor, so the vector holds at the real minimum.
	in.KDFMemoryKiB, in.KDFPasses, in.KDFLanes = 64*1024, 3, 1
	in.Salt = pattern(0x70, 16)
	in.SlotNonce = pattern(0x80, 24)
	in.RecoveryNonce = pattern(0x90, 24)
	in.RecordID = pattern(0xa0, 16)
	in.Kind, in.Owner, in.Class, in.RecordVersion = "kes.skey", "mypool#7", ClassSecret, 3
	in.DataKey = pattern(0xb0, 32)
	in.PayloadNonce = pattern(0xc0, 24)
	in.WrapNonce = pattern(0xd0, 24)
	in.Plaintext = []byte(`{"type":"KesSigningKey_ed25519_kes_2^6"}`)
	in.TagNamespace = "record-ref"
	in.TagParts = []hx{[]byte("mypool"), []byte("kes.skey"), []byte("7")}
	in.AuditPrev = make([]byte, MACSize)
	in.AuditRow = []any{FormatVersion, 5, "update", "x"}

	master := secret.Take(append([]byte(nil), in.MasterKey...))
	defer master.Destroy()
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	out := &v.Outputs
	grab := func(b *secret.Buffer) hx {
		var c []byte
		b.Use(func(x []byte) error { c = append([]byte(nil), x...); return nil })
		return c
	}
	out.RecordWrapKey = grab(keys.wrap)
	out.IndexKey = grab(keys.Index.k)
	out.AuditKey = grab(keys.Audit.k)
	rk := secret.Take(append([]byte(nil), in.RecoveryKey...))
	defer rk.Destroy()
	sk, err := hkdfKey(rk, labelRecoverySlot)
	if err != nil {
		t.Fatal(err)
	}
	out.RecoverySlotKey = grab(sk)
	sk.Destroy()

	// Passphrase slot. Randomness order: salt, nonce.
	pw := secret.Take([]byte(in.Passphrase))
	defer pw.Destroy()
	rng := &scripted{t: t, chunks: [][]byte{in.Salt, in.SlotNonce}}
	slot, err := sealer{rand: rng}.newPassphraseSlot(in.WorkspaceID, in.SlotID, master, pw,
		KDFParams{in.KDFMemoryKiB, in.KDFPasses, in.KDFLanes})
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	if out.PassphraseSlotAD, err = slot.ad(in.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	out.PassphraseSlotWrapped = slot.Wrapped
	if got, err := slot.Unwrap(in.WorkspaceID, pw); err != nil {
		t.Fatal(err)
	} else {
		got.Destroy()
	}

	// Recovery slot. Randomness order: recovery key, nonce.
	rng = &scripted{t: t, chunks: [][]byte{in.RecoveryKey, in.RecoveryNonce}}
	rslot, gotKey, err := sealer{rand: rng}.newRecoverySlot(in.WorkspaceID, in.RecoverySlotID, master)
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	gotKey.Destroy()
	if out.RecoverySlotAD, err = rslot.ad(in.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	out.RecoverySlotWrapped = rslot.Wrapped
	txt, err := EncodeRecoveryKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	txt.Use(func(b []byte) error { out.RecoveryKeyText = string(b); return nil })

	// Record. Randomness order: data key, payload nonce, wrap nonce.
	m := RecordMeta{WorkspaceID: in.WorkspaceID, RecordID: in.RecordID, Kind: in.Kind, Owner: in.Owner, Class: in.Class, Version: in.RecordVersion}
	if out.RecordAD, err = m.AD(); err != nil {
		t.Fatal(err)
	}
	rng = &scripted{t: t, chunks: [][]byte{in.DataKey, in.PayloadNonce, in.WrapNonce}}
	sr, err := sealer{rand: rng}.sealRecord(keys, m, in.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	out.RecordNonce, out.RecordWrappedKey, out.RecordCiphertext = sr.Nonce, sr.WrappedKey, sr.Ciphertext
	if pt, err := keys.OpenRecord(m, sr); err != nil {
		t.Fatal(err)
	} else {
		pt.Destroy()
	}

	// Index tag and audit MAC.
	parts := make([][]byte, len(in.TagParts))
	for i, p := range in.TagParts {
		parts[i] = p
	}
	if out.IndexTag, err = keys.Index.Tag(in.TagNamespace, parts...); err != nil {
		t.Fatal(err)
	}
	if out.AuditRowCBOR, err = EncodeCanonical(in.AuditRow); err != nil {
		t.Fatal(err)
	}
	if out.AuditMAC, err = keys.Audit.MAC(in.AuditPrev, out.AuditRowCBOR); err != nil {
		t.Fatal(err)
	}

	b, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestVectors(t *testing.T) {
	got := generateVectors(t)
	if *update {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("rewrote %s", vectorsPath)
		return
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (create it with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the sealed format changed: regenerated vectors differ from %s.\n"+
			"If the change is deliberate, bump FormatVersion, add new vectors, and run with -update.", vectorsPath)
	}
}

// Independent of regeneration: the committed outputs must decrypt with the
// committed inputs, so a stale file cannot pass by accident.
func TestCommittedVectorsOpen(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Skip("no vectors yet")
	}
	var generic struct {
		Inputs  map[string]any `json:"inputs"`
		Outputs map[string]any `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	h := func(m map[string]any, k string) []byte {
		b, err := hex.DecodeString(m[k].(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	master := secret.Take(h(generic.Inputs, "master_key"))
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	m := RecordMeta{
		WorkspaceID: h(generic.Inputs, "workspace_id"), RecordID: h(generic.Inputs, "record_id"),
		Kind: generic.Inputs["kind"].(string), Owner: generic.Inputs["owner"].(string),
		Class: generic.Inputs["class"].(string), Version: uint64(generic.Inputs["record_version"].(float64)),
	}
	sr := SealedRecord{Nonce: h(generic.Outputs, "record_nonce"), WrappedKey: h(generic.Outputs, "record_wrapped_key"), Ciphertext: h(generic.Outputs, "record_ciphertext")}
	pt, err := keys.OpenRecord(m, sr)
	if err != nil {
		t.Fatal(err)
	}
	pt.Use(func(b []byte) error {
		if !bytes.Equal(b, h(generic.Inputs, "plaintext")) {
			t.Error("plaintext mismatch")
		}
		return nil
	})
	m.Version++
	if _, err := keys.OpenRecord(m, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("altered version opened: %v", err)
	}
}
