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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strconv"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

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
		OwnerNonce     hx     `json:"owner_nonce"`
		NewMasterKey   hx     `json:"rewrap_master_key"`
		NewWrapNonce   hx     `json:"rewrap_wrap_nonce"`
		NewOwnerNonce  hx     `json:"rewrap_owner_nonce"`
		SensitiveKind  string `json:"sensitive_kind"`
		SensitiveText  hx     `json:"sensitive_plaintext"`
		Plaintext      hx     `json:"plaintext"`
		TagNamespace   string `json:"tag_namespace"`
		TagParts       []hx   `json:"tag_parts"`
		AuditPrev      hx     `json:"audit_prev_mac"`
		AuditRow       []any  `json:"audit_row"`
		KeyEpoch       hx     `json:"key_epoch"`
	} `json:"inputs"`

	Outputs struct {
		RecordWrapKey   hx `json:"hkdf_record_wrap_key"`
		IndexKey        hx `json:"hkdf_index_key"`
		AuditKey        hx `json:"hkdf_audit_key"`
		RecoverySlotKey hx `json:"hkdf_recovery_slot_key"`

		PassphraseSlotKey     hx     `json:"passphrase_slot_key"`
		PassphraseSlotCommit  hx     `json:"passphrase_slot_commit"`
		PassphraseSlotAD      hx     `json:"passphrase_slot_ad"`
		PassphraseSlotWrapped hx     `json:"passphrase_slot_wrapped"`
		RecoverySlotCommit    hx     `json:"recovery_slot_commit"`
		RecoverySlotAD        hx     `json:"recovery_slot_ad"`
		RecoverySlotWrapped   hx     `json:"recovery_slot_wrapped"`
		RecoveryKeyText       string `json:"recovery_key_text"`

		RecordAD         hx `json:"record_ad"`
		RecordOwnerAD    hx `json:"record_owner_ad"`
		RecordPadded     hx `json:"record_padded_plaintext"`
		RecordNonce      hx `json:"record_nonce"`
		RecordWrappedKey hx `json:"record_wrapped_key"`
		RecordOwner      hx `json:"record_owner"`
		RecordCiphertext hx `json:"record_ciphertext"`
		RecordBytes      hx `json:"record_bytes"`

		SensitiveAD         hx `json:"sensitive_ad"`
		SensitiveWrappedKey hx `json:"sensitive_wrapped_key"`
		SensitiveOwner      hx `json:"sensitive_owner"`
		SensitiveCiphertext hx `json:"sensitive_ciphertext"`

		RewrapWrappedKey hx `json:"rewrap_wrapped_key"`
		RewrapOwner      hx `json:"rewrap_owner"`

		PadBuckets map[string]int `json:"pad_buckets"`

		IndexTag     hx `json:"index_tag"`
		AuditRowCBOR hx `json:"audit_row_cbor"`
		AuditMAC     hx `json:"audit_mac"`
		EpochMAC     hx `json:"epoch_mac"`
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
	in.OwnerNonce = pattern(0xe0, 24)
	in.NewMasterKey = pattern(0x01, 32)
	in.NewWrapNonce = pattern(0x21, 24)
	in.NewOwnerNonce = pattern(0x41, 24)
	in.SensitiveKind = "kes.vkey"
	in.SensitiveText = []byte(`{"type":"KesVerificationKey_ed25519_kes_2^6"}`)
	in.Plaintext = []byte(`{"type":"KesSigningKey_ed25519_kes_2^6"}`)
	in.TagNamespace = "record-ref"
	in.TagParts = []hx{[]byte("mypool"), []byte("kes.skey"), []byte("7")}
	in.AuditPrev = make([]byte, MACSize)
	in.AuditRow = []any{FormatVersion, 5, "update", "x"}
	in.KeyEpoch = pattern(0xf0, EpochSize)

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
		KDFParams{in.KDFMemoryKiB, in.KDFPasses, in.KDFLanes}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	if out.PassphraseSlotAD, err = slot.ad(in.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	psk, err := slot.slotKey(pw)
	if err != nil {
		t.Fatal(err)
	}
	out.PassphraseSlotKey = grab(psk)
	psk.Destroy()
	out.PassphraseSlotCommit = slot.Commit
	out.PassphraseSlotWrapped = slot.Wrapped
	if got, err := slot.Unwrap(in.WorkspaceID, pw); err != nil {
		t.Fatal(err)
	} else {
		got.Destroy()
	}

	// Recovery slot. Randomness order: recovery key, nonce.
	rng = &scripted{t: t, chunks: [][]byte{in.RecoveryKey, in.RecoveryNonce}}
	rslot, gotKey, err := sealer{rand: rng}.newRecoverySlot(in.WorkspaceID, in.RecoverySlotID, master, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	gotKey.Destroy()
	if out.RecoverySlotAD, err = rslot.ad(in.WorkspaceID); err != nil {
		t.Fatal(err)
	}
	out.RecoverySlotCommit = rslot.Commit
	out.RecoverySlotWrapped = rslot.Wrapped
	txt, err := EncodeRecoveryKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	txt.Use(func(b []byte) error { out.RecoveryKeyText = string(b); return nil })

	// Secret record. Randomness order: data key, payload nonce, wrap nonce,
	// owner nonce.
	m := RecordMeta{WorkspaceID: in.WorkspaceID, RecordID: in.RecordID, Kind: in.Kind, Owner: in.Owner, Class: in.Class, Version: in.RecordVersion}
	if out.RecordAD, err = m.AD(); err != nil {
		t.Fatal(err)
	}
	if out.RecordOwnerAD, err = ownerAD(LegacyRecordFormat, in.WorkspaceID, in.RecordID, in.Kind); err != nil {
		t.Fatal(err)
	}
	src := secret.Take(append([]byte(nil), in.Plaintext...))
	defer src.Destroy()
	framed, err := frameSecret(src)
	if err != nil {
		t.Fatal(err)
	}
	out.RecordPadded = grab(framed)
	framed.Destroy()
	rng = &scripted{t: t, chunks: [][]byte{in.DataKey, in.PayloadNonce, in.WrapNonce, in.OwnerNonce}}
	sr, err := sealer{rand: rng}.sealRecord(keys, m, func(fn func([]byte) error) error {
		padded, err := frameSecret(src)
		if err != nil {
			return err
		}
		defer padded.Destroy()
		return padded.Use(fn)
	})
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	out.RecordNonce, out.RecordWrappedKey, out.RecordOwner, out.RecordCiphertext = sr.Nonce, sr.WrappedKey, sr.Owner, sr.Ciphertext
	out.RecordBytes = sr.Bytes()
	if pt, err := keys.OpenSecret(m, sr); err != nil {
		t.Fatal(err)
	} else {
		pt.Destroy()
	}

	// Sensitive record: the plaintext is not framed or padded.
	sm := m
	sm.Kind, sm.Class = in.SensitiveKind, ClassSensitive
	if out.SensitiveAD, err = sm.AD(); err != nil {
		t.Fatal(err)
	}
	rng = &scripted{t: t, chunks: [][]byte{in.DataKey, in.PayloadNonce, in.WrapNonce, in.OwnerNonce}}
	ssr, err := sealer{rand: rng}.sealRecord(keys, sm, func(fn func([]byte) error) error { return fn(in.SensitiveText) })
	if err != nil {
		t.Fatal(err)
	}
	rng.done()
	out.SensitiveWrappedKey, out.SensitiveOwner, out.SensitiveCiphertext = ssr.WrappedKey, ssr.Owner, ssr.Ciphertext
	if pt, err := keys.OpenRecord(sm, ssr); err != nil || !bytes.Equal(pt, in.SensitiveText) {
		t.Fatalf("sensitive round trip: %v", err)
	}

	// Rewrap of the secret record under a second master key. Randomness
	// order: wrap nonce, owner nonce.
	master2 := secret.Take(append([]byte(nil), in.NewMasterKey...))
	defer master2.Destroy()
	keys2, err := DeriveKeys(master2)
	if err != nil {
		t.Fatal(err)
	}
	defer keys2.Destroy()
	rng = &scripted{t: t, chunks: [][]byte{in.NewWrapNonce, in.NewOwnerNonce}}
	dk, ad, err := keys.openDataKey(m, sr)
	if err != nil {
		t.Fatal(err)
	}
	out.RewrapWrappedKey, out.RewrapOwner, err = sealer{rand: rng}.wrapUnder(keys2, m, ad, dk)
	dk.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	rng.done()

	out.PadBuckets = map[string]int{}
	for _, n := range []int{1, 252, 253, 508, 509, 1021, 1022} {
		out.PadBuckets[strconv.Itoa(n)] = paddedLen(n)
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
	if out.EpochMAC, err = keys.Audit.EpochMAC(in.WorkspaceID, in.KeyEpoch); err != nil {
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
// committed inputs, so a stale file cannot pass by accident. Slots are opened
// from the committed bytes only, and the AEAD is cross-checked against
// golang.org/x/crypto/chacha20poly1305 called directly, independent of this
// package's wrappers.
func TestCommittedVectorsOpen(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (create it with -update)", err)
	}
	var generic struct {
		Inputs  map[string]any `json:"inputs"`
		Outputs map[string]any `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	in, out := generic.Inputs, generic.Outputs
	h := func(m map[string]any, k string) []byte {
		s, ok := m[k].(string)
		if !ok {
			t.Fatalf("vector %q missing", k)
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ws := h(in, "workspace_id")
	master := secret.Take(h(in, "master_key"))
	defer master.Destroy()
	keys, err := DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()

	// Slots, from the committed bytes.
	withProductionFloor(t)
	pw := secret.Take([]byte(in["passphrase"].(string)))
	defer pw.Destroy()
	pslot := Slot{
		ID: h(in, "slot_id"), Kind: SlotPassphrase,
		KDF:  KDFParams{uint32(in["kdf_memory_kib"].(float64)), uint32(in["kdf_passes"].(float64)), uint8(in["kdf_lanes"].(float64))},
		Salt: h(in, "salt"), Commit: h(out, "passphrase_slot_commit"), Nonce: h(in, "slot_nonce"), Wrapped: h(out, "passphrase_slot_wrapped"),
	}
	got, err := pslot.Unwrap(ws, pw)
	if err != nil {
		t.Fatalf("committed passphrase slot: %v", err)
	}
	sameKey(t, master, got)
	got.Destroy()
	rk := secret.Take(h(in, "recovery_key"))
	defer rk.Destroy()
	rslot := Slot{ID: h(in, "recovery_slot_id"), Kind: SlotRecovery, Commit: h(out, "recovery_slot_commit"), Nonce: h(in, "recovery_slot_nonce"), Wrapped: h(out, "recovery_slot_wrapped")}
	if got, err = rslot.Unwrap(ws, rk); err != nil {
		t.Fatalf("committed recovery slot: %v", err)
	}
	sameKey(t, master, got)
	got.Destroy()
	bad := rslot
	bad.Commit = append([]byte(nil), bad.Commit...)
	bad.Commit[0] ^= 1
	if _, err := bad.Unwrap(ws, rk); !errors.Is(err, ErrAuth) {
		t.Errorf("slot with an altered commitment opened: %v", err)
	}

	// Records, with the committed metadata.
	m := RecordMeta{
		WorkspaceID: ws, RecordID: h(in, "record_id"),
		Kind: in["kind"].(string), Owner: in["owner"].(string),
		Class: in["class"].(string), Version: uint64(in["record_version"].(float64)),
	}
	sr := SealedRecord{Nonce: h(out, "record_nonce"), WrappedKey: h(out, "record_wrapped_key"), Owner: h(out, "record_owner"), Ciphertext: h(out, "record_ciphertext")}
	pt, err := keys.OpenSecret(m, sr)
	if err != nil {
		t.Fatal(err)
	}
	pt.Use(func(b []byte) error {
		if !bytes.Equal(b, h(in, "plaintext")) {
			t.Error("plaintext mismatch")
		}
		return nil
	})
	pt.Destroy()
	if o, err := keys.OpenOwner(ws, m.RecordID, m.Kind, sr); err != nil || o != m.Owner {
		t.Errorf("owner %q %v", o, err)
	}
	if !bytes.Equal(sr.Bytes(), h(out, "record_bytes")) {
		t.Error("record bytes layout changed")
	}
	if back, err := ParseSealed(h(out, "record_bytes")); err != nil || !bytes.Equal(back.Ciphertext, sr.Ciphertext) || !bytes.Equal(back.Owner, sr.Owner) {
		t.Errorf("ParseSealed: %v", err)
	}
	m.Version++
	if _, err := keys.OpenSecret(m, sr); !errors.Is(err, ErrAuth) {
		t.Errorf("altered version opened: %v", err)
	}
	sm := m
	sm.Version, sm.Kind, sm.Class = uint64(in["record_version"].(float64)), in["sensitive_kind"].(string), ClassSensitive
	ssr := SealedRecord{Nonce: sr.Nonce, WrappedKey: h(out, "sensitive_wrapped_key"), Owner: h(out, "sensitive_owner"), Ciphertext: h(out, "sensitive_ciphertext")}
	if spt, err := keys.OpenRecord(sm, ssr); err != nil || !bytes.Equal(spt, h(in, "sensitive_plaintext")) {
		t.Errorf("committed sensitive record: %v", err)
	}
	// Rewrapped under the second master key.
	master2 := secret.Take(h(in, "rewrap_master_key"))
	defer master2.Destroy()
	keys2, err := DeriveKeys(master2)
	if err != nil {
		t.Fatal(err)
	}
	defer keys2.Destroy()
	m.Version--
	re := SealedRecord{Nonce: sr.Nonce, WrappedKey: h(out, "rewrap_wrapped_key"), Owner: h(out, "rewrap_owner"), Ciphertext: sr.Ciphertext}
	if p2, err := keys2.OpenSecret(m, re); err != nil {
		t.Errorf("committed rewrapped record: %v", err)
	} else {
		p2.Destroy()
	}
	ak := keys.Audit
	if ok, err := ak.CheckEpoch(m.WorkspaceID, h(in, "key_epoch"), h(out, "epoch_mac")); err != nil || !ok {
		t.Errorf("committed epoch MAC: %v %v", ok, err)
	}
	for k, v := range out["pad_buckets"].(map[string]any) {
		n, _ := strconv.Atoi(k)
		if paddedLen(n) != int(v.(float64)) {
			t.Errorf("padding of %d bytes: %d, committed %v", n, paddedLen(n), v)
		}
	}
}

// The AEAD vector against golang.org/x/crypto/chacha20poly1305 called
// directly: the committed ciphertext of the secret record is
// XChaCha20-Poly1305(padded plaintext) under the data key, and the committed
// wrapped data key is XChaCha20-Poly1305 under the record-wrapping key.
func TestAEADVectorsAgainstXCrypto(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Inputs  map[string]any `json:"inputs"`
		Outputs map[string]any `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	h := func(m map[string]any, k string) []byte {
		b, err := hex.DecodeString(m[k].(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ad, dataKey, nonce := h(g.Outputs, "record_ad"), h(g.Inputs, "data_key"), h(g.Inputs, "payload_nonce")
	x, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	// The padded plaintext is 4-byte length || payload || zeros up to 256 bytes.
	padded := h(g.Outputs, "record_padded_plaintext")
	payload := h(g.Inputs, "plaintext")
	want := make([]byte, 256)
	binary.BigEndian.PutUint32(want, uint32(len(payload)))
	copy(want[4:], payload)
	if !bytes.Equal(padded, want) {
		t.Fatal("committed padded plaintext is not length || payload || zeros")
	}
	if got := x.Seal(nil, nonce, padded, ad); !bytes.Equal(got, h(g.Outputs, "record_ciphertext")) {
		t.Error("x/crypto XChaCha20-Poly1305 does not reproduce the committed ciphertext")
	}
	if pt, err := x.Open(nil, nonce, h(g.Outputs, "record_ciphertext"), ad); err != nil || !bytes.Equal(pt, padded) {
		t.Errorf("x/crypto cannot open the committed ciphertext: %v", err)
	}
	// Wrapped data key: wrap nonce || AEAD(data key) under the wrapping key.
	wrapKey := h(g.Outputs, "hkdf_record_wrap_key")
	w, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := h(g.Outputs, "record_wrapped_key")
	if len(wrapped) != 24+32+16 || !bytes.Equal(wrapped[:24], h(g.Inputs, "wrap_nonce")) {
		t.Fatal("wrapped key layout is not wrap nonce || 48 bytes")
	}
	if dk, err := w.Open(nil, wrapped[:24], wrapped[24:], ad); err != nil || !bytes.Equal(dk, dataKey) {
		t.Errorf("x/crypto cannot unwrap the committed data key: %v", err)
	}
	// Owner blob under the owner AD.
	owner := h(g.Outputs, "record_owner")
	if o, err := w.Open(nil, owner[:24], owner[24:], h(g.Outputs, "record_owner_ad")); err != nil {
		t.Errorf("x/crypto cannot open the committed owner blob: %v", err)
	} else if got, err := unpadOwner(o); err != nil || string(got) != g.Inputs["owner"].(string) {
		t.Errorf("committed owner blob holds %q: %v", got, err)
	}
	// Slot: the wrapped master key opens under the committed slot key, and
	// the commitment is HMAC-SHA256(slot key, label).
	sk := h(g.Outputs, "passphrase_slot_key")
	sx, err := chacha20poly1305.NewX(sk)
	if err != nil {
		t.Fatal(err)
	}
	if mk, err := sx.Open(nil, h(g.Inputs, "slot_nonce"), h(g.Outputs, "passphrase_slot_wrapped"), h(g.Outputs, "passphrase_slot_ad")); err != nil || !bytes.Equal(mk, h(g.Inputs, "master_key")) {
		t.Errorf("x/crypto cannot unwrap the committed master key: %v", err)
	}
	mac := hmac.New(sha256.New, sk)
	mac.Write([]byte("spo-workbench/seal/v1/slot-commit"))
	if !bytes.Equal(mac.Sum(nil), h(g.Outputs, "passphrase_slot_commit")) {
		t.Error("slot commitment is not HMAC-SHA256(slot key, label)")
	}
}
