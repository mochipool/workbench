package sqlitestore

// Store-level byte layouts, pinned. testdata/store_vectors.json holds fixed
// inputs and the bytes the store derives from them: the owner string, the
// record hash that the audit chain covers, the touched list, the associated
// data of an audit event, the audit row the chain MAC covers, the chain MAC
// and the head file. The seal package pins the sealed record layouts
// (platform/seal/testdata/vectors.json). Regenerate deliberately with
//
//	go test ./internal/adapters/sqlitestore -run TestStoreVectors -update

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var update = flag.Bool("update", false, "rewrite testdata/store_vectors.json")

const storeVectorsPath = "testdata/store_vectors.json"

type hx []byte

func (h hx) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

func pattern(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func generateStoreVectors(t *testing.T) []byte {
	t.Helper()
	ws := pattern(0x20, 16)
	master := secret.Take(pattern(0x10, 32))
	defer master.Destroy()
	keys, err := seal.DeriveKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	ref := rf("mypool", ports.KesVKey, 3)
	ab, _ := ref.Anchor.MarshalBinary()
	ownerBlob, err := seal.EncodeOwnerRef(ab, string(ref.Kind), uint64(ref.Num))
	if err != nil {
		t.Fatal(err)
	}
	tag, err := tagFor(keys, ref.Anchor, string(ref.Kind), ref.Num)
	if err != nil {
		t.Fatal(err)
	}
	sealed := seal.SealedRecord{Nonce: pattern(0x40, 24), WrappedKey: pattern(0x60, 72), Owner: pattern(0x80, 24+160+16), Ciphertext: pattern(0xa0, 45+16)}
	hash, err := recordHash(string(ref.Kind), tag, sealed)
	if err != nil {
		t.Fatal(err)
	}
	id := pattern(0xc0, 16)
	entries := []touched{{ID: id, Version: 4, Hash: hash}, {ID: pattern(0xd0, 16), Version: 2, Hash: []byte{}}}
	touchedRaw, err := seal.EncodeCanonical(entries)
	if err != nil {
		t.Fatal(err)
	}
	evAD, err := eventMeta(ws, 7).AD()
	if err != nil {
		t.Fatal(err)
	}
	event := pattern(0xe0, 100)
	slotset := pattern(0xf0, 32)
	row, err := auditRowBytes(ws, 7, auditSlots, 1700000000, event, touchedRaw, slotset)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := keys.Audit.MAC(zeroMAC, row)
	if err != nil {
		t.Fatal(err)
	}
	events, err := seal.EncodeCanonical([][]any{{"put", ref.String()}, {"rollover", uint64(6), zeroMAC, pattern(0x11, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	slotRows := [][]any{
		{pattern(0x01, 16), "passphrase", int64(65536), int64(3), int64(1), pattern(0x02, 16), pattern(0x03, 32), pattern(0x04, 24), pattern(0x05, 48)},
		{pattern(0x06, 16), "recovery", nil, nil, nil, nil, pattern(0x07, 32), pattern(0x08, 24), pattern(0x09, 48)},
	}
	slotSet, err := hashSlotRows(slotRows)
	if err != nil {
		t.Fatal(err)
	}
	history, err := historyHash([]auditRow{
		{seq: 1, at: 1700000000, kind: auditSlots, event: pattern(0x21, 50), touchedRaw: []byte{0x80}, slotset: slotset, mac: pattern(0x31, 32), prev: zeroMAC},
		{seq: 2, at: 1700000001, kind: auditUpdate, event: pattern(0x22, 60), touchedRaw: touchedRaw, slotset: []byte{}, mac: pattern(0x32, 32), prev: pattern(0x31, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := struct {
		Comment       string   `json:"_comment"`
		WorkspaceID   hx       `json:"workspace_id"`
		MasterKey     hx       `json:"master_key"`
		Ref           string   `json:"ref"`
		Owner         string   `json:"owner_blob_content"`
		LookupTag     hx       `json:"lookup_tag"`
		SealedNonce   hx       `json:"sealed_nonce"`
		SealedWrapped hx       `json:"sealed_wrapped_key"`
		SealedOwner   hx       `json:"sealed_owner"`
		SealedCT      hx       `json:"sealed_ciphertext"`
		SealedBytes   hx       `json:"sealed_bytes"`
		RecordHash    hx       `json:"record_hash"`
		Touched       hx       `json:"touched_cbor"`
		AuditID       hx       `json:"audit_id_of_seq_7"`
		EventAD       hx       `json:"event_ad_of_seq_7"`
		EventsCBOR    hx       `json:"events_cbor"`
		AuditRow      hx       `json:"audit_row_cbor"`
		AuditMAC      hx       `json:"audit_mac"`
		HeadFile      string   `json:"head_file"`
		AuditKinds    []string `json:"audit_kinds"`
		PaddedEvent   hx       `json:"padded_event_of_put_a"`
		SlotSet       hx       `json:"slot_set_hash"`
		History       hx       `json:"history_hash"`
	}{
		Comment:     "Pins the store byte layouts. Regenerate only for a deliberate format change: go test ./internal/adapters/sqlitestore -run TestStoreVectors -update",
		WorkspaceID: ws, MasterKey: pattern(0x10, 32), Ref: ref.String(), Owner: hex.EncodeToString(ownerBlob), LookupTag: tag,
		SealedNonce: sealed.Nonce, SealedWrapped: sealed.WrappedKey, SealedOwner: sealed.Owner, SealedCT: sealed.Ciphertext,
		SealedBytes: sealed.Bytes(), RecordHash: hash, Touched: touchedRaw, AuditID: auditID(7), EventAD: evAD,
		EventsCBOR: events, AuditRow: row, AuditMAC: mac, HeadFile: string(encodeHead(ws, Head{Seq: 7, MAC: mac})),
		AuditKinds:  []string{auditUpdate, auditSlots, auditRollover},
		PaddedEvent: padEvent([]byte("put a")), SlotSet: slotSet, History: history,
	}
	b, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestStoreVectors(t *testing.T) {
	got := generateStoreVectors(t)
	if *update {
		if err := os.WriteFile(storeVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(storeVectorsPath)
	if err != nil {
		t.Fatalf("%v (create it with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("a store byte layout changed (record hash, touched list, event AD, audit row, MAC or head file): " +
			"if deliberate, bump the format version, add vectors and run with -update")
	}
}
