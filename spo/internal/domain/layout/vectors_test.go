package layout_test

// testdata/vectors.json pins the layout: the canonical CBOR of every object
// kind, the bucket arithmetic at the edges, the slots object of each policy
// and a provisional head. TestVectors regenerates it in memory and compares it
// with the committed file byte for byte; a difference is a format change.
// The records come from testdata/records.json, which the seal package's
// TestRecordFixtures writes from the real seal functions. Rewrite deliberately
// (see internal/platform/seal/object_vectors_test.go for the order):
//
//	go test ./internal/domain/layout -run TestVectors -update

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

type hxs []byte

func (h hxs) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }

type recordsFile struct {
	WorkspaceID hxs `json:"workspace_id"`
	KeyEpoch    hxs `json:"key_epoch"`
	Records     []struct {
		Name       string `json:"name"`
		Cold       bool   `json:"cold"`
		Class      string `json:"class"`
		Kind       string `json:"kind"`
		RecordID   string `json:"record_id"`
		Anchor     string `json:"anchor"`
		Num        uint64 `json:"num"`
		Version    uint64 `json:"version"`
		Format     uint64 `json:"format"`
		UpdatedAt  int64  `json:"updated_at"`
		PayloadLen int    `json:"payload_len"`
		Nonce      string `json:"nonce"`
		WrappedKey string `json:"wrapped_key"`
		Owner      string `json:"owner"`
		Ciphertext string `json:"ciphertext"`
	} `json:"records"`
}

func loadRecords(t testing.TB) (recordsFile, []layout.Record) {
	t.Helper()
	raw, err := os.ReadFile("testdata/records.json")
	if err != nil {
		t.Fatalf("%v (written by the seal package's TestRecordFixtures)", err)
	}
	var f recordsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// the open-only record with an HPKE recovery wrap
	raw2, err := os.ReadFile("testdata/records_recovery.json")
	if err != nil {
		t.Fatalf("%v (written by the seal package's TestRecoveryRecordFixture)", err)
	}
	var f2 recordsFile
	if err := json.Unmarshal(raw2, &f2); err != nil {
		t.Fatal(err)
	}
	f.Records = append(f.Records, f2.Records...)
	var recs []layout.Record
	for _, r := range f.Records {
		recs = append(recs, layout.Record{Kind: r.Kind, Class: r.Class, ID: hx(r.RecordID), Anchor: hx(r.Anchor), Num: r.Num, Version: r.Version,
			RecordFormat: r.Format, UpdatedAt: r.UpdatedAt,
			Inner: layout.Inner{Nonce: hx(r.Nonce), WrappedKey: hx(r.WrappedKey), Owner: hx(r.Owner), Ciphertext: hx(r.Ciphertext)}})
	}
	return f, recs
}

type vecObject struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	CBOR     hxs    `json:"cbor"`
	BodyLen  int    `json:"body_len"`
	BodySHA  hxs    `json:"body_sha256"`
	StoredIn int    `json:"stored_len"`
}

type vecSlots struct {
	Policy      string `json:"policy"`
	Stored      hxs    `json:"stored"`
	ObjectName  string `json:"object_name"`
	Path        string `json:"path"`
	SlotSetHash hxs    `json:"slot_set_hash"`
}

type vecEdge struct {
	CBORLen   int    `json:"cbor_len"`
	StoredLen int    `json:"stored_len,omitempty"`
	Refused   string `json:"refused,omitempty"`
}

type vecHead struct {
	Note string `json:"note"`
	Hash hxs    `json:"hash"`
	Path string `json:"path"`
}

type vectorsFile struct {
	Comment    string      `json:"_comment"`
	Edges      []vecEdge   `json:"bucket_edges"`
	Objects    []vecObject `json:"objects"`
	Slots      []vecSlots  `json:"slots_objects"`
	Head       vecHead     `json:"head"`
	Namespace  string      `json:"head_namespace"`
	ParentFmt  string      `json:"parent_format"`
	WrappedMax int         `json:"wrapped_key_width"`
}

// sampleObjects are the non-record objects of the vectors.
func sampleObjects() []struct {
	name string
	o    layout.Object
} {
	rp := layout.RecordPage{Entries: []layout.RecordEntry{
		{ID: pat(0xa0, 16), Version: 1, Hash: pat(0x10, 32)},
		{ID: pat(0xa1, 16), Version: 4, Hash: pat(0x20, 32)},
		{ID: pat(0xa3, 16), Version: 5, Hash: pat(0x30, 32)},
	}}
	ap := layout.AuditPage{Entries: []layout.AuditEntry{{Seq: 1, Hash: pat(0x40, 32)}, {Seq: 2, Hash: pat(0x50, 32)}, {Seq: 3, Hash: pat(0x60, 32)}}}
	root := layout.Root{RecordPages: [][]byte{pat(0x70, 32)}, AuditPages: [][]byte{pat(0x80, 32)}, Slots: pat(0x90, 32), AuditSeq: 3, AuditMAC: pat(0xa0, 32),
		Records: 3, Audits: 3, Parent: layout.Parent{Format: layout.ParentFormat, Seq: 2, PreviousHead: pat(0xb0, 32)}}
	au := layout.Audit{Seq: 3, At: 1700000003, Kind: "update", Event: pat(0xc0, 304), Touched: pat(0xd0, 150), MAC: pat(0xe0, 32), PrevMAC: pat(0xe1, 32)}
	slotsRow := layout.Audit{Seq: 1, At: 1700000000, Kind: "slots", Event: pat(0xc0, 304), Touched: []byte{0x80}, SlotSet: pat(0xf0, 32), MAC: pat(0xe2, 32), PrevMAC: make([]byte, 32)}
	return []struct {
		name string
		o    layout.Object
	}{{"audit-update", au}, {"audit-slots", slotsRow}, {"manifest-page-records", rp}, {"manifest-page-audit", ap}, {"manifest-root", root}}
}

func generateVectors(t testing.TB) []byte {
	t.Helper()
	_, recs := loadRecords(t)
	var v vectorsFile
	v.Comment = "Pins the layout format. Regenerate only for a deliberate format change: go test ./internal/domain/layout -run TestVectors -update"
	v.Namespace, v.ParentFmt, v.WrappedMax = layout.NamespaceHead, layout.ParentFormat, layout.WrappedKeyMax
	for _, c := range []int{0, 1, 4034, 4035, 4036, 8131, 8132, 4<<20 - 62, 4<<20 - 61} {
		body, err := layout.FrameBody(make([]byte, c))
		if err != nil {
			t.Fatal(err)
		}
		v.Edges = append(v.Edges, vecEdge{CBORLen: c, StoredLen: len(body) + layout.SealedOverhead})
	}
	if _, err := layout.FrameBody(make([]byte, 4<<20-60)); err == nil {
		t.Fatal("one byte over the largest bucket was framed")
	}
	v.Edges = append(v.Edges, vecEdge{CBORLen: 4<<20 - 60, Refused: "needs a stored object of 4194305 bytes"})
	add := func(name, kind string, o layout.Object) {
		c, err := layout.EncodeObject(o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, err := layout.FrameBody(c)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		v.Objects = append(v.Objects, vecObject{Name: name, Kind: kind, CBOR: c, BodyLen: len(body), BodySHA: sum[:], StoredIn: len(body) + layout.SealedOverhead})
	}
	f, _ := loadRecords(t)
	for i, r := range recs {
		add("record-"+f.Records[i].Name, r.Kind, r)
	}
	for _, s := range sampleObjects() {
		add(s.name, "", s.o)
	}
	for _, pol := range []string{"standard", "hardware", "strict"} {
		so := samplePolicySlots(pol)
		stored, err := layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			t.Fatal(err)
		}
		name := layout.ObjectName(stored)
		path, _ := layout.ObjectPath(name)
		h, err := layout.SlotSetHash(pol, so.Slots)
		if err != nil {
			t.Fatal(err)
		}
		v.Slots = append(v.Slots, vecSlots{Policy: pol, Stored: stored, ObjectName: name, Path: path, SlotSetHash: h})
	}
	head := layout.Head{Workspace: pat(0x20, 16), Sequence: 2, Previous: pat(0x30, 32), Manifest: pat(0x40, 32), Slots: pat(0x50, 32),
		AuditSeq: 3, AuditMAC: pat(0x60, 32), RecoveryKey: pat(0x70, 32), CheckpointKey: pat(0x80, 32), Epoch: pat(0xf0, 16), Time: time.Date(2026, 11, 18, 12, 30, 5, 0, time.UTC)}
	note, err := head.Encode()
	if err != nil {
		t.Fatal(err)
	}
	v.Head = vecHead{Note: string(note), Hash: layout.HeadHash(note), Path: layout.HeadPath(head.Sequence)}
	out, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// spec: SPO-Xlayout-OUT-013
func TestVectors(t *testing.T) {
	got := generateVectors(t)
	if *update {
		if err := os.WriteFile("testdata/vectors.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/vectors.json differs from what the code produces now: a change to the format")
	}
}

// Every vector object decodes, re-encodes to itself and keeps its inner bytes.
// spec: SPO-Xlayout-INV-002, SPO-Xlayout-INV-003, SPO-Xlayout-OUT-013
func TestVectorObjectsRoundTrip(t *testing.T) {
	_, recs := loadRecords(t)
	var all []layout.Object
	for _, r := range recs {
		all = append(all, r)
	}
	for _, s := range sampleObjects() {
		all = append(all, s.o)
	}
	for _, o := range all {
		body, err := layout.EncodeBody(o)
		if err != nil {
			t.Fatal(err)
		}
		got, err := layout.DecodeBody(body, rule)
		if err != nil {
			t.Fatalf("%T: %v", o, err)
		}
		again, err := layout.EncodeBody(got)
		if err != nil || !bytes.Equal(again, body) {
			t.Fatalf("%T: encode(decode(x)) != x", o)
		}
		if r, ok := o.(layout.Record); ok {
			g := got.(layout.Record).Inner
			if !bytes.Equal(g.Nonce, r.Inner.Nonce) || !bytes.Equal(g.WrappedKey, r.Inner.WrappedKey) || !bytes.Equal(g.Owner, r.Inner.Owner) || !bytes.Equal(g.Ciphertext, r.Inner.Ciphertext) {
				t.Fatal("inner bytes out differ from inner bytes in")
			}
		}
	}
}

// The four record vectors fall into one bucket (equal payload sizes), cold or hot.
// spec: SPO-Xlayout-INV-004
func TestVectorRecordsShareABucket(t *testing.T) {
	_, recs := loadRecords(t)
	var secrets []int
	for _, r := range recs {
		if r.Class != "secret" {
			continue
		}
		b, err := layout.EncodeBody(r)
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, len(b))
	}
	if len(secrets) != 4 || secrets[0] != secrets[1] || secrets[1] != secrets[2] || secrets[2] != secrets[3] {
		t.Fatalf("hot secret, cold passphrase, cold FIDO2 and cold FIDO2 with a recovery wrap bodies: %v", secrets)
	}
}
