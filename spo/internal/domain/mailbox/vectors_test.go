package mailbox_test

// testdata/vectors.json pins the wire format of what protocol version 2 shares
// with the framing and the envelope id: the envelope hash and the frames whose
// shape does not carry the identity (the Challenge, the PutResult, the Fetch, the
// Items, the Ack, the AckResult and the Error). The frames that are new in
// version 2 and the auth bytes are in testdata/vectors_v2.json. A later
// independent implementation can check its own output against them
// (testdata/check_vectors.py does so for the hash, the auth bytes and every
// frame). TestVectors regenerates the file in memory and compares it byte for byte
// with the committed one; a difference is a format change. Rewrite deliberately
// with:
//
//	go test ./internal/domain/mailbox -run TestVectors -update

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

type frameVector struct {
	Name     string         `json:"name"`
	Type     uint           `json:"type"`
	Fields   map[string]any `json:"fields"`
	CBORHex  string         `json:"cbor_hex"`
	FrameHex string         `json:"frame_hex"` // with the 4-byte length prefix
}

type hashVector struct {
	EnvelopeHex string `json:"envelope_hex"`
	Mid         string `json:"mid"`
}

type vectorFile struct {
	Note   string        `json:"note"`
	Hash   []hashVector  `json:"hash"`
	Frames []frameVector `json:"frames"`
}

func x(b []byte) string { return hex.EncodeToString(b) }

func buildVectors(t *testing.T) []byte {
	t.Helper()
	vf := vectorFile{Note: "ADR 0013 work package 1, kept under protocol version 2 (ADR 0014 work package 7); hex fields are lower-case; numbers are decimal"}
	for _, env := range [][]byte{{}, []byte("abc"), bs(100, 0xA5)} {
		vf.Hash = append(vf.Hash, hashVector{x(env), mailbox.HashOf(env).String()})
	}
	h := hash(9)
	named := []struct {
		name   string
		m      mailbox.Message
		fields map[string]any
	}{
		{"challenge", mailbox.Challenge{Min: 2, Max: 2, Nonce: nonce(1), RelayKey: nk(2), RelayTime: 1700000000},
			map[string]any{"min": 2, "max": 2, "nonce": x(nonceb(1)), "relay_key": x(func() []byte { k := nk(2); return k[:] }()), "relay_time": 1700000000}},
		{"put_result_stored", mailbox.PutResult{RequestID: 7, Status: mailbox.StatusStored}, map[string]any{"request_id": 7, "status": 0}},
		{"put_result_unavailable", mailbox.PutResult{RequestID: 1<<32 - 1, Status: mailbox.StatusUnavailable}, map[string]any{"request_id": uint64(1<<32 - 1), "status": 7}},
		{"fetch_from_start", mailbox.Fetch{RequestID: 8, MaxItems: 16, WaitSeconds: 20}, map[string]any{"request_id": 8, "after": "", "max_items": 16, "wait_seconds": 20}},
		{"fetch_after", mailbox.Fetch{RequestID: 9, After: &h, MaxItems: 1, WaitSeconds: 0}, map[string]any{"request_id": 9, "after": x(h[:]), "max_items": 1, "wait_seconds": 0}},
		{"items", mailbox.Items{RequestID: 8, Entries: []mailbox.Item{{Mid: hash(1), Size: 10}, {Mid: hash(2), Size: 20}}, More: true},
			map[string]any{"request_id": 8, "entries": []any{[]any{x(mid(1)), 10}, []any{x(mid(2)), 20}}, "more": true}},
		{"items_empty", mailbox.Items{RequestID: 8}, map[string]any{"request_id": 8, "entries": []any{}, "more": false}},
		{"ack", mailbox.Ack{RequestID: 9, Mids: []mailbox.Hash{hash(1), hash(2)}}, map[string]any{"request_id": 9, "mids": []any{x(mid(1)), x(mid(2))}}},
		{"ack_result", mailbox.AckResult{RequestID: 9, Deleted: 2}, map[string]any{"request_id": 9, "deleted": 2}},
		{"error_auth", mailbox.Error{Code: mailbox.CodeAuth}, map[string]any{"code": 1}},
	}
	for _, n := range named {
		b := mustEncode(t, n.m)
		fr, err := mailbox.AppendFrame(nil, b)
		if err != nil {
			t.Fatal(err)
		}
		vf.Frames = append(vf.Frames, frameVector{n.name, uint(n.m.Type()), n.fields, x(b), x(fr)})
	}
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func mid(b byte) []byte { h := hash(b); return h[:] }

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spec: SPO-Xmailbox-OUT-011
func TestVectors(t *testing.T) {
	got := buildVectors(t)
	const path = "testdata/vectors.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to write it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/vectors.json differs from the regenerated vectors; a difference is a format change")
	}
}

// The committed file is checked on its own: hashes recompute and every frame
// decodes (at one of the stages and sides of version 2) and re-encodes to itself.
//
// spec: SPO-Xmailbox-OUT-011, SPO-Xmailbox-INV-002
func TestCommittedVectorsStandAlone(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Hash) < 3 || len(vf.Frames) != 10 {
		t.Fatalf("too few vectors: %d hashes, %d frames", len(vf.Hash), len(vf.Frames))
	}
	for _, v := range vf.Hash {
		if got := mailbox.HashOf(unhex(t, v.EnvelopeHex)).String(); got != v.Mid {
			t.Errorf("hash %s", v.EnvelopeHex)
		}
	}
	for _, v := range vf.Frames {
		c := unhex(t, v.CBORHex)
		m, err := mailbox.DecodeAny(c)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if uint(m.Type()) != v.Type {
			t.Errorf("%s: type %d", v.Name, m.Type())
		}
		if !bytes.Equal(mustEncode(t, m), c) {
			t.Errorf("%s: re-encode", v.Name)
		}
		fr := unhex(t, v.FrameHex)
		if binary.BigEndian.Uint32(fr) != uint32(len(c)) || !bytes.Equal(fr[4:], c) {
			t.Errorf("%s: frame", v.Name)
		}
		if body, err := mailbox.ReadHeaderFrame(bytes.NewReader(fr)); err != nil || !bytes.Equal(body, c) {
			t.Errorf("%s: ReadHeaderFrame: %v", v.Name, err)
		}
	}
}

// The independent check of the vectors, when a Python interpreter is present
// (the convention of internal/domain/layout). Where the check must run, as in
// the Nix check, SPO_REQUIRE_PYTHON=1 makes a missing interpreter a failure.
//
// spec: SPO-Xmailbox-OUT-011
func TestVectorsAgreeWithTheIndependentCheck(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv("SPO_REQUIRE_PYTHON") == "1" {
			t.Fatal("python3 is not on PATH, and SPO_REQUIRE_PYTHON=1 says the check must run it")
		}
		t.Skip("no python3: run testdata/check_vectors.py where one is available")
	}
	out, err := exec.Command(py, "-I", "testdata/check_vectors.py").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !bytes.HasPrefix(out, []byte("ok ")) {
		t.Fatalf("unexpected output %q", out)
	}
}
