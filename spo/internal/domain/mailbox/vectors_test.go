package mailbox_test

// testdata/vectors.json pins the wire format: the envelope hash, the auth
// bytes with a signature of a fixed test key, and every frame. A later
// independent implementation can check its own output against it
// (testdata/check_vectors.py does so for the hash and the auth bytes).
// TestVectors regenerates the file in memory and compares it byte for byte
// with the committed one; a difference is a format change. Rewrite
// deliberately with:
//
//	go test ./internal/domain/mailbox -run TestVectors -update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"reflect"
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

type authVector struct {
	Name         string `json:"name"`
	Version      uint   `json:"version"`
	RelayKey     string `json:"relay_key"`
	ClientKey    string `json:"client_node_key"`
	Nonce        string `json:"nonce"`
	RelayTime    int64  `json:"relay_time"`
	Fingerprint  string `json:"fingerprint"`
	BytesHex     string `json:"bytes_hex"`
	SeedHex      string `json:"ed25519_seed"`
	PublicHex    string `json:"ed25519_public"`
	SignatureHex string `json:"signature_hex"`
}

type hashVector struct {
	EnvelopeHex string `json:"envelope_hex"`
	Mid         string `json:"mid"`
}

type vectorFile struct {
	Note   string        `json:"note"`
	Hash   []hashVector  `json:"hash"`
	Auth   []authVector  `json:"auth"`
	Frames []frameVector `json:"frames"`
}

func x(b []byte) string { return hex.EncodeToString(b) }

func buildVectors(t *testing.T) []byte {
	t.Helper()
	vf := vectorFile{Note: "ADR 0013 work package 1; hex fields are lower-case; numbers are decimal"}
	for _, env := range [][]byte{{}, []byte("abc"), bs(100, 0xA5)} {
		vf.Hash = append(vf.Hash, hashVector{x(env), mailbox.HashOf(env).String()})
	}
	priv := ed25519.NewKeyFromSeed(bs(32, 1))
	for i, p := range []mailbox.AuthParams{
		params(),
		{Version: 1, RelayKey: nk(0), ClientNodeKey: nk(0), Nonce: nonce(0), RelayTime: 0, Fingerprint: fp(0)},
		{Version: 300, RelayKey: nk(200), ClientNodeKey: nk(100), Nonce: nonce(255), RelayTime: mailbox.MaxTime, Fingerprint: fp(250)},
	} {
		b, err := mailbox.AuthBytes(p)
		if err != nil {
			t.Fatal(err)
		}
		vf.Auth = append(vf.Auth, authVector{
			Name: []string{"typical", "zeros", "large values"}[i], Version: p.Version,
			RelayKey: x(p.RelayKey[:]), ClientKey: x(p.ClientNodeKey[:]), Nonce: x(p.Nonce[:]),
			RelayTime: p.RelayTime, Fingerprint: x(p.Fingerprint[:]), BytesHex: x(b),
			SeedHex: x(bs(32, 1)), PublicHex: x(priv.Public().(ed25519.PublicKey)), SignatureHex: x(ed25519.Sign(priv, b)),
		})
	}
	h := hash(9)
	named := []struct {
		name   string
		m      mailbox.Message
		fields map[string]any
	}{
		{"challenge", samples()[0], map[string]any{"min": 1, "max": 1, "nonce": x(nonceb(1)), "relay_key": x(func() []byte { k := nk(2); return k[:] }()), "relay_time": 1700000000}},
		{"auth", samples()[1], map[string]any{"version": 1, "fingerprint": x(fpb(3)), "signature": x(sigb(4))}},
		{"auth_ok", samples()[2], map[string]any{"version": 1, "max_envelope": 1 << 20, "max_entries": 256, "max_bytes": 64 << 20, "retention_seconds": 7 * 86400}},
		{"put", samples()[3], map[string]any{"request_id": 7, "to": x(fpb(4)), "mid": x(mid(5)), "size": 1234}},
		{"put_result_stored", samples()[4], map[string]any{"request_id": 7, "status": 0}},
		{"put_result_unavailable", mailbox.PutResult{RequestID: 1<<32 - 1, Status: mailbox.StatusUnavailable}, map[string]any{"request_id": uint64(1<<32 - 1), "status": 7}},
		{"fetch_from_start", samples()[5], map[string]any{"request_id": 8, "after": "", "max_items": 16, "wait_seconds": 20}},
		{"fetch_after", samples()[6], map[string]any{"request_id": 9, "after": x(h[:]), "max_items": 1, "wait_seconds": 0}},
		{"items", samples()[7], map[string]any{"request_id": 8, "entries": []any{[]any{x(mid(1)), 10}, []any{x(mid(2)), 20}}, "more": true}},
		{"items_empty", samples()[8], map[string]any{"request_id": 8, "entries": []any{}, "more": false}},
		{"ack", samples()[9], map[string]any{"request_id": 9, "mids": []any{x(mid(1)), x(mid(2))}}},
		{"ack_result", samples()[10], map[string]any{"request_id": 9, "deleted": 2}},
		{"error_auth", samples()[11], map[string]any{"code": 1}},
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

// The committed file is checked on its own: hashes recompute, auth bytes
// rebuild and verify, and every frame decodes and re-encodes to itself.
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
	if len(vf.Hash) < 3 || len(vf.Auth) < 3 || len(vf.Frames) < 13 {
		t.Fatalf("too few vectors: %d, %d, %d", len(vf.Hash), len(vf.Auth), len(vf.Frames))
	}
	for _, v := range vf.Hash {
		if got := mailbox.HashOf(unhex(t, v.EnvelopeHex)).String(); got != v.Mid {
			t.Errorf("hash %s", v.EnvelopeHex)
		}
	}
	for _, v := range vf.Auth {
		var p mailbox.AuthParams
		p.Version, p.RelayTime = v.Version, v.RelayTime
		copy(p.RelayKey[:], unhex(t, v.RelayKey))
		copy(p.ClientNodeKey[:], unhex(t, v.ClientKey))
		copy(p.Nonce[:], unhex(t, v.Nonce))
		copy(p.Fingerprint[:], unhex(t, v.Fingerprint))
		b, err := mailbox.AuthBytes(p)
		if err != nil || x(b) != v.BytesHex {
			t.Errorf("%s: bytes %x, %v", v.Name, b, err)
		}
		// No bare-key verifier is exported; the signature is checked with the
		// standard library over the bytes just rebuilt.
		if !ed25519.Verify(unhex(t, v.PublicHex), b, unhex(t, v.SignatureHex)) {
			t.Errorf("%s: the signature does not verify", v.Name)
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
	if !reflect.DeepEqual(len(vf.Frames), 13) {
		t.Error("frame count")
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
