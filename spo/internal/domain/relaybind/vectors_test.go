package relaybind_test

// testdata/vectors.json pins the statement formats with a fixed SOFTWARE test
// key. The vectors are provisional: ADR 0014 freezes them only after one
// real-device check (payment and stake message signing, un-hashed, on Ledger
// and Trezor, with the protected header bytes cardano-hw-cli writes). A later
// independent implementation can check its own output against them
// (testdata/check_vectors.py does so, including the Ed25519 signatures, with a
// hand-written implementation of RFC 8032 and the standard library).
// TestVectors regenerates the file in memory and compares it byte for byte
// with the committed one; a difference is a format change. Rewrite
// deliberately with:
//
//	go test ./internal/domain/relaybind -run TestVectors -update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

type stmtVector struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"` // binding or revoke
	Device          string `json:"device,omitempty"`
	All             bool   `json:"all,omitempty"`
	From            int64  `json:"from"`       // bindings only; 0 for a revoke
	Until           int64  `json:"until"`      // bindings only; 0 for a revoke
	NotBefore       int64  `json:"not_before"` // revokes only; 0 for a binding
	Payload         string `json:"payload"`
	PayloadHex      string `json:"payload_hex"`
	AddressForm     string `json:"address_form"` // key-hash or base-address
	AddressHex      string `json:"address_hex"`
	ProtectedHex    string `json:"protected_hex"`
	SigStructureHex string `json:"sig_structure_hex"`
	SignatureHex    string `json:"signature_hex"`
	Sign1Hex        string `json:"sign1_hex"`
	// CanonicalHashHex is Statement.FullHash (signature included, the value the
	// v2 auth bytes commit to); StatementIDHex is the signature-free identity
	// the registry de-duplicates by (VerifiedBinding.StatementID).
	CanonicalHashHex string `json:"canonical_hash_hex"`
	StatementIDHex   string `json:"statement_id_hex"`
	CoseKeyHex       string `json:"cose_key_hex"`
}

func (v stmtVector) deviceFP(t testing.TB) (fp party.Fingerprint) {
	t.Helper()
	copy(fp[:], unhex(t, v.Device))
	return fp
}

type rejectedKey struct {
	Name string `json:"name"`
	Hex  string `json:"public_key_hex"`
}

type deviceRevokeVector struct {
	Name         string `json:"name"`
	Ed25519Seed  string `json:"ed25519_seed"`
	Ed25519      string `json:"ed25519_public"`
	X25519       string `json:"x25519_public"`
	Fingerprint  string `json:"fingerprint"`
	NotBefore    int64  `json:"not_before"`
	BytesHex     string `json:"bytes_hex"`
	SignatureHex string `json:"signature_hex"`
}

type vectorFile struct {
	Note          string               `json:"note"`
	SeedHex       string               `json:"software_key_seed"`
	PublicHex     string               `json:"software_key_public"`
	KeyHashHex    string               `json:"software_key_hash"`
	Statements    []stmtVector         `json:"statements"`
	DeviceRevokes []deviceRevokeVector `json:"device_revokes"`
	NearMisses    []string             `json:"near_miss_payloads"`
	// RejectedKeys are verification keys the package refuses (small-order points
	// in every encoding, and non-canonical y >= p); the Python check shows each
	// is small-order or non-canonical with its own point arithmetic.
	RejectedKeys []rejectedKey `json:"rejected_public_keys"`
}

func nearMisses() []string {
	f0 := fpOf(0)
	dev := fmt.Sprintf("%x", f0[:])
	return []string{
		"",
		"Spo-relay-binding-v1 device " + dev + " from 1700000000 until 1707776000",
		"spo-relay-binding-v1 device " + dev + " from 01700000000 until 1707776000",
		"spo-relay-binding-v1 device " + dev + " from +1700000000 until 1707776000",
		"spo-relay-binding-v1 device " + dev + "  from 1700000000 until 1707776000",
		"spo-relay-binding-v1 device " + dev + " from 1700000000 until 1707776000\n",
		"spo-relay-binding-v1 device " + dev + " from 1700000000 until 1707776000 ",
		"spo-relay-binding-v1 device " + dev[:39] + " from 1700000000 until 1707776000",
		"spo-relay-binding-v1 device 000102030405060708090A0B0C0D0E0F10111213 from 1700000000 until 1707776000",
		"spo-relay-binding-v1 device " + dev + " until 1707776000 from 1700000000",
		"spo-relay-revoke-v1 device ALL not-before 1700000000",
		"spo-relay-revoke-v1 device all not-before 01",
		"spo-relay-revoke-v1 device all not-before 1700000000 ",
	}
}

func buildVectors(t *testing.T) []byte {
	t.Helper()
	vf := vectorFile{
		Note: "ADR 0014 work package 1. SOFTWARE test-key vectors: provisional, NOT frozen for hardware wallets " +
			"(ADR 0014 freezes them only after a real-device check). Hex is lower-case; numbers are decimal.",
		SeedHex: hx(bs(32, 7)), PublicHex: hx(testPub[:]), KeyHashHex: hx(testK[:]),
	}
	base := append([]byte{0x01}, testK[:]...)
	base = append(base, bs(28, 0x40)...)
	add := func(name, kind string, v stmtVector, payload []byte, addr []byte, form string) {
		prot := cose.ProtectedHeader(addr)
		ss := cose.SigStructure(prot, payload)
		sig := ed25519.Sign(testPriv, ss)
		s1 := cose.Sign1{Protected: prot, Payload: payload, Signature: sig}.Encode()
		st, err := relaybind.ParseStatement(s1)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v.Name, v.Kind, v.Payload, v.PayloadHex = name, kind, string(payload), hx(payload)
		v.AddressForm, v.AddressHex, v.ProtectedHex = form, hx(addr), hx(prot)
		v.SigStructureHex, v.SignatureHex, v.Sign1Hex = hx(ss), hx(sig), hx(s1)
		h := st.FullHash()
		v.CanonicalHashHex, v.CoseKeyHex = hx(h[:]), hx(cose.EncodeKey(testPub[:]))
		var id [32]byte
		if kind == "binding" {
			vb, err := relaybind.VerifyBinding(st, testPub, v.deviceFP(t), v.From, relaybind.DefaultPolicy())
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			id = vb.StatementID()
		} else {
			vr, err := relaybind.VerifyRevoke(st, testPub, v.NotBefore, relaybind.DefaultPolicy())
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			id = vr.StatementID()
		}
		v.StatementIDHex = hx(id[:])
		vf.Statements = append(vf.Statements, v)
	}
	bind := func(name string, dev party.Fingerprint, from, until int64, addr []byte, form string) {
		p, err := relaybind.Binding{Device: dev, From: from, Until: until}.Render()
		if err != nil {
			t.Fatal(err)
		}
		add(name, "binding", stmtVector{Device: hx(dev[:]), From: from, Until: until}, p, addr, form)
	}
	bind("typical", testDev, fromT, untilT, testK[:], "key-hash")
	bind("shortest lifetime, from zero", fpOf(0), 0, relaybind.MinLifetimeSeconds, testK[:], "key-hash")
	bind("longest lifetime", fpOf(0xe0), 1700000000, 1700000000+relaybind.MaxLifetimeSeconds, testK[:], "key-hash")
	bind("until at the largest time", fpOf(0x10), relaybind.MaxTime-relaybind.MinLifetimeSeconds, relaybind.MaxTime, testK[:], "key-hash")
	bind("Shelley base address", testDev, fromT, untilT, base, "base-address")
	rev := func(name string, r relaybind.Revoke, addr []byte, form string) {
		p, err := r.Render()
		if err != nil {
			t.Fatal(err)
		}
		v := stmtVector{All: r.All, NotBefore: r.NotBefore}
		if !r.All {
			v.Device = hx(r.Device[:])
		}
		add(name, "revoke", v, p, addr, form)
	}
	rev("revoke one device", relaybind.Revoke{Device: testDev, NotBefore: nowT}, testK[:], "key-hash")
	rev("revoke all devices", relaybind.Revoke{All: true, NotBefore: nowT}, testK[:], "key-hash")
	rev("revoke all, not-before zero", relaybind.Revoke{All: true, NotBefore: 0}, base, "base-address")

	x := bs(32, 0x50)
	for _, c := range []struct {
		name string
		nb   int64
	}{{"device revoke", nowT}, {"device revoke, not-before zero", 0}} {
		var ed party.Ed25519Public = party.Ed25519Public(testPub)
		var xp party.X25519Public
		copy(xp[:], x)
		dev := party.FingerprintOf(ed, xp)
		b, err := relaybind.DeviceRevokeBytes(dev, c.nb)
		if err != nil {
			t.Fatal(err)
		}
		vf.DeviceRevokes = append(vf.DeviceRevokes, deviceRevokeVector{
			Name: c.name, Ed25519Seed: hx(bs(32, 7)), Ed25519: hx(testPub[:]), X25519: hx(x), Fingerprint: hx(dev[:]),
			NotBefore: c.nb, BytesHex: hx(b), SignatureHex: hx(ed25519.Sign(testPriv, b)),
		})
	}
	vf.NearMisses = nearMisses()
	for _, name := range sortedNames(smallOrderEncodings()) {
		vf.RejectedKeys = append(vf.RejectedKeys, rejectedKey{Name: name, Hex: hx(smallOrderEncodings()[name])})
	}
	for _, name := range sortedNames(nonCanonicalEncodings()) {
		vf.RejectedKeys = append(vf.RejectedKeys, rejectedKey{Name: name, Hex: hx(nonCanonicalEncodings()[name])})
	}
	out, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// spec: SPO-Xrelaybind-OUT-008
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

// The committed file is checked on its own: every statement parses strictly, is
// its own canonical form, verifies, and the near misses are refused.
//
// spec: SPO-Xrelaybind-OUT-008
func TestCommittedVectorsStandAlone(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Statements) < 8 || len(vf.DeviceRevokes) < 2 || len(vf.NearMisses) < 10 {
		t.Fatalf("too few vectors: %d, %d, %d", len(vf.Statements), len(vf.DeviceRevokes), len(vf.NearMisses))
	}
	var pub [32]byte
	copy(pub[:], unhex(t, vf.PublicHex))
	for _, v := range vf.Statements {
		s1 := unhex(t, v.Sign1Hex)
		st, err := relaybind.ParseStatement(s1)
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if !bytes.Equal(st.Canonical(), s1) || hx(st.Payload()) != v.PayloadHex || hx(st.Protected()) != v.ProtectedHex {
			t.Errorf("%s: the parts do not match", v.Name)
		}
		if h := st.FullHash(); hx(h[:]) != v.CanonicalHashHex {
			t.Errorf("%s: hash", v.Name)
		}
		if k, err := relaybind.ParseCOSEKey(unhex(t, v.CoseKeyHex)); err != nil || k != pub {
			t.Errorf("%s: COSE_Key %v", v.Name, err)
		}
		if got := hx(cose.SigStructure(st.Protected(), st.Payload())); got != v.SigStructureHex {
			t.Errorf("%s: Sig_structure", v.Name)
		}
		switch v.Kind {
		case "binding":
			b, err := relaybind.ParseBinding(st.Payload())
			if err != nil || b.From != v.From || b.Until != v.Until || hx(b.Device[:]) != v.Device {
				t.Errorf("%s: %+v %v", v.Name, b, err)
				continue
			}
			vb, err := relaybind.VerifyBinding(st, pub, b.Device, b.From+10, relaybind.DefaultPolicy())
			if err != nil || vb.Key() != testK || hx(idSlice(vb.StatementID())) != v.StatementIDHex {
				t.Errorf("%s: %v", v.Name, err)
			}
		case "revoke":
			r, err := relaybind.ParseRevoke(st.Payload())
			if err != nil || r.All != v.All || r.NotBefore != v.NotBefore {
				t.Errorf("%s: %+v %v", v.Name, r, err)
				continue
			}
			if _, err := relaybind.VerifyRevoke(st, pub, v.NotBefore, relaybind.DefaultPolicy()); err != nil {
				t.Errorf("%s: %v", v.Name, err)
			}
		default:
			t.Errorf("%s: kind %q", v.Name, v.Kind)
		}
	}
	for _, d := range vf.DeviceRevokes {
		var ed party.Ed25519Public
		var x party.X25519Public
		var sig [64]byte
		copy(ed[:], unhex(t, d.Ed25519))
		copy(x[:], unhex(t, d.X25519))
		copy(sig[:], unhex(t, d.SignatureHex))
		fp, err := verifyDevRevoke(ed, x, d.NotBefore, sig, d.NotBefore, relaybind.SkewSeconds)
		if err != nil || hx(fp[:]) != d.Fingerprint {
			t.Errorf("%s: %v", d.Name, err)
		}
		var dev party.Fingerprint
		copy(dev[:], unhex(t, d.Fingerprint))
		if b, err := relaybind.DeviceRevokeBytes(dev, d.NotBefore); err != nil || hx(b) != d.BytesHex {
			t.Errorf("%s: bytes %v", d.Name, err)
		}
	}
	for _, k := range vf.RejectedKeys {
		if _, err := relaybind.ParseCOSEKey(cose.EncodeKey(unhex(t, k.Hex))); !errors.Is(err, relaybind.ErrWeakKey) {
			t.Errorf("rejected key %s: %v, want ErrWeakKey", k.Name, err)
		}
	}
	if len(vf.RejectedKeys) < 10 {
		t.Errorf("only %d rejected keys", len(vf.RejectedKeys))
	}
	for _, p := range vf.NearMisses {
		_, e1 := relaybind.ParseBinding([]byte(p))
		_, e2 := relaybind.ParseRevoke([]byte(p))
		if e1 == nil || e2 == nil {
			t.Errorf("near miss %q accepted (binding %v, revoke %v)", p, e1, e2)
		}
	}
}

// The independent check of the vectors, when a Python interpreter is present.
// Where the check must run, SPO_REQUIRE_PYTHON=1 makes a missing interpreter a
// failure. tools/spo.nix sets it (and adds python3 to nativeCheckInputs), so
// `nix flake check` always runs it; on a development machine without python3
// the test skips.
//
// spec: SPO-Xrelaybind-OUT-008
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
