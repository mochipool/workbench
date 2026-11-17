package hwcli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

func envelopeOf(t *testing.T, b []byte) pool.Envelope {
	t.Helper()
	e, err := pool.ParseEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// spec: SPO-03a-EXT-004, SPO-03a-INV-001, SPO-Pfiles-OUT-004, SPO-Pfiles-INV-002
// Exercised, still waived until a use case enables the hardware path: SPO-02-EXT-003, SPO-02-OUT-002, SPO-03a-EXT-002, SPO-03a-OUT-001, SPO-Pfiles-INV-001
func TestExportWritesTheKeyAndSigningFileWithTheHardwareMarkers(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	cases := []struct {
		role         custody.Role
		path         string
		typ, desc    string // wanted of the verification key; "" = as the tool wrote it
		hwsType      string
		hwsDesc      string
		wantSubcmd   []string
		ownerForFile string
	}{
		{role: custody.RolePayment, path: "1852H/1815H/0H/0/0", desc: "Payment Hardware Verification Key", wantSubcmd: []string{"address", "key-gen"}},
		{role: custody.RolePayment, path: "1854H/1815H/1H/0/3", desc: "Payment Hardware Verification Key", wantSubcmd: []string{"address", "key-gen"}},
		{role: custody.RoleStake, path: "1852H/1815H/0H/2/0", desc: "Stake Hardware Verification Key", wantSubcmd: []string{"address", "key-gen"}},
		{role: custody.RolePolicy, path: "1855H/1815H/0H", desc: "Mint Hardware Verification Key", wantSubcmd: []string{"address", "key-gen"}},
		{role: custody.RoleDRep, path: "1852H/1815H/0H/3/0", typ: "DRepVerificationKey_ed25519", desc: "Hardware Delegate Representative Verification Key", wantSubcmd: []string{"address", "key-gen"}},
		{role: custody.RoleCommitteeCold, path: "1852H/1815H/0H/4/0", typ: "PaymentVerificationKeyShelley_ed25519", desc: "Payment Verification Key", wantSubcmd: []string{"address", "key-gen"}}, // SPO-23a-OUT-003: left as the tool wrote it
		{role: custody.RoleCommitteeHot, path: "1852H/1815H/0H/5/0", typ: "ConstitutionalCommitteeHotVerificationKey_ed25519", desc: "Payment Verification Key", hwsType: "ConstitutionalCommitteeHotHWSigningFile_ed25519", wantSubcmd: []string{"address", "key-gen"}},
		{role: custody.RolePoolCold, path: "1853H/1815H/0H/0H", typ: "StakePoolVerificationKey_ed25519", desc: "Stake Pool Operator Verification Key", wantSubcmd: []string{"node", "key-gen"}},
	}
	for _, c := range cases {
		hk, err := s.ExportHardwareKey(context.Background(), hwKey(c.role, "o"), c.path)
		if err != nil {
			t.Errorf("%s: %v", c.role, err)
			continue
		}
		e := envelopeOf(t, hk.VKey)
		if c.typ != "" && e.Type != c.typ {
			t.Errorf("%s: vkey type %q", c.role, e.Type)
		}
		if e.Description != c.desc {
			t.Errorf("%s: vkey description %q, want %q", c.role, e.Description, c.desc)
		}
		_, pub := fakeKey(c.path)
		if raw, _ := e.Key32(); !bytes.Equal(raw, pub) {
			t.Errorf("%s: the verification key is not the device's key for the path", c.role)
		}
		if got, ok := pubOfHws(hk.SigningFile); !ok || !bytes.Equal(got, pub) {
			t.Errorf("%s: signing file", c.role)
		}
		if c.hwsType != "" && !strings.Contains(string(hk.SigningFile), c.hwsType) {
			t.Errorf("%s: signing file type not rewritten: %s", c.role, hk.SigningFile)
		}
		if strings.Contains(string(hk.SigningFile), "skey") || strings.Contains(string(hk.VKey), "skey") {
			t.Errorf("%s: a signing key appears", c.role)
		}
		argv := r.lastCall(c.wantSubcmd...)
		if got := flagValues(argv, "--path"); len(got) != 1 || got[0] != c.path {
			t.Errorf("%s: argv %v", c.role, argv)
		}
		if c.role == custody.RolePoolCold && len(flagValues(argv, "--operational-certificate-issue-counter-file")) != 1 {
			t.Errorf("node key-gen argv %v", argv)
		}
	}
	// The catalyst voting key needs the 6.0.3 Ledger app: the 8.0.8 session has it.
	hk, err := s.ExportHardwareKey(context.Background(), hwKey(custody.RoleCatalystVote, "v"), "1694H/1815H/0H/0/0")
	if err != nil {
		t.Fatal(err)
	}
	if e := envelopeOf(t, hk.VKey); e.Description != "Hardware Catalyst Vote Verification Key" {
		t.Errorf("voting vkey %+v", e)
	}
	if !strings.Contains(string(hk.SigningFile), "Hardware Catalyst Vote Signing File") {
		t.Errorf("voting signing file %s", hk.SigningFile)
	}
}

func pubOfHws(b []byte) ([]byte, bool) {
	i := strings.Index(string(b), `"cborXPubKeyHex": "5840`)
	if i < 0 {
		return nil, false
	}
	raw, err := hex.DecodeString(string(b[i+len(`"cborXPubKeyHex": "5840`) : i+len(`"cborXPubKeyHex": "5840`)+64]))
	return raw, err == nil
}

// spec: SPO-Chw-PRE-003
// Exercised, still waived until a use case enables the hardware path: SPO-04a-EXT-003, SPO-04a-EXT-004, SPO-04a-INV-002, SPO-10-EXT-002, SPO-21a-PRE-011, SPO-23a-PRE-008, SPO-23b-PRE-007
func TestExportIsRefusedWhereTheVendorOrTheSpecsDoNotAllowIt(t *testing.T) {
	r := newRig(t, "Trezor", "2.7.2")
	s := r.open()
	for _, c := range []struct {
		role custody.Role
		path string
	}{
		{custody.RolePoolCold, "1853H/1815H/0H/0H"},
		{custody.RoleDRep, "1852H/1815H/0H/3/0"},
		{custody.RoleCommitteeCold, "1852H/1815H/0H/4/0"},
		{custody.RoleCommitteeHot, "1852H/1815H/0H/5/0"},
		{custody.RoleCatalystVote, "1694H/1815H/0H/0/0"},
		{custody.RoleCalidus, "1852H/1815H/0H/0/0"}, // SPO-15-PRE-002: suspended
		{custody.RoleKES, "1/2"},
	} {
		if _, err := s.ExportHardwareKey(context.Background(), hwKey(c.role, "o"), c.path); !errors.Is(err, hwcli.ErrNotSupported) {
			t.Errorf("Trezor %s: %v", c.role, err)
		}
	}
	// The same on a Ledger or Keystone for the keys they have.
	for _, v := range [][2]string{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		s2 := newRig(t, v[0], v[1]).open()
		if _, err := s2.ExportHardwareKey(context.Background(), hwKey(custody.RoleDRep, "d"), "1852H/1815H/0H/3/0"); err != nil {
			t.Errorf("%s drep: %v", v[0], err)
		}
		if _, err := s2.ExportHardwareKey(context.Background(), hwKey(custody.RolePayment, "d"), "not a path"); err == nil {
			t.Errorf("%s: a bad path was accepted", v[0])
		}
	}
	if calls := r.calls(); len(calls) != 1 { // only `device version`
		t.Errorf("a refused export started the tool: %v", calls)
	}
	// Paths are the specs'.
	for _, c := range []struct {
		role     custody.Role
		acc, idx uint32
		multi    bool
		want     string
	}{
		{custody.RolePayment, 1, 7, false, "1852H/1815H/1H/0/7"},
		{custody.RolePayment, 0, 0, true, "1854H/1815H/0H/0/0"},
		{custody.RoleStake, 2, 9, false, "1852H/1815H/2H/2/0"},
		{custody.RolePoolCold, 5, 3, false, "1853H/1815H/0H/3H"},
		{custody.RoleDRep, 0, 1, false, "1852H/1815H/0H/3/1"},
		{custody.RoleCommitteeCold, 0, 1, false, "1852H/1815H/0H/4/1"},
		{custody.RoleCommitteeHot, 0, 1, false, "1852H/1815H/0H/5/1"},
		{custody.RolePolicy, 3, 3, false, "1855H/1815H/0H"},
		{custody.RoleCatalystVote, 0, 0, false, "1694H/1815H/0H/0/0"},
	} {
		got, err := custody.HardwarePath(c.role, c.acc, c.idx, c.multi)
		if err != nil || got != c.want {
			t.Errorf("%s: %q %v, want %q", c.role, got, err, c.want)
		}
	}
	if _, err := custody.HardwarePath(custody.RoleCalidus, 0, 0, false); err == nil {
		t.Error("a Calidus hardware path exists")
	}
}

// spec: SPO-04d-OUT-002
// Exercised, still waived until a use case enables the hardware path: SPO-04d-EXT-004, SPO-04d-PR-003, SPO-04a-EXT-004
//
// The certificate is checked against the vault signer's: for the same cold key
// and request the bytes are equal, and the counter the tool advanced is never
// read back.
func TestIssueOpCertMatchesTheVaultSigner(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	const path = "1853H/1815H/0H/0H"
	r.export(s, custody.RolePoolCold, "mypool", path)
	kes := bytes.Repeat([]byte{0x42}, 32)
	cold, _ := custody.As[custody.PoolCold](hwKey(custody.RolePoolCold, "mypool"))

	got, err := s.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: kes, Counter: 7, KesPeriod: 300})
	if err != nil {
		t.Fatal(err)
	}
	vault := vaultWithSeed(t, "mypool.node.skey", "StakePoolSigningKey_ed25519", fakeSeed(path))
	want, err := native.VaultSigner{Vault: vault}.IssueOpCert(context.Background(),
		cold,
		ports.OpCertRequest{KesVKey: kes, Counter: 7, KesPeriod: 300})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the hardware certificate differs from the vault's:\n%s\n%s", got, want)
	}
	oc, err := pool.ParseOpCert(got)
	if err != nil || oc.Counter != 7 || oc.KesPeriod != 300 {
		t.Errorf("%+v %v", oc, err)
	}
	// The tool is given a private copy of the counter: argv names a path inside the private directory, gone afterwards.
	argv := r.lastCall("node", "issue-op-cert")
	ctr := flagValues(argv, "--operational-certificate-issue-counter-file")
	if len(ctr) != 1 || !strings.HasPrefix(ctr[0], r.tempRoot) {
		t.Fatalf("argv %v", argv)
	}
	if _, err := os.Stat(ctr[0]); !os.IsNotExist(err) {
		t.Error("the counter copy survived")
	}
	// A second issue with another counter gives another certificate: nothing carries over.
	got2, err := s.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: kes, Counter: 7, KesPeriod: 300})
	if err != nil || !bytes.Equal(got, got2) {
		t.Errorf("an issue with the same counter is not repeatable: %v", err)
	}

	// A failed issue returns nothing.
	r.fake.Action = "rejected"
	r.writeFake()
	if out, err := s.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: kes, Counter: 8, KesPeriod: 300}); !errors.Is(err, hwcli.ErrRejected) || out != nil {
		t.Errorf("rejected: %v %v", out, err)
	}
	// Refused for a Trezor.
	tr := newRig(t, "Trezor", "2.7.2").open()
	if _, err := tr.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: kes}); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("trezor: %v", err)
	}
	if _, err := s.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: kes[:5]}); err == nil {
		t.Error("a short KES key was accepted")
	}
}

func mustAs[R custody.RoleMarker](t *testing.T, ref custody.KeyRef) custody.Key[R] {
	t.Helper()
	k, err := custody.As[R](ref)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// spec: SPO-Pfiles-INV-002
// Exercised, still waived until a use case enables the hardware path: SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-01sendLovelaces-EXT-002
func TestWitnessMatchesTheVaultSignerAndDeclaresTheChangeKeys(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	const payPath, stakePath = "1852H/1815H/0H/0/0", "1852H/1815H/0H/2/0"
	r.export(s, custody.RolePayment, "w", payPath)
	r.export(s, custody.RoleStake, "w", stakePath)
	body := realBody(t, "a canonical transaction body")

	pay := hwKey(custody.RolePayment, "w")
	w, err := s.Witness(context.Background(), pay, body)
	if err != nil {
		t.Fatal(err)
	}
	vault := vaultWithSeed(t, "w.skey", "PaymentSigningKeyShelley_ed25519", fakeSeed(payPath))
	want, err := native.VaultSigner{Vault: vault}.Witness(context.Background(), pay, body)
	if err != nil {
		t.Fatal(err)
	}
	if w != want {
		t.Error("the hardware witness differs from the vault signer's")
	}
	if err := txbuild.VerifyWitness(body, w, txbuild.HashKey(w.VKey[:])); err != nil {
		t.Error(err)
	}
	argv := r.lastCall("transaction", "witness")
	if len(flagValues(argv, "--hw-signing-file")) != 1 || len(flagValues(argv, "--change-output-key-file")) != 0 || len(flagValues(argv, "--testnet-magic")) != 1 {
		t.Errorf("argv %v", argv)
	}
	if strings.Contains(strings.Join(argv, " "), "--allow-unrestricted-mode") {
		t.Error("unrestricted mode was implied")
	}

	// The change output keys are declared (SPO-Ptx-INV-009).
	if _, err := s.WitnessWith(context.Background(), pay, body, ports.HardwareTxOptions{ChangeKeys: []custody.KeyRef{pay, hwKey(custody.RoleStake, "w")}}); err != nil {
		t.Fatal(err)
	}
	if got := flagValues(r.lastCall("transaction", "witness"), "--change-output-key-file"); len(got) != 2 {
		t.Errorf("change keys %v", got)
	}

	// On mainnet the flag is --mainnet.
	rm := newRig(t, "Ledger", "8.0.8", func(_ *fakeCfg, c *hwcli.Config) { c.Network = hwcli.Network{Mainnet: true} })
	sm := rm.open()
	rm.export(sm, custody.RolePayment, "w", payPath)
	if _, err := sm.Witness(context.Background(), pay, body); err != nil {
		t.Fatal(err)
	}
	if a := rm.lastCall("transaction", "witness"); !contains(a, "--mainnet") || contains(a, "--testnet-magic") {
		t.Errorf("mainnet argv %v", a)
	}

	// A body whose id is not the id of its bytes is refused before the device is asked.
	bad := body
	bad.ID[0] ^= 1
	before := r.called("transaction", "witness")
	if _, err := s.Witness(context.Background(), pay, bad); err == nil || r.called("transaction", "witness") != before {
		t.Errorf("bad id: %v", err)
	}
	// A key the device does not hold the file of.
	if _, err := s.Witness(context.Background(), hwKey(custody.RolePayment, "nobody"), body); err == nil {
		t.Error("a missing signing file was accepted")
	}
	// Refused for a role the device has no witness for.
	if _, err := s.Witness(context.Background(), hwKey(custody.RoleKES, "k"), body); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("kes: %v", err)
	}
}

// policyScript is a native script by one key hash.
var policyScript = []byte(`{"type":"sig","keyHash":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"}`)

func contains(a []string, w string) bool {
	for _, x := range a {
		if x == w {
			return true
		}
	}
	return false
}

// spec: SPO-Ctx-EXT-001, SPO-Ctx-IF-001, SPO-Ctx-PRE-003, SPO-Ctx-PRE-004, SPO-Ctx-OUT-001, SPO-Ctx-OUT-002, SPO-Ctx-OUT-004, SPO-Ctx-IF-002, SPO-Xparty-INV-012
// Exercised, still waived until a use case enables the hardware path: SPO-Ptx-EXT-005
//
// Decision (M4): a transformed body has another id, so the adapter does not
// witness a changed body in place. It refuses with the canonical bytes, and
// Canonicalize is what a use case calls before the body is fixed.
func TestANonCanonicalBodyIsRefusedAndCanonicalizeFixesItBeforeSigning(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	const payPath = "1852H/1815H/0H/0/0"
	r.export(s, custody.RolePayment, "w", payPath)
	pay := hwKey(custody.RolePayment, "w")

	marked := legacyBody(t, "marked")
	want := realBody(t, "marked") // the same body with the inputs as a tag-258 set
	_, err := s.Witness(context.Background(), pay, marked)
	var nc *ports.ErrNotHardwareCanonical
	if !errors.As(err, &nc) {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(nc.Canonical, want.CBOR) {
		t.Errorf("canonical bytes %x", nc.Canonical)
	}
	if r.called("transaction", "witness") != 0 {
		t.Error("the device was asked to witness a body that is not canonical")
	}

	canon, changed, err := s.Canonicalize(context.Background(), marked, ports.HardwareTxOptions{})
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if !bytes.Equal(canon.CBOR, want.CBOR) || canon.ID == marked.ID || canon.ID != want.ID {
		t.Errorf("canonical body %x id unchanged=%v", canon.CBOR, canon.ID == marked.ID)
	}
	// With no option, transform runs without the unrestricted flag (the variant of SPO-Ctx-IF-002).
	if a := r.lastCall("transaction", "transform"); contains(a, "--allow-unrestricted-mode") || len(flagValues(a, "--tx-file")) != 1 || len(flagValues(a, "--out-file")) != 1 {
		t.Errorf("transform argv %v", a)
	}
	// Canonicalising a canonical body changes nothing.
	again, changed, err := s.Canonicalize(context.Background(), canon, ports.HardwareTxOptions{})
	if err != nil || changed || again.ID != canon.ID {
		t.Errorf("%v %v", changed, err)
	}
	// The canonical body can be witnessed, and the witness is over the new id.
	w, err := s.Witness(context.Background(), pay, canon)
	if err != nil {
		t.Fatal(err)
	}
	if err := txbuild.VerifyWitness(canon, w, txbuild.HashKey(w.VKey[:])); err != nil {
		t.Error(err)
	}
	if txbuild.VerifyWitness(marked, w, txbuild.HashKey(w.VKey[:])) == nil {
		t.Error("the witness also verifies over the old id")
	}

	// Canonicalising needs no device: a failing transform is the typed error.
	r.fake.Action = "ok"
	rr := newRig(t, "Ledger", "8.0.8")
	s2 := rr.open()
	rr.fake.Action = "error"
	rr.writeFake()
	// transform does not gate on the action, so ask for the unrestricted-only body.
	needs := unrestrictedBody(t)
	if _, _, err := s2.Canonicalize(context.Background(), needs, ports.HardwareTxOptions{}); !errors.Is(err, hwcli.ErrExpertModeRequired) {
		t.Errorf("SECURITY from transform: %v", err)
	}
	if _, _, err := s2.Canonicalize(context.Background(), needs, ports.HardwareTxOptions{Unrestricted: true}); err != nil {
		t.Errorf("unrestricted: %v", err)
	}
}

// spec: SPO-Ctx-IN-001, SPO-Ctx-IN-002, SPO-Ctx-PRE-005
func TestATransformThatBreaksTheAuxiliaryDataHashIsRefused(t *testing.T) {
	// A real body with metadata, which a (misbehaving) transform re-serialises
	// without the hash the body carries of it.
	r := newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, _ *hwcli.Config) { f.Misbehave = "stale-aux" })
	s := r.open()
	if _, _, err := s.Canonicalize(context.Background(), legacyBody(t, "metadata"), ports.HardwareTxOptions{}); !errors.Is(err, hwcli.ErrAuxDataHashStale) {
		t.Errorf("%v", err)
	}
	// With no auxiliary data nothing is stale, as upstream: only the inputs change.
	ok := newRig(t, "Ledger", "8.0.8").open()
	canon, changed, err := ok.Canonicalize(context.Background(), legacyBody(t), ports.HardwareTxOptions{})
	if err != nil || !changed || canon.ID != realBody(t).ID {
		t.Errorf("%v %v", changed, err)
	}
}

// spec: SPO-Chw-INV-002
// Exercised, still waived until a use case enables the hardware path: SPO-Ptx-PRE-005, SPO-21b-PRE-009
func TestDeviceOutputIsClassifiedAsTheSpecsSay(t *testing.T) {
	var warned []string
	r := newRig(t, "Ledger", "8.0.8", func(_ *fakeCfg, c *hwcli.Config) { c.OnWarning = func(s string) { warned = append(warned, s) } })
	s := r.open()
	r.export(s, custody.RolePayment, "w", "1852H/1815H/0H/0/0")
	body := realBody(t)
	pay := hwKey(custody.RolePayment, "w")
	for action, want := range map[string]error{
		"rejected":   hwcli.ErrRejected,
		"disconnect": hwcli.ErrDisconnected,
		"error":      hwcli.ErrDeviceError,
		"errorzero":  hwcli.ErrDeviceError, // ERROR with exit 0 is still a failure (SPO-Ctx-PRE-004)
		"warning":    nil,                  // WARNING continues
	} {
		r.fake.Action = action
		r.writeFake()
		_, err := s.Witness(context.Background(), pay, body)
		if want == nil {
			if err != nil {
				t.Errorf("%s: %v", action, err)
			}
			continue
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v", action, err)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "WARNING") {
		t.Errorf("warnings %v", warned)
	}
}

// spec: SPO-21b-INV-006
// Exercised, still waived until a use case enables the hardware path: SPO-21b-PR-001, SPO-21b-SEC-003, SPO-21b-PRE-009, SPO-24b-PR-001, SPO-Ptx-PR-001
func TestUnrestrictedModeIsNeverImplied(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	r.export(s, custody.RolePayment, "w", "1852H/1815H/0H/0/0")
	pay := hwKey(custody.RolePayment, "w")
	needs := unrestrictedBody(t)

	// Without the option the device refuses and the flag is not on any command line.
	if _, err := s.Witness(context.Background(), pay, needs); !errors.Is(err, hwcli.ErrExpertModeRequired) {
		t.Errorf("%v", err)
	}
	for _, c := range r.calls() {
		if contains(c, "--allow-unrestricted-mode") {
			t.Errorf("implied: %v", c)
		}
	}
	// With the explicit option the flag goes to transform and to witness.
	if _, err := s.WitnessWith(context.Background(), pay, needs, ports.HardwareTxOptions{Unrestricted: true}); err != nil {
		t.Fatal(err)
	}
	if !contains(r.lastCall("transaction", "witness"), "--allow-unrestricted-mode") || !contains(r.lastCall("transaction", "transform"), "--allow-unrestricted-mode") {
		t.Error("the explicit option did not reach the tool")
	}
	// The profile models it as a separate feature: a Keystone, and a Ledger below 8.0.0, do not have it.
	ks := newRig(t, "Keystone", "1.7.7").open()
	if got := ks.Profile().Check(custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx, Features: custody.NewFeatures(custody.FeatUnrestricted)}); got == "" {
		t.Error("a Keystone has unrestricted mode")
	}
	if _, err := ks.WitnessWith(context.Background(), pay, needs, ports.HardwareTxOptions{Unrestricted: true}); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("keystone: %v", err)
	}
	old := newRig(t, "Ledger", "7.9.9", func(_ *fakeCfg, c *hwcli.Config) { c.MinLedger = "6.0.3" }).open()
	if got := old.Profile().Check(custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx, Features: custody.NewFeatures(custody.FeatUnrestricted)}); got == "" {
		t.Error("a Ledger app 7.9.9 has unrestricted mode")
	}
	if got := s.Profile().Check(custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx, Features: custody.NewFeatures(custody.FeatMetadata)}); got != "" {
		t.Errorf("a plain demand is refused: %s", got)
	}
}

// spec: SPO-15-EXT-005, SPO-Xidentity-SEC-003
// Exercised, still waived until a use case enables the hardware path: SPO-15-EXT-004, SPO-15-PR-001, SPO-10-EXT-005
func TestMessageSigningAndPolicyIDThroughTheDevice(t *testing.T) {
	r := newRig(t, "Keystone", "1.7.7")
	s := r.open()
	const path = "1853H/1815H/0H/0H"
	r.export(s, custody.RolePoolCold, "mypool", path)
	payload := bytes.Repeat([]byte{7}, 32)
	got, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: hwKey(custody.RolePoolCold, "mypool"), Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	_, pub := fakeKey(path)
	if !bytes.HasSuffix(got.Key, pub) {
		t.Error("the COSE key is not the device key")
	}
	if v, err := cose.VerifyCip8(got.Sign1, got.Key, payload, true); err != nil || !bytes.Equal(v.Payload, payload) {
		t.Errorf("the signed message does not verify: %v", err)
	}
	argv := r.lastCall("message", "sign")
	if len(flagValues(argv, "--message-hex")) != 1 || contains(argv, "--hashed") {
		t.Errorf("argv %v", argv)
	}
	if _, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: hwKey(custody.RolePoolCold, "mypool"), Payload: payload, Address: []byte{1}}); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("raw address: %v", err)
	}
	if _, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: hwKey(custody.RolePayment, "w"), Payload: payload}); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("payment message: %v", err)
	}

	// Policy id: the policy key at 1855H/1815H/0H.
	r.export(s, custody.RolePolicy, "pol", "1855H/1815H/0H")
	id, err := s.PolicyID(context.Background(), mustAs[custody.Policy](t, hwKey(custody.RolePolicy, "pol")), policyScript)
	if err != nil || len(id) != 56 {
		t.Errorf("%q %v", id, err)
	}
	if _, err := s.PolicyID(context.Background(), mustAs[custody.Policy](t, hwKey(custody.RolePolicy, "pol")), policyScript); err != nil {
		t.Error(err)
	}
}

// spec: SPO-09a-EXT-004, SPO-09a-INV-004, SPO-09a-INV-005
func TestCip36RegistrationSignedOnTheDevice(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	const stakePath = "1852H/1815H/0H/2/0"
	r.export(s, custody.RoleStake, "w", stakePath)
	_, pub := fakeKey(stakePath)
	var reg cose.Cip36
	copy(reg.StakePub[:], pub)
	reg.Delegations = []cose.Delegation{{Weight: 3}, {Weight: 1}}
	reg.Delegations[0].VotePub[0], reg.Delegations[1].VotePub[0] = 9, 10
	reg.Address = append([]byte{0x00}, bytes.Repeat([]byte{5}, 56)...) // testnet base address
	reg.Nonce, reg.Purpose = 12345, 0

	got, err := s.SignCip36(context.Background(), mustAs[custody.Stake](t, hwKey(custody.RoleStake, "w")), reg)
	if err != nil {
		t.Fatal(err)
	}
	sig := got.CBOR[len(got.CBOR)-64:]
	h := reg.SigningHash()
	if !ed25519.Verify(pub, h[:], sig) || !bytes.Equal(got.CBOR, reg.Metadata(sig)) || got.JSON != reg.MetadataJSON(sig) {
		t.Error("the registration is not the one asked for")
	}
	argv := r.lastCall("vote", "registration-metadata")
	if len(flagValues(argv, "--vote-public-key-string")) != 2 || len(flagValues(argv, "--vote-weight")) != 2 || flagValues(argv, "--nonce")[0] != "12345" {
		t.Errorf("argv %v", argv)
	}
	if a := flagValues(argv, "--payment-address")[0]; !strings.HasPrefix(a, "addr_test1") {
		t.Errorf("address %q", a)
	}
	if _, data, err := chain.Bech32Decode(flagValues(argv, "--vote-public-key-string")[0]); err != nil || len(data) != 32 {
		t.Error("vote key")
	}
	// The key must be the registration's stake key.
	other := reg
	other.StakePub[0] ^= 1
	if _, err := s.SignCip36(context.Background(), mustAs[custody.Stake](t, hwKey(custody.RoleStake, "w")), other); err == nil {
		t.Error("another stake key accepted")
	}
	// Ledger only: a Keystone refuses.
	if _, err := newRig(t, "Keystone", "1.7.7").open().SignCip36(context.Background(), mustAs[custody.Stake](t, hwKey(custody.RoleStake, "w")), reg); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("keystone: %v", err)
	}
}

// spec: SPO-Pfiles-OUT-004, SPO-Pfiles-INV-002
func TestSigningFilesComeFromTheStoreNotFromAnOperatorPath(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	hk := r.export(s, custody.RolePoolCold, "mypool", "1853H/1815H/0H/0H")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mypool.node.hwsfile"), hk.SigningFile, 0o400); err != nil {
		t.Fatal(err)
	}
	// the verification key beside it: the file is found by the key's identity
	if err := os.WriteFile(filepath.Join(dir, "mypool.node.vkey"), hk.VKey, 0o400); err != nil {
		t.Fatal(err)
	}
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.cfg.Files = hwcli.StoreFiles{Store: st}
	sess := r.open()
	cold := mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "mypool"))
	if _, err := sess.IssueOpCert(context.Background(), cold, ports.OpCertRequest{KesVKey: bytes.Repeat([]byte{1}, 32), Counter: 1, KesPeriod: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := (hwcli.StoreFiles{Store: st}).HardwareSigningFile(context.Background(), hwKey(custody.RoleKES, "x")); err == nil {
		t.Error("a KES key has a signing file")
	}
	if _, err := (hwcli.StoreFiles{Store: st}).HardwareSigningFile(context.Background(), hwKey(custody.RolePoolCold, "other")); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("%v", err)
	}
}

// poolRegistration is a Calidus registration of the pool cold key at path.
func poolRegistration(path string) cose.Cip88 {
	_, pub := fakeKey(path)
	reg := cose.Cip88{PoolID: cose.Blake2b224(pub), Nonce: 77}
	reg.CalidusPub[0] = 9
	return reg
}

// spec: SPO-15-EXT-004, SPO-15-EXT-005, SPO-15-INV-005, SPO-15-INV-006, SPO-15-OUT-003
// The registration is signed by the pool cold key on the device with the argument vector of the
// spec (`message sign --message-hex <blake2b-256 of the payload> --signing-path-hwsfile ... --out-file`,
// no --hashed), and the metadata verifies as a CIP-88 registration of this payload.
func TestCip88RegistrationSignedOnTheDevice(t *testing.T) {
	const path = "1853H/1815H/0H/0H"
	for _, v := range []struct{ vendor, app string }{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		r := newRig(t, v.vendor, v.app)
		s := r.open()
		r.export(s, custody.RolePoolCold, "mypool", path)
		reg := poolRegistration(path)
		got, err := s.SignCip88(context.Background(), mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "mypool")), reg)
		if err != nil {
			t.Fatalf("%s: %v", v.vendor, err)
		}
		if back, err := cose.VerifyCip88(got.CBOR); err != nil || back != reg {
			t.Errorf("%s: metadata does not verify as the registration: %v", v.vendor, err)
		}
		if !strings.Contains(got.JSON, `"867"`) || strings.Contains(got.JSON, `"hashed"`) {
			t.Errorf("json %s", got.JSON)
		}
		argv := r.lastCall("message", "sign")
		h := reg.PayloadHash()
		if flagValues(argv, "--message-hex")[0] != hex.EncodeToString(h[:]) || contains(argv, "--hashed") || len(flagValues(argv, "--signing-path-hwsfile")) != 1 || len(flagValues(argv, "--out-file")) != 1 {
			t.Errorf("argv %v", argv)
		}
	}
	// Trezor: refused by the profile, before the tool is called.
	r := newRig(t, "Trezor", "2.7.2")
	s := r.open()
	if _, err := s.SignCip88(context.Background(), mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "mypool")), poolRegistration(path)); !errors.Is(err, hwcli.ErrNotSupported) {
		t.Errorf("trezor: %v", err)
	}
	if r.called("message") != 0 {
		t.Error("the tool was called")
	}
	// Another pool's key: refused before the device is asked.
	r = newRig(t, "Ledger", "8.0.8")
	s = r.open()
	r.export(s, custody.RolePoolCold, "mypool", path)
	other := poolRegistration(path)
	other.PoolID[0] ^= 1
	if _, err := s.SignCip88(context.Background(), mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "mypool")), other); err == nil || r.called("message") != 0 {
		t.Errorf("another pool: %v (%d calls)", err, r.called("message"))
	}
}

// spec: SPO-15-EXT-005, SPO-Xidentity-SEC-003
// A tool that signs another payload, signs with another key, writes a bad
// signature, names another address or truncates its output is refused.
func TestCip88MisbehavingToolIsRefused(t *testing.T) {
	const path = "1853H/1815H/0H/0H"
	for _, m := range []string{"msgwrongpayload", "msgbadsig", "msgwrongkey", "msgaddr", "msgtruncated"} {
		r := newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, _ *hwcli.Config) {})
		s := r.open()
		r.export(s, custody.RolePoolCold, "mypool", path)
		r.fake.Misbehave = m
		r.writeFake()
		_, err := s.SignCip88(context.Background(), mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "mypool")), poolRegistration(path))
		if !errors.Is(err, hwcli.ErrBadDeviceOutput) {
			t.Errorf("%s: %v", m, err)
		}
	}
}

func stakeRegistration(path string) cose.Cip36 {
	_, pub := fakeKey(path)
	var reg cose.Cip36
	copy(reg.StakePub[:], pub)
	reg.Delegations = []cose.Delegation{{Weight: 1}}
	reg.Delegations[0].VotePub[0] = 9
	reg.Nonce = 99
	return reg
}

// spec: SPO-09a-EXT-004, SPO-09a-INV-004
// With the rewards key on the same device its signing file is passed as
// --payment-address-signing-key-hwsfile, once the adapter has checked that it is the payment
// credential of the rewards address; a key that is not, or a stake key, is refused before the device is asked.
func TestCip36RewardsKeyOnTheSameDevice(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	const stakePath, payPath = "1852H/1815H/0H/2/0", "1852H/1815H/0H/0/0"
	r.export(s, custody.RoleStake, "w", stakePath)
	r.export(s, custody.RolePayment, "w", payPath)
	_, paypub := fakeKey(payPath)
	h := cose.Blake2b224(paypub)
	reg := stakeRegistration(stakePath)
	reg.Address = append(append([]byte{0x00}, h[:]...), bytes.Repeat([]byte{5}, 28)...)
	stake := mustAs[custody.Stake](t, hwKey(custody.RoleStake, "w"))
	pay := hwKey(custody.RolePayment, "w")
	if _, err := s.SignCip36With(context.Background(), stake, reg, ports.Cip36HardwareOptions{RewardsKey: &pay}); err != nil {
		t.Fatal(err)
	}
	argv := r.lastCall("vote", "registration-metadata")
	if len(flagValues(argv, "--payment-address-signing-key-hwsfile")) != 1 {
		t.Errorf("argv %v", argv)
	}
	// Without the option the flag is absent.
	if _, err := s.SignCip36(context.Background(), stake, reg); err != nil {
		t.Fatal(err)
	}
	if argv := r.lastCall("vote", "registration-metadata"); len(flagValues(argv, "--payment-address-signing-key-hwsfile")) != 0 {
		t.Errorf("argv %v", argv)
	}
	// A payment key that is not the address's, and a stake key as rewards key.
	r.export(s, custody.RolePayment, "x", "1852H/1815H/0H/0/9")
	x := hwKey(custody.RolePayment, "x")
	n := r.called("vote")
	if _, err := s.SignCip36With(context.Background(), stake, reg, ports.Cip36HardwareOptions{RewardsKey: &x}); err == nil {
		t.Error("a foreign payment key accepted")
	}
	st := hwKey(custody.RoleStake, "w")
	if _, err := s.SignCip36With(context.Background(), stake, reg, ports.Cip36HardwareOptions{RewardsKey: &st}); err == nil {
		t.Error("a stake key accepted as rewards key")
	}
	if r.called("vote") != n {
		t.Error("the device was asked")
	}
}

// spec: SPO-09a-EXT-004, SPO-Xidentity-SEC-003
func TestCip36MisbehavingToolIsRefused(t *testing.T) {
	const stakePath = "1852H/1815H/0H/2/0"
	for _, m := range []string{"votewrongkey", "votebadsig", "votewrongaddr", "votetruncated"} {
		r := newRig(t, "Ledger", "8.0.8")
		s := r.open()
		r.export(s, custody.RoleStake, "w", stakePath)
		r.fake.Misbehave = m
		r.writeFake()
		reg := stakeRegistration(stakePath)
		reg.Address = append([]byte{0x00}, bytes.Repeat([]byte{5}, 56)...)
		if _, err := s.SignCip36(context.Background(), mustAs[custody.Stake](t, hwKey(custody.RoleStake, "w")), reg); err == nil {
			t.Errorf("%s: accepted", m)
		}
	}
}

// spec: SPO-05c-EXT-004, SPO-Ptx-EXT-005
// One call with a signing file and an output file per key; each witness verifies
// against its own key, and a tool that swaps or damages them is refused.
func TestWitnessManyIsOneCallWithOneWitnessPerKey(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	r.export(s, custody.RolePoolCold, "p", "1853H/1815H/0H/0H")
	r.export(s, custody.RolePayment, "p", "1852H/1815H/0H/0/0")
	body := realBody(t, "combined")
	keys := []custody.KeyRef{hwKey(custody.RolePoolCold, "p"), hwKey(custody.RolePayment, "p")}
	ws, err := s.WitnessMany(context.Background(), keys, body, ports.HardwareTxOptions{})
	if err != nil || len(ws) != 2 {
		t.Fatalf("%v %v", ws, err)
	}
	_, coldPub := fakeKey("1853H/1815H/0H/0H")
	_, payPub := fakeKey("1852H/1815H/0H/0/0")
	if !bytes.Equal(ws[0].VKey[:], coldPub) || !bytes.Equal(ws[1].VKey[:], payPub) {
		t.Error("the witnesses are not in the order of the keys")
	}
	argv := r.lastCall("transaction", "witness")
	if len(flagValues(argv, "--hw-signing-file")) != 2 || len(flagValues(argv, "--out-file")) != 2 || r.called("transaction", "witness") != 1 {
		t.Errorf("argv %v", argv)
	}
	if _, err := s.WitnessMany(context.Background(), []custody.KeyRef{keys[0], keys[0]}, body, ports.HardwareTxOptions{}); err == nil {
		t.Error("the same key twice")
	}
	if _, err := s.WitnessMany(context.Background(), nil, body, ports.HardwareTxOptions{}); err == nil {
		t.Error("no key")
	}
	for _, m := range []string{"wrongkey", "badsig", "truncated"} {
		r.fake.Misbehave = m
		r.writeFake()
		if _, err := s.WitnessMany(context.Background(), keys, body, ports.HardwareTxOptions{}); err == nil {
			t.Errorf("%s: accepted", m)
		}
	}
}

// A signing file that holds another account's key is refused before the tool is
// asked anything: no transform, no witness, no prompt.
//
// spec: SPO-Xidentity-SEC-005
func TestAWrongFileIsRefusedBeforeTheDeviceIsAsked(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	r.export(s, custody.RolePayment, "w", "1852H/1815H/0H/0/0")
	r.export(s, custody.RolePayment, "o", "1852H/1815H/1H/0/0")
	r.files["payment/w"] = r.files["payment/o"] // the file stored for w is o's
	_, err := s.Witness(context.Background(), hwKey(custody.RolePayment, "w"), realBody(t, "a body"))
	if !errors.Is(err, hwcli.ErrWrongKey) {
		t.Fatalf("%v", err)
	}
	if n := r.called("transaction"); n != 0 {
		t.Errorf("the tool ran `transaction` %d times before the wrong file was refused", n)
	}
}
