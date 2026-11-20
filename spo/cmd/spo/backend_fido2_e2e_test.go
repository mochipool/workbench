package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// A Vault composite with a FIDO2 factor beside it, through the command layer,
// end to end: add-backend --with fido2 makes one credential on the
// authenticator, slot list shows both factors, --unlock backend opens the
// workspace through the backend and the authenticator, the approval gate asks
// the authenticator again (its PIN typed at the terminal) before a key signs,
// and slot remove takes the slot away. The stand-ins are fakefido and the
// Vault Transit server on 127.0.0.1.
//
// spec: SPO-Xunlock-OUT-022, SPO-Xunlock-SEC-014, SPO-Xunlock-OUT-020, SPO-Xunlock-OUT-023
func TestVaultAndFIDO2SlotThroughTheCommandLayer(t *testing.T) {
	v, srv := newE2EVault(t)
	w := newPartyWorld(t, false)
	w.register()
	carry := filepath.Join(t.TempDir(), "to-bob")
	w.coord(nil, "party", "request", "export", "p", "--out", carry, "--purpose", "register the pool")
	files, _ := filepath.Glob(filepath.Join(carry, "SigningRequest-*-*.spo"))
	if len(files) != 1 {
		t.Fatalf("request files %v", files)
	}
	if out, err := w.bobRun(nil, nil, "party", "inbox", "import", files[0]); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	req := reqIDRE.FindStringSubmatch(reqs)[1]

	toml := filepath.Join(w.bob, "spo.toml")
	b, err := os.ReadFile(toml)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toml, append(b, vaultTOML(srv.URL)...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TOKEN", v.token)
	rig := newFidoRig(t, "seed-vault-fido2", "")

	// enrol: the workspace opens with its passphrase; the new credential is made
	// on dev0 with the PIN from the descriptor
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	out, err := runFido(t, rig, nil, "-C", w.bob, "--passphrase-fd", pfd, "--fido2-device", dev0, "--fido2-pin-fd", pinFD,
		"workspace", "slot", "add-backend", "--backend", "vault", "--with", "fido2")
	if err != nil {
		t.Fatalf("add-backend --with fido2: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`added composite slot ([0-9a-f]{32}): .* AND a fido2 factor`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no slot id in %q", out)
	}
	id := m[1]
	// the fingerprint of the whole reference is printed at enrolment, in the
	// listing and in the notice of every unlock (SPO-Xunlock-OUT-023), with the
	// client setting of [vault] that the test's spo.toml has (plain http to
	// loopback): not the reference's own fingerprint
	ref := ports.BackendRef{Kind: ports.BackendVaultTransit, Address: srv.URL, Key: "transit/spo"}
	fp := ref.ClientFingerprint([]ports.BackendSetting{{Name: "allow_loopback_http", Value: "true"}})
	if fp == ref.Fingerprint() {
		t.Fatal("the client setting is not in the fingerprint")
	}
	if !strings.Contains(out, "fingerprint "+fp) {
		t.Errorf("enrolment does not print the fingerprint %s:\n%s", fp, out)
	}
	if n := rig.count("fido2-cred"); n != 1 {
		t.Errorf("%d credentials made, want 1", n)
	}
	if v.calls.Load() == 0 {
		t.Error("the backend was not asked to wrap")
	}

	out, err = runFido(t, nil, nil, "-C", w.bob, "workspace", "slot", "list")
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "fido2") || !strings.Contains(out, "backend (vault-transit "+srv.URL+" transit/spo") {
		t.Fatalf("slot list: %v\n%s", err, out)
	}
	if strings.Contains(out, v.token) {
		t.Fatal("the listing shows the token")
	}
	if !strings.Contains(out, "fingerprint "+fp) {
		t.Errorf("slot list does not show the fingerprint %s:\n%s", fp, out)
	}

	// open through the composite and approve: the gate asks for the PIN on the
	// terminal (a fresh presentation), not from --fido2-pin-fd
	before := v.calls.Load()
	term := &fakeTerm{lines: []string{"y"}, secrets: []string{fidoPIN}, rows: 40}
	gr := &gateRunner{cfg: rig.cfg, term: term}
	apin, apinFD := fdIn(t, fidoPIN+"\n")
	defer apin.Close()
	out, err = runFidoWith(t, gr, term, "-C", w.bob, "--unlock", "backend", "--fido2-device", dev0, "--fido2-pin-fd", apinFD,
		"party", "approve", req, "--shelley-genesis", w.r.genesis)
	if err != nil || !strings.Contains(out, "Signed.") {
		t.Fatalf("approve through the Vault and FIDO2 composite: %v\n%s", err, out)
	}
	if !strings.Contains(out, "asking vault-transit at "+srv.URL) || !strings.Contains(out, "fingerprint "+fp) {
		t.Errorf("no notice of the backend call with its fingerprint %s:\n%s", fp, out)
	}
	if v.calls.Load() == before {
		t.Error("the open did not go through the backend")
	}
	if len(term.asked) == 0 || !strings.Contains(term.asked[len(term.asked)-1], "PIN") {
		t.Errorf("the gate did not ask for the PIN on the terminal: %q", term.asked)
	}
	if gr.beforeGate < 1 || gr.atGate != 1 {
		t.Errorf("assertions: %d for the open, %d at the gate (want >= 1 and 1)", gr.beforeGate, gr.atGate)
	}
	if strings.Contains(out, testPass) || strings.Contains(out, v.token) {
		t.Error("the output shows a secret")
	}

	// remove it (a rotation: the current recovery key is presented)
	_, rec := template(t)
	_, pfd2 := fdIn(t, testPass+"\n")
	_, rfd := fdIn(t, rec+"\n")
	rf, rkfd := fdOut(t)
	out, err = runFido(t, rig, nil, "-C", w.bob, "--passphrase-fd", pfd2, "workspace", "slot", "remove", id[:8], "--recovery-key-in-fd", rfd, "--recovery-key-fd", rkfd)
	if err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	_ = contents(rf)
	if out, err := runFido(t, nil, nil, "-C", w.bob, "workspace", "slot", "list"); err != nil || strings.Contains(out, "backend") || strings.Contains(out, id) {
		t.Fatalf("after the removal: %v\n%s", err, out)
	}
}
