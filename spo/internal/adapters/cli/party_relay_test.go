package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// testRelayOps is the composition root's relay stack over the fixture's vault.
func testRelayOps(v ports.Vault) RelayOps {
	var signer ports.RelayStatementSigner = native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: v}}
	return RelayOps{
		Signing: func(clock ports.Clock, history func(context.Context, identity.Ref) (custody.RoleHistory, bool, error)) relaybinding.Service {
			return relaybinding.Service{Signer: signer, Clock: clock, History: history}
		},
		SignDeviceRevoke: func(ctx context.Context, svc relaybinding.Service, local ports.LocalIdentity, nb int64) (relaybinding.DeviceRevokeResult, error) {
			return svc.SignDeviceRevoke(ctx, local.(relayport.DeviceRevokeSigner), nb)
		},
	}
}

var walletKeyRE = regexp.MustCompile(`wallet key\s+([0-9a-f]{56})`)

// relayPair is two workspaces on one clock: alice binds her device with a
// payment key of her vault; bob enrolls her.
type relayPair struct {
	wa, wb *partyrig.Workspace
	fa, fb *pfix
}

func newRelayPair(t *testing.T) *relayPair {
	t.Helper()
	clock := partyrig.NewClock(partyT0)
	ch := partyrig.NewChain(clock.Now())
	wa, wb := partyrig.New(t, "alice", clock, ch), partyrig.New(t, "bob", clock, ch)
	return &relayPair{wa: wa, wb: wb, fa: newPfixOf(t, wa), fb: newPfixOf(t, wb)}
}

func first4(fp party.Fingerprint) string { return fp.String()[:19] }

// The flags of the relay commands: exactly one way to sign, the flags of each
// way complete, and never a cold role. Each misuse is refused before the
// workspace is opened.
//
// spec: SPO-Xmailbox-IF-021
func TestRelayCommandMisuse(t *testing.T) {
	f := newPfix(t)
	for _, args := range [][]string{
		{"party", "relay", "bind"},
		{"party", "relay", "bind", "--key", "a", "--print", "--wallet", "00"},
		{"party", "relay", "bind", "--print"},
		{"party", "relay", "bind", "--import", "--sign1", "00"},
		{"party", "relay", "bind", "--key", "a", "--role", "pool-cold"},
		{"party", "relay", "bind", "--key", "a", "--wallet", "00"},
		{"party", "relay", "bind", "--key", "a", "--lifetime-days", "181"},
		{"party", "relay", "revoke", "--key", "a"},
		{"party", "relay", "revoke", "--key", "a", "--all", "--device", "x"},
		{"party", "relay", "revoke", "--import", "--sign1", "00", "--cose-key", "00", "--all"},
		{"party", "relay", "forget", "--key", "a"},
		{"party", "relay", "forget", "--lost", "x"},
		{"party", "relay", "peer", "bob"},
		{"party", "relay", "peer", "bob", "--clear", "--binding", "f"},
	} {
		if _, err := f.run(forbid{t}, args...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}

// The whole software path through the command tree: alice binds her device with a
// payment key of her vault and exports it with her identity; bob enrolls her
// with the binding, sees it as evidence and still types the groups; the list
// shows the wallet key; status and forget work; a revoke is pending afterwards.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xparty-IF-009, SPO-Xparty-PR-007, SPO-Xmailbox-SEC-073
func TestRelayBindExportEnrollThroughTheCommands(t *testing.T) {
	p := newRelayPair(t)
	kh := p.wa.AddKey(custody.RolePayment, "alice")
	out := p.fa.must(p.fa.term(), "party", "relay", "bind", "--key", "alice")
	if !strings.Contains(out, fmt.Sprintf("Bound this device to the wallet key %x", kh[:])) {
		t.Fatalf("bind: %s", out)
	}
	out = p.fa.must(p.fa.term(), "party", "relay", "status")
	if !strings.Contains(out, fmt.Sprintf("wallet key   %x", kh[:])) || !strings.Contains(out, "89 day(s) left") || !strings.Contains(out, "revokes waiting to be sent  0") {
		t.Fatalf("status: %s", out)
	}
	doc, bfile := filepath.Join(t.TempDir(), "alice.doc"), filepath.Join(t.TempDir(), "alice.binding")
	p.fa.must(p.fa.term(), "party", "export", doc, "--binding", bfile)

	// with the wrong groups, a valid binding enrolls nothing
	if _, err := p.fb.run(p.fb.term("aaaa-aaaa-aaaa-aaaa"), "party", "enroll", doc, "--as", "alice", "--role", "signer", "--binding", bfile); err == nil {
		t.Fatal("enrolled with the wrong groups and a valid binding")
	}
	out = p.fb.must(p.fb.term(first4(p.wa.Identity.Fingerprint)), "party", "enroll", doc, "--as", "alice", "--role", "signer", "--binding", bfile)
	if !strings.Contains(out, "relay binding (evidence; it does not replace the groups you type)") || !strings.Contains(out, fmt.Sprintf("wallet key  %x", kh[:])) {
		t.Fatalf("enroll did not show the evidence: %s", out)
	}
	if m := walletKeyRE.FindStringSubmatch(out); m == nil || m[1] != hex.EncodeToString(kh[:]) {
		t.Fatalf("enroll: %s", out)
	}
	if out = p.fb.must(p.fb.term(), "party", "list"); !strings.Contains(out, fmt.Sprintf("relay wallet key %x", kh[:])) {
		t.Fatalf("list: %s", out)
	}

	// forget: asks, then revokes this device and deletes the binding
	if _, err := p.fa.run(p.fa.term("n"), "party", "relay", "forget"); err == nil {
		t.Fatal("forget without a yes")
	}
	p.fa.must(p.fa.term(), "party", "relay", "forget", "--yes")
	out = p.fa.must(p.fa.term(), "party", "relay", "status")
	if !strings.Contains(out, "no binding") || !strings.Contains(out, "revokes waiting to be sent  1") {
		t.Fatalf("status after forget: %s", out)
	}
	if _, err := p.fa.run(p.fa.term(), "party", "export", filepath.Join(t.TempDir(), "d"), "--binding", filepath.Join(t.TempDir(), "b")); err == nil {
		t.Fatal("exported a binding after forget")
	}
}

// A binding file of another device, a cold key's binding and a damaged file are
// refused at enrollment with nothing enrolled; --lost naming this device is
// refused.
//
// spec: SPO-Xparty-PRE-008, SPO-Xparty-IF-009, SPO-Xmailbox-SEC-073
func TestRelayEnrollRefusesBadBindings(t *testing.T) {
	p := newRelayPair(t)
	doc := filepath.Join(t.TempDir(), "alice.doc")
	p.fa.must(p.fa.term(), "party", "export", doc)
	now := partyT0.Unix()
	wal := relayporttest.NewWallet(9)
	write := func(name string, b []byte) string {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	other := wal.BindingStatement(p.wb.Identity.Fingerprint, now-60, now+3600, false)
	files := map[string]string{
		"another device": write("o", []byte(fmt.Sprintf(`{"v":1,"statement":"%x","cose_key":"%x"}`, other.Sign1, other.COSEKey))),
		"damaged":        write("d", []byte(`{"v":1,"statement":"zz","cose_key":"00"}`)),
		"oversize":       write("x", []byte(strings.Repeat(" ", 4096))),
	}
	for name, path := range files {
		term := p.fb.term(first4(p.wa.Identity.Fingerprint))
		if _, err := p.fb.run(term, "party", "enroll", doc, "--as", "alice", "--role", "signer", "--binding", path); err == nil {
			t.Errorf("%s: enrolled", name)
		}
		if len(term.prompts) != 0 {
			// a refused binding is refused before anything is shown or typed
			t.Errorf("%s: the operator was asked %q", name, term.prompts)
		}
	}
	if out := p.fb.must(p.fb.term(), "party", "list"); strings.Contains(out, "alice") {
		t.Fatalf("a refused binding enrolled alice: %s", out)
	}
	if _, err := p.fa.run(p.fa.term(), "party", "relay", "forget", "--lost", p.wa.Identity.Fingerprint.String(), "--key", "x"); !errors.Is(err, relayself.ErrSelf) {
		t.Fatalf("--lost this device: %v", err)
	}
}

// An external wallet: --print shows the exact payload, the device and the key;
// --import takes the wallet's answer and binds; a forged answer is refused.
//
// spec: SPO-Xmailbox-IF-021, SPO-Xmailbox-PRE-059
func TestRelayPrintAndImport(t *testing.T) {
	p := newRelayPair(t)
	wal := relayporttest.NewWallet(5)
	out := p.fa.must(p.fa.term("payment"), "party", "relay", "bind", "--print", "--wallet", hex.EncodeToString(wal.Key[:]))
	fp := p.wa.Identity.Fingerprint
	payload := regexp.MustCompile(`spo-relay-binding-v1 device [0-9a-f]{40} from [0-9]+ until [0-9]+`).FindString(out)
	if payload == "" || !strings.Contains(out, fp.String()) || !strings.Contains(out, fmt.Sprintf("%x", fp[:])) || !strings.Contains(out, fmt.Sprintf("%x", wal.Key[:])) {
		t.Fatalf("print: %s", out)
	}
	s1 := wal.Sign1([]byte(payload), false)
	bad := append([]byte(nil), s1...)
	bad[len(bad)-1] ^= 1
	if _, err := p.fa.run(p.fa.term(), "party", "relay", "bind", "--import", "--sign1", hex.EncodeToString(bad), "--cose-key", hex.EncodeToString(wal.COSEKey())); err == nil {
		t.Fatal("a forged answer was imported")
	}
	out = p.fa.must(p.fa.term(), "party", "relay", "bind", "--import", "--sign1", hex.EncodeToString(s1), "--cose-key", hex.EncodeToString(wal.COSEKey()))
	if !strings.Contains(out, fmt.Sprintf("Bound this device to the wallet key %x", wal.Key[:])) || !strings.Contains(out, "no record of the wallet key") {
		t.Fatalf("import: %s", out)
	}
}

// Updating a peer's relay identity asks for the groups; --clear removes it.
//
// spec: SPO-Xparty-PR-007
func TestRelayPeerCommand(t *testing.T) {
	p := newRelayPair(t)
	doc := filepath.Join(t.TempDir(), "alice.doc")
	p.fa.must(p.fa.term(), "party", "export", doc)
	p.fb.must(p.fb.term(first4(p.wa.Identity.Fingerprint)), "party", "enroll", doc, "--as", "alice", "--role", "signer")
	now := partyT0.Unix()
	wal := relayporttest.NewWallet(6)
	st := wal.BindingStatement(p.wa.Identity.Fingerprint, now-60, now+3600, false)
	bfile := filepath.Join(t.TempDir(), "b")
	if err := os.WriteFile(bfile, []byte(fmt.Sprintf(`{"v":1,"statement":"%x","cose_key":"%x"}`, st.Sign1, st.COSEKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.fb.run(p.fb.term("aaaa-aaaa-aaaa-aaaa"), "party", "relay", "peer", "alice", "--binding", bfile); err == nil {
		t.Fatal("updated with the wrong groups")
	}
	if _, err := p.fb.run(p.fb.term(), "party", "relay", "peer", "alice", "--binding", bfile); err == nil {
		t.Fatal("updated with no terminal")
	}
	out := p.fb.must(p.fb.term(first4(p.wa.Identity.Fingerprint)), "party", "relay", "peer", "alice", "--binding", bfile)
	if !strings.Contains(out, fmt.Sprintf("Recorded the wallet key %x", wal.Key[:])) {
		t.Fatalf("peer: %s", out)
	}
	p.fb.must(p.fb.term(), "party", "relay", "peer", "alice", "--clear", "--yes")
	if out := p.fb.must(p.fb.term(), "party", "list"); strings.Contains(out, "relay wallet key") {
		t.Fatalf("not cleared: %s", out)
	}
}

// The outbox status lists what waits and the refusals; retry clears them.
//
// spec: SPO-Xmailbox-IF-021
func TestOutboxStatusAndRetry(t *testing.T) {
	p := newRelayPair(t)
	if out := p.fa.must(p.fa.term(), "party", "outbox", "status"); !strings.Contains(out, "Nothing waits") {
		t.Fatalf("status of an empty outbox: %s", out)
	}
	if out := p.fa.must(p.fa.term(), "party", "outbox", "retry"); !strings.Contains(out, "0 refused") {
		t.Fatalf("retry: %s", out)
	}
}

// A refused identity is told with its remedy; anything else is unchanged.
func TestRelayRemedy(t *testing.T) {
	err := relayRemedy(fmt.Errorf("%w: the relay refuses the binding: %w", ports.ErrNoRoute, ports.ErrIdentityRefused))
	if !errors.Is(err, ports.ErrIdentityRefused) || !strings.Contains(err.Error(), "spo party relay bind") || !strings.Contains(err.Error(), "relay's operator") {
		t.Fatalf("remedy: %v", err)
	}
	other := errors.New("x")
	if relayRemedy(other) != other {
		t.Fatal("another error was changed")
	}
}
