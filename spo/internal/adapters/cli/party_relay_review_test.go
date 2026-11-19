package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

var revokeIDRE = regexp.MustCompile(`(?m)^  ([0-9a-f]{16})  `)

// --print for a key this workspace has no record of asks the operator to type
// its role, payment or stake; no answer (no terminal) and any other answer print
// nothing and prepare nothing.
//
// spec: SPO-Xmailbox-SEC-075
func TestRelayPrintAsksTheRoleOfAnUnknownKey(t *testing.T) {
	p := newRelayPair(t)
	wal := relayporttest.NewWallet(5)
	k := hex.EncodeToString(wal.Key[:])
	for _, answer := range [][]string{nil, {"pool"}, {"cold"}, {""}} {
		out, err := p.fa.run(p.fa.term(answer...), "party", "relay", "bind", "--print", "--wallet", k)
		if err == nil || strings.Contains(out, "spo-relay-binding-v1") {
			t.Fatalf("answer %q: printed\n%s (%v)", answer, out, err)
		}
	}
	if out := p.fa.must(p.fa.term(), "party", "relay", "status"); strings.Contains(out, "prepared for an external wallet") {
		t.Fatalf("a refused print prepared a request: %s", out)
	}
	for _, args := range [][]string{
		{"party", "relay", "revoke", "--all", "--print", "--wallet", k},
		{"party", "relay", "forget", "--lost", relayporttest.Device(7).String(), "--print", "--wallet", k},
	} {
		if out, err := p.fa.run(p.fa.term(), args...); err == nil || strings.Contains(out, "spo-relay-revoke-v1") {
			t.Fatalf("%v without the role typed: %v\n%s", args, err, out)
		}
	}
	out := p.fa.must(p.fa.term("stake"), "party", "relay", "revoke", "--all", "--print", "--wallet", k)
	if !strings.Contains(out, "MUST be a payment or a stake key") || !strings.Contains(out, "spo-relay-revoke-v1") {
		t.Fatalf("print with the role typed: %s", out)
	}
}

// A workspace whose pool is known only by its id (a pool.id record, no cold
// key, so no role history of it here): that key hash is refused on every relay
// path that names a wallet key, before anything is asked or printed.
//
// spec: SPO-Xmailbox-SEC-075
func TestRelayRefusesAPoolKnownOnlyByID(t *testing.T) {
	p := newRelayPair(t)
	wal := relayporttest.NewWallet(5)
	if err := p.fa.st.Update(context.Background(), func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: "mypool", Kind: ports.PoolIDFile}, []byte(hex.EncodeToString(wal.Key[:])+"\n"))
	}); err != nil {
		t.Fatal(err)
	}
	k := hex.EncodeToString(wal.Key[:])
	for _, args := range [][]string{
		{"party", "relay", "bind", "--print", "--wallet", k},
		{"party", "relay", "revoke", "--all", "--print", "--wallet", k},
		{"party", "relay", "forget", "--lost", relayporttest.Device(7).String(), "--print", "--wallet", k},
	} {
		term := p.fa.term("payment")
		_, err := p.fa.run(term, args...)
		if !errors.Is(err, relayself.ErrPoolID) {
			t.Fatalf("%v: %v", args, err)
		}
		for _, q := range term.prompts {
			if strings.Contains(q, "role") {
				t.Fatalf("%v asked %q before refusing a pool id", args, q)
			}
		}
	}
}

// export FILE --binding FILE with one path is refused before anything is
// written; an ended binding is refused (a peer's check would refuse it on its
// clock) and one near its end is written with a warning.
//
// spec: SPO-Xparty-IF-009
func TestExportBindingPathsAndEnd(t *testing.T) {
	p := newRelayPair(t)
	p.wa.AddKey(custody.RolePayment, "alice")
	p.fa.must(p.fa.term(), "party", "relay", "bind", "--key", "alice", "--lifetime-days", "10")
	dir := t.TempDir()
	same := filepath.Join(dir, "x")
	if _, err := p.fa.run(p.fa.term(), "party", "export", same, "--binding", filepath.Join(dir, ".", "x")); err == nil || !strings.Contains(err.Error(), "same file") {
		t.Fatalf("one path for both: %v", err)
	}
	p.fa.must(p.fa.term(), "party", "export", filepath.Join(dir, "d1"), "--binding", filepath.Join(dir, "b1"))
	if !strings.Contains(p.fa.err.String(), "WARNING: this device's binding ends in") {
		t.Fatalf("no warning 10 days before the end: %s", p.fa.err.String())
	}
	p.wa.Clock.Advance(11 * 24 * time.Hour)
	if _, err := p.fa.run(p.fa.term(), "party", "export", filepath.Join(dir, "d2"), "--binding", filepath.Join(dir, "b2")); err == nil || !strings.Contains(err.Error(), "ended") {
		t.Fatalf("an ended binding was exported: %v", err)
	}
}

// forget --lost DEVICE --import takes only a prepared revoke of that device: a
// prepared revoke of every device of the key (revoke --all --print) is refused
// and nothing is stored.
//
// spec: SPO-Xmailbox-SEC-073
func TestForgetLostImportChecksTheDevice(t *testing.T) {
	p := newRelayPair(t)
	wal := relayporttest.NewWallet(5)
	out := p.fa.must(p.fa.term("payment"), "party", "relay", "revoke", "--all", "--print", "--wallet", hex.EncodeToString(wal.Key[:]))
	payload := regexp.MustCompile(`spo-relay-revoke-v1 device all not-before [0-9]+`).FindString(out)
	if payload == "" {
		t.Fatalf("print: %s", out)
	}
	s1 := wal.Sign1([]byte(payload), false)
	_, err := p.fa.run(p.fa.term(), "party", "relay", "forget", "--lost", relayporttest.Device(7).String(), "--import",
		"--sign1", hex.EncodeToString(s1), "--cose-key", hex.EncodeToString(wal.COSEKey()))
	if !errors.Is(err, relayself.ErrLostMismatch) {
		t.Fatalf("a prepared --all imported with --lost: %v", err)
	}
	if out := p.fa.must(p.fa.term(), "party", "relay", "status"); !strings.Contains(out, "revokes waiting to be sent  0") {
		t.Fatalf("something was stored: %s", out)
	}
}

// After `party rotate` the relay commands work: status shows no binding and the
// revoke of the old device (signed by its key before it was replaced), bind,
// revoke and forget --lost work; drop-revoke asks and drops one.
//
// spec: SPO-Xmailbox-SEC-076, SPO-Xmailbox-IF-021, SPO-Xmailbox-OUT-098
func TestRelayCommandsAfterRotate(t *testing.T) {
	p := newRelayPair(t)
	p.wa.AddKey(custody.RolePayment, "alice")
	p.fa.must(p.fa.term(), "party", "relay", "bind", "--key", "alice")
	old := p.wa.Identity.Fingerprint
	out := p.fa.must(p.fa.term("y"), "party", "rotate")
	if !strings.Contains(out, "the old device's binding is dropped and its revoke") {
		t.Fatalf("rotate: %s", out)
	}
	out = p.fa.must(p.fa.term(), "party", "relay", "status")
	if !strings.Contains(out, "no binding") || !strings.Contains(out, "revokes waiting to be sent  1") || !strings.Contains(out, "device "+old.String()+" (signed by the device)") {
		t.Fatalf("status after rotate: %s", out)
	}
	if strings.Contains(out, old.String()[:9]) && strings.Contains(out, "device       "+old.String()) {
		t.Fatalf("status shows the old device as this one: %s", out)
	}
	p.fa.must(p.fa.term(), "party", "relay", "bind", "--key", "alice")
	p.fa.must(p.fa.term(), "party", "relay", "revoke", "--device", fmt.Sprintf("%x", old[:]), "--key", "alice")
	p.fa.must(p.fa.term(), "party", "relay", "forget", "--lost", relayporttest.Device(7).String(), "--key", "alice")
	out = p.fa.must(p.fa.term(), "party", "relay", "status")
	ids := revokeIDRE.FindAllStringSubmatch(out, -1)
	if len(ids) != 3 {
		t.Fatalf("status lists %d revokes: %s", len(ids), out)
	}
	if _, err := p.fa.run(p.fa.term(), "party", "relay", "drop-revoke", ids[0][1]); err == nil {
		t.Fatal("dropped with no terminal")
	}
	if _, err := p.fa.run(p.fa.term("n"), "party", "relay", "drop-revoke", ids[0][1]); err == nil {
		t.Fatal("dropped without a yes")
	}
	p.fa.must(p.fa.term("y"), "party", "relay", "drop-revoke", ids[0][1])
	if out := p.fa.must(p.fa.term(), "party", "relay", "status"); !strings.Contains(out, "revokes waiting to be sent  2") {
		t.Fatalf("after the drop: %s", out)
	}
}

// A peer whose stored relay identity no longer verifies does not lock the
// registry: party list loads and warns with the repair, and the repair works.
//
// spec: SPO-Xparty-OUT-007, SPO-Xparty-PR-007
func TestUnverifiedPeerIsReportedAndRepaired(t *testing.T) {
	p := newRelayPair(t)
	p.wa.AddKey(custody.RolePayment, "alice")
	p.fa.must(p.fa.term(), "party", "relay", "bind", "--key", "alice")
	doc, bfile := filepath.Join(t.TempDir(), "a.doc"), filepath.Join(t.TempDir(), "a.b")
	p.fa.must(p.fa.term(), "party", "export", doc, "--binding", bfile)
	p.fb.must(p.fb.term(first4(p.wa.Identity.Fingerprint)), "party", "enroll", doc, "--as", "alice", "--role", "signer", "--binding", bfile)
	ref := ports.NamedRef{Name: "all", Kind: ports.PartyRecords}
	ctx := context.Background()
	if err := p.fb.st.Update(ctx, func(w ports.NamedWriter) error {
		raw, err := w.Get(ref)
		if err != nil {
			return err
		}
		i := bytes.Index(raw, []byte(`"statement":"`))
		if i < 0 {
			return errors.New("no statement")
		}
		j := i + len(`"statement":"`) + 200 // a digit inside the signature
		raw = bytes.Clone(raw)
		if raw[j] == '0' {
			raw[j] = '1'
		} else {
			raw[j] = '0'
		}
		return w.Put(ref, raw)
	}); err != nil {
		t.Fatal(err)
	}
	out := p.fb.must(p.fb.term(), "party", "list")
	if !strings.Contains(out, "alice") || !strings.Contains(p.fb.err.String(), "no longer verifies") || !strings.Contains(p.fb.err.String(), "spo party relay peer alice") {
		t.Fatalf("list: %s\n%s", out, p.fb.err.String())
	}
	p.fb.must(p.fb.term(), "party", "relay", "peer", "alice", "--clear", "--yes")
	if p.fb.must(p.fb.term(), "party", "list"); strings.Contains(p.fb.err.String(), "no longer verifies") {
		t.Fatalf("still warned after --clear: %s", p.fb.err.String())
	}
}

// The outbox loops tell a refused identity once, with the remedy, and any other
// error at every run.
//
// spec: SPO-Xmailbox-OUT-099
func TestFlushNoteTellsTheRemedyOnce(t *testing.T) {
	var b bytes.Buffer
	told := false
	refused := fmt.Errorf("%w: the relay refuses the binding: %w", ports.ErrNoRoute, ports.ErrIdentityRefused)
	for range 3 {
		flushNote(&b, "sending", refused, &told)
	}
	if n := strings.Count(b.String(), "spo party relay bind"); n != 1 {
		t.Fatalf("the remedy was told %d times:\n%s", n, b.String())
	}
	b.Reset()
	for range 2 {
		flushNote(&b, "sending", errors.New("disk full"), &told)
	}
	if strings.Count(b.String(), "disk full") != 2 {
		t.Fatalf("another error: %s", b.String())
	}
	if err := relayRemedy(refused); !strings.Contains(err.Error(), "relay's operator") {
		t.Fatalf("remedy: %v", err)
	}
}
