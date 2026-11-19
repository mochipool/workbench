package labels_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

var ctx = context.Background()

const pass = "labels test passphrase"

var (
	tmplOnce sync.Once
	tmplDir  string
	tmplPath string
)

func TestMain(m *testing.M) {
	// Every Open derives a key with 256 MiB of Argon2id memory. Without a limit
	// the runtime keeps that garbage between tests and the package needs well
	// over a gibibyte (more under the race detector).
	debug.SetMemoryLimit(512 << 20)
	code := m.Run()
	if tmplDir != "" {
		os.RemoveAll(tmplDir)
	}
	os.Exit(code)
}

func template(t *testing.T) {
	t.Helper()
	tmplOnce.Do(func() {
		dir, err := os.MkdirTemp("", "labels-tmpl-")
		if err != nil {
			t.Fatal(err)
		}
		tmplDir = dir
		tmplPath = filepath.Join(dir, "ws.db")
		rk, err := sqlitestore.Init(tmplPath, secret.Take([]byte(pass)))
		if err != nil {
			t.Fatal(err)
		}
		rk.Destroy()
	})
}

func fresh(t *testing.T) string {
	t.Helper()
	template(t)
	p := filepath.Join(t.TempDir(), "ws.db")
	in, err := os.Open(tmplPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	out.Close()
	return p
}

func open(t *testing.T, path string) *sqlitestore.Store {
	t.Helper()
	s, err := sqlitestore.Open(path, secret.Take([]byte(pass)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newWS(t *testing.T) (*sqlitestore.Store, *labels.Store, string) {
	p := fresh(t)
	s := open(t, p)
	return s, labels.Named(s), p
}

func key(label string) []byte {
	s := sha256.Sum256([]byte("labels test key " + label))
	return ed25519.NewKeyFromSeed(s[:]).Public().(ed25519.PublicKey)
}

func vkey(typ, label string) []byte {
	return []byte(fmt.Sprintf(`{"type":%q,"description":"","cborHex":"5820%s"}`, typ, hex.EncodeToString(key(label))))
}

const (
	payT   = "PaymentVerificationKeyShelley_ed25519"
	stakeT = "StakeVerificationKeyShelley_ed25519"
	coldT  = "StakePoolVerificationKey_ed25519"
	vrfT   = "VrfVerificationKey_PraosVRF"
	kesT   = "KesVerificationKey_ed25519_kes_2^6"
)

func nref(name string, k ports.Kind, num ...int) ports.NamedRef {
	r := ports.NamedRef{Name: name, Kind: k}
	if len(num) > 0 {
		r.Num = num[0]
	}
	return r
}

func put(t *testing.T, n *labels.Store, ref ports.NamedRef, data []byte) {
	t.Helper()
	if err := n.Update(ctx, func(w ports.NamedWriter) error { return w.Put(ref, data) }); err != nil {
		t.Fatalf("put %s: %v", ref, err)
	}
}

func get(t *testing.T, n *labels.Store, ref ports.NamedRef) ([]byte, error) {
	t.Helper()
	var out []byte
	err := n.View(ctx, func(r ports.NamedReader) error {
		var e error
		out, e = r.Get(ref)
		return e
	})
	return out, err
}

func idOf(t *testing.T, role custody.Role, env []byte) identity.Ref {
	t.Helper()
	id, err := ports.IdentityOfVKey(role, env)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// spec: SPO-Xidentity-INV-019
func TestFirstKeyCreatesTheOwnerAndItsLabel(t *testing.T) {
	s, n, _ := newWS(t)
	pay := vkey(payT, "alice pay")
	put(t, n, nref("alice.payment", ports.AddrVKey), pay)
	put(t, n, nref("alice", ports.StakingVKey), vkey(stakeT, "alice stake"))
	put(t, n, nref("alice.payment", ports.AddrFile), []byte("addr_test1qz\n"))

	// reads by name, by the payment stem, and by the identity written as a name
	for _, name := range []string{"alice", "alice.payment", idOf(t, custody.RolePayment, pay).String()} {
		got, err := get(t, n, nref(name, ports.AddrVKey))
		if err != nil || string(got) != string(pay) {
			t.Fatalf("get addr.vkey of %q: %v", name, err)
		}
	}
	// the owner has the payment key as its anchor, and both members
	var owners []labels.Owner
	var lab map[identity.Ref]labels.Label
	if err := s.View(ctx, func(r ports.Reader) error {
		var e error
		owners, lab, e = labels.OwnersOf(r)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 {
		t.Fatalf("%d owners, want 1", len(owners))
	}
	o := owners[0]
	if o.Anchor != idOf(t, custody.RolePayment, pay) {
		t.Errorf("the wallet is anchored by %s, want its payment key", o.Anchor)
	}
	if len(o.Manifest.Members()) != 2 || lab[o.Anchor].Name != "alice" || lab[o.Anchor].Group != "wallet" {
		t.Errorf("manifest %v label %v", o.Manifest.Members(), lab[o.Anchor])
	}
	// a manifest version chain: payment, then payment+stake
	if o.Manifest.Predecessor().IsZero() {
		t.Errorf("the second member did not write a new manifest version")
	}
	// the store sees anchors only: no record under the name exists
	if _, err := get(t, n, nref("nobody", ports.AddrVKey)); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("unknown name: %v", err)
	}
}

// spec: SPO-Xidentity-INV-011
func TestWalletAnchorIsFixedAtCreation(t *testing.T) {
	s, n, _ := newWS(t)
	stake := vkey(stakeT, "w stake")
	put(t, n, nref("w", ports.StakingVKey), stake)
	put(t, n, nref("w.payment", ports.AddrVKey), vkey(payT, "w pay"))
	var owners []labels.Owner
	if err := s.View(ctx, func(r ports.Reader) error {
		var e error
		owners, _, e = labels.OwnersOf(r)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].Anchor != idOf(t, custody.RoleStake, stake) {
		t.Fatalf("a stake-only wallet that gained a payment key must keep its stake anchor: %+v", owners)
	}
}

// An owner whose anchoring key does not exist yet is provisional: its records are
// kept under a derived anchor, and the key that anchors it moves them to the real
// anchor (a pool descriptor written before the cold key; a VRF key generated first).
//
// spec: SPO-Xidentity-INV-019
func TestAProvisionalOwnerIsPromotedByItsAnchoringKey(t *testing.T) {
	s, n, path := newWS(t)
	vrf := vkey(vrfT, "p vrf")
	put(t, n, nref("p", ports.PoolDescriptor), []byte(`{"poolName":"p"}`))
	put(t, n, nref("p", ports.VrfVKey), vrf)
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.PutSecret(nref("p", ports.VrfSKey), secret.Take([]byte(`{"cborHex":"5820aa"}`)))
	}); err != nil {
		t.Fatal(err)
	}
	// nothing is an owner yet, and the records are readable by name
	var owners []labels.Owner
	if err := s.View(ctx, func(r ports.Reader) error { var e error; owners, _, e = labels.OwnersOf(r); return e }); err != nil || len(owners) != 0 {
		t.Fatalf("owners before the cold key: %v %v", owners, err)
	}
	if got, err := get(t, n, nref("p", ports.PoolDescriptor)); err != nil || string(got) != `{"poolName":"p"}` {
		t.Fatalf("descriptor: %q %v", got, err)
	}
	cold := vkey(coldT, "p cold")
	put(t, n, nref("p", ports.NodeVKey), cold)
	if err := s.View(ctx, func(r ports.Reader) error { var e error; owners, _, e = labels.OwnersOf(r); return e }); err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].Anchor != idOf(t, custody.RolePoolCold, cold) {
		t.Fatalf("owners after the cold key: %+v", owners)
	}
	if _, ok := owners[0].Manifest.Lookup(identity.MemberVRF, 0); !ok {
		t.Error("the VRF key kept meanwhile did not join the manifest")
	}
	// every record is under the real anchor, none under the provisional one
	prov, _ := labels.ProvisionalAnchor(identity.OwnerPool, "p")
	refs, _ := s.ListRecords(ctx)
	have := map[ports.Kind]bool{}
	for _, r := range refs {
		if r.Anchor == prov {
			t.Errorf("%s is still under the provisional anchor", r.Kind)
		}
		if r.Anchor == owners[0].Anchor {
			have[r.Kind] = true
		}
	}
	for _, k := range []ports.Kind{ports.PoolDescriptor, ports.VrfVKey, ports.VrfSKey, ports.NodeVKey} {
		if !have[k] {
			t.Errorf("no %s under the real anchor", k)
		}
	}
	if got, err := get(t, n, nref("p", ports.PoolDescriptor)); err != nil || string(got) != `{"poolName":"p"}` {
		t.Fatalf("descriptor after the move: %q %v", got, err)
	}
	s.Close()
	// and the store opens: the identity layer is consistent
	open(t, path)
}

// spec: SPO-Xidentity-INV-019
func TestMembershipIsUniqueAcrossOwners(t *testing.T) {
	_, n, _ := newWS(t)
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "shared"))
	err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(nref("bob", ports.AddrVKey), vkey(payT, "shared"))
	})
	if !errors.Is(err, labels.ErrMembership) {
		t.Fatalf("one key under two wallets: %v", err)
	}
	if !strings.Contains(err.Error(), "wallet \"alice\"") {
		t.Errorf("the refusal does not show the owner that has it: %v", err)
	}
	// the same key as another role of another owner is refused too
	err = n.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(nref("pool", ports.NodeVKey), vkey(coldT, "shared"))
	})
	if !errors.Is(err, labels.ErrMembership) {
		t.Fatalf("a wallet key as a pool cold key: %v", err)
	}
}

// spec: SPO-Xidentity-INV-019
func TestAManifestNeverReplacesAMember(t *testing.T) {
	_, n, _ := newWS(t)
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "one"))
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "one")) // the same key again is a no-op
	err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(nref("alice", ports.AddrVKey), vkey(payT, "two"))
	})
	if !errors.Is(err, identity.ErrManifestAppend) {
		t.Fatalf("replacing the payment key: %v", err)
	}
}

// spec: SPO-Xidentity-INV-019
func TestNumberedKESKeysAreMembers(t *testing.T) {
	s, n, _ := newWS(t)
	put(t, n, nref("pool", ports.NodeVKey), vkey(coldT, "cold"))
	for i := 0; i < 3; i++ {
		put(t, n, nref("pool", ports.KesVKey, i), vkey(kesT, fmt.Sprint("kes", i)))
	}
	var owners []labels.Owner
	if err := s.View(ctx, func(r ports.Reader) error {
		var e error
		owners, _, e = labels.OwnersOf(r)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if got := len(owners[0].Manifest.Members()); got != 4 {
		t.Fatalf("%d members, want cold + 3 KES keys", got)
	}
	if _, ok := owners[0].Manifest.Lookup(identity.MemberKES, 2); !ok {
		t.Error("KES key 2 is not listed")
	}
}

// spec: SPO-Xidentity-INV-020
func TestRoleHistoryIsRecordedAndOnlyGrows(t *testing.T) {
	s, n, _ := newWS(t)
	cold := vkey(coldT, "c")
	put(t, n, nref("pool", ports.NodeVKey), cold)
	id := idOf(t, custody.RolePoolCold, cold)
	idx := labels.NewIndex(s)
	h, ok, err := idx.RoleHistory(ctx, id)
	if err != nil || !ok || !h.Has(custody.RolePoolCold) || !h.HasColdRole() {
		t.Fatalf("history %v %v %v", h.Roles(), ok, err)
	}
	if _, ok, _ := idx.RoleHistory(ctx, idOf(t, custody.RolePayment, vkey(payT, "none"))); ok {
		t.Error("a key never stored has a history")
	}
	// RecordRole adds a role; the stored history never loses one
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.RecordRole(w, id, custody.RoleVRF) }); err != nil {
		t.Fatal(err)
	}
	h, _, _ = idx.RoleHistory(ctx, id)
	if !h.Has(custody.RolePoolCold) || !h.Has(custody.RoleVRF) {
		t.Fatalf("roles %v", h.Roles())
	}
	// a record that lacks a stored role is refused by Extends and so cannot be written through RecordRole;
	// a record of another identity stored under this one is refused when read
	other, _ := custody.NewRoleHistory(idOf(t, custody.RolePayment, vkey(payT, "o")), custody.RolePayment)
	b, _ := other.Canonical()
	if err := s.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Anchor: id, Kind: ports.RoleHistory}, b)
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := idx.RoleHistory(ctx, id); err == nil {
		t.Fatal("a role history of another identity was read as this one's")
	}
}

// spec: SPO-Xidentity-INV-018
func TestASecondLabelIsRefusedAndShowsBoth(t *testing.T) {
	s, n, _ := newWS(t)
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "a"))
	// a second label for the same anchor, written under the store's nose
	var anchor identity.Ref
	if err := s.View(ctx, func(r ports.Reader) error {
		o, _, e := labels.OwnersOf(r)
		anchor = o[0].Anchor
		return e
	}); err != nil {
		t.Fatal(err)
	}
	second := labels.Label{Group: "wallet", Name: "alias", Anchor: anchor}
	ref, _ := second.Record()
	b, _ := second.Encode()
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(ref, b) }); err != nil {
		t.Fatal(err)
	}
	err := n.View(ctx, func(r ports.NamedReader) error { _, e := r.Get(nref("idnotused", ports.AddrVKey)); return e })
	_ = err
	var ownersErr error
	if e := s.View(ctx, func(r ports.Reader) error { _, _, ownersErr = labels.OwnersOf(r); return nil }); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(ownersErr, labels.ErrLabelTaken) {
		t.Fatalf("two labels for one anchor: %v", ownersErr)
	}
	if !strings.Contains(ownersErr.Error(), "alice") || !strings.Contains(ownersErr.Error(), "alias") {
		t.Errorf("the refusal does not show both labels: %v", ownersErr)
	}
}

// spec: SPO-Xidentity-INV-018
func TestALabelNamesOneOwnerPerKindAndName(t *testing.T) {
	_, n, _ := newWS(t)
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "a"))
	// "alice" as a pool is another label (another kind of owner)
	put(t, n, nref("alice", ports.NodeVKey), vkey(coldT, "b"))
	// a new wallet that wants the name "alice" takes the existing label: its key is refused as a replacement
	err := n.Update(ctx, func(w ports.NamedWriter) error { return w.Put(nref("alice", ports.AddrVKey), vkey(payT, "c")) })
	if !errors.Is(err, identity.ErrManifestAppend) {
		t.Fatalf("%v", err)
	}
}

// spec: SPO-Xidentity-INV-023
func TestTheIdentityLayerIsCheckedOnEveryOpen(t *testing.T) {
	s, n, path := newWS(t)
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "a"))
	// the verification key stored for a member no longer hashes to its identity
	var anchor identity.Ref
	if err := s.View(ctx, func(r ports.Reader) error {
		o, _, e := labels.OwnersOf(r)
		anchor = o[0].Anchor
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Anchor: anchor, Kind: ports.AddrVKey}, vkey(payT, "someone else"))
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err := sqlitestore.Open(path, secret.Take([]byte(pass)))
	if !errors.Is(err, labels.ErrCorrupt) {
		t.Fatalf("open of a store whose manifest disagrees with its key: %v", err)
	}
}

// spec: SPO-Xidentity-INV-019
func TestTwoOwnersListingOneIdentityIsRefusedOnOpen(t *testing.T) {
	s, n, path := newWS(t)
	put(t, n, nref("alice", ports.AddrVKey), vkey(payT, "a"))
	put(t, n, nref("bob", ports.AddrVKey), vkey(payT, "b"))
	// write a manifest for bob that also lists alice's key, and point bob at it
	var al, bo labels.Owner
	if err := s.View(ctx, func(r ports.Reader) error {
		o, lab, e := labels.OwnersOf(r)
		for _, x := range o {
			if lab[x.Anchor].Name == "alice" {
				al = x
			} else {
				bo = x
			}
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	m, err := bo.Manifest.Add(identity.Member{Role: identity.MemberStake, Identity: al.Anchor})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := m.ID()
	mb, _ := m.Canonical()
	rec := labels.OwnerRec{Kind: identity.OwnerWallet, Manifest: id}
	rb, _ := rec.Encode()
	if err := s.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(ports.Ref{Anchor: id, Kind: ports.OwnerManifest}, mb); err != nil {
			return err
		}
		return w.Put(ports.Ref{Anchor: bo.Anchor, Kind: ports.OwnerRecord}, rb)
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	_, err = sqlitestore.Open(path, secret.Take([]byte(pass)))
	if !errors.Is(err, labels.ErrMembership) {
		t.Fatalf("open: %v", err)
	}
	if !strings.Contains(err.Error(), "alice") || !strings.Contains(err.Error(), "bob") {
		t.Errorf("the refusal does not show both owners: %v", err)
	}
}

// spec: SPO-Xidentity-INV-022

// spec: SPO-Xidentity-INV-022
func TestNamedRecordRoundTripAndList(t *testing.T) {
	s, n, _ := newWS(t)
	put(t, n, nref("00ab12", ports.PendingUpdate), []byte(`{"txid":"00ab12"}`))
	put(t, n, nref("state", ports.MultisigCoordinator), []byte("x"))
	got, err := get(t, n, nref("00ab12", ports.PendingUpdate))
	if err != nil || string(got) != `{"txid":"00ab12"}` {
		t.Fatal(got, err)
	}
	names, err := n.NamedRecords(ctx, ports.PendingUpdate)
	if err != nil || len(names) != 1 || names[0] != "00ab12" {
		t.Fatalf("pending names %v %v", names, err)
	}
	l, err := n.List(ctx)
	if err != nil || len(l.Unknown) != 0 || len(l.Entries) != 2 {
		t.Fatalf("list %+v %v", l, err)
	}
	// delete removes the record and its label
	if err := n.Update(ctx, func(w ports.NamedWriter) error { return w.Delete(nref("00ab12", ports.PendingUpdate)) }); err != nil {
		t.Fatal(err)
	}
	if names, _ := n.NamedRecords(ctx, ports.PendingUpdate); len(names) != 0 {
		t.Fatalf("names after delete: %v", names)
	}
	// no record of the store is keyed by a name: every anchor is an identity
	refs, err := s.ListRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.Anchor.IsZero() {
			t.Fatal("a record without an anchor")
		}
	}
}

// spec: SPO-Xidentity-INV-017
func TestAnEncryptedSigningKeyIsKeyedByItsSiblingVerificationKey(t *testing.T) {
	s, n, _ := newWS(t)
	pay := vkey(payT, "hal")
	put(t, n, nref("hal.payment", ports.AddrVKey), pay)
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.PutSecret(nref("hal.payment", ports.UpstreamEncryptedSKey), secret.Take([]byte("gpg bytes")))
	}); err != nil {
		t.Fatal(err)
	}
	refs, _ := s.ListRecords(ctx)
	id := idOf(t, custody.RolePayment, pay)
	found := false
	for _, r := range refs {
		if r.Kind == ports.UpstreamEncryptedSKey {
			found = r.Anchor == id
		}
	}
	if !found {
		t.Error("the encrypted key is not keyed by its verification key's identity")
	}
	l, _ := n.List(ctx)
	have := false
	for _, e := range l.Entries {
		have = have || (e.Ref.Kind == ports.UpstreamEncryptedSKey && e.Ref.Name == "hal.payment")
	}
	if !have {
		t.Errorf("listing %+v does not give the stem back", l.Entries)
	}
	// with no sibling there is no identity: the record is quarantined, a named
	// record that no signer can use, found by its stem
	err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.PutSecret(nref("orphan.payment", ports.UpstreamEncryptedSKey), secret.Take([]byte("gpg bytes")))
	})
	if err != nil {
		t.Fatalf("orphan: %v", err)
	}
	var quarantined bool
	if err := n.View(ctx, func(r ports.NamedReader) error {
		quarantined, _ = r.Exists(nref("orphan.payment", ports.UpstreamEncryptedSKey))
		return nil
	}); err != nil || !quarantined {
		t.Fatalf("the quarantined key is not found by its stem: %v %v", quarantined, err)
	}
	if l, _ := n.List(ctx); len(l.Entries) != 3 {
		t.Errorf("listing %+v", l.Entries)
	}
}

// spec: SPO-Xidentity-IF-001
func TestHomesAreFoundByIdentity(t *testing.T) {
	s, n, _ := newWS(t)
	pay := vkey(payT, "a")
	put(t, n, nref("alice", ports.AddrVKey), pay)
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.PutSecret(nref("alice", ports.AddrSKey), secret.Take([]byte(`{"cborHex":"5820aa"}`)))
	}); err != nil {
		t.Fatal(err)
	}
	homes, err := labels.NewIndex(s).Homes(ctx, idOf(t, custody.RolePayment, pay))
	if err != nil || len(homes) != 1 || !homes[0].HasSecret || homes[0].HasHardware {
		t.Fatalf("homes %+v %v", homes, err)
	}
	if homes[0].VKeyRef().Anchor != homes[0].Anchor {
		t.Error("the home does not carry the owner's anchor")
	}
}

type dirReader map[ports.NamedRef][]byte

func (d dirReader) Get(r ports.NamedRef) ([]byte, error) {
	b, ok := d[r]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return b, nil
}
func (d dirReader) Exists(r ports.NamedRef) (bool, error) { _, ok := d[r]; return ok, nil }

func derive(t *testing.T, d dirReader) *labels.Derived {
	t.Helper()
	var entries []ports.SourceEntry
	for r := range d {
		entries = append(entries, ports.SourceEntry{Ref: r})
	}
	out, err := labels.Derive(d, entries)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The residual case of the wallet anchor rule: a wallet made stake-only here, that
// later gained a payment key, is anchored by its stake key; the same keys in an
// upstream directory are anchored by the payment key. The import of the directory's
// owner is refused, showing both; merge, run by the operator, keeps this
// workspace's anchor and records the other as an alias, and only when the member
// sets are identical.
//
// spec: SPO-Xidentity-INV-011, SPO-Xidentity-IF-004
func TestMergeKeepsOneAnchorAndRecordsTheOtherAsAnAlias(t *testing.T) {
	s, n, _ := newWS(t)
	pay, stake := vkey(payT, "m pay"), vkey(stakeT, "m stake")
	put(t, n, nref("alice", ports.StakingVKey), stake) // made stake-only: anchored by the stake key
	put(t, n, nref("alice.payment", ports.AddrVKey), pay)
	src := derive(t, dirReader{nref("alice.payment", ports.AddrVKey): pay, nref("alice", ports.StakingVKey): stake})
	other, ok := src.Owner(identity.OwnerWallet, "alice")
	if !ok || other.Anchor != idOf(t, custody.RolePayment, pay) {
		t.Fatalf("the directory's wallet is anchored by %v", other.Anchor)
	}
	// the import of that owner is refused: its keys already belong to an owner here
	err := s.Update(ctx, func(w ports.Writer) error { return labels.CreateOwner(w, other) })
	if !errors.Is(err, labels.ErrMembership) || !strings.Contains(err.Error(), "alice") {
		t.Fatalf("the residual case: %v", err)
	}
	// differing member sets cannot merge
	partial := derive(t, dirReader{nref("alice.payment", ports.AddrVKey): pay})
	po, _ := partial.Owner(identity.OwnerWallet, "alice")
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Merge(w, identity.OwnerWallet, "alice", po) }); !errors.Is(err, labels.ErrMergeDiffers) {
		t.Fatalf("members differ: %v", err)
	}
	// identical member sets merge: the kept anchor stays, the other is an alias
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Merge(w, identity.OwnerWallet, "alice", other) }); err != nil {
		t.Fatal(err)
	}
	var owners []labels.Owner
	if err := s.View(ctx, func(r ports.Reader) error { var e error; owners, _, e = labels.OwnersOf(r); return e }); err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].Anchor != idOf(t, custody.RoleStake, stake) || len(owners[0].Record.Aliases) != 1 || owners[0].Record.Aliases[0] != other.Anchor {
		t.Fatalf("owners %+v", owners)
	}
	// a later import that carries the alias resolves to the kept owner: nothing to add
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.CreateOwner(w, other) }); err != nil {
		t.Fatalf("an owner with a recorded alias: %v", err)
	}
	if got, err := get(t, n, nref(other.Anchor.String(), ports.AddrVKey)); err != nil || string(got) != string(pay) {
		t.Errorf("the alias as a name: %v", err)
	}
	// a merge of the same anchor is nothing; an owner of another kind cannot merge
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Merge(w, identity.OwnerPool, "alice", other) }); err == nil {
		t.Error("a wallet merged as a pool")
	}
}

// A label is a plain name and never the text form of an identity: such a name
// resolves through membership, so a label spelled so would show one owner under
// another's name. Every write path of a label refuses it, and the check of every
// open reports a stored one.
//
// spec: SPO-Xidentity-INV-027
func TestALabelNameIsNeverTheFormOfAnIdentity(t *testing.T) {
	s, n, path := newWS(t)
	cold := vkey(coldT, "pool B")
	put(t, n, nref("a", ports.NodeVKey), vkey(coldT, "pool A"))
	put(t, n, nref("b", ports.NodeVKey), cold)
	spoof := idOf(t, custody.RolePoolCold, cold).String()
	// Rename
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Rename(w, identity.OwnerPool, "a", spoof) }); !errors.Is(err, labels.ErrLabelName) {
		t.Fatalf("the rename spoof: %v", err)
	}
	// every write path
	derived := labels.DerivedOwner{Kind: identity.OwnerPool, Name: spoof, Anchor: idOf(t, custody.RolePoolCold, vkey(coldT, "pool C"))}
	derived.Members = []identity.Member{{Role: identity.MemberCold, Identity: derived.Anchor}}
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.CreateOwner(w, derived) }); !errors.Is(err, labels.ErrLabelName) {
		t.Errorf("CreateOwner: %v", err)
	}
	if err := n.Update(ctx, func(w ports.NamedWriter) error { return w.Put(nref(spoof, ports.PendingUpdate), []byte("x")) }); !errors.Is(err, labels.ErrLabelName) {
		t.Errorf("a named record: %v", err)
	}
	for _, name := range []string{"key-hash:" + strings.Repeat("ab", 28), "vrf-key-hash:" + strings.Repeat("ab", 32)} {
		if err := labels.CheckLabelName(name); !errors.Is(err, labels.ErrLabelName) {
			t.Errorf("%q: %v", name, err)
		}
	}
	if pl, err := labels.PlanMigration([]labels.LegacyRecord{{Name: spoof, Kind: ports.PendingUpdate, Data: []byte("x")}}, labels.MigrationOptions{}); err != nil || len(pl.Problems) == 0 {
		t.Errorf("the migration plan wrote a label with the form of an identity: %v %v", err, pl)
	}
	// a stored label with such a name is reported by the check of every open
	bad := labels.Label{Group: "pool", Name: spoof, Anchor: idOf(t, custody.RolePoolCold, cold)}
	ref, _ := bad.Record()
	b, _ := bad.Encode()
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(ref, b) }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := sqlitestore.Open(path, secret.Take([]byte(pass))); !errors.Is(err, labels.ErrCorrupt) {
		t.Fatalf("open with a spoofed label stored: %v", err)
	}
}

// A provisional owner (records, no anchoring key) cannot be renamed: the error
// says to add the key first.
//
// spec: SPO-Xidentity-PRE-007
func TestAProvisionalOwnerCannotBeRenamed(t *testing.T) {
	s, n, _ := newWS(t)
	put(t, n, nref("p", ports.PoolDescriptor), []byte(`{"poolName":"p"}`))
	err := s.Update(ctx, func(w ports.Writer) error { return labels.Rename(w, identity.OwnerPool, "p", "q") })
	if err == nil || !strings.Contains(err.Error(), "no anchoring key") || !strings.Contains(err.Error(), "add its key first") {
		t.Fatalf("rename of a provisional owner: %v", err)
	}
}

// One key may be a member under two roles of one owner (a wallet whose payment
// and stake keys are one key), and may never be a member of two owners.
//
// spec: SPO-Xidentity-INV-028
func TestOneKeyUnderTwoRolesOfOneOwner(t *testing.T) {
	s, n, path := newWS(t)
	same := vkey(payT, "one key")
	put(t, n, nref("w.payment", ports.AddrVKey), same)
	put(t, n, nref("w", ports.StakingVKey), vkey(stakeT, "one key")) // the same verification key bytes under the stake type
	id := idOf(t, custody.RolePayment, same)
	var owners []labels.Owner
	if err := s.View(ctx, func(r ports.Reader) error { var e error; owners, _, e = labels.OwnersOf(r); return e }); err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 || owners[0].Anchor != id || len(owners[0].Manifest.Members()) != 2 {
		t.Fatalf("owners %+v", owners)
	}
	homes, err := labels.NewIndex(s).Homes(ctx, id)
	if err != nil || len(homes) != 2 {
		t.Fatalf("homes %+v %v", homes, err)
	}
	h, ok, _ := labels.NewIndex(s).RoleHistory(ctx, id)
	if !ok || !h.Has(custody.RolePayment) || !h.Has(custody.RoleStake) {
		t.Errorf("history %v", h.Roles())
	}
	if err := n.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(nref("other", ports.StakingVKey), vkey(stakeT, "one key"))
	}); !errors.Is(err, labels.ErrMembership) {
		t.Errorf("the same key in a second owner: %v", err)
	}
	s.Close()
	open(t, path) // the store opens
}

// The check of every open requires, for every manifest member with a role, a role
// history that has the role; the key index fails closed for a member without one.
//
// spec: SPO-Xidentity-INV-029
func TestAMemberWithoutARoleHistoryIsRefused(t *testing.T) {
	s, n, path := newWS(t)
	cold := vkey(coldT, "no history")
	put(t, n, nref("p", ports.NodeVKey), cold)
	id := idOf(t, custody.RolePoolCold, cold)
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Delete(ports.Ref{Anchor: id, Kind: ports.RoleHistory}) }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := labels.NewIndex(s).RoleHistory(ctx, id); err == nil {
		t.Error("a member without a history was answered with none")
	}
	s.Close()
	if _, err := sqlitestore.Open(path, secret.Take([]byte(pass))); !errors.Is(err, labels.ErrCorrupt) {
		t.Fatalf("open: %v", err)
	}
}

// The alias branch of the name lookup checks the kind of owner like the others.
//
// spec: SPO-Xidentity-INV-019
func TestAnAliasResolvesOnlyAsAnOwnerOfItsKind(t *testing.T) {
	s, n, _ := newWS(t)
	pay, stake := vkey(payT, "al pay"), vkey(stakeT, "al stake")
	put(t, n, nref("alice", ports.StakingVKey), stake)
	put(t, n, nref("alice.payment", ports.AddrVKey), pay)
	src := derive(t, dirReader{nref("alice.payment", ports.AddrVKey): pay, nref("alice", ports.StakingVKey): stake})
	other, _ := src.Owner(identity.OwnerWallet, "alice")
	if err := s.Update(ctx, func(w ports.Writer) error { return labels.Merge(w, identity.OwnerWallet, "alice", other) }); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, n, nref(other.Anchor.String(), ports.AddrVKey)); err != nil {
		t.Fatalf("the alias as a wallet: %v", err)
	}
	if _, err := get(t, n, nref(other.Anchor.String(), ports.NodeVKey)); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("the alias of a wallet read as a pool: %v", err)
	}
}

// Of records that collide on one reference, the one whose stem sorts first stays
// at the real reference, whatever order the store lists them in (random record id
// order), and identical ones merge into it. Differing ones refuse; only wallets
// collide (`<w>` and `<w>.payment`), so the refusal cannot be quarantined.
//
// spec: SPO-Xidentity-PRE-006
func TestCollisionKeepsTheFirstStemAtTheRealReference(t *testing.T) {
	k := vkey(payT, "gina")
	for _, order := range [][]int{{0, 1}, {1, 0}} {
		base := []labels.LegacyRecord{{Name: "gina", Kind: ports.AddrVKey, Data: k}, {Name: "gina.payment", Kind: ports.AddrVKey, Data: k}}
		recs := []labels.LegacyRecord{base[order[0]], base[order[1]]}
		pl, err := labels.PlanMigration(recs, labels.MigrationOptions{Same: func(a, b int) bool { return bytes.Equal(recs[a].Data, recs[b].Data) }})
		if err != nil || len(pl.Problems) != 0 {
			t.Fatalf("%v %v", err, pl.Problems)
		}
		for i, r := range recs {
			if pl.Drop[i] != (r.Name == "gina.payment") {
				t.Errorf("order %v: record %q dropped=%v; the stem that sorts first must stay", order, r.Name, pl.Drop[i])
			}
		}
	}
	diff := []labels.LegacyRecord{{Name: "gina", Kind: ports.AddrVKey, Data: k}, {Name: "gina.payment", Kind: ports.AddrVKey, Data: vkey(payT, "other")}}
	pl, _ := labels.PlanMigration(diff, labels.MigrationOptions{Same: func(a, b int) bool { return bytes.Equal(diff[a].Data, diff[b].Data) }, Quarantine: map[string]bool{"gina": true}})
	if len(pl.Problems) == 0 {
		t.Error("differing records of a wallet were not refused")
	}
}
