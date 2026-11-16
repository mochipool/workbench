package parties_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var ctx = context.Background()

type clock struct{ t time.Time }

func (c clock) Now() time.Time { return c.t }

type ws struct {
	t     *testing.T
	store *fsstore.Store
	kit   envelope.Kit
	reg   partystore.Registry
	clk   clock
}

func newWS(t *testing.T) *ws {
	st, err := fsstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &ws{t: t, store: st, kit: envelope.Kit{Store: st, Vault: st}, clk: clock{time.Unix(1_800_000_000, 0).UTC()}}
}

func (w *ws) init(label string) parties.InitResult {
	w.t.Helper()
	r, err := parties.InitIdentity{Store: w.store, Kit: w.kit, Clock: w.clk}.Run(ctx, parties.InitRequest{Label: label})
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *ws) enroll() parties.Enroll {
	return parties.Enroll{Store: w.store, Kit: w.kit, Registry: w.reg, Clock: w.clk}
}

func typed(fp party.Fingerprint) string { return fp.String()[:19] }

// The identity is made once; its secret is in the vault and nowhere in the
// public document, and it is never replaced.
// spec: SPO-Xparty-INV-001, SPO-Xparty-INV-003, SPO-Xparty-IF-001, SPO-Xparty-SEC-001
func TestInitAndExport(t *testing.T) {
	a := newWS(t)
	if _, err := (parties.ExportIdentity{Store: a.store, Kit: a.kit}).Run(ctx); !errors.Is(err, parties.ErrNoIdentity) {
		t.Fatalf("export before init: %v", err)
	}
	res := a.init("alpha")
	if _, err := (parties.InitIdentity{Store: a.store, Kit: a.kit, Clock: a.clk}).Run(ctx, parties.InitRequest{Label: "again"}); !errors.Is(err, parties.ErrIdentityExists) {
		t.Fatalf("second init: %v", err)
	}
	exp, err := parties.ExportIdentity{Store: a.store, Kit: a.kit}.Run(ctx)
	if err != nil || !bytes.Equal(exp.Document, res.Document) || exp.Fingerprint != res.Fingerprint {
		t.Fatalf("export = %v", err)
	}
	// The secret is read only through the vault and is not in the document.
	if err := a.store.View(ctx, func(r ports.Reader) error {
		if _, err := r.Get(ports.Ref{Name: "local", Kind: ports.PartyKeys}); !errors.Is(err, ports.ErrSecretKind) {
			t.Errorf("the keys are readable as a plain record: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	keys, err := a.store.Open(ctx, ports.Ref{Name: "local", Kind: ports.PartyKeys})
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Destroy()
	keys.Use(func(k []byte) error {
		if bytes.Contains(res.Document, k[:32]) || bytes.Contains(res.Document, k[32:]) {
			t.Error("a private key is in the public document")
		}
		return nil
	})
	doc, err := a.kit.ParseDocument(res.Document)
	if err != nil || doc.Verify() != nil || doc.Identity.Node != nil || doc.Identity.Label != "alpha" {
		t.Errorf("document %+v %v", doc.Identity, err)
	}
	// The local identity loads and seals.
	l, err := a.kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if l.Identity().Fingerprint() != res.Fingerprint {
		t.Error("the loaded identity is another")
	}
	l.Destroy()
}

// spec: SPO-Xparty-PRE-001, SPO-Xparty-PR-001, SPO-Xparty-OUT-001, SPO-Xparty-INV-004, SPO-Xparty-IF-002
func TestEnroll(t *testing.T) {
	a, b := newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	uc := a.enroll()
	pool := chain.PoolID{1, 2, 3}
	good := parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner, party.RoleCoordinator},
		KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{pool.Bech32()}, Confirmation: typed(rb.Fingerprint)}

	list := func() []party.Party {
		ps, err := parties.List{Store: a.store, Registry: a.reg}.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return ps
	}
	refused := func(name string, mod func(*parties.EnrollRequest), want error) {
		t.Helper()
		req := good
		mod(&req)
		if _, err := uc.Run(ctx, req); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", name, err, want)
		}
		if len(list()) != 0 {
			t.Errorf("%s: a party was recorded", name)
		}
	}
	// PRE-001: a document whose signature does not verify.
	tampered := append([]byte(nil), rb.Document...)
	tampered[len(tampered)-1] ^= 1
	refused("tampered document", func(r *parties.EnrollRequest) { r.Document = tampered }, party.ErrDocumentSignature)
	if _, err := uc.Inspect(tampered, nil); !errors.Is(err, party.ErrDocumentSignature) {
		t.Errorf("Inspect shows a document that does not verify: %v", err)
	}
	// PR-001: the first four groups, typed; nothing else passes, nothing skips it.
	fp := rb.Fingerprint.String()
	refused("no confirmation", func(r *parties.EnrollRequest) { r.Confirmation = "" }, party.ErrConfirmation)
	refused("two groups", func(r *parties.EnrollRequest) { r.Confirmation = fp[:9] }, party.ErrConfirmation)
	refused("a wrong group", func(r *parties.EnrollRequest) { r.Confirmation = fp[:15] + "aaaa" }, party.ErrConfirmation)
	refused("another party's groups", func(r *parties.EnrollRequest) {
		r.Confirmation = typed(party.Fingerprint{1})
	}, party.ErrConfirmation)
	refused("a bad role", func(r *parties.EnrollRequest) { r.Roles = []party.Role{"admin"} }, party.ErrInvalidEnrollment)
	refused("no role", func(r *parties.EnrollRequest) { r.Roles = nil }, party.ErrInvalidEnrollment)
	refused("a pool that is not a pool id", func(r *parties.EnrollRequest) { r.Pools = []string{"mypool"} }, parties.ErrBadPool)
	// INV-010: the scope is named, never defaulted.
	refused("no key roles", func(r *parties.EnrollRequest) { r.KeyRoles = nil }, party.ErrInvalidEnrollment)
	refused("no pool and not unscoped", func(r *parties.EnrollRequest) { r.Pools = nil }, party.ErrInvalidEnrollment)
	refused("a bad key role", func(r *parties.EnrollRequest) { r.KeyRoles = []custody.Role{"root"} }, party.ErrInvalidEnrollment)
	refused("a name with a slash", func(r *parties.EnrollRequest) { r.Name = "a/b" }, party.ErrInvalidEnrollment)

	// What the operator is shown first.
	in, err := uc.Inspect(rb.Document, good.Roles)
	if err != nil || in.LastGroup != rb.Fingerprint.Tail() || in.Label != "beta" || len(in.Roles) != 2 {
		t.Fatalf("inspect = %+v, %v", in, err)
	}
	// PR-001: nothing of what must be typed is in what is shown.
	if shown := fmt.Sprintf("%+v %v", in, in); strings.Contains(shown, fp[:19]) || strings.Contains(shown, fp[:4]) || strings.Contains(in.LastGroup, fp[:4]) {
		t.Fatalf("the display holds the groups to be typed: %s", shown)
	}
	if len(in.LastGroup) != 19 || in.LastGroup != fp[20:] {
		t.Fatalf("the display is not the last four groups: %q of %q", in.LastGroup, fp)
	}
	// The groups may be typed with capitals and spaces.
	good.Confirmation = strings.ToUpper(strings.ReplaceAll(typed(rb.Fingerprint), "-", " "))
	p, err := uc.Run(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != party.StateActive || p.Fingerprint != rb.Fingerprint || p.Name != "beta" || len(p.Roles) != 2 || !slices.Contains(p.Scope.Pools, pool.Bech32()) || p.EnrolledAt.IsZero() {
		t.Errorf("record %+v", p)
	}
	// OUT-001: stored; and enrollment is an audit event.
	if got := list(); len(got) != 1 || got[0].Name != "beta" {
		t.Errorf("list %+v", got)
	}
	var evs []parties.Event
	a.store.View(ctx, func(r ports.Reader) error { evs, _ = parties.Events(r); return nil })
	if len(evs) != 1 || evs[0].Kind != "party-enrolled" || evs[0].Peer != rb.Fingerprint.String() {
		t.Errorf("events %+v", evs)
	}
	// INV-004: mutual, not automatic: beta has not enrolled alpha.
	if ps, _ := (parties.List{Store: b.store, Registry: b.reg}).Run(ctx); len(ps) != 0 {
		t.Errorf("enrolling made the other side enroll: %+v", ps)
	}
	// The same identity or the same name again.
	if _, err := uc.Run(ctx, good); !errors.Is(err, party.ErrAlreadyEnrolled) {
		t.Errorf("same identity: %v", err)
	}
	c := newWS(t)
	rc := c.init("gamma")
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: rc.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, KeyRoles: []custody.Role{custody.RoleStake}, Unscoped: true, Confirmation: typed(rc.Fingerprint)}); !errors.Is(err, party.ErrNameTaken) {
		t.Errorf("same name: %v", err)
	}
	// A pool given as 56 hex characters is stored as its bech32 id.
	hexPool := strings.Repeat("0a", 28)
	p2, err := uc.Run(ctx, parties.EnrollRequest{Document: rc.Document, Name: "gamma", Roles: []party.Role{party.RoleSigner}, KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{hexPool},
		Confirmation: typed(rc.Fingerprint)})
	if err != nil || !slices.Contains(p2.Scope.Pools, chain.PoolID{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}.Bech32()) {
		t.Errorf("hex pool: %+v %v", p2, err)
	}
	// A workspace does not enroll itself.
	ra, _ := (parties.ExportIdentity{Store: a.store, Kit: a.kit}).Run(ctx)
	if _, err := uc.Run(ctx, parties.EnrollRequest{Document: ra.Document, Name: "me", Roles: []party.Role{party.RoleMachine}, Confirmation: typed(ra.Fingerprint)}); !errors.Is(err, parties.ErrOwnIdentity) {
		t.Errorf("own identity: %v", err)
	}
}

// spec: SPO-Xparty-IF-003, SPO-Xparty-INV-005, SPO-Xparty-OUT-004
func TestRevoke(t *testing.T) {
	a, b := newWS(t), newWS(t)
	a.init("alpha")
	rb := b.init("beta")
	if _, err := a.enroll().Run(ctx, parties.EnrollRequest{Document: rb.Document, Name: "beta", Roles: []party.Role{party.RoleSigner}, KeyRoles: []custody.Role{custody.RoleStake}, Unscoped: true, Confirmation: typed(rb.Fingerprint)}); err != nil {
		t.Fatal(err)
	}
	uc := parties.Revoke{Store: a.store, Registry: a.reg, Clock: a.clk}
	// A hook that fails rolls everything back: the party stays active.
	boom := errors.New("boom")
	failing := uc
	failing.Hooks = []func(ports.Writer, party.Party) error{func(ports.Writer, party.Party) error { return boom }}
	if _, err := failing.Run(ctx, "beta"); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if p, _ := a.reg.ByName(readerOf(a), "beta"); !p.Active() {
		t.Fatal("a failed revocation left the party revoked")
	}
	var hooked party.Party
	uc.Hooks = []func(ports.Writer, party.Party) error{func(_ ports.Writer, p party.Party) error { hooked = p; return nil }}
	p, err := uc.Run(ctx, "beta")
	if err != nil || p.State != party.StateRevoked || hooked.Name != "beta" {
		t.Fatalf("revoke = %+v, %v", p, err)
	}
	if _, err := uc.Run(ctx, "beta"); !errors.Is(err, party.ErrAlreadyRevoked) {
		t.Errorf("revoke twice: %v", err)
	}
	if _, err := uc.Run(ctx, "nobody"); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("revoke unknown: %v", err)
	}
	var evs []parties.Event
	a.store.View(ctx, func(r ports.Reader) error { evs, _ = parties.Events(r); return nil })
	if len(evs) != 2 || evs[1].Kind != "party-revoked" {
		t.Errorf("events %+v", evs)
	}
}

func readerOf(w *ws) ports.Reader {
	var out ports.Reader
	w.store.View(ctx, func(r ports.Reader) error { out = r; return nil })
	return out
}

// Two logs: garbage that failed before the signature step cannot push a
// security event out; security events are evicted only by security events.
// spec: SPO-Xparty-INV-023
func TestEventLogsAreSeparate(t *testing.T) {
	a := newWS(t)
	// A full security log, written directly: appending MaxSecurityEvents
	// events one by one rewrites the record each time.
	seed := make([]parties.Event, parties.MaxSecurityEvents)
	for i := range seed {
		seed[i] = parties.Event{At: a.clk.t, Kind: "security", Slot: i}
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: "log", Kind: ports.MultisigEvents}, raw) // also the older, single-list form
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3*parties.MaxNoiseEvents; i++ {
		if err := a.store.Update(ctx, func(w ports.Writer) error {
			return parties.AppendNoise(w, parties.Event{At: a.clk.t, Kind: "envelope-refused", Slot: i})
		}); err != nil {
			t.Fatal(err)
		}
	}
	var evs, ring []parties.Event
	var total uint64
	a.store.View(ctx, func(r ports.Reader) error {
		evs, _ = parties.Events(r)
		ring, total, _ = parties.Noise(r)
		return nil
	})
	if len(evs) != parties.MaxSecurityEvents || evs[0].Slot != 0 {
		t.Fatalf("noise evicted security events: %d left, first slot %d", len(evs), evs[0].Slot)
	}
	if len(ring) != parties.MaxNoiseEvents || ring[len(ring)-1].Slot != 3*parties.MaxNoiseEvents-1 || total != 3*parties.MaxNoiseEvents {
		t.Fatalf("noise ring %d, last %d, total %d", len(ring), ring[len(ring)-1].Slot, total)
	}
	// A security event evicts the oldest security event, and only that.
	if err := a.store.Update(ctx, func(w ports.Writer) error {
		return parties.AppendEvent(w, parties.Event{At: a.clk.t, Kind: "security", Slot: -1})
	}); err != nil {
		t.Fatal(err)
	}
	a.store.View(ctx, func(r ports.Reader) error { evs, _ = parties.Events(r); ring, _, _ = parties.Noise(r); return nil })
	if len(evs) != parties.MaxSecurityEvents || evs[0].Slot != 1 || evs[len(evs)-1].Slot != -1 || len(ring) != parties.MaxNoiseEvents {
		t.Fatalf("eviction: %d events, first %d, last %d, ring %d", len(evs), evs[0].Slot, evs[len(evs)-1].Slot, len(ring))
	}
}
