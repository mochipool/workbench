// Package partyrig builds workspaces for the multi-party tests: each party is
// a directory with its own store, its own party identity and its own keys,
// over the real adapters (plainstore, envelope, partystore, native). Only what
// is outside the process is faked: the chain tip and the clock.
package partyrig

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// Magic is the network magic of the rig (preview).
const Magic = 2

// Clock is a settable clock shared by the parties of a test.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts at t.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// Now implements ports.Clock.
func (c *Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

// Advance moves the clock on.
func (c *Clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// Chain is a settable tip and the genesis that goes with it: one-second
// slots from Start.
type Chain struct {
	mu    sync.Mutex
	slot  uint64
	Start time.Time
	// Down makes the tip reader fail, so the clock decides.
	Down bool
}

// NewChain starts at slot 1000 at the clock's time.
func NewChain(now time.Time) *Chain {
	return &Chain{slot: 1000, Start: now.Add(-1000 * time.Second)}
}

// SetSlot moves the tip.
func (c *Chain) SetSlot(s uint64) { c.mu.Lock(); c.slot = s; c.mu.Unlock() }

// Source implements ports.ChainSource.
func (c *Chain) Source() chain.Source { return "rig chain" }

// Tip implements ports.TipReader.
func (c *Chain) Tip(context.Context) (chain.Tip, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Down {
		return chain.Tip{}, context.DeadlineExceeded
	}
	return chain.Tip{Slot: c.slot, Epoch: 7}, nil
}

// Genesis implements ports.GenesisReader.
func (c *Chain) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{SystemStart: c.Start, SlotLength: time.Second, NetworkMagic: Magic}, nil
}

// Workspace is one party: a directory, its store and its identity.
type Workspace struct {
	T        *testing.T
	Name     string
	Dir      string
	Store    *plainstore.Store
	Kit      envelope.Kit
	Registry partystore.Registry
	Replay   partystore.Replay
	Clock    *Clock
	Chain    *Chain
	Identity parties.InitResult
	// Owned, Resolver and Addresses are the signer's own view of its funds
	// (SPO-Xparty-PR-002): the credentials it holds, a resolver of inputs by
	// reference and the address inspector. The zero values are a signer that
	// owns nothing and has no chain view of its own.
	Owned     party.OwnedKeys
	Resolver  ports.UtxoResolver
	Addresses ports.AddressInspector
	// Gate is the re-authentication of Approve; the default approves and
	// counts.
	Gate *Gate
	keys map[[28]byte]custody.KeyRef
	mu   sync.Mutex
}

// ForeignInputs is a signer's own chain view in which every input exists and
// is at somebody else's enterprise key address: no input is the signer's, none
// is a script's. It is the rig's default so that a request that came over a
// network, which needs every input resolved (SPO-Xparty-PRE-007), is not
// refused for that reason alone in the tests of something else. Set
// Workspace.Resolver to nil for a signer with no chain view.
type ForeignInputs struct{}

// Source implements ports.UtxoResolver.
func (ForeignInputs) Source() chain.Source { return "the rig's foreign view" }

// ResolveUtxos implements ports.UtxoResolver.
func (ForeignInputs) ResolveUtxos(_ context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	b := append([]byte{0x60}, make([]byte, 28)...)
	for i := 1; i < len(b); i++ {
		b[i] = 0xee
	}
	addr, err := chain.Bech32Encode("addr_test", b)
	if err != nil {
		return nil, err
	}
	out := map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]{}
	for _, r := range refs {
		out[r] = chain.Value(chain.ResolvedUtxo{Address: chain.Address(addr), Lovelace: 10_000_000})
	}
	return out, nil
}

// Gate is a test ports.ApprovalGate: it counts the calls and refuses when
// Deny is set.
type Gate struct {
	mu    sync.Mutex
	Calls []custody.KeyRef
	Deny  bool
}

// Reauthenticate implements ports.ApprovalGate.
func (g *Gate) Reauthenticate(_ context.Context, key custody.KeyRef, _ [32]byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Calls = append(g.Calls, key)
	if g.Deny {
		return errors.New("the operator did not authenticate")
	}
	return nil
}

// Count is how many times the gate was asked.
func (g *Gate) Count() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.Calls) }

// New creates the workspace and its party identity.
func New(t *testing.T, name string, clock *Clock, ch *Chain) *Workspace {
	t.Helper()
	return NewWithNode(t, name, clock, ch, nil)
}

// NewWithNode is New with the tailcat node public key published in the
// identity document.
func NewWithNode(t *testing.T, name string, clock *Clock, ch *Chain, node *party.NodeKey) *Workspace {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	w := &Workspace{T: t, Name: name, Dir: dir, Store: st, Kit: envelope.Kit{Store: st, Vault: st}, Clock: clock, Chain: ch,
		Gate: &Gate{}, keys: map[[28]byte]custody.KeyRef{}, Addresses: native.Ledger{}, Resolver: ForeignInputs{}}
	res, err := parties.InitIdentity{Store: st, Kit: w.Kit, Clock: clock}.Run(context.Background(), parties.InitRequest{Label: name, Node: node})
	if err != nil {
		t.Fatal(err)
	}
	w.Identity = res
	return w
}

// Node is the wiring both roles share.
func (w *Workspace) Node() multisig.Node {
	return multisig.Node{Store: w.Store, Parties: w.Registry, Replay: w.Replay, Kit: w.Kit, Viewer: native.TxViewer{}, Clock: w.Clock,
		Chain: multisig.Chain{Tip: w.Chain, Genesis: w.Chain}}
}

// Rotate replaces this workspace's identity (SPO-Xparty-IF-008) and updates
// Identity to the new one, so that Seal and the other helpers that name a
// workspace by its identity find the current one.
func (w *Workspace) Rotate(label string) multisig.RotationDone {
	w.T.Helper()
	done, err := w.Node().RotateIdentity(context.Background(), label)
	if err != nil {
		w.T.Fatal(err)
	}
	w.Identity = parties.InitResult{Fingerprint: done.New, Document: done.Document}
	return done
}

// SealTo seals body from this workspace's identity to the identity it has
// enrolled as to, valid for an hour: for tests of what a peer may send.
func (w *Workspace) SealTo(t *testing.T, to *Workspace, body party.Body) []byte {
	t.Helper()
	return Seal(t, w, to, body, time.Hour)
}

// Coordinator is the coordinator role of this workspace.
func (w *Workspace) Coordinator() multisig.Coordinator {
	return multisig.Coordinator{Node: w.Node(), TxIDs: native.Ledger{}, NetworkMagic: Magic}
}

// Signer is the signer role of this workspace.
func (w *Workspace) Signer() multisig.Signer {
	var res multisig.OwnResolver
	if w.Resolver != nil {
		res = multisig.OwnProvider(w.Resolver) // the rig's resolver is this signer's own
	}
	return multisig.Signer{Node: w.Node(), Signers: native.Signers{Vault: w.Store}, Keys: w, NetworkMagic: Magic,
		Owned: w.Owned, Resolver: res, Addresses: w.Addresses, Gate: w.Gate}
}

// Outbox is this workspace's outbox.
func (w *Workspace) Outbox() multisig.Outbox { return w.Node().Outbox() }

// FindKey implements multisig.KeyFinder over the keys added with AddKey.
func (w *Workspace) FindKey(_ context.Context, role custody.Role, hash [28]byte) (custody.KeyRef, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	k, ok := w.keys[hash]
	return k, ok && k.Role == role, nil
}

// AddKey makes a key of the role (stake, payment or pool-cold) named owner in
// the vault and returns its key hash.
func (w *Workspace) AddKey(role custody.Role, owner string) txbuild.KeyHash {
	w.T.Helper()
	ctx := context.Background()
	var kp ports.KeyPair
	var err error
	var vk, sk ports.Kind
	switch role {
	case custody.RoleStake:
		kp, err = native.SoftwareKeys{}.GenerateStake(ctx)
		vk, sk = ports.StakingVKey, ports.StakingSKey
	case custody.RolePayment:
		kp, err = native.SoftwareKeys{}.GeneratePayment(ctx)
		vk, sk = ports.AddrVKey, ports.AddrSKey
	case custody.RolePoolCold:
		kp, err = native.SoftwareKeys{}.GenerateCold(ctx)
		vk, sk = ports.NodeVKey, ports.NodeSKey
	default:
		w.T.Fatalf("no key of role %s", role)
	}
	if err != nil {
		w.T.Fatal(err)
	}
	defer kp.SKey.Destroy()
	if err := w.Store.Update(ctx, func(wr ports.Writer) error {
		if err := wr.Put(ports.Ref{Name: owner, Kind: vk}, kp.VKey); err != nil {
			return err
		}
		return wr.PutSecret(ports.Ref{Name: owner, Kind: sk}, kp.SKey)
	}); err != nil {
		w.T.Fatal(err)
	}
	e, err := pool.ParseEnvelope(kp.VKey)
	if err != nil {
		w.T.Fatal(err)
	}
	raw, err := e.Key32()
	if err != nil {
		w.T.Fatal(err)
	}
	h := txbuild.HashKey(raw)
	w.mu.Lock()
	w.keys[h] = custody.KeyRef{Role: role, Holder: custody.HolderVault, Owner: owner}
	w.mu.Unlock()
	return h
}

// Enroll records other as a party named name here, with the generous scope
// the older tests were written against: every key role a test asks for, and
// the given pools. Tests of the scope itself use EnrollScoped.
func (w *Workspace) Enroll(other *Workspace, name string, roles []party.Role, pools []string) party.Party {
	w.T.Helper()
	return w.EnrollScoped(other, name, roles, party.Scope{KeyRoles: []custody.Role{custody.RoleStake, custody.RolePayment, custody.RolePoolCold}, Pools: pools, Unscoped: len(pools) == 0})
}

// EnrollScoped records other as a party named name here with the scope an
// operator names, typing the first four groups of its fingerprint as an
// operator would after hearing them read out.
func (w *Workspace) EnrollScoped(other *Workspace, name string, roles []party.Role, scope party.Scope) party.Party {
	w.T.Helper()
	ctx := context.Background()
	doc, err := parties.ExportIdentity{Store: other.Store, Kit: other.Kit}.Run(ctx)
	if err != nil {
		w.T.Fatal(err)
	}
	uc := parties.Enroll{Store: w.Store, Kit: w.Kit, Registry: w.Registry, Clock: w.Clock}
	if _, err := uc.Inspect(doc.Document, roles); err != nil {
		w.T.Fatal(err)
	}
	p, err := uc.Run(ctx, parties.EnrollRequest{Document: doc.Document, Name: name, Roles: roles, KeyRoles: scope.KeyRoles, Pools: scope.Pools,
		Unscoped: scope.Unscoped, Confirmation: doc.Fingerprint.String()[:19]})
	if err != nil {
		w.T.Fatal(err)
	}
	return p
}

// SetScope changes the scope of the party named name, as an operator narrowing
// what a coordinator may ask.
func (w *Workspace) SetScope(name string, scope party.Scope) {
	w.T.Helper()
	if err := w.Store.Update(context.Background(), func(wr ports.Writer) error {
		_, err := w.Registry.SetScope(wr, name, scope)
		return err
	}); err != nil {
		w.T.Fatal(err)
	}
}

// Revoke revokes the party named name, with the coordinator hook when this
// workspace is a coordinator.
func (w *Workspace) Revoke(name string) party.Party {
	w.T.Helper()
	c := w.Coordinator()
	p, err := parties.Revoke{Store: w.Store, Registry: w.Registry, Clock: w.Clock, Hooks: []func(ports.Writer, party.Party) error{c.OnRevoke}}.
		Run(context.Background(), name)
	if err != nil {
		w.T.Fatal(err)
	}
	return p
}

// Events reads this workspace's audit log.
func (w *Workspace) Events() []parties.Event {
	w.T.Helper()
	var es []parties.Event
	if err := w.Store.View(context.Background(), func(r ports.Reader) error {
		var err error
		es, err = multisig.Events(r)
		return err
	}); err != nil {
		w.T.Fatal(err)
	}
	return es
}

// Noise reads this workspace's ring of unauthenticated refusals and how many
// there have been.
func (w *Workspace) Noise() ([]parties.Event, uint64) {
	w.T.Helper()
	var es []parties.Event
	var n uint64
	if err := w.Store.View(context.Background(), func(r ports.Reader) error {
		var err error
		es, n, err = multisig.Noise(r)
		return err
	}); err != nil {
		w.T.Fatal(err)
	}
	return es, n
}

// HasEvent reports whether the log has an event of the kind whose reason
// contains the text.
func (w *Workspace) HasEvent(kind, reasonContains string) bool {
	for _, e := range w.Events() {
		if e.Kind == kind && contains(e.Reason, reasonContains) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return sub == ""
}

// Body builds a real transaction body with the native ledger: one input, a
// payment output, the change, and the certificates given.
func Body(t *testing.T, ttl uint64, certs ...stake.Certificate) txbuild.TxBody {
	t.Helper()
	spec := txbuild.BodySpec{
		Inputs:  []chain.Utxo{{TxID: chain.TxID{1}, Index: 0, Lovelace: 100_000_000}},
		Outputs: []txbuild.Output{{Address: "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0", Lovelace: 5_000_000}},
		Fee:     200_000, TTL: ttl,
	}
	spec.Certificates = certs
	b, err := native.Ledger{}.BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Seal seals body from one workspace's identity to the identity it has
// enrolled as to, at the workspace clock's time.
func Seal(t *testing.T, from, to *Workspace, body party.Body, expires time.Duration) []byte {
	t.Helper()
	ctx := context.Background()
	local, err := from.Kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Destroy()
	var rcpt party.Party
	if err := from.Store.View(ctx, func(r ports.Reader) error {
		ps, err := from.Registry.List(r)
		for _, p := range ps {
			if p.Fingerprint == to.Identity.Fingerprint {
				rcpt = p
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rcpt.Name == "" {
		t.Fatalf("%s has not enrolled %s", from.Name, to.Name)
	}
	now := from.Clock.Now()
	env, _, err := local.Seal(rcpt.Identity, body, now, now.Add(expires))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// AddKnownKey tells the workspace's KeyFinder about a key that is already in
// its vault (a key the test wrote as files).
func (w *Workspace) AddKnownKey(role custody.Role, owner string, hash [28]byte) {
	w.mu.Lock()
	w.keys[hash] = custody.KeyRef{Role: role, Holder: custody.HolderVault, Owner: owner}
	w.mu.Unlock()
}
