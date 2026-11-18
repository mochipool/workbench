package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// Obligation 1: the signer's address inspector is the one the root wired for
// the party stack, always. A kit without one is a configuration error, not a
// refusal of a request; an environment without an inspector of its own does not
// matter.
//
// spec: SPO-Xparty-PR-004, SPO-Xparty-PR-002
func TestObligation1AddressInspectorIsAlwaysTheKits(t *testing.T) {
	s := newPscene(t)
	file := s.request("register mypool")
	f := s.bob
	// The environment's own inspector is gone: the signer does not use it.
	f.edit = func(env *Env, k *PartyKit) { env.AddressInspector = nil }
	id := func() string {
		f.must(f.term(), "party", "inbox", "import", file)
		return f.must(f.term(), "party", "requests")[:32]
	}()
	if out := f.must(f.term(), "party", "review", id); !strings.Contains(out, "Whose money moves") {
		t.Fatalf("review without the environment's inspector:\n%s", out)
	}
	// The kit has none: a configuration error, from every command that builds a
	// signer, before any request is touched.
	f.edit = func(env *Env, k *PartyKit) { k.Addresses = nil }
	before := len(f.events())
	for _, args := range [][]string{{"party", "requests"}, {"party", "review", id}, {"party", "approve", id}, {"party", "refuse", id},
		{"party", "inbox", "import", file}} {
		_, err := f.run(f.term("y"), args...)
		if !errors.Is(err, multisig.ErrNoAddressInspector) || !strings.Contains(err.Error(), "configuration error") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if after := len(f.events()); after != before {
		t.Errorf("a configuration error was recorded as events: %v", f.events()[before:])
	}
	// The domain's own error, wherever it comes from, is a configuration error.
	if err := mapSignerErr(multisig.ErrNoAddressInspector); !errors.Is(err, multisig.ErrNoAddressInspector) || !strings.Contains(err.Error(), "not a refusal of the request") {
		t.Errorf("mapSignerErr: %v", err)
	}
}

// Obligation 2: Owned and the keys held are the store's own, read from the
// store: payment and stake key hashes of keys that have a signing key here (or
// a hardware file), nothing a coordinator supplies, and not a verification key
// that is only a copy.
//
// spec: SPO-Xparty-PR-002
func TestObligation2OwnedIsTheStoresOwnKeysOnly(t *testing.T) {
	clock := partyrig.NewClock(partyT0)
	ch := partyrig.NewChain(clock.Now())
	w := partyrig.New(t, "me", clock, ch)
	stakeH := w.AddKey(custody.RoleStake, "alice")
	payH := w.AddKey(custody.RolePayment, "pay")
	coldH := w.AddKey(custody.RolePoolCold, "mypool")
	// A verification key with no signing key here (somebody else's key that
	// was only copied in) is not held.
	other := partyrig.New(t, "other", clock, ch)
	otherH := other.AddKey(custody.RoleStake, "stranger")
	var vk []byte
	if err := other.Store.View(context.Background(), func(r ports.NamedReader) error {
		var err error
		vk, err = r.Get(ports.NamedRef{Name: "stranger", Kind: ports.StakingVKey})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Store.Update(context.Background(), func(wr ports.NamedWriter) error {
		return wr.Put(ports.NamedRef{Name: "copy", Kind: ports.StakingVKey}, vk)
	}); err != nil {
		t.Fatal(err)
	}
	d, err := loadStoreKeys(context.Background(), w.Store)
	if err != nil {
		t.Fatal(err)
	}
	o := d.Owned()
	if len(o.Stake) != 1 || o.Stake[0] != [28]byte(stakeH) || len(o.Payment) != 1 || o.Payment[0] != [28]byte(payH) {
		t.Fatalf("owned %+v", o)
	}
	if o.OwnsStake([28]byte(otherH)) {
		t.Error("a copied verification key is owned")
	}
	for role, h := range map[custody.Role]txbuildHash{custody.RoleStake: stakeH, custody.RolePayment: payH, custody.RolePoolCold: coldH} {
		k, ok, err := d.FindKey(context.Background(), role, [28]byte(h))
		if err != nil || !ok || k.Role != role || k.Identity.IsZero() {
			t.Errorf("%s: %+v %v %v", role, k, ok, err)
		}
	}
	if _, ok, _ := d.FindKey(context.Background(), custody.RoleStake, [28]byte(otherH)); ok {
		t.Error("a key that is not held was found")
	}
	// The role must match: the stake key's hash is not a payment key.
	if _, ok, _ := d.FindKey(context.Background(), custody.RolePayment, [28]byte(stakeH)); ok {
		t.Error("a stake key answered for the payment role")
	}
	// The pool cold key is held but never owned as funds.
	if o.OwnsPayment([28]byte(coldH)) || o.OwnsStake([28]byte(coldH)) {
		t.Error("the cold key is owned as a payment or stake key")
	}
	// The command tree builds the same from the same store.
	src, _ := os.ReadFile("party_signer.go")
	if !strings.Contains(string(src), "Owned: dir.Owned()") || strings.Contains(string(src), "Owned: party.OwnedKeys{") {
		t.Error("the signer's Owned is not the store's")
	}
}

type txbuildHash = [28]byte

// Obligation 3: the resolver is the operator's own provider or an offline
// snapshot the operator named for the purpose, and a path that is part of the
// party store, an inbox or outbox, a link, or not the operator's alone is
// refused.
//
// spec: SPO-Xparty-PR-005, SPO-Xparty-PRE-007
func TestObligation3ResolverIsOwnProviderOrANamedCleanSnapshot(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	tmp := t.TempDir()
	good := filepath.Join(tmp, "snapshot.json")
	os.WriteFile(good, []byte("{}"), 0o600)
	if out := f.must(f.term(), "party", "requests", "--own-snapshot", good); !strings.Contains(out, "No request") {
		t.Fatalf("a clean snapshot:\n%s", out)
	}
	// The reader is handed a private copy of the bytes that were judged, never
	// the path the operator named (F4).
	real, _ := filepath.EvalSymlinks(good)
	if len(f.snapshots) != 1 || f.snapshots[0] == real || string(f.snapshotData[0]) != "{}" {
		t.Fatalf("the snapshot reader was built for %v with %q", f.snapshots, f.snapshotData)
	}
	if _, err := os.Stat(f.snapshots[0]); err == nil {
		t.Errorf("the private copy %s outlived the command", f.snapshots[0])
	}

	ws := f.dir
	inbox, outbox := filepath.Join(ws, "party", "inbox"), filepath.Join(ws, "party", "outbox")
	os.MkdirAll(inbox, 0o700)
	os.MkdirAll(outbox, 0o700)
	custom := filepath.Join(tmp, "mail")
	os.Mkdir(custom, 0o700)
	mk := func(dir, name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("{}"), mode)
		os.Chmod(p, mode)
		return p
	}
	link := filepath.Join(tmp, "link.json")
	os.Symlink(good, link)
	cases := map[string]struct {
		path string
		args []string
	}{
		"in the inbox":                 {mk(inbox, "x.json", 0o600), nil},
		"in the outbox":                {mk(outbox, "x.json", 0o600), nil},
		"in a custom inbox":            {mk(custom, "x.json", 0o600), []string{"--inbox", custom}},
		"in a custom outbox":           {mk(custom, "y.json", 0o600), []string{"--outbox", custom}},
		"the sealed workspace":         {filepath.Join(ws, WorkspaceFile), nil},
		"the workspace's head file":    {mk(ws, WorkspaceFile+".head", 0o600), nil},
		"a symbolic link":              {link, nil},
		"writable by the group":        {mk(tmp, "g.json", 0o664), nil},
		"writable by others":           {mk(tmp, "o.json", 0o606), nil},
		"a directory":                  {tmp, nil},
		"missing":                      {filepath.Join(tmp, "nope.json"), nil},
		"in the party directory":       {mk(filepath.Join(ws, "party"), "z.json", 0o600), nil},
		"a hard link to an inbox file": {hardLinkTo(t, tmp, mk(inbox, "peer.spo", 0o600)), nil},
		"inside the inbox, via a dot":  {filepath.Join(inbox, "..", "inbox", "x.json"), nil},
	}
	for name, c := range cases {
		f.snapshots = nil
		args := append([]string{"party", "requests", "--own-snapshot", c.path}, c.args...)
		if _, err := f.run(f.term(), args...); err == nil {
			t.Errorf("%s: %s was accepted", name, c.path)
		}
		if len(f.snapshots) != 0 {
			t.Errorf("%s: a snapshot reader was built for %v", name, f.snapshots)
		}
	}
	// Without the flag, the chain view is the provider of the environment, and
	// in a mode with none, there is none; the transfer file of the workspace is
	// never a source.
	f.own = nil
	f.snapshots = nil
	out := f.must(f.term(), "party", "inbox", "import", f.dirEmpty(t))
	if !strings.Contains(f.err.String(), "none: this workspace's mode has no provider of its own") || len(f.snapshots) != 0 {
		t.Errorf("no provider:\n%s%s", out, f.err.String())
	}
	f.own = partyrig.ForeignInputs{}
	f.must(f.term(), "party", "inbox", "import", f.dirEmpty(t))
	if !strings.Contains(f.err.String(), "the provider this workspace is configured with") {
		t.Errorf("own provider:\n%s", f.err.String())
	}
	// The source keeps the two constructors to one call site each.
	files, _ := filepath.Glob("*.go")
	var prov, snap int
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(name)
		prov += strings.Count(string(b), "multisig.OwnProvider(")
		snap += strings.Count(string(b), "multisig.OwnSnapshot(")
		if strings.Contains(string(b), "multisig.OwnProvider(r.env.OwnUtxos)") == false && strings.Contains(string(b), "multisig.OwnProvider(") {
			t.Errorf("%s: OwnProvider is not fed from Env.OwnUtxos", name)
		}
	}
	if prov != 1 || snap != 1 {
		t.Errorf("OwnProvider at %d call sites, OwnSnapshot at %d; each must have exactly one", prov, snap)
	}
}

func (f *pfix) dirEmpty(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "none")
	os.Mkdir(d, 0o700)
	return d
}

// ---- tailcat, with fakes -----------------------------------------------------------------------

type fakeServer struct {
	mu      sync.Mutex
	cfg     TailcatServerConfig
	allowed []party.NodeKey
	revoked []party.NodeKey
	sent    [][]byte
	frames  chan ports.Received
	started bool
	closed  bool
	peers   []party.Fingerprint
}

func newFakeServer(cfg TailcatServerConfig) *fakeServer {
	return &fakeServer{cfg: cfg, frames: make(chan ports.Received, 16)}
}

func (s *fakeServer) Send(_ context.Context, to party.Fingerprint, env []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.peers {
		if p == to {
			s.sent = append(s.sent, env)
			return nil
		}
	}
	return ports.ErrNoRoute
}
func (s *fakeServer) Receive(ctx context.Context) (ports.Received, error) {
	select {
	case r := <-s.frames:
		return r, nil
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	}
}
func (s *fakeServer) Transport() ports.Transport { return ports.NetworkTransport(s) }
func (s *fakeServer) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = true
	return nil
}
func (s *fakeServer) Address() (*secret.Buffer, error) {
	return secret.TryTake([]byte("fake-tailcat-address-SECRET-psk"))
}
func (s *fakeServer) Keys() (*secret.Buffer, *secret.Buffer) { return nil, nil }
func (s *fakeServer) Allow(k party.NodeKey) {
	s.mu.Lock()
	s.allowed = append(s.allowed, k)
	s.mu.Unlock()
}
func (s *fakeServer) Revoke(k party.NodeKey) {
	s.mu.Lock()
	s.revoked = append(s.revoked, k)
	s.mu.Unlock()
}
func (s *fakeServer) Peers() []party.Fingerprint { return s.peers }
func (s *fakeServer) Close() error               { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }
func (n *netScene) srv() *fakeServer             { n.smu.Lock(); defer n.smu.Unlock(); return n.server }
func (s *fakeServer) isStarted() bool            { s.mu.Lock(); defer s.mu.Unlock(); return s.started }
func (s *fakeServer) isClosed() bool             { s.mu.Lock(); defer s.mu.Unlock(); return s.closed }
func (s *fakeServer) revokedKeys() []party.NodeKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]party.NodeKey(nil), s.revoked...)
}

type fakeClient struct {
	mu       sync.Mutex
	cfg      TailcatClientConfig
	failures []error
	// onConnect, when set, decides each Connect (after the failures).
	onConnect func() error
	connects  int
	attempts  int
	frames    chan ports.Received
	closed    bool
	sent      [][]byte
}

func (c *fakeClient) Receive(ctx context.Context) (ports.Received, error) {
	select {
	case r := <-c.frames:
		return r, nil
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	}
}
func (c *fakeClient) Send(_ context.Context, _ party.Fingerprint, env []byte) error {
	c.mu.Lock()
	c.sent = append(c.sent, env)
	c.mu.Unlock()
	return nil
}
func (c *fakeClient) sentCount() int             { c.mu.Lock(); defer c.mu.Unlock(); return len(c.sent) }
func (c *fakeClient) Transport() ports.Transport { return ports.NetworkTransport(c) }
func (c *fakeClient) Connect(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	if len(c.failures) > 0 {
		err := c.failures[0]
		c.failures = c.failures[1:]
		return err
	}
	if c.onConnect != nil {
		f := c.onConnect
		c.mu.Unlock()
		err := f()
		c.mu.Lock()
		if err != nil {
			return err
		}
	}
	c.connects++
	return nil
}
func (c *fakeClient) Disconnect()  {}
func (c *fakeClient) Close() error { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *fakeClient) counts() (attempts, connects int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts, c.connects
}

// A network scene: the coordinator (the command tree runs on its machine) and
// bob, both with tailcat node keys that are published in their identities.
type netScene struct {
	t       *testing.T
	clock   *partyrig.Clock
	ch      *partyrig.Chain
	C, B    *partyrig.Workspace
	cNode   party.NodeKey
	bNode   party.NodeKey
	coord   *pfix
	bob     *pfix
	smu     sync.Mutex
	server  *fakeServer
	client  *fakeClient
	bech    string
	hash    [28]byte
	request func() []byte
}

func tailcatNewKey() (*secret.Buffer, error)                { return tailcat.NewKey() }
func tailcatPublic(b *secret.Buffer) (party.NodeKey, error) { return tailcat.PublicKey(b) }
func openBagForTest(dir string) (*filebag.Bag, error)       { return filebag.Open(dir) }
func partyrigReceived(b []byte) ports.Received              { return ports.NetworkReceived(b) }

func newNetScene(t *testing.T, mode string) *netScene {
	t.Helper()
	clock := partyrig.NewClock(partyT0)
	ch := partyrig.NewChain(clock.Now())
	mk := func() (*secret.Buffer, party.NodeKey) {
		k, err := tailcatNewKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := tailcatPublic(k)
		if err != nil {
			t.Fatal(err)
		}
		return k, pub
	}
	ck, cpub := mk()
	bk, bpub := mk()
	s := &netScene{t: t, clock: clock, ch: ch, cNode: cpub, bNode: bpub}
	s.C = partyrig.NewWithNode(t, "coord", clock, ch, &cpub)
	s.B = partyrig.NewWithNode(t, "bob", clock, ch, &bpub)
	for _, x := range []struct {
		w *partyrig.Workspace
		k *secret.Buffer
	}{{s.C, ck}, {s.B, bk}} {
		if err := x.w.Store.Update(context.Background(), func(wr ports.NamedWriter) error {
			return wr.PutSecret(ports.NamedRef{Name: "local", Kind: ports.TailcatNodeKey}, x.k)
		}); err != nil {
			t.Fatal(err)
		}
	}
	hash := s.B.AddKey(custody.RoleStake, "bob")
	s.hash = [28]byte(hash)
	var poolID chain.PoolID
	for i := range poolID {
		poolID[i] = byte(i + 1)
	}
	s.bech = poolID.Bech32()
	s.C.Enroll(s.B, "bob", []party.Role{party.RoleSigner}, []string{s.bech})
	s.B.EnrollScoped(s.C, "coord", []party.Role{party.RoleCoordinator}, party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{s.bech}})
	// The invitation bob imported: the coordinator's address, sealed.
	addr, _ := secret.TryTake([]byte("fake-tailcat-address"))
	if err := s.B.Store.Update(context.Background(), func(wr ports.NamedWriter) error {
		return wr.PutSecret(ports.NamedRef{Name: "coord", Kind: ports.TailcatAddr}, addr)
	}); err != nil {
		t.Fatal(err)
	}
	s.coord, s.bob = newPfixOf(t, s.C), newPfixOf(t, s.B)
	s.coord.mode, s.bob.mode = mode, mode
	s.server = nil
	s.coord.edit = func(env *Env, k *PartyKit) {
		k.Tailcat.NewServer = func(c TailcatServerConfig) (TailcatServer, error) {
			fs := newFakeServer(c)
			fs.peers = []party.Fingerprint{s.B.Identity.Fingerprint}
			s.smu.Lock()
			s.server = fs
			s.smu.Unlock()
			return fs, nil
		}
	}
	s.client = &fakeClient{frames: make(chan ports.Received, 16)}
	s.bob.edit = func(env *Env, k *PartyKit) {
		k.Tailcat.NewClient = func(c TailcatClientConfig) (TailcatClient, error) { s.client.cfg = c; return s.client, nil }
	}
	return s
}

// runUntil runs a long command in the background until cond holds or a second
// has passed, then stops it and returns its error.
func (f *pfix) runUntil(term Terminal, cond func() bool, args ...string) error {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.out.Reset()
	f.err.Reset()
	root := NewRoot(f.deps(term))
	root.SetArgs(append([]string{"-C", f.dir}, args...))
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-deadline:
			cancel()
			<-done
			f.t.Fatalf("timed out; out:\n%s\nerr:\n%s", f.out.String(), f.err.String())
		case <-tick.C:
			if cond() {
				cancel()
				return <-done
			}
		}
	}
}

// serve: admits the enrolled signers only, writes the invitation sealed to the
// signer and never prints the address, and follows a revocation made in
// another process.
//
// spec: SPO-Xparty-IF-005, SPO-Xparty-SEC-001, SPO-Xparty-INV-018
func TestServeAdmitsEnrolledSignersAndWritesSealedInvitations(t *testing.T) {
	serveSyncEvery = 20 * time.Millisecond
	t.Cleanup(func() { serveSyncEvery = 2 * time.Second })
	n := newNetScene(t, ModeLight)
	outbox := filepath.Join(t.TempDir(), "invites")
	err := n.coord.runUntil(n.coord.term(), func() bool { return strings.Contains(n.coord.out.String(), "invitation for bob written") },
		"party", "serve", "--invite", "bob", "--outbox", outbox)
	if err != nil {
		t.Fatal(err)
	}
	out := n.coord.out.String() + n.coord.err.String()
	if strings.Contains(out, "SECRET") || strings.Contains(out, "fake-tailcat-address") {
		t.Errorf("the address was printed:\n%s", out)
	}
	sv := n.srv()
	if !sv.isStarted() || !sv.isClosed() || len(sv.cfg.Allowed) != 1 || sv.cfg.Allowed[0] != n.bNode {
		t.Fatalf("server %+v", sv)
	}
	if sv.cfg.Admit == nil || sv.cfg.NodeKey == nil || sv.cfg.PSK == nil {
		t.Fatal("the server has no admit check or no keys")
	}
	// The invitation is a sealed file bob opens: the address is in it and in
	// nothing else.
	files, _ := filepath.Glob(filepath.Join(outbox, "*.spo"))
	if len(files) != 1 {
		t.Fatalf("invitation files %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	if strings.Contains(string(raw), "fake-tailcat-address") {
		t.Error("the address is in the file in clear")
	}
	var got party.Invite
	bob := n.B.Signer()
	bob.OnInvite = func(_ ports.NamedWriter, _ party.Party, inv party.Invite) error { got = inv; return nil }
	if h, err := bob.Handle(context.Background(), receivedFromFile(t, files[0])); err != nil || h.Effect != "invite" {
		t.Fatalf("bob: %+v %v", h, err)
	}
	if got.Address != "fake-tailcat-address-SECRET-psk" || got.Node != n.cNode {
		t.Errorf("invite %+v", got)
	}
}

// A server with nobody to admit is not started: tailcat would admit everyone.
//
// spec: SPO-Xparty-IF-005
func TestServeRefusesAnEmptyAllowList(t *testing.T) {
	n := newNetScene(t, ModeLight)
	if _, err := n.coord.run(n.coord.term(), "party", "revoke", "bob", "--yes"); err != nil {
		t.Fatal(err)
	}
	_, err := n.coord.run(n.coord.term(), "party", "serve")
	if err == nil || !strings.Contains(err.Error(), "admits every client when its allow-list is empty") {
		t.Fatalf("serve: %v", err)
	}
	if sv := n.srv(); sv != nil && sv.isStarted() {
		t.Error("the server started")
	}
}

// Revoking a party stops serving its node key at once in the server of this
// process, and a server of another process notices within its sync interval.
//
// spec: SPO-Xparty-IF-003, SPO-Xparty-INV-005, SPO-Xparty-IF-005
func TestRevokeReachesARunningServer(t *testing.T) {
	// (1) Another process revokes: the registry is followed.
	serveSyncEvery = 20 * time.Millisecond
	t.Cleanup(func() { serveSyncEvery = 2 * time.Second })
	n := newNetScene(t, ModeLight)
	revokedSeen := func() bool { sv := n.srv(); return sv != nil && len(sv.revokedKeys()) > 0 }
	started := make(chan struct{})
	go func() {
		for sv := n.srv(); sv == nil || !sv.isStarted(); sv = n.srv() {
			time.Sleep(5 * time.Millisecond)
		}
		close(started)
		time.Sleep(50 * time.Millisecond)
		n.C.Revoke("bob") // the library, as another process would
	}()
	if err := n.coord.runUntil(n.coord.term(), revokedSeen, "party", "serve"); err != nil {
		t.Fatal(err)
	}
	<-started
	if ks := n.srv().revokedKeys(); len(ks) == 0 || ks[0] != n.bNode {
		t.Fatalf("revoked %v", ks)
	}
	if !strings.Contains(n.coord.out.String(), "no longer admitting node key") {
		t.Errorf("serve said nothing:\n%s", n.coord.out.String())
	}

	// (2) The command in the same process: revoked before it returns, no wait.
	serveSyncEvery = time.Hour
	m := newNetScene(t, ModeLight)
	var revokeOut string
	err := m.coord.runUntil(m.coord.term(), func() bool {
		if sv := m.srv(); sv == nil || !sv.isStarted() || revokeOut != "" {
			return revokeOut != ""
		}
		g := newPfixOf(t, m.C)
		out, err := g.run(g.term(), "party", "revoke", "bob", "--yes")
		if err != nil {
			t.Error(err)
		}
		revokeOut = out + "done"
		return true
	}, "party", "serve")
	if err != nil {
		t.Fatal(err)
	}
	if ks := m.srv().revokedKeys(); len(ks) == 0 || ks[0] != m.bNode {
		t.Fatalf("the live server was not told: %v\n%s", ks, revokeOut)
	}
}

func receivedFromFile(t *testing.T, path string) ports.Received {
	t.Helper()
	dir := filepath.Dir(path)
	b, err := openBagForTest(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rcv, err := b.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rcv
}

// connect: reconnects with a backoff after a failed dial, says at startup that
// every network request will be refused when there is no resolver, receives
// requests into the pending list without signing anything, and refuses a pool
// cold key request that arrives over tailcat.
//
// spec: SPO-Xparty-IF-006, SPO-Xparty-PRE-007, SPO-Xparty-PRE-006, SPO-Xparty-INV-021, SPO-Xparty-INV-016
func TestConnectReconnectsReceivesAndNeverApprovesByItself(t *testing.T) {
	connectBackoffBase, connectBackoffMax = 5*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { connectBackoffBase, connectBackoffMax = time.Second, 30*time.Second })
	n := newNetScene(t, ModeLight)
	n.client.failures = []error{errors.New("no route"), errors.New("no route")}
	// The coordinator's request, sealed for a network, delivered as a frame.
	ref := n.openCollection()
	pipe := partyrig.NewPipe(ports.ViaNetwork)
	if _, err := n.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: ref, Purpose: "register mypool"}, pipe.Transport()); err != nil {
		t.Fatal(err)
	}
	for _, env := range pipe.Take() {
		n.client.frames <- partyrigReceived(env)
	}
	term := n.bob.term()
	err := n.bob.runUntil(term, func() bool { return strings.Contains(n.bob.out.String(), "is pending") }, "party", "connect", "coord")
	if err != nil {
		t.Fatal(err)
	}
	if a, c := n.client.counts(); a < 3 || c < 1 {
		t.Errorf("connect attempts %d, connected %d", a, c)
	}
	if !strings.Contains(n.bob.err.String(), "cannot reach coord") || !strings.Contains(n.bob.err.String(), "trying again in 5ms") || !strings.Contains(n.bob.err.String(), "10ms") {
		t.Errorf("no backoff:\n%s", n.bob.err.String())
	}
	if n.client.cfg.ExpectServerKey != n.cNode || n.client.cfg.Coordinator != n.C.Identity.Fingerprint || n.client.cfg.Address == nil || n.client.cfg.NodeKey == nil {
		t.Errorf("client config %+v", n.client.cfg)
	}
	// Every connection starts with a fresh Hello: a new envelope each call.
	h1, err1 := n.client.cfg.Hello(context.Background())
	h2, err2 := n.client.cfg.Hello(context.Background())
	if err1 != nil || err2 != nil || len(h1) == 0 || string(h1) == string(h2) {
		t.Errorf("hello: %v %v same=%v", err1, err2, string(h1) == string(h2))
	}
	// Receiving signed nothing: the passphrase was asked once (to open), the
	// request waits and arrived by network.
	if term.secretsAsked != 1 || len(n.bob.outbox()) != 0 {
		t.Errorf("connect approved by itself: %d passphrases, outbox %v", term.secretsAsked, n.bob.outbox())
	}
	if out := n.bob.must(n.bob.term(), "party", "requests"); !strings.Contains(out, "arrived by network") {
		t.Errorf("requests:\n%s", out)
	}
	// The approval is a separate, deliberate command.
	id := n.bob.must(n.bob.term(), "party", "requests")[:32]
	if out := n.bob.must(n.bob.term("y"), "party", "approve", id); !strings.Contains(out, "Signed.") || !strings.Contains(out, "the network transport") {
		t.Errorf("approve:\n%s", out)
	}
}

// No chain view of its own: the startup says every request will be refused
// and why, and one that arrives is refused in silence and listed in the log.
//
// spec: SPO-Xparty-PRE-007
func TestConnectWithoutAResolverSaysEveryRequestWillBeRefused(t *testing.T) {
	connectBackoffBase = 5 * time.Millisecond
	t.Cleanup(func() { connectBackoffBase = time.Second })
	n := newNetScene(t, ModeLight)
	n.bob.own = nil
	ref := n.openCollection()
	pipe := partyrig.NewPipe(ports.ViaNetwork)
	if _, err := n.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: ref, Purpose: "register mypool"}, pipe.Transport()); err != nil {
		t.Fatal(err)
	}
	for _, env := range pipe.Take() {
		n.client.frames <- partyrigReceived(env)
	}
	err := n.bob.runUntil(n.bob.term(), func() bool { return strings.Contains(n.bob.out.String(), "was refused") }, "party", "connect", "coord")
	if err != nil {
		t.Fatal(err)
	}
	e := n.bob.err.String()
	if !strings.Contains(e, "EVERY request that arrives over tailcat will be refused automatically and in silence") || !strings.Contains(e, "SPO-Xparty-PRE-007") {
		t.Errorf("no warning at startup:\n%s", e)
	}
	if out := n.bob.must(n.bob.term(), "party", "requests"); !strings.Contains(out, "No request is waiting") {
		t.Errorf("a refused request is pending:\n%s", out)
	}
	ev := n.bob.must(n.bob.term(), "party", "events")
	if !strings.Contains(ev, "cannot resolve the inputs of a stake key request") || !strings.Contains(ev, "not sent to the coordinator") {
		t.Errorf("events:\n%s", ev)
	}
	if len(n.bob.outbox()) != 0 {
		t.Error("a silent refusal was sent")
	}
}

// A request for the pool cold key that reaches a signer over tailcat is
// refused, and the refusal is sent (it depends on the request alone).
//
// spec: SPO-Xparty-PRE-004, SPO-Xparty-PRE-006, SPO-Xparty-INV-006
func TestConnectRefusesAPoolColdKeyRequestOverTailcat(t *testing.T) {
	connectBackoffBase = 5 * time.Millisecond
	t.Cleanup(func() { connectBackoffBase = time.Second })
	n := newNetScene(t, ModeLight)
	cold := n.B.AddKey(custody.RolePoolCold, "mypool")
	var poolID chain.PoolID
	copy(poolID[:], cold[:])
	// bob enrolled the coordinator for his cold key too, as one who allows it.
	n.B.SetScope("coord", party.Scope{KeyRoles: []custody.Role{custody.RoleStake, custody.RolePoolCold}, Pools: []string{poolID.Bech32()}})
	ref := n.openColdCollection(poolID)
	// Sealed for a file, which the coordinator allows ...
	pipe := partyrig.NewPipe(ports.ViaFile)
	if _, err := n.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: ref, Purpose: "register"}, pipe.Transport()); err != nil {
		t.Fatal(err)
	}
	envs := pipe.Take()
	if len(envs) != 1 {
		t.Fatalf("%d envelopes", len(envs))
	}
	// ... and handed to bob's client as a frame of the network.
	n.client.frames <- partyrigReceived(envs[0])
	err := n.bob.runUntil(n.bob.term(), func() bool { return n.client.sentCount() > 0 }, "party", "connect", "coord")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n.bob.out.String(), party.RefuseColdKeyOverNetwork.String()) {
		t.Errorf("connect:\n%s", n.bob.out.String())
	}
	// The refusal depends on the request alone, so it was sent to the
	// coordinator (once, and it is done).
	if n.client.sentCount() != 1 || len(n.bob.outbox()) != 0 {
		t.Errorf("sent %d, outbox %v", n.client.sentCount(), n.bob.outbox())
	}
	if out := n.bob.must(n.bob.term(), "party", "requests"); !strings.Contains(out, "No request") {
		t.Errorf("pending:\n%s", out)
	}
}

// --interactive runs the same prompts in the same process, and the default
// answer is still No.
//
// spec: SPO-Xparty-INV-016
func TestConnectInteractiveAsksTheSameQuestionsDefaultNo(t *testing.T) {
	connectBackoffBase = 5 * time.Millisecond
	t.Cleanup(func() { connectBackoffBase = time.Second })
	n := newNetScene(t, ModeLight)
	ref := n.openCollection()
	pipe := partyrig.NewPipe(ports.ViaNetwork)
	if _, err := n.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: ref, Purpose: "register mypool"}, pipe.Transport()); err != nil {
		t.Fatal(err)
	}
	for _, env := range pipe.Take() {
		n.client.frames <- partyrigReceived(env)
	}
	term := n.bob.term("")
	err := n.bob.runUntil(term, func() bool { return strings.Contains(n.bob.out.String(), "Not signed") }, "party", "connect", "coord", "--interactive")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n.bob.out.String(), "Whose money moves") || len(n.bob.outbox()) != 0 || term.secretsAsked != 1 {
		t.Errorf("interactive:\n%s", n.bob.out.String())
	}
}

func (n *netScene) openCollection() multisig.CollectionRef {
	n.t.Helper()
	var poolID chain.PoolID
	for i := range poolID {
		poolID[i] = byte(i + 1)
	}
	return openRegistration(n.t, n.C, poolID, n.hash, false)
}

func (n *netScene) openColdCollection(poolID chain.PoolID) multisig.CollectionRef {
	n.t.Helper()
	return openRegistration(n.t, n.C, poolID, n.hash, true)
}

// hardLinkTo makes a second name, in dir, for a file that lives elsewhere.
func hardLinkTo(t *testing.T, dir, target string) string {
	t.Helper()
	p := filepath.Join(dir, "hl-"+filepath.Base(target))
	if err := os.Link(target, p); err != nil {
		t.Skip("hard links are not available: ", err)
	}
	return p
}

// A snapshot with more than one hard link is refused whatever its path; an
// inbox or outbox that spo.toml configures stays in the refused set when
// another --inbox is given; a snapshot under an ancestor others can replace is
// refused.
//
// spec: SPO-Xparty-PR-005
func TestSnapshotHardLinksConfiguredDirsAndAncestors(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	tmp := t.TempDir()
	// the configured inbox is outside the default place
	cfgIn := filepath.Join(tmp, "cfgmail")
	os.Mkdir(cfgIn, 0o700)
	f.cfg = WorkspaceConfig{Network: "preview", Mode: f.mode, Party: &PartyConfig{Inbox: cfgIn}}
	other := filepath.Join(tmp, "other")
	os.Mkdir(other, 0o700)
	in := filepath.Join(cfgIn, "x.json")
	os.WriteFile(in, []byte("{}"), 0o600)
	if _, err := f.run(f.term(), "party", "requests", "--own-snapshot", in, "--inbox", other); err == nil {
		t.Error("a file in the inbox spo.toml configures was accepted because another --inbox was given")
	}
	// hard link: the same file under a clean name
	hl := filepath.Join(tmp, "hl.json")
	if err := os.Link(in, hl); err != nil {
		t.Skip(err)
	}
	f.cfg = WorkspaceConfig{Network: "preview", Mode: f.mode}
	_, err := f.run(f.term(), "party", "requests", "--own-snapshot", hl)
	if err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Errorf("a hard-linked snapshot: %v", err)
	}
	// an ancestor writable by others, with no sticky bit
	shared := filepath.Join(tmp, "shared")
	os.Mkdir(shared, 0o700)
	os.Chmod(shared, 0o777)
	snap := filepath.Join(shared, "snap.json")
	os.WriteFile(snap, []byte("{}"), 0o600)
	_, err = f.run(f.term(), "party", "requests", "--own-snapshot", snap)
	if err == nil || !strings.Contains(err.Error(), "sticky") {
		t.Errorf("a snapshot under a world-writable ancestor: %v", err)
	}
}
