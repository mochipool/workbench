package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

var partyT0 = time.Unix(1_800_000_000, 0).UTC()

// ptTerm is a terminal that answers what a test scripts: secrets for
// ReadSecret (the workspace passphrase, asked first to open it and again at the
// approval gate) and lines for ReadLine.
type ptTerm struct {
	t            *testing.T
	secrets      []string
	lines        []string
	prompts      []string
	secretsAsked int
	// onLine runs when a line is asked, before it is answered: a test changes
	// the world while the operator is "reading".
	onLine func(prompt string)
	// calls records what was asked, in order: "flush", "line", "secret".
	calls         []string
	secretPrompts []string
	// cols and rows, when set, are the terminal size this terminal reports.
	cols, rows int
}

// Size makes a ptTerm a sizer when it was given a size.
func (p *ptTerm) Size() (int, int, bool) { return p.cols, p.rows, p.cols > 0 && p.rows > 0 }

// FlushInput is the optional hook a terminal has to drop typed-ahead input.
func (p *ptTerm) FlushInput() { p.calls = append(p.calls, "flush") }

func (p *ptTerm) ReadSecret(_ context.Context, prompt string) (*secret.Buffer, error) {
	p.secretsAsked++
	p.calls = append(p.calls, "secret")
	p.secretPrompts = append(p.secretPrompts, prompt)
	if len(p.secrets) == 0 {
		return nil, ErrNoTerminal
	}
	s := p.secrets[0]
	p.secrets = p.secrets[1:]
	return secret.Take([]byte(s)), nil
}

func (p *ptTerm) ReadLine(_ context.Context, prompt string) (string, error) {
	p.prompts = append(p.prompts, prompt)
	p.calls = append(p.calls, "line")
	if p.onLine != nil {
		p.onLine(prompt)
	}
	if len(p.lines) == 0 {
		return "", ErrNoTerminal
	}
	l := p.lines[0]
	p.lines = p.lines[1:]
	return l, nil
}

// syncBuf is a buffer a test can read while a command in the background writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
func (s *syncBuf) Reset()                      { s.mu.Lock(); s.b.Reset(); s.mu.Unlock() }

const ptPass = "a long enough passphrase"

// pfix is a workspace the command tree runs on: a plain directory store that
// stands in for the sealed one (as the other tests of this package do), the
// real party adapters, and an Env a test can reshape.
type pfix struct {
	t     *testing.T
	dir   string
	st    *plainstore.Store
	clock *partyrig.Clock
	ch    *partyrig.Chain
	out   syncBuf
	err   syncBuf
	mode  string
	cfg   WorkspaceConfig
	// own is Env.OwnUtxos; the default is a chain view in which every input
	// exists at somebody else's address.
	own ports.UtxoResolver
	// edit changes the Env and the kit after the fixture built them.
	edit      func(*Env, *PartyKit)
	snapshots []string
	// snapshotData is what the file of each snapshot reader held when it was built.
	snapshotData [][]byte
	absent       map[Cap]string
}

func newPfixDir(t *testing.T, dir string, st *plainstore.Store, clock *partyrig.Clock, ch *partyrig.Chain) *pfix {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, WorkspaceFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return &pfix{t: t, dir: dir, st: st, clock: clock, ch: ch, mode: ModeOffline, own: partyrig.ForeignInputs{}, absent: map[Cap]string{}}
}

// newPfix is a workspace with no identity yet.
func newPfix(t *testing.T) *pfix {
	t.Helper()
	dir := t.TempDir()
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	clock := partyrig.NewClock(partyT0)
	return newPfixDir(t, dir, st, clock, partyrig.NewChain(clock.Now()))
}

// newPfixOf runs the command tree on a rig workspace (which already has its
// identity).
func newPfixOf(t *testing.T, w *partyrig.Workspace) *pfix {
	t.Helper()
	return newPfixDir(t, w.Dir, w.Store, w.Clock, w.Chain)
}

type bagCLI struct{ *filebag.Bag }

func (b bagCLI) Rejected() []BagRejection {
	var out []BagRejection
	for _, r := range b.Bag.Rejected() {
		out = append(out, BagRejection{Name: r.Name, Reason: r.Reason})
	}
	return out
}

func bagOpener(open func(string) (*filebag.Bag, error)) func(string) (FileBag, error) {
	return func(dir string) (FileBag, error) {
		b, err := open(dir)
		if err != nil {
			return nil, err
		}
		return bagCLI{b}, nil
	}
}

func realKit(st ports.Store) *PartyKit {
	var v ports.Vault
	if st != nil {
		v, _ = st.(ports.Vault)
	}
	reg := partystore.Registry{}
	return &PartyKit{Kit: envelope.Kit{Store: st, Vault: v}, Registry: reg, SetScope: reg.SetScope, Replay: partystore.Replay{}, Addresses: native.Ledger{},
		CheckAncestors: filebag.CheckAncestors, OpenInbox: bagOpener(filebag.Open), OpenOutput: bagOpener(filebag.OpenOutput),
		Tailcat: TailcatOps{NewNodeKey: tailcat.NewKey, NodePublic: tailcat.PublicKey}}
}

func (f *pfix) deps(term Terminal) Deps {
	cfgs := map[string]WorkspaceConfig{f.dir: f.cfg}
	if f.cfg.Network == "" {
		cfgs[f.dir] = WorkspaceConfig{Network: "preview", Mode: f.mode}
	}
	return Deps{
		Out: &f.out, Err: &f.err, Terminal: term, Config: memConfig(cfgs),
		Sealed: SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) {
			return fakeSealed{Store: f.st, tokens: map[string][]byte{}}, nil
		}},
		OpenUpstream: func(dir string) (ports.Store, error) { return plainstore.OpenTestnet(dir) },
		Wire: func(st ports.Store, o WireOptions) (*Env, error) {
			led := native.Ledger{}
			env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, Clock: f.clock, Genesis: f.ch, Tip: f.ch,
				AddressInspector: led, TxIDs: led, TxViewer: native.TxViewer{}, OwnUtxos: f.own,
				SnapshotResolver: func(p string) ports.UtxoResolver {
					f.snapshots = append(f.snapshots, p)
					b, _ := os.ReadFile(p)
					f.snapshotData = append(f.snapshotData, b)
					return partyrig.ForeignInputs{}
				}}
			var v ports.Vault
			if st != nil {
				v, _ = st.(ports.Vault)
			}
			env.Signers = native.Signers{Vault: v}
			env.Party = realKit(st)
			if f.edit != nil {
				f.edit(env, env.Party)
			}
			for c, why := range f.absent {
				switch c {
				case CapParty:
					env.Party = nil
				case CapTxView:
					env.TxViewer = nil
				case CapGenesis:
					env.Genesis = nil
				}
				env.Absent(c, why)
			}
			return env, nil
		},
	}
}

// run executes a command and returns what it printed.
func (f *pfix) run(term Terminal, args ...string) (string, error) {
	f.t.Helper()
	f.out.Reset()
	f.err.Reset()
	root := NewRoot(f.deps(term))
	root.SetArgs(append([]string{"-C", f.dir}, args...))
	err := root.ExecuteContext(context.Background())
	return f.out.String(), err
}

func (f *pfix) must(term Terminal, args ...string) string {
	f.t.Helper()
	out, err := f.run(term, args...)
	if err != nil {
		f.t.Fatalf("%v: %v\n%s%s", args, err, out, f.err.String())
	}
	return out
}

// term is a terminal that gives the passphrase to open the workspace, and
// then what is scripted.
func (f *pfix) term(lines ...string) *ptTerm {
	return &ptTerm{t: f.t, secrets: []string{ptPass, ptPass}, lines: lines}
}

// forbid is a terminal that fails the test when anything is asked of it.
type forbid struct{ t *testing.T }

func (f forbid) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	f.t.Helper()
	f.t.Error("the terminal was asked for a secret")
	return nil, ErrNoTerminal
}
func (f forbid) ReadLine(_ context.Context, p string) (string, error) {
	f.t.Helper()
	f.t.Errorf("the terminal was asked: %q", p)
	return "", ErrNoTerminal
}

func (f *pfix) events() []string {
	f.t.Helper()
	var out []string
	err := f.st.View(context.Background(), func(r ports.Reader) error {
		es, err := multisig.Events(r)
		for _, e := range es {
			out = append(out, e.Kind+" "+e.Reason+" "+e.Detail)
		}
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *pfix) outbox() []multisig.OutItem {
	f.t.Helper()
	items, err := (multisig.Outbox{Store: f.st, Clock: f.clock, Parties: realKit(f.st).Registry, Kit: realKit(f.st).Kit}).Pending(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return items
}

// ---- a registration the coordinator asks bob to sign -------------------------------------------

// pscene is a coordinator (driven through the library, as another machine) and
// bob, whose machine the command tree runs on. Bob has enrolled the coordinator
// with the scope of one pool and the stake role, and has a stake key.
type pscene struct {
	t      *testing.T
	clock  *partyrig.Clock
	ch     *partyrig.Chain
	C, B   *partyrig.Workspace
	bob    *pfix
	bech   string
	hash   txbuild.KeyHash
	ref    multisig.CollectionRef
	bodyID chain.TxID
}

func newPscene(t *testing.T) *pscene { return newPsceneMeta(t, "https://example.org/p.json") }

// newPsceneMeta is newPscene for a registration whose metadata URL is metaURL.
func newPsceneMeta(t *testing.T, metaURL string) *pscene {
	t.Helper()
	clock := partyrig.NewClock(partyT0)
	ch := partyrig.NewChain(clock.Now())
	s := &pscene{t: t, clock: clock, ch: ch}
	s.C = partyrig.New(t, "coord", clock, ch)
	s.B = partyrig.New(t, "bob", clock, ch)
	s.hash = s.B.AddKey(custody.RoleStake, "bob")
	var poolID chain.PoolID
	for i := range poolID {
		poolID[i] = byte(i + 1)
	}
	s.bech = poolID.Bech32()
	s.C.Enroll(s.B, "bob", []party.Role{party.RoleSigner}, []string{s.bech})
	s.B.EnrollScoped(s.C, "coord", []party.Role{party.RoleCoordinator}, party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{s.bech}})
	cert, err := native.Ledger{}.BuildPoolRegistration(pool.RegistrationSpec{Operator: poolID, VrfKeyHash: [32]byte{7}, Pledge: 1_000_000,
		Cost: 340_000_000, Margin: chain.Rational{Num: 1, Den: 100}, RewardAccount: stake.KeyHash(s.hash), NetworkID: 0,
		Owners: []stake.KeyHash{stake.KeyHash(s.hash)}, Relays: []pool.Relay{{Kind: pool.RelayDNS, Host: "relay.example.org", Port: 3001, HasPort: true}},
		MetaURL: metaURL, MetaHash: [32]byte{9}})
	if err != nil {
		t.Fatal(err)
	}
	ttl := uint64(1500)
	body := partyrig.Body(t, ttl, cert.Attachment(500_000_000))
	s.bodyID = body.ID
	slots := []pool.Slot{{Name: "bob.staking", Role: custody.RoleStake, KeyHash: s.hash, PartyFingerprint: s.C.FingerprintOf("bob")}}
	s.ref, err = s.C.Coordinator().Open(context.Background(), multisig.OpenRequest{Name: "reg1", Body: body, TTL: ttl, Slots: slots, Local: txflow.Prepared{}})
	if err != nil {
		t.Fatal(err)
	}
	s.bob = newPfixOf(t, s.B)
	return s
}

// request seals the coordinator's request for bob into a new directory and
// returns the file's path. purpose is what the coordinator claims.
func (s *pscene) request(purpose string) string {
	s.t.Helper()
	dir := filepath.Join(s.t.TempDir(), "carry")
	if err := os.Mkdir(dir, 0o700); err != nil {
		s.t.Fatal(err)
	}
	bag, err := filebag.OpenOutput(dir)
	if err != nil {
		s.t.Fatal(err)
	}
	defer bag.Close()
	res, err := s.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: s.ref, Purpose: purpose, Renew: true}, bag.Transport())
	if err != nil || len(res) != 1 || res[0].Status != multisig.SlotRequested {
		s.t.Fatalf("request: %+v %v", res, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.spo"))
	if len(files) != 1 {
		s.t.Fatalf("files %v", files)
	}
	return files[0]
}

// imported puts the request in bob's pending list through the command tree and
// returns its id (prefix).
func (s *pscene) imported(purpose string) string {
	s.t.Helper()
	file := s.request(purpose)
	out := s.bob.must(s.bob.term(), "party", "inbox", "import", file)
	reqs := s.bob.must(s.bob.term(), "party", "requests")
	if len(reqs) < 32 {
		s.t.Fatalf("no request is pending after the import:\n%s\n%s", out, reqs)
	}
	return reqs[:32]
}

// openRegistration opens a standalone collection on the coordinator c for a
// pool registration whose owner is bob (his stake key hash); with cold set the
// only open slot is the pool cold key, held by bob, whose hash is the pool id.
func openRegistration(t *testing.T, c *partyrig.Workspace, poolID chain.PoolID, bob [28]byte, cold bool, nameAndParty ...string) multisig.CollectionRef {
	t.Helper()
	cert, err := native.Ledger{}.BuildPoolRegistration(pool.RegistrationSpec{Operator: poolID, VrfKeyHash: [32]byte{7}, Pledge: 1_000_000,
		Cost: 340_000_000, Margin: chain.Rational{Num: 1, Den: 100}, RewardAccount: stake.KeyHash(bob), NetworkID: 0,
		Owners: []stake.KeyHash{stake.KeyHash(bob)}, Relays: []pool.Relay{{Kind: pool.RelayDNS, Host: "relay.example.org", Port: 3001, HasPort: true}},
		MetaURL: "https://example.org/p.json", MetaHash: [32]byte{9}})
	if err != nil {
		t.Fatal(err)
	}
	ttl := uint64(1500)
	body := partyrig.Body(t, ttl, cert.Attachment(500_000_000))
	slot := pool.Slot{Name: "bob.staking", Role: custody.RoleStake, KeyHash: txbuild.KeyHash(bob), PartyFingerprint: c.FingerprintOf("bob")}
	if cold {
		slot = pool.Slot{Name: "mypool.node", Role: custody.RolePoolCold, KeyHash: txbuild.KeyHash(poolID), PartyFingerprint: c.FingerprintOf("bob")}
	}
	name := "reg1"
	if len(nameAndParty) == 2 {
		name, slot.PartyFingerprint = nameAndParty[0], c.FingerprintOf(nameAndParty[1])
		slot.Name = nameAndParty[1] + ".staking"
	}
	ref, err := c.Coordinator().Open(context.Background(), multisig.OpenRequest{Name: name, Body: body, TTL: ttl, Slots: []pool.Slot{slot}, Local: txflow.Prepared{}})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
