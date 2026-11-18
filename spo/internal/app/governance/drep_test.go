package governance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r *rig) registerDRep(dreps *fakeDReps) RegisterDRep {
	// The existing tests are about the DRep, not the anchor policy: they acknowledge
	// the unverified anchor (TestRegisterDRepAnchorPolicy has the policy).
	return RegisterDRep{Base: r.base, Certs: r.certs, DReps: dreps, AnchorUnverifiedAcknowledged: true}
}

// A DRep that is not registered gets a registration that pays the deposit of
// the protocol parameters; the queue entry has the DRep type and name, two
// witnesses sign and the certificate is stored after the queue.
//
// spec: SPO-21b-INV-002, SPO-21b-EXT-005, SPO-21b-INV-004, SPO-21b-INV-005, SPO-21b-OUT-001, SPO-21b-OUT-002, SPO-21b-IN-002, SPO-21b-PRE-003
// spec: SPO-21b-INV-007, SPO-21b-INV-009, SPO-21b-INV-010, SPO-21b-INV-011, SPO-21b-INV-016, SPO-21b-INV-017, SPO-21b-INV-008, SPO-21b-INV-014, SPO-21b-INV-018, SPO-21b-IN-001, SPO-21b-IF-001
func TestRegisterDRepRegistration(t *testing.T) {
	r := newRig(t)
	dr := &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	res, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d.drep", Payer: "w.payment.addr"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Kind != stake.CertDRepRegistration || res.Deposit != 500_000_000 || !res.Queued {
		t.Fatalf("result %+v", res)
	}
	if r.l.count("witness drep d") != 1 || r.l.count("witness payment w.payment") != 1 || r.l.count("assemble witnesses=2") != 1 {
		t.Errorf("witnesses: %v", r.l.calls)
	}
	if r.l.count("fee witnesses=2") == 0 || r.l.count("fee witnesses=1") != 0 {
		t.Errorf("the fee is estimated for two witnesses: %v", r.l.calls)
	}
	q := r.queue.got[0]
	if q.Type != "DRepIDRegistration" || len(q.Extra) != 1 || q.Extra[0] != (ports.QueuedField{Key: "drepName", Value: "d"}) {
		t.Errorf("queue entry %+v", q)
	}
	if string(r.store.files[ports.NamedRef{Name: "d", Kind: ports.DRepRegCert}]) != string(res.Certificate.Envelope) {
		t.Error("the certificate file is not stored")
	}
	// The cert is stored after the queue (a refused run leaves no file).
	if r.l.indexOf("enqueue") > r.l.indexOf("put d/drep-reg.cert") {
		t.Errorf("order: %v", r.l.calls)
	}
}

func (l *log) indexOf(prefix string) int {
	for i, c := range l.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

// A registered DRep (also an expired one) gets an update that pays nothing.
//
// spec: SPO-21b-INV-002, SPO-21b-EXT-006, SPO-21b-INV-005
func TestRegisterDRepUpdate(t *testing.T) {
	r := newRig(t)
	dr := &fakeDReps{src: "koios", l: r.l, r: registeredDRep(500_000_000, "")}
	res, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment", URL: "https://x.org/a.json", Hash: strings.Repeat("ab", 32)})
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Kind != stake.CertDRepUpdate || res.Deposit != 0 || res.Certificate.Anchor.URL != "https://x.org/a.json" {
		t.Fatalf("result %+v", res.Certificate)
	}
}

// An unknown DRep state is refused: a duplicate registration or an update of
// nothing would follow. Nothing is written.
//
// spec: SPO-21b-EXT-004, SPO-21b-MODE-003
// spec: SPO-21b-PRE-007, SPO-21d-PRE-003
func TestRegisterDRepUnknownStateRefused(t *testing.T) {
	r := newRig(t)
	dr := &fakeDReps{src: "snapshot", l: r.l, r: chain.Unknown[chain.DRepState]("not in the snapshot")}
	_, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"})
	if !errors.Is(err, governance.ErrDRepUnknown) {
		t.Fatalf("got %v", err)
	}
	r.nothingWritten(t)
}

// An update without an anchor of a DRep that has one on chain is refused
// unless clearing is allowed; the decision is recorded.
//
// spec: SPO-21b-INV-003
func TestRegisterDRepUpdateWouldClearAnchor(t *testing.T) {
	r := newRig(t)
	dr := &fakeDReps{src: "koios", l: r.l, r: registeredDRep(500_000_000, "https://old.org/a.json")}
	if _, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, ErrAnchorWouldBeCleared) {
		t.Fatalf("got %v", err)
	}
	r.nothingWritten(t)
	res, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment", AllowAnchorClear: true})
	if err != nil || len(res.Decisions) != 1 || !strings.Contains(res.Decisions[0], "clears the anchor") {
		t.Fatalf("got %+v %v", res.Decisions, err)
	}
}

// A hardware DRep key is refused before any chain read; nothing is written.
//
// spec: SPO-21b-INV-006, SPO-21b-INV-015
func TestRegisterDRepHardwareRefusedUpFront(t *testing.T) {
	r := newRig(t)
	r.hardware(ports.NamedRef{Name: "d", Kind: ports.DRepSKey}, ports.DRepHwsFile)
	dr := &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	_, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"})
	if err == nil {
		t.Fatal("a hardware DRep key must be refused")
	}
	if r.l.count("params") != 0 || r.l.count("utxos") != 0 || r.l.count("drep-state") != 0 {
		t.Errorf("chain reads before the refusal: %v", r.l.calls)
	}
	r.nothingWritten(t)
}

// A pre-Conway protocol version, a missing dRepDeposit, a url without a hash,
// and a declined confirmation each write nothing.
//
// spec: SPO-21b-PRE-002, SPO-21b-PRE-003, SPO-21b-PRE-006, SPO-21b-PR-002
// spec: SPO-21b-IF-002
func TestRegisterDRepRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(*rig)
		req    RegisterDRepRequest
		want   error
	}{
		"old protocol":     {func(r *rig) { r.chain.params.ProtocolMajor = 8 }, RegisterDRepRequest{DRep: "d", Payer: "w.payment"}, ErrProtocolTooOld},
		"no deposit":       {func(r *rig) { r.chain.params.DRepDeposit = 0 }, RegisterDRepRequest{DRep: "d", Payer: "w.payment"}, ErrNoDRepDeposit},
		"url without hash": {func(*rig) {}, RegisterDRepRequest{DRep: "d", Payer: "w.payment", URL: "https://x.org/a.json"}, ErrAnchorNotChecked},
		"hash without url": {func(*rig) {}, RegisterDRepRequest{DRep: "d", Payer: "w.payment", Hash: strings.Repeat("00", 32)}, governance.ErrAnchorPair},
		"declined":         {func(r *rig) { r.conf.yes = false }, RegisterDRepRequest{DRep: "d", Payer: "w.payment"}, ErrDeclined},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.base.Pipeline.Approval = ApprovalAsk
			tc.mutate(r)
			dr := &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
			_, err := r.registerDRep(dr).Run(context.Background(), tc.req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			r.nothingWritten(t)
		})
	}
}

// The refund of a retirement is the deposit in the on-chain state, not the
// parameters' dRepDeposit.
//
// spec: SPO-21d-INV-001, SPO-21d-EXT-002, SPO-21d-INV-003, SPO-21d-OUT-002
// spec: SPO-21d-INV-005, SPO-21d-INV-006, SPO-21d-INV-007, SPO-21d-INV-008, SPO-21d-INV-009, SPO-21d-INV-014, SPO-21d-INV-015, SPO-21d-INV-016, SPO-21d-IN-002, SPO-21d-PRE-002, SPO-21d-MODE-001, SPO-21d-INV-004, SPO-21d-IN-001, SPO-21d-IF-001, SPO-21d-INV-013
func TestRetireDRepRefundIsTheOnChainDeposit(t *testing.T) {
	r := newRig(t)
	dr := &fakeDReps{src: "koios", l: r.l, r: registeredDRep(123_000_000, "")}
	res, err := RetireDRep{Base: r.base, Certs: r.certs, DReps: dr, Sources: SingleSourceAcknowledged, OnSingle: noopHook}.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Refund != 123_000_000 || res.Certificate.Deposit != 123_000_000 || !res.SingleSource {
		t.Fatalf("result %+v", res)
	}
	if r.queue.got[0].Type != "DRepIDRetirement" {
		t.Errorf("queue %+v", r.queue.got[0])
	}
	if r.store.files[ports.NamedRef{Name: "d", Kind: ports.DRepRetCert}] == nil {
		t.Error("the retirement certificate is not stored")
	}
}

// The refund is a "harmful if false" read: one source is refused unless
// acknowledged, a second source that disagrees is refused, and Unknown is never
// "not registered".
//
// spec: SPO-21d-INV-001, SPO-21d-EXT-001, SPO-21d-PRE-004
func TestRetireDRepSourcePolicy(t *testing.T) {
	r := newRig(t)
	one := &fakeDReps{src: "koios", l: r.l, r: registeredDRep(500_000_000, "")}
	uc := RetireDRep{Base: r.base, Certs: r.certs, DReps: one}
	if _, err := uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, ErrSingleSource) {
		t.Fatalf("one source: %v", err)
	}
	r.nothingWritten(t)
	uc.CrossCheck = &fakeDReps{src: "node", l: r.l, r: registeredDRep(400_000_000, "")}
	if _, err := uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, ErrSourcesDisagree) {
		t.Fatalf("disagreement: %v", err)
	}
	uc.CrossCheck = &fakeDReps{src: "node", l: r.l, r: registeredDRep(500_000_000, "")}
	res, err := uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if err != nil || len(res.Sources) != 2 || res.SingleSource {
		t.Fatalf("two agreeing sources: %+v %v", res, err)
	}
	// Not registered: nothing to retire, distinct from Unknown.
	r2 := newRig(t)
	none := RetireDRep{Base: r2.base, Certs: r2.certs, DReps: &fakeDReps{src: "koios", l: r2.l, r: chain.None[chain.DRepState]()}, Sources: SingleSourceAcknowledged, OnSingle: noopHook}
	if _, err := none.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, governance.ErrDRepNotRegistered) {
		t.Fatalf("not registered: %v", err)
	}
	r2.nothingWritten(t)
	unk := RetireDRep{Base: r2.base, Certs: r2.certs, DReps: &fakeDReps{src: "koios", l: r2.l, r: chain.Unknown[chain.DRepState]("timeout")}, Sources: SingleSourceAcknowledged, OnSingle: noopHook}
	if _, err := unk.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, governance.ErrDRepUnknown) || errors.Is(err, governance.ErrDRepNotRegistered) {
		t.Fatalf("unknown: %v", err)
	}
	r2.nothingWritten(t)
}

// A registered DRep whose state has no deposit is refused, not refunded 0.
//
// spec: SPO-21d-INV-001
func TestRetireDRepUnstatedDepositRefused(t *testing.T) {
	r := newRig(t)
	dr := &fakeDReps{src: "koios", l: r.l, r: registeredDRep(0, "")}
	_, err := RetireDRep{Base: r.base, Certs: r.certs, DReps: dr, Sources: SingleSourceAcknowledged, OnSingle: noopHook}.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if !errors.Is(err, governance.ErrDRepDeposit) {
		t.Fatalf("got %v", err)
	}
	r.nothingWritten(t)
}

type fakeEpoch struct{ e uint64 }

func (f fakeEpoch) Source() chain.Source                  { return "fake" }
func (f fakeEpoch) Epoch(context.Context) (uint64, error) { return f.e, nil }

type fakeFetcher struct {
	docs map[string][]byte
	got  []string
}

func (f *fakeFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	f.got = append(f.got, url)
	if d, ok := f.docs[url]; ok {
		return d, nil
	}
	return nil, errors.New("404")
}

type fakeVerifier struct {
	v   ports.AnchorVerdict
	got []ports.AnchorDocKind
}

func (f *fakeVerifier) VerifyAnchor(_ context.Context, k ports.AnchorDocKind, _ []byte) (ports.AnchorVerdict, error) {
	f.got = append(f.got, k)
	return f.v, nil
}

// The check reports registered, expired and not registered as three
// standings, never an error for "not registered"; an unknown state is an error.
//
// spec: SPO-21c-PRE-004, SPO-21c-INV-003, SPO-21c-OUT-001
// spec: SPO-21c-IF-001, SPO-21c-IF-002, SPO-21c-IN-001, SPO-21c-INV-002, SPO-21c-PRE-003, SPO-21c-EXT-001, SPO-21c-EXT-002, SPO-21c-IN-002
func TestCheckDRepStandings(t *testing.T) {
	r := newRig(t)
	id, _ := governance.DRepIDsOf(governance.Credential{Hash: r.drep})
	for name, tc := range map[string]struct {
		state chain.Reading[chain.DRepState]
		want  governance.DRepStanding
	}{
		"registered":     {chain.Value(chain.DRepState{Deposit: 1, Expiry: chain.Value(uint64(510))}), governance.DRepActive},
		"expired":        {chain.Value(chain.DRepState{Deposit: 1, Expiry: chain.Value(uint64(499))}), governance.DRepInactive},
		"not registered": {chain.None[chain.DRepState](), governance.DRepNotRegistered},
	} {
		t.Run(name, func(t *testing.T) {
			uc := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: tc.state}, Epoch: fakeEpoch{500}}
			rep, err := uc.Run(context.Background(), id.Legacy)
			if err != nil || rep.Standing != tc.want || rep.Credential.Hash != r.drep {
				t.Fatalf("got %+v %v", rep, err)
			}
		})
	}
	uc := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: chain.Unknown[chain.DRepState]("x")}, Epoch: fakeEpoch{500}}
	if _, err := uc.Run(context.Background(), id.Hex); !errors.Is(err, governance.ErrDRepUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	// A CIP-129 script id keeps its credential type; the vkey name resolves too.
	cs := governance.Credential{Hash: [28]byte{7}, Script: true}
	ids, _ := governance.DRepIDsOf(cs)
	rep, err := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "k", l: r.l, r: chain.None[chain.DRepState]()}, Epoch: fakeEpoch{1}}.Run(context.Background(), ids.CIP129)
	if err != nil || !rep.Credential.Script {
		t.Fatalf("script id: %+v %v", rep, err)
	}
	rep, err = CheckDRep{Store: r.store, DReps: &fakeDReps{src: "k", l: r.l, r: chain.None[chain.DRepState]()}, Epoch: fakeEpoch{1}}.Run(context.Background(), "d")
	if err != nil || rep.Credential.Hash != r.drep {
		t.Fatalf("by name: %+v %v", rep, err)
	}
}

// The anchor of a DRep is verified only when it can be fetched; without a
// verifier the check is refused unless the unverified anchor is acknowledged,
// and the decision is recorded. A document that does not hash to the anchor is
// reported and not verified.
//
// spec: SPO-21c-EXT-003, SPO-21c-EXT-004, SPO-21c-MODE-001, SPO-21c-OUT-002
func TestCheckDRepAnchorPolicy(t *testing.T) {
	r := newRig(t)
	doc := []byte(`{"body":{"title":"t"}}`)
	h := governance.HashDocument(doc)
	state := chain.Value(chain.DRepState{Deposit: 1, AnchorURL: "https://x.org/a.json", AnchorHash: governance.Anchor{Hash: h}.HashHex(), Expiry: chain.Value(uint64(510))})
	f := &fakeFetcher{docs: map[string][]byte{"https://x.org/a.json": doc}}
	base := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: state}, Epoch: fakeEpoch{500}, Anchors: AnchorSource{Fetcher: f}}
	if _, err := base.Run(context.Background(), "d"); !errors.Is(err, ErrAnchorVerifierMissing) {
		t.Fatalf("no verifier: %v", err)
	}
	base.AnchorUnverifiedAcknowledged = true
	rep, err := base.Run(context.Background(), "d")
	if err != nil || !rep.AnchorCheck.HashMatch || rep.AnchorCheck.Unverified == "" {
		t.Fatalf("acknowledged: %+v %v", rep.AnchorCheck, err)
	}
	v := &fakeVerifier{v: ports.AnchorVerdict{StructureOK: true, Authors: []ports.AnchorAuthor{{Name: "a", Valid: true}}}}
	base.Verifier, base.AnchorUnverifiedAcknowledged = v, false
	rep, err = base.Run(context.Background(), "d")
	if err != nil || rep.AnchorCheck.Verdict == nil || len(v.got) != 1 || v.got[0] != ports.AnchorCIP119 {
		t.Fatalf("verified: %+v %v", rep.AnchorCheck, err)
	}
	// A different document: the hash differs, no verification.
	f.docs["https://x.org/a.json"] = []byte(`{"other":1}`)
	v.got = nil
	rep, err = base.Run(context.Background(), "d")
	if err != nil || rep.AnchorCheck.HashMatch || len(v.got) != 0 || rep.AnchorCheck.Reason == "" {
		t.Fatalf("mismatch: %+v %v", rep.AnchorCheck, err)
	}
	// Offline (no fetcher): the anchor is shown, not checked, no verifier needed.
	off := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "snapshot", l: r.l, r: state}, Epoch: fakeEpoch{500}}
	rep, err = off.Run(context.Background(), "d")
	if err != nil || rep.AnchorCheck.Checked || rep.Anchor.URL == "" {
		t.Fatalf("offline: %+v %v", rep.AnchorCheck, err)
	}
	_ = custody.RoleDRep
}

// The anchor source: the computed hash wins over a given one, a body that is
// not JSON is refused, ipfs:// URLs go through the gateway and stay ipfs:// in
// the anchor, and with no fetcher the given hash is used.
//
// spec: SPO-21b-EXT-002, SPO-21b-EXT-003, SPO-21b-INV-001, SPO-21b-PRE-004, SPO-21b-PRE-005, SPO-21b-MODE-001, SPO-25a-INV-002, SPO-25a-PRE-008
func TestAnchorSource(t *testing.T) {
	doc := []byte(`{"a":1}`)
	f := &fakeFetcher{docs: map[string][]byte{"https://ipfs.io/ipfs/Qm1": doc, "https://x.org/bad": []byte("not json")}}
	s := AnchorSource{Fetcher: f}
	got, err := s.Resolve(context.Background(), "ipfs://Qm1", strings.Repeat("11", 32))
	if err != nil || got.Anchor.URL != "ipfs://Qm1" || got.Anchor.Hash != governance.HashDocument(doc) || !got.GivenHashDiffered {
		t.Fatalf("ipfs: %+v %v", got, err)
	}
	if _, err := s.Resolve(context.Background(), "https://x.org/bad", ""); !errors.Is(err, ErrAnchorFetch) {
		t.Fatalf("not json: %v", err)
	}
	if _, err := s.Resolve(context.Background(), "https://x.org/missing", ""); !errors.Is(err, ErrAnchorFetch) {
		t.Fatalf("404: %v", err)
	}
	off, err := AnchorSource{}.Resolve(context.Background(), "https://x.org/a", strings.Repeat("22", 32))
	if err != nil || off.Fetched || off.Anchor.Hash[0] != 0x22 {
		t.Fatalf("offline: %+v %v", off, err)
	}
	if _, err := (AnchorSource{}).Resolve(context.Background(), "https://x.org/a", ""); !errors.Is(err, ErrAnchorNotChecked) {
		t.Fatalf("offline without hash: %v", err)
	}
	if z, err := (AnchorSource{}).Resolve(context.Background(), "", ""); err != nil || !z.Anchor.IsZero() {
		t.Fatalf("no anchor: %+v %v", z, err)
	}
}

// A change below the minimum output value is refused and nothing is written,
// signed or queued (upstream exits 0 and builds nothing); an empty UTxO set is
// refused too.
//
// spec: SPO-21b-PRE-008, SPO-21d-PRE-005, SPO-23c-PRE-004, SPO-23e-PRE-004, SPO-Ptx-PRE-001, SPO-Ptx-PRE-002
func TestGovernanceTransactionsRefuseSmallFunds(t *testing.T) {
	r := newRig(t)
	r.chain.utxos[0].Lovelace = 400_000_000 // below dRepDeposit + fee + minimum output
	dr := &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	if _, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"}); err == nil {
		t.Fatal("a registration that cannot be paid must be refused")
	}
	r.nothingWritten(t)
	r.chain.utxos[0].Lovelace = 1_100_000 // fee leaves less than the minimum output
	ret := RetireDRep{Base: r.base, Certs: r.certs, DReps: &fakeDReps{src: "k", l: r.l, r: registeredDRep(1, "")}, Sources: SingleSourceAcknowledged, OnSingle: noopHook}
	if _, err := ret.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); err == nil {
		t.Fatal("a change below the minimum output must be refused")
	}
	r.nothingWritten(t)
	r.chain.utxos = nil
	if _, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"}); err == nil {
		t.Fatal("no UTxO")
	}
	r.nothingWritten(t)
	// The committee certificates pay no deposit: only the minimum output stops them.
	rc := newRig(t)
	rc.online()
	rc.chain.utxos[0].Lovelace = 1_100_000
	c := &fakeCommittee{l: rc.l, cold: chain.None[governance.CommitteeMember]()}
	if _, err := (AuthorizeCommitteeHotKey{Base: rc.base, Certs: rc.certs, Committee: c}).Run(context.Background(), AuthorizeRequest{Cold: "m", Hot: "h", Payer: "w.payment"}); err == nil {
		t.Fatal("an authorisation with a change below the minimum output")
	}
	cm := &fakeCommittee{l: rc.l, cold: member(governance.HotAuthorized, rc.hot)}
	if _, err := (ResignCommitteeColdKey{Base: rc.base, Certs: rc.certs, Committee: cm}).Run(context.Background(), ResignRequest{Cold: "m", Payer: "w.payment"}); err == nil {
		t.Fatal("a resignation with a change below the minimum output")
	}
	rc.nothingWritten(t)
}

// An anchor with no verifier wired is refused unless the operator acknowledged
// that it is not verified, before anything is read; the acknowledgement is
// recorded as a decision; with a verifier the fetched document is verified as CIP-119.
//
// spec: SPO-21b-EXT-003, SPO-21b-INV-001
func TestRegisterDRepAnchorPolicy(t *testing.T) {
	req := RegisterDRepRequest{DRep: "d", Payer: "w.payment", URL: "https://x.org/a.json", Hash: strings.Repeat("ab", 32)}
	r := newRig(t)
	dr := &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	_, err := RegisterDRep{Base: r.base, Certs: r.certs, DReps: dr}.Run(context.Background(), req)
	if !errors.Is(err, ErrAnchorVerifierMissing) {
		t.Fatalf("got %v", err)
	}
	if r.l.count("params") != 0 || r.l.count("drep-state") != 0 {
		t.Errorf("chain reads before the refusal: %v", r.l.calls)
	}
	r.nothingWritten(t)
	// no anchor: nothing to verify, nothing refused
	if _, err := (RegisterDRep{Base: r.base, Certs: r.certs, DReps: dr}).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"}); err != nil {
		t.Fatalf("no anchor: %v", err)
	}
	// acknowledged: goes on and records the decision
	r = newRig(t)
	dr = &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	res, err := RegisterDRep{Base: r.base, Certs: r.certs, DReps: dr, AnchorUnverifiedAcknowledged: true}.Run(context.Background(), req)
	if err != nil || len(res.Decisions) != 1 || !strings.Contains(res.Decisions[0], "not verified") {
		t.Fatalf("%+v %v", res.Decisions, err)
	}
	// a verifier verifies the fetched document as CIP-119 and no decision is recorded
	r = newRig(t)
	dr = &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	v := &fakeVerifier{v: ports.AnchorVerdict{StructureOK: true}}
	f := &fakeFetcher{docs: map[string][]byte{"https://x.org/a.json": []byte(`{}`)}}
	res, err = RegisterDRep{Base: r.base, Certs: r.certs, DReps: dr, Anchors: AnchorSource{Fetcher: f}, Verifier: v}.Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment", URL: "https://x.org/a.json"})
	if err != nil || len(res.Decisions) != 0 || len(v.got) != 1 || v.got[0] != ports.AnchorCIP119 {
		t.Fatalf("%+v %v %v", res.Decisions, err, v.got)
	}
}

// A second source that does not state the deposit (Blockfrost) corroborates the
// registration; a refund is never computed from it, and a second source that
// does not answer is refused naming both sources unless acknowledged.
//
// spec: SPO-21d-INV-001, SPO-21d-EXT-001
func TestRetireDRepCrossCheckWithASourceThatStatesNoDeposit(t *testing.T) {
	r := newRig(t)
	uc := RetireDRep{Base: r.base, Certs: r.certs, DReps: &fakeDReps{src: "koios", l: r.l, r: registeredDRep(500_000_000, "")}}
	uc.CrossCheck = &fakeDReps{src: "blockfrost", l: r.l, r: chain.Value(chain.DRepState{DepositUnstated: true})}
	res, err := uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if err != nil || res.SingleSource || len(res.Sources) != 2 || res.Refund != 500_000_000 {
		t.Fatalf("%+v %v", res, err)
	}
	// It says "not registered" while the primary says registered.
	r = newRig(t)
	uc = RetireDRep{Base: r.base, Certs: r.certs, DReps: &fakeDReps{src: "koios", l: r.l, r: registeredDRep(500_000_000, "")},
		CrossCheck: &fakeDReps{src: "blockfrost", l: r.l, r: chain.None[chain.DRepState]()}}
	_, err = uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if !errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), "koios says registered, deposit 500000000 lovelace") || !strings.Contains(err.Error(), "blockfrost says not registered") {
		t.Fatalf("%v", err)
	}
	// It is down.
	uc.CrossCheck = &fakeDReps{src: "blockfrost", l: r.l, r: chain.Unknown[chain.DRepState]("HTTP 503")}
	_, err = uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"})
	if !errors.Is(err, ErrSingleSource) || !strings.Contains(err.Error(), "blockfrost did not answer: HTTP 503") {
		t.Fatalf("%v", err)
	}
	uc.Sources = SingleSourceAcknowledged
	uc.OnSingle = noopHook
	if res, err := uc.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); err != nil || !res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
	// A source that states no deposit is never the one a refund rests on.
	r = newRig(t)
	only := RetireDRep{Base: r.base, Certs: r.certs, Sources: SingleSourceAcknowledged, OnSingle: noopHook,
		DReps: &fakeDReps{src: "blockfrost", l: r.l, r: chain.Value(chain.DRepState{DepositUnstated: true})}}
	if _, err := only.Run(context.Background(), RetireDRepRequest{DRep: "d", Payer: "w.payment"}); !errors.Is(err, governance.ErrDRepDeposit) {
		t.Fatalf("%v", err)
	}
}
