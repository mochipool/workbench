package governance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func member(auth governance.HotAuth, hot [28]byte) chain.Reading[governance.CommitteeMember] {
	return chain.Value(governance.CommitteeMember{Auth: auth, Hot: governance.Credential{Hash: hot}, Status: "Active", Expiry: chain.Value(uint64(600))})
}

func (r *rig) authorize(c *fakeCommittee) AuthorizeCommitteeHotKey {
	r.online()
	return AuthorizeCommitteeHotKey{Base: r.base, Certs: r.certs, Committee: c}
}

// A hot key is authorised by the cold key: two witnesses (payment, cold key;
// the hot key never signs), no deposit, the certificate named after the hot key.
//
// spec: SPO-23c-INV-004, SPO-23c-OUT-001, SPO-23c-EXT-003, SPO-23c-IN-001, SPO-23c-INV-006, SPO-23c-INV-002
// spec: SPO-23c-IF-001, SPO-23c-INV-001, SPO-23c-INV-007, SPO-23c-INV-008, SPO-23c-INV-009, SPO-23c-INV-010, SPO-23c-INV-011, SPO-23c-INV-012, SPO-23c-INV-013, SPO-23c-INV-014, SPO-23c-INV-015, SPO-23c-INV-016, SPO-23c-INV-017, SPO-23c-INV-018, SPO-23c-PR-001, SPO-23c-MODE-002, SPO-23c-INV-005
func TestAuthorizeCommitteeHotKey(t *testing.T) {
	r := newRig(t)
	c := &fakeCommittee{l: r.l, cold: chain.None[governance.CommitteeMember]()}
	res, err := r.authorize(c).Run(context.Background(), AuthorizeRequest{Cold: "m.cc-cold", Hot: "h", Payer: "w.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Kind != stake.CertCommitteeAuthorize || res.Certificate.Hot != r.hot || res.Certificate.Stake != r.cold || res.Deposit != 0 {
		t.Fatalf("certificate %+v", res.Certificate)
	}
	if r.l.count("witness committee-cold m") != 1 || r.l.count("witness committee-hot") != 0 || r.l.count("assemble witnesses=2") != 1 {
		t.Errorf("witnesses: %v", r.l.calls)
	}
	if r.store.files[ports.Ref{Name: "h", Kind: ports.CCHotCert}] == nil {
		t.Error("the certificate is not stored under the hot key's name")
	}
	if res.Submitted != true {
		t.Error("not submitted")
	}
}

// A resigned cold key cannot be authorised; the same hot key is refused; an
// unknown answer is refused and never read as "not on chain".
//
// spec: SPO-23c-PRE-002, SPO-23c-PRE-003, SPO-23c-EXT-001
// spec: SPO-23c-INV-003
func TestAuthorizeCommitteeHotKeyRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		state chain.Reading[governance.CommitteeMember]
		want  error
	}{
		"resigned": {member(governance.HotResigned, [28]byte{}), governance.ErrCommitteeResigned},
		"same hot": {chain.Value(governance.CommitteeMember{Auth: governance.HotAuthorized, Hot: governance.Credential{Hash: [28]byte{}}}), governance.ErrSameHotKey},
		"unknown":  {chain.Unknown[governance.CommitteeMember]("koios down"), governance.ErrCommitteeUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			st := tc.state
			if name == "same hot" {
				st = chain.Value(governance.CommitteeMember{Auth: governance.HotAuthorized, Hot: governance.Credential{Hash: r.hot}})
			}
			_, err := r.authorize(&fakeCommittee{l: r.l, cold: st}).Run(context.Background(), AuthorizeRequest{Cold: "m", Hot: "h", Payer: "w.payment"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v", err)
			}
			r.nothingWritten(t)
		})
	}
}

// A queueing composition (offline) is refused before anything is read, for
// both the authorisation and the resignation, as upstream does.
//
// spec: SPO-23c-MODE-001, SPO-23e-MODE-001
// spec: SPO-23e-INV-012, SPO-23c-INV-005
func TestCommitteeTransactionsRefuseOffline(t *testing.T) {
	r := newRig(t) // the rig queues
	c := &fakeCommittee{l: r.l, cold: chain.None[governance.CommitteeMember]()}
	if _, err := (AuthorizeCommitteeHotKey{Base: r.base, Certs: r.certs, Committee: c}).Run(context.Background(), AuthorizeRequest{Cold: "m", Hot: "h", Payer: "w.payment"}); !errors.Is(err, ErrOfflineUnsupported) {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := (ResignCommitteeColdKey{Base: r.base, Certs: r.certs, Committee: c}).Run(context.Background(), ResignRequest{Cold: "m", Payer: "w.payment"}); !errors.Is(err, ErrOfflineUnsupported) {
		t.Fatalf("resign: %v", err)
	}
	if r.l.count("committee-state") != 0 || r.l.count("params") != 0 {
		t.Errorf("reads before the refusal: %v", r.l.calls)
	}
	r.nothingWritten(t)
}

// A hardware cold key is refused up front.
//
// spec: SPO-23c-INV-006, SPO-23e-INV-003
func TestAuthorizeCommitteeHardwareRefused(t *testing.T) {
	r := newRig(t)
	r.hardware(ports.Ref{Name: "m", Kind: ports.CCColdSKey}, ports.CCColdHwsFile)
	c := &fakeCommittee{l: r.l, cold: chain.None[governance.CommitteeMember]()}
	if _, err := r.authorize(c).Run(context.Background(), AuthorizeRequest{Cold: "m", Hot: "h", Payer: "w.payment"}); err == nil {
		t.Fatal("hardware must be refused")
	}
	if r.l.count("committee-state") != 0 || r.l.count("params") != 0 {
		t.Errorf("reads before the refusal: %v", r.l.calls)
	}
	r.nothingWritten(t)
}

// A .hash file that is not the hash of the verification key beside it is refused.
//
// spec: SPO-23c-IN-001
func TestAuthorizeHashFileMismatch(t *testing.T) {
	r := newRig(t)
	r.store.files[ports.Ref{Name: "m", Kind: ports.CCColdHash}] = []byte(strings.Repeat("00", 28) + "\n")
	c := &fakeCommittee{l: r.l, cold: chain.None[governance.CommitteeMember]()}
	if _, err := r.authorize(c).Run(context.Background(), AuthorizeRequest{Cold: "m", Hot: "h", Payer: "w.payment"}); !errors.Is(err, ErrHashFileMismatch) {
		t.Fatalf("got %v", err)
	}
	r.nothingWritten(t)
}

// A cold key resigns when it is on chain, with the optional anchor; a key that is
// not on chain has nothing to resign; an already resigned key is submitted
// again and the decision is recorded.
//
// spec: SPO-23e-EXT-002, SPO-23e-INV-002, SPO-23e-PRE-002, SPO-23e-INV-001, SPO-23e-OUT-002, SPO-23e-PRE-003, SPO-23e-MODE-002
// spec: SPO-23e-IF-001, SPO-23e-IF-002, SPO-23e-IN-001, SPO-23e-IN-002, SPO-23e-EXT-001, SPO-23e-INV-004, SPO-23e-INV-005, SPO-23e-INV-006, SPO-23e-INV-007, SPO-23e-INV-008, SPO-23e-INV-009, SPO-23e-INV-010, SPO-23e-INV-011, SPO-23e-INV-013, SPO-23e-INV-014, SPO-23e-INV-015, SPO-23e-PR-001, SPO-23e-MODE-003, SPO-23e-OUT-001
func TestResignCommitteeColdKey(t *testing.T) {
	r := newRig(t)
	r.online()
	f := &fakeFetcher{docs: map[string][]byte{"https://x.org/r.json": []byte(`{}`)}}
	uc := ResignCommitteeColdKey{Base: r.base, Certs: r.certs, Committee: &fakeCommittee{l: r.l, cold: member(governance.HotAuthorized, r.hot)}, Anchors: AnchorSource{Fetcher: f}, AnchorUnverifiedAcknowledged: true}
	res, err := uc.Run(context.Background(), ResignRequest{Cold: "m.cc-cold", Payer: "w.payment", URL: "https://x.org/r.json"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate.Kind != stake.CertCommitteeResign || res.Certificate.Anchor.URL != "https://x.org/r.json" || res.Certificate.Anchor.Hash != governance.HashDocument([]byte(`{}`)) {
		t.Fatalf("certificate %+v", res.Certificate)
	}
	if r.store.files[ports.Ref{Name: "m", Kind: ports.CCColdRetCert}] == nil {
		t.Error("certificate not stored under the cold key's name")
	}
	if len(res.Decisions) != 1 || !strings.Contains(res.Decisions[0], "not verified") {
		t.Errorf("decisions %v", res.Decisions)
	}
	if _, err := uc.Run(context.Background(), ResignRequest{Cold: "m", Payer: "w.payment", Hash: strings.Repeat("00", 32)}); !errors.Is(err, governance.ErrAnchorPair) {
		t.Errorf("hash without url: %v", err)
	}
	again := ResignCommitteeColdKey{Base: r.base, Certs: r.certs, Committee: &fakeCommittee{l: r.l, cold: member(governance.HotResigned, [28]byte{})}}
	res, err = again.Run(context.Background(), ResignRequest{Cold: "m", Payer: "w.payment"})
	if err != nil || len(res.Decisions) != 1 {
		t.Fatalf("second resignation: %+v %v", res.Decisions, err)
	}
	r2 := newRig(t)
	r2.online()
	none := ResignCommitteeColdKey{Base: r2.base, Certs: r2.certs, Committee: &fakeCommittee{l: r2.l, cold: chain.None[governance.CommitteeMember]()}}
	if _, err := none.Run(context.Background(), ResignRequest{Cold: "m", Payer: "w.payment"}); !errors.Is(err, governance.ErrNotOnChain) {
		t.Fatalf("not on chain: %v", err)
	}
	r2.nothingWritten(t)
}

// The committee check resolves hashes and ids of every spelling, tries the
// cold credential first and the hot one only when no member matched, and
// reports an unknown answer as an error.
//
// spec: SPO-23d-IN-001, SPO-23d-EXT-001, SPO-23d-INV-002, SPO-23d-PRE-003, SPO-23d-OUT-001, SPO-23d-PRE-002
// spec: SPO-23d-IF-001, SPO-23d-IF-002, SPO-23d-INV-003, SPO-23d-INV-004, SPO-23d-MODE-001, SPO-23d-EXT-002
func TestCheckCommittee(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	hot := governance.Credential{Hash: r.hot}
	ids, _ := governance.CommitteeIDsOf(hot, true)
	// A hot CIP-129 id resolves (upstream's length test misses it) and finds the member by its hot key.
	c := &fakeCommittee{l: r.l, cold: chain.None[governance.CommitteeMember](), byHot: member(governance.HotAuthorized, r.hot)}
	rep, err := CheckCommittee{Store: r.store, Committee: c}.Run(ctx, ids.CIP129)
	if err != nil || len(rep.Matches) == 0 || !rep.Matches[0].ByHot {
		t.Fatalf("by hot: %+v %v", rep, err)
	}
	if r.l.count("committee-state-by-hot") == 0 {
		t.Error("the hot lookup did not run")
	}
	// A name resolves through the stored hash file.
	r.l.calls = nil
	c.cold = member(governance.HotAuthorized, r.hot)
	rep, err = CheckCommittee{Store: r.store, Committee: c}.Run(ctx, "m")
	if err != nil || len(rep.Matches) == 0 || rep.Matches[0].ByHot || r.l.count("committee-state-by-hot") != 0 {
		t.Fatalf("by cold name: %+v %v %v", rep, err, r.l.calls)
	}
	// Not on the committee is a positive, empty answer.
	empty := &fakeCommittee{l: r.l, cold: chain.None[governance.CommitteeMember](), byHot: chain.None[governance.CommitteeMember]()}
	rep, err = CheckCommittee{Store: r.store, Committee: empty}.Run(ctx, ids.Hex)
	if err != nil || len(rep.Matches) != 0 {
		t.Fatalf("empty: %+v %v", rep, err)
	}
	unk := &fakeCommittee{l: r.l, cold: chain.Unknown[governance.CommitteeMember]("x")}
	if _, err := (CheckCommittee{Store: r.store, Committee: unk}).Run(ctx, ids.Hex); !errors.Is(err, governance.ErrCommitteeUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := (CheckCommittee{Store: r.store, Committee: empty, Offline: true}).Run(ctx, ids.Hex); !errors.Is(err, ErrOfflineUnsupported) {
		t.Fatalf("offline: %v", err)
	}
	if _, err := (CheckCommittee{Store: r.store, Committee: empty}).Run(ctx, "nosuch"); !errors.Is(err, ErrBadWord) {
		t.Fatalf("bad word: %v", err)
	}
}

// An anchor with no verifier wired is refused unless acknowledged, before the
// chain is read; with a verifier the fetched document is verified as CIP-100.
//
// spec: SPO-23e-MODE-002, SPO-23e-PRE-003
func TestResignAnchorPolicy(t *testing.T) {
	req := ResignRequest{Cold: "m", Payer: "w.payment", URL: "https://x.org/r.json", Hash: strings.Repeat("ab", 32)}
	r := newRig(t)
	r.online()
	c := &fakeCommittee{l: r.l, cold: member(governance.HotAuthorized, r.hot)}
	_, err := ResignCommitteeColdKey{Base: r.base, Certs: r.certs, Committee: c}.Run(context.Background(), req)
	if !errors.Is(err, ErrAnchorVerifierMissing) {
		t.Fatalf("got %v", err)
	}
	if r.l.count("committee-state") != 0 || r.l.count("params") != 0 {
		t.Errorf("chain reads before the refusal: %v", r.l.calls)
	}
	r.nothingWritten(t)
	v := &fakeVerifier{v: ports.AnchorVerdict{StructureOK: true}}
	f := &fakeFetcher{docs: map[string][]byte{"https://x.org/r.json": []byte(`{}`)}}
	res, err := ResignCommitteeColdKey{Base: r.base, Certs: r.certs, Committee: c, Anchors: AnchorSource{Fetcher: f}, Verifier: v}.Run(context.Background(), ResignRequest{Cold: "m", Payer: "w.payment", URL: "https://x.org/r.json"})
	if err != nil || len(res.Decisions) != 0 || len(v.got) != 1 || v.got[0] != ports.AnchorCIP100 {
		t.Fatalf("%+v %v %v", res.Decisions, err, v.got)
	}
}
