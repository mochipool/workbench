package governance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrHashFileMismatch: a `.hash` file does not hold the hash of the verification key beside it.
var ErrHashFileMismatch = errors.New("the .hash file does not hold the hash of the verification key")

// coldInputs is what the store holds for a committee member's cold key.
type coldInputs struct {
	name   string
	hash   stake.KeyHash
	holder custody.Holder
}

func hashOfFile(r ports.Reader, nm string, vk, hf ports.Kind) (stake.KeyHash, error) {
	v, err := get(r, ports.Ref{Name: nm, Kind: vk})
	if err != nil {
		return stake.KeyHash{}, err
	}
	vh, err := vkeyHash(v)
	if err != nil {
		return stake.KeyHash{}, fmt.Errorf("%s: %w", ports.Ref{Name: nm, Kind: vk}, err)
	}
	hb, err := get(r, ports.Ref{Name: nm, Kind: hf})
	if err != nil {
		return stake.KeyHash{}, err
	}
	fh, err := governance.ParseHash28(firstLine(hb))
	if err != nil {
		return stake.KeyHash{}, fmt.Errorf("%s: %w", ports.Ref{Name: nm, Kind: hf}, err)
	}
	if fh != [28]byte(vh) {
		return stake.KeyHash{}, fmt.Errorf("%w: %s", ErrHashFileMismatch, ports.Ref{Name: nm, Kind: hf})
	}
	return stake.KeyHash(vh), nil
}

func readCold(r ports.Reader, nm string) (coldInputs, error) {
	h, err := hashOfFile(r, nm, ports.CCColdVKey, ports.CCColdHash)
	if err != nil {
		return coldInputs{}, err
	}
	holder, err := holderOf(r, ports.Ref{Name: nm, Kind: ports.CCColdSKey}, ports.Ref{Name: nm, Kind: ports.CCColdHwsFile})
	if err != nil {
		return coldInputs{}, err
	}
	return coldInputs{name: nm, hash: h, holder: holder}, nil
}

func (c coldInputs) slot() txflow.Slot {
	return txflow.Slot{Label: "committee cold key", Key: custody.KeyRef{Role: custody.RoleCommitteeCold, Holder: c.holder, Owner: c.name}, Hash: txbuild.KeyHash(c.hash)}
}

func (c coldInputs) cred() governance.Credential { return governance.Credential{Hash: c.hash} }

// committeeState reads one member by its cold credential. A failed reader
// is an error; Unknown stays Unknown for the domain rule to refuse.
func committeeState(ctx context.Context, rd ports.CommitteeStateReader, cold governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	if rd == nil {
		return chain.Reading[governance.CommitteeMember]{}, fmt.Errorf("the committee state: %w", ErrNoChainReader)
	}
	r, err := rd.CommitteeMember(ctx, cold)
	if err != nil {
		return r, fmt.Errorf("the committee state from %s: %w", rd.Source(), err)
	}
	return r, nil
}

// ---- 23c --------------------------------------------------------------------------------

// AuthorizeCommitteeHotKey authorises a committee hot key for a cold key on
// chain (upstream 23c): two witnesses, the payment key and the cold key; the
// hot key never signs; no deposit.
//
// Offline is refused, as upstream does (SPO-23c-MODE-001): the committee state
// is needed, and a composition that queues the transaction gets
// ErrOfflineUnsupported before anything is read. The certificate
// `<hot>.cc-hot.cert` is named after the hot key and written after the
// transaction was submitted.
type AuthorizeCommitteeHotKey struct {
	Base
	Certs ports.CertificateBuilder
	// Committee reads the member's state (required).
	Committee ports.CommitteeStateReader
}

// AuthorizeRequest names the cold and hot members and the paying address.
type AuthorizeRequest struct {
	Cold, Hot, Payer string
	Message          []string
}

// Run authorises the hot key.
//
// spec: SPO-23c-IF-001, SPO-23c-IN-001, SPO-23c-IN-002, SPO-23c-PRE-002, SPO-23c-PRE-003, SPO-23c-EXT-001, SPO-23c-EXT-003, SPO-23c-MODE-001,
// spec: SPO-23c-INV-001, SPO-23c-INV-002, SPO-23c-INV-003, SPO-23c-INV-004, SPO-23c-INV-005, SPO-23c-INV-006, SPO-23c-OUT-001, SPO-23c-PR-001,
// spec: SPO-23c-MODE-002, SPO-Pfiles-OUT-028
func (uc AuthorizeCommitteeHotKey) Run(ctx context.Context, req AuthorizeRequest) (Result, error) {
	if uc.Pipeline.Queue != nil {
		return Result{}, ErrOfflineUnsupported
	}
	if req.Cold == "" || req.Hot == "" || req.Payer == "" {
		return Result{}, errors.New("a hot-key authorisation needs a cold key, a hot key and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	cn, err := coldName(req.Cold)
	if err != nil {
		return Result{}, fmt.Errorf("cold key: %w", err)
	}
	hn, err := hotName(req.Hot)
	if err != nil {
		return Result{}, fmt.Errorf("hot key: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var cold coldInputs
	var hot stake.KeyHash
	var pay payer
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if cold, err = readCold(r, cn); err != nil {
			return err
		}
		if hot, err = hashOfFile(r, hn, ports.CCHotVKey, ports.CCHotHash); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	probe := stake.Certificate{Spec: stake.Spec{Kind: stake.CertCommitteeAuthorize, Stake: cold.hash, Hot: hot}}
	run := txRun{payer: pay, signers: []txflow.Slot{cold.slot()}, certs: []stake.Certificate{probe}, message: req.Message}
	if err := uc.early(run); err != nil {
		return Result{}, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	state, err := committeeState(ctx, uc.Committee, cold.cred())
	if err != nil {
		return Result{}, err
	}
	if _, err := governance.CheckAuthorize(state, governance.Credential{Hash: hot}); err != nil {
		return Result{}, err
	}
	cert, err := uc.Certs.BuildCertificate(stake.Spec{Kind: stake.CertCommitteeAuthorize, Stake: cold.hash, Hot: hot})
	if err != nil {
		return Result{}, err
	}
	run.certs, run.params = []stake.Certificate{cert}, params
	run.summary = ports.TxSummary{Kind: "committee hot key authorisation", Account: cn, Sources: []chain.Source{uc.Committee.Source()}}
	res, sum, err := uc.execute(ctx, run)
	if err != nil {
		return Result{}, err
	}
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: hn, Kind: ports.CCHotCert}, cert.Envelope)
	}); err != nil {
		return Result{}, fmt.Errorf("the transaction was sent, but the certificate file could not be stored: %w", err)
	}
	return Result{Result: res, Summary: sum, Certificate: cert, Sources: run.summary.Sources}, nil
}

// ---- 23e --------------------------------------------------------------------------------

// ResignCommitteeColdKey resigns a committee cold key on chain (upstream 23e):
// two witnesses, the payment key and the cold key; an optional anchor. The
// member must be on chain; an already resigned key is submitted again, as
// upstream does (SPO-23e-INV-001). Offline is refused (SPO-23e-MODE-001).
type ResignCommitteeColdKey struct {
	Base
	Certs     ports.CertificateBuilder
	Committee ports.CommitteeStateReader
	Anchors   AnchorSource
	// Verifier checks the CIP-100 document. Optional by policy: with an anchor
	// and no verifier the run is refused unless AnchorUnverifiedAcknowledged,
	// and the decision is recorded in the result.
	Verifier                     ports.AnchorVerifier
	AnchorUnverifiedAcknowledged bool
}

// ResignRequest names the cold member and the paying address and the anchor words.
type ResignRequest struct {
	Cold, Payer string
	URL, Hash   string
	Message     []string
}

// Run resigns the cold key. `<cold>.cc-cold-ret.cert` is written after the
// transaction was submitted.
//
// spec: SPO-23e-IF-001, SPO-23e-IF-002, SPO-23e-IN-001, SPO-23e-IN-002, SPO-23e-EXT-001, SPO-23e-EXT-002, SPO-23e-INV-001, SPO-23e-INV-002,
// spec: SPO-23e-INV-003, SPO-23e-MODE-001, SPO-23e-MODE-002, SPO-23e-MODE-003, SPO-23e-OUT-001, SPO-23e-OUT-002, SPO-23e-PRE-002, SPO-23e-PRE-003,
// spec: SPO-23e-PR-001, SPO-Pfiles-OUT-028
func (uc ResignCommitteeColdKey) Run(ctx context.Context, req ResignRequest) (Result, error) {
	if uc.Pipeline.Queue != nil {
		return Result{}, ErrOfflineUnsupported
	}
	if req.Cold == "" || req.Payer == "" {
		return Result{}, errors.New("a cold-key resignation needs a cold key and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	if err := gateAnchor(uc.Verifier, uc.AnchorUnverifiedAcknowledged, req.URL); err != nil {
		return Result{}, err
	}
	cn, err := coldName(req.Cold)
	if err != nil {
		return Result{}, fmt.Errorf("cold key: %w", err)
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var cold coldInputs
	var pay payer
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if cold, err = readCold(r, cn); err != nil {
			return err
		}
		pay, err = uc.readPayer(r, pn)
		return err
	}); err != nil {
		return Result{}, err
	}
	probe := stake.Certificate{Spec: stake.Spec{Kind: stake.CertCommitteeResign, Stake: cold.hash}}
	run := txRun{payer: pay, signers: []txflow.Slot{cold.slot()}, certs: []stake.Certificate{probe}, message: req.Message}
	if err := uc.early(run); err != nil {
		return Result{}, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	state, err := committeeState(ctx, uc.Committee, cold.cred())
	if err != nil {
		return Result{}, err
	}
	if err := governance.CheckResign(state); err != nil {
		return Result{}, err
	}
	anchor, err := uc.Anchors.Resolve(ctx, req.URL, req.Hash)
	if err != nil {
		return Result{}, err
	}
	decisions, err := anchorDecisions(ctx, uc.Verifier, ports.AnchorCIP100, anchor)
	if err != nil {
		return Result{}, err
	}
	if anchor.GivenHashDiffered {
		decisions = append(decisions, "the given anchor hash differed from the document's and was replaced")
	}
	if m, ok := state.Get(); ok && m.Auth == governance.HotResigned {
		decisions = append(decisions, "the key had already resigned: a second resignation is submitted, as upstream does")
	}
	cert, err := uc.Certs.BuildCertificate(stake.Spec{Kind: stake.CertCommitteeResign, Stake: cold.hash, Anchor: anchor.Anchor})
	if err != nil {
		return Result{}, err
	}
	run.certs, run.params = []stake.Certificate{cert}, params
	run.summary = ports.TxSummary{Kind: "committee cold key resignation", Account: cn, Sources: []chain.Source{uc.Committee.Source()}}
	res, sum, err := uc.execute(ctx, run)
	if err != nil {
		return Result{}, err
	}
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		return w.Put(ports.Ref{Name: cn, Kind: ports.CCColdRetCert}, cert.Envelope)
	}); err != nil {
		return Result{}, fmt.Errorf("the transaction was sent, but the certificate file could not be stored: %w", err)
	}
	return Result{Result: res, Summary: sum, Certificate: cert, Sources: run.summary.Sources, Decisions: decisions}, nil
}

// ---- 23d --------------------------------------------------------------------------------

// CheckCommittee reports what the chain says about a committee credential
// (upstream 23d): the members whose cold credential is the one, and, when
// there are none, the members whose authorised hot credential is. Online or
// light only: offline is refused (SPO-23d-PRE-002).
type CheckCommittee struct {
	Store     ports.Store
	Committee ports.CommitteeStateReader
	// Offline composes the use case with a snapshot that cannot answer.
	Offline bool
}

// CommitteeMatch is one member the lookup found.
type CommitteeMatch struct {
	Member governance.CommitteeMember
	// ByHot: found through its authorised hot credential.
	ByHot bool
}

// CommitteeReport is the result of CheckCommittee. Matches is empty when the
// credential is on no member (a positive answer: an error is returned when
// the provider failed or did not say).
type CommitteeReport struct {
	Credential governance.Credential
	IDs        governance.CommitteeIDs
	Matches    []CommitteeMatch
	Source     chain.Source
}

// Run resolves the word and reads the committee state.
//
// spec: SPO-23d-IF-001, SPO-23d-IF-002, SPO-23d-IN-001, SPO-23d-INV-001, SPO-23d-INV-002, SPO-23d-INV-003, SPO-23d-INV-004, SPO-23d-EXT-001,
// spec: SPO-23d-EXT-002, SPO-23d-PRE-002, SPO-23d-PRE-003, SPO-23d-OUT-001
func (uc CheckCommittee) Run(ctx context.Context, word string) (CommitteeReport, error) {
	if uc.Offline {
		return CommitteeReport{}, ErrOfflineUnsupported
	}
	if word == "" {
		return CommitteeReport{}, errors.New("a committee check needs a hash, an id or a name")
	}
	cred, err := uc.resolve(ctx, word)
	if err != nil {
		return CommitteeReport{}, err
	}
	if uc.Committee == nil {
		return CommitteeReport{}, fmt.Errorf("the committee state: %w", ErrNoChainReader)
	}
	rep := CommitteeReport{Credential: cred, Source: uc.Committee.Source()}
	// The same hash is tried as a key and as a script credential (SPO-23d-EXT-001).
	creds := []governance.Credential{cred}
	if alt := (governance.Credential{Hash: cred.Hash, Script: !cred.Script}); true {
		creds = append(creds, alt)
	}
	find := func(byHot bool) error {
		for _, c := range creds {
			var r chain.Reading[governance.CommitteeMember]
			var err error
			if byHot {
				r, err = uc.Committee.CommitteeMemberByHot(ctx, c)
			} else {
				r, err = uc.Committee.CommitteeMember(ctx, c)
			}
			if err != nil {
				return fmt.Errorf("the committee state from %s: %w", rep.Source, err)
			}
			if r.IsUnknown() {
				return fmt.Errorf("%w: %s", governance.ErrCommitteeUnknown, r.Why())
			}
			if m, ok := r.Get(); ok {
				rep.Matches = append(rep.Matches, CommitteeMatch{Member: m, ByHot: byHot})
			}
		}
		return nil
	}
	if err := find(false); err != nil {
		return CommitteeReport{}, err
	}
	if len(rep.Matches) == 0 {
		if err := find(true); err != nil {
			return CommitteeReport{}, err
		}
	}
	rep.IDs, err = governance.CommitteeIDsOf(cred, false)
	return rep, err
}

// resolve follows SPO-23d-IN-001: a hash, a bech32 id (any of the four spellings),
// then the `.cc-cold.hash` and `.cc-hot.hash` files and the verification keys.
func (uc CheckCommittee) resolve(ctx context.Context, word string) (governance.Credential, error) {
	c, isID, err := governance.ParseCommitteeWord(word)
	if err != nil {
		return governance.Credential{}, err
	}
	if isID {
		return c, nil
	}
	if uc.Store == nil {
		return governance.Credential{}, fmt.Errorf("%w: %q", ErrBadWord, word)
	}
	nm := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(trimDir(word), ".hash"), ".cc-cold"), ".cc-hot")
	if nm == "" || strings.ContainsAny(nm, "/\\") {
		return governance.Credential{}, fmt.Errorf("%w: %q", ErrBadWord, word)
	}
	var out governance.Credential
	err = uc.Store.View(ctx, func(r ports.Reader) error {
		for _, k := range []ports.Kind{ports.CCColdHash, ports.CCHotHash} {
			b, err := r.Get(ports.Ref{Name: nm, Kind: k})
			if errors.Is(err, ports.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			h, err := governance.ParseHash28(firstLine(b))
			if err != nil {
				return fmt.Errorf("%s: %w", ports.Ref{Name: nm, Kind: k}, err)
			}
			out = governance.Credential{Hash: h}
			return nil
		}
		for _, k := range []ports.Kind{ports.CCColdVKey, ports.CCHotVKey} {
			b, err := r.Get(ports.Ref{Name: nm, Kind: k})
			if errors.Is(err, ports.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			h, err := vkeyHash(b)
			if err != nil {
				return err
			}
			out = governance.Credential{Hash: h}
			return nil
		}
		return fmt.Errorf("%w: %q is no hash, id or stored committee key", ErrBadWord, word)
	})
	return out, err
}
