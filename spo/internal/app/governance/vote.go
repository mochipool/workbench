package governance

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the vote use cases.
var (
	// ErrActionNotOpen: the action is not on chain or has expired.
	ErrActionNotOpen = errors.New("the governance action is not on chain or has expired")
	// ErrNoVoterKey: no verification key of a DRep, committee hot key or pool by that name.
	ErrNoVoterKey = errors.New("no verification key (.drep.vkey, .cc-hot.vkey or .node.vkey) for the voter")
	// ErrVoteFile: a vote file the transaction cannot carry.
	ErrVoteFile = errors.New("invalid vote file")
)

// ---- the voter ------------------------------------------------------------------------

type voterKeys struct {
	// name is the owner name of the key artefacts (`<name>.drep.vkey`).
	name string
	role governance.Role
	hash [28]byte
}

// voteStampSuffix is the `_<yymmddHHMMSS>` that ends a vote file name stem.
var voteStampSuffix = regexp.MustCompile(`_[0-9]{12}$`)

var voterKinds = []struct {
	role       governance.Role
	suffix     string
	vkey, skey ports.Kind
	hws        ports.Kind
	custody    custody.Role
}{
	{governance.RoleDRep, ".drep", ports.DRepVKey, ports.DRepSKey, ports.DRepHwsFile, custody.RoleDRep},
	{governance.RoleCommitteeHot, ".cc-hot", ports.CCHotVKey, ports.CCHotSKey, ports.CCHotHwsFile, custody.RoleCommitteeHot},
	{governance.RolePool, ".node", ports.NodeVKey, ports.NodeSKey, ports.NodeHwsFile, custody.RolePoolCold},
}

// findVoter follows SPO-24a-IN-004: the argument without `.vkey` names a stem;
// when the stem already ends `.drep`, `.cc-hot` or `.node` that is the voter
// type, else `<name>.drep.vkey`, `<name>.cc-hot.vkey` and `<name>.node.vkey` are
// tried in that order and the first that exists wins. It never reads a signing key.
//
// spec: SPO-24a-IF-002, SPO-24a-IN-001, SPO-24a-IN-004, SPO-24a-INV-001
func findVoter(r ports.Reader, arg string) (voterKeys, error) {
	stem := strings.TrimSuffix(strings.TrimSuffix(trimDir(arg), "."), ".vkey")
	for _, vk := range voterKinds {
		if base, ok := strings.CutSuffix(stem, vk.suffix); ok && base != "" && !strings.ContainsAny(base, "/\\") {
			b, err := get(r, ports.Ref{Name: base, Kind: vk.vkey})
			if err != nil {
				return voterKeys{}, err
			}
			h, err := vkeyHash(b)
			return voterKeys{name: base, role: vk.role, hash: h}, err
		}
	}
	if stem == "" || strings.ContainsAny(stem, "/\\") {
		return voterKeys{}, fmt.Errorf("%w: %q", ErrBadWord, arg)
	}
	for _, vk := range voterKinds {
		b, err := r.Get(ports.Ref{Name: stem, Kind: vk.vkey})
		if errors.Is(err, ports.ErrNotFound) {
			continue
		}
		if err != nil {
			return voterKeys{}, err
		}
		h, err := vkeyHash(b)
		return voterKeys{name: stem, role: vk.role, hash: h}, err
	}
	return voterKeys{}, fmt.Errorf("%w: %s", ErrNoVoterKey, arg)
}

// voteFileName is the output name stem of SPO-24a-IF-002: a trailing `.drep`,
// `.cc-hot`, `.node` and `.vkey`, each stripped at most once and in that order.
func voteFileName(arg string) string {
	s := trimDir(strings.TrimSuffix(arg, "."))
	for _, suf := range []string{".drep", ".cc-hot", ".node", ".vkey"} {
		s = strings.TrimSuffix(s, suf)
	}
	return s
}

// ---- 24a --------------------------------------------------------------------------------

// Choice is the operator's answer for one action.
type Choice struct {
	Decision governance.Decision
	// Skip leaves this action without a vote file; Cancel ends the run.
	Skip, Cancel bool
}

// ActionView is what the operator decides on: the open action, the voter's
// earlier vote on it and the verified title of its anchor document.
type ActionView struct {
	State   governance.ActionState
	Voter   governance.Voter
	Earlier governance.Decision // empty when none
	// Title is the verified `body.title` of the action's anchor document;
	// empty when not verified.
	Title string
	// Anchor is what was done with the on-chain anchor.
	Anchor AnchorCheck
}

// Chooser asks the operator for a decision per action (SPO-24a-PR-001). The
// default of an empty answer is Cancel.
type Chooser interface {
	Choose(ctx context.Context, v ActionView) (Choice, error)
}

// GenerateVote chooses the actions to vote on and writes one vote file per
// decision (upstream 24a): `<voter>_<yymmddHHMMSS>.drep.vote`, `.cc-hot.vote` or
// `.pool.vote`, the `governance vote create` file with the action title injected
// as its description.
//
// Offline is refused (SPO-24a-PRE-001). The role rule of 24a decides which role
// may vote on which action type; a violation ends the whole run, as upstream
// does (SPO-24a-PRE-003). Files already written stay. Two votes in the same
// second get the next free second instead of overwriting each other
// (SPO-24a-INV-006).
type GenerateVote struct {
	Store   ports.Store
	Votes   ports.VoteFileBuilder
	Actions ports.GovActionReader
	Params  ports.ProtocolParametersReader
	Epoch   ports.EpochReader
	Clock   ports.Clock
	Chooser Chooser
	// Anchors fetches the anchor of the vote and the on-chain anchors of the
	// actions; a zero value has no fetcher.
	Anchors AnchorSource
	// Verifier checks the CIP-100/108 documents. It is optional by policy: with
	// an anchor to process and no verifier the run is refused unless
	// AnchorUnverifiedAcknowledged (SPO-24a-IN-002), and the decision is recorded.
	Verifier                     ports.AnchorVerifier
	AnchorUnverifiedAcknowledged bool
	// Offline composes the use case with a snapshot that cannot answer.
	Offline bool
}

// GenerateVoteRequest names the voter as typed, the action id word or `all`,
// and the optional anchor of the vote.
type GenerateVoteRequest struct {
	Voter, Action string
	URL, Hash     string
}

// VoteWritten is one vote file the run wrote.
type VoteWritten struct {
	Ref         ports.Ref
	Vote        governance.Vote
	Description string
}

// VotesGenerated is the result.
type VotesGenerated struct {
	Files     []VoteWritten
	Skipped   int
	Cancelled bool
	Decisions []string
}

// Run reads the open actions and asks for a decision per action.
//
// spec: SPO-24a-IF-001, SPO-24a-IF-002, SPO-24a-IF-003, SPO-24a-IF-004, SPO-24a-IN-001, SPO-24a-IN-002, SPO-24a-IN-003, SPO-24a-IN-004,
// spec: SPO-24a-PRE-001, SPO-24a-PRE-002, SPO-24a-PRE-003, SPO-24a-PRE-004, SPO-24a-INV-001, SPO-24a-INV-002, SPO-24a-INV-004, SPO-24a-INV-005,
// spec: SPO-24a-EXT-001, SPO-24a-EXT-002, SPO-24a-EXT-003, SPO-24a-EXT-004, SPO-24a-MODE-001, SPO-24a-MODE-002, SPO-24a-MODE-003, SPO-24a-MODE-004,
// spec: SPO-24a-INV-003, SPO-24a-OUT-001, SPO-24a-OUT-002, SPO-24a-OUT-003, SPO-24a-PR-001, SPO-24a-INV-006, SPO-Pfiles-OUT-029
func (uc GenerateVote) Run(ctx context.Context, req GenerateVoteRequest) (VotesGenerated, error) {
	var res VotesGenerated
	if uc.Offline {
		return res, ErrOfflineUnsupported
	}
	if req.Voter == "" || req.Action == "" {
		return res, errors.New("a vote needs a voter and an action id or `all`")
	}
	var want *governance.ActionID
	if !strings.EqualFold(req.Action, "all") {
		id, err := governance.ParseActionID(req.Action)
		if err != nil {
			return res, err
		}
		want = &id
	}
	if req.Hash != "" && req.URL == "" {
		return res, governance.ErrAnchorPair // SPO-24a-PRE-002
	}
	if uc.Chooser == nil || uc.Actions == nil || uc.Params == nil || uc.Epoch == nil || uc.Clock == nil {
		return res, fmt.Errorf("%w: a chooser, the action, parameter and epoch readers and a clock are needed", ErrMisconfigured)
	}
	var vk voterKeys
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		vk, err = findVoter(r, req.Voter)
		return err
	}); err != nil {
		return res, err
	}
	voter := governance.Voter{Role: vk.role, Cred: governance.Credential{Hash: vk.hash}}

	// The gate on the verifier comes before any anchor or action is processed.
	processesAnchors := req.URL != "" || uc.Anchors.Fetcher != nil
	if processesAnchors && uc.Verifier == nil && !uc.AnchorUnverifiedAcknowledged {
		return res, ErrAnchorVerifierMissing
	}
	anchor, err := uc.Anchors.Resolve(ctx, req.URL, req.Hash)
	if err != nil {
		return res, err
	}
	if anchor.GivenHashDiffered {
		res.Decisions = append(res.Decisions, "the given anchor hash differed from the document's and was replaced")
	}
	if anchor.Fetched && uc.Verifier != nil {
		if _, _, err := verifyAnchor(ctx, uc.Verifier, false, ports.AnchorCIP100, anchor.Doc); err != nil {
			return res, err
		}
	} else if anchor.Fetched {
		res.Decisions = append(res.Decisions, "the vote's anchor document was not verified (no verifier wired, acknowledged)")
	}

	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return res, fmt.Errorf("protocol parameters: %w", err)
	}
	if params.ProtocolMajor < MinConwayMajor {
		return res, ErrProtocolTooOld
	}
	epoch, err := uc.Epoch.Epoch(ctx)
	if err != nil {
		return res, fmt.Errorf("the current epoch: %w", err)
	}
	rd, err := uc.Actions.GovActions(ctx, want)
	if err != nil {
		return res, fmt.Errorf("the governance state from %s: %w", uc.Actions.Source(), err)
	}
	if rd.IsUnknown() {
		return res, fmt.Errorf("%w: the governance state from %s: %s", ErrUnverified, uc.Actions.Source(), rd.Why())
	}
	all, _ := rd.Get()
	var open []governance.ActionState
	for _, a := range all {
		if want != nil && a.ID != *want {
			continue
		}
		if a.Open(epoch) {
			open = append(open, a)
		}
	}
	if want != nil && len(open) == 0 {
		return res, fmt.Errorf("%w: %s", ErrActionNotOpen, want.Hex())
	}

	for _, a := range open {
		if err := governance.CheckCanVote(voter.Role, a.Kind, params.ProtocolMajor, a.Security); err != nil {
			return res, fmt.Errorf("%s: %w", a.ID.Hex(), err)
		}
		view := ActionView{State: a, Voter: voter, Earlier: a.Votes[voter]}
		if !a.Anchor.IsZero() && uc.Anchors.Fetcher != nil {
			view.Anchor, view.Title, err = uc.checkActionAnchor(ctx, a)
			if err != nil {
				return res, err
			}
			if view.Anchor.Unverified != "" {
				res.Decisions = append(res.Decisions, view.Anchor.Unverified)
			}
		}
		ch, err := uc.Chooser.Choose(ctx, view)
		if err != nil {
			return res, fmt.Errorf("choose: %w", err)
		}
		switch {
		case ch.Cancel:
			res.Cancelled = true
			return res, nil
		case ch.Skip:
			res.Skipped++
			continue
		}
		vote := governance.Vote{Voter: voter, Action: a.ID, Decision: ch.Decision, Anchor: anchor.Anchor}
		if err := vote.Validate(); err != nil {
			return res, err
		}
		desc := describe(view)
		vf, err := uc.Votes.BuildVoteFile(vote, desc)
		if err != nil {
			return res, err
		}
		ref, err := uc.write(ctx, voteFileName(req.Voter), voter.Role, vf.Envelope)
		if err != nil {
			return res, err
		}
		res.Files = append(res.Files, VoteWritten{Ref: ref, Vote: vote, Description: desc})
	}
	return res, nil
}

// describe is the injected description: the verified title with every character
// outside the fixed set removed; empty with no verified title; `-` for a
// verified document without a title.
func describe(v ActionView) string {
	if v.Anchor.Verdict == nil {
		return ""
	}
	if v.Title == "" {
		return "-"
	}
	return governance.SanitizeDescription(v.Title)
}

func (uc GenerateVote) checkActionAnchor(ctx context.Context, a governance.ActionState) (AnchorCheck, string, error) {
	doc, err := uc.Anchors.Fetcher.Fetch(ctx, governance.FetchURL(a.Anchor.URL, uc.Anchors.IPFSGateway))
	if err != nil {
		return AnchorCheck{Checked: true, Reason: "the document could not be fetched: " + err.Error()}, "", nil
	}
	out := AnchorCheck{Checked: true, HashMatch: governance.HashDocument(doc) == a.Anchor.Hash}
	if !out.HashMatch {
		out.Reason = "the document does not hash to the registered anchor hash"
		return out, "", nil
	}
	vd, dec, err := verifyAnchor(ctx, uc.Verifier, uc.AnchorUnverifiedAcknowledged, ports.AnchorCIP108, doc)
	if err != nil {
		return AnchorCheck{}, "", err
	}
	out.Verdict, out.Unverified = vd, dec
	if vd != nil && vd.StructureOK {
		return out, vd.Title, nil
	}
	out.Verdict = nil // the title counts only when the check succeeded
	return out, "", nil
}

// write stores the vote file under the first free `<name>_<stamp>` of the local time.
func (uc GenerateVote) write(ctx context.Context, nm string, role governance.Role, env []byte) (ports.Ref, error) {
	kind := ports.VoteFileKind(role)
	t := uc.Clock.Now()
	var ref ports.Ref
	err := uc.Store.Update(ctx, func(w ports.Writer) error {
		for i := 0; i < 600; i++ {
			ref = ports.Ref{Name: governance.VoteFileName(nm, t.Add(time.Duration(i)*time.Second).Format("060102150405")), Kind: kind}
			ok, err := w.Exists(ref)
			if err != nil {
				return err
			}
			if !ok {
				return w.Put(ref, env)
			}
		}
		return fmt.Errorf("no free vote file name for %s", nm)
	})
	return ref, err
}

// ---- 24b --------------------------------------------------------------------------------

// RegisterVote puts one or more vote files on chain (upstream 24b): the votes
// of one voter, signed by that voter's key and the payment key (two witnesses
// whatever the number of votes). No deposit; the change is inputs - fee.
//
// The checks of upstream are kept: each vote file's role fits the signing key
// (SPO-24b-PRE-003), all files carry the same voter hash (PRE-004), an action
// id occurs in one file only (PRE-005) and the voter key matches the voter
// hash (PRE-008). No check is made against chain state (INV-001); an empty
// list of vote files is refused (the port note of IF-005), where upstream
// builds a plain transaction.
type RegisterVote struct {
	Base
	Votes ports.VoteFileBuilder
}

// RegisterVoteRequest names the paying address and the vote files by their
// file names. Voter is an optional override: the owner of the signing key as
// typed. Without it the signing key is derived from the vote files: the stored
// key of the files' role whose hash is the voter of the files, looked up under
// the stem of each file name before its time stamp.
type RegisterVoteRequest struct {
	Voter, Payer string
	// Files are vote file names as given (`x_<ts>.drep.vote`).
	Files   []string
	Message []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase is the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
	// Unrestricted is the operator's consent to the device's unrestricted mode
	// for several votes at once (`--allow-unrestricted-mode`, SPO-24b-PR-001:
	// asked, default Yes, when more than one vote file is given and the payment
	// or voter key is on a device; declining exits 2). Never implied; without it
	// that case is refused with ErrUnrestrictedNeeded. It has no effect with one
	// vote file or with key files only.
	Unrestricted bool
}

func parseVoteFileName(s string) (ports.Ref, error) {
	s = trimDir(s)
	for _, k := range []ports.Kind{ports.VoteDRepFile, ports.VoteCCHotFile, ports.VotePoolFile} {
		if base, ok := strings.CutSuffix(s, "."+string(k)); ok && base != "" && !strings.ContainsAny(base, "/\\") {
			return ports.Ref{Name: base, Kind: k}, nil
		}
	}
	return ports.Ref{}, fmt.Errorf("%w: %q is not a .drep.vote, .cc-hot.vote or .pool.vote file", ErrVoteFile, s)
}

// Run registers the votes.
//
// spec: SPO-24b-IF-001, SPO-24b-IF-002, SPO-24b-IF-003, SPO-24b-IF-004, SPO-24b-IF-005, SPO-24b-IN-001, SPO-24b-IN-002, SPO-24b-IN-003,
// spec: SPO-24b-PRE-002, SPO-24b-PRE-003, SPO-24b-PRE-004, SPO-24b-PRE-005, SPO-24b-PRE-006, SPO-24b-PRE-007, SPO-24b-PRE-008, SPO-24b-INV-001,
// spec: SPO-24b-OUT-001, SPO-24b-OUT-002, SPO-24b-INV-002, SPO-24b-EXT-003, SPO-24b-EXT-004, SPO-24b-MODE-001, SPO-24b-MODE-002, SPO-24b-MODE-003,
// spec: SPO-24b-INV-009, SPO-24b-INV-014
func (uc RegisterVote) Run(ctx context.Context, req RegisterVoteRequest) (Result, error) {
	if req.Payer == "" {
		return Result{}, errors.New("a vote registration needs a paying address")
	}
	if len(req.Files) == 0 {
		return Result{}, fmt.Errorf("%w: no vote file given", ErrVoteFile)
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return Result{}, fmt.Errorf("payer: %w", err)
	}
	var pay payer
	var atts []txbuild.VoteAttachment
	var vk voterKeys
	var signer txflow.Slot
	var refs []ports.Ref
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if pay, err = uc.readPayer(r, pn); err != nil {
			return err
		}
		seen := map[governance.ActionID]bool{}
		for _, f := range req.Files {
			ref, err := parseVoteFileName(f)
			if err != nil {
				return err
			}
			refs = append(refs, ref)
			raw, err := get(r, ref)
			if err != nil {
				return err
			}
			vf, err := uc.Votes.DecodeVoteFile(raw)
			if err != nil {
				return fmt.Errorf("%s: %w: %v", f, ErrVoteFile, err)
			}
			if ports.VoteFileKind(vf.Vote.Voter.Role) != ref.Kind {
				return fmt.Errorf("%s: %w: the voter in the file is a %s", f, ErrVoteFile, vf.Vote.Voter.Role)
			}
			if len(atts) > 0 && atts[0].Vote.Voter != vf.Vote.Voter {
				return fmt.Errorf("%s: %w: the vote files carry different voters", f, ErrVoteFile)
			}
			if seen[vf.Vote.Action] {
				return fmt.Errorf("%s: %w: the action %s is voted on in two files", f, ErrVoteFile, vf.Vote.Action.Hex())
			}
			seen[vf.Vote.Action] = true
			atts = append(atts, txbuild.VoteAttachment{Vote: vf.Vote, CBOR: vf.CBOR})
		}
		// The signing key: the key of the files' role whose hash is the voter of
		// the files. The name is the override as typed, else the stem of each
		// file name before its time stamp (SPO-24a-OUT-001 names the file
		// `<voter>_<stamp>`).
		role, want := atts[0].Vote.Voter.Role, txbuild.KeyHash(atts[0].Vote.Voter.Cred.Hash)
		for _, kd := range voterKinds {
			if kd.role != role {
				continue
			}
			var stems []string
			if req.Voter != "" {
				stem := strings.TrimSuffix(trimDir(req.Voter), ".")
				stem = strings.TrimSuffix(strings.TrimSuffix(stem, ".vkey"), kd.suffix)
				stem = strings.TrimSuffix(strings.TrimSuffix(stem, ".skey"), ".hwsfile")
				stem = strings.TrimSuffix(stem, kd.suffix)
				if stem == "" || strings.ContainsAny(stem, "/\\") {
					return fmt.Errorf("%w: %q", ErrBadWord, req.Voter)
				}
				stems = []string{stem}
			} else {
				for _, ref := range refs {
					st := voteStampSuffix.ReplaceAllString(ref.Name, "")
					if st != "" && !slices.Contains(stems, st) {
						stems = append(stems, st)
					}
				}
			}
			var mismatch string
			for _, stem := range stems {
				b, err := r.Get(ports.Ref{Name: stem, Kind: kd.vkey})
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
				if h != want {
					mismatch = stem
					continue
				}
				vkey, err := keyring.Held(r, kd.custody, stem, ErrNoSigningKey)
				if err != nil {
					return err
				}
				vk = voterKeys{name: stem, role: kd.role, hash: h}
				signer = txflow.Slot{Label: string(kd.role) + " key", Key: vkey, Hash: h}
				return nil
			}
			switch {
			case req.Voter != "" && mismatch != "":
				return fmt.Errorf("%w: the signing key of %s is not the key of the voter in the vote files", ErrVoteFile, mismatch)
			case req.Voter != "":
				return fmt.Errorf("%w: %s", ErrNoVoterKey, req.Voter)
			case mismatch != "":
				return fmt.Errorf("%w: the key %s is not the voter of the vote files, and no other stored key is named by them: name the signing voter", ErrNoVoterKey, mismatch)
			}
			return fmt.Errorf("%w: none of the vote file names (%s) names a stored %s key whose hash is the voter of the files: name the signing voter", ErrNoVoterKey, strings.Join(stems, ", "), role)
		}
		return fmt.Errorf("%w: unknown voter role", ErrVoteFile)
	}); err != nil {
		return Result{}, err
	}
	_ = vk
	run := txRun{payer: pay, signers: []txflow.Slot{signer}, votes: atts, message: req.Message, extras: req.Extras, pass: req.Passphrase}
	// spec: SPO-24b-PRE-009 (payment hardware with a key-file voter is refused,
	// SPO-Ptx-PRE-006; a key-file payer with a hardware voter is allowed),
	// SPO-24b-PR-001 (unrestricted mode for several votes, never implied).
	signerHW := hwkeys.OnDevice(uc.Pipeline.Signers, signer.Key)
	payHW := hwkeys.OnDevice(uc.Pipeline.Signers, pay.key)
	if payHW && !signerHW {
		return Result{}, txflow.ErrMixedHolders
	}
	if len(atts) > 1 && (payHW || signerHW) {
		if !req.Unrestricted {
			return Result{}, ErrUnrestrictedNeeded
		}
		run.unrestricted = true
	}
	if err := uc.early(run); err != nil {
		return Result{}, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return Result{}, err
	}
	run.params = params
	run.summary = ports.TxSummary{Kind: "vote", Account: vk.name}
	// Upstream's history line prints an unset variable: "to ''" (SPO-24b-MODE-003).
	run.queued = ports.QueuedTx{Type: "Transaction", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
		Description: fmt.Sprintf("signed utxo-transaction from '%s' to ''", pay.name)}
	res, sum, err := uc.execute(ctx, run)
	if err != nil {
		return Result{}, err
	}
	return Result{Result: res, Summary: sum}, nil
}
