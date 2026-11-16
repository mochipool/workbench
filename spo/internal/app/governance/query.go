package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// QueryFilter is what the words of 24c select. Every set field must match
// (SPO-24c-IF-009); the zero filter is `all`.
type QueryFilter struct {
	Action *governance.ActionID
	Kind   governance.ActionKind
	// Voter, when set, keeps the proposals the credential voted on and shows
	// its answer. VoterRole is "" for a bare hash (type Hash): it then matches a
	// vote of any role.
	Voter     *governance.Credential
	VoterRole governance.Role
	// DepositReturn keeps the proposals whose deposit returns to this key credential.
	DepositReturn *governance.Credential
}

// ParseQueryWords classifies the words as 24c does, first matching form wins. A
// file word needs the store (nil store: file forms are refused). A word matching
// no form is refused with a hint to use `all`.
//
// spec: SPO-24c-IF-001, SPO-24c-IF-002, SPO-24c-IF-003, SPO-24c-IF-004, SPO-24c-IF-005, SPO-24c-IF-006, SPO-24c-IF-007, SPO-24c-IF-008, SPO-24c-IF-009, SPO-24c-IN-001
func ParseQueryWords(ctx context.Context, st ports.Store, words []string) (QueryFilter, error) {
	var f QueryFilter
	if len(words) == 0 {
		return f, errors.New("a vote query needs at least one word: an action id, a voter, a stake account, an action type or `all`")
	}
	for _, w := range words {
		lower := strings.ToLower(strings.TrimSpace(w))
		switch {
		case lower == "all":
			return QueryFilter{}, nil
		case governance.ActionKind(w).Valid() || kindFold(lower) != "":
			k := kindFold(lower)
			if f.Kind != "" {
				return f, fmt.Errorf("a second action type %q", w)
			}
			f.Kind = k
			continue
		case strings.HasPrefix(lower, "gov_action1") || strings.Contains(lower, "#"):
			id, err := governance.ParseActionID(lower)
			if err != nil {
				return f, err
			}
			if f.Action != nil && !strings.HasPrefix(lower, "gov_action1") {
				return f, errors.New("a second action id")
			}
			f.Action = &id
			continue
		}
		// Voter by identifier.
		if h, err := governance.ParseHash28(lower); err == nil {
			if f.Voter != nil && f.VoterRole == "" {
				return f, errors.New("a second voter hash")
			}
			f.Voter, f.VoterRole = &governance.Credential{Hash: h}, ""
			continue
		}
		if sw, err := stake.ParseDRepWord(lower); err == nil && sw.IsID {
			f.Voter, f.VoterRole = &governance.Credential{Script: sw.DRep.Kind == stake.DRepScript, Hash: sw.DRep.Hash}, governance.RoleDRep
			continue
		}
		if c, isID, err := governance.ParseCommitteeWord(lower); isID && err == nil && strings.HasPrefix(lower, "cc_hot") {
			f.Voter, f.VoterRole = &c, governance.RoleCommitteeHot
			continue
		} else if isID && err != nil {
			return f, err
		}
		if strings.HasPrefix(lower, "pool1") {
			id, err := chain.ParsePoolBech32(lower)
			if err != nil {
				return f, err
			}
			f.Voter, f.VoterRole = &governance.Credential{Hash: id}, governance.RolePool
			continue
		}
		if strings.HasPrefix(lower, "stake") {
			_, data, err := chain.Bech32Decode(lower)
			if err != nil || len(data) != 29 {
				return f, fmt.Errorf("%q is not a stake address", w)
			}
			c := governance.Credential{Script: data[0]>>4 == 0xf}
			copy(c.Hash[:], data[1:])
			f.DepositReturn = &c
			continue
		}
		if st != nil {
			ok, err := fileWord(ctx, st, w, &f)
			if err != nil {
				return f, err
			}
			if ok {
				continue
			}
		}
		return f, fmt.Errorf("%w: %q matches no form; use `all` to see every open action", ErrBadWord, w)
	}
	return f, nil
}

func kindFold(lower string) governance.ActionKind {
	for _, k := range governance.ActionKinds() {
		if strings.ToLower(string(k)) == lower {
			return k
		}
	}
	return ""
}

// fileWord tries `<w>.drep.id`, `<w>.cc-hot.hash`, `<w>.pool.id`, the verification
// keys and `<w>.staking.addr`.
func fileWord(ctx context.Context, st ports.Store, w string, f *QueryFilter) (bool, error) {
	nm := trimDir(w)
	if nm == "" || strings.ContainsAny(nm, "/\\") {
		return false, nil
	}
	found := false
	err := st.View(ctx, func(r ports.Reader) error {
		try := func(k ports.Kind) ([]byte, bool, error) {
			b, err := r.Get(ports.Ref{Name: nm, Kind: k})
			if errors.Is(err, ports.ErrNotFound) {
				return nil, false, nil
			}
			return b, err == nil, err
		}
		if b, ok, err := try(ports.DRepID); err != nil || ok {
			if err != nil {
				return err
			}
			sw, perr := stake.ParseDRepWord(firstLine(b))
			if perr != nil || !sw.IsID {
				return fmt.Errorf("%s.drep.id does not hold a DRep id", nm)
			}
			f.Voter, f.VoterRole, found = &governance.Credential{Script: sw.DRep.Kind == stake.DRepScript, Hash: sw.DRep.Hash}, governance.RoleDRep, true
			return nil
		}
		if b, ok, err := try(ports.CCHotHash); err != nil || ok {
			if err != nil {
				return err
			}
			h, perr := governance.ParseHash28(firstLine(b))
			if perr != nil {
				return perr
			}
			f.Voter, f.VoterRole, found = &governance.Credential{Hash: h}, governance.RoleCommitteeHot, true
			return nil
		}
		if b, ok, err := try(ports.PoolIDFile); err != nil || ok {
			if err != nil {
				return err
			}
			h, perr := governance.ParseHash28(firstLine(b))
			if perr != nil {
				return perr
			}
			f.Voter, f.VoterRole, found = &governance.Credential{Hash: h}, governance.RolePool, true
			return nil
		}
		for _, vk := range voterKinds {
			if b, ok, err := try(vk.vkey); err != nil || ok {
				if err != nil {
					return err
				}
				h, herr := vkeyHash(b)
				if herr != nil {
					return herr
				}
				f.Voter, f.VoterRole, found = &governance.Credential{Hash: h}, vk.role, true
				return nil
			}
		}
		if b, ok, err := try(ports.StakingAddr); err != nil || ok {
			if err != nil {
				return err
			}
			_, data, derr := chain.Bech32Decode(firstLine(b))
			if derr != nil || len(data) != 29 {
				return fmt.Errorf("%s.staking.addr is not a stake address", nm)
			}
			c := governance.Credential{Script: data[0]>>4 == 0xf}
			copy(c.Hash[:], data[1:])
			f.DepositReturn, found = &c, true
		}
		return nil
	})
	return found, err
}

// QueryVote reads the open governance actions and derives for each the tally
// of 24c: the DRep, pool and committee percentages, their thresholds and the
// verdict (domain/governance.Compute). It is a projection: it writes nothing and
// no transaction is gated by it. Offline is refused (SPO-24c-PRE-001).
//
// Every failed or unknown reader is an error, where upstream carries on with
// empty data and reports every proposal as accepted or at 0 %
// (SPO-24c-EXT-001, SPO-24c-EXT-002, SPO-24c-EXT-003, SPO-24c-EXT-005).
//
// The tally comes from one of two sources. With Dists it is computed from the
// stake distributions (online, SPO-24c-OUT-001 to OUT-003). Without Dists, with
// Summaries, the three percentages are the provider's own voting summary
// (light mode, SPO-24c-MODE-005) and only the thresholds are computed here.
type QueryVote struct {
	Store     ports.Store
	Actions   ports.GovActionReader
	Dists     ports.StakeDistributionReader
	Summaries ports.VotingSummaryReader
	Params    ports.ProtocolParametersReader
	Epoch     ports.EpochReader
	Offline   bool
}

// VoteReport is the result.
type VoteReport struct {
	Epoch uint64
	Major uint64
	// TallySource names where the percentages came from; FromSummary is true
	// when they are the provider's own (light mode) and not computed here.
	TallySource chain.Source
	FromSummary bool
	// Tallies are the matching open proposals, in the order the chain lists them.
	Tallies []governance.Tally
	// Answers holds the filtered voter's vote per action (SPO-24c-OUT-007).
	Answers map[governance.ActionID]governance.Decision
}

// Run applies the filter and tallies each matching proposal.
//
// spec: SPO-24c-PRE-001, SPO-24c-MODE-001, SPO-24c-MODE-002, SPO-24c-MODE-006, SPO-24c-INV-001, SPO-24c-INV-002, SPO-24c-EXT-001, SPO-24c-EXT-002,
// spec: SPO-24c-EXT-003, SPO-24c-EXT-004, SPO-24c-EXT-005, SPO-24c-EXT-006, SPO-24c-OUT-001, SPO-24c-OUT-002, SPO-24c-OUT-003, SPO-24c-OUT-004,
// spec: SPO-24c-OUT-005, SPO-24c-OUT-006, SPO-24c-OUT-007, SPO-24c-INV-004, SPO-24c-INV-005, SPO-24c-IN-003
func (uc QueryVote) Run(ctx context.Context, f QueryFilter) (VoteReport, error) {
	var rep VoteReport
	if uc.Offline {
		return rep, ErrOfflineUnsupported
	}
	if uc.Actions == nil || (uc.Dists == nil && uc.Summaries == nil) || uc.Params == nil || uc.Epoch == nil {
		return rep, fmt.Errorf("%w: the action, distribution (or voting summary), parameter and epoch readers are needed", ErrMisconfigured)
	}
	epoch, err := uc.Epoch.Epoch(ctx)
	if err != nil {
		return rep, fmt.Errorf("the current epoch: %w", err)
	}
	rep.Epoch = epoch
	rd, err := uc.Actions.GovActions(ctx, f.Action)
	if err != nil {
		return rep, fmt.Errorf("the governance state from %s: %w", uc.Actions.Source(), err)
	}
	if rd.IsUnknown() {
		return rep, fmt.Errorf("%w: the governance state from %s: %s", ErrUnverified, uc.Actions.Source(), rd.Why())
	}
	all, _ := rd.Get()
	var keep []governance.ActionState
	if f.Action != nil {
		var found bool
		for _, a := range all {
			found = found || a.ID == *f.Action
		}
		if !found {
			return rep, fmt.Errorf("%w: %s", ErrActionNotOpen, f.Action.Hex())
		}
	}
	for _, a := range all {
		switch {
		case f.Action != nil && a.ID != *f.Action:
		case !a.Open(epoch): // an expired action passes the id step upstream and is dropped later
		case f.Kind != "" && a.Kind != f.Kind:
		case f.DepositReturn != nil && a.DepositReturn != *f.DepositReturn: // a script return account never matches a key filter
		case f.Voter != nil && !voted(a, *f.Voter, f.VoterRole):
		default:
			keep = append(keep, a)
		}
	}
	if f.Voter != nil {
		rep.Answers = map[governance.ActionID]governance.Decision{}
		for _, a := range keep {
			rep.Answers[a.ID] = answerOf(a, *f.Voter, f.VoterRole)
		}
	}
	if len(keep) == 0 {
		return rep, nil
	}
	p, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return rep, fmt.Errorf("protocol parameters: %w", err)
	}
	rep.Major = p.ProtocolMajor
	drepTh, poolTh, err := thresholdsOf(p.Raw)
	if err != nil {
		return rep, err
	}
	if uc.Dists == nil {
		return uc.fromSummaries(ctx, rep, keep, p, drepTh, poolTh)
	}
	rep.TallySource = uc.Dists.Source()
	dd, err := uc.Dists.DRepDistribution(ctx)
	if err != nil {
		return rep, fmt.Errorf("the DRep stake distribution from %s: %w", uc.Dists.Source(), err)
	}
	if dd.IsUnknown() {
		return rep, fmt.Errorf("%w: the DRep stake distribution: %s", ErrUnverified, dd.Why())
	}
	pd, err := uc.Dists.PoolDistribution(ctx)
	if err != nil {
		return rep, fmt.Errorf("the pool stake distribution from %s: %w", uc.Dists.Source(), err)
	}
	if pd.IsUnknown() {
		return rep, fmt.Errorf("%w: the pool stake distribution: %s", ErrUnverified, pd.Why())
	}
	cm, err := uc.Dists.CommitteeComposition(ctx)
	if err != nil {
		return rep, fmt.Errorf("the committee state from %s: %w", uc.Dists.Source(), err)
	}
	if cm.IsUnknown() {
		return rep, fmt.Errorf("%w: the committee state: %s", ErrUnverified, cm.Why())
	}
	dv, _ := dd.Get()
	pv, _ := pd.Get()
	cv, _ := cm.Get()
	for _, a := range keep {
		t, err := governance.Compute(governance.TallyInput{Action: a, Major: p.ProtocolMajor, DReps: dv, Pools: pv, Committee: cv, DRepThresholds: drepTh, PoolThresholds: poolTh})
		if err != nil {
			return rep, err
		}
		rep.Tallies = append(rep.Tallies, t)
	}
	return rep, nil
}

// fromSummaries tallies from the provider's voting summaries: the percentages
// are the provider's, the thresholds are computed. Any summary or threshold
// that is unknown is an error, never a zero.
func (uc QueryVote) fromSummaries(ctx context.Context, rep VoteReport, keep []governance.ActionState, p chain.ProtocolParameters, drepTh, poolTh map[string]chain.Rational) (VoteReport, error) {
	rep.TallySource, rep.FromSummary = uc.Summaries.Source(), true
	ct, err := uc.Summaries.CommitteeThreshold(ctx)
	if err != nil {
		return rep, fmt.Errorf("the committee threshold from %s: %w", uc.Summaries.Source(), err)
	}
	if ct.IsUnknown() {
		return rep, fmt.Errorf("%w: the committee threshold: %s", ErrUnverified, ct.Why())
	}
	th, _ := ct.Get()
	for _, a := range keep {
		sr, err := uc.Summaries.VotingSummary(ctx, a.ID)
		if err != nil {
			return rep, fmt.Errorf("the voting summary of %s from %s: %w", a.ID.Hex(), uc.Summaries.Source(), err)
		}
		if sr.IsUnknown() {
			return rep, fmt.Errorf("%w: the voting summary of %s: %s", ErrUnverified, a.ID.Hex(), sr.Why())
		}
		sv, _ := sr.Get()
		t, err := governance.ComputeFromSummary(governance.SummaryTallyInput{Action: a, Summary: sv, Major: p.ProtocolMajor,
			Committee: governance.CommitteeComposition{Exists: true, Threshold: th}, DRepThresholds: drepTh, PoolThresholds: poolTh})
		if err != nil {
			return rep, err
		}
		rep.Tallies = append(rep.Tallies, t)
	}
	return rep, nil
}

func roleMatches(r governance.Role, want governance.Role) bool { return want == "" || r == want }

// voted: the credential voted on the action (a bare hash matches any role).
func voted(a governance.ActionState, c governance.Credential, role governance.Role) bool {
	for v := range a.Votes {
		if v.Cred.Hash == c.Hash && roleMatches(v.Role, role) {
			return true
		}
	}
	return false
}

// answerOf reads the voter's answer: DRep, then committee, then pool for a bare hash.
func answerOf(a governance.ActionState, c governance.Credential, role governance.Role) governance.Decision {
	for _, r := range []governance.Role{governance.RoleDRep, governance.RoleCommitteeHot, governance.RolePool} {
		if !roleMatches(r, role) {
			continue
		}
		if d, ok := a.Votes[governance.Voter{Role: r, Cred: c}]; ok {
			return d
		}
		if d, ok := a.Votes[governance.Voter{Role: r, Cred: governance.Credential{Script: !c.Script, Hash: c.Hash}}]; ok {
			return d
		}
	}
	return ""
}

// thresholdsOf reads the DRep and pool voting thresholds of the protocol
// parameters document: JSON numbers, converted exactly to fractions. A key that
// is absent is 0, as upstream reads it (SPO-24c-INV-004).
func thresholdsOf(raw json.RawMessage) (drep, pool map[string]chain.Rational, err error) {
	var doc struct {
		D map[string]json.Number `json:"dRepVotingThresholds"`
		P map[string]json.Number `json:"poolVotingThresholds"`
	}
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("%w: the protocol parameters document is missing: the thresholds cannot be read", ErrUnverified)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("the voting thresholds of the protocol parameters: %w", err)
	}
	conv := func(m map[string]json.Number) (map[string]chain.Rational, error) {
		out := map[string]chain.Rational{}
		for k, n := range m {
			r, ok := new(big.Rat).SetString(n.String())
			if !ok || r.Sign() < 0 || !r.Num().IsUint64() || !r.Denom().IsUint64() {
				return nil, fmt.Errorf("the threshold %s = %s is not a fraction", k, n)
			}
			out[k] = chain.Rational{Num: r.Num().Uint64(), Den: r.Denom().Uint64()}
		}
		return out, nil
	}
	if drep, err = conv(doc.D); err != nil {
		return nil, nil, err
	}
	pool, err = conv(doc.P)
	return drep, pool, err
}
