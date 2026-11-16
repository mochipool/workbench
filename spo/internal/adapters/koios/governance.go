package koios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.EpochReader          = (*Client)(nil)
	_ ports.EraReader            = (*Client)(nil)
	_ ports.CommitteeStateReader = (*Client)(nil)
	_ ports.GovActionReader      = (*Client)(nil)
	_ ports.VotingSummaryReader  = (*Client)(nil)

	// The light-mode parameters document is where upstream's light mode takes
	// the constitution and the last enacted action ids from (SPO-25a-IN-002,
	// SPO-25a-MODE-002).
	_ ports.ConstitutionReader = (*LightParameters)(nil)
	_ ports.LastEnactedReader  = (*LightParameters)(nil)
)

// Not implemented for Koios, on purpose: ports.StakeDistributionReader.
// Upstream's light mode computes no tally from stake distributions: it takes
// the three percentages from the proposal voting summary (SPO-24c-MODE-005,
// SPO-Clight-EXT-011), which is what VotingSummary reads. A DRep or pool stake
// distribution from Koios would be an endpoint upstream does not use in light
// mode, so none is invented here and the capability stays absent.

// Epoch implements ports.EpochReader: the epoch of GET /tip, the same
// request upstream's get_currentEpoch makes in light mode (SPO-Cchain-OUT-001,
// SPO-Clight-OUT-017).
func (c *Client) Epoch(ctx context.Context) (uint64, error) {
	t, err := c.Tip(ctx)
	if err != nil {
		return 0, err
	}
	return t.Epoch, nil
}

var eraName = regexp.MustCompile(`^[A-Za-z]{3,20}$`)

// Era implements ports.EraReader: the `era` of GET /tip (recorded: "Conway"),
// in lower case (SPO-Ptransfer-OUT-003). An answer with no era, or one that is
// not a plain word, is an error: there is no default era.
func (c *Client) Era(ctx context.Context) (string, error) {
	body, err := c.get(ctx, "tip", "/tip", "", true)
	if err != nil {
		return "", err
	}
	var rows []struct {
		Era optional[string] `json:"era"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return "", fmt.Errorf("koios tip: not a JSON array: %w", err)
	}
	if len(rows) == 0 || !rows[0].Era.present || rows[0].Era.null {
		return "", errors.New("koios tip: answer has no era")
	}
	if !eraName.MatchString(rows[0].Era.val) {
		return "", fmt.Errorf("koios tip: era %q is not an era name", prefix([]byte(rows[0].Era.val)))
	}
	return strings.ToLower(rows[0].Era.val), nil
}

// ---- committee ------------------------------------------------------------

type committeeMemberRow struct {
	Status     optional[string]  `json:"status"`
	HotHex     optional[string]  `json:"cc_hot_hex"`
	HotScript  optional[bool]    `json:"cc_hot_has_script"`
	ColdHex    optional[string]  `json:"cc_cold_hex"`
	ColdScript optional[bool]    `json:"cc_cold_has_script"`
	Expiration optional[uintVal] `json:"expiration_epoch"`
}

type committeeInfoRow struct {
	Num     optional[uintVal]    `json:"quorum_numerator"`
	Den     optional[uintVal]    `json:"quorum_denominator"`
	Members []committeeMemberRow `json:"members"`
}

// committeeInfo fetches SPO-Clight-EXT-008 and returns its single element.
func (c *Client) committeeInfo(ctx context.Context) (committeeInfoRow, error) {
	body, err := c.get(ctx, "committee_info", "/committee_info", "", true)
	if err != nil {
		return committeeInfoRow{}, err
	}
	var rows []committeeInfoRow
	if err := strictUnmarshal(body, &rows); err != nil {
		return committeeInfoRow{}, fmt.Errorf("committee_info answer is not a JSON array of committees: %s", prefix([]byte(err.Error())))
	}
	if len(rows) != 1 {
		return committeeInfoRow{}, fmt.Errorf("committee_info answered %d committees, want one", len(rows))
	}
	return rows[0], nil
}

// parseMember reads one member row; an error says why it cannot be trusted.
func parseMember(r committeeMemberRow) (governance.CommitteeMember, governance.Credential, error) {
	var m governance.CommitteeMember
	var hot governance.Credential
	if !r.ColdHex.present || r.ColdHex.null || !r.ColdScript.present || r.ColdScript.null {
		return m, hot, errors.New("no cc_cold_hex or cc_cold_has_script")
	}
	h, err := governance.ParseHash28(r.ColdHex.val)
	if err != nil {
		return m, hot, fmt.Errorf("cc_cold_hex: %w", err)
	}
	m.Cold = governance.Credential{Script: r.ColdScript.val, Hash: h}
	if !r.Status.present || r.Status.null {
		return m, hot, errors.New("no status")
	}
	switch r.Status.val {
	case "authorized":
		if !r.HotHex.present || r.HotHex.null || !r.HotScript.present || r.HotScript.null {
			return m, hot, errors.New("authorized but no cc_hot_hex or cc_hot_has_script")
		}
		hh, err := governance.ParseHash28(r.HotHex.val)
		if err != nil {
			return m, hot, fmt.Errorf("cc_hot_hex: %w", err)
		}
		hot = governance.Credential{Script: r.HotScript.val, Hash: hh}
		m.Auth, m.Hot = governance.HotAuthorized, hot
	case "not_authorized":
		m.Auth = governance.HotNotAuthorized
	case "resigned":
		m.Auth = governance.HotResigned
	default:
		return m, hot, fmt.Errorf("unrecognised status %q", prefix([]byte(r.Status.val)))
	}
	// Status and NextChange stay empty: Koios states neither (upstream prints
	// the constants Active and null, SPO-Clight-OUT-019, which are not Koios's).
	switch {
	case r.Expiration.present && !r.Expiration.null:
		m.Expiry = chain.Value(uint64(r.Expiration.val))
	default:
		m.Expiry = chain.Unknown[uint64]("committee_info states no expiration_epoch for the member")
	}
	return m, hot, nil
}

// findMember looks for a member by cold or hot credential in the committee
// list. A match is a Value; no match is None only when every row could be
// read and the list is not empty; anything else is Unknown.
func (c *Client) findMember(ctx context.Context, want governance.Credential, byHot bool) (chain.Reading[governance.CommitteeMember], error) {
	unknown := func(why string) (chain.Reading[governance.CommitteeMember], error) {
		return chain.Unknown[governance.CommitteeMember](why), nil
	}
	info, err := c.committeeInfo(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[governance.CommitteeMember]("cancelled"), err
		}
		return unknown(err.Error())
	}
	if len(info.Members) == 0 {
		return unknown("committee_info lists no members (no committee, or no answer)")
	}
	var found []governance.CommitteeMember
	var bad []string
	for i, r := range info.Members {
		m, hot, err := parseMember(r)
		if err != nil {
			bad = append(bad, fmt.Sprintf("member %d: %v", i, err))
			continue
		}
		switch {
		case byHot && m.Auth == governance.HotAuthorized && hot == want:
			found = append(found, m)
		case !byHot && m.Cold == want:
			found = append(found, m)
		}
	}
	switch {
	case len(found) > 1:
		return unknown("committee_info lists the credential for several members")
	case len(found) == 1:
		return chain.Value(found[0]), nil
	case len(bad) > 0:
		return unknown("the credential is not in the readable rows, and committee_info has rows that cannot be read: " + bad[0])
	}
	return chain.None[governance.CommitteeMember](), nil
}

// CommitteeMember implements ports.CommitteeStateReader: GET /committee_info
// (SPO-Clight-EXT-008), no parameters.
//
//   - a member whose cold credential (hash and script flag) is the one: Value
//     with the authorisation from `status` (authorized gives the hot credential,
//     not_authorized, resigned, SPO-Clight-OUT-020) and the expiration epoch
//     (Unknown when Koios states none);
//   - none of the members, every row readable: None. The hash matches by hash
//     and credential type, so a key hash is not found among script members;
//   - an empty member list (the no-committee state and a miss look alike),
//     a failed request, non-JSON, an error object, several committees, a row
//     that cannot be read while the credential is not in the others, a
//     credential on several members: Unknown with the reason.
//
// Status and NextChange are left empty: Koios gives neither, and upstream's
// constants (Active, null) are quirks (SPO-Clight-OUT-019) this port does not
// repeat.
//
// spec: SPO-Clight-EXT-008, SPO-Clight-IN-003, SPO-Clight-OUT-019, SPO-Clight-OUT-020
func (c *Client) CommitteeMember(ctx context.Context, cold governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	return c.findMember(ctx, cold, false)
}

// CommitteeMemberByHot implements ports.CommitteeStateReader by the
// authorised hot credential of the same committee list (SPO-Clight-IN-003:
// upstream keeps the members whose cold or hot hex is the filter).
//
// spec: SPO-Clight-EXT-008, SPO-Clight-IN-003, SPO-Clight-OUT-020
func (c *Client) CommitteeMemberByHot(ctx context.Context, hot governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	return c.findMember(ctx, hot, true)
}

// CommitteeThreshold implements ports.VotingSummaryReader: the committee's
// quorum fraction from the same committee_info, exact (upstream truncates to
// two decimals, SPO-Clight-OUT-018; the tally truncates). An absent number is
// Unknown: it is not a positive statement of the no-confidence state.
//
// spec: SPO-Clight-EXT-008, SPO-Clight-OUT-018
func (c *Client) CommitteeThreshold(ctx context.Context) (chain.Reading[chain.Rational], error) {
	unknown := func(why string) (chain.Reading[chain.Rational], error) {
		return chain.Unknown[chain.Rational](why), nil
	}
	info, err := c.committeeInfo(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.Rational]("cancelled"), err
		}
		return unknown(err.Error())
	}
	if !info.Num.present || info.Num.null || !info.Den.present || info.Den.null || info.Den.val == 0 {
		return unknown("committee_info states no quorum (no committee, or no answer)")
	}
	return chain.Value(chain.Rational{Num: uint64(info.Num.val), Den: uint64(info.Den.val)}), nil
}

// ---- governance actions ------------------------------------------------------

type proposalRow struct {
	Tx       string            `json:"proposal_tx_hash"`
	Index    *uintVal          `json:"proposal_index"`
	Desc     json.RawMessage   `json:"proposal_description"`
	Deposit  *uintVal          `json:"deposit"`
	Return   string            `json:"return_address"`
	Proposed *uintVal          `json:"proposed_epoch"`
	Expires  *uintVal          `json:"expiration"`
	MetaURL  optional[string]  `json:"meta_url"`
	MetaHash optional[string]  `json:"meta_hash"`
	Dropped  optional[uintVal] `json:"dropped_epoch"`
	Enacted  optional[uintVal] `json:"enacted_epoch"`
	Expired  optional[uintVal] `json:"expired_epoch"`
}

// kindOfTag maps proposal_description.tag to the kinds of the governance state.
var kindOfTag = map[string]governance.ActionKind{
	"InfoAction":          governance.InfoAction,
	"NoConfidence":        governance.NoConfidenceAction,
	"UpdateCommittee":     governance.UpdateCommittee,
	"NewCommittee":        governance.UpdateCommittee,
	"NewConstitution":     governance.NewConstitution,
	"HardForkInitiation":  governance.HardForkInitiation,
	"ParameterChange":     governance.ParameterChange,
	"TreasuryWithdrawals": governance.TreasuryWithdrawals,
}

const proposalSelect = "proposal_tx_hash,proposal_index,proposal_description,deposit,return_address,proposed_epoch,expiration,meta_url,meta_hash,dropped_epoch,enacted_epoch,expired_epoch"

func (r proposalRow) id() (governance.ActionID, error) {
	tx, err := chain.ParseTxID(r.Tx)
	if err != nil {
		return governance.ActionID{}, err
	}
	if r.Index == nil || uint64(*r.Index) > 0xffff {
		return governance.ActionID{}, errors.New("missing or out-of-range proposal_index")
	}
	return governance.ActionID{TxID: tx, Index: uint32(*r.Index)}, nil
}

// state maps one open proposal as SPO-Clight-OUT-021 does (without votes).
func (r proposalRow) state(id governance.ActionID) (governance.ActionState, error) {
	var a governance.ActionState
	a.ID = id
	if r.Deposit == nil || r.Proposed == nil || r.Expires == nil || *r.Expires == 0 {
		return a, errors.New("missing deposit, proposed_epoch or expiration")
	}
	if !r.Dropped.present || !r.Dropped.null || !r.Enacted.present || !r.Enacted.null || !r.Expired.present || !r.Expired.null {
		return a, errors.New("the proposal is not open")
	}
	a.Deposit = chain.Lovelace(*r.Deposit)
	a.ProposedIn = uint64(*r.Proposed)
	a.ExpiresAfter = uint64(*r.Expires) - 1 // SPO-Clight-OUT-021
	// The anchor: both null is "none stated"; one without the other, or a bad hash, is unreadable.
	switch {
	case r.MetaURL.present && r.MetaURL.null && r.MetaHash.present && r.MetaHash.null:
	case r.MetaURL.present && !r.MetaURL.null && r.MetaURL.val != "" && r.MetaHash.present && !r.MetaHash.null:
		h, err := governance.ParseHash32(r.MetaHash.val)
		if err != nil {
			return a, fmt.Errorf("meta_hash: %w", err)
		}
		a.Anchor = governance.Anchor{URL: r.MetaURL.val, Hash: h}
	default:
		return a, errors.New("meta_url and meta_hash are not both stated or both null")
	}
	// The deposit-return credential from the stake address (SPO-Clight-OUT-022).
	hrp, data, err := chain.Bech32Decode(r.Return)
	if err != nil || (hrp != "stake" && hrp != "stake_test") || len(data) != 29 || data[0]>>4 < 0xe {
		return a, fmt.Errorf("return_address %q is not a stake address", prefix([]byte(r.Return)))
	}
	a.DepositReturn.Script = data[0]>>4 == 0xf
	copy(a.DepositReturn.Hash[:], data[1:])
	// The kind and, for a parameter change, the names of the proposed parameters.
	var desc struct {
		Tag      optional[string] `json:"tag"`
		Contents json.RawMessage  `json:"contents"`
	}
	if err := strictUnmarshal(r.Desc, &desc); err != nil || !desc.Tag.present || desc.Tag.null {
		return a, errors.New("proposal_description has no tag")
	}
	kind, ok := kindOfTag[desc.Tag.val]
	if !ok {
		return a, fmt.Errorf("unrecognised proposal tag %q", prefix([]byte(desc.Tag.val)))
	}
	a.Kind = kind
	if kind == governance.ParameterChange {
		var contents []json.RawMessage
		if err := strictUnmarshal(desc.Contents, &contents); err != nil || len(contents) < 2 {
			return a, errors.New("a ParameterChange description has no parameter update")
		}
		var upd map[string]json.RawMessage
		if err := strictUnmarshal(contents[1], &upd); err != nil {
			return a, errors.New("the parameter update of a ParameterChange is not an object")
		}
		for n := range upd {
			a.ParamNames = append(a.ParamNames, n)
		}
		sort.Strings(a.ParamNames)
		// Koios does not say whether a change touches a security-group parameter.
		a.Security = chain.Unknown[bool]("koios does not state whether the parameter change touches a security-group parameter")
	}
	return a, nil
}

// GovActions implements ports.GovActionReader: GET /proposal_list with the
// open filter (SPO-Clight-EXT-009, without a voter id), narrowed to the action
// id locally (SPO-Clight-IN-004), then GET /proposal_votes for each action
// kept (SPO-Clight-EXT-010, SPO-Clight-MODE-004 of 24c).
//
// An empty list is Value with no actions: the request is a filtered list, as
// for the deposits of a reward account, and [] is its real answer for "none
// open". Everything else that is not well-formed is Unknown, the whole
// reading: a failed request, non-JSON, an error object, a list as long as
// Koios's row limit (it may be truncated), a row that is not open (the filter
// promised it was), a malformed id, amount, anchor or return address, an
// unrecognised proposal tag, or a failed or uninterpretable votes answer (a
// missing vote would make a tally or an "earlier vote" false).
//
// The proposals are requested with a select that leaves out meta_json, which
// is large and unused (the spec's request has none).
//
// spec: SPO-Clight-EXT-009, SPO-Clight-IN-004, SPO-Clight-OUT-021, SPO-Clight-OUT-022
func (c *Client) GovActions(ctx context.Context, id *governance.ActionID) (chain.Reading[[]governance.ActionState], error) {
	unknown := func(why string) (chain.Reading[[]governance.ActionState], error) {
		return chain.Unknown[[]governance.ActionState](why), nil
	}
	query := "dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null&select=" + proposalSelect
	body, err := c.get(ctx, "proposal_list", "/proposal_list", query, true)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[[]governance.ActionState]("cancelled"), err
		}
		return unknown("proposal_list: " + err.Error())
	}
	var rows []proposalRow
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("proposal_list answer is not a JSON array of proposals: " + prefix([]byte(err.Error())))
	}
	if rows == nil {
		return unknown("proposal_list answer is not a JSON array")
	}
	if len(rows) >= koiosListLimit {
		return unknown(fmt.Sprintf("proposal_list: %d rows is Koios' row limit; the list may be truncated", len(rows)))
	}
	seen := map[governance.ActionID]bool{}
	out := make([]governance.ActionState, 0, len(rows))
	for i, r := range rows {
		rid, err := r.id()
		if err != nil {
			return unknown(fmt.Sprintf("proposal_list: row %d: %v", i, err))
		}
		if seen[rid] {
			return unknown("proposal_list: duplicate action " + rid.Hex())
		}
		seen[rid] = true
		if id != nil && rid != *id {
			continue
		}
		a, err := r.state(rid)
		if err != nil {
			return unknown(fmt.Sprintf("proposal_list: action %s: %v", rid.Hex(), err))
		}
		a.Votes, err = c.proposalVotes(ctx, rid)
		if err != nil {
			if ctx.Err() != nil {
				return chain.Unknown[[]governance.ActionState]("cancelled"), err
			}
			return unknown(fmt.Sprintf("proposal_votes of %s: %v", rid.Hex(), err))
		}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.Hex() < out[j].ID.Hex() })
	return chain.Value(out), nil
}

type voteRow struct {
	Time   optional[uintVal] `json:"block_time"`
	Role   string            `json:"voter_role"`
	Hex    string            `json:"voter_hex"`
	Script *bool             `json:"voter_has_script"`
	Vote   string            `json:"vote"`
}

// proposalVotes reads GET /proposal_votes?_proposal_id=<gov_action id>
// (SPO-Clight-EXT-010) and maps the rows as SPO-Clight-OUT-023 and OUT-024 do:
// DRep, SPO and ConstitutionalCommittee rows by credential. [] is a real answer
// for a proposal known to exist: no votes yet.
//
// When one voter appears in several rows the LATEST vote (greatest
// block_time) counts, which is the ledger's rule. Upstream takes the later row
// of the response (OUT-024), and Koios lists the newest first, so upstream
// would keep the oldest vote. Rows of one voter without a block_time, or with the
// same block_time and different votes, cannot be ordered: an error.
func (c *Client) proposalVotes(ctx context.Context, id governance.ActionID) (map[governance.Voter]governance.Decision, error) {
	gid, err := id.CIP129()
	if err != nil {
		return nil, err
	}
	body, err := c.get(ctx, "proposal_votes", "/proposal_votes", "_proposal_id="+url.QueryEscape(gid), true)
	if err != nil {
		return nil, err
	}
	var rows []voteRow
	if err := strictUnmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("not a JSON array of votes: %s", prefix([]byte(err.Error())))
	}
	if rows == nil {
		return nil, errors.New("not a JSON array")
	}
	if len(rows) >= koiosListLimit {
		return nil, fmt.Errorf("%d rows is Koios' row limit; the votes may be truncated", len(rows))
	}
	type latest struct {
		d    governance.Decision
		t    uint64
		have bool
	}
	got := map[governance.Voter]latest{}
	for i, r := range rows {
		var role governance.Role
		switch r.Role {
		case "DRep":
			role = governance.RoleDRep
		case "SPO":
			role = governance.RolePool
		case "ConstitutionalCommittee":
			role = governance.RoleCommitteeHot
		default:
			return nil, fmt.Errorf("row %d: unrecognised voter_role %q", i, prefix([]byte(r.Role)))
		}
		var d governance.Decision
		switch r.Vote {
		case "Yes":
			d = governance.Yes
		case "No":
			d = governance.No
		case "Abstain":
			d = governance.Abstain
		default:
			return nil, fmt.Errorf("row %d: unrecognised vote %q", i, prefix([]byte(r.Vote)))
		}
		h, err := governance.ParseHash28(r.Hex)
		if err != nil || r.Script == nil {
			return nil, fmt.Errorf("row %d: no voter_hex or voter_has_script", i)
		}
		cred := governance.Credential{Hash: h}
		if role != governance.RolePool {
			cred.Script = *r.Script
		}
		v := governance.Voter{Role: role, Cred: cred}
		cur := latest{d: d, have: r.Time.present && !r.Time.null, t: uint64(r.Time.val)}
		prev, dup := got[v]
		switch {
		case !dup:
			got[v] = cur
		case !prev.have || !cur.have:
			return nil, fmt.Errorf("row %d: the voter voted more than once and a row has no block_time", i)
		case cur.t > prev.t:
			got[v] = cur
		case cur.t == prev.t && cur.d != prev.d:
			return nil, fmt.Errorf("row %d: two different votes of one voter in the same block time", i)
		}
	}
	out := make(map[governance.Voter]governance.Decision, len(got))
	for v, l := range got {
		out[v] = l.d
	}
	return out, nil
}

// ---- voting summary -------------------------------------------------------------

// pctVal is a Koios percentage (a JSON number such as 52.23, 0 or 100.00, or
// a string of one) in hundredths of a percent, truncated to two decimals as the
// tally truncates (bc scale=2). Exponents, signs and anything else are refused.
type pctVal int64

var pctText = regexp.MustCompile(`^([0-9]{1,3})(?:\.([0-9]+))?$`)

func (p *pctVal) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	m := pctText.FindStringSubmatch(s)
	if m == nil {
		return fmt.Errorf("not a percentage: %q", prefix([]byte(s)))
	}
	frac := (m[2] + "00")[:2]
	var whole, f int64
	fmt.Sscanf(m[1], "%d", &whole)
	fmt.Sscanf(frac, "%d", &f)
	v := whole*100 + f
	if v > 10000 {
		return fmt.Errorf("percentage above 100: %q", s)
	}
	*p = pctVal(v)
	return nil
}

type summaryRow struct {
	DRepYesPct       *pctVal  `json:"drep_yes_pct"`
	PoolYesPct       *pctVal  `json:"pool_yes_pct"`
	CommitteeYesPct  *pctVal  `json:"committee_yes_pct"`
	DRepAlwaysNoConf *uintVal `json:"drep_always_no_confidence_vote_power"`
	PoolPassiveNoCon *uintVal `json:"pool_passive_always_no_confidence_vote_power"`
	DRepYesPower     *uintVal `json:"drep_yes_vote_power"`
	DRepNoPower      *uintVal `json:"drep_active_no_vote_power"`
	DRepAbstain      *uintVal `json:"drep_active_abstain_vote_power"`
	PoolYesPower     *uintVal `json:"pool_yes_vote_power"`
	PoolNoPower      *uintVal `json:"pool_active_no_vote_power"`
	PoolAbstain      *uintVal `json:"pool_active_abstain_vote_power"`
}

// VotingSummary implements ports.VotingSummaryReader: GET
// /proposal_voting_summary?_proposal_id=<gov_action id> (SPO-Clight-EXT-011).
// Light mode takes the three yes percentages (drep_yes_pct, pool_yes_pct,
// committee_yes_pct) and the eight powers of SPO-24c-MODE-005 from it.
//
// Upstream defaults an absent percentage to 0 (SPO-24c-MODE-005); here every
// one of the eleven fields must be present and well-formed, else the reading
// is Unknown: a tally of zeros is a false statement. Also Unknown: an empty
// array (a proposal Koios has no summary of), a failed request, non-JSON, an
// error object, several rows, a percentage that is not a plain decimal up to
// 100, a power that is not a non-negative integer.
//
// spec: SPO-Clight-EXT-011, SPO-Clight-OUT-025, SPO-24c-MODE-005
func (c *Client) VotingSummary(ctx context.Context, id governance.ActionID) (chain.Reading[governance.VotingSummary], error) {
	unknown := func(why string) (chain.Reading[governance.VotingSummary], error) {
		return chain.Unknown[governance.VotingSummary](why), nil
	}
	gid, err := id.CIP129()
	if err != nil {
		return unknown(err.Error())
	}
	body, err := c.get(ctx, "proposal_voting_summary", "/proposal_voting_summary", "_proposal_id="+url.QueryEscape(gid), true)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[governance.VotingSummary]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []summaryRow
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("proposal_voting_summary answer is not a JSON array of summaries: " + prefix([]byte(err.Error())))
	}
	switch {
	case len(rows) == 0:
		return unknown("koios has no voting summary of this proposal")
	case len(rows) > 1:
		return unknown(fmt.Sprintf("koios returned %d summaries for one proposal", len(rows)))
	}
	r := rows[0]
	var miss []string
	pct := func(name string, v *pctVal) governance.Pct {
		if v == nil {
			miss = append(miss, name)
			return 0
		}
		return governance.Pct(*v)
	}
	pow := func(name string, v *uintVal) chain.Lovelace {
		if v == nil {
			miss = append(miss, name)
			return 0
		}
		return chain.Lovelace(*v)
	}
	s := governance.VotingSummary{
		DRepYes:      pct("drep_yes_pct", r.DRepYesPct),
		PoolYes:      pct("pool_yes_pct", r.PoolYesPct),
		CommitteeYes: pct("committee_yes_pct", r.CommitteeYesPct),
		Powers: governance.Powers{
			DRepYes:          pow("drep_yes_vote_power", r.DRepYesPower),
			DRepNo:           pow("drep_active_no_vote_power", r.DRepNoPower),
			DRepAbstain:      pow("drep_active_abstain_vote_power", r.DRepAbstain),
			DRepNoConfidence: pow("drep_always_no_confidence_vote_power", r.DRepAlwaysNoConf),
			PoolYes:          pow("pool_yes_vote_power", r.PoolYesPower),
			PoolNo:           pow("pool_active_no_vote_power", r.PoolNoPower),
			PoolAbstain:      pow("pool_active_abstain_vote_power", r.PoolAbstain),
			PoolNoConfidence: pow("pool_passive_always_no_confidence_vote_power", r.PoolPassiveNoCon),
		},
	}
	if len(miss) > 0 {
		return unknown("proposal_voting_summary lacks or cannot read " + strings.Join(miss, ", "))
	}
	return chain.Value(s), nil
}

// ---- constitution and last enacted actions: the light-mode parameters document ----

type constitutionDoc struct {
	Anchor *struct {
		DataHash string `json:"dataHash"`
		URL      string `json:"url"`
	} `json:"anchor"`
	Script optional[string] `json:"script"`
}

// Constitution implements ports.ConstitutionReader from the hosted light-mode
// parameters document, where upstream takes `constitution` from in light mode
// (SPO-25a-MODE-002, SPO-25a-IN-002). The document goes through the same
// refusals as the protocol parameters (status 200, JSON, fresh, right magic).
//
//   - an anchor with a URL and a 32-byte dataHash, and a `script` that is a
//     28-byte hash: Value with the guardrails script;
//   - the same with `"script": null`: Value with no script (the chain has no
//     guardrails script: a positive statement);
//   - no `constitution` object, no anchor, a bad hash, a `script` key that is
//     absent (the document does not say: upstream defaults to none, which
//     could leave a proposal without a script it needs), a failed fetch: Unknown.
//
// spec: SPO-25a-IN-002, SPO-25a-MODE-002
func (l *LightParameters) Constitution(ctx context.Context) (chain.Reading[governance.Constitution], error) {
	unknown := func(why string) (chain.Reading[governance.Constitution], error) {
		return chain.Unknown[governance.Constitution](why), nil
	}
	body, _, err := l.fetch(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[governance.Constitution]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var doc struct {
		Constitution optional[constitutionDoc] `json:"constitution"`
	}
	if err := strictUnmarshal(body, &doc); err != nil {
		return unknown("light parameters: " + prefix([]byte(err.Error())))
	}
	if !doc.Constitution.present || doc.Constitution.null {
		return unknown("the light-mode parameters document has no constitution")
	}
	cd := doc.Constitution.val
	if cd.Anchor == nil || cd.Anchor.URL == "" {
		return unknown("the constitution in the light-mode parameters document has no anchor")
	}
	h, err := governance.ParseHash32(cd.Anchor.DataHash)
	if err != nil {
		return unknown("the constitution anchor hash: " + err.Error())
	}
	out := governance.Constitution{Anchor: governance.Anchor{URL: cd.Anchor.URL, Hash: h}}
	switch {
	case !cd.Script.present:
		return unknown("the constitution in the light-mode parameters document does not say whether it has a guardrails script")
	case cd.Script.null:
	default:
		sh, err := governance.ParseHash28(cd.Script.val)
		if err != nil {
			return unknown("the constitution script hash: " + err.Error())
		}
		out.Script = &sh
	}
	return chain.Value(out), nil
}

// LastEnacted implements ports.LastEnactedReader from `prevActionIDs` of the
// light-mode parameters document (SPO-25a-MODE-002, SPO-25a-IN-002): an object
// with a txId and govActionIx is Value, an explicit null is None (the chain
// has no enacted action of the purpose), anything else, including an absent
// key (upstream defaults to none) or a document without prevActionIDs, is
// Unknown.
//
// spec: SPO-25a-IN-002, SPO-25a-MODE-002, SPO-25a-INV-004
func (l *LightParameters) LastEnacted(ctx context.Context, p governance.Purpose) (chain.Reading[governance.ActionID], error) {
	unknown := func(why string) (chain.Reading[governance.ActionID], error) {
		return chain.Unknown[governance.ActionID](why), nil
	}
	body, _, err := l.fetch(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[governance.ActionID]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var doc struct {
		Prev optional[map[string]json.RawMessage] `json:"prevActionIDs"`
	}
	if err := strictUnmarshal(body, &doc); err != nil {
		return unknown("light parameters: " + prefix([]byte(err.Error())))
	}
	if !doc.Prev.present || doc.Prev.null {
		return unknown("the light-mode parameters document has no prevActionIDs")
	}
	raw, ok := doc.Prev.val[string(p)]
	if !ok {
		return unknown(fmt.Sprintf("prevActionIDs of the light-mode parameters document has no %s entry", p))
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return chain.None[governance.ActionID](), nil
	}
	var a struct {
		Tx    string   `json:"txId"`
		Index *uintVal `json:"govActionIx"`
	}
	if err := strictUnmarshal(raw, &a); err != nil || a.Index == nil || uint64(*a.Index) > 0xffff {
		return unknown(fmt.Sprintf("prevActionIDs.%s is not an action id", p))
	}
	tx, err := chain.ParseTxID(a.Tx)
	if err != nil {
		return unknown(fmt.Sprintf("prevActionIDs.%s: %v", p, err))
	}
	return chain.Value(governance.ActionID{TxID: tx, Index: uint32(*a.Index)}), nil
}
