package n2c

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.CommitteeStateReader    = (*Client)(nil)
	_ ports.GovActionReader         = (*Client)(nil)
	_ ports.ConstitutionReader      = (*Client)(nil)
	_ ports.LastEnactedReader       = (*Client)(nil)
	_ ports.StakeDistributionReader = (*Client)(nil)
)

// proposal is a proposal procedure as a ledger state carries it:
// [deposit, return account, governance action, anchor].
type proposal struct {
	Deposit       uint64
	ReturnCred    governance.Credential
	ReturnMainnet bool
	Kind          governance.ActionKind
	ParamKeys     []uint64
	Anchor        governance.Anchor
}

func decodeProposal(raw []byte) (proposal, error) {
	var p struct {
		cbor.StructAsArray
		Deposit uint64
		Return  []byte
		Action  cbor.RawMessage
		Anchor  lcommon.GovAnchor
	}
	if _, err := cbor.Decode(raw, &p); err != nil {
		return proposal{}, fmt.Errorf("proposal procedure: %w", err)
	}
	if len(p.Return) != 29 || (p.Return[0]&0xe0) != 0xe0 {
		return proposal{}, errors.New("proposal procedure: the return account is not a stake address")
	}
	out := proposal{
		Deposit:       p.Deposit,
		ReturnCred:    governance.Credential{Script: p.Return[0]&0x10 != 0, Hash: [28]byte(p.Return[1:])},
		ReturnMainnet: p.Return[0]&0x0f == 1,
		Anchor:        governance.Anchor{URL: p.Anchor.Url, Hash: p.Anchor.DataHash},
	}
	var parts []cbor.RawMessage
	if _, err := cbor.Decode(p.Action, &parts); err != nil || len(parts) == 0 {
		return proposal{}, errors.New("proposal procedure: the governance action is not an array")
	}
	var typ uint64
	if _, err := cbor.Decode(parts[0], &typ); err != nil {
		return proposal{}, errors.New("proposal procedure: the governance action has no type")
	}
	switch lcommon.GovActionType(typ) {
	case lcommon.GovActionTypeParameterChange:
		out.Kind = governance.ParameterChange
		if len(parts) < 3 {
			return proposal{}, errors.New("proposal procedure: a parameter change has no update")
		}
		var upd map[uint64]cbor.RawMessage
		if _, err := cbor.Decode(parts[2], &upd); err != nil {
			return proposal{}, errors.New("proposal procedure: the parameter update is not a map")
		}
		for k := range upd {
			out.ParamKeys = append(out.ParamKeys, k)
		}
		sort.Slice(out.ParamKeys, func(i, j int) bool { return out.ParamKeys[i] < out.ParamKeys[j] })
	case lcommon.GovActionTypeHardForkInitiation:
		out.Kind = governance.HardForkInitiation
	case lcommon.GovActionTypeTreasuryWithdrawal:
		out.Kind = governance.TreasuryWithdrawals
	case lcommon.GovActionTypeNoConfidence:
		out.Kind = governance.NoConfidenceAction
	case lcommon.GovActionTypeUpdateCommittee:
		out.Kind = governance.UpdateCommittee
	case lcommon.GovActionTypeNewConstitution:
		out.Kind = governance.NewConstitution
	case lcommon.GovActionTypeInfo:
		out.Kind = governance.InfoAction
	default:
		return proposal{}, fmt.Errorf("proposal procedure: unknown governance action type %d", typ)
	}
	return out, nil
}

// paramNames maps the keys of a Conway parameter update to the names
// cardano-cli prints (the names SPO-24c-OUT-005 matches its groups on). The keys
// are those of gouroboros' ConwayProtocolParameterUpdate. securityKeys are the
// parameters of the security group of CIP-1694.
var paramNames = map[uint64]string{
	0: "txFeePerByte", 1: "txFeeFixed", 2: "maxBlockBodySize", 3: "maxTxSize", 4: "maxBlockHeaderSize",
	5: "stakeAddressDeposit", 6: "stakePoolDeposit", 7: "poolRetireMaxEpoch", 8: "stakePoolTargetNum",
	9: "poolPledgeInfluence", 10: "monetaryExpansion", 11: "treasuryCut", 14: "protocolVersion",
	16: "minPoolCost", 17: "utxoCostPerByte", 18: "costModels", 19: "executionUnitPrices",
	20: "maxTxExecutionUnits", 21: "maxBlockExecutionUnits", 22: "maxValueSize", 23: "collateralPercentage",
	24: "maxCollateralInputs", 25: "poolVotingThresholds", 26: "dRepVotingThresholds", 27: "committeeMinSize",
	28: "committeeMaxTermLength", 29: "govActionLifetime", 30: "govActionDeposit", 31: "dRepDeposit",
	32: "dRepActivity", 33: "minFeeRefScriptCostPerByte",
}

var securityKeys = map[uint64]bool{0: true, 1: true, 2: true, 3: true, 4: true, 17: true, 21: true, 22: true, 30: true, 33: true}

func voteDecision(v lcommon.Vote) (governance.Decision, error) {
	switch uint8(v) {
	case lcommon.GovVoteYes:
		return governance.Yes, nil
	case lcommon.GovVoteNo:
		return governance.No, nil
	case lcommon.GovVoteAbstain:
		return governance.Abstain, nil
	}
	return "", fmt.Errorf("unknown vote value %d", uint8(v))
}

func toActionState(g localstatequery.GovActionState) (governance.ActionState, error) {
	pp, err := decodeProposal(g.ProposalProcedure)
	if err != nil {
		return governance.ActionState{}, err
	}
	a := governance.ActionState{
		ID:            governance.ActionID{TxID: chain.TxID(g.Id.TransactionId), Index: g.Id.GovActionIdx},
		Kind:          pp.Kind,
		ProposedIn:    g.ProposedIn,
		ExpiresAfter:  g.ExpiresAfter,
		Anchor:        pp.Anchor,
		Deposit:       chain.Lovelace(pp.Deposit),
		DepositReturn: pp.ReturnCred,
		Votes:         map[governance.Voter]governance.Decision{},
	}
	if pp.Kind == governance.ParameterChange {
		sec, known := false, true
		for _, k := range pp.ParamKeys {
			n, ok := paramNames[k]
			if !ok {
				known = false
				continue
			}
			a.ParamNames = append(a.ParamNames, n)
			sec = sec || securityKeys[k]
		}
		sort.Strings(a.ParamNames)
		if known {
			a.Security = chain.Value(sec)
		} else {
			a.Security = chain.Unknown[bool]("the update has a parameter this adapter has no name for")
		}
	}
	add := func(role governance.Role, cred governance.Credential, v lcommon.Vote) error {
		d, err := voteDecision(v)
		if err != nil {
			return err
		}
		a.Votes[governance.Voter{Role: role, Cred: cred}] = d
		return nil
	}
	for sc, v := range g.DRepVotes {
		if err := add(governance.RoleDRep, credOf(sc), v); err != nil {
			return a, err
		}
	}
	for sc, v := range g.CommitteeVotes {
		if err := add(governance.RoleCommitteeHot, credOf(sc), v); err != nil {
			return a, err
		}
	}
	for h, v := range g.SPOVotes {
		if err := add(governance.RolePool, governance.Credential{Hash: [28]byte(h)}, v); err != nil {
			return a, err
		}
	}
	return a, nil
}

// GovActions lists the open proposals (GetProposals), or the one named by id
// (an id the node does not list gives an empty list). A proposal that does not
// decode makes the whole answer Unknown.
func (c *Client) GovActions(ctx context.Context, id *governance.ActionID) (chain.Reading[[]governance.ActionState], error) {
	var out []governance.ActionState
	err := c.do(ctx, "governance proposals", func(q *localstatequery.Client) error {
		ps, err := q.GetProposals()
		if err != nil {
			return err
		}
		out = []governance.ActionState{}
		for _, g := range *ps {
			a, err := toActionState(g)
			if err != nil {
				return fmt.Errorf("proposal %x#%d: %w", g.Id.TransactionId[:], g.Id.GovActionIdx, err)
			}
			if id != nil && a.ID != *id {
				continue
			}
			out = append(out, a)
		}
		return nil
	})
	if err != nil {
		return unknown[[]governance.ActionState](ctx, err)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := compareTx(out[i].ID.TxID, out[j].ID.TxID); c != 0 {
			return c < 0
		}
		return out[i].ID.Index < out[j].ID.Index
	})
	return chain.Value(out), nil
}

func (c *Client) committeeMember(ctx context.Context, cold, hot *governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	toCred := func(c governance.Credential) lcommon.Credential {
		t := uint(0)
		if c.Script {
			t = 1
		}
		return lcommon.Credential{CredType: t, Credential: lcommon.NewBlake2b224(c.Hash[:])}
	}
	var coldF, hotF []lcommon.Credential
	if cold != nil {
		coldF = []lcommon.Credential{toCred(*cold)}
	} else {
		hotF = []lcommon.Credential{toCred(*hot)}
	}
	var res *localstatequery.CommitteeMembersStateResult
	err := c.do(ctx, "committee state", func(q *localstatequery.Client) error {
		var err error
		res, err = q.GetCommitteeMembersState(coldF, hotF, nil)
		return err
	})
	if err != nil {
		return unknown[governance.CommitteeMember](ctx, err)
	}
	if len(res.Members) == 0 {
		return chain.None[governance.CommitteeMember](), nil
	}
	if len(res.Members) > 1 {
		return chain.Unknown[governance.CommitteeMember](fmt.Sprintf("the node returned %d members for one credential", len(res.Members))), nil
	}
	for sc, ms := range res.Members {
		m, err := toMember(sc, ms)
		if err != nil {
			return chain.Unknown[governance.CommitteeMember](err.Error()), nil
		}
		return chain.Value(m), nil
	}
	return chain.None[governance.CommitteeMember](), nil
}

func toMember(sc localstatequery.StakeCredential, ms localstatequery.CommitteeMemberState) (governance.CommitteeMember, error) {
	m := governance.CommitteeMember{Cold: credOf(sc)}
	switch ms.HotCredStatus.Status {
	case localstatequery.HotCredNotAuthorized:
		m.Auth = governance.HotNotAuthorized
	case localstatequery.HotCredAuthorized:
		m.Auth = governance.HotAuthorized
		if ms.HotCredStatus.Credential == nil {
			return m, errors.New("an authorised member without a hot credential")
		}
		m.Hot = governance.Credential{Script: ms.HotCredStatus.Credential.CredType == 1, Hash: [28]byte(ms.HotCredStatus.Credential.Credential)}
	case localstatequery.HotCredResigned:
		m.Auth = governance.HotResigned
	default:
		return m, fmt.Errorf("unknown hot credential status %d", ms.HotCredStatus.Status)
	}
	switch ms.Status {
	case localstatequery.MemberStatusActive:
		m.Status = "Active"
	case localstatequery.MemberStatusExpired:
		m.Status = "Expired"
	case localstatequery.MemberStatusUnrecognized:
		m.Status = "Unrecognized"
	default:
		return m, fmt.Errorf("unknown member status %d", ms.Status)
	}
	if ms.Expiry != nil {
		m.Expiry = chain.Value(*ms.Expiry)
	} else {
		m.Expiry = chain.Unknown[uint64]("the node did not state the member's term")
	}
	switch ms.NextEpochChange.Change {
	case localstatequery.NextEpochNoChange:
		m.NextChange = "NoChange"
	case localstatequery.NextEpochToBeEnacted:
		m.NextChange = "ToBeEnacted"
	case localstatequery.NextEpochToBeRemoved:
		m.NextChange = "ToBeRemoved"
	case localstatequery.NextEpochToBeExpired:
		m.NextChange = "ToBeExpired"
	case localstatequery.NextEpochTermAdjusted:
		m.NextChange = "TermAdjusted"
	default:
		return m, fmt.Errorf("unknown next-epoch change %d", ms.NextEpochChange.Change)
	}
	return m, nil
}

// CommitteeMember finds the member whose cold credential is cold
// (GetCommitteeMembersState filtered by cold credential).
func (c *Client) CommitteeMember(ctx context.Context, cold governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	return c.committeeMember(ctx, &cold, nil)
}

// CommitteeMemberByHot finds the member whose authorised hot credential is hot.
func (c *Client) CommitteeMemberByHot(ctx context.Context, hot governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	return c.committeeMember(ctx, nil, &hot)
}

// Constitution reads the constitution's anchor and guardrails script hash
// (GetConstitution, decoded as the library does: a bare two-element array). A
// reply that does not decode, or whose script hash is not 28 bytes, is Unknown.
// There is no None: every Conway chain has a constitution.
func (c *Client) Constitution(ctx context.Context) (chain.Reading[governance.Constitution], error) {
	var res *localstatequery.ConstitutionResult
	err := c.do(ctx, "constitution", func(q *localstatequery.Client) error {
		var err error
		res, err = q.GetConstitution()
		return err
	})
	if err != nil {
		return unknown[governance.Constitution](ctx, err)
	}
	out := governance.Constitution{Anchor: governance.Anchor{URL: res.Anchor.Url, Hash: res.Anchor.DataHash}}
	switch len(res.ScriptHash) {
	case 0:
	case 28:
		h := [28]byte(res.ScriptHash)
		out.Script = &h
	default:
		return chain.Unknown[governance.Constitution](fmt.Sprintf("the guardrails script hash has %d bytes", len(res.ScriptHash))), nil
	}
	return chain.Value(out), nil
}

// LastEnacted reads the last enacted action of a purpose from the ratify
// state's previous-action ids, read as four optional ids in the order
// parameter update, hard fork, committee, constitution. Any other shape is
// Unknown.
func (c *Client) LastEnacted(ctx context.Context, p governance.Purpose) (chain.Reading[governance.ActionID], error) {
	idx := map[governance.Purpose]int{governance.PurposePParamUpdate: 0, governance.PurposeHardFork: 1, governance.PurposeCommittee: 2, governance.PurposeConstitution: 3}
	i, ok := idx[p]
	if !ok {
		return chain.Reading[governance.ActionID]{}, fmt.Errorf("n2c: %q is not a governance purpose", p)
	}
	var res *localstatequery.RatifyStateResult
	err := c.do(ctx, "last enacted actions", func(q *localstatequery.Client) error {
		var err error
		res, err = q.GetRatifyState()
		return err
	})
	if err != nil {
		return unknown[governance.ActionID](ctx, err)
	}
	return decodePrevActionIDs(res.EnactState.PrevActionIds, i)
}

func decodePrevActionIDs(raw []byte, i int) (chain.Reading[governance.ActionID], error) {
	bad := func(why string) (chain.Reading[governance.ActionID], error) {
		return chain.Unknown[governance.ActionID]("previous action ids: " + why), nil
	}
	var fields []cbor.RawMessage
	if _, err := cbor.Decode(raw, &fields); err != nil || len(fields) != 4 {
		return bad("not an array of four optional ids")
	}
	f := fields[i]
	if len(f) == 1 && (f[0] == 0xf6 || f[0] == 0x80) {
		return chain.None[governance.ActionID](), nil
	}
	var one []lcommon.GovActionId
	if _, err := cbor.Decode(f, &one); err != nil || len(one) != 1 {
		return bad("an entry is neither empty nor one action id")
	}
	return chain.Value(governance.ActionID{TxID: chain.TxID(one[0].TransactionId), Index: one[0].GovActionIdx}), nil
}

// DRepDistribution reads the stake of the active DReps: those registered with
// an expiry at or after the current epoch, and the always-no-confidence power.
func (c *Client) DRepDistribution(ctx context.Context) (chain.Reading[governance.DRepDistribution], error) {
	var out governance.DRepDistribution
	err := c.do(ctx, "drep distribution", func(q *localstatequery.Client) error {
		epoch, err := q.GetEpochNo()
		if err != nil {
			return err
		}
		states, err := q.GetDRepState(nil)
		if err != nil {
			return err
		}
		dist, err := q.GetDRepStakeDistr(nil)
		if err != nil {
			return err
		}
		out = governance.DRepDistribution{Active: map[governance.Credential]chain.Lovelace{}}
		for _, e := range *dist {
			switch e.Drep.Type {
			case lcommon.DrepTypeNoConfidence:
				out.AlwaysNoConfidence += chain.Lovelace(e.Stake)
			case lcommon.DrepTypeAbstain:
			case lcommon.DrepTypeAddrKeyHash, lcommon.DrepTypeScriptHash:
				if len(e.Drep.Credential) != 28 {
					return errors.New("a DRep credential is not 28 bytes")
				}
				tag := uint64(e.Drep.Type)
				key := localstatequery.StakeCredential{Tag: tag, Bytes: lcommon.NewBlake2b224(e.Drep.Credential)}
				st, registered := (*states)[key]
				if registered && int64(st.Expiry) >= int64(epoch) {
					out.Active[credOf(key)] += chain.Lovelace(e.Stake)
				}
			default:
				return fmt.Errorf("unknown DRep type %d", e.Drep.Type)
			}
		}
		return nil
	})
	if err != nil {
		return unknown[governance.DRepDistribution](ctx, err)
	}
	return chain.Value(out), nil
}

// PoolDistribution reads the pools' governance voting power with the DRep
// default of each pool's reward account (one query per pool).
func (c *Client) PoolDistribution(ctx context.Context) (chain.Reading[[]governance.PoolStake], error) {
	var out []governance.PoolStake
	err := c.do(ctx, "pool distribution", func(q *localstatequery.Client) error {
		d, err := q.GetSPOStakeDistr(nil)
		if err != nil {
			return err
		}
		out = make([]governance.PoolStake, 0, len(d.Results))
		for id, stake := range d.Results {
			def, err := q.GetStakePoolDefaultVote(ledger.PoolId(id))
			if err != nil {
				return fmt.Errorf("default vote of pool %x: %w", id[:], err)
			}
			ps := governance.PoolStake{Pool: chain.PoolID(id), Stake: chain.Lovelace(stake)}
			switch def {
			case localstatequery.DefaultVoteAbstain:
				ps.Default = governance.DefaultAlwaysAbstain
			case localstatequery.DefaultVoteNoConfidence:
				ps.Default = governance.DefaultAlwaysNoConfidence
			case localstatequery.DefaultVoteNo:
			default:
				return fmt.Errorf("unknown default vote %d", def)
			}
			out = append(out, ps)
		}
		return nil
	})
	if err != nil {
		return unknown[[]governance.PoolStake](ctx, err)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Pool[:]) < string(out[j].Pool[:]) })
	return chain.Value(out), nil
}

// CommitteeComposition reads the committee: the hot credentials of the members
// that are authorised and active, and the threshold. A reply without a
// threshold is the state without a committee.
func (c *Client) CommitteeComposition(ctx context.Context) (chain.Reading[governance.CommitteeComposition], error) {
	var res *localstatequery.CommitteeMembersStateResult
	err := c.do(ctx, "committee composition", func(q *localstatequery.Client) error {
		var err error
		res, err = q.GetCommitteeMembersState(nil, nil, nil)
		return err
	})
	if err != nil {
		return unknown[governance.CommitteeComposition](ctx, err)
	}
	out := governance.CommitteeComposition{ActiveHot: map[governance.Credential]bool{}}
	if res.Threshold == nil || res.Threshold.Rat == nil {
		out.NoConfidence = true
		return chain.Value(out), nil
	}
	n, d := res.Threshold.Num(), res.Threshold.Denom()
	if !n.IsUint64() || !d.IsUint64() || d.Sign() == 0 {
		return chain.Unknown[governance.CommitteeComposition]("the committee threshold is not a fraction of 64-bit numbers"), nil
	}
	out.Exists = true
	out.Threshold = chain.Rational{Num: n.Uint64(), Den: d.Uint64()}
	for sc, ms := range res.Members {
		m, err := toMember(sc, ms)
		if err != nil {
			return chain.Unknown[governance.CommitteeComposition](err.Error()), nil
		}
		if m.Auth == governance.HotAuthorized && m.Status == "Active" {
			out.ActiveHot[m.Hot] = true
		}
	}
	return chain.Value(out), nil
}
