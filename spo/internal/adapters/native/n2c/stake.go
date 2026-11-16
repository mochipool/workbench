package n2c

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.RewardAccountReader = (*Client)(nil)
	_ ports.PoolStateReader     = (*Client)(nil)
	_ ports.DRepStateReader     = (*Client)(nil)
	_ ports.OpCertCounterReader = (*Client)(nil)
)

// stakeCredential reads a stake address into the node's credential form and
// checks that its network nibble agrees with the configured magic: an address
// of another network is a mistake the node would answer "not registered" to.
func (c *Client) stakeCredential(a chain.StakeAddress) (localstatequery.StakeCredential, error) {
	hrp, data, err := chain.Bech32Decode(string(a))
	if err != nil {
		return localstatequery.StakeCredential{}, fmt.Errorf("%q is not a stake address: %w", a, err)
	}
	if (hrp != "stake" && hrp != "stake_test") || len(data) != 29 {
		return localstatequery.StakeCredential{}, fmt.Errorf("%q is not a stake address", a)
	}
	var tag uint64
	switch data[0] & 0xf0 {
	case 0xe0:
		tag = 0
	case 0xf0:
		tag = 1
	default:
		return localstatequery.StakeCredential{}, fmt.Errorf("%q is not a stake address (header %#02x)", a, data[0])
	}
	mainnet := data[0]&0x0f == 1
	if (hrp == "stake") != mainnet || mainnet != (c.cfg.NetworkMagic == mainnetMagic) {
		return localstatequery.StakeCredential{}, fmt.Errorf("%q belongs to another network than magic %d", a, c.cfg.NetworkMagic)
	}
	return localstatequery.StakeCredential{Tag: tag, Bytes: lcommon.NewBlake2b224(data[1:])}, nil
}

const mainnetMagic = 764824073

func credOf(sc localstatequery.StakeCredential) governance.Credential {
	return governance.Credential{Script: sc.Tag == 1, Hash: [28]byte(sc.Bytes)}
}

// RewardAccount reads a stake address: registration, delegation, vote
// delegation, withdrawable rewards, the deposit and the governance-action
// deposits to be refunded to it. None means the node says the address is not
// registered. A node that answers the registration question inconsistently
// (rewards without a deposit entry the other way round), or a failure of the
// queries that decide it, is Unknown. Fields a second query could not supply
// are Unknown inside a Value.
func (c *Client) RewardAccount(ctx context.Context, stake chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	cred, err := c.stakeCredential(stake)
	if err != nil {
		return chain.Reading[chain.RewardAccount]{}, fmt.Errorf("n2c reward account: %w", err)
	}
	var acc chain.RewardAccount
	registered := false
	err = c.do(ctx, "reward account", func(q *localstatequery.Client) error {
		creds := []localstatequery.StakeCredential{cred}
		da, err := q.GetFilteredDelegationsAndRewardAccounts(creds)
		if err != nil {
			return err
		}
		_, inRewards := da.Rewards[cred]
		pool, delegated := da.Delegations[cred]
		if delegated && !inRewards {
			return errors.New("the node reports a delegation for an address it has no reward account for")
		}
		deps, depErr := q.GetStakeDelegDeposits(creds)
		var deposit chain.Reading[chain.Lovelace]
		switch {
		case depErr != nil:
			deposit = chain.Unknown[chain.Lovelace]("deposit query failed: " + depErr.Error())
		default:
			d, ok := (*deps)[cred]
			switch {
			case ok && !inRewards:
				return errors.New("the node reports a deposit for an address it has no reward account for")
			case ok:
				deposit = chain.Value(chain.Lovelace(d))
			case inRewards:
				deposit = chain.Unknown[chain.Lovelace]("the node did not state a deposit for a registered address")
			}
		}
		if !inRewards {
			// A filtered query answers for the credentials asked and no others.
			// An empty answer is "not registered"; an answer about other
			// addresses is not an answer about this one.
			if len(da.Rewards) > 0 || len(da.Delegations) > 0 {
				return errors.New("the node answered the reward account query for other addresses than the one asked")
			}
			return nil
		}
		registered = true
		acc = chain.RewardAccount{Address: stake, Withdrawable: chain.Lovelace(da.Rewards[cred]), Deposit: deposit}
		if delegated {
			acc.DelegatedPool = chain.Value(chain.PoolID(pool))
		} else {
			acc.DelegatedPool = chain.None[chain.PoolID]()
		}
		acc.VoteDelegation = chain.Unknown[string]("vote delegation not read")
		vd, err := q.GetFilteredVoteDelegatees([]lcommon.Credential{{CredType: uint(cred.Tag), Credential: cred.Bytes}})
		if err != nil {
			acc.VoteDelegation = chain.Unknown[string]("vote delegation query failed: " + err.Error())
		} else {
			// The node keys this map by the stake credential.
			if d, ok := (*vd)[cred]; ok {
				acc.VoteDelegation = chain.Value(drepText(d))
			} else if len(*vd) > 0 {
				acc.VoteDelegation = chain.Unknown[string]("the node answered the vote delegation query for other addresses than the one asked")
			} else {
				acc.VoteDelegation = chain.None[string]()
			}
		}
		acc.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("governance proposals not read")
		if ps, err := q.GetProposals(); err != nil {
			acc.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("proposals query failed: " + err.Error())
		} else {
			deps := []chain.GovActionDeposit{}
			ok := true
			for _, p := range *ps {
				pp, err := decodeProposal(p.ProposalProcedure)
				if err != nil {
					ok = false
					acc.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("a proposal did not decode: " + err.Error())
					break
				}
				if pp.ReturnCred == credOf(cred) && pp.ReturnMainnet == (c.cfg.NetworkMagic == mainnetMagic) {
					deps = append(deps, chain.GovActionDeposit{
						Action: fmt.Sprintf("%x#%d", p.Id.TransactionId[:], p.Id.GovActionIdx),
						Amount: chain.Lovelace(pp.Deposit),
					})
				}
			}
			if ok {
				acc.GovActionDeposits = chain.Value(deps)
			}
		}
		return nil
	})
	if err != nil {
		return unknown[chain.RewardAccount](ctx, err)
	}
	if !registered {
		return chain.None[chain.RewardAccount](), nil
	}
	return chain.Value(acc), nil
}

// drepText is the text of a vote delegation: CIP-129 bech32 for a credential,
// and the names Koios uses for the two predefined options.
func drepText(d lcommon.Drep) string {
	switch d.Type {
	case lcommon.DrepTypeAbstain:
		return "drep_always_abstain"
	case lcommon.DrepTypeNoConfidence:
		return "drep_always_no_confidence"
	}
	hdr := byte(0x22)
	if d.Type == lcommon.DrepTypeScriptHash {
		hdr = 0x23
	}
	s, err := chain.Bech32Encode("drep", append([]byte{hdr}, d.Credential...))
	if err != nil {
		return "unrepresentable drep"
	}
	return s
}

// OpCertCounter reads the operational-certificate counter the node enforces
// for a pool (the chain-dependent state of the consensus layer, the value
// `cardano-cli query kes-period-info` reports). Value is the highest counter
// of a block the node accepted from the pool; None means the node's counter
// map has no entry for the pool, which is what a pool that has made no block
// looks like; a failed query is Unknown.
func (c *Client) OpCertCounter(ctx context.Context, pool chain.PoolID) (chain.Reading[uint64], error) {
	var counters map[lcommon.Blake2b224]uint64
	err := c.do(ctx, "opcert counter", func(q *localstatequery.Client) error {
		var err error
		counters, err = q.GetOpCertCounters()
		return err
	})
	if err != nil {
		return unknown[uint64](ctx, err)
	}
	// The counter map covers every pool that made a block, so a pool missing
	// from it made none (None); an empty map is not that answer (a node that
	// has not loaded its consensus state, or one that does not state it).
	if len(counters) == 0 {
		return chain.Unknown[uint64]("the node returned an empty operational certificate counter map"), nil
	}
	if n, ok := counters[lcommon.Blake2b224(pool)]; ok {
		return chain.Value(n), nil
	}
	return chain.None[uint64](), nil
}

// PoolState reads a pool's registration (GetPoolState). None means the pool is
// not in the node's registered set: a retired pool, or one never registered.
// A pool with a retirement scheduled is Value with status retiring. Name and
// ticker are not on chain and stay empty.
func (c *Client) PoolState(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolState], error) {
	var res *localstatequery.PoolStateResult
	err := c.do(ctx, "pool state", func(q *localstatequery.Client) error {
		var err error
		res, err = q.GetPoolState([]any{ledger.PoolId(pool)})
		return err
	})
	if err != nil {
		return unknown[chain.PoolState](ctx, err)
	}
	h := lcommon.Blake2b224(pool)
	p, ok := res.PState[h]
	if !ok || p == nil {
		if len(res.PState) > 0 {
			return chain.Unknown[chain.PoolState]("the node answered the pool state query for other pools than the one asked"), nil
		}
		return chain.None[chain.PoolState](), nil
	}
	st := chain.PoolState{
		ID:     pool,
		Pledge: chain.Value(chain.Lovelace(p.Pledge)),
		Cost:   chain.Value(chain.Lovelace(p.Cost)),
	}
	if p.Margin != nil && p.Margin.Rat != nil {
		st.Margin = ratDecimal(p.Margin.Rat)
	}
	st.RewardAddress = p.RewardAccount.String()
	if p.PoolMetadata != nil {
		st.MetaURL = p.PoolMetadata.Url
		st.MetaHash = p.PoolMetadata.MetadataHash.String()
	}
	if e, ok := res.Retiring[h]; ok {
		st.Status, st.RetiringEpoch = chain.PoolRetiring, e
	}
	return chain.Value(st), nil
}

// ratDecimal writes a margin as decimal text: exact when the denominator
// divides a power of ten, otherwise to 18 places with trailing zeros removed.
func ratDecimal(r *big.Rat) string {
	s := r.FloatString(18)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

// DRepState reads a DRep's registration. None means the node has no such DRep
// registered. The delegated stake is Unknown when its query fails.
func (c *Client) DRepState(ctx context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	tag := uint64(0)
	if id.Script {
		tag = 1
	}
	key := localstatequery.StakeCredential{Tag: tag, Bytes: lcommon.NewBlake2b224(id.Hash[:])}
	var (
		entry localstatequery.DRepStateEntry
		found bool
		stake = chain.Unknown[chain.Lovelace]("not read")
	)
	err := c.do(ctx, "drep state", func(q *localstatequery.Client) error {
		res, err := q.GetDRepState([]lcommon.Credential{{CredType: uint(tag), Credential: key.Bytes}})
		if err != nil {
			return err
		}
		entry, found = (*res)[key]
		if !found {
			if len(*res) > 0 {
				return errors.New("the node answered the DRep state query for other DReps than the one asked")
			}
			return nil
		}
		dist, err := q.GetDRepStakeDistr([]lcommon.Drep{{Type: int(tag), Credential: id.Hash[:]}})
		if err != nil {
			stake = chain.Unknown[chain.Lovelace]("stake query failed: " + err.Error())
			return nil
		}
		stake = chain.Value(chain.Lovelace(0))
		for _, e := range *dist {
			if e.Drep.Type == int(tag) && string(e.Drep.Credential) == string(id.Hash[:]) {
				stake = chain.Value(chain.Lovelace(e.Stake))
			}
		}
		return nil
	})
	if err != nil {
		return unknown[chain.DRepState](ctx, err)
	}
	if !found {
		return chain.None[chain.DRepState](), nil
	}
	st := chain.DRepState{ID: id, Deposit: chain.Lovelace(entry.Deposit), Expiry: chain.Value(entry.Expiry), DelegatedStake: stake}
	if entry.Anchor != nil {
		st.AnchorURL = entry.Anchor.Url
		st.AnchorHash = fmt.Sprintf("%x", entry.Anchor.DataHash[:])
	}
	return chain.Value(st), nil
}
