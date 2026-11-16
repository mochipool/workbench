package n2c

import (
	"context"
	"fmt"
	"strconv"

	"github.com/blinklabs-io/gouroboros/ledger"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.PoolInfoReader = (*Client)(nil)

// PoolInfo reads the registration data the pool import needs: the pool's
// parameters from GetPoolState (pledge, cost, margin, reward account, owners,
// relays, metadata, VRF key hash) and the opcert counter from the chain-
// dependent state. None means the node has no such pool registered. The time
// of the last registration update is not on the node's state, so no
// ports.PoolUpdateReader is implemented.
func (c *Client) PoolInfo(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	var (
		res      *localstatequery.PoolStateResult
		counters map[lcommon.Blake2b224]uint64
		cntErr   error
	)
	err := c.do(ctx, "pool info", func(q *localstatequery.Client) error {
		var err error
		if res, err = q.GetPoolState([]any{ledger.PoolId(pool)}); err != nil {
			return err
		}
		counters, cntErr = q.GetOpCertCounters()
		return nil
	})
	if err != nil {
		return unknown[chain.PoolInfo](ctx, err)
	}
	h := lcommon.Blake2b224(pool)
	p, ok := res.PState[h]
	if !ok || p == nil {
		if len(res.PState) > 0 {
			return chain.Unknown[chain.PoolInfo]("the node answered the pool state query for other pools than the one asked"), nil
		}
		return chain.None[chain.PoolInfo](), nil
	}
	info := chain.PoolInfo{
		IDBech:     pool.Bech32(),
		IDHex:      fmt.Sprintf("%x", pool[:]),
		Status:     "registered",
		Pledge:     strconv.FormatUint(p.Pledge, 10),
		FixedCost:  strconv.FormatUint(p.Cost, 10),
		VRFKeyHash: fmt.Sprintf("%x", p.VrfKeyHash[:]),
		RewardAddr: p.RewardAccount.String(),
	}
	if p.Margin != nil && p.Margin.Rat != nil {
		info.Margin = ratDecimal(p.Margin.Rat)
	} else {
		return chain.Unknown[chain.PoolInfo]("the node gave no margin"), nil
	}
	if _, retiring := res.Retiring[h]; retiring {
		info.Status = "retiring"
	}
	if p.PoolMetadata != nil {
		info.MetaURL = p.PoolMetadata.Url
		info.MetaHash = p.PoolMetadata.MetadataHash.String()
	}
	mainnet := c.cfg.NetworkMagic == mainnetMagic
	for _, o := range p.PoolOwners {
		hdr := byte(0xe0)
		if mainnet {
			hdr = 0xe1
		}
		a, err := chain.Bech32Encode(stakeHRP(mainnet), append([]byte{hdr}, o[:]...))
		if err != nil {
			return chain.Unknown[chain.PoolInfo](err.Error()), nil
		}
		info.Owners = append(info.Owners, a)
	}
	for i, r := range p.Relays {
		pr, err := toRelay(r)
		if err != nil {
			return chain.Unknown[chain.PoolInfo](fmt.Sprintf("relay %d: %v", i, err)), nil
		}
		info.Relays = append(info.Relays, pr)
	}
	switch {
	case cntErr != nil:
		info.OpCertCounter = chain.Unknown[uint64]("counter query failed: " + cntErr.Error())
	case len(counters) == 0:
		info.OpCertCounter = chain.Unknown[uint64]("the node returned an empty operational certificate counter map")
	default:
		if n, ok := counters[h]; ok {
			info.OpCertCounter = chain.Value(n)
		} else {
			info.OpCertCounter = chain.None[uint64]()
		}
	}
	return chain.Value(info), nil
}

func stakeHRP(mainnet bool) string {
	if mainnet {
		return "stake"
	}
	return "stake_test"
}

// toRelay writes a relay as Koios does: one member for the address kind, and the
// port as text (empty when the relay has none).
func toRelay(r ledger.PoolRelay) (chain.PoolRelay, error) {
	out := chain.PoolRelay{Members: map[string]string{}}
	if r.Port != nil {
		out.Port = strconv.FormatUint(uint64(*r.Port), 10)
	}
	switch r.Type {
	case lcommon.PoolRelayTypeSingleHostAddress:
		if r.Ipv4 != nil {
			out.Members["ipv4"] = r.Ipv4.String()
		}
		if r.Ipv6 != nil {
			out.Members["ipv6"] = r.Ipv6.String()
		}
	case lcommon.PoolRelayTypeSingleHostName:
		if r.Hostname == nil {
			return out, fmt.Errorf("a host name relay without a name")
		}
		out.Members["dns"] = *r.Hostname
	case lcommon.PoolRelayTypeMultiHostName:
		if r.Hostname == nil {
			return out, fmt.Errorf("a service relay without a name")
		}
		out.Members["srv"] = *r.Hostname
	default:
		return out, fmt.Errorf("unknown relay type %d", r.Type)
	}
	return out, nil
}
