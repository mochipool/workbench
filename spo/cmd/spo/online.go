package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/httpfetch"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// This file wires the node-to-client provider (the "node" kind, adapter n2c,
// ADR 0006): online mode, and the node as a layer of the provider order.

// mainnetMagic is the network magic of mainnet.
const mainnetMagic = 764824073

// networkMagicOf reads the preset's magic text ("mainnet" or a decimal).
func networkMagicOf(o cli.WireOptions) (uint32, error) {
	if o.Preset.Magic == "mainnet" || (o.Preset.Magic == "" && o.Config.Network == "mainnet") {
		return mainnetMagic, nil
	}
	n, err := strconv.ParseUint(o.Preset.Magic, 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("the node provider needs the network magic of %q, which this network has none of", o.Config.Network)
	}
	return uint32(n), nil
}

// newNode builds the node client of a command. It does not connect: the
// connection is made when a read first needs it, once, and is closed with the
// command's Env. A TCP address that is not loopback prints the warning on errw
// when the connection is made, once.
func newNode(env *cli.Env, o cli.WireOptions, errw io.Writer) (*n2c.Client, error) {
	n := o.Config.Node
	if n == nil || n.Address == "" {
		return nil, errors.New("no node address is configured: spo provider set node <socket path | tcp://host:port>")
	}
	magic, err := networkMagicOf(o)
	if err != nil {
		return nil, err
	}
	cfg := n2c.Config{Address: n.Address, NetworkMagic: magic, Network: o.Config.Network}
	if n.TimeoutSeconds > 0 {
		cfg.Timeout = time.Duration(n.TimeoutSeconds) * time.Second
	}
	if n2c.IsPlainTCP(n.Address) {
		var once sync.Once
		cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			once.Do(func() {
				if errw != nil {
					fmt.Fprintln(errw, n2c.WarnPlainTCP)
				}
			})
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		}
	}
	c, err := n2c.DialLazy(cfg)
	if err != nil {
		return nil, err
	}
	env.OnClose(func() { _ = c.Close() })
	env.Endpoints[string(c.Source())] = n.Address
	return c, nil
}

// syncGate makes the node's state reads refuse an unsynced node, as every
// transaction and query script of upstream's online mode does (SPO-Ptx-MODE-002:
// "refuses unless the node reports fully synced"). The gate asks the node's
// own sync check (the Sync capability) once per command; a synced answer is
// remembered, a refusal is not.
type syncGate struct {
	sync ports.SyncChecker
	mu   sync.Mutex
	ok   bool
}

func (g *syncGate) check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ok {
		return nil
	}
	ok, err := g.sync.Synced(ctx)
	if err != nil {
		return fmt.Errorf("the sync state from %s: %w", g.sync.Source(), err)
	}
	if !ok {
		return fmt.Errorf("%w: %s", query.ErrNotSynced, g.sync.Source())
	}
	g.ok = true
	return nil
}

// gatedNode is the node client whose state reads (UTxOs, accounts, pools,
// DReps, the opcert counter, governance state) first pass the sync gate. The
// tip, the sync check itself, the parameters, the genesis and the submission
// are not gated: they are not state a decision rests on, or they are the check.
//
// The client is a named field, not an embedded one: an embedded client would
// promote every reader it has, so a method the gate forgot would be reachable
// through the field's interface, or through a type assertion on it. Only the
// methods written below exist on the type.
type gatedNode struct {
	c    *n2c.Client
	gate *syncGate
}

func (g gatedNode) Source() chain.Source { return g.c.Source() }

// OpCertCounterEnforced says the counter is the node's (ports.OpCertCounterEnforcer).
func (g gatedNode) OpCertCounterEnforced() bool { return g.c.OpCertCounterEnforced() }

// Epoch is the current epoch number: like the tip, not state a decision rests on.
func (g gatedNode) Epoch(ctx context.Context) (uint64, error) { return g.c.Epoch(ctx) }

// The narrow views of the ungated reads. Each exposes the methods of one port
// and nothing else, by composition, so the field that holds it cannot be
// asserted to a state reader and read around the gate.
type (
	nodeTip     struct{ c *n2c.Client }
	nodeSync    struct{ c *n2c.Client }
	nodeParams  struct{ c *n2c.Client }
	nodeSubmit  struct{ c *n2c.Client }
	nodeGenesis struct{ c *n2c.Client }
)

func (v nodeTip) Source() chain.Source                       { return v.c.Source() }
func (v nodeTip) Tip(ctx context.Context) (chain.Tip, error) { return v.c.Tip(ctx) }
func (v nodeSync) Source() chain.Source                      { return v.c.Source() }
func (v nodeSync) Synced(ctx context.Context) (bool, error)  { return v.c.Synced(ctx) }
func (v nodeParams) Source() chain.Source                    { return v.c.Source() }
func (v nodeParams) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	return v.c.ProtocolParameters(ctx)
}
func (v nodeSubmit) Source() chain.Source { return v.c.Source() }
func (v nodeSubmit) Submit(ctx context.Context, tx []byte) (chain.TxID, error) {
	return v.c.Submit(ctx, tx)
}
func (v nodeGenesis) Genesis(ctx context.Context) (chain.Genesis, error) { return v.c.Genesis(ctx) }

func (g gatedNode) Utxos(ctx context.Context, a chain.Address) ([]chain.Utxo, error) {
	if err := g.gate.check(ctx); err != nil {
		return nil, err
	}
	return g.c.Utxos(ctx, a)
}

func (g gatedNode) ResolveUtxos(ctx context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	if err := g.gate.check(ctx); err != nil {
		return nil, err
	}
	return g.c.ResolveUtxos(ctx, refs)
}

func (g gatedNode) RewardAccount(ctx context.Context, s chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[chain.RewardAccount]{}, err
	}
	return g.c.RewardAccount(ctx, s)
}

func (g gatedNode) OpCertCounter(ctx context.Context, p chain.PoolID) (chain.Reading[uint64], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[uint64]{}, err
	}
	return g.c.OpCertCounter(ctx, p)
}

func (g gatedNode) PoolState(ctx context.Context, p chain.PoolID) (chain.Reading[chain.PoolState], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[chain.PoolState]{}, err
	}
	return g.c.PoolState(ctx, p)
}

func (g gatedNode) PoolInfo(ctx context.Context, p chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[chain.PoolInfo]{}, err
	}
	return g.c.PoolInfo(ctx, p)
}

func (g gatedNode) DRepState(ctx context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[chain.DRepState]{}, err
	}
	return g.c.DRepState(ctx, id)
}

func (g gatedNode) GovActions(ctx context.Context, id *governance.ActionID) (chain.Reading[[]governance.ActionState], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[[]governance.ActionState]{}, err
	}
	return g.c.GovActions(ctx, id)
}

func (g gatedNode) CommitteeMember(ctx context.Context, cold governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[governance.CommitteeMember]{}, err
	}
	return g.c.CommitteeMember(ctx, cold)
}

func (g gatedNode) CommitteeMemberByHot(ctx context.Context, hot governance.Credential) (chain.Reading[governance.CommitteeMember], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[governance.CommitteeMember]{}, err
	}
	return g.c.CommitteeMemberByHot(ctx, hot)
}

func (g gatedNode) Constitution(ctx context.Context) (chain.Reading[governance.Constitution], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[governance.Constitution]{}, err
	}
	return g.c.Constitution(ctx)
}

func (g gatedNode) LastEnacted(ctx context.Context, p governance.Purpose) (chain.Reading[governance.ActionID], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[governance.ActionID]{}, err
	}
	return g.c.LastEnacted(ctx, p)
}

func (g gatedNode) DRepDistribution(ctx context.Context) (chain.Reading[governance.DRepDistribution], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[governance.DRepDistribution]{}, err
	}
	return g.c.DRepDistribution(ctx)
}

func (g gatedNode) PoolDistribution(ctx context.Context) (chain.Reading[[]governance.PoolStake], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[[]governance.PoolStake]{}, err
	}
	return g.c.PoolDistribution(ctx)
}

func (g gatedNode) CommitteeComposition(ctx context.Context) (chain.Reading[governance.CommitteeComposition], error) {
	if err := g.gate.check(ctx); err != nil {
		return chain.Reading[governance.CommitteeComposition]{}, err
	}
	return g.c.CommitteeComposition(ctx)
}

// nodeAddOn is how a web provider may be asked about what the node cannot
// answer: it needs a section and a place in [provider] order.
const nodeAddOn = "; a web provider that has it can be allowed: configure it (spo provider set koios) and name it in the order (spo provider order node koios)"

// nodeLacks is why each capability the node cannot answer is absent.
var nodeLacks = map[cli.Cap]string{
	cli.CapCalidusRead:   "the Calidus registrations are transaction metadata, which the node cannot be asked for" + nodeAddOn,
	cli.CapAdaHandle:     "the node cannot say which address holds an asset, which an ADA Handle needs" + nodeAddOn,
	cli.CapPollQuestion:  "SPO polls are transaction metadata, which the node cannot be asked for" + nodeAddOn,
	cli.CapPoolUpdates:   "the time of a pool's last registration update is not ledger state, so the node cannot answer it" + nodeAddOn,
	cli.CapVotingSummary: "a node gives the stake distributions to tally from, not a tally",
	cli.CapEras:          "the node adapter does not read the era name for the air-gap commands yet" + nodeAddOn,
	cli.CapTokenRegistry: "the token registry is a web service, not a chain read: it is asked only when a web provider is allowed in the order" + nodeAddOn,
	cli.CapTxEvaluator:   noEvaluator,
	cli.CapCrossCheck:    noOnlineSecond,
	cli.CapPoolCross:     noOnlineSecond,
	cli.CapDRepCross:     noOnlineSecond,
	cli.CapOpCertCross:   noOnlineSecond,
	cli.CapQueue:         "online mode submits through the node; there is no queue",
	cli.CapAttach:        "online mode submits through the node; there is no transfer file to attach to",
}

// noOnlineSecond is why the node has no second source of a harmful-class read.
const noOnlineSecond = "online mode reads from the node alone, so reads that need corroboration are refused unless the command is given --single-source" + nodeAddOn

const noNode = "no node address is configured: give the node's socket with: spo provider set node <socket path | tcp://host:port>"

// absentAll records one reason for every chain capability.
func absentAll(env *cli.Env, why string) {
	for _, c := range chainCaps {
		env.Absent(c, why)
	}
}

// wireChain wires the chain capabilities of the online and light modes from
// the configured providers (ADR 0006). The node is the answering provider in
// online mode, and in light mode when the operator's order puts it first;
// otherwise it is, when the order puts it second, the second source of the reads
// that need corroboration. A web provider (Koios, Blockfrost) never answers or
// corroborates in online mode unless the operator named it in [provider] order,
// so an addresses-bearing request goes to a third party only by an explicit
// setting.
func wireChain(env *cli.Env, o cli.WireOptions, errw io.Writer) error {
	if err := wireChainProviders(env, o, errw); err != nil {
		return err
	}
	freshenSources(env, time.Now)
	if err := wireTxWatchers(env, o, errw); err != nil {
		return err
	}
	announceFetches(env, errw)
	return nil
}

func wireChainProviders(env *cli.Env, o cli.WireOptions, errw io.Writer) error {
	cfg := toConfig(o.Config)
	haveWeb := o.Config.Koios != nil || o.Config.Blockfrost != nil
	nodeFirst := o.Mode == cli.ModeOnline || (cfg.Node != nil && cfg.Providers()[0] == config.KindNode)
	switch {
	case nodeFirst:
		return wireNodeFirst(env, o, cfg, errw)
	case !haveWeb:
		absentAll(env, "no chain provider is configured: spo provider set koios")
		return nil
	}
	if err := wireLightProviders(env, o); err != nil {
		return err
	}
	if cfg.Node != nil {
		if ps := cfg.Providers(); len(ps) > 1 && ps[1] == config.KindNode {
			return addNodeSecond(env, o, errw)
		}
	}
	return nil
}

// addNodeSecond makes the node the second source of the reads that are
// corroborated, in place of any other second provider, in light mode where
// the order puts the node right after the answering provider.
func addNodeSecond(env *cli.Env, o cli.WireOptions, errw io.Writer) error {
	n, err := newNode(env, o, errw)
	if err != nil {
		return err
	}
	// The node as a second source passes the same sync gate as the node as
	// the answering provider: an unsynced node's "agreement" is not one.
	g := gatedNode{c: n, gate: &syncGate{sync: n}}
	env.CrossCheck, env.PoolCross, env.DRepCross, env.OpCertCross = g, g, g, g
	env.PoolInfoCross = g
	return env.CheckIndependentSources()
}

// wireNodeFirst wires the node as the answering provider.
func wireNodeFirst(env *cli.Env, o cli.WireOptions, cfg config.Config, errw io.Writer) error {
	if o.Config.Node == nil {
		absentAll(env, noNode)
		return nil
	}
	n, err := newNode(env, o, errw)
	if err != nil {
		return err
	}
	g := gatedNode{c: n, gate: &syncGate{sync: n}}
	env.Tip, env.Sync, env.Params, env.Submitter = nodeTip{n}, nodeSync{n}, nodeParams{n}, nodeSubmit{n}
	env.OpCertCounters = g
	env.Utxos, env.OwnUtxos = g, g
	env.Rewards, env.Pools, env.DReps = g, g, g
	env.PoolInfos = g
	if env.Genesis == nil {
		env.Genesis = nodeGenesis{n}
	}
	env.AnchorFetcher = httpfetch.Fetcher{Limit: anchorLimit}
	env.Metadata = httpfetch.Fetcher{Limit: pool.MaxMetadataBytes}
	env.Absent(cli.CapVotingSummary, nodeLacks[cli.CapVotingSummary])
	env.Absent(cli.CapEras, nodeLacks[cli.CapEras])
	governanceReaders(env, g, "the node has no query for this"+nodeAddOn)

	// The web providers the operator allowed: all that are configured in light
	// mode, only those named in the order in online mode.
	var allowed []string
	for _, k := range cfg.Providers() {
		if !config.IsWebKind(k) {
			continue
		}
		if o.Mode == cli.ModeOnline && !contains(o.Config.Order, k) {
			continue
		}
		allowed = append(allowed, k)
	}
	var web *cli.Env
	if len(allowed) > 0 {
		web = &cli.Env{Mode: cli.ModeLight, Endpoints: map[string]string{}, SameHostOK: o.Config.SameHostOK}
		o2 := o
		o2.Mode = cli.ModeLight
		o2.Config.Node = nil
		o2.Config.Order = allowed
		if !contains(allowed, config.KindKoios) {
			o2.Config.Koios = nil
		}
		if !contains(allowed, config.KindBlockfrost) {
			o2.Config.Blockfrost = nil
		}
		if err := wireLightProviders(web, o2); err != nil {
			return err
		}
		for k, v := range web.Endpoints {
			env.Endpoints[k] = v
		}
		mergeWeb(env, web)
	}
	for _, c := range chainCaps {
		if env.Has(c) {
			continue
		}
		switch {
		case web != nil && web.Reason(c) != "" && !isGeneric(web.Reason(c)):
			env.Absent(c, web.Reason(c))
		case nodeLacks[c] != "":
			env.Absent(c, nodeLacks[c])
		default:
			env.Absent(c, "the node has no query for this"+nodeAddOn)
		}
	}
	env.Absent(cli.CapDRepCross, noOnlineSecond)
	return env.CheckIndependentSources()
}

// isGeneric is true for the reason an Env gives a capability nobody said
// anything about.
func isGeneric(reason string) bool { return reason == "light mode cannot supply it" }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// mergeWeb takes from the allowed web providers what the node cannot answer,
// and their answering readers as the second source of the reads that need
// corroboration. A reader the node answers is never replaced.
func mergeWeb(env, web *cli.Env) {
	env.CrossCheck, env.PoolCross, env.DRepCross = web.Rewards, web.Pools, web.DReps
	env.OpCertCross = web.OpCertCounters
	env.PoolInfoCross = web.PoolInfos
	if env.Polls == nil {
		env.Polls = web.Polls
	}
	if env.CalidusReader == nil {
		env.CalidusReader = web.CalidusReader
	}
	if env.PoolUpdates == nil {
		env.PoolUpdates = web.PoolUpdates
	}
	if env.Eras == nil {
		env.Eras = web.Eras
	}
	if env.Handles == nil && web.Has(cli.CapAdaHandle) {
		env.Handles = web.Handles
	}
	if env.Registry == nil {
		env.Registry = web.Registry
	}
	if env.Summaries == nil {
		env.Summaries = web.Summaries
	}
	if env.TxEvaluator == nil {
		env.TxEvaluator = web.TxEvaluator
	}
}
