// Package n2ctest is an in-process cardano-node for tests: it serves the server
// side of the node-to-client mini-protocols (local-state-query,
// local-tx-submission, local-tx-monitor) on a UNIX socket, with replies a test
// registers by query name. It is test support: nothing outside _test.go files
// imports it, and a reply is only as true as the bytes the test gives it (see
// the n2c README for which are hand-written and which are the library's own
// encoding). It lives inside the Blink Labs confinement (adapters/native)
// because it uses gouroboros.
//
// It does not import package n2c, so n2c's own tests can use it.
package n2ctest

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/cbor"
	lsq "github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	ltm "github.com/blinklabs-io/gouroboros/protocol/localtxmonitor"
	lts "github.com/blinklabs-io/gouroboros/protocol/localtxsubmission"
)

// Magic is the network magic of preview, the network the fake node serves.
const Magic = 2

// A Node is an in-process cardano-node: it serves the server side of
// gouroboros' local-state-query, local-tx-submission and local-tx-monitor on a
// UNIX socket. Replies are registered by query name; a reply is any value the
// library encodes, or a cbor.RawMessage of hand-written bytes. Shelley-era
// replies are put inside the one-element array the node wraps them in, except
// where the reply is registered with raw: true.
type Node struct {
	t       testing.TB
	magic   uint32
	path    string
	ln      net.Listener
	mu      sync.Mutex
	replies map[string]reply
	asked   []string
	// release counts Release messages; a query waits on hold when set.
	released int
	hold     chan struct{}
	submit   func(tx lts.MsgSubmitTxTransaction) error
	mempool  []ltm.TxAndEraId
	conns    []*ouroboros.Connection
	accepted int
	errs     []string // errors the fake's side of the protocol reported
}

// Hold makes every query wait until ch is closed (nil stops holding).
func (n *Node) Hold(ch chan struct{}) {
	n.mu.Lock()
	n.hold = ch
	n.mu.Unlock()
}

// SubmitMessage is what a node receives when a client submits a transaction.
type SubmitMessage = lts.MsgSubmitTxTransaction

// OnSubmit sets what the node answers a submitted transaction: nil accepts.
func (n *Node) OnSubmit(f func(tx SubmitMessage) error) {
	n.mu.Lock()
	n.submit = f
	n.mu.Unlock()
}

// SetMempool sets the transactions the node's mempool holds.
func (n *Node) SetMempool(txs []ltm.TxAndEraId) {
	n.mu.Lock()
	n.mempool = txs
	n.mu.Unlock()
}

// Released is the number of times a client released its acquired state.
func (n *Node) Released() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.released
}

// Errs are the errors the node's side of the protocol reported.
func (n *Node) Errs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.errs...)
}

// Accepted is the number of connections accepted so far: a test that must show
// no connection was made asserts it is zero.
func (n *Node) Accepted() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.accepted
}

type reply struct {
	value any
	raw   bool // the reply is sent as is, without the era wrapper
	err   error
	fn    func(q any) any // when set, builds the reply from the decoded query
}

// Start serves a fake node on a fresh UNIX socket in the test's temporary
// directory and stops it when the test ends.
func Start(t testing.TB) *Node {
	t.Helper()
	// A short path: a UNIX socket path is limited to about 100 bytes, which a
	// long test name in t.TempDir() can exceed.
	dir, err := os.MkdirTemp("", "n2c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	n := &Node{t: t, magic: Magic, path: filepath.Join(dir, "node.socket"), replies: map[string]reply{}}
	ln, err := net.Listen("unix", n.path)
	if err != nil {
		t.Fatal(err)
	}
	n.ln = ln
	go n.accept()
	t.Cleanup(n.Stop)
	return n
}

// Stop closes the listener and every connection. It runs at test end; a test
// calls it to simulate a node that goes away.
func (n *Node) Stop() {
	_ = n.ln.Close()
	n.mu.Lock()
	conns := n.conns
	n.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (n *Node) accept() {
	for {
		raw, err := n.ln.Accept()
		if err != nil {
			return
		}
		n.mu.Lock()
		n.accepted++
		n.mu.Unlock()
		go n.serve(raw)
	}
}

func (n *Node) serve(raw net.Conn) {
	errCh := make(chan error, 16)
	go func() {
		for err := range errCh {
			n.mu.Lock()
			n.errs = append(n.errs, err.Error())
			n.mu.Unlock()
		}
	}()
	conn, err := ouroboros.NewConnection(
		ouroboros.WithErrorChan(errCh),
		ouroboros.WithConnection(raw),
		ouroboros.WithNetworkMagic(n.magic),
		ouroboros.WithServer(true),
		ouroboros.WithNodeToNode(false),
		ouroboros.WithLocalStateQueryConfig(lsq.NewConfig(
			lsq.WithAcquireFunc(func(lsq.CallbackContext, lsq.AcquireTarget, bool) error { return nil }),
			lsq.WithQueryFunc(n.query),
			lsq.WithReleaseFunc(func(lsq.CallbackContext) error {
				n.mu.Lock()
				n.released++
				n.mu.Unlock()
				return nil
			}),
		)),
		ouroboros.WithLocalTxSubmissionConfig(lts.NewConfig(
			lts.WithSubmitTxFunc(func(_ lts.CallbackContext, tx lts.MsgSubmitTxTransaction) error {
				n.mu.Lock()
				f := n.submit
				n.mu.Unlock()
				if f == nil {
					return nil
				}
				return f(tx)
			}),
		)),
		ouroboros.WithLocalTxMonitorConfig(ltm.NewConfig(
			ltm.WithGetMempoolFunc(func(ltm.CallbackContext) (uint64, uint32, []ltm.TxAndEraId, error) {
				n.mu.Lock()
				defer n.mu.Unlock()
				return 1_000_000, 100, n.mempool, nil
			}),
		)),
	)
	if err != nil {
		_ = raw.Close()
		return
	}
	n.mu.Lock()
	n.conns = append(n.conns, conn)
	n.mu.Unlock()
}

// Path is the node's socket.
func (n *Node) Path() string { return n.path }

// Set registers the reply to a query name (see queryName).
func (n *Node) Set(name string, v any) {
	n.mu.Lock()
	n.replies[name] = reply{value: v}
	n.mu.Unlock()
}

// SetRaw registers hand-written reply bytes that are sent unwrapped: the bytes
// include the era wrapper, as they are on the wire.
func (n *Node) SetRaw(name, hexBytes string) {
	b, err := hex.DecodeString(hexBytes)
	if err != nil {
		n.t.Fatalf("bad hex for %s: %v", name, err)
	}
	n.mu.Lock()
	n.replies[name] = reply{value: cbor.RawMessage(b), raw: true}
	n.mu.Unlock()
}

// SetFn registers a reply built from the query; it is sent unwrapped.
func (n *Node) SetFn(name string, f func(q any) any) {
	n.mu.Lock()
	n.replies[name] = reply{fn: f, raw: true}
	n.mu.Unlock()
}

// Fail makes the query fail with err.
func (n *Node) Fail(name string, err error) {
	n.mu.Lock()
	n.replies[name] = reply{err: err}
	n.mu.Unlock()
}

// Questions are the names of the queries asked so far, in order.
func (n *Node) Questions() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.asked...)
}

func queryName(q any) string {
	switch x := q.(type) {
	case *lsq.SystemStartQuery:
		return "system-start"
	case *lsq.ChainPointQuery:
		return "chain-point"
	case *lsq.ChainBlockNoQuery:
		return "chain-block-no"
	case *lsq.BlockQuery:
		switch y := x.Query.(type) {
		case *lsq.HardForkQuery:
			switch y.Query.(type) {
			case *lsq.HardForkCurrentEraQuery:
				return "current-era"
			case *lsq.HardForkEraHistoryQuery:
				return "era-history"
			}
		case *lsq.ShelleyQuery:
			return shelleyName(y.Query)
		}
	}
	return fmt.Sprintf("unknown %T", q)
}

func shelleyName(q any) string {
	switch q.(type) {
	case *lsq.ShelleyEpochNoQuery:
		return "epoch-no"
	case *lsq.ShelleyCurrentProtocolParamsQuery:
		return "protocol-params"
	case *lsq.ShelleyUtxoByAddressQuery:
		return "utxo-by-address"
	case *lsq.ShelleyUtxoByTxinQuery:
		return "utxo-by-txin"
	case *lsq.ShelleyFilteredDelegationAndRewardAccountsQuery:
		return "delegations-rewards"
	case *lsq.ShelleyStakeDelegDepositsQuery:
		return "stake-deposits"
	case *lsq.ShelleyFilteredVoteDelegateesQuery:
		return "vote-delegatees"
	case *lsq.ShelleyDebugChainDepStateQuery:
		return "chain-dep-state"
	case *lsq.ShelleyPoolStateQuery:
		return "pool-state"
	case *lsq.ShelleyGenesisConfigQuery:
		return "genesis-config"
	case *lsq.ShelleyDRepStateQuery:
		return "drep-state"
	case *lsq.ShelleyDRepStakeDistrQuery:
		return "drep-stake-distr"
	case *lsq.ShelleyCommitteeMembersStateQuery:
		return "committee-members"
	case *lsq.ShelleyConstitutionQuery:
		return "constitution"
	case *lsq.ShelleyGetProposalsQuery:
		return "proposals"
	case *lsq.ShelleyGetRatifyStateQuery:
		return "ratify-state"
	case *lsq.ShelleySPOStakeDistrQuery:
		return "spo-stake-distr"
	case *lsq.ShelleyStakePoolDefaultVoteQuery:
		return "pool-default-vote"
	}
	return fmt.Sprintf("unknown shelley %T", q)
}

func (n *Node) query(_ lsq.CallbackContext, w lsq.QueryWrapper) (any, error) {
	name := queryName(w.Query)
	n.mu.Lock()
	n.asked = append(n.asked, name)
	r, ok := n.replies[name]
	hold := n.hold
	n.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if !ok {
		return nil, fmt.Errorf("fake node: no reply for %s", name)
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.fn != nil {
		if b, ok := r.fn(w.Query.(*lsq.BlockQuery).Query.(*lsq.ShelleyQuery).Query).(string); ok {
			raw, err := hex.DecodeString(b)
			if err != nil {
				return nil, err
			}
			return cbor.RawMessage(raw), nil
		}
		return nil, fmt.Errorf("fake node: reply function of %s gave no hex", name)
	}
	if r.raw {
		return r.value, nil
	}
	switch name {
	case "system-start", "chain-point", "current-era", "era-history":
		return r.value, nil
	}
	return []any{r.value}, nil
}
