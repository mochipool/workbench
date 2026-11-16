// Package n2c is the node-to-client chain adapter: the "online" provider of
// ADR 0006 without cardano-cli. It speaks the Ouroboros node-to-client
// mini-protocols (local-state-query, local-tx-submission, local-tx-monitor)
// through gouroboros to a cardano-node UNIX socket, or to that socket
// forwarded over TCP.
//
// Every read returns what ADR 0006 calls a value, "none" or "unknown": a failed
// query, a timeout or a closed connection is Unknown, never None. Only a
// positive answer of the node that the thing does not exist is None.
//
// Node-to-client has no authentication and no encryption. A TCP address that
// is not loopback is accepted, and WarnPlainTCP gives the text the wiring
// prints; the operator is expected to tunnel the connection (SSH, a VPN).
package n2c

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	ouroboros "github.com/blinklabs-io/gouroboros"
	"github.com/blinklabs-io/gouroboros/protocol"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	"github.com/blinklabs-io/gouroboros/protocol/localtxmonitor"
	"github.com/blinklabs-io/gouroboros/protocol/localtxsubmission"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// DefaultTimeout bounds one operation (one port call, which may be several
// queries against one acquired ledger state).
const DefaultTimeout = 30 * time.Second

// DefaultSyncTolerance is how far behind the wall clock the node's tip may be
// for Synced to say true.
const DefaultSyncTolerance = 2 * time.Minute

// Errors of the adapter. Callers test them with errors.Is.
var (
	// ErrClosed: the client was closed, or its connection is gone. Every
	// later call fails with it; reads turn it into Unknown.
	ErrClosed = errors.New("n2c: the node connection is closed")
	// ErrTimeout: an operation took longer than Config.Timeout. The
	// connection is closed, because the protocol state is then unknown.
	ErrTimeout = errors.New("n2c: the node did not answer in time")
	// ErrUnsupportedEra: the node's current era is one this adapter does not
	// decode the protocol parameters of.
	ErrUnsupportedEra = errors.New("n2c: unsupported ledger era")
)

// WarnPlainTCP is printed by the wiring when the address is a TCP address that
// is not loopback. Node-to-client carries no authentication and no encryption:
// anyone on the path can read the queries and submit transactions through the
// connection.
const WarnPlainTCP = "warning: the node address is plain TCP to a non-loopback host. " +
	"Node-to-client has no authentication and no encryption; use an SSH or VPN tunnel and give a loopback address."

// Config builds a Client.
type Config struct {
	// Address is the node's UNIX socket path ("/run/cardano/node.socket",
	// "unix:/path" or "unix:///path") or "tcp://host:port" for a forwarded
	// socket.
	Address string
	// NetworkMagic is the magic of the workspace network (mainnet 764824073,
	// preprod 1, preview 2). It must be non-zero.
	NetworkMagic uint32
	// Network names the network for Source(), for example "preview". Optional.
	Network string
	// Timeout bounds each operation; zero means DefaultTimeout.
	Timeout time.Duration
	// Clock is the wall clock of the sync check; nil means the system time.
	Clock ports.Clock
	// SyncTolerance is how far the tip may lag; zero means DefaultSyncTolerance.
	SyncTolerance time.Duration
	// DialContext replaces the dialer; nil dials Address. Tests use it to put a
	// fake node behind the client.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

// Client is a connection to one node. All methods are safe for concurrent
// use; they run one at a time, because the protocols are sequential. One
// Client is reused for a whole command and closed once.
type Client struct {
	cfg     Config
	timeout time.Duration
	source  chain.Source
	clock   ports.Clock

	conn *ouroboros.Connection
	// lazy is true for a client made by DialLazy: it connects on the first
	// operation (under mu), and a failed connection is remembered, so a command
	// that reads several things waits for an unreachable node once.
	lazy    bool
	network string
	addr    string
	dialErr error

	mu     sync.Mutex // serialises operations
	stateM sync.Mutex // guards closed and why
	closed bool
	why    error
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// IsPlainTCP reports whether address is a TCP address that is not loopback.
// The wiring prints WarnPlainTCP for it.
func IsPlainTCP(address string) bool {
	network, host, err := parseAddress(address)
	if err != nil || network != "tcp" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return false
	}
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip == nil || !ip.IsLoopback()
}

// parseAddress splits Address into a network and the dial address.
func parseAddress(a string) (network, addr string, err error) {
	a = strings.TrimSpace(a)
	switch {
	case a == "":
		return "", "", errors.New("n2c: the node address is empty")
	case strings.HasPrefix(a, "tcp://"):
		rest := strings.TrimPrefix(a, "tcp://")
		if _, _, err := net.SplitHostPort(rest); err != nil {
			return "", "", fmt.Errorf("n2c: tcp address %q: want tcp://host:port", a)
		}
		return "tcp", rest, nil
	case strings.HasPrefix(a, "unix://"):
		return "unix", strings.TrimPrefix(a, "unix://"), nil
	case strings.HasPrefix(a, "unix:"):
		return "unix", strings.TrimPrefix(a, "unix:"), nil
	case strings.Contains(a, "://"):
		return "", "", fmt.Errorf("n2c: unsupported address scheme in %q (use a socket path or tcp://host:port)", a)
	}
	return "unix", a, nil
}

// Dial connects to the node and runs the handshake with the configured
// network magic. A node on another network refuses the handshake, which is
// returned as an error. The returned Client must be closed.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// DialLazy returns a Client that has not connected: it validates the
// configuration and connects when the first operation needs the node, so a
// command that makes no chain read never touches the socket. The connection is
// made once; if it fails, every operation returns that error (as Unknown for a
// reader) without trying again. The returned Client must be closed (Close is
// harmless on one that never connected).
func DialLazy(cfg Config) (*Client, error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	c.lazy = true
	return c, nil
}

func newClient(cfg Config) (*Client, error) {
	if cfg.NetworkMagic == 0 {
		return nil, errors.New("n2c: the network magic is required")
	}
	network, addr, err := parseAddress(cfg.Address)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	clock := cfg.Clock
	if clock == nil {
		clock = wallClock{}
	}
	c := &Client{cfg: cfg, timeout: timeout, clock: clock, network: network, addr: addr}
	name := "node socket"
	if cfg.Network != "" {
		name += " " + cfg.Network
	}
	c.source = chain.Source(name)
	return c, nil
}

// connect dials and runs the handshake. It is called with no lock held by Dial
// and with c.mu held by run.
func (c *Client) connect(ctx context.Context) error {
	cfg, timeout := c.cfg, c.timeout
	// The library's own per-message timeouts are a backstop one second behind
	// the operation timer of run, so a slow node is reported as ErrTimeout by
	// run and not, depending on which timer fires first, as a closed connection.
	libTimeout := timeout + time.Second
	dial := cfg.DialContext
	if dial == nil {
		d := net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := dial(dctx, c.network, c.addr)
	if err != nil {
		return fmt.Errorf("n2c: cannot reach the node at %s: %w", cfg.Address, err)
	}

	errCh := make(chan error, 16)
	type result struct {
		conn *ouroboros.Connection
		err  error
	}
	res := make(chan result, 1)
	go func() {
		conn, err := ouroboros.NewConnection(
			ouroboros.WithConnection(raw),
			ouroboros.WithNetworkMagic(cfg.NetworkMagic),
			ouroboros.WithNodeToNode(false),
			ouroboros.WithKeepAlive(false),
			ouroboros.WithErrorChan(errCh),
			ouroboros.WithHandshakeTimeout(timeout),
			ouroboros.WithLocalStateQueryConfig(localstatequery.NewConfig(
				localstatequery.WithAcquireTimeout(libTimeout),
				localstatequery.WithQueryTimeout(libTimeout),
			)),
			ouroboros.WithLocalTxSubmissionConfig(localtxsubmission.NewConfig(
				localtxsubmission.WithTimeout(libTimeout),
			)),
			ouroboros.WithLocalTxMonitorConfig(localtxmonitor.NewConfig(
				localtxmonitor.WithAcquireTimeout(libTimeout),
				localtxmonitor.WithQueryTimeout(libTimeout),
			)),
		)
		res <- result{conn, err}
	}()
	select {
	case r := <-res:
		if r.err != nil {
			_ = raw.Close()
			return fmt.Errorf("n2c: handshake with the node failed (is the network magic %d right?): %w", cfg.NetworkMagic, r.err)
		}
		c.conn = r.conn
	case <-dctx.Done():
		_ = raw.Close()
		return fmt.Errorf("n2c: handshake with the node at %s did not finish in %s: %w", cfg.Address, timeout, dctx.Err())
	}
	// Mark the client unusable when the connection reports an error or is
	// closed (the channel is closed on shutdown).
	go func() {
		for err := range errCh {
			c.fail(fmt.Errorf("%w: %v", ErrClosed, err))
		}
		c.fail(ErrClosed)
	}()
	return nil
}

// Source implements ports.ChainSource.
func (c *Client) Source() chain.Source { return c.source }

// Close ends the session and closes the connection. It is safe to call more
// than once.
func (c *Client) Close() error {
	c.fail(ErrClosed)
	c.mu.Lock() // a lazy connect in progress finishes first
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (c *Client) fail(err error) {
	c.stateM.Lock()
	defer c.stateM.Unlock()
	if !c.closed {
		c.closed, c.why = true, err
	}
}

func (c *Client) usable() error {
	c.stateM.Lock()
	defer c.stateM.Unlock()
	if c.closed {
		return c.why
	}
	return nil
}

// do runs one operation against the state-query client, with the per-operation
// timeout. The ledger state is acquired by the first query and released when
// the operation ends, so every operation sees one consistent state and the next
// one sees a fresh one. A timeout closes the connection: the protocol is then
// in an unknown state.
func (c *Client) do(ctx context.Context, op string, fn func(q *localstatequery.Client) error) error {
	return c.run(ctx, op, func() error {
		q := c.conn.LocalStateQuery().Client
		err := fn(q)
		if rerr := q.Release(); rerr != nil && err == nil {
			err = rerr
		}
		return err
	})
}

// run executes fn under the connection lock with the per-operation timeout.
func (c *Client) run(ctx context.Context, op string, fn func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.lazy && c.conn == nil {
		if c.dialErr == nil {
			c.dialErr = c.connect(ctx)
			if c.dialErr != nil && ctx.Err() != nil {
				err := c.dialErr
				c.dialErr = nil // the caller cancelled; that says nothing about the node
				return err
			}
		}
		if c.dialErr != nil {
			return c.dialErr
		}
	}
	octx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("n2c %s: %v", op, r)
			}
		}()
		done <- fn()
	}()
	select {
	case err := <-done:
		if err != nil {
			if errors.Is(err, protocol.ErrProtocolShuttingDown) {
				c.fail(ErrClosed)
			}
			if cerr := c.usable(); cerr != nil {
				return cerr
			}
			return fmt.Errorf("n2c %s: %w", op, err)
		}
		return nil
	case <-octx.Done():
		c.fail(ErrTimeout)
		go func() { _ = c.conn.Close() }()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w (%s, %s)", ErrTimeout, op, c.timeout)
	}
}

// unknown makes the Unknown reading of a failed operation, and passes a
// cancellation of the caller on as the error.
func unknown[T any](ctx context.Context, err error) (chain.Reading[T], error) {
	if ctx.Err() != nil {
		return chain.Unknown[T]("cancelled"), ctx.Err()
	}
	return chain.Unknown[T](err.Error()), nil
}
