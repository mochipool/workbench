package tailcat

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	tc "github.com/tailscale/tailcat"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ClientConfig configures the signer side (SPO-Xparty-IF-006).
type ClientConfig struct {
	// Address is the coordinator's tailcat address from its Invite, as text
	// in a buffer (a Secret, SPO-Xparty-SEC-001). The client takes ownership.
	Address *secret.Buffer
	// NodeKey is this party's persistent node private key (32 bytes), whose
	// public half the coordinator enrolled. The client takes ownership.
	NodeKey *secret.Buffer
	// Coordinator is who the address leads to. Send accepts only this
	// recipient.
	Coordinator party.Fingerprint
	// Hello builds a fresh Hello for the coordinator: a new message id and a
	// five-minute expiry on every call. The client sends one as the first
	// frame of EVERY connection, so no connection starts with an envelope
	// that is in the coordinator's replay log, and the coordinator learns
	// that this signer is connected (SPO-Xparty-INV-018, INV-021). The wiring
	// supplies it (multisig.Signer.NewHello): this adapter holds no identity
	// key. It is required.
	Hello func(ctx context.Context) ([]byte, error)
	// ExpectServerKey is the coordinator's node key from the same Invite. It
	// is required: NewClient refuses an address whose server key differs, so
	// a mismatched address and invite are caught before any dial, and refuses
	// to be built without one.
	ExpectServerKey *party.NodeKey
	// Port is the coordinator's served port; zero means DefaultPort.
	Port        uint16
	DERPMapURL  string
	DialTimeout time.Duration // zero: 20 s
	Limits      Limits        // idle timeout for writes; zero keeps the default
	Logf        func(format string, args ...any)
}

// Client is the signer side. It implements ports.EnvelopeSender and
// ports.EnvelopeReceiver over one connection to the coordinator, dialled on
// first use and again after it drops. Every connection begins with a fresh
// Hello that the client itself sends (ClientConfig.Hello): the coordinator
// closes a connection whose first frame is anything else.
type Client struct {
	cfg  ClientConfig
	idle time.Duration
	port uint16
	tc   *tc.Client

	inbox chan []byte
	done  chan struct{}
	once  sync.Once

	mu      sync.Mutex
	conn    *peerConn
	started bool // the tailcat client came up (first dial); DrainTCP panics before
}

var (
	_ ports.EnvelopeSender   = (*Client)(nil)
	_ ports.EnvelopeReceiver = (*Client)(nil)
)

// NewClient checks the configuration and builds the tailcat client. It does
// not dial.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Hello == nil {
		return nil, errors.New("tailcat: a Hello builder is required: every connection starts with a fresh Hello")
	}
	if cfg.ExpectServerKey == nil || *cfg.ExpectServerKey == (party.NodeKey{}) {
		return nil, errors.New("tailcat: the coordinator's node key from the invitation is required")
	}
	var addr tc.Addr
	if err := cfg.Address.Use(func(b []byte) error { addr = tc.Addr(b); return nil }); err != nil {
		return nil, err
	}
	info, err := tc.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("tailcat: bad address: %w", err)
	}
	if party.NodeKey(info.ServerPublic.Raw32()) != *cfg.ExpectServerKey {
		return nil, errors.New("tailcat: the address leads to a different node key than the invite named")
	}
	priv, err := nodePrivate(cfg.NodeKey)
	if err != nil {
		return nil, err
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 20 * time.Second
	}
	idle := DefaultLimits.Idle
	if cfg.Limits.Idle > 0 {
		idle = min(idle, cfg.Limits.Idle)
	}
	port := cfg.Port
	if port == 0 {
		port = DefaultPort
	}
	return &Client{cfg: cfg, idle: idle, port: port, inbox: make(chan []byte, MaxFramesPerConn), done: make(chan struct{}),
		tc: &tc.Client{Server: addr, Key: priv, Logf: logf, DERPMapURL: cfg.DERPMapURL}}, nil
}

// Transport is the client as the sending side of multisig: its kind is a
// network.
func (c *Client) Transport() ports.Transport { return ports.NetworkTransport(c) }

// PublicKey is the node public key the coordinator must have enrolled.
func (c *Client) PublicKey() party.NodeKey { return party.NodeKey(c.tc.PublicKey().Raw32()) }

// Connect dials the coordinator if there is no live connection. Send does
// this itself.
func (c *Client) Connect(ctx context.Context) error {
	_, err := c.connection(ctx)
	return err
}

func (c *Client) connection(ctx context.Context) (*peerConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return nil, ports.ErrClosed
	default:
	}
	if c.conn != nil {
		return c.conn, nil
	}
	dctx, cancel := context.WithTimeout(ctx, c.cfg.DialTimeout)
	defer cancel()
	c.started = true
	nc, err := c.tc.DialTCPPort(dctx, c.port)
	if err != nil {
		return nil, fmt.Errorf("tailcat: dial: %w", err)
	}
	pc := &peerConn{c: nc}
	// The first frame of every connection is a fresh Hello. A caller cannot
	// skip it and cannot send anything before it: the connection is not handed
	// out until it is written.
	hello, err := c.cfg.Hello(dctx)
	if err == nil && (len(hello) == 0 || len(hello) > MaxFrame) {
		err = ports.ErrEnvelopeSize
	}
	if err == nil {
		err = writeWithContext(dctx, pc, c.idle, hello)
	}
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("tailcat: hello: %w", err)
	}
	c.conn = pc
	go c.read(pc)
	return pc, nil
}

func (c *Client) drop(pc *peerConn) {
	pc.c.Close()
	c.mu.Lock()
	if c.conn == pc {
		c.conn = nil
	}
	c.mu.Unlock()
}

// read passes frames from the coordinator to Receive until the connection
// ends, which drops it so the next Send dials again.
func (c *Client) read(pc *peerConn) {
	defer c.drop(pc)
	for n := 0; n < MaxFramesPerConn; n++ {
		env, err := ReadFrame(pc.c)
		if err != nil {
			return
		}
		select {
		case c.inbox <- env:
		case <-c.done:
			return
		}
	}
}

// Send writes one frame to the coordinator, dialling first if needed. A
// failed write drops the connection, so the next Send starts afresh.
func (c *Client) Send(ctx context.Context, to party.Fingerprint, envelope []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(envelope) == 0 || len(envelope) > MaxFrame {
		return ports.ErrEnvelopeSize
	}
	if to != c.cfg.Coordinator {
		return ports.ErrNoRoute
	}
	pc, err := c.connection(ctx)
	if err != nil {
		return err
	}
	if err := writeWithContext(ctx, pc, c.idle, envelope); err != nil {
		c.drop(pc)
		return err
	}
	return nil
}

// Receive returns the next frame from the coordinator, as a network delivery.
func (c *Client) Receive(ctx context.Context) (ports.Received, error) {
	select {
	case env := <-c.inbox:
		return ports.NetworkReceived(env), nil
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	case <-c.done:
		return ports.Received{}, ports.ErrClosed
	}
}

// Disconnect drops the connection to the coordinator. The next Send or Connect
// dials again, and the new connection opens with a fresh Hello. A caller does
// this when it knows the connection is no good; read does it itself when the
// coordinator closes it.
func (c *Client) Disconnect() {
	c.mu.Lock()
	pc := c.conn
	c.conn = nil
	c.mu.Unlock()
	if pc != nil {
		pc.c.Close()
	}
}

// Close drops the connection, drains tailcat's TCP stack (bounded) and shuts
// it down.
func (c *Client) Close() error {
	var err error
	c.once.Do(func() {
		close(c.done)
		c.mu.Lock()
		pc, started := c.conn, c.started
		c.conn = nil
		c.mu.Unlock()
		if pc != nil {
			pc.c.Close()
		}
		if started { // tailcat's DrainTCP dereferences state a first dial creates
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			c.tc.DrainTCP(ctx)
			cancel()
		}
		err = c.tc.Close()
		c.cfg.Address.Destroy()
		c.cfg.NodeKey.Destroy()
	})
	return err
}
