package relay_test

import (
	"context"
	"crypto/ed25519"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The fuzz rig's limits: every timer is a few milliseconds, so that an
// iteration that leaves the session waiting for more input ends in tens of
// milliseconds and not in seconds, and the number of bytes the relay may send
// is small, so that the bound the target asserts is the relay's own.
const (
	fuzzTimer     = 20 * time.Millisecond
	fuzzHandshake = 500 * time.Millisecond // the honest login of the authed target must not race its timer
	fuzzLifetime  = 800 * time.Millisecond
	fuzzMaxSent   = 32 << 10               // the relay's MaxBytesSent for a fuzzed connection
	fuzzErrorSlop = 16                     // the one Error frame a closing session may still send
	fuzzUnauth    = 150 * time.Millisecond // the whole login of the pre-login target, a signed Auth seed included
	fuzzMaxInput  = 1024                   // an input above it is skipped (a signed Auth is about 500 bytes)
)

// fuzzLogins counts the logins that reached AuthOK in this process: the seeds of
// the pre-login target include an Auth that is signed for the deterministic
// nonce, relay key, relay time and node key of the first connection of an
// iteration, so that its fuzzed continuations reach the states after the login.
var fuzzLogins atomic.Int64

// signedAuthSeed is the Auth that peer p signs for the first connection of an
// iteration of the pre-login target: the first nonce of countRand, the node key of
// "relay" on a fakenet and the relay's clock at startTime.
func signedAuthSeed(f *testing.F, relayKey party.NodeKey, p *peer) mailbox.AuthV2 {
	var nonce [mailbox.NonceSize]byte
	(&countRand{}).Read(nonce[:])
	st, err := relaybind.ParseStatement(p.stmt.Sign1)
	if err != nil {
		f.Fatal(err)
	}
	sh, err := mailbox.SendersHash(p.senders)
	if err != nil {
		f.Fatal(err)
	}
	b, err := mailbox.AuthBytesV2(mailbox.AuthV2Params{
		RelayKey: relayKey, ClientNodeKey: p.node.Key, Nonce: nonce, RelayTime: startTime,
		Fingerprint: p.fp, BindingHash: st.FullHash(), SendersHash: sh,
	})
	if err != nil {
		f.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(p.dev.priv, b))
	return mailbox.AuthV2{Fingerprint: p.fp, Signature: sig, Keys: p.dev.keys(), Sign1: p.stmt.Sign1, Key: p.stmt.COSEKey, Senders: p.senders}
}

// fuzzSession runs one session against the arbitrary bytes in. With authed the
// bytes follow an honest login (a real binding, a real signature); without, they
// are the client's first frames: the Revokes and the Auth of version 2 included.
// The relay must not panic, must send at most its own egress bound, must end the
// session, Serve must return, and the store must stay within its bounds. The
// store is emptied after each input (and found empty at the start of the next),
// so that one input cannot fill the quota for the ones after it and a counter
// that leaks shows. The registry is new for each input, with both devices bound.
func fuzzSession(f *testing.F, authed bool) {
	clock := relayporttest.NewManualClock(startTime)
	st, _, err := mailboxstore.Open(f.TempDir(), clock)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { st.Close() })

	// small seeds: frames a session sees
	n0 := fakenet.New()
	a0, b0 := newPeer(n0, "alice", 1), newPeer(n0, "bob", 2)
	a0.senders = sortedKeys(b0.wkey())
	b0.senders = sortedKeys(a0.wkey())
	env := envelope(40, 3)
	put, _ := mailbox.NewPutV2Of(1, b0.wkey(), b0.fp, env)
	auth := mailbox.AuthV2{Fingerprint: a0.fp, Signature: [64]byte{1}, Keys: a0.dev.keys(), Sign1: a0.stmt.Sign1, Key: a0.stmt.COSEKey, Senders: a0.senders}
	good := signedAuthSeed(f, n0.Node("relay").Key, a0)
	var seeds [][]byte
	if !authed {
		// a login that succeeds, alone and followed by each kind of request
		seeds = append(seeds,
			frame(f, good),
			append(frame(f, good), frame(f, mailbox.Fetch{RequestID: 1, MaxItems: 16})...),
			append(append(frame(f, good), frame(f, put)...), rawFrame(f, env)...),
			append(frame(f, good), frame(f, mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}})...),
			append(frame(f, deviceRevoke(f, b0, 1, startTime)), frame(f, good)...),
		)
	}
	f.Cleanup(func() { f.Logf("authed=%v: %d logins reached AuthOK while the seeds ran", authed, fuzzLogins.Load()) })
	seeds = append(seeds, [][]byte{
		nil,
		{0, 0, 0, 0},
		{0xff, 0xff, 0xff, 0xff},
		frame(f, auth),
		frame(f, deviceRevoke(f, a0, 1, startTime)),
		frame(f, walletRevoke(a0.wallet, 1, a0.fp, false, startTime)),
		frame(f, walletRevoke(a0.wallet, 2, a0.fp, true, startTime)),
		append(frame(f, deviceRevoke(f, b0, 1, startTime)), frame(f, auth)...),
		frame(f, mailbox.Fetch{RequestID: 1, MaxItems: 16}),
		frame(f, mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 20}),
		frame(f, mailbox.Ack{RequestID: 2, Mids: []mailbox.Hash{{1}}}),
		append(frame(f, put), rawFrame(f, env)...),
		append(append(frame(f, put), rawFrame(f, env)...), frame(f, mailbox.Fetch{RequestID: 2, MaxItems: 16})...),
		append(frame(f, put), rawFrame(f, env[:20])...),
		frame(f, mailbox.PutResult{RequestID: 1}),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}...)
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		// Every seed is small and so is every input: the engine minimises a new
		// interesting input for up to a minute (-fuzzminimizetime), and during
		// that time it counts no execs, which shows as a throughput of 0 for
		// seconds. A large input takes the longest to shrink.
		if len(in) > fuzzMaxInput {
			t.Skip()
		}
		fakenet.CheckLeaks(t)
		n := fakenet.New()
		relayNode := n.Node("relay")
		a, b := newPeer(n, "alice", 1), newPeer(n, "bob", 2)
		a.senders = sortedKeys(b.wkey())
		b.senders = sortedKeys(a.wkey())
		lim := relay.DefaultLimits()
		lim.UnauthBudget = fuzzUnauth
		if authed {
			lim.UnauthBudget = fuzzHandshake
		}
		lim.IdleTimeout = fuzzTimer
		lim.BodyTimeout = fuzzTimer
		lim.WriteTimeout = fuzzTimer
		lim.ConnLifetime = fuzzLifetime
		lim.MaxBytesSent = fuzzMaxSent
		vl, err := lim.Validated()
		if err != nil {
			t.Fatal(err)
		}
		vq, err := mailbox.DefaultOpenQuota().Validated()
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []*peer{a, b} { // the store starts empty
			if u, err := st.Usage(context.Background(), p.fp, a.fp); err != nil || u.MailboxEntries != 0 || u.GlobalBytes != 0 {
				t.Fatalf("the store was not empty at the start: %+v, %v", u, err)
			}
		}
		guard := relay.NewGuard(st)
		rc := relayregistry.DefaultConfig()
		rc.Evictable = guard.Evictable
		reg, err := relayporttest.NewMemRegistry(rc, clock)
		if err != nil {
			t.Fatal(err)
		}
		defer reg.Close()
		for _, p := range []*peer{a, b} { // both devices are bound, each listing the other
			pr, err := p.present(startTime)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reg.Register(context.Background(), pr); err != nil {
				t.Fatal(err)
			}
			if err := reg.SetExpectedSenders(context.Background(), p.fp, p.senders); err != nil {
				t.Fatal(err)
			}
		}
		srv, err := relay.New(relay.Config{
			Writer: st, Reader: st, Acker: st, Retractor: st, MailboxRevoker: st, Usage: st,
			Registry: reg, Guard: guard, Clock: clock,
			Rand: &countRand{}, RelayKey: relayNode.Key, Quota: vq, Limits: vl, Policy: rc.Policy,
			Events: func(e relay.Event) {
				if e.Kind == relay.EventAuthOK {
					fuzzLogins.Add(1)
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := n.Listen(relayNode, []party.NodeKey{a.node.Key, b.node.Key})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ctx, ln) }()
		defer func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve returned %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("Serve did not return")
			}
			ln.Close()
			for _, p := range []*peer{a, b} { // reset the store for the next input
				if _, err := st.RemoveMailbox(context.Background(), p.fp); err != nil {
					t.Error(err)
				}
			}
		}()

		s, _, err := n.Dialer(a.node, relayNode).Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c := &conn{t: t, s: s, p: a, relayKey: relayNode.Key, stage: mailbox.StageV2PreAuth}
		defer s.Close()
		if authed {
			c.handshake()
		}
		_ = c.tryWrite(in)
		// read until the relay closes or goes quiet: the session ends by its own
		// timers within a few of them
		var got int
		buf := make([]byte, 4096)
		for end := time.Now().Add(20 * fuzzTimer); time.Now().Before(end); {
			s.SetReadDeadline(time.Now().Add(5 * fuzzTimer))
			k, err := s.Read(buf)
			got += k
			if err != nil {
				break
			}
			if got > fuzzMaxSent+fuzzErrorSlop {
				t.Fatalf("the relay sent %d bytes to %d bytes of input; its bound is %d", got, len(in), fuzzMaxSent)
			}
		}
		for _, p := range []*peer{a, b} {
			for _, q := range []*peer{a, b} {
				u, err := st.Usage(context.Background(), p.fp, q.fp)
				if err != nil {
					t.Fatal(err)
				}
				if u.MailboxEntries > mailbox.MaxMailboxEntries || u.MailboxBytes > mailbox.MaxMailboxBytes || u.PairEntries > mailbox.MaxPairEntries {
					t.Fatalf("usage past a bound: %+v", u)
				}
			}
		}
	})
}

// FuzzSessionBeforeAuth: arbitrary bytes as the client's first frames (the
// Revokes and the Auth of version 2 included).
//
// spec: SPO-Xmailbox-INV-015, SPO-Xmailbox-OUT-082
func FuzzSessionBeforeAuth(f *testing.F) { fuzzSession(f, false) }

// FuzzSessionAfterAuth: arbitrary bytes after an honest login.
//
// spec: SPO-Xmailbox-INV-015, SPO-Xmailbox-OUT-082
func FuzzSessionAfterAuth(f *testing.F) { fuzzSession(f, true) }
