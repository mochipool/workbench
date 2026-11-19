package relay_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// recvChallenge reads the Challenge a relay opens a connection with and moves the
// client's stage as a version 2 client does. It fails unless the relay offers
// version 2 and nothing else.
func recvChallenge(t *testing.T, c *conn) mailbox.Challenge {
	t.Helper()
	return c.challenge()
}

// The Challenge carries what the ADR says: the versions the relay speaks (2 and
// nothing else), a 32-byte nonce, the relay's own node key and the relay's clock.
//
// spec: SPO-Xmailbox-OUT-025, SPO-Xmailbox-OUT-082
func TestChallengeCarriesTheRelaysFacts(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	if ch.Min != 2 || ch.Max != 2 {
		t.Errorf("versions [%d, %d], want [2, 2]", ch.Min, ch.Max)
	}
	if ch.RelayKey != r.relay.Key {
		t.Errorf("relay key %x, want the relay's own", ch.RelayKey)
	}
	if ch.RelayTime != r.clock.Now().Unix() {
		t.Errorf("relay time %d, want %d", ch.RelayTime, r.clock.Now().Unix())
	}
	if ch.Nonce == ([32]byte{}) {
		t.Error("an all-zero nonce")
	}
	if n := r.rnd.n.Load(); n != 1 {
		t.Errorf("the nonce took %d reads of the random source, want 1", n)
	}
}

// Every connection gets a fresh nonce.
//
// spec: SPO-Xmailbox-OUT-025, SPO-Xmailbox-SEC-020
func TestEveryConnectionGetsAFreshNonce(t *testing.T) {
	r := newRig(t)
	c1, c2 := r.dial(r.a), r.dial(r.b)
	n1, n2 := recvChallenge(t, c1).Nonce, recvChallenge(t, c2).Nonce
	if n1 == n2 {
		t.Fatal("two connections got one nonce")
	}
}

// A good handshake ends in AuthOK with the limits that apply and the end of the
// device's binding. (The queue bound of open mode keeps a full envelope of room
// beyond the stranger allowance, so the byte bound here is 2 MiB, not 1 MiB.)
//
// spec: SPO-Xmailbox-OUT-025, SPO-Xmailbox-OUT-082
func TestAuthOKCarriesTheLimits(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxEnvelope = 4096; l.RetentionSeconds = 3600 }),
		withQuota(func(q *mailbox.OpenQuota) {
			q.Quota.MailboxEntries = 10
			q.Quota.MailboxBytes = 2 << 20
			q.StrangerEntries = 4
		}))
	_, ok := r.login(r.a)
	want := mailbox.AuthOKV2{MaxEnvelope: 4096, MaxEntries: 10, MaxBytes: 2 << 20, RetentionSeconds: 3600, Until: defaultUntil}
	if ok != want {
		t.Fatalf("AuthOK %+v, want %+v", ok, want)
	}
}

// A connection refused at accept (here: a second live connection of one tunnel
// node key under a bound of one) gets one bounded reply and nothing else: no nonce
// is drawn and no challenge is made. (Version 1 closed the connection of a node
// key that was not on the access list in this way; in version 2 the tunnel admits
// or refuses a node key, and what the relay refuses at accept is a bound.)
//
// spec: SPO-Xmailbox-PRE-021, SPO-Xmailbox-OUT-034
func TestRefusedConnectionIsClosedBeforeAnyChallenge(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConnsPerKey = 1 }))
	_, _ = r.login(r.a)
	draws := r.rnd.n.Load()
	c := r.dial(r.a)
	if code := c.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit (%d)", code, mailbox.CodeLimit)
	}
	c.expectClosed()
	if n := r.rnd.n.Load(); n != draws {
		t.Fatalf("the random source was read %d times for a refused connection", n-draws)
	}
	if got := r.ev.of(relay.EventRejected); len(got) != 1 || got[0].Reason != relay.ReasonLimit || got[0].Node != r.a.node.Key {
		t.Fatalf("events %+v", got)
	}
}

// A device whose binding was revoked in the registry is refused at login with the
// binding code, and the revoked statement is not served again. (Version 1: a node
// key that the tunnel still admitted after the operator removed it from the access
// list.)
//
// spec: SPO-Xmailbox-OUT-082, SPO-Xmailbox-PRE-053
func TestRevokedDeviceIsRefusedAtLogin(t *testing.T) {
	r := newRig(t)
	if _, err := r.reg.Revoke(context.Background(), r.a.wallet.WalletRevoke(t, r.a.fp, startTime, startTime)); err != nil {
		t.Fatal(err)
	}
	c := r.dial(r.a)
	if code := c.loginFails(authOpt{}); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	if got := r.ev.of(relay.EventAuthFail); len(got) != 1 || got[0].Reason != relay.ReasonBinding {
		t.Fatalf("events %+v", got)
	}
}

// A device is not tied to a tunnel node key (version 1 found the party by it): its
// keys from another admitted node log in when the signature names that node, and
// are refused, with the auth code, when the signature names the node the device
// does not connect from.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-SEC-012, SPO-Xmailbox-OUT-082
func TestDeviceMayComeFromAnyAdmittedNodeButMustSignForIt(t *testing.T) {
	r := newRig(t)
	// alice's keys over bob's tunnel node, signed for bob's node: honest
	c := r.dialNode(r.a, r.b.node, zeroFault)
	c.handshakeWith(authOpt{clientNode: nodeKeyPtr(r.b.node.Key)})
	// the same keys over bob's node, signed for alice's own node: every signed
	// field is consistent except the tunnel binding
	c2 := r.dialNode(r.a, r.b.node, zeroFault)
	if code := c2.loginFails(authOpt{clientNode: nodeKeyPtr(r.a.node.Key)}); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	got := r.ev.of(relay.EventAuthFail)
	if len(got) != 1 || got[0].Reason != relay.ReasonSignature {
		t.Fatalf("events %+v", got)
	}
}

// A device whose binding is revoked between the Challenge and its Auth is refused
// with the binding code, whatever it signs, and no auth_ok is logged.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-SEC-024, SPO-Xmailbox-PRE-053
func TestDeviceRevokedBetweenChallengeAndAuthIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	if _, err := r.reg.Revoke(context.Background(), r.a.wallet.WalletRevoke(t, r.a.fp, startTime, startTime)); err != nil {
		t.Fatal(err)
	}
	c.send(c.authFrame(ch, authOpt{}))
	if code := c.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	c.expectClosed()
	if len(r.ev.of(relay.EventAuthOK)) != 0 {
		t.Fatal("an auth_ok for a revoked device")
	}
}

// A device with no binding of its own that claims the fingerprint of a bound device
// and presents that device's binding is refused: the fingerprint is that of the
// presented keys and nothing else.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-PRE-053
func TestUnknownDeviceClaimingABoundFingerprintIsRefused(t *testing.T) {
	r := newRig(t)
	mallory := newDevKeys("mallory")
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	c.send(c.authFrame(ch, authOpt{present: &mallory, sign: &mallory, claimFP: &r.a.fp, signedFP: &r.a.fp}))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c.expectClosed()
	if got := r.ev.of(relay.EventAuthFail); len(got) != 1 || got[0].Reason != relay.ReasonFingerprint {
		t.Fatalf("events %+v", got)
	}
}

// A signature by another device's key is refused: alice's node and fingerprint,
// bob's key.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-SEC-002
func TestSignatureByAnotherKeyIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	c.send(c.authFrame(ch, authOpt{sign: &r.b.dev}))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c.expectClosed()
	if got := r.ev.of(relay.EventAuthFail); len(got) != 1 || got[0].Reason != relay.ReasonSignature {
		t.Fatalf("events %+v", got)
	}
}

// A captured Auth frame replayed on a second connection fails: the second
// connection has its own nonce.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-OUT-025
func TestChallengeReplayOnASecondConnectionFails(t *testing.T) {
	r := newRig(t)
	c1 := r.dial(r.a)
	ch1 := recvChallenge(t, c1)
	captured := frame(t, c1.authFrame(ch1, authOpt{}))
	c1.write(captured)
	if _, ok := c1.recv().(mailbox.AuthOKV2); !ok {
		t.Fatal("the honest handshake failed")
	}
	c2 := r.dial(r.a)
	recvChallenge(t, c2)
	c2.write(captured) // the same bytes, a new connection
	if code := c2.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c2.expectClosed()
}

// A signature over another relay's key is useless here: the relay takes its
// own key, not the client's.
//
// spec: SPO-Xmailbox-SEC-012
func TestSignatureForAnotherRelayKeyIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	c.send(c.authFrame(ch, authOpt{relayKey: nodeKeyPtr(party.NodeKey{9})}))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
}

// A signature that names another client node key than the tunnel's is refused.
//
// spec: SPO-Xmailbox-SEC-012
func TestSignatureNamingAnotherClientNodeIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	c.send(c.authFrame(ch, authOpt{clientNode: nodeKeyPtr(party.NodeKey{7})}))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
}

// One failed auth closes the connection: there is no second try.
//
// spec: SPO-Xmailbox-PRE-020, SPO-Xmailbox-PRE-053
func TestOneFailedAuthClosesTheConnection(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	c.send(c.authFrame(ch, authOpt{edit: func(a *mailbox.AuthV2) { a.Signature = [64]byte{1} }}))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c.expectClosed()
	// a second, honest Auth on the same stream reaches nobody
	_ = c.tryWrite(frame(t, c.authFrame(ch, authOpt{})))
	c.expectClosed()
	if len(r.ev.of(relay.EventAuthOK)) != 0 {
		t.Fatal("an auth_ok after a failed auth")
	}
}

// No frame but Auth (and the revokes of version 2) is accepted before
// authentication, and nothing is stored or read for it.
//
// spec: SPO-Xmailbox-PRE-020, SPO-Xmailbox-OUT-082
func TestFrameBeforeAuthIsRefused(t *testing.T) {
	env := envelope(100, 1)
	put, err := mailbox.NewPutV2Of(1, mailbox.WalletKey{1}, party.Fingerprint{1}, env)
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]mailbox.Message{
		"put":   put,
		"fetch": mailbox.Fetch{RequestID: 1, MaxItems: 1},
		"ack":   mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			c := r.dial(r.a)
			recvChallenge(t, c)
			c.send(m)
			if code := c.expectError(); code != mailbox.CodeProtocol {
				t.Fatalf("code %d, want protocol", code)
			}
			c.expectClosed()
			if n := len(r.store.putCalls()); n != 0 {
				t.Fatalf("%d store puts before auth", n)
			}
		})
	}
}

// A frame only the relay sends is refused from the client, before and after
// authentication (the decoder takes the direction).
//
// spec: SPO-Xmailbox-PRE-020, SPO-Xmailbox-OUT-018
func TestRelayOnlyFramesFromAClientAreRefused(t *testing.T) {
	relayOnly := []mailbox.Message{
		mailbox.Challenge{Min: 2, Max: 2, RelayKey: party.NodeKey{1}},
		mailbox.AuthOKV2{MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: 1},
		mailbox.PutResult{RequestID: 1},
		mailbox.Items{RequestID: 1},
		mailbox.AckResult{RequestID: 1},
		mailbox.RevokeResult{RequestID: 1},
		mailbox.Error{Code: mailbox.CodeAuth},
	}
	for _, m := range relayOnly {
		for _, authed := range []bool{false, true} {
			r := newRig(t)
			var c *conn
			if authed {
				c, _ = r.login(r.a)
			} else {
				c = r.dial(r.a)
				recvChallenge(t, c)
			}
			c.send(m)
			if code := c.expectError(); code != mailbox.CodeProtocol {
				t.Fatalf("type %d (authed %v): code %d, want protocol", m.Type(), authed, code)
			}
			c.expectClosed()
			r.stop()
		}
	}
}

// A version the relay does not speak is the version error: a version 1 Auth.
//
// spec: SPO-Xmailbox-OUT-025, SPO-Xmailbox-OUT-082
func TestUnspokenVersionIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	recvChallenge(t, c)
	c.write(retiredAuthFrame(t, r.a.fp))
	if code := c.expectError(); code != mailbox.CodeVersion {
		t.Fatalf("code %d, want version", code)
	}
	c.expectClosed()
}

// A hostile length before authentication costs a read of its prefix and a
// bounded allocation, not the size it claims.
//
// spec: SPO-Xmailbox-PRE-020, SPO-Xmailbox-SEC-003
func TestOversizeClaimBeforeAuthAllocatesNothingMuch(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	recvChallenge(t, c)
	before := r.read.Load()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	// a prefix that claims 4 GiB, and a few bytes that must never be read
	c.write([]byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 7, 8})
	if code := c.expectError(); code != mailbox.CodeProtocol {
		t.Fatalf("code %d, want protocol", code)
	}
	c.expectClosed()
	runtime.ReadMemStats(&ms1)
	if read := r.read.Load() - before; read != 4 {
		t.Errorf("the relay read %d bytes of a hostile frame, want the 4-byte prefix only", read)
	}
	if a := ms1.TotalAlloc - ms0.TotalAlloc; a > 1<<20 {
		t.Errorf("a 4 GiB claim allocated %d bytes", a)
	}
}

// A header claim of 4 KiB plus one is refused after its prefix too.
//
// spec: SPO-Xmailbox-PRE-020
func TestHeaderOverTheBoundIsRefusedAfterThePrefix(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	recvChallenge(t, c)
	before := r.read.Load()
	c.write([]byte{0, 0, 0x10, 0x01, 9, 9, 9})
	if code := c.expectError(); code != mailbox.CodeProtocol {
		t.Fatalf("code %d, want protocol", code)
	}
	if read := r.read.Load() - before; read != 4 {
		t.Errorf("read %d bytes, want 4", read)
	}
}

// A peer that does not answer the challenge is closed at the unauthenticated
// budget.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-INV-013, SPO-Xmailbox-PRE-054
func TestSilentPeerIsClosedAtTheHandshakeTimeout(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.UnauthBudget = 150 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	c := r.dial(r.a)
	recvChallenge(t, c)
	start := time.Now()
	if code := c.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closed after %v, want about 150ms", d)
	}
	c.expectClosed()
}

// A random source that fails gives no challenge and no handshake.
//
// spec: SPO-Xmailbox-OUT-025
func TestRandomFailureClosesWithoutAChallenge(t *testing.T) {
	r := newRig(t, func(r *rig) { r.randSrc = failingReader{} })
	c := r.dial(r.a)
	c.expectClosed()
	eventually(t, "the close event", closed(r, 1))
	if got := r.ev.of(relay.EventClose); len(got) != 1 || got[0].Reason != relay.ReasonRandom {
		t.Fatalf("events %+v", r.ev.all())
	}
}
