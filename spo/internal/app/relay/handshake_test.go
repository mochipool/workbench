package relay_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// recvChallenge reads the Challenge a relay opens a connection with.
func recvChallenge(t *testing.T, c *conn) mailbox.Challenge {
	t.Helper()
	ch, ok := c.recv().(mailbox.Challenge)
	if !ok {
		t.Fatal("the relay did not open with a Challenge")
	}
	return ch
}

// The Challenge carries what the ADR says: the versions the relay speaks, a
// 32-byte nonce, the relay's own node key and the relay's clock.
//
// spec: SPO-Xmailbox-OUT-025
func TestChallengeCarriesTheRelaysFacts(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	if ch.Min != 1 || ch.Max != 1 {
		t.Errorf("versions [%d, %d], want [1, 1]", ch.Min, ch.Max)
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

// A good handshake ends in AuthOK with the limits that apply.
//
// spec: SPO-Xmailbox-OUT-025
func TestAuthOKCarriesTheLimits(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxEnvelope = 4096; l.RetentionSeconds = 3600 }),
		withQuota(func(q *mailbox.Quota) { q.MailboxEntries = 10; q.MailboxBytes = 1 << 20 }))
	_, ok := r.login(r.a)
	want := mailbox.AuthOK{Version: 1, MaxEnvelope: 4096, MaxEntries: 10, MaxBytes: 1 << 20, RetentionSeconds: 3600}
	if ok != want {
		t.Fatalf("AuthOK %+v, want %+v", ok, want)
	}
}

// A tunnel peer whose node key is not in the access list (a revoked key that
// the tunnel still admits) gets one bounded reply and nothing else: no nonce is
// drawn and no challenge is made.
//
// spec: SPO-Xmailbox-PRE-021
func TestUnlistedNodeIsClosedBeforeAnyChallenge(t *testing.T) {
	r := newRig(t)
	c := r.dialNode(r.a, r.stranger, zeroFault)
	if code := c.expectError(); code != mailbox.CodeRevoked {
		t.Fatalf("code %d, want revoked (%d)", code, mailbox.CodeRevoked)
	}
	c.expectClosed()
	if n := r.rnd.n.Load(); n != 0 {
		t.Fatalf("the random source was read %d times for an unlisted node", n)
	}
	if got := r.ev.of(relay.EventRejected); len(got) != 1 || got[0].Reason != relay.ReasonUnlisted || got[0].Node != r.stranger.Key {
		t.Fatalf("events %+v", got)
	}
}

// The party is found by the tunnel node key. A tunnel peer that is listed (as
// bob) and claims the fingerprint of another listed party (alice), even with
// alice's valid signature over its own node key, is refused: the entry used is
// bob's, and the fingerprint in Auth must be the entry's.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-SEC-012
func TestClaimedFingerprintMustBeTheTunnelKeysEntry(t *testing.T) {
	r := newRig(t)
	c := r.dialNode(r.a, r.b.node, zeroFault) // alice's keys over bob's tunnel
	ch := recvChallenge(t, c)
	// alice signs for her own fingerprint and bob's node key, so every signed
	// field is consistent; only the tunnel binding is wrong.
	c.sendAuth(ch, r.a.fp, c.signAuth(ch, r.a.fp, r.b.node.Key, r.relay.Key))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c.expectClosed()
	got := r.ev.of(relay.EventAuthFail)
	if len(got) != 1 || got[0].Reason != relay.ReasonFingerprint {
		t.Fatalf("events %+v", got)
	}
}

// A party that leaves the access list between the admission of its connection
// and its Auth is refused as revoked, whatever it signs.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-SEC-024
func TestPartyRemovedBetweenChallengeAndAuthIsRevoked(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	r.acc.remove(r.a.fp)
	c.sendAuth(ch, r.a.fp, c.signAuth(ch, r.a.fp, r.a.node.Key, r.relay.Key))
	if code := c.expectError(); code != mailbox.CodeRevoked {
		t.Fatalf("code %d, want revoked", code)
	}
	c.expectClosed()
	if len(r.ev.of(relay.EventAuthOK)) != 0 {
		t.Fatal("an auth_ok for a removed party")
	}
}

// The fingerprint of an unlisted party is no better.
//
// spec: SPO-Xmailbox-SEC-020
func TestUnknownFingerprintIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	other := newPeer(r.net, "mallory")
	c.sendAuth(ch, other.fp, c.signAuth(ch, other.fp, r.a.node.Key, r.relay.Key))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c.expectClosed()
}

// A signature by another party's key is refused: alice's node and fingerprint,
// bob's key.
//
// spec: SPO-Xmailbox-SEC-020, SPO-Xmailbox-SEC-002
func TestSignatureByAnotherKeyIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	b, err := mailbox.AuthBytes(mailbox.AuthParams{Version: 1, RelayKey: r.relay.Key, ClientNodeKey: r.a.node.Key, Nonce: ch.Nonce, RelayTime: ch.RelayTime, Fingerprint: r.a.fp})
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], signWith(r.b, b))
	c.sendAuth(ch, r.a.fp, sig)
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
	captured := frame(t, mailbox.Auth{Version: 1, Fingerprint: r.a.fp, Signature: c1.signAuth(ch1, r.a.fp, r.a.node.Key, r.relay.Key)})
	c1.write(captured)
	if _, ok := c1.recv().(mailbox.AuthOK); !ok {
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
	c.sendAuth(ch, r.a.fp, c.signAuth(ch, r.a.fp, r.a.node.Key, party.NodeKey{9}))
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
	c.sendAuth(ch, r.a.fp, c.signAuth(ch, r.a.fp, party.NodeKey{7}, r.relay.Key))
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
}

// One failed auth closes the connection: there is no second try.
//
// spec: SPO-Xmailbox-PRE-020
func TestOneFailedAuthClosesTheConnection(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := recvChallenge(t, c)
	c.sendAuth(ch, r.a.fp, [64]byte{1})
	if code := c.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	c.expectClosed()
	// a second, honest Auth on the same stream reaches nobody
	_ = c.tryWrite(frame(t, mailbox.Auth{Version: 1, Fingerprint: r.a.fp, Signature: c.signAuth(ch, r.a.fp, r.a.node.Key, r.relay.Key)}))
	c.expectClosed()
	if len(r.ev.of(relay.EventAuthOK)) != 0 {
		t.Fatal("an auth_ok after a failed auth")
	}
}

// No frame but Auth is accepted before authentication, and nothing is stored
// or read for it.
//
// spec: SPO-Xmailbox-PRE-020
func TestFrameBeforeAuthIsRefused(t *testing.T) {
	env := envelope(100, 1)
	put, err := mailbox.NewPutOf(1, party.Fingerprint{1}, env)
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
		mailbox.Challenge{Min: 1, Max: 1, RelayKey: party.NodeKey{1}},
		mailbox.AuthOK{Version: 1, MaxEnvelope: 1, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1},
		mailbox.PutResult{RequestID: 1},
		mailbox.Items{RequestID: 1},
		mailbox.AckResult{RequestID: 1},
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

// A version the relay does not speak is the version error.
//
// spec: SPO-Xmailbox-OUT-025
func TestUnspokenVersionIsRefused(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	recvChallenge(t, c)
	c.send(mailbox.Auth{Version: 2, Fingerprint: r.a.fp})
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

// A peer that does not answer the challenge is closed at the handshake bound.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-INV-013
func TestSilentPeerIsClosedAtTheHandshakeTimeout(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.HandshakeTimeout = 150 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
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
