package relay_test

import (
	"context"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The version 2 relay session: login with a wallet-key binding, over fakenet,
// against the real mailbox store and the in-memory reference registry. Each test
// that cites "obligation N" discharges item N of "What a session must still do
// in version 2" (spec/extensions/Xmailbox.md).

// The whole path for two bound devices of two wallet keys: A puts to B while B
// long-polls, B receives the exact bytes, acks, and the usage returns to zero.
//
// spec: SPO-Xmailbox-OUT-082, SPO-Xmailbox-OUT-084, SPO-Xmailbox-OUT-085
func TestV2TwoDevicesOfTwoWalletKeysEndToEnd(t *testing.T) {
	r := newRig(t)
	a, aok := r.login(r.a)
	b, bok := r.login(r.b)
	if aok.Until != defaultUntil || bok.Until != defaultUntil {
		t.Fatalf("AuthOK until %d and %d, want the bindings' %d", aok.Until, bok.Until, int64(defaultUntil))
	}
	if aok.MaxEnvelope != mailbox.MaxEnvelopeBytes || aok.MaxEntries != 256 || aok.MaxBytes != 4<<20 {
		t.Fatalf("AuthOK %+v does not carry the open-mode limits", aok)
	}
	env := envelope(5000, 7)

	lists := r.store.listCalls()
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 5})
	r.awaitLongPoll(lists)
	start := time.Now()
	if pr := a.put(1, r.b.fp, env); pr.Status != mailbox.StatusStored {
		t.Fatalf("put status %d, want stored", pr.Status)
	}
	items, bodies := b.readItems(1)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the long-poll was not woken by the put: %v", time.Since(start))
	}
	if len(bodies) != 1 || string(bodies[0]) != string(env) {
		t.Fatalf("B received %d bodies, want the exact envelope", len(bodies))
	}
	if u := r.usage(r.b.fp, r.a.fp); u.MailboxEntries != 1 || u.MailboxBytes != 5000 {
		t.Fatalf("usage after the put %+v", u)
	}
	if got := b.ack(2, items.Entries[0].Mid); got.Deleted != 1 {
		t.Fatalf("ack deleted %d", got.Deleted)
	}
	if u := r.usage(r.b.fp, r.a.fp); u.MailboxEntries != 0 || u.MailboxBytes != 0 || u.PairBytes != 0 || u.SenderBytes != 0 {
		t.Fatalf("usage after the ack %+v, want zero", u)
	}
	// and the other way
	if pr := b.put(3, r.a.fp, envelope(100, 9)); pr.Status != mailbox.StatusStored {
		t.Fatalf("B to A: status %d", pr.Status)
	}
	if it, _ := a.fetch(2, nil, 16, 0); len(it.Entries) != 1 {
		t.Fatalf("A sees %d entries", len(it.Entries))
	}
}

// The relay offers version 2 and nothing else: its Challenge is [2, 2], and the
// stage it decodes at is the one for version 2 before login.
//
// spec: SPO-Xmailbox-OUT-082
func TestChallengeOffersOnlyVersion2(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := c.challenge() // fails unless the range is 2..2
	if ch.RelayKey != r.relay.Key {
		t.Fatalf("the Challenge names %x, not the relay's own key", ch.RelayKey[:4])
	}
}

// Obligation 1: the stage machine. Before login a Put, Fetch or Ack, a frame
// only the relay sends and an unknown type are refused with the protocol code; a
// version 1 Auth is the version code; after login a second Auth and a Revoke are
// the protocol code; a version 1 Put after login is malformed.
//
// spec: SPO-Xmailbox-OUT-082, SPO-Xmailbox-PRE-053
func TestOblig1StageMachine(t *testing.T) {
	env := envelope(10, 1)
	v1auth := func(t *testing.T, r *rig) []byte { return retiredAuthFrame(t, r.a.fp) }
	v1put := func(t *testing.T, r *rig) []byte { return retiredPutFrame(t, r.b.fp, env) }
	revoke := func(t *testing.T, r *rig) []byte {
		return frame(t, deviceRevoke(t, r.a, 1, startTime))
	}
	cases := []struct {
		name  string
		login bool
		frame func(t *testing.T, r *rig) []byte
		code  mailbox.Code
	}{
		{"put before login", false, func(t *testing.T, r *rig) []byte {
			h, _ := mailbox.NewPutV2Of(1, r.b.wkey(), r.b.fp, env)
			return append(frame(t, h), rawFrame(t, env)...)
		}, mailbox.CodeProtocol},
		{"fetch before login", false, func(t *testing.T, r *rig) []byte {
			return frame(t, mailbox.Fetch{RequestID: 1, MaxItems: 1})
		}, mailbox.CodeProtocol},
		{"ack before login", false, func(t *testing.T, r *rig) []byte {
			return frame(t, mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}})
		}, mailbox.CodeProtocol},
		{"a frame only the relay sends", false, func(t *testing.T, r *rig) []byte {
			return frame(t, mailbox.AckResult{RequestID: 1})
		}, mailbox.CodeProtocol},
		{"a version 1 auth", false, v1auth, mailbox.CodeVersion},
		{"a version 1 put before login", false, v1put, mailbox.CodeProtocol},
		{"a second auth", true, func(t *testing.T, r *rig) []byte {
			return frame(t, mailbox.AuthV2{Fingerprint: r.a.fp, Keys: r.a.dev.keys(), Sign1: r.a.stmt.Sign1, Key: r.a.stmt.COSEKey})
		}, mailbox.CodeProtocol},
		{"a revoke after login", true, revoke, mailbox.CodeProtocol},
		{"a version 1 put after login", true, v1put, mailbox.CodeProtocol},
		{"a version 1 auth after login", true, v1auth, mailbox.CodeProtocol}, // the type is not allowed at the stage, before the version is looked at
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			var c *conn
			if tc.login {
				c, _ = r.login(r.a)
			} else {
				c = r.dial(r.a)
				c.challenge()
			}
			c.write(tc.frame(t, r))
			if code := c.expectError(); code != tc.code {
				t.Fatalf("code %d, want %d", code, tc.code)
			}
			c.expectClosed()
			if n := len(r.store.putCalls()); n != 0 {
				t.Fatalf("%d puts reached the store", n)
			}
		})
	}
}

// Obligations 2 and 18: every refusal at login and its exact code, and nothing is
// registered or replaced by a failed login.
//
// spec: SPO-Xmailbox-PRE-053, SPO-Xmailbox-OUT-082
func TestOblig2And18LoginFailureCodes(t *testing.T) {
	other := newDevKeys("mallory")
	weak := party.Ed25519Public{1} // the identity point: a small-order key
	weakKeys := devKeys{priv: other.priv, ed: weak, x: other.x}
	weakKeys.fp = party.FingerprintOf(weak, other.x)
	otherNode := party.NodeKey{9, 9, 9}
	day := int64(24 * 3600)

	type tc struct {
		name   string
		opts   []rigOpt
		bound  bool // a is bound before the login (and its list is checked afterwards)
		opt    func(r *rig) authOpt
		who    func(r *rig) *peer
		code   mailbox.Code
		reason relay.Reason
	}
	aPeer := func(r *rig) *peer { return r.a }
	stmtOf := func(r *rig, from, until int64) *relayporttest.Statements {
		s := r.a.wallet.BindingStatement(r.a.fp, from, until, false)
		return &s
	}
	cases := []tc{
		{"a signature by another key", nil, true, func(r *rig) authOpt { return authOpt{sign: &other} }, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"a flipped signature bit", nil, true, func(r *rig) authOpt {
			return authOpt{edit: func(a *mailbox.AuthV2) { a.Signature[0] ^= 1 }}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"a weak device key", nil, true, func(r *rig) authOpt { return authOpt{present: &weakKeys, sign: &weakKeys} }, aPeer, mailbox.CodeAuth, relay.ReasonWeakKey},
		{"a fingerprint that is not that of the presented keys", nil, true, func(r *rig) authOpt {
			fp := party.Fingerprint{7}
			return authOpt{claimFP: &fp}
		}, aPeer, mailbox.CodeAuth, relay.ReasonFingerprint},
		{"the signed fingerprint is not the presented one", nil, true, func(r *rig) authOpt {
			fp := party.Fingerprint{7}
			return authOpt{signedFP: &fp}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"signed over another client node key", nil, true, func(r *rig) authOpt { return authOpt{clientNode: &otherNode} }, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"signed over another relay key", nil, true, func(r *rig) authOpt { return authOpt{relayKey: &otherNode} }, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"signed over another nonce", nil, true, func(r *rig) authOpt {
			n := [32]byte{1}
			return authOpt{nonce: &n}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"signed over another relay time", nil, true, func(r *rig) authOpt {
			rt := int64(startTime + 1)
			return authOpt{relayTime: &rt}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"the full hash of another encoding of the statement", nil, true, func(r *rig) authOpt {
			flipped := r.a.wallet.BindingStatement(r.a.fp, startTime-60, startTime+30*day, true)
			st, err := relaybind.ParseStatement(flipped.Sign1)
			if err != nil {
				t.Fatal(err)
			}
			h := st.FullHash()
			return authOpt{bindingHash: &h}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"the hash of another sender list", nil, true, func(r *rig) authOpt {
			h, _ := mailbox.SendersHash(nil)
			return authOpt{sendersHash: &h}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"a sender list changed after signing", nil, true, func(r *rig) authOpt {
			return authOpt{edit: func(a *mailbox.AuthV2) { a.Senders = sortedKeys(r.c.wkey()) }}
		}, aPeer, mailbox.CodeAuth, relay.ReasonSignature},
		{"a binding for another device presented on this connection", nil, true, func(r *rig) authOpt {
			s := r.a.wallet.BindingStatement(r.b.fp, startTime-60, startTime+30*day, false)
			return authOpt{stmt: &s}
		}, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"a statement that does not parse", nil, true, func(r *rig) authOpt {
			return authOpt{stmt: &relayporttest.Statements{Sign1: []byte{1, 2, 3}, COSEKey: r.a.stmt.COSEKey}}
		}, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"a cose key that does not parse", nil, true, func(r *rig) authOpt {
			return authOpt{stmt: &relayporttest.Statements{Sign1: r.a.stmt.Sign1, COSEKey: []byte{1, 2, 3}}}
		}, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"another wallet's cose key", nil, true, func(r *rig) authOpt {
			return authOpt{stmt: &relayporttest.Statements{Sign1: r.a.stmt.Sign1, COSEKey: r.b.wallet.COSEKey()}}
		}, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"an expired binding", nil, true, func(r *rig) authOpt { return authOpt{stmt: stmtOf(r, startTime-4000, startTime-10)} }, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"a binding that is not valid yet", nil, true, func(r *rig) authOpt { return authOpt{stmt: stmtOf(r, startTime+1000, startTime+1000+3600)} }, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"a lifetime over the relay's policy", []rigOpt{withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) { c.Policy.MaxLifetime = 30 * day })}, false,
			func(r *rig) authOpt { return authOpt{stmt: stmtOf(r, startTime-60, startTime+90*day)} }, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"an older binding than the stored one", nil, true, func(r *rig) authOpt { return authOpt{stmt: stmtOf(r, startTime-120, startTime+10*day)} }, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"a wallet key that is not on the allow-list", []rigOpt{withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) {
			c.Restricted, c.Allowed = true, []relaybind.KeyHash{{1, 2, 3}}
		})}, false, func(r *rig) authOpt { return authOpt{} }, aPeer, mailbox.CodeNotAllowed, relay.ReasonNotAllowed},
		{"an invalid binding of a key that is not on the allow-list says binding", []rigOpt{withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) {
			c.Restricted, c.Allowed = true, []relaybind.KeyHash{{1, 2, 3}}
		})}, false, func(r *rig) authOpt { return authOpt{stmt: stmtOf(r, startTime-4000, startTime-10)} }, aPeer, mailbox.CodeBinding, relay.ReasonBinding},
		{"a registry that is down", nil, true, func(r *rig) authOpt {
			r.hreg.RegisterErr = context.DeadlineExceeded
			return authOpt{}
		}, aPeer, mailbox.CodeShuttingDown, relay.ReasonRegistry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, tc.opts...)
			if tc.name == "a registry that is down" {
				// a renewal would not reach the registry's writer: it always does
			}
			p := tc.who(r)
			o := tc.opt(r)
			c := r.dial(p)
			if code := c.loginFails(o); code != tc.code {
				t.Fatalf("code %d, want %d", code, tc.code)
			}
			evs := r.ev.of(relay.EventAuthFail)
			if len(evs) != 1 || evs[0].Reason != tc.reason {
				t.Fatalf("auth_fail events %+v, want one with reason %q", evs, tc.reason)
			}
			if tc.bound {
				got, err := r.reg.ExpectedSenders(context.Background(), p.fp)
				if err != nil || !sameKeys(got, p.senders) {
					t.Fatalf("a failed login changed the stored list: %v, %v", got, err)
				}
			} else if _, ok := r.bindingOf(p.fp); ok {
				t.Fatal("a failed login left a binding")
			}
			if n := len(r.ev.of(relay.EventAuthOK)); n != 0 {
				t.Fatalf("%d auth_ok events for a failed login", n)
			}
		})
	}
}

func sameKeys(a, b []mailbox.WalletKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Obligation 2 (a registry bound is `limit`) and 18: the devices of a key, a
// registry that is full of connected devices, and the cap on new bindings.
//
// spec: SPO-Xmailbox-PRE-053
func TestOblig18RegistryBoundsAreLimit(t *testing.T) {
	t.Run("nine devices of one wallet key", func(t *testing.T) {
		r := newRig(t, withoutBindings())
		var last *peer
		for i := range 8 {
			p := r.addPeer("a"+string(rune('0'+i)), r.a.wallet)
			r.bind(p)
		}
		last = r.addPeer("a-ninth", r.a.wallet)
		if code := r.dial(last).loginFails(authOpt{}); code != mailbox.CodeLimit {
			t.Fatalf("code %d, want limit", code)
		}
	})
	t.Run("a full registry of connected devices", func(t *testing.T) {
		r := newRig(t, withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 32 }))
		_, _ = r.login(r.a)
		_, _ = r.login(r.b)
		if code := r.dial(r.c).loginFails(authOpt{}); code != mailbox.CodeLimit {
			t.Fatalf("code %d, want limit", code)
		}
	})
	t.Run("the cap on new bindings", func(t *testing.T) {
		r := newRig(t, withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) { c.NewBindingBurst, c.NewBindingsPerHour = 1, 1 }))
		_, _ = r.login(r.a)
		if code := r.dial(r.b).loginFails(authOpt{}); code != mailbox.CodeLimit {
			t.Fatalf("code %d, want limit", code)
		}
	})
}

// A registry that answers an error that is neither a binding nor a bound fails
// the login with the "not now" code, never with a code that blames the peer.
//
// spec: SPO-Xmailbox-PRE-053
func TestSetExpectedSendersFailureEndsLogin(t *testing.T) {
	r := newRig(t)
	r.hreg.SetSendersErr = context.DeadlineExceeded
	c := r.dial(r.a)
	if code := c.loginFails(authOpt{}); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d, want the not-now code", code)
	}
}

// The theft scenario: a valid binding for device D, signed by D's wallet, is
// presented on a connection that the device keys of E authenticated. The binding
// names D, not E: it is refused with the binding code, nothing is registered for
// E and D's stored list is not touched. Presenting D's keys with E's signature is
// the auth code.
//
// spec: SPO-Xmailbox-SEC-064 (obligation 10)
func TestOblig10TheftOfABindingForAnotherDevice(t *testing.T) {
	r := newRig(t, withoutBindings())
	d := r.a                          // the victim: a bound device
	e := r.addPeer("eve", r.c.wallet) // another device on another tunnel node
	r.bind(d)
	stolen := d.stmt // D's binding, signed by D's wallet

	if code := r.dial(e).loginFails(authOpt{stmt: &stolen}); code != mailbox.CodeBinding {
		t.Fatalf("a binding for another device: code %d, want binding", code)
	}
	if _, ok := r.bindingOf(e.fp); ok {
		t.Fatal("the thief's device was registered")
	}
	// the thief presents D's keys but cannot sign for them
	if code := r.dial(e).loginFails(authOpt{present: &d.dev, stmt: &stolen}); code != mailbox.CodeAuth {
		t.Fatalf("D's keys signed by E: code %d, want auth", code)
	}
	// D's own list is untouched and D still logs in
	got, _ := r.reg.ExpectedSenders(context.Background(), d.fp)
	if !sameKeys(got, d.senders) {
		t.Fatal("a refused login replaced D's list")
	}
	r.dial(d).handshake()
}

// Obligation 10: the fingerprint is computed once from the presented keys, and
// the claimed one has no weight: a frame whose fingerprint field names another
// device is the auth code and no binding of that device is looked at.
//
// spec: SPO-Xmailbox-SEC-064
func TestOblig10ClaimedFingerprintIsNotUsed(t *testing.T) {
	r := newRig(t)
	victim := r.b.fp
	c := r.dial(r.a)
	if code := c.loginFails(authOpt{claimFP: &victim, signedFP: &victim}); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	if e, ok := r.bindingOf(r.b.fp); !ok || e.Binding.Device != r.b.fp {
		t.Fatal("the victim's binding changed")
	}
}

// Obligation 10: the claimed fingerprint of a frame names the victim's device,
// the signature is the thief's own over the thief's own fingerprint, and the
// statement is the victim's. The relay uses the fingerprint of the presented keys
// for both checks and the claim is `auth`; a relay that took the claimed value for
// the binding check would register the thief's keys under the victim's binding.
//
// spec: SPO-Xmailbox-SEC-064
func TestOblig10ClaimedFingerprintIsNotUsedForTheBinding(t *testing.T) {
	r := newRig(t, withoutBindings())
	d := r.a
	e := r.addPeer("eve", r.c.wallet)
	r.bind(d)
	stolen := d.stmt
	if code := r.dial(e).loginFails(authOpt{claimFP: &d.fp, signedFP: &e.fp, stmt: &stolen}); code != mailbox.CodeAuth {
		t.Fatalf("code %d, want auth", code)
	}
	if _, ok := r.bindingOf(e.fp); ok {
		t.Fatal("the thief's device was registered under the victim's binding")
	}
	if cur, ok := r.bindingOf(d.fp); !ok || cur.Device != d.fp {
		t.Fatal("the victim's binding changed")
	}
}

// Obligation 11: the signed bytes commit to the full hash of the statement
// presented in THIS Auth, not to the stored one. After a renewal by re-signature
// (the same statement, another signature) the client signs the hash of what it
// presents and is admitted; a client that signs the stored statement's hash while
// presenting the other one is refused.
//
// spec: SPO-Xmailbox-SEC-065
func TestOblig11CommitmentIsToThePresentedStatement(t *testing.T) {
	r := newRig(t)
	flipped := r.a.wallet.BindingStatement(r.a.fp, startTime-60, startTime+30*24*3600, true)
	storedSt, _ := relaybind.ParseStatement(r.a.stmt.Sign1)
	flipSt, _ := relaybind.ParseStatement(flipped.Sign1)
	if storedSt.FullHash() == flipSt.FullHash() {
		t.Fatal("the two encodings must have different full hashes")
	}
	// presents the flipped statement and commits to the stored one: refused
	stored := storedSt.FullHash()
	if code := r.dial(r.a).loginFails(authOpt{stmt: &flipped, bindingHash: &stored}); code != mailbox.CodeAuth {
		t.Fatalf("a commitment to the stored statement: code %d, want auth", code)
	}
	// presents the flipped statement and commits to it: a re-presentation of the
	// same statement, admitted without a new binding
	c := r.dial(r.a)
	ok := c.handshakeWith(authOpt{stmt: &flipped})
	if ok.Until != defaultUntil {
		t.Fatalf("until %d", ok.Until)
	}
	e, _ := r.bindingOf(r.a.fp)
	if e.FullHash != storedSt.FullHash() {
		t.Fatal("a renewal replaced the stored statement")
	}
}

// A renewal under a longer lifetime is a new statement: the AuthOK carries the
// `until` the registry recorded, and the session ends no later than that.
//
// spec: SPO-Xmailbox-OUT-082
func TestAuthOKCarriesTheRecordedUntil(t *testing.T) {
	r := newRig(t)
	longer := r.a.wallet.BindingStatement(r.a.fp, startTime-30, startTime+60*24*3600, false)
	c := r.dial(r.a)
	ok := c.handshakeWith(authOpt{stmt: &longer})
	if ok.Until != startTime+60*24*3600 {
		t.Fatalf("until %d, want the new statement's", ok.Until)
	}
	if e, _ := r.bindingOf(r.a.fp); e.Binding.Until != ok.Until {
		t.Fatalf("recorded until %d", e.Binding.Until)
	}
}

// Obligation 13: the expected-sender list is replaced on EVERY successful login,
// an empty list included; a login that fails stores nothing.
//
// spec: SPO-Xmailbox-OUT-082, SPO-Xmailbox-OUT-065
func TestOblig13ListReplacedAtEveryLogin(t *testing.T) {
	r := newRig(t)
	get := func() []mailbox.WalletKey {
		l, err := r.reg.ExpectedSenders(context.Background(), r.a.fp)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	if got := get(); !sameKeys(got, sortedKeys(r.b.wkey())) {
		t.Fatalf("list %v", got)
	}
	r.dial(r.a).handshakeWith(authOpt{senders: sortedKeys(r.c.wkey(), r.b.wkey())})
	if got := get(); len(got) != 2 {
		t.Fatalf("the new list was not stored: %v", got)
	}
	r.clock.Advance(time.Minute)
	c := r.dial(r.a)
	c.handshakeWith(authOpt{senders: []mailbox.WalletKey{}})
	if got := get(); len(got) != 0 {
		t.Fatalf("an empty list did not replace the old one: %v", got)
	}
}

// Obligation 7: the nonce and the relay's time are the relay's own, fresh on each
// connection: an Auth captured on one connection fails on another.
//
// spec: SPO-Xmailbox-SEC-065, SPO-Xmailbox-PRE-053
func TestOblig7NonceIsFreshPerConnection(t *testing.T) {
	r := newRig(t)
	c1 := r.dial(r.a)
	ch1 := c1.challenge()
	captured := frame(t, c1.authFrame(ch1, authOpt{}))
	c1.write(captured)
	c1.recv() // AuthOK
	c2 := r.dial(r.a)
	ch2 := c2.challenge()
	if ch1.Nonce == ch2.Nonce {
		t.Fatal("two connections got one nonce")
	}
	c2.write(captured)
	if code := c2.expectError(); code != mailbox.CodeAuth {
		t.Fatalf("a replayed Auth: code %d, want auth", code)
	}
	if r.rnd.n.Load() < 2 {
		t.Fatal("the nonce was not drawn for each connection")
	}
}

// Obligations 2 and 8: a binding that is not valid yet is refused with the
// binding code and never stored.
//
// spec: SPO-Xmailbox-PRE-053, SPO-Xmailbox-SEC-043
func TestOblig8NotYetValidBindingIsNeverStored(t *testing.T) {
	r := newRig(t, withoutBindings())
	future := r.a.wallet.BindingStatement(r.a.fp, startTime+1000, startTime+1000+3600, false)
	if code := r.dial(r.a).loginFails(authOpt{stmt: &future}); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	if _, ok := r.bindingOf(r.a.fp); ok {
		t.Fatal("a binding that is not valid yet was stored")
	}
	// at the edge of the skew the binding is accepted: from - skew <= now
	edge := r.a.wallet.BindingStatement(r.a.fp, startTime+300, startTime+300+3600, false)
	r.dial(r.a).handshakeWith(authOpt{stmt: &edge})
}

// Obligation 12: the session verifies with the policy it is given, and the
// registry checks the lifetime against its own: a relay limited to 30 days
// refuses a 90-day binding with the binding code at both places, and accepts a
// 30-day one.
//
// spec: SPO-Xmailbox-PRE-046, SPO-Xmailbox-PRE-053
func TestOblig12PolicyIsTheRegistrys(t *testing.T) {
	day := int64(24 * 3600)
	r := newRig(t, withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) { c.Policy.MaxLifetime = 30 * day }))
	long := r.a.wallet.BindingStatement(r.a.fp, startTime-60, startTime-60+90*day, false)
	if code := r.dial(r.a).loginFails(authOpt{stmt: &long}); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	ok := r.a.wallet.BindingStatement(r.a.fp, startTime-60, startTime-60+30*day, false)
	r.dial(r.a).handshakeWith(authOpt{stmt: &ok})
}

// Obligation 5: the re-authentication of a registered device with the same
// statement is not a new binding and uses no token of the cap (60 an hour, burst
// 10); a new device does.
//
// spec: SPO-Xmailbox-PRE-044, SPO-Xmailbox-OUT-082
func TestOblig5ReauthenticationCostsNoToken(t *testing.T) {
	r := newRig(t, withoutBindings(), withRegistryConfig(func(c *relayregistry.Config) { c.NewBindingBurst, c.NewBindingsPerHour = 1, 1 }))
	for i := range 3 { // more logins than the burst: each is the same statement again
		r.clock.Advance(time.Minute)
		c := r.dial(r.a)
		c.handshake()
		c.s.Close()
		_ = i
	}
	if code := r.dial(r.b).loginFails(authOpt{}); code != mailbox.CodeLimit {
		t.Fatalf("a second new device: code %d, want limit", code)
	}
}

// What the tunnel does not decide, the session does: a peer whose node key is
// admitted by the tunnel but that holds no binding gets the Challenge and may do
// nothing else; its Auth is refused and it reaches no mailbox.
//
// spec: SPO-Xmailbox-OUT-082
func TestUnboundNodeReachesNothing(t *testing.T) {
	r := newRig(t, withoutBindings())
	c := r.dialNode(r.a, r.stranger, zeroFault) // the stranger's node key, A's device keys
	if code := c.loginFails(authOpt{clientNode: nodeKeyPtr(r.a.node.Key)}); code != mailbox.CodeAuth {
		t.Fatalf("code %d: the signed node key is not the tunnel's", code)
	}
	c2 := r.dialNode(r.a, r.stranger, zeroFault)
	c2.challenge()
	c2.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
	if code := c2.expectError(); code != mailbox.CodeProtocol {
		t.Fatalf("code %d, want protocol", code)
	}
}

func nodeKeyPtr(k party.NodeKey) *party.NodeKey { return &k }

// defaultUntil is the end of the binding a rig peer presents.
const defaultUntil = startTime + 30*24*3600
