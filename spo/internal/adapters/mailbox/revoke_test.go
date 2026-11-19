package mailbox_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// walletRevoke is a wallet-signed revoke of one device by the peer's wallet key,
// owed until the end of the peer's binding.
func walletRevoke(p *peer, device party.Fingerprint, notBefore int64) mailbox.Revoke {
	s := p.wallet.RevokeStatement(device, false, notBefore)
	return mailbox.Revoke{Kind: mailbox.RevokeByWalletKey, Until: p.until, Sign1: s.Sign1, Key: s.COSEKey}
}

// deviceRevoke is a revoke signed by the device key of seed's device.
func deviceRevoke(t testing.TB, seed string, notBefore, until int64) (mailbox.Revoke, party.Fingerprint) {
	t.Helper()
	sd := sha256.Sum256([]byte("old device " + seed))
	priv := ed25519.NewKeyFromSeed(sd[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	x := party.X25519Public(sha256.Sum256([]byte("old device x " + seed)))
	fp := party.FingerprintOf(ed, x)
	msg, err := relaybind.DeviceRevokeBytes(fp, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(priv, msg))
	return mailbox.Revoke{Kind: mailbox.RevokeByDeviceKey, Until: until, Keys: wire.DeviceKeys{Ed25519: ed, X25519: x}, NotBefore: notBefore, Signature: sig}, fp
}

func revokeSign1(m wire.Message) []byte {
	if r, ok := m.(wire.RevokeByWallet); ok {
		return r.Sign1
	}
	return nil
}

// A client with pending revokes sends them first on a connection, before the
// Auth, in the book's order (oldest first), each with its own request id and in
// the frame of its kind, and calls the signer only after the last answer. The
// book is told `recorded` for each.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-SEC-071
func TestPendingRevokesGoBeforeTheAuthOldestFirst(t *testing.T) {
	h := newHostile(t, putOK)
	r1 := walletRevoke(h.me, party.Fingerprint{1}, startTime-100)
	r2, fp2 := deviceRevoke(t, "two", startTime-50, h.me.until)
	r3 := walletRevoke(h.me, party.Fingerprint{3}, startTime-10)
	h.book = &testBook{pending: []mailbox.Revoke{r1, r2, r3}}
	c := h.client()
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	recs := h.revokeRecs()
	if len(recs) != 3 {
		t.Fatalf("%d Revoke frames reached the relay, want 3", len(recs))
	}
	if !bytes.Equal(revokeSign1(recs[0].msg), r1.Sign1) || !bytes.Equal(revokeSign1(recs[2].msg), r3.Sign1) {
		t.Fatal("the wallet-signed revokes did not arrive in the book's order with their own bytes")
	}
	d, ok := recs[1].msg.(wire.RevokeByDevice)
	if !ok || d.Keys != r2.Keys || d.NotBefore != r2.NotBefore || d.Signature != r2.Signature || d.Keys.Fingerprint() != fp2 {
		t.Fatalf("the device-signed revoke did not arrive as given: %+v", recs[1].msg)
	}
	ids := map[uint32]bool{}
	for _, r := range recs {
		var id uint32
		switch m := r.msg.(type) {
		case wire.RevokeByWallet:
			id = m.RequestID
		case wire.RevokeByDevice:
			id = m.RequestID
		}
		if ids[id] {
			t.Fatalf("request id %d is used twice", id)
		}
		ids[id] = true
	}
	h.mu.Lock()
	auth := h.auths[0]
	h.mu.Unlock()
	if auth.revokes != 3 {
		t.Fatalf("%d revokes came before the Auth, want 3", auth.revokes)
	}
	if out := h.book.outcomes(); len(out) != 3 || out[0] != mailbox.RevokeRecorded || out[1] != mailbox.RevokeRecorded || out[2] != mailbox.RevokeRecorded {
		t.Fatalf("outcomes = %v, want three recorded", out)
	}
}

// At most wire.MaxRevokesPerConn revokes go on one connection, oldest first; the
// rest are reported as deferred and wait. On the next connection the ones that
// were not sent go first, then those sent the longest ago, in the book's order
// (TestEveryPendingRevokeIsSentWithinCeilNOverEightConnections has the bound).
//
// spec: SPO-Xmailbox-OUT-090
func TestAtMostEightRevokesPerConnectionAndTheUnsentGoFirstNextTime(t *testing.T) {
	h := newHostile(t, func(s *sconn) { s.handshake(hs{}) }) // answers every revoke, then closes after the login
	var pending []mailbox.Revoke
	for i := range 12 {
		pending = append(pending, walletRevoke(h.me, party.Fingerprint{byte(i + 1)}, startTime-int64(100-i)))
	}
	h.book = &testBook{pending: pending}
	c := h.client()
	if err := sendOnce(c); err == nil {
		// the scripted relay closes after the login: the put is no route, which is fine here
		t.Log("the put went through")
	}
	recs := h.revokeRecs()
	if len(recs) != wire.MaxRevokesPerConn {
		t.Fatalf("%d revokes on the first connection, want %d", len(recs), wire.MaxRevokesPerConn)
	}
	for i, r := range recs {
		if !bytes.Equal(revokeSign1(r.msg), pending[i].Sign1) {
			t.Fatalf("revoke %d on the first connection is not the book's %d-th (oldest first)", i, i)
		}
	}
	var deferred int
	for _, o := range h.book.outcomes() {
		if o == mailbox.RevokeDeferred {
			deferred++
		}
	}
	if deferred != 4 {
		t.Fatalf("%d revokes reported as deferred, want 4", deferred)
	}
	time.Sleep(60 * time.Millisecond) // the backoff of the closed connection
	sendOnce(c)
	recs = h.revokeRecs()
	if len(recs) != 16 {
		t.Fatalf("%d revokes in all after the second connection, want 16", len(recs))
	}
	second := recs[8:]
	for i := range 4 {
		if !bytes.Equal(revokeSign1(second[i].msg), pending[8+i].Sign1) {
			t.Fatalf("revoke %d on the second connection is not one the first did not send", i)
		}
	}
	for i := 4; i < 8; i++ {
		if !bytes.Equal(revokeSign1(second[i].msg), pending[i-4].Sign1) {
			t.Fatalf("revoke %d on the second connection is not a re-send of an earlier one, oldest first", i)
		}
	}
}

// A revoke is sent again on every connection until the revoked binding's end,
// recorded or not (a relay may lose state); a refusal is not final, and a relay
// that answers recorded to the first is asked again by the next connection.
//
// spec: SPO-Xmailbox-OUT-090
func TestARevokeIsSentOnEveryConnectionUntilItsBindingEnds(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.handshake(hs{revokeStatus: func(i int, m wire.Message) wire.Message {
			id := m.(wire.RevokeByWallet).RequestID
			if s.n == 1 {
				return wire.RevokeResult{RequestID: id, Status: wire.RevokeRefused} // the relay-wide cap, say
			}
			return wire.RevokeResult{RequestID: id, Status: wire.RevokeRecorded}
		}})
	})
	r := walletRevoke(h.me, party.Fingerprint{1}, startTime-10)
	h.book = &testBook{pending: []mailbox.Revoke{r}}
	clk := newStepClock()
	c := h.client(func(cfg *mailbox.Config) { cfg.Clock = clk })
	for range 3 {
		sendOnce(c)
		time.Sleep(60 * time.Millisecond)
	}
	if n := len(h.revokeRecs()); n != 3 {
		t.Fatalf("the revoke was sent %d times in three connections, want 3 (every connection)", n)
	}
	out := h.book.outcomes()
	if len(out) != 3 || out[0] != mailbox.RevokeRefused || out[1] != mailbox.RevokeRecorded || out[2] != mailbox.RevokeRecorded {
		t.Fatalf("outcomes = %v, want refused, recorded, recorded", out)
	}
	for _, o := range out {
		if o.Final() {
			t.Fatalf("outcome %v is final: the book would drop the revoke", o)
		}
	}
	// past the end of the revoked binding it is no longer sent, and the book is told
	clk.Advance(time.Duration(h.me.until-startTime+1) * time.Second)
	before := len(h.revokeRecs())
	h2 := h.book.outcomes()
	c2 := h.client(func(cfg *mailbox.Config) {
		cfg.Clock = clk
		cfg.Binding = h.me.rebind(h.me.until-10*24*3600, h.me.until+30*24*3600, false)
	})
	sendOnce(c2)
	if n := len(h.revokeRecs()); n != before {
		t.Fatalf("a revoke past its binding's end was sent (%d frames, was %d)", n, before)
	}
	out = h.book.outcomes()
	if len(out) != len(h2)+1 || out[len(out)-1] != mailbox.RevokeExpired || !out[len(out)-1].Final() {
		t.Fatalf("outcomes = %v, want an expired one last", out)
	}
}

// The end of the revoked binding is inclusive: at its `until` the revoke is still
// sent, a second later it is expired and is not.
//
// spec: SPO-Xmailbox-OUT-090
func TestTheRevokeIsSentAtItsUntilAndNotAfter(t *testing.T) {
	for _, tc := range []struct {
		name string
		till int64
		sent bool
	}{{"at the end", startTime, true}, {"one second after", startTime - 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, putOK)
			r := walletRevoke(h.me, party.Fingerprint{1}, startTime-10)
			r.Until = tc.till
			h.book = &testBook{pending: []mailbox.Revoke{r}}
			sendOnce(h.client())
			if got := len(h.revokeRecs()) == 1; got != tc.sent {
				t.Fatalf("sent = %v, want %v", got, tc.sent)
			}
			out := h.book.outcomes()
			if !tc.sent && (len(out) != 1 || out[0] != mailbox.RevokeExpired) {
				t.Fatalf("outcomes = %v, want expired", out)
			}
		})
	}
}

// A revoke whose own statement does not verify is never sent: the client says so
// (final), without a refusal from the relay. A not-before the relay would still
// call future is deferred, not final.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-IF-018
func TestARevokeThatDoesNotVerifyIsNotSent(t *testing.T) {
	h := newHostile(t, putOK)
	good := walletRevoke(h.me, party.Fingerprint{1}, startTime-10)
	garbage := mailbox.Revoke{Kind: mailbox.RevokeByWalletKey, Until: h.me.until, Sign1: []byte{1, 2, 3}, Key: good.Key}
	flipped := good
	flipped.Sign1 = bytes.Clone(good.Sign1)
	flipped.Sign1[len(flipped.Sign1)-1] ^= 1 // the signature
	otherKey := walletRevoke(h.me, party.Fingerprint{2}, startTime-10)
	otherKey.Key = relayporttest.NewWallet(9).COSEKey()
	future := walletRevoke(h.me, party.Fingerprint{4}, startTime+10_000)
	dev, _ := deviceRevoke(t, "bad", startTime-10, h.me.until)
	dev.Signature[0] ^= 1
	noKind := mailbox.Revoke{Until: h.me.until}
	noUntil := walletRevoke(h.me, party.Fingerprint{5}, startTime-10)
	noUntil.Until = 0
	h.book = &testBook{pending: []mailbox.Revoke{garbage, flipped, otherKey, future, dev, noKind, noUntil, good}}
	sendOnce(h.client())
	recs := h.revokeRecs()
	if len(recs) != 1 || !bytes.Equal(revokeSign1(recs[0].msg), good.Sign1) {
		t.Fatalf("%d revokes were sent, want only the good one", len(recs))
	}
	out := h.book.outcomes()
	want := []mailbox.RevokeOutcome{mailbox.RevokeInvalid, mailbox.RevokeInvalid, mailbox.RevokeInvalid, mailbox.RevokeDeferred,
		mailbox.RevokeInvalid, mailbox.RevokeInvalid, mailbox.RevokeInvalid, mailbox.RevokeRecorded}
	if len(out) != len(want) {
		t.Fatalf("outcomes = %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("outcomes = %v, want %v", out, want)
		}
	}
	if mailbox.RevokeDeferred.Final() || mailbox.RevokeRefused.Final() || mailbox.RevokeRecorded.Final() {
		t.Fatal("a retryable outcome is final")
	}
}

// Every answer to a revoke is checked: the request id of the revoke, the frame
// type, and the connection ends on any deviation; no answer costs the reply
// timeout; an Error frame is the relay's error. None of them is final for the
// revoke, and the signer is never called.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-PRE-058
func TestRevokeAnswerViolations(t *testing.T) {
	cases := []struct {
		name   string
		answer func(s *sconn, id uint32)
		is     error
	}{
		{"a wrong request id", func(s *sconn, id uint32) {
			s.send(wire.RevokeResult{RequestID: id + 1, Status: wire.RevokeRecorded})
		}, mailbox.ErrProtocol},
		{"a status that does not exist", func(s *sconn, id uint32) { s.header([]any{uint64(wire.MsgRevokeResult), uint64(id), uint64(1)}) }, mailbox.ErrProtocol},
		{"a PutResult", func(s *sconn, id uint32) { s.send(wire.PutResult{RequestID: id}) }, mailbox.ErrProtocol},
		{"an AuthOK before the Auth", func(s *sconn, id uint32) {
			s.send(wire.AuthOKV2{MaxEnvelope: 1000, MaxEntries: 1, MaxBytes: 1, RetentionSeconds: 1, Until: startTime + 100})
		}, mailbox.ErrProtocol},
		{"a Challenge again", func(s *sconn, id uint32) { s.challenge(hs{}) }, mailbox.ErrProtocol},
		{"an Items reply", func(s *sconn, id uint32) { s.send(wire.Items{RequestID: id}) }, mailbox.ErrProtocol},
		{"garbage", func(s *sconn, id uint32) { s.raw([]byte{0, 0, 0, 3, 0xff, 0xff, 0xff}) }, mailbox.ErrProtocol},
		{"an Error frame (limit)", func(s *sconn, id uint32) { s.send(wire.Error{Code: wire.CodeLimit}) }, mailbox.ErrRelayError},
		{"no answer", func(s *sconn, id uint32) {}, mailbox.ErrUnreachable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				s.challenge(hs{})
				m, err := s.recv()
				if err != nil {
					return
				}
				s.stage, _ = s.stage.AfterRevoke(m)
				tc.answer(s, m.(wire.RevokeByWallet).RequestID)
				s.waitClosed()
			})
			r := walletRevoke(h.me, party.Fingerprint{1}, startTime-10)
			h.book = &testBook{pending: []mailbox.Revoke{r}}
			t0 := time.Now()
			err := sendOnce(h.client())
			if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, tc.is) {
				t.Fatalf("Send = %v, want ErrNoRoute wrapping %v", err, tc.is)
			}
			if d := time.Since(t0); d > 1500*time.Millisecond {
				t.Fatalf("took %v", d)
			}
			if n := len(h.me.sg.calls()); n != 0 || h.authCount() != 0 {
				t.Fatalf("%d signatures and %d Auths after a failed revoke exchange", n, h.authCount())
			}
			for _, o := range h.book.outcomes() {
				if o.Final() {
					t.Fatalf("outcome %v is final: a failure of the relay must not drop a revoke", o)
				}
			}
			waitFor(t, "the client to close", func() bool { return h.closedCount() == 1 })
		})
	}
}

// A relay that never answers the revokes costs the handshake timeout and no more.
//
// spec: SPO-Xmailbox-OUT-041, SPO-Xmailbox-OUT-090
func TestAStallDuringTheRevokesCostsTheHandshakeTimeout(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{})
		s.recv()
		s.waitClosed()
	})
	h.book = &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
	t0 := time.Now()
	err := sendOnce(h.client())
	if d := time.Since(t0); d > 1200*time.Millisecond {
		t.Fatalf("the stalled revoke exchange took %v", d)
	}
	if !errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Send = %v, want ErrUnreachable", err)
	}
}

// SendRevokes sends the pending revokes on a connection of its own and ends it
// without a login: no signature is made, no Auth is sent, and the connection is
// closed after the last answer. It is how a device forgets itself or a lost one
// after its mail was handled (ADR 0014 decision 8), and how a revoke goes out
// from an unbound client.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-INV-038
func TestSendRevokesSendsThemWithoutALogin(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{})
		for {
			m, err := s.recv()
			if err != nil {
				s.waitClosed()
				return
			}
			rb, isRevoke := m.(wire.RevokeByWallet)
			if !isRevoke { // a login is not expected here: the test fails on the counts
				s.h.mu.Lock()
				s.h.auths = append(s.h.auths, authRec{})
				s.h.mu.Unlock()
				return
			}
			s.stage, _ = s.stage.AfterRevoke(m)
			s.h.mu.Lock()
			s.h.revokes = append(s.h.revokes, revokeRec{conn: s.n, msg: m})
			s.h.mu.Unlock()
			s.send(wire.RevokeResult{RequestID: rb.RequestID, Status: wire.RevokeRecorded})
		}
	})
	h.book = &testBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10), walletRevoke(h.me, party.Fingerprint{2}, startTime-9)}}
	c := h.client()
	if _, err := c.SendRevokes(context.Background()); err != nil {
		t.Fatalf("SendRevokes = %v", err)
	}
	if n := len(h.revokeRecs()); n != 2 {
		t.Fatalf("%d revokes sent, want 2", n)
	}
	if n := len(h.me.sg.calls()); n != 0 || h.authCount() != 0 {
		t.Fatalf("%d signatures and %d Auths for a revoke-only connection", n, h.authCount())
	}
	waitFor(t, "the client to close the connection", func() bool { return h.closedCount() == 1 })
	if out := h.book.outcomes(); len(out) != 2 || out[0] != mailbox.RevokeRecorded {
		t.Fatalf("outcomes = %v", out)
	}
	// with nothing pending it does not dial
	h2 := newHostile(t, func(s *sconn) {})
	h2.book = &testBook{}
	if _, err := h2.client().SendRevokes(context.Background()); err != nil || h2.connCount() != 0 {
		t.Fatalf("SendRevokes with nothing pending = %v after %d connections", err, h2.connCount())
	}
	// after Close it is ErrClosed
	c.Close()
	if _, err := c.SendRevokes(context.Background()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("SendRevokes after Close = %v", err)
	}
	// and it honours the context
	if _, err := h2.client().SendRevokes(canceled()); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendRevokes with a cancelled context = %v", err)
	}
}

// Against the real relay: a client that is not the revoked device sends a
// wallet-signed revoke of alice's device before its login. The relay records it,
// alice's binding is gone and a put to her is `unbound`; sending it again on the
// next connection is harmless. A device-signed revoke of the client's own old
// device works the same.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-OUT-089
func TestPendingRevokesAreRecordedByTheRealRelay(t *testing.T) {
	w := newWorld(t)
	rv := walletRevoke(w.a, w.a.fp, startTime) // from the wallet that bound alice
	oldDev, oldFP := deviceRevoke(t, "gone", startTime, w.b.until)
	book := &testBook{pending: []mailbox.Revoke{rv, oldDev}}
	cc := w.client(w.c, func(cfg *mailbox.Config) { cfg.Revokes = book })
	if err := cc.Send(context.Background(), w.b.fp, body(10, 1)); err != nil {
		t.Fatal(err)
	}
	if out := book.outcomes(); len(out) != 2 || out[0] != mailbox.RevokeRecorded || out[1] != mailbox.RevokeRecorded {
		t.Fatalf("outcomes = %v, want recorded twice", out)
	}
	if _, ok, err := w.reg.Lookup(context.Background(), w.a.fp); err != nil || ok {
		t.Fatalf("alice's binding is still served after the wallet revoke (%v, %v)", ok, err)
	}
	if _, ok, _ := w.reg.Lookup(context.Background(), w.b.fp); !ok {
		t.Fatal("bob's binding was removed by alice's revoke")
	}
	// a put to alice is unbound now
	w.mu.Lock()
	w.routes[party.Fingerprint{0xaa}] = mailbox.Route{WalletKey: w.a.wkey(), Device: w.a.fp}
	w.mu.Unlock()
	err := cc.Send(context.Background(), party.Fingerprint{0xaa}, body(10, 2))
	if !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send to the revoked device = %v, want ErrNoRoute (unbound)", err)
	}
	_ = oldFP
	// the next connection sends them again; the relay answers recorded again
	cc.Close()
	cc2 := w.client(w.c, func(cfg *mailbox.Config) { cfg.Revokes = book })
	if err := cc2.Send(context.Background(), w.b.fp, body(10, 3)); err != nil {
		t.Fatal(err)
	}
	if out := book.outcomes(); len(out) != 4 || out[2] != mailbox.RevokeRecorded || out[3] != mailbox.RevokeRecorded {
		t.Fatalf("outcomes = %v, want every revoke re-sent and recorded", out)
	}
	if _, ok, _ := w.reg.Lookup(context.Background(), w.a.fp); ok {
		t.Fatal("alice's binding came back after the second send")
	}
}
