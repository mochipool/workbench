package relay_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// Each test here ends with fakenet.CheckLeaks (the rig starts it): a session
// that kept a goroutine after its peer stalled or was cut fails the test.

// A frame whose prefix is half sent: the relay waits for the rest only until
// its deadline.
//
// spec: SPO-Xmailbox-INV-013
func TestStallInTheMiddleOfTheAuthFrame(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.HandshakeTimeout = 150 * time.Millisecond }))
	c := r.dial(r.a)
	recvChallenge(t, c)
	c.write([]byte{0, 0})
	if code := c.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
}

// A put header with no body: the store holds a reservation while the relay
// waits, and releases it when the body deadline passes.
//
// spec: SPO-Xmailbox-INV-013
func TestStallAfterThePutHeaderReleasesTheReservation(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 250 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	a, _ := r.login(r.a)
	env := envelope(500, 1)
	h, _ := mailbox.NewPutOf(1, r.b.fp, env)
	a.write(frame(t, h)) // the header and nothing more
	eventually(t, "the reservation", func() bool { return r.usage(r.b.fp, r.a.fp).PairEntries == 1 })
	start := time.Now()
	if code := a.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the stalled put held its slot for %v", d)
	}
	eventually(t, "the reservation to go", func() bool { return r.usage(r.b.fp, r.a.fp) == mailbox.Usage{} })
}

// The same in the middle of the body.
//
// spec: SPO-Xmailbox-INV-013
func TestStallInTheMiddleOfTheBodyReleasesTheReservation(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 250 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	a, _ := r.login(r.a)
	env := envelope(500, 1)
	h, _ := mailbox.NewPutOf(1, r.b.fp, env)
	a.write(append(frame(t, h), rawFrame(t, env)[:4+200]...))
	eventually(t, "the reservation", func() bool { return r.usage(r.b.fp, r.a.fp).PairEntries == 1 })
	start := time.Now()
	if code := a.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the stalled body held its slot for %v", d)
	}
	eventually(t, "the reservation to go", func() bool { return r.usage(r.b.fp, r.a.fp) == mailbox.Usage{} })
	if n := len(r.list(r.b.fp)); n != 0 {
		t.Fatalf("%d entries", n)
	}
}

// A put that is refused (the recipient is not in send_to) still has its body
// read to keep the stream in step; a stall in that body ends at the body
// deadline too.
//
// spec: SPO-Xmailbox-INV-013, SPO-Xmailbox-PRE-022
func TestStallInTheBodyOfARefusedPutEndsAtTheBodyDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 250 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	a, _ := r.login(r.a)
	env := envelope(500, 1)
	h, _ := mailbox.NewPutOf(1, r.c.fp, env) // carol is not in alice's send_to
	a.write(append(frame(t, h), rawFrame(t, env)[:4+100]...))
	start := time.Now()
	if code := a.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the stalled body of a refused put held the session for %v", d)
	}
}

// The write deadline is set for each frame, not once for the reply: a peer that
// reads each frame within the bound but all of them in more than the bound is
// served.
//
// spec: SPO-Xmailbox-INV-013
func TestWriteDeadlineIsPerFrame(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.WriteTimeout = 300 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	q, _ := mailbox.DefaultQuota().Validated(3)
	var envs [][]byte
	for i := 0; i < 2; i++ {
		env := envelope(600, byte(i+1))
		envs = append(envs, env)
		if out, err := r.real.Put(context.Background(), relayport.MailboxPut{Recipient: r.b.fp, Sender: r.a.fp, Mid: mailbox.HashOf(env), Size: 600, Quota: q}, bytes.NewReader(env)); err != nil || out != relayport.MailboxStored {
			t.Fatalf("%v %v", out, err)
		}
		r.clock.Advance(time.Second)
	}
	r.net.SetBuffer(128)
	b, _ := r.login(r.b)
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 2})
	items, ok := b.recv().(mailbox.Items)
	if !ok || len(items.Entries) != 2 {
		t.Fatalf("items %+v", items)
	}
	start := time.Now()
	for i, e := range items.Entries {
		got := make([]byte, 4+600)
		for off := 0; off < len(got); off += 100 { // 7 reads, 40 ms apart: about 280 ms a frame
			b.s.SetReadDeadline(time.Now().Add(wait))
			if _, err := io.ReadFull(b.s, got[off:min(off+100, len(got))]); err != nil {
				t.Fatalf("frame %d after %v: %v", i, time.Since(start), err)
			}
			time.Sleep(40 * time.Millisecond)
		}
		if !bytes.Equal(got[4:], envs[i]) || e.Size != 600 {
			t.Fatalf("frame %d is not the entry", i)
		}
	}
	if d := time.Since(start); d < 400*time.Millisecond {
		t.Fatalf("the test read both frames in %v, which is inside one write timeout", d)
	}
}

// A peer that does not read the reply cannot hold the session: the write
// deadline ends it, and its slot is freed.
//
// spec: SPO-Xmailbox-INV-013
func TestStallOnTheReplyEndsAtTheWriteDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.WriteTimeout = 200 * time.Millisecond; l.MaxConnsPerKey = 1 }))
	q, _ := mailbox.DefaultQuota().Validated(3)
	env := envelope(3000, 1)
	if out, err := r.real.Put(context.Background(), relayport.MailboxPut{Recipient: r.b.fp, Sender: r.a.fp, Mid: mailbox.HashOf(env), Size: uint32(len(env)), Quota: q}, bytes.NewReader(env)); err != nil || out != relayport.MailboxStored {
		t.Fatalf("%v %v", out, err)
	}
	r.net.SetBuffer(256) // the raw frame cannot fit
	b, _ := r.login(r.b)
	r.net.SetBuffer(fakenet.DefaultBuffer)
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
	if _, ok := b.recv().(mailbox.Items); !ok { // the header; the body is never read
		t.Fatal("no Items header")
	}
	eventually(t, "the session to end", closed(r, 1))
	if got := closeReason(r, 0); got != relay.ReasonPeer {
		t.Fatalf("reason %q", got)
	}
	r.login(r.b) // the slot is free
}

// A peer that sends requests and reads no replies fills the stream's buffer;
// the header write that cannot finish ends at the write deadline.
//
// spec: SPO-Xmailbox-INV-013
func TestStallOnAHeaderReplyEndsAtTheWriteDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.WriteTimeout = 200 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	r.net.SetBuffer(160)
	b, _ := r.login(r.b)
	// each empty Items reply is a few bytes; the buffer holds 160 of them at most
	for i := uint32(1); i <= 60; i++ {
		if err := b.tryWrite(frame(t, mailbox.Fetch{RequestID: i, MaxItems: 1})); err != nil {
			break
		}
	}
	eventually(t, "the session to end", closed(r, 1))
	if got := closeReason(r, 0); got != relay.ReasonPeer {
		t.Fatalf("reason %q", got)
	}
}

// A connection cut at a chosen byte, in each direction and state, ends the
// session and releases what it held.
//
// spec: SPO-Xmailbox-INV-013
func TestCutsAtEveryStateReleaseEverything(t *testing.T) {
	auth := int64(authFrameLen(t))
	env := envelope(400, 1)
	hdr := int64(len(frame(t, mailboxPutTo(newPeer(fakenet.New(), "bob").fp, env))))
	for _, tc := range []struct {
		name string
		cut  int64 // client to server
	}{
		{"in the auth frame", auth - 10},
		{"after auth", auth},
		{"in the put header", auth + hdr - 3},
		{"before the body", auth + hdr},
		{"in the body", auth + hdr + 4 + 100},
		{"one byte short of the body", auth + hdr + 4 + int64(len(env)) - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			c := r.dialFault(r.a, fakenet.Fault{CutClientToServer: fakenet.Int64(tc.cut)})
			ch := recvChallenge(t, c)
			// the writes may fail once the cut is reached; that is the fault
			_ = c.tryWrite(frame(t, mailbox.Auth{Version: 1, Fingerprint: r.a.fp, Signature: c.signAuth(ch, r.a.fp, r.a.node.Key, r.relay.Key)}))
			if tc.cut > auth {
				_ = c.tryWrite(append(frame(t, mailboxPutTo(r.b.fp, env)), rawFrame(t, env)...))
			}
			eventually(t, "the session to end", closed(r, 1))
			if u := r.usage(r.b.fp, r.a.fp); u != (mailbox.Usage{}) {
				t.Fatalf("usage %+v after a cut", u)
			}
			if n := len(r.list(r.b.fp)); n != 0 {
				t.Fatalf("%d entries after a cut", n)
			}
			// the retry stores it once
			a, _ := r.login(r.a)
			if got := a.put(1, r.b.fp, env).Status; got != mailbox.StatusStored {
				t.Fatalf("retry: %d", got)
			}
			if got := a.put(2, r.b.fp, env).Status; got != mailbox.StatusDuplicate {
				t.Fatalf("second retry: %d", got)
			}
		})
	}
}

// A cut towards the client, at the challenge and after the AuthOK.
//
// spec: SPO-Xmailbox-INV-013
func TestCutsTowardsTheClientEndTheSession(t *testing.T) {
	for _, cut := range []int64{3, 100} {
		r := newRig(t)
		c := r.dialFault(r.a, fakenet.Fault{CutServerToClient: fakenet.Int64(cut)})
		_, _ = c.tryRecv()
		_ = c.tryWrite([]byte{0, 0, 0, 1, 0})
		eventually(t, "the session to end", closed(r, 1))
		r.stop()
	}
}

// A peer that sends one byte at a time is served; a trickle cannot outlast the
// body deadline.
//
// spec: SPO-Xmailbox-INV-013
func TestSlowBodyEndsAtTheBodyDeadline(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 300 * time.Millisecond }))
	a, _ := r.login(r.a)
	env := envelope(400, 1)
	h, _ := mailbox.NewPutOf(1, r.b.fp, env)
	a.write(frame(t, h))
	body := rawFrame(t, env)
	start := time.Now()
	for i := 0; i < len(body); i++ {
		if err := a.tryWrite(body[i : i+1]); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond) // 4 s for the whole body: far past 300 ms
		if time.Since(start) > 2*time.Second {
			t.Fatal("the relay is still reading a trickle after 2 s")
		}
	}
	eventually(t, "the session to end", closed(r, 1))
	if n := len(r.list(r.b.fp)); n != 0 {
		t.Fatalf("%d entries", n)
	}
}

// Shutdown ends every session promptly, whatever state it is in, with the
// shutting-down code, and Serve returns.
//
// spec: SPO-Xmailbox-INV-013
func TestShutdownEndsEverySessionPromptly(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.IdleTimeout = 10 * time.Second
		l.BodyTimeout = 10 * time.Second
		l.HandshakeTimeout = 10 * time.Second
	}))
	idle, _ := r.login(r.b)
	pre := r.dial(r.c) // never answers the challenge
	recvChallenge(t, pre)
	a, _ := r.login(r.a)
	env := envelope(500, 1)
	h, _ := mailbox.NewPutOf(1, r.b.fp, env)
	a.write(append(frame(t, h), rawFrame(t, env)[:4+10]...)) // half a body
	eventually(t, "the reservation", func() bool { return r.usage(r.b.fp, r.a.fp).PairEntries == 1 })
	start := time.Now()
	r.ev.slowClose(150 * time.Millisecond) // sessions take a while to finish
	r.cancel()
	for name, c := range map[string]*conn{"idle": idle, "pre-auth": pre, "mid-body": a} {
		if code := c.expectError(); code != mailbox.CodeShuttingDown {
			t.Errorf("%s: code %d, want shutting down", name, code)
		}
	}
	select {
	case <-r.served:
		r.served <- nil
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	// Serve returns only after every session has ended and logged its close
	if got := len(r.ev.of(relay.EventClose)); got != 3 {
		t.Fatalf("Serve returned with %d of 3 sessions finished", got)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("shutdown took %v", d)
	}
	if u := r.usage(r.b.fp, r.a.fp); u != (mailbox.Usage{}) {
		t.Fatalf("usage %+v after shutdown", u)
	}
}

// CloseParty (the reload's revocation) ends that party's live sessions with the
// revoked code, also in a long-poll, and no one else's.
//
// spec: SPO-Xmailbox-SEC-024
func TestCloseParty(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout = 10 * time.Second }))
	a1, _ := r.login(r.a)
	a2, _ := r.login(r.a)
	b, _ := r.login(r.b)
	lists := r.store.listCalls()
	a2.send(mailbox.Fetch{RequestID: 1, MaxItems: 1, WaitSeconds: 20})
	r.awaitLongPoll(lists) // a2 is parked in its long-poll
	start := time.Now()
	r.srv.CloseParty(r.a.fp)
	for _, c := range []*conn{a1, a2} {
		if code := c.expectError(); code != mailbox.CodeRevoked {
			t.Fatalf("code %d, want revoked", code)
		}
		c.expectClosed()
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("CloseParty took %v", d)
	}
	b.fetch(1, nil, 1, 0) // bob is untouched
}

// The reload as the relay's main will do it, in the order the spec fixes: the
// list first, then the live sessions, then the mailbox. The revoked party's
// next request on a connection the reload missed is still refused, and its
// mailbox is gone.
//
// spec: SPO-Xmailbox-SEC-024
func TestRevocationEndToEnd(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	a.put(1, r.b.fp, envelope(100, 1))
	b.put(1, r.a.fp, envelope(100, 2))
	r.acc.remove(r.a.fp)
	r.srv.CloseParty(r.a.fp)
	if _, err := r.real.RemoveMailbox(context.Background(), r.a.fp); err != nil {
		t.Fatal(err)
	}
	if code := a.expectError(); code != mailbox.CodeRevoked {
		t.Fatalf("code %d", code)
	}
	// A cannot come back
	again := r.dial(r.a)
	if code := again.expectError(); code != mailbox.CodeRevoked {
		t.Fatalf("code %d, want revoked", code)
	}
	// what A put before stays for B; what was addressed to A is gone
	if items, _ := b.fetch(2, nil, 16, 0); len(items.Entries) != 1 {
		t.Fatalf("B's mailbox: %+v", items)
	}
	if n := len(r.list(r.a.fp)); n != 0 {
		t.Fatalf("%d entries in the revoked mailbox", n)
	}
}
