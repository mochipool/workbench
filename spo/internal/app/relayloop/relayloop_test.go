package relayloop_test

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// plainBuf is a writer with no lock of its own: the teller must serialise.
type plainBuf struct{ b bytes.Buffer }

func (p *plainBuf) Write(b []byte) (int, error) { return p.b.Write(b) }

func remedy(err error) error { return errors.Join(err, errors.New("bind again")) }

// The exchange loop and the composite's member goroutines use the teller at
// once: the binding renewed by the loop, the refusals told by the callbacks
// and the loop's own messages. Nothing races (run with -race), every line is
// whole, and the remedy is told once per binding statement.
//
// spec: SPO-Xmailbox-OUT-108
func TestTheTellerIsSharedByTheLoopAndTheCallbacks(t *testing.T) {
	var w plainBuf
	run := t.Name() + time.Now().String() // the remedies are remembered per process
	tell := relayloop.New(&w, []byte("binding one "+run), remedy)
	refused := errors.Join(ports.ErrIdentityRefused, errors.New("binding"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { // a member's event callback
			defer wg.Done()
			for range 50 {
				tell.Remedy(refused)
				_ = tell.Statement()
			}
		}()
	}
	wg.Add(1)
	go func() { // the loop
		defer wg.Done()
		for i := range 50 {
			tell.Printf("acknowledging: %d\n", i)
			if i%2 == 1 || i == 49 {
				tell.SetStatement([]byte("binding two " + run))
			} else {
				tell.SetStatement([]byte("binding one " + run))
			}
		}
	}()
	wg.Wait()
	out := w.b.String()
	if n := strings.Count(out, "bind again"); n < 1 || n > 2 {
		t.Fatalf("the remedy was told %d times for at most two bindings:\n%s", n, out)
	}
	// each message is whole: the remedy is three lines (the joined errors)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		switch {
		case strings.HasPrefix(line, "acknowledging: "), line == "relay: identity refused by the relay" || strings.HasPrefix(line, "relay: "),
			line == "binding", line == "bind again":
		default:
			t.Fatalf("a torn line %q", line)
		}
	}
	if got := string(tell.Statement()); got != "binding two "+run {
		t.Fatalf("statement %q", got)
	}
	// a third binding refused again is told once more
	tell.SetStatement([]byte("binding three " + run))
	if !tell.Remedy(refused) || tell.Remedy(refused) {
		t.Fatal("a new binding's refusal is told once")
	}
	if tell.Remedy(errors.New("unreachable")) {
		t.Fatal("an error that is not a refused identity was told as one")
	}
}

// A failure that persists is told once, and again when its text changes or
// after a success cleared it; kinds are separate.
//
// spec: SPO-Xmailbox-OUT-108
func TestAPersistingFailureIsToldOnce(t *testing.T) {
	var w lockedBuf
	tell := relayloop.New(&w, nil, remedy)
	for range 10 {
		tell.Failure("receiving", errors.New("relay one: protocol violation"))
	}
	tell.Failure("sending", errors.New("relay one: protocol violation"))
	tell.Failure("receiving", errors.New("relay two: protocol violation"))
	tell.Clear("receiving")
	tell.Failure("receiving", errors.New("relay two: protocol violation"))
	want := "receiving: relay one: protocol violation\nsending: relay one: protocol violation\nreceiving: relay two: protocol violation\nreceiving: relay two: protocol violation\n"
	if got := w.String(); got != want {
		t.Fatalf("told:\n%s\nwant:\n%s", got, want)
	}
}

// Junk (envelopes refused before their sender is known) passes at once up to
// the burst; beyond it each one waits for a token, which comes back with time,
// so a relay that serves junk without end costs at most one handling per
// interval.
//
// spec: SPO-Xmailbox-OUT-112
func TestJunkIsPaced(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := relayloop.Pacer{Burst: 3, Every: time.Second, Now: func() time.Time { return now }}
	for i := range 3 {
		if d := p.Junk(); d != 0 {
			t.Fatalf("junk %d within the burst waits %v", i, d)
		}
	}
	if d := p.Junk(); d != time.Second {
		t.Fatalf("junk beyond the burst waits %v, want 1s", d)
	}
	now = now.Add(time.Second) // the loop waited
	if d := p.Junk(); d != time.Second {
		t.Fatalf("the next waits %v, want 1s", d)
	}
	now = now.Add(time.Hour) // the bucket refills to the burst, not beyond
	for range 3 {
		if d := p.Junk(); d != 0 {
			t.Fatal("a refilled bucket made junk wait")
		}
	}
	if d := p.Junk(); d == 0 {
		t.Fatal("the bucket grew past its burst")
	}
	var def relayloop.Pacer
	for range relayloop.DefaultJunkBurst {
		if def.Junk() != 0 {
			t.Fatal("the default burst")
		}
	}
	if d := def.Junk(); d <= 0 || d > 2*relayloop.DefaultJunkEvery {
		t.Fatalf("the default pace %v", d)
	}
}
