package multisig_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// storedCount is how many requests bob's inbox record holds.
func storedCount(t *testing.T, s *scene) int {
	t.Helper()
	var raw []byte
	if err := s.B.Store.View(ctx, func(r ports.Reader) error {
		var err error
		raw, err = r.Get(ports.Ref{Name: "state", Kind: ports.MultisigSigner})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var st struct {
		Requests []json.RawMessage `json:"requests"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return len(st.Requests)
}

// A flood of short-lived requests that are refused leaves the inbox record
// bounded: each is gone at its expiry (N3).
// spec: SPO-Xparty-INV-029
func TestFloodOfRefusedRequestsLeavesBoundedState(t *testing.T) {
	s := newScene(t, sceneOpt{ttl: 100000})
	for range 40 {
		env := s.forgedRequest(func(r *party.SigningRequest) { r.KeyHash = [28]byte{0xee} }) // a key bob does not hold: refused in silence
		h, err := s.B.Signer().Handle(ctx, ports.FileReceived(env))
		if err != nil || h.Effect != "refused" {
			t.Fatalf("handled = %+v, %v", h, err)
		}
		s.clock.Advance(3 * time.Minute) // past the envelope's two minutes
	}
	if n := storedCount(t, s); n > 2 {
		t.Fatalf("%d refused requests are still stored after the flood", n)
	}
}

// The first-frame check of a network transport runs the signer-role and
// Hello-lifetime checks before any route exists: a Hello that Handle would
// refuse is refused at the door (N5).
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-021, SPO-Xparty-INV-027
func TestAdmitRefusesAHelloThatHandleWouldRefuse(t *testing.T) {
	s := newScene(t, sceneOpt{kind: ports.ViaNetwork, bobNode: true})
	// A signer's Hello of the allowed lifetime is admitted.
	good := s.sealFrom(s.B, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(time.Minute))
	if _, err := s.C.Coordinator().Admit(ctx, good, bobNodeKey); err != nil {
		t.Fatalf("a good Hello was refused: %v", err)
	}
	// Ten minutes is longer than a Hello may live.
	long := s.sealFrom(s.B, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(10*time.Minute))
	if _, err := s.C.Coordinator().Admit(ctx, long, bobNodeKey); !errors.Is(err, party.ErrHelloExpiry) || !errors.Is(err, multisig.ErrFirstFrame) {
		t.Fatalf("a long Hello: %v", err)
	}
	// A party that is a coordinator and no signer, on a node key the connection
	// really has, does not get a route either.
	node := party.NodeKey{0xc0, 9}
	co := partyrig.NewWithNode(t, "coonly", s.clock, s.chain, &node)
	s.C.Enroll(co, "coonly", []party.Role{party.RoleCoordinator}, []string{s.bech})
	co.Enroll(s.C, "coord", []party.Role{party.RoleCoordinator}, nil)
	env := s.sealFrom(co, s.C, party.Hello{}, s.clock.Now(), s.clock.Now().Add(time.Minute))
	if _, err := s.C.Coordinator().Admit(ctx, env, node); !errors.Is(err, party.ErrNotAuthorised) || !errors.Is(err, multisig.ErrFirstFrame) {
		t.Fatalf("a Hello from a non-signer: %v", err)
	}
}

// blockingGate holds the first Reauthenticate until released and counts calls.
type blockingGate struct {
	mu      sync.Mutex
	calls   int
	entered chan struct{}
	release chan struct{}
}

func (g *blockingGate) Reauthenticate(context.Context, custody.KeyRef, [32]byte) error {
	g.mu.Lock()
	g.calls++
	first := g.calls == 1
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.release
	}
	return nil
}

func (g *blockingGate) count() int { g.mu.Lock(); defer g.mu.Unlock(); return g.calls }

// Two approvals of one request: the second is refused while the first is at the
// gate, so there is one prompt and one response (N6).
// spec: SPO-Xparty-INV-028, SPO-Xparty-INV-017
func TestConcurrentApprovalsPromptOnceAndAnswerOnce(t *testing.T) {
	s := newScene(t, sceneOpt{})
	a := s.reviewed()
	g := &blockingGate{entered: make(chan struct{}), release: make(chan struct{})}
	sg := s.B.Signer()
	sg.Gate = g
	done := make(chan error, 1)
	go func() { _, err := sg.Approve(ctx, a); done <- err }()
	<-g.entered // the first approval is at the gate
	if _, err := sg.Approve(ctx, a); !errors.Is(err, multisig.ErrNotPending) {
		t.Fatalf("a second approval while the first is at the gate: %v", err)
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if g.count() != 1 {
		t.Fatalf("the operator was prompted %d times", g.count())
	}
	items, _ := s.B.Outbox().Pending(ctx)
	if len(items) != 1 || items[0].Type != string(party.TypeSigningResponse) {
		t.Fatalf("responses queued: %+v", items)
	}
	if _, err := sg.Approve(ctx, a); !errors.Is(err, multisig.ErrNotPending) {
		t.Fatalf("an approval of an answered request: %v", err)
	}
}

// A request left in the signing state by a crash is claimable again after the
// gate timeout and not before (N6).
// spec: SPO-Xparty-INV-028
func TestStaleSigningClaimIsRecoveredAfterTheGateTimeout(t *testing.T) {
	s := newScene(t, sceneOpt{})
	a := s.reviewed()
	// What a crash between the claim and the stored response leaves behind.
	err := s.B.Store.Update(ctx, func(w ports.Writer) error {
		raw, err := w.Get(ports.Ref{Name: "state", Kind: ports.MultisigSigner})
		if err != nil {
			return err
		}
		var st map[string][]map[string]any
		if err := json.Unmarshal(raw, &st); err != nil {
			return err
		}
		st["requests"][0]["state"] = "signing"
		st["requests"][0]["signingSince"] = s.clock.Now().Unix()
		raw, _ = json.Marshal(st)
		return w.Put(ports.Ref{Name: "state", Kind: ports.MultisigSigner}, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	sg := s.B.Signer()
	sg.GateTimeout = 30 * time.Second
	if _, err := sg.Approve(ctx, a); !errors.Is(err, multisig.ErrNotPending) {
		t.Fatalf("a claim inside the gate timeout was taken over: %v", err)
	}
	s.clock.Advance(40 * time.Second)
	if pend, _ := sg.Pending(ctx); len(pend) != 1 {
		t.Fatalf("the stale claim is not listed again: %+v", pend)
	}
	if _, err := sg.Approve(ctx, a); err != nil {
		t.Fatalf("the stale claim was not recovered: %v", err)
	}
	if items, _ := s.B.Outbox().Pending(ctx); len(items) != 1 || items[0].Type != string(party.TypeSigningResponse) {
		t.Fatalf("queued: %+v", items)
	}
}
