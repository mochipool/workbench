package multisig_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// closeAndDeliver has the coordinator close the collection and carries the
// notice to bob.
func (s *scene) closeAndDeliver(outcome party.Outcome) []multisig.Handled {
	s.t.Helper()
	if err := s.C.Coordinator().Close(ctx, s.ref, outcome, [32]byte{}); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil {
		s.t.Fatal(err)
	}
	return s.bobHandles()
}

// A collection that ends gets a signed notice to the parties that were asked.
// The signer marks its request closed: it is no longer listed as waiting, it
// is listed as closed, review and approve refuse it by name of the outcome, and
// the notice made the signer do nothing else: no key was asked for, nothing
// was queued.
//
// spec: SPO-Xparty-INV-035, SPO-Xparty-INV-036
func TestClosedNoticeClosesTheRequestAndNothingMore(t *testing.T) {
	for _, outcome := range []party.Outcome{party.OutcomeDiscarded, party.OutcomeExpired} {
		t.Run(string(outcome), func(t *testing.T) {
			s := newScene(t, sceneOpt{})
			s.request()
			s.bobHandles()
			pend, _ := s.B.Signer().Pending(ctx)
			if len(pend) != 1 {
				t.Fatalf("pending %v", pend)
			}
			// The operator has already reviewed it when the notice arrives, so an
			// approval token exists.
			rv, err := s.B.Signer().ReviewRequest(ctx, pend[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			hs := s.closeAndDeliver(outcome)
			if len(hs) != 1 || hs[0].Refused || hs[0].Effect != "closed" {
				t.Fatalf("handled = %+v", hs)
			}
			if got, _ := s.B.Signer().Pending(ctx); len(got) != 0 {
				t.Errorf("still listed as waiting: %+v", got)
			}
			closed, _ := s.B.Signer().Closed(ctx)
			if len(closed) != 1 || closed[0].Outcome != string(outcome) || closed[0].ID != pend[0].ID {
				t.Fatalf("closed = %+v", closed)
			}
			// Review refuses, naming the outcome.
			_, err = s.B.Signer().ReviewRequest(ctx, pend[0].ID)
			var ce multisig.ClosedError
			if !errors.As(err, &ce) || ce.Outcome != string(outcome) || !errors.Is(err, multisig.ErrRequestClosed) || !errors.Is(err, multisig.ErrNotPending) ||
				!strings.Contains(err.Error(), "("+string(outcome)+")") || !strings.Contains(err.Error(), "nothing was signed") {
				t.Fatalf("review of a closed request: %v", err)
			}
			// Approve, with the review taken before the notice, refuses too, before
			// the operator is asked to authenticate and before the key is touched.
			a, err := rv.Approval()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.B.Signer().Approve(ctx, a); !errors.Is(err, multisig.ErrRequestClosed) {
				t.Fatalf("approve of a closed request: %v", err)
			}
			if s.B.Gate.Count() != 0 {
				t.Error("the operator was asked to authenticate for a closed request")
			}
			// Nothing was queued by the notice or by the refused approval.
			if items := outboxOf(t, s.B); len(items) != 0 {
				t.Errorf("bob queued %+v", items)
			}
			if !eventWith(events(s.B), "collection-closed") {
				t.Error("no event")
			}
		})
	}
}

// A notice cannot be used to make a signer sign: it never reaches the signing
// path, and a closed request stays unsigned.
//
// spec: SPO-Xparty-INV-035
func TestClosedNoticeNeverCausesASignature(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	s.closeAndDeliver(party.OutcomeSubmitted) // a submission naming the body hash
	if s.B.Gate.Count() != 0 || len(outboxOf(t, s.B)) != 0 {
		t.Errorf("a notice made bob act: gate %d, outbox %v", s.B.Gate.Count(), outboxOf(t, s.B))
	}
}

// Forged, misdirected and replayed notices are dropped with an event and change
// nothing: from a coordinator that never asked, about a collection nobody asked
// about, repeated, or from a party that is not a coordinator.
//
// spec: SPO-Xparty-INV-037
func TestForgedAndReplayedClosedNoticesAreDropped(t *testing.T) {
	s := newScene(t, sceneOpt{})
	// xavier is another coordinator bob has enrolled, who never asked bob anything
	s.B.Enroll(s.X, "xav-coord", []party.Role{party.RoleCoordinator}, []string{s.bech})
	s.X.Enroll(s.B, "bob", []party.Role{party.RoleSigner}, []string{s.bech})
	s.request()
	s.bobHandles()
	deliver := func(env []byte) multisig.Handled {
		t.Helper()
		h, err := s.B.Signer().Handle(ctx, partyrigReceived(env))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	still := func(why string) {
		t.Helper()
		if got, _ := s.B.Signer().Pending(ctx); len(got) != 1 {
			t.Fatalf("%s: the request is no longer pending", why)
		}
	}
	// wrong collector
	wrong := s.sealFrom(s.X, s.B, party.CollectionClosed{Collection: s.cid(), Outcome: party.OutcomeDiscarded}, s.clock.Now(), s.clock.Now().Add(time.Hour))
	mustRefuse(t, deliver(wrong), "no request of that coordinator")
	still("wrong collector")
	// unknown collection
	unknown := s.sealFrom(s.C, s.B, party.CollectionClosed{Collection: party.CollectionID{9, 9}, Outcome: party.OutcomeDiscarded}, s.clock.Now(), s.clock.Now().Add(time.Hour))
	mustRefuse(t, deliver(unknown), "no request of that coordinator")
	still("unknown collection")
	// a submission naming another transaction
	wrongTx := s.sealFrom(s.C, s.B, party.CollectionClosed{Collection: s.cid(), Outcome: party.OutcomeSubmitted, TxID: make([]byte, 32)}, s.clock.Now(), s.clock.Now().Add(time.Hour))
	mustRefuse(t, deliver(wrongTx), "not the body hash")
	still("wrong transaction id")
	if !eventWith(events(s.B), "message-refused") {
		t.Error("no refusal event")
	}
	// a genuine notice, then the same envelope again
	genuine := s.sealFrom(s.C, s.B, party.CollectionClosed{Collection: s.cid(), Outcome: party.OutcomeDiscarded}, s.clock.Now(), s.clock.Now().Add(time.Hour))
	if h := deliver(genuine); h.Refused || h.Effect != "closed" {
		t.Fatalf("the genuine notice: %+v", h)
	}
	if h := deliver(genuine); !h.Refused {
		t.Fatalf("a replayed notice: %+v", h)
	}
	// the first outcome stays when a different one arrives afterwards
	later := s.sealFrom(s.C, s.B, party.CollectionClosed{Collection: s.cid(), Outcome: party.OutcomeExpired}, s.clock.Now(), s.clock.Now().Add(time.Hour))
	if h := deliver(later); h.Refused {
		t.Fatalf("a second notice: %+v", h)
	}
	if closed, _ := s.B.Signer().Closed(ctx); len(closed) != 1 || closed[0].Outcome != "discarded" {
		t.Errorf("closed = %+v", closed)
	}
}

func partyrigReceived(env []byte) ports.Received { return ports.FileReceived(env) }

// A party that is not a coordinator cannot close anything.
//
// spec: SPO-Xparty-INV-037, SPO-Xparty-INV-010
func TestClosedNoticeFromANonCoordinatorIsRefused(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.B.Enroll(s.X, "xav-signer", []party.Role{party.RoleSigner}, []string{s.bech})
	s.X.Enroll(s.B, "bob", []party.Role{party.RoleSigner}, []string{s.bech})
	s.request()
	s.bobHandles()
	env := s.sealFrom(s.X, s.B, party.CollectionClosed{Collection: s.cid(), Outcome: party.OutcomeDiscarded}, s.clock.Now(), s.clock.Now().Add(time.Hour))
	h, err := s.B.Signer().Handle(ctx, ports.FileReceived(env))
	if err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, h, "not a coordinator")
	if got, _ := s.B.Signer().Pending(ctx); len(got) != 1 {
		t.Error("the request was closed by a party that is not a coordinator")
	}
}

// The coordinator announces a collection that ended without saying so: one whose
// TTL slot has passed is Expired, and the signers it asked get the notice at
// the next sweep (SPO-Xparty-INV-035).
//
// spec: SPO-Xparty-INV-035, SPO-Xparty-INV-015, SPO-Xconfirm-PR-007
func TestSweepAnnouncesAnExpiredCollection(t *testing.T) {
	s := newScene(t, sceneOpt{})
	s.request()
	s.bobHandles()
	s.chain.SetSlot(s.ttl + 1)
	got, err := s.C.Coordinator().Sweep(ctx)
	if err != nil || len(got) != 1 {
		t.Fatalf("sweep: %v, %v", got, err)
	}
	var notices int
	for _, it := range outboxOf(t, s.C) {
		if it.Type == string(party.TypeCollectionClosed) {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("%d notices queued for bob", notices)
	}
	// a second sweep announces nothing again
	if got, _ := s.C.Coordinator().Sweep(ctx); len(got) != 0 {
		t.Errorf("a closed collection was announced again: %v", got)
	}
}

// A registration the pool command submitted (the descriptor records a
// submission after the request and the collection is cleared) is announced as
// submitted, with the transaction id the signer was asked to sign; a collection
// that is simply gone is announced as discarded, and so is one that was replaced
// by another collection whose transaction the pool command then submitted: the
// pool command records the id of what it submitted, and "submitted" needs it to
// be the collection's own body id.
//
// spec: SPO-Xparty-INV-035, SPO-Xparty-INV-015, SPO-Xconfirm-PR-007
func TestSweepTellsASubmissionFromADiscard(t *testing.T) {
	// "pending" modes: the registration was sent and waits for its confirmation,
	// so the descriptor records no submission yet (hazard H9); the pending
	// update under the body's transaction id is the proof.
	for _, mode := range []string{"submitted", "queued", "discarded", "replaced", "pending", "pending-queued", "pending-other"} {
		pending := strings.HasPrefix(mode, "pending")
		submitted := mode != "discarded" && !pending
		name := mode
		want := mode
		switch mode {
		case "replaced", "pending-other":
			want = "discarded"
		case "pending":
			want = "submitted"
		case "pending-queued":
			want = "queued"
		}
		t.Run(name, func(t *testing.T) {
			s := newScene(t, sceneOpt{})
			// the scene's collection is a pool's: keep it under a pool descriptor
			ref := ports.Ref{Name: s.ref.Name, Kind: ports.MultisigCollection}
			var raw []byte
			if err := s.C.Store.View(ctx, func(r ports.Reader) error { var err error; raw, err = r.Get(ref); return err }); err != nil {
				t.Fatal(err)
			}
			poolRef := ports.Ref{Name: "mypool", Kind: ports.PoolDescriptor}
			if err := s.C.Store.Update(ctx, func(w ports.Writer) error { return w.Put(poolRef, raw) }); err != nil {
				t.Fatal(err)
			}
			s.ref = multisig.CollectionRef{Kind: multisig.KindPool, Name: "mypool"}
			s.request()
			s.bobHandles()
			if err := s.C.Store.Update(ctx, func(w ports.Writer) error {
				b, err := w.Get(poolRef)
				if err != nil {
					return err
				}
				d, err := pool.ParseDescriptor(b)
				if err != nil {
					return err
				}
				if submitted {
					stamp := s.clock.Now().Add(time.Minute).Format(time.RFC1123Z)
					if mode == "queued" {
						stamp += " (only offline, no proof)" // queued offline, never sent: announced as queued
					}
					d.RecordSubmission("5", stamp)
					id := s.body.ID
					if mode == "replaced" {
						id[0] ^= 0xff // another transaction was submitted for the pool
					}
					if err := w.Put(ports.Ref{Name: "mypool", Kind: ports.MultisigSubmitted}, []byte(hex.EncodeToString(id[:]))); err != nil {
						return err
					}
				} else {
					d.ClearCollection()
				}
				if pending {
					id := s.body.ID
					if mode == "pending-other" {
						id[0] ^= 0xff
					}
					p := assets.Pending{Kind: assets.PendingPoolRegistration, TxID: hex.EncodeToString(id[:]), Pool: "mypool", Epoch: "5", Stamp: "x", Queued: mode == "pending-queued"}
					pb, _ := p.Marshal()
					if err := w.Put(ports.Ref{Name: p.TxID, Kind: ports.PendingUpdate}, pb); err != nil {
						return err
					}
				}
				return w.Put(poolRef, d.Render())
			}); err != nil {
				t.Fatal(err)
			}
			got, err := s.C.Coordinator().Sweep(ctx)
			if err != nil || len(got) != 1 {
				t.Fatalf("sweep: %v, %v", got, err)
			}
			if _, err := s.C.Outbox().Flush(ctx, s.cb.Transport()); err != nil {
				t.Fatal(err)
			}
			hs := s.bobHandles()
			if len(hs) != 1 || hs[0].Refused || hs[0].Effect != "closed" {
				t.Fatalf("handled = %+v", hs)
			}
			closed, _ := s.B.Signer().Closed(ctx)
			if len(closed) != 1 || closed[0].Outcome != want {
				t.Fatalf("closed = %+v, want %s", closed, want)
			}
		})
	}
}
