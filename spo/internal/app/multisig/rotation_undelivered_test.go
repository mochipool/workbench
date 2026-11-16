package multisig_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func rotations(items []multisig.OutItem) (ids []string) {
	for _, it := range items {
		if it.Type == string(party.TypeRotation) {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

// A second rotation while the first one's announcements wait in the outbox is
// refused and changes nothing: it would replace the identity that sealed them,
// and a peer that has not received them could never accept either. Once they
// are delivered it goes ahead; a delivered announcement is kept sealed for its
// lifetime and can be written again; after the lifetime nothing waits.
//
// spec: SPO-Xparty-IF-008, SPO-Xparty-INV-033
func TestRotateAgainIsRefusedWhileAnnouncementsAreUndelivered(t *testing.T) {
	s := newScene(t, sceneOpt{})
	first := s.B.Rotate("")
	before := rotations(rawOutbox(t, s.B))
	if len(before) != 1 {
		t.Fatalf("announcements %v", before)
	}
	_, err := s.B.Node().RotateIdentity(ctx, "")
	if !errors.Is(err, multisig.ErrRotationUndelivered) {
		t.Fatalf("a second rotation before delivery: %v", err)
	}
	after := rotations(rawOutbox(t, s.B))
	if len(after) != 1 || after[0] != before[0] {
		t.Errorf("the announcements changed: %v -> %v", before, after)
	}
	local, _ := s.B.Kit.Local(ctx)
	if local.Identity().Fingerprint() != first.New {
		t.Error("the identity changed although the rotation was refused")
	}
	local.Destroy()

	// delivered: the next rotation is allowed
	if n, err := s.B.Outbox().Flush(ctx, s.bc.Transport()); err != nil || n != 1 {
		t.Fatalf("flush %d, %v", n, err)
	}
	// a delivered announcement is kept, sealed: it can be written again
	if n, err := s.B.Outbox().RearmRotations(ctx); err != nil || n != 1 {
		t.Fatalf("rearm %d, %v", n, err)
	}
	if got, _ := s.B.Outbox().Pending(ctx); len(rotations(got)) != 1 {
		t.Fatalf("pending after rearm %v", got)
	}
	if _, err := s.B.Node().RotateIdentity(ctx, ""); !errors.Is(err, multisig.ErrRotationUndelivered) {
		t.Fatalf("rearmed announcements wait again: %v", err)
	}
	if _, err := s.B.Outbox().Flush(ctx, s.bc.Transport()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.B.Node().RotateIdentity(ctx, ""); err != nil {
		t.Fatalf("a rotation after delivery: %v", err)
	}
	// after their lifetime they cannot be delivered and no longer hold a rotation back
	s.clock.Advance(8 * 24 * time.Hour)
	if _, err := s.B.Node().RotateIdentity(ctx, ""); err != nil {
		t.Fatalf("a rotation after the announcements expired: %v", err)
	}
}

// walStore is a store with a write-ahead log: it counts the checkpoints asked.
type walStore struct {
	ports.Store
	calls int
	err   error
}

func (w *walStore) CheckpointWAL(context.Context) error { w.calls++; return w.err }

// After a rotation committed, a store that keeps a write-ahead log is asked to
// fold it, so the replaced old keys do not linger in it; a refused rotation
// asks nothing; a failing checkpoint is reported and does not undo the rotation.
//
// spec: SPO-Xparty-IF-008, SPO-Xparty-INV-033
func TestRotationAsksTheStoreToCheckpointItsLog(t *testing.T) {
	s := newScene(t, sceneOpt{})
	ws := &walStore{Store: s.B.Store}
	node := s.B.Node()
	node.Store = ws
	done, err := node.RotateIdentity(ctx, "")
	if err != nil || ws.calls != 1 || !done.Checkpointed || done.CheckpointErr != nil {
		t.Fatalf("calls %d, %+v, %v", ws.calls, done, err)
	}
	// the announcements are undelivered: the next rotation is refused before the store is touched
	if _, err := node.RotateIdentity(ctx, ""); !errors.Is(err, multisig.ErrRotationUndelivered) || ws.calls != 1 {
		t.Fatalf("a refused rotation: %v, checkpoints %d", err, ws.calls)
	}
	if _, err := s.B.Outbox().Flush(ctx, s.bc.Transport()); err != nil {
		t.Fatal(err)
	}
	ws.err = errors.New("log busy")
	done, err = node.RotateIdentity(ctx, "")
	if err != nil || done.Checkpointed || done.CheckpointErr == nil {
		t.Fatalf("a failing checkpoint: %+v, %v", done, err)
	}
}
