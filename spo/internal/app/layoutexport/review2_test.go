package layoutexport_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// B1: with a checkpoint key enrolled, --adopt-layout never overrides a head that
// fails verification, and the key never signs a head chained onto one.
//
// spec: SPO-Xlayout-INV-022
func TestAdoptLayoutNeverOverridesTheKey(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.withKey()
	w.mustRun() // head 1, signed
	_, n1 := newestHead(t, w.dir)
	w.plantHead(2, func(h *layout.Head) { h.Previous = layout.HeadHash(n1) }) // forged, unsigned, linked
	x := w.fork()
	x.dir, x.keys = w.dir, w.keys
	x.adopt = true
	signs := w.sk.Signs
	heads := len(w.dir.names("heads/"))
	err := wantRefusal(t, x, "a forged head under a key with --adopt-layout", layout.HeadPath(2), "fresh directory")
	if strings.Contains(err.Error(), "--adopt-layout") {
		t.Errorf("the refusal suggests the flag: %v", err)
	}
	if w.sk.Signs != signs || len(w.dir.names("heads/")) != heads {
		t.Errorf("the key signed (%d) or a head was written", w.sk.Signs-signs)
	}
	// with no key the flag still works
	n := newWorld(t, "standard", 3)
	n.mustRun()
	m := n.fork()
	m.dir, m.adopt = n.dir, true
	if res, err := m.run(); err != nil || !res.Adopted {
		t.Fatalf("%+v %v", res, err)
	}
}

// S1: every head the new head builds on must be this workspace's history.
//
// spec: SPO-Xlayout-INV-023
func TestEveryHeadOfTheChainMustBeThisWorkspacesHistory(t *testing.T) {
	setup := func(withKey bool) (*world, *world) {
		w := newWorld(t, "standard", 3)
		if withKey {
			w.withKey()
		}
		w.mustRun()
		w.change(0)
		w.mustRun() // heads 1 and 2
		d := w.fork()
		d.audit[3].MAC = bytes.Repeat([]byte{0x42}, 32) // diverged at the sequence of head 1; the last row is the same
		return w, d
	}
	// a pin, no key: head 1 is the pinned head and is checked too
	w, d := setup(false)
	_, n1 := newestHead(t, w.dir)
	_ = n1
	d.dir = w.dir
	d.pins = &memPins{pin: &ports.LayoutPin{Sequence: 1, HeadHash: layout.HeadHash(w.dir.objs[layout.HeadPath(1)])}}
	wantRefusal(t, d, "a diverged workspace, pin, no key", layout.HeadPath(1), "not the same workspace history")
	// --adopt-layout, no key
	w, d = setup(false)
	d.dir, d.adopt = w.dir, true
	wantRefusal(t, d, "a diverged workspace, adopted", layout.HeadPath(1), "not the same workspace history")
	// every head verifies against the key, and the workspace diverged
	w, d = setup(true)
	d.dir = w.dir
	wantRefusal(t, d, "a diverged workspace, verified by the key", layout.HeadPath(1), "not the same workspace history")
	// a head whose recovery key is not the workspace's (no rollover since)
	r := newWorld(t, "standard", 3)
	r.mustRun()
	r.plantHead(1, func(h *layout.Head) { h.RecoveryKey = bytes.Repeat([]byte{4}, 32) })
	r.pins, r.adopt = &memPins{}, true
	wantRefusal(t, r, "another recovery key", layout.HeadPath(1), "not the same workspace history")
	e := newWorld(t, "standard", 3)
	e.mustRun()
	e.plantHead(1, func(h *layout.Head) { h.Epoch = bytes.Repeat([]byte{6}, 16) })
	e.pins, e.adopt = &memPins{}, true
	wantRefusal(t, e, "another epoch", layout.HeadPath(1), "not the same workspace history")
}

// the layout is ahead: the wording depends on whether the key vouches for it
//
// spec: SPO-Xlayout-PRE-016
func TestTheAheadMessageSaysWhatIsKnown(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.withKey()
	w.change(0)
	w.mustRun()
	old := newWorld(t, "standard", 3)
	old.dir, old.keys, old.keyRec, old.signing, old.sk = w.dir, w.keys, w.keyRec, w.signing, w.sk
	old.pins = &memPins{} // every head verifies against the key
	err := wantRefusal(t, old, "an older workspace", "older than what was exported")
	if strings.Contains(err.Error(), "cannot vouch") {
		t.Errorf("claims it cannot vouch for a head the key signed: %v", err)
	}
	n := newWorld(t, "standard", 3)
	n.mustRun()
	_, n1 := newestHead(t, n.dir)
	n.plantHead(2, func(h *layout.Head) { h.Previous = layout.HeadHash(n1); h.AuditSeq = 999 })
	wantRefusal(t, n, "a head no key vouches for", "cannot vouch")
}

// S2: a crash between a head and its signature is completed by the re-run, under
// exactly the stated conditions.
//
// spec: SPO-Xlayout-OUT-019
func TestACrashBetweenAHeadAndItsSignatureIsCompleted(t *testing.T) {
	crash := func() *world {
		w := newWorld(t, "standard", 3)
		w.withKey()
		w.mustRun() // head 1 signed, pin 1
		w.change(1)
		w.dir.putHook = func(_ int, name string) error {
			if name == layout.HeadPath(2)+".sig" {
				return errors.New("input/output error")
			}
			return nil
		}
		_, err := w.run()
		if err == nil || !strings.Contains(err.Error(), "run the command again") {
			t.Fatalf("the interrupted run: %v", err)
		}
		w.dir.putHook = nil
		if w.pins.pin.Sequence != 1 || w.headCount() != 2 {
			t.Fatalf("pin %d heads %d", w.pins.pin.Sequence, w.headCount())
		}
		return w
	}
	w := crash()
	signs := w.sk.Signs
	w.dir.resetPuts()
	res, err := w.run()
	if err != nil || !res.UpToDate || !res.SignedNow || !res.Signed || res.HeadSequence != 2 || w.pins.pin.Sequence != 2 || w.sk.Signs != signs+1 {
		t.Fatalf("%+v %v", res, err)
	}
	if w.dir.putCount() != 1 || w.dir.puts[0] != layout.HeadPath(2)+".sig" {
		t.Errorf("puts %v", w.dir.puts)
	}
	// and a following run builds on it
	w.change(0)
	if r, err := w.run(); err != nil || r.HeadSequence != 3 {
		t.Fatalf("%+v %v", r, err)
	}

	refuse := func(name string, mutate func(w *world), contains ...string) {
		t.Helper()
		x := crash()
		mutate(x)
		wantRefusal(t, x, name, contains...)
		if x.sk.Signs != 1+1 {
			// head 1's signature and head 2's attempt (made before the put failed)
			t.Errorf("%s: the key signed again (%d)", name, x.sk.Signs)
		}
	}
	refuse("the workspace changed since the crash", func(x *world) { x.change(2) }, "changed since", "fresh directory")
	refuse("no pin", func(x *world) { x.pins = &memPins{} }, "fresh directory")
	refuse("a signature file that does not verify", func(x *world) { x.dir.objs[layout.HeadPath(2)+".sig"] = []byte("garbage") }, layout.HeadPath(2))
	refuse("the head names no key", func(x *world) {
		x.plantHead(2, func(h *layout.Head) { h.CheckpointKey = nil })
	}, "fresh directory")
	refuse("the head is dated in the future", func(x *world) {
		x.plantHead(2, func(h *layout.Head) { h.Time = x.clock.Add(time.Hour) })
	}, "fresh directory")
	refuse("the head is dated before the pinned one", func(x *world) {
		x.plantHead(2, func(h *layout.Head) { h.Time = x.clock.Add(-48 * time.Hour) })
	}, "fresh directory")
	refuse("--no-checkpoint", func(x *world) { x.signing = nil }, "fresh directory")
	// two unsigned heads above the pin
	x := crash()
	x.plantHead(3, nil)
	wantRefusal(t, x, "two unsigned heads", "fresh directory")
}

// (a) the adopt notice carries the audit sequence and comes before the pin is recorded
//
// spec: SPO-Xlayout-PRE-019
func TestTheAdoptNoticeNamesTheAuditSequenceAndComesBeforeThePin(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.mustRun()
	x := w.fork()
	x.dir = w.dir
	var said []string
	var pinWritesAtNotice = -1
	x.notify = func(m string) { said = append(said, m); pinWritesAtNotice = x.pins.writes }
	err := wantRefusal(t, x, "no flag", "audit sequence 4")
	_ = err
	x.adopt = true
	if _, err := x.run(); err != nil {
		t.Fatal(err)
	}
	if len(said) != 1 || !strings.Contains(said[0], "audit sequence 4") || pinWritesAtNotice != 0 {
		t.Errorf("notice %q, pin writes at the notice %d", said, pinWritesAtNotice)
	}
}

// M06 and M17: a first head with a previous hash, and the two refusals of the pin.
//
// spec: SPO-Xlayout-INV-020
func TestAFirstHeadWithAPreviousHashAndThePinsRefusalsAreNamed(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.mustRun()
	note := w.dir.objs[layout.HeadPath(1)]
	bad := bytes.Replace(note, []byte("previous "+strings.Repeat("0", 64)), []byte("previous "+strings.Repeat("a", 64)), 1)
	if bytes.Equal(bad, note) {
		t.Fatal("setup")
	}
	w.dir.objs[layout.HeadPath(1)] = bad
	x := w.fork()
	x.dir, x.adopt = w.dir, true
	wantRefusal(t, x, "a first head with a previous hash", layout.HeadPath(1), "not a valid head")

	// the pin names a sequence that is not there: a rollback, said as such
	r := newWorld(t, "standard", 3)
	r.mustRun()
	r.pins.pin = &ports.LayoutPin{Sequence: 5, HeadHash: bytes.Repeat([]byte{1}, 32)}
	if _, err := r.run(); !errors.Is(err, layoutexport.ErrRolledBack) {
		t.Errorf("%v", err)
	}
	// the pinned head is missing and a later one is there
	m := newWorld(t, "standard", 3)
	m.mustRun()
	m.change(0)
	m.mustRun()
	h1 := layout.HeadHash(m.dir.objs[layout.HeadPath(1)])
	delete(m.dir.objs, layout.HeadPath(1))
	m.pins.pin = &ports.LayoutPin{Sequence: 1, HeadHash: h1}
	if _, err := m.run(); !errors.Is(err, layoutexport.ErrRolledBack) {
		t.Errorf("%v", err)
	}
}
