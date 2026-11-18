package layoutexport_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- helpers ----

func objPath(name string) string { p, _ := layout.ObjectPath(name); return p }

// flip replaces an object with bytes of the same size and another content.
func (w *world) flip(path string) {
	b := append([]byte(nil), w.dir.objs[path]...)
	b[len(b)/2] ^= 0xff
	w.dir.objs[path] = b
}

// namesByKind opens the directory with the keys and says which object is which.
func (w *world) namesByKind() map[string][]string {
	o := w.openAll(w.dir, w.epoch)
	out := map[string][]string{}
	for n := range o.records {
		out["record"] = append(out["record"], n)
	}
	for n := range o.audit {
		out["audit"] = append(out["audit"], n)
	}
	for n := range o.rpages {
		out["record page"] = append(out["record page"], n)
	}
	for n := range o.apages {
		out["audit page"] = append(out["audit page"], n)
	}
	for n := range o.roots {
		out["root"] = append(out["root"], n)
	}
	for n := range o.slots {
		out["slots"] = append(out["slots"], n)
	}
	return out
}

// plantHead writes a head note of this workspace at seq, made from the newest
// head with mutate applied. It returns the hash of the note.
func (w *world) plantHead(seq uint64, mutate func(*layout.Head)) []byte {
	h, _ := newestHead(w.t, w.dir)
	h.Sequence = seq
	if mutate != nil {
		mutate(&h)
	}
	note, err := h.Encode()
	if err != nil {
		w.t.Fatal(err)
	}
	w.dir.objs[layout.HeadPath(seq)] = note
	return layout.HeadHash(note)
}

func (w *world) headCount() int {
	n := 0
	for _, p := range w.dir.names("heads/") {
		if !strings.HasSuffix(p, ".sig") {
			n++
		}
	}
	return n
}

func wantRefusal(t *testing.T, w *world, what string, contains ...string) error {
	t.Helper()
	res, err := w.run()
	if err == nil {
		t.Fatalf("%s: accepted: %+v", what, res)
	}
	for _, c := range contains {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("%s: the refusal lacks %q: %v", what, c, err)
		}
	}
	return err
}

// ---- B1: an object that is there is read, not believed ----

// The two scenarios of the review: every object of a layout replaced by bytes of
// the same size. An unchanged run said "up to date", and a changed one wrote a head
// that named thirteen objects that did not hash to their names.
//
// spec: SPO-Xlayout-INV-018
func TestAnObjectThatIsThereIsReadAndHashedNotBelieved(t *testing.T) {
	for _, changed := range []bool{false, true} {
		w := newWorld(t, "standard", 3)
		w.mustRun()
		for _, p := range w.dir.names("objects/") {
			w.flip(p)
		}
		if changed {
			w.change(1)
		}
		heads := w.headCount()
		res, err := w.run()
		if err == nil || res.UpToDate || !strings.Contains(err.Error(), "wrong content") || !strings.Contains(err.Error(), "fresh directory") {
			t.Fatalf("changed=%v: %+v %v", changed, res, err)
		}
		if w.headCount() != heads {
			t.Errorf("changed=%v: a head was written", changed)
		}
	}
}

// Each kind of object, corrupted alone, truncated or padded under its valid name.
//
// spec: SPO-Xlayout-INV-018
func TestEachKindOfObjectIsVerifiedWhenReused(t *testing.T) {
	probe := newWorld(t, "standard", 3)
	probe.mustRun()
	kinds := probe.namesByKind()
	for kind := range kinds {
		for _, damage := range []string{"flipped", "truncated", "oversized"} {
			w := newWorld(t, "standard", 3)
			w.mustRun()
			names := w.namesByKind()[kind]
			path := objPath(names[0])
			switch damage {
			case "flipped":
				w.flip(path)
			case "truncated":
				w.dir.objs[path] = w.dir.objs[path][:len(w.dir.objs[path])-1]
			case "oversized":
				w.dir.objs[path] = append(append([]byte(nil), w.dir.objs[path]...), 0)
			}
			damaged := append([]byte(nil), w.dir.objs[path]...)
			wantRefusal(t, w, kind+" "+damage, "wrong content", names[0][:16])
			if !bytes.Equal(w.dir.objs[path], damaged) {
				t.Errorf("%s %s: the object was overwritten", kind, damage)
			}
			if w.headCount() != 1 {
				t.Errorf("%s %s: a head was written", kind, damage)
			}
		}
	}
}

// ---- S1: a signature is believed only when it verifies ----

// spec: SPO-Xlayout-INV-019
func TestASignatureFileIsNotBelievedByExistence(t *testing.T) {
	// garbage in heads/…1.sig of a head, with a key enrolled: never "signed"
	w := newWorld(t, "standard", 3)
	w.mustRun()
	w.dir.objs[layout.HeadPath(1)+".sig"] = []byte("garbage")
	res, err := w.run()
	if err != nil || res.Signed || res.SignedNow {
		t.Fatalf("no key: %+v %v", res, err)
	}
	w.withKey()
	res, err = w.run()
	if err == nil || res.Signed || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a key and a garbage signature: %+v %v", res, err)
	}
	if w.sk.Signs != 0 {
		t.Error("the key signed over a name that is taken")
	}
	// a stray signature at the next sequence blocks the directory with advice that works
	w2 := newWorld(t, "standard", 3)
	w2.mustRun()
	w2.dir.objs[layout.HeadPath(2)+".sig"] = []byte("garbage")
	w2.change(1)
	err = wantRefusal(t, w2, "a stray signature", layout.HeadPath(2)+".sig", "fresh directory")
	if strings.Contains(err.Error(), "run the command again") || strings.Contains(err.Error(), "can be run again") {
		t.Errorf("advice that cannot work: %v", err)
	}
	// a real signature is counted, from verification
	w3 := newWorld(t, "standard", 3)
	w3.withKey()
	w3.mustRun()
	res, err = w3.run()
	if err != nil || !res.UpToDate || !res.Signed || res.SignedNow {
		t.Fatalf("%+v %v", res, err)
	}
	// the same signature under another key is not
	w4 := newWorld(t, "standard", 3)
	w4.withKey()
	w4.mustRun()
	other := newWorld(t, "standard", 3)
	other.withKey()
	w4.keyRec = other.keyRec
	w4.signing = nil
	res, err = w4.run()
	if err != nil || res.Signed {
		t.Fatalf("a signature by another key counted: %+v %v", res, err)
	}
}

// ---- S2: heads this machine did not write ----

// spec: SPO-Xlayout-INV-020
func TestPlantedHeadsAreNotChainedOnto(t *testing.T) {
	// the pin is at 1; heads 50 and 51 are planted
	w := newWorld(t, "standard", 3)
	w.mustRun()
	h50 := w.plantHead(50, func(h *layout.Head) { h.Previous = bytes.Repeat([]byte{9}, 32) })
	w.plantHead(51, func(h *layout.Head) { h.Previous = h50 })
	w.change(1)
	w.unlocks = 0
	err := wantRefusal(t, w, "planted heads", layout.HeadPath(50), "this machine did not write", "fresh directory")
	if strings.Contains(err.Error(), "rolled back") {
		t.Errorf("blames a rollback: %v", err)
	}
	if w.pins.pin.Sequence != 1 {
		t.Errorf("the pin moved to %d", w.pins.pin.Sequence)
	}
	if w.headCount() != 3 || w.unlocks != 0 {
		t.Errorf("heads %d unlocks %d", w.headCount(), w.unlocks)
	}

	// a gap
	g := newWorld(t, "standard", 3)
	g.mustRun()
	g.change(0)
	g.mustRun() // head 2
	_, n2 := newestHead(t, g.dir)
	g.plantHead(4, func(h *layout.Head) { h.Previous = layout.HeadHash(n2) })
	wantRefusal(t, g, "a gap", layout.HeadPath(4))

	// a broken link (the checkChain mutant)
	b := newWorld(t, "standard", 3)
	b.mustRun()
	b.plantHead(2, func(h *layout.Head) { h.Previous = bytes.Repeat([]byte{7}, 32) })
	wantRefusal(t, b, "a broken link", layout.HeadPath(2))

	// a head of another workspace in the chain
	o := newWorld(t, "standard", 3)
	o.mustRun()
	_, n1 := newestHead(t, o.dir)
	o.plantHead(2, func(h *layout.Head) { h.Previous = layout.HeadHash(n1); h.Workspace = bytes.Repeat([]byte{5}, 16) })
	wantRefusal(t, o, "another workspace", "another workspace")

	// the pinned head is not the one the pin names
	p := newWorld(t, "standard", 3)
	p.mustRun()
	p.change(0)
	p.mustRun()
	p.pins.pin = &ports.LayoutPin{Sequence: 1, HeadHash: bytes.Repeat([]byte{3}, 32)}
	wantRefusal(t, p, "a pinned head that was replaced", "pin")

	// with a key enrolled, an unsigned head above the pin is not chained onto
	k := newWorld(t, "standard", 3)
	k.withKey()
	k.mustRun()
	_, n1 = newestHead(t, k.dir)
	k.plantHead(2, func(h *layout.Head) { h.Previous = layout.HeadHash(n1); h.AuditSeq = 999 })
	err = wantRefusal(t, k, "a forged head with a high audit sequence", layout.HeadPath(2), "cannot vouch")
	if strings.Contains(err.Error(), "rolled back") {
		t.Errorf("blames a rollback: %v", err)
	}
	if k.sk.Signs != 1 {
		t.Errorf("the key signed (%d)", k.sk.Signs)
	}

	// without a key a linked head cannot be told from ours; the message does not
	// claim the workspace was rolled back
	n := newWorld(t, "standard", 3)
	n.mustRun()
	_, n1 = newestHead(t, n.dir)
	n.plantHead(2, func(h *layout.Head) { h.Previous = layout.HeadHash(n1); h.AuditSeq = 999 })
	err = wantRefusal(t, n, "ahead", "cannot vouch")
	if strings.Contains(err.Error(), "rolled back") {
		t.Errorf("asserts a rollback: %v", err)
	}
}

// The newest head's manifest and slots objects are read before anything is asked.
//
// spec: SPO-Xlayout-INV-018
func TestTheNewestHeadsManifestAndSlotsAreVerifiedBeforeAnyPrompt(t *testing.T) {
	for _, kind := range []string{"root", "slots"} {
		for _, damage := range []string{"missing", "flipped"} {
			w := newWorld(t, "standard", 3)
			w.mustRun()
			path := objPath(w.namesByKind()[kind][0])
			if damage == "missing" {
				delete(w.dir.objs, path)
			} else {
				w.flip(path)
			}
			w.unlocks = 0
			wantRefusal(t, w, kind+" "+damage, "newest head")
			if w.unlocks != 0 {
				t.Errorf("%s %s: unlocked", kind, damage)
			}
		}
	}
}

// A sequence number near the top of 64 bits is refused, not wrapped.
//
// spec: SPO-Xlayout-INV-020
func TestHeadSequenceOverflowIsRefused(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.mustRun()
	for _, seq := range []uint64{1 << 40, 18446744073709551615} {
		x := newWorld(t, "standard", 3)
		x.mustRun()
		x.plantHead(seq, func(h *layout.Head) { h.Previous = bytes.Repeat([]byte{1}, 32) })
		wantRefusal(t, x, fmt.Sprint(seq), "out of range")
	}
	x := newWorld(t, "standard", 3)
	x.mustRun()
	x.dir.objs["heads/99999999999999999999"] = []byte("x")
	wantRefusal(t, x, "20 digits beyond 64 bits", "out of range")
}

// ---- S3: only a note this run built is signed ----

// spec: SPO-Xlayout-INV-021
func TestAnExistingUnsignedHeadIsSignedOnlyWhenItIsWhatTheWorkspaceWouldGet(t *testing.T) {
	// the unsigned head is the pinned one (written when no key was enrolled)
	for name, c := range map[string]struct {
		mutate func(*layout.Head)
		want   string
	}{
		"recovery-key":   {func(h *layout.Head) { h.RecoveryKey = bytes.Repeat([]byte{4}, 32) }, "not the same workspace history"},
		"checkpoint-key": {func(h *layout.Head) { h.CheckpointKey = bytes.Repeat([]byte{5}, 32) }, "differs from the workspace"},
		"epoch":          {func(h *layout.Head) { h.Epoch = bytes.Repeat([]byte{6}, 16) }, "not the same workspace history"},
	} {
		w := newWorld(t, "standard", 3)
		w.mustRun()
		h := w.plantHead(1, c.mutate)
		w.pins = &memPins{pin: &ports.LayoutPin{Sequence: 1, HeadHash: h}}
		w.withKey()
		wantRefusal(t, w, name, c.want)
		if w.sk.Signs != 0 {
			t.Errorf("%s: the key signed a note this run did not build", name)
		}
		if _, ok := w.dir.objs[layout.HeadPath(1)+".sig"]; ok {
			t.Errorf("%s: a signature was put", name)
		}
	}
	// a head that is what the workspace would get, differing only in time, is signed
	w := newWorld(t, "standard", 3)
	w.mustRun()
	w.withKey()
	w.clock = w.clock.Add(48 * time.Hour)
	res, err := w.run()
	if err != nil || !res.SignedNow {
		t.Fatalf("%+v %v", res, err)
	}
}

// ---- S4: no pin, a layout that already has heads ----

// spec: SPO-Xlayout-PRE-019
func TestAnExistingLayoutWithoutAPinIsNotTrustedSilently(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.mustRun()
	// no key, no --adopt-layout
	fresh := newWorld(t, "standard", 3)
	fresh.dir, fresh.keys = w.dir, w.keys
	err := wantRefusal(t, fresh, "no pin, no key", "--adopt-layout", "sequence 1")
	_ = err
	if fresh.pins.pin != nil {
		t.Error("a pin was recorded")
	}
	// the operator's statement
	fresh.adopt = true
	res, err := fresh.run()
	if err != nil || !res.UpToDate || fresh.pins.pin == nil {
		t.Fatalf("%+v %v", res, err)
	}
	if !res.Adopted {
		t.Error("the result does not say the layout was adopted")
	}

	// a key is enrolled and every head verifies against it: proceeds and says so
	k := newWorld(t, "standard", 3)
	k.withKey()
	k.mustRun()
	k.change(0)
	k.mustRun()
	k2 := newWorld(t, "standard", 3)
	k2.dir, k2.keys = k.dir, k.keys
	k2.keyRec, k2.signing, k2.sk = k.keyRec, k.signing, k.sk
	k2.records, k2.refs, k2.audit = k.records, k.refs, k.audit
	res, err = k2.run()
	if err != nil || !res.UpToDate || !res.AdoptedByKey || k2.pins.pin == nil || k2.pins.pin.Sequence != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// a key is enrolled and a head does not verify
	u := newWorld(t, "standard", 3)
	u.mustRun() // unsigned
	u2 := newWorld(t, "standard", 3)
	u2.dir, u2.keys = u.dir, u.keys
	u2.withKey()
	wantRefusal(t, u2, "an unsigned head under a key", layout.HeadPath(1))
}

// ---- S5: checks whose removal no test noticed ----

// spec: SPO-Xlayout-INV-011
func TestTheSlotSetHashOfTheNewestSlotsRowMustMatchAndOneMustExist(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.audit[0].SlotSet = bytes.Repeat([]byte{1}, 32)
	wantRefusal(t, w, "a slot-set hash that does not match", "slot-set hash")
	if len(w.dir.names("objects/")) != 0 {
		t.Error("something was put")
	}
	// a workspace with no slots or rollover row at all is refused, not waved through
	n := newWorld(t, "standard", 3)
	n.audit = n.audit[1:]
	for i := range n.audit {
		n.audit[i].Seq = int64(i + 1)
	}
	wantRefusal(t, n, "no slot-table row", "genesis slot-table row")
}

// spec: SPO-Xlayout-PRE-016
func TestTheSameAuditSequenceWithAnotherMACIsRefused(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.mustRun()
	x := newWorld(t, "standard", 3)
	x.dir, x.adopt = w.dir, true
	x.audit[len(x.audit)-1].MAC = bytes.Repeat([]byte{2}, 32)
	wantRefusal(t, x, "another chain", "not the same workspace history")
}

// spec: SPO-Xlayout-PRE-016
func TestASealerForAnotherEpochIsRefused(t *testing.T) {
	w := newWorld(t, "standard", 3)
	in := w.input()
	inner := in.Unlock
	in.Unlock = func(ctx context.Context) (layoutexport.Material, error) {
		m, err := inner(ctx)
		m.Sealer = w.newSealer(bytes.Repeat([]byte{0xee}, 16))
		return m, err
	}
	_, err := layoutexport.Run(context.Background(), in)
	if err == nil || !strings.Contains(err.Error(), "key epoch") {
		t.Fatalf("%v", err)
	}
	if len(w.dir.names("objects/")) != 0 {
		t.Error("something was put")
	}
}

// A head that appears under the next name between the check and the put is not
// overwritten and the run ends.
//
// spec: SPO-Xlayout-INV-012
func TestAHeadThatAppearsMeanwhileIsNotOverwritten(t *testing.T) {
	w := newWorld(t, "standard", 3)
	var planted []byte
	w.dir.putHook = func(_ int, name string) error {
		if name == layout.HeadPath(1) {
			planted = []byte("someone else's head\n")
			w.dir.objs[name] = planted
		}
		return nil
	}
	err := wantRefusal(t, w, "a head that appeared", "appeared during this run", "nothing was overwritten")
	if !bytes.Equal(w.dir.objs[layout.HeadPath(1)], planted) {
		t.Error("the head was overwritten")
	}
	if w.pins.pin != nil {
		t.Error("a pin was recorded")
	}
	_ = err
}
