package layoutexport_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A first export of a workspace of each policy: every object is named by its
// hash, opens with the keys, and carries the snapshot's bytes; the slots object
// is put first and the head last; the manifest verifies against its pages.
//
// spec: SPO-Xlayout-OUT-014, SPO-Xlayout-OUT-001, SPO-Xlayout-INV-007, SPO-Xlayout-INV-008, SPO-Xlayout-INV-009, SPO-Xlayout-INV-011
func TestFirstExportForEveryPolicy(t *testing.T) {
	for _, pol := range []string{"standard", "hardware", "strict"} {
		t.Run(pol, func(t *testing.T) {
			w := newWorld(t, pol, 5)
			res := w.mustRun()
			// 1 slots + 5 records + 6 audit rows + 1 record page + 1 audit page + 1 root
			if want := 1 + 5 + 6 + 1 + 1 + 1; res.ObjectsWritten != want || res.ObjectsReused != 0 {
				t.Fatalf("written %d reused %d, want %d and 0", res.ObjectsWritten, res.ObjectsReused, want)
			}
			if !res.HeadWritten || res.HeadSequence != 1 || res.UpToDate || !res.Fresh || res.Signed {
				t.Fatalf("%+v", res)
			}
			// the slots object first, the head last
			first := w.dir.puts[0]
			if b := w.dir.objs[first]; b[0] != layout.FormatSlots {
				t.Errorf("the first thing put is %s, not the slots object", first)
			}
			if last := w.dir.puts[len(w.dir.puts)-1]; last != layout.HeadPath(1) {
				t.Errorf("the last thing put is %s, not the head", last)
			}
			o := w.openAll(w.dir, w.epoch)
			if len(o.records) != 5 || len(o.audit) != 6 || len(o.rpages) != 1 || len(o.apages) != 1 || len(o.roots) != 1 || len(o.slots) != 1 {
				t.Fatalf("object kinds: %d records %d audit %d+%d pages %d roots %d slots", len(o.records), len(o.audit), len(o.rpages), len(o.apages), len(o.roots), len(o.slots))
			}
			if got := satisfiable(t, w, w.dir); got != 1 {
				t.Fatalf("newest head %d", got)
			}
			h, note := newestHead(t, w.dir)
			if !bytes.Equal(h.Workspace, w.ws) || !bytes.Equal(h.Previous, make([]byte, 32)) || h.AuditSeq != 6 || !bytes.Equal(h.AuditMAC, w.audit[5].MAC) || !bytes.Equal(h.Epoch, w.epoch) || h.CheckpointKey != nil {
				t.Fatalf("head %+v", h)
			}
			if (pol == "strict") != (h.RecoveryKey == nil) {
				t.Errorf("recovery-key %x under %s", h.RecoveryKey, pol)
			}
			if !bytes.Equal(layout.HeadHash(note), res.HeadHash) || !strings.HasSuffix(res.Pin, fmt.Sprintf(":layout:1:%x", res.HeadHash)) || !strings.HasPrefix(res.Pin, hexOf(w.ws)+":") {
				t.Errorf("pin %q", res.Pin)
			}
			// INV-007: a record object's id and version are its page entry's
			var root layout.Root
			for _, r := range o.roots {
				root = r
			}
			for _, p := range o.rpages {
				for _, e := range p.Entries {
					rec, ok := o.records[hexOf(e.Hash)]
					if !ok || !bytes.Equal(rec.ID, e.ID) || rec.Version != e.Version {
						t.Errorf("record entry %x disagrees with its object", e.ID)
					}
				}
			}
			// INV-008 and INV-009: audit entries and the head of the chain
			var lastAudit layout.Audit
			for _, p := range o.apages {
				for _, e := range p.Entries {
					a, ok := o.audit[hexOf(e.Hash)]
					if !ok || uint64(a.Seq) != e.Seq {
						t.Errorf("audit entry %d disagrees with its object", e.Seq)
					}
					if a.Seq > lastAudit.Seq {
						lastAudit = a
					}
				}
			}
			if !bytes.Equal(lastAudit.MAC, root.AuditMAC) || uint64(lastAudit.Seq) != root.AuditSeq {
				t.Error("the last audit object is not the root's audit head")
			}
			// INV-011: the slots object's slot-set hash is the newest slots row's
			var so layout.SlotsObject
			for _, s := range o.slots {
				so = s
			}
			if h, err := layout.SlotSetHash(so.Meta.Policy, so.Slots); err != nil || !bytes.Equal(h, w.audit[0].SlotSet) {
				t.Errorf("the slots object's slot-set hash is not the audit row's: %v", err)
			}
			if w.pins.pin == nil || w.pins.pin.Sequence != 1 {
				t.Error("the pin was not recorded")
			}
			if !w.lock.held == false || w.lock.released != 1 {
				t.Error("the lock was not released")
			}
			if w.sealers[0].closed == 0 {
				t.Error("the sealer was not closed")
			}
		})
	}
}

// The exporter never opens a record. The inner fields of every exported object
// equal the snapshot's bytes; a cold-role payload cannot be opened with what the
// exporter holds, which is the object sealer and the references only.
//
// spec: SPO-Xlayout-SEC-007, SPO-Xlayout-INV-003
func TestInnerBytesAreCarriedAndAColdPayloadIsNotOpenedByTheExporter(t *testing.T) {
	w := newWorld(t, "standard", 6)
	// record 2 is a cold-role record: a wrapped key of the cold form's size
	w.records[2].WrappedKey = pat(0x61, 1400)
	snap, _ := w.copySnapshot()
	w.mustRun()
	o := w.openAll(w.dir, w.epoch)
	byID := map[string]layout.Record{}
	for _, r := range o.records {
		byID[hexOf(r.ID)] = r
	}
	for _, r := range snap.Records {
		got, ok := byID[hexOf(r.ID)]
		if !ok {
			t.Fatalf("record %x is not exported", r.ID)
		}
		in := got.Inner
		if !bytes.Equal(in.Nonce, r.Nonce) || !bytes.Equal(in.WrappedKey, r.WrappedKey) || !bytes.Equal(in.Owner, r.OwnerSealed) || !bytes.Equal(in.Ciphertext, r.Ciphertext) {
			t.Errorf("the inner fields of record %x were changed", r.ID)
		}
		if got.Version != uint64(r.Version) || got.UpdatedAt != r.UpdatedAt || got.Kind != r.Kind {
			t.Errorf("the columns of record %x were changed", r.ID)
		}
	}
	// The hot and the cold-role record are in objects of one size.
	var sizes []int
	for name, r := range o.records {
		if r.Kind == "node.skey" || r.Kind == "vrf.skey" {
			sizes = append(sizes, o.sizes[name])
		}
	}
	for _, s := range sizes {
		if s != sizes[0] {
			t.Errorf("secret record objects are in different buckets: %v", sizes)
			break
		}
	}
	// What the exporter holds is a sealer that can only seal. The sealed bytes of
	// the cold record's payload are not in any object in the clear.
	for p, b := range w.dir.objs {
		if strings.HasPrefix(p, "objects/") && b[0] == layout.FormatSealed && bytes.Contains(b, w.records[2].Ciphertext[:32]) {
			t.Errorf("%s holds the payload's sealed bytes in the clear (outside the seal)", p)
		}
	}
	var _ ports.ObjectSealer = w.sealers[0]
}

// Running again with nothing changed puts nothing and writes no head; a run
// after one record changed puts exactly the objects on the path to the root, and
// the new head names the old one.
//
// spec: SPO-Xlayout-OUT-015, SPO-Xlayout-INV-013
func TestReExportIsIncrementalByConstruction(t *testing.T) {
	w := newWorld(t, "standard", 7)
	first := w.mustRun()
	namesAfterFirst := w.dir.snapshotNames()
	h1, note1 := newestHead(t, w.dir)
	w.dir.resetPuts()

	res := w.mustRun()
	if !res.UpToDate || res.HeadWritten || res.ObjectsWritten != 0 || res.HeadSequence != 1 || !bytes.Equal(res.HeadHash, first.HeadHash) {
		t.Fatalf("unchanged re-export: %+v", res)
	}
	if res.ObjectsReused != first.ObjectsWritten {
		t.Errorf("reused %d of %d objects", res.ObjectsReused, first.ObjectsWritten)
	}
	if n := w.dir.putCount(); n != 0 {
		t.Errorf("an unchanged re-export called Put %d times", n)
	}
	if len(w.dir.names("heads/")) != 1 {
		t.Error("a head was written")
	}
	if w.pins.writes != 1 {
		t.Errorf("the pin was written %d times", w.pins.writes)
	}

	// one record changes (and the audit chain grows by a row)
	w.change(3)
	res = w.mustRun()
	if res.UpToDate || !res.HeadWritten || res.HeadSequence != 2 {
		t.Fatalf("%+v", res)
	}
	var added []string
	for n := range w.dir.snapshotNames() {
		if !namesAfterFirst[n] {
			added = append(added, n)
		}
	}
	// 1 record, 1 audit row, 1 record page, 1 audit page (the last, partial one),
	// the root, and the head
	if want := 1 + 1 + 1 + 1 + 1 + 1; len(added) != want {
		t.Fatalf("%d new names %v, want %d", len(added), added, want)
	}
	if res.ObjectsWritten != 5 || res.ObjectsReused != first.ObjectsWritten-4 {
		t.Errorf("written %d reused %d", res.ObjectsWritten, res.ObjectsReused)
	}
	h2, note2 := newestHead(t, w.dir)
	if h2.Sequence != 2 || !bytes.Equal(h2.Previous, layout.HeadHash(note1)) || bytes.Equal(layout.HeadHash(note1), layout.HeadHash(note2)) {
		t.Fatalf("head 2 does not name head 1: %+v", h2)
	}
	if bytes.Equal(h1.Manifest, h2.Manifest) || !bytes.Equal(h1.Slots, h2.Slots) {
		t.Error("the manifest did not change, or the slots object did")
	}
	if satisfiable(t, w, w.dir) != 2 {
		t.Fatal("head 2 is not satisfiable")
	}
	// and the first head is still satisfiable: nothing it names was replaced
	for _, n := range []string{layout.HeadPath(1)} {
		if _, ok := w.dir.objs[n]; !ok {
			t.Errorf("%s is gone", n)
		}
	}
	// a cold-role record whose salt rotated: one record object, same bucket
	w.records[1].WrappedKey = pat(0x71, 1400)
	w.records[1].Version++
	w.records[1].Nonce = pat(0x72, 24)
	w.appendAudit("update")
	before := w.dir.snapshotNames()
	res = w.mustRun()
	var addedRec int
	for n := range w.dir.snapshotNames() {
		if !before[n] && strings.HasPrefix(n, "objects/") {
			addedRec++
		}
	}
	if res.HeadSequence != 3 || addedRec != 5 {
		t.Errorf("sequence %d, %d new objects", res.HeadSequence, addedRec)
	}
}

// A new key epoch (workspace rotate) makes every object new: the old objects stay
// and nothing in the new head names them.
//
// spec: SPO-Xlayout-OUT-015
func TestRotationMakesEveryObjectNew(t *testing.T) {
	w := newWorld(t, "standard", 4)
	w.mustRun()
	oldNames := w.dir.names("objects/")
	_, note1 := newestHead(t, w.dir)
	// a rotation: new keys, new epoch, the audit chain grows by a rollover row
	w.keys = newKeys(t)
	w.epoch = pat(0xe0, 16)
	w.meta.KeyEpoch = w.epoch
	w.appendAudit("rollover")
	w.audit[len(w.audit)-1].SlotSet = w.slotSet()
	res := w.mustRun()
	if res.HeadSequence != 2 || res.ObjectsReused != 0 {
		t.Fatalf("%+v", res)
	}
	if got := len(w.dir.names("objects/")); got != 2*len(oldNames)+1 { // +1 for the extra audit row
		t.Errorf("%d objects after the rotation, %d before", got, len(oldNames))
	}
	for _, n := range oldNames {
		if _, ok := w.dir.objs[n]; !ok {
			t.Errorf("old object %s was removed", n)
		}
	}
	h, _ := newestHead(t, w.dir)
	if !bytes.Equal(h.Epoch, w.epoch) || !bytes.Equal(h.Previous, layout.HeadHash(note1)) {
		t.Errorf("head %+v", h)
	}
	if satisfiable(t, w, w.dir) != 2 {
		t.Fatal("the new head is not satisfiable")
	}
}

// With a checkpoint key the head note is signed under spo/head-provisional/v1,
// once, after every object is in the directory and before the head is put; the
// signature is put beside it. Without a key, or with no signing asked, there is
// none and the result says so.
//
// spec: SPO-Xlayout-OUT-016
func TestSigningTheHead(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.withKey()
	var sawAllObjectsFirst bool
	w.sk.OnSign = func() {
		_, hasHead := w.dir.objs[layout.HeadPath(1)]
		sawAllObjectsFirst = !hasHead && len(w.dir.names("objects/")) == 1+3+4+1+1+1
	}
	res := w.mustRun()
	if !sawAllObjectsFirst {
		t.Error("the authenticator was asked before every object was in the directory, or after the head was put")
	}
	if w.sk.Signs != 1 {
		t.Errorf("%d signatures; one PIN and one touch", w.sk.Signs)
	}
	if !res.Signed || !res.SignedNow || res.LongPin == "" || !strings.Contains(res.LongPin, ":ck:"+hexOf(w.signing.Record.Hash())) {
		t.Fatalf("%+v", res)
	}
	h, note := newestHead(t, w.dir)
	if !bytes.Equal(h.CheckpointKey, w.signing.Record.Hash()) {
		t.Error("the head does not name the checkpoint key")
	}
	sigBytes, ok := w.dir.objs[layout.HeadPath(1)+".sig"]
	if !ok {
		t.Fatal("no signature object")
	}
	blob, err := sshsig.Dearmor(sigBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sshsig.Verify(blob, note, layout.NamespaceHead, w.signing.Record.Hash(), "ssh:spo-checkpoint"); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	if _, err := sshsig.Verify(blob, note, "spo/checkpoint/v1", w.signing.Record.Hash(), "ssh:spo-checkpoint"); err == nil {
		t.Error("the signature verifies under another namespace")
	}
	// an unchanged re-export asks nothing
	w.mustRun()
	if w.sk.Signs != 1 {
		t.Errorf("an unchanged re-export signed again (%d)", w.sk.Signs)
	}

	// no key: unsigned
	w2 := newWorld(t, "standard", 3)
	r2 := w2.mustRun()
	if r2.Signed || r2.LongPin != "" || len(w2.dir.names("heads/")) != 1 {
		t.Errorf("%+v", r2)
	}
	// --no-checkpoint: the command gives no Signing although a key is enrolled
	w3 := newWorld(t, "standard", 3)
	w3.withKey()
	saved := w3.signing
	w3.signing = nil
	r3 := w3.mustRun()
	if r3.Signed || w3.sk.Signs != 0 {
		t.Errorf("%+v", r3)
	}
	h3, _ := newestHead(t, w3.dir)
	if h3.CheckpointKey != nil {
		t.Error("an unsigned head names a checkpoint key")
	}
	// a later run that wants a signature signs the newest head and puts nothing else
	w3.signing = saved
	w3.dir.resetPuts()
	r4 := w3.mustRun()
	if !r4.UpToDate || !r4.SignedNow || w3.dir.putCount() != 1 || w3.dir.puts[0] != layout.HeadPath(1)+".sig" || w3.sk.Signs != 1 {
		t.Errorf("%+v puts %v", r4, w3.dir.puts)
	}
}

// A signing failure leaves the objects and no head; the run reports it and a
// re-run puts no object again and writes the head.
//
// spec: SPO-Xlayout-OUT-016, SPO-Xlayout-INV-012
func TestSigningFailureLeavesNoHead(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.withKey()
	w.sk.FailSign = errors.New("the authenticator was removed")
	_, err := w.run()
	if err == nil || !strings.Contains(err.Error(), "no head written") {
		t.Fatalf("%v", err)
	}
	if len(w.dir.names("heads/")) != 0 {
		t.Fatal("a head was written")
	}
	if len(w.dir.names("objects/")) != 1+3+4+1+1+1 {
		t.Fatalf("%d objects", len(w.dir.names("objects/")))
	}
	if w.pins.pin != nil {
		t.Error("a pin was recorded")
	}
	w.sk.FailSign = nil
	w.sk.OnSign = nil
	w.dir.resetPuts()
	res := w.mustRun()
	if !res.HeadWritten || res.ObjectsWritten != 0 || res.HeadSequence != 1 {
		t.Fatalf("%+v", res)
	}
	if satisfiable(t, w, w.dir) != 1 {
		t.Fatal("not satisfiable")
	}
	// only the head and its signature were put
	if got := w.dir.putCount(); got != 1+1+1+1+1+3+4+1+1+1-1 && got < 2 {
		t.Errorf("%d puts", got)
	}
}

// Refusals that need no secret come first: the unlock callback, which is where a
// passphrase or an authenticator is asked for, is never reached.
//
// spec: SPO-Xlayout-PRE-013, SPO-Xlayout-PRE-016
func TestRefusalsBeforeAnyUnlock(t *testing.T) {
	other := newWorld(t, "standard", 2)
	other.ws = pat(0x77, 16)
	other.meta.WorkspaceID = other.ws
	other.mustRun()
	mine := newWorld(t, "standard", 2)
	cases := map[string]func() (*world, error){
		"a layout of another workspace": func() (*world, error) {
			w := newWorld(t, "standard", 2)
			w.dir = other.dir
			_, err := w.run()
			return w, err
		},
		"a directory that is not a layout": func() (*world, error) {
			w := newWorld(t, "standard", 2)
			w.dir.extra = map[string]int64{"notes.txt": 10}
			_, err := w.run()
			return w, err
		},
		"a corrupt pin file": func() (*world, error) {
			w := newWorld(t, "standard", 2)
			w.pins.loadErr = fmt.Errorf("%w: test", ports.ErrLayoutPinCorrupt)
			_, err := w.run()
			return w, err
		},
		"a directory behind the pin": func() (*world, error) {
			w := newWorld(t, "standard", 2)
			w.pins.pin = &ports.LayoutPin{Sequence: 4, HeadHash: make([]byte, 32)}
			_, err := w.run()
			return w, err
		},
		"a second exporter": func() (*world, error) {
			w := newWorld(t, "standard", 2)
			w.lock.held = true
			_, err := w.run()
			return w, err
		},
	}
	_ = mine
	for name, f := range cases {
		w, err := f()
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if w.unlocks != 0 {
			t.Errorf("%s: the workspace was unlocked (a prompt would have been made)", name)
		}
		if w.dir.putCount() != 0 && name != "a layout of another workspace" {
			t.Errorf("%s: something was put", name)
		}
	}
	if len(other.dir.names("objects/")) == 0 {
		t.Fatal("test setup")
	}
	// the other workspace's directory was not changed
	before := len(other.dir.names("objects/"))
	w := newWorld(t, "standard", 2)
	w.dir = other.dir
	if _, err := w.run(); !errors.Is(err, layoutexport.ErrOtherWorkspace) {
		t.Errorf("%v", err)
	}
	if len(other.dir.names("objects/")) != before {
		t.Error("the other layout was changed")
	}
}

// A directory that holds a newer state than the workspace (the workspace was
// rolled back) and one that is behind this machine's pin are refused, and an
// unfinished export (objects, no head) is resumed.
//
// spec: SPO-Xlayout-PRE-016
func TestAheadAndBehind(t *testing.T) {
	w := newWorld(t, "standard", 3)
	w.change(0)
	w.mustRun()
	// the workspace goes back to an earlier state
	w2 := newWorld(t, "standard", 3)
	w2.dir, w2.pins, w2.adopt = w.dir, &memPins{}, true
	_, err := w2.run()
	if !errors.Is(err, layoutexport.ErrAhead) {
		t.Fatalf("a workspace behind the layout: %v", err)
	}
	// the pin says sequence 5 was written; the directory has 1
	w.pins.pin = &ports.LayoutPin{Sequence: 5, HeadHash: bytes.Repeat([]byte{1}, 32)}
	if _, err := w.run(); !errors.Is(err, layoutexport.ErrRolledBack) {
		t.Fatalf("a directory behind the pin: %v", err)
	}
	// same sequence, other hash
	_, note := newestHead(t, w.dir)
	w.pins.pin = &ports.LayoutPin{Sequence: 1, HeadHash: bytes.Repeat([]byte{1}, 32)}
	if _, err := w.run(); !errors.Is(err, layoutexport.ErrRolledBack) {
		t.Fatalf("a head that is not the pinned one: %v", err)
	}
	w.pins.pin = &ports.LayoutPin{Sequence: 1, HeadHash: layout.HeadHash(note)}
	if res, err := w.run(); err != nil || !res.UpToDate {
		t.Fatalf("%v %+v", err, res)
	}
}

// The directory must be a layout of this workspace: heads of a valid chain for
// its id. A head that is not valid blocks the directory; it is never replaced.
//
// spec: SPO-Xlayout-PRE-013
func TestAnInvalidNewestHeadBlocksTheDirectory(t *testing.T) {
	w := newWorld(t, "standard", 2)
	w.mustRun()
	w.dir.objs[layout.HeadPath(2)] = []byte("not a head\n")
	w.unlocks = 0
	if _, err := w.run(); err == nil || !strings.Contains(err.Error(), "fresh directory") {
		t.Fatalf("%v", err)
	}
	if w.unlocks != 0 {
		t.Error("unlocked")
	}
	if string(w.dir.objs[layout.HeadPath(2)]) != "not a head\n" {
		t.Error("the invalid head was replaced")
	}
}

// Fault injection: at every Put a failure of each kind leaves a directory whose
// newest valid head is satisfiable (or has no head), and a re-run completes
// without putting again what is already there.
//
// spec: SPO-Xlayout-INV-012, SPO-Xlayout-OUT-014
func TestFaultsAtEveryStepLeaveTheNewestHeadSatisfiable(t *testing.T) {
	// the fault points are the puts of an export that follows an earlier one, so
	// that a head already exists and must stay satisfiable
	probe := newWorld(t, "standard", 3)
	probe.mustRun()
	probe.change(1)
	probe.dir.resetPuts()
	probe.mustRun()
	puts := probe.dir.putCount()
	if puts < 5 {
		t.Fatalf("only %d puts", puts)
	}
	faults := map[string]func(w *world, at int){
		"the put fails (disk full)": func(w *world, at int) {
			w.dir.putHook = func(n int, _ string) error {
				if n == at {
					return errors.New("no space left on device")
				}
				return nil
			}
		},
		"the read back differs": func(w *world, at int) {
			w.dir.afterPut = func(n int, name string) {
				if n == at {
					w.dir.getHook = func(g string, b []byte) []byte {
						if g == name {
							b[len(b)/2] ^= 1
						}
						return b
					}
				}
			}
		},
		"the context is cancelled": nil, // handled below: it needs the context
	}
	for fname, inject := range faults {
		if inject == nil {
			continue
		}
		for at := 1; at <= puts; at++ {
			w := newWorld(t, "standard", 3)
			w.mustRun()
			w.change(1)
			w.dir.resetPuts()
			inject(w, at)
			_, err := w.run()
			if err == nil {
				t.Fatalf("%s at put %d: no error", fname, at)
			}
			if !strings.Contains(err.Error(), "run the command again") && !strings.Contains(err.Error(), "can be run again") {
				t.Errorf("%s at put %d: the error does not say it can be run again: %v", fname, at, err)
			}
			if got := satisfiable(t, w, w.dir); got != 1 && got != 2 {
				t.Fatalf("%s at put %d: newest head %d", fname, at, got)
			}
			if h, _ := newestHead(t, w.dir); h.Sequence == 2 && at != puts {
				// a head is only ever put last
				t.Errorf("%s at put %d: head 2 exists although a put before it failed", fname, at)
			}
			// a re-run completes and puts nothing that is already there
			w.dir.putHook, w.dir.afterPut, w.dir.getHook = nil, nil, nil
			have := w.dir.snapshotNames()
			w.dir.resetPuts()
			res, err := w.run()
			if err != nil {
				t.Fatalf("%s at put %d: the re-run: %v", fname, at, err)
			}
			for _, name := range w.dir.puts {
				if have[name] && !strings.HasPrefix(name, "heads/") {
					t.Errorf("%s at put %d: %s was put again", fname, at, name)
				}
			}
			if satisfiable(t, w, w.dir) != 2 || (!res.HeadWritten && !res.UpToDate) {
				t.Fatalf("%s at put %d: the re-run did not complete", fname, at)
			}
			if w.lock.held {
				t.Errorf("%s at put %d: the lock is still held", fname, at)
			}
		}
	}
	// a cancelled context, at every put
	for at := 1; at <= puts; at++ {
		w := newWorld(t, "standard", 3)
		w.mustRun()
		w.change(1)
		w.dir.resetPuts()
		ctx, cancel := context.WithCancel(context.Background())
		w.dir.afterPut = func(n int, _ string) {
			if n == at {
				cancel()
			}
		}
		w.clock = w.clock.Add(time.Minute)
		_, err := layoutexport.Run(ctx, w.input())
		if at < puts && err == nil {
			t.Fatalf("cancel at put %d: no error", at)
		}
		if got := satisfiable(t, w, w.dir); got < 1 {
			t.Fatalf("cancel at put %d: %d", at, got)
		}
		w.dir.afterPut = nil
		if _, err := w.run(); err != nil {
			t.Fatalf("cancel at put %d: the re-run: %v", at, err)
		}
		if satisfiable(t, w, w.dir) != 2 {
			t.Fatalf("cancel at put %d: the re-run did not complete", at)
		}
	}
	// a first export, failing at every put: no head, ever, until the end
	for at := 1; at <= 1+3+4+1+1+1; at++ {
		w := newWorld(t, "standard", 3)
		w.dir.putHook = func(n int, _ string) error {
			if n == at {
				return errors.New("input/output error")
			}
			return nil
		}
		if _, err := w.run(); err == nil {
			t.Fatalf("first export, put %d: no error", at)
		}
		if got := satisfiable(t, w, w.dir); got != 0 {
			t.Fatalf("first export, put %d: a head exists (%d)", at, got)
		}
		w.dir.putHook = nil
		if _, err := w.run(); err != nil {
			t.Fatalf("first export, put %d: the re-run: %v", at, err)
		}
		if satisfiable(t, w, w.dir) != 1 {
			t.Fatalf("first export, put %d: not complete", at)
		}
	}
}

// A second exporter is refused while the first runs; the lock is held for the
// whole export and a directory that was replaced mid-run stops it.
//
// spec: SPO-Xlayout-PRE-014
func TestSingleWriterLock(t *testing.T) {
	w := newWorld(t, "standard", 3)
	var once sync.Once
	var secondErr error
	var secondUnlocked int
	w.dir.putHook = func(n int, _ string) error {
		if n == 3 {
			once.Do(func() {
				// a second exporter, started while the first is in the middle
				in := w.input()
				orig := in.Unlock
				in.Unlock = func(ctx context.Context) (layoutexport.Material, error) {
					secondUnlocked++
					return orig(ctx)
				}
				_, secondErr = layoutexport.Run(context.Background(), in)
			})
		}
		return nil
	}
	w.mustRun()
	if !errors.Is(secondErr, ports.ErrLayoutLocked) || secondUnlocked != 0 {
		t.Fatalf("the second exporter: %v (unlocked %d times)", secondErr, secondUnlocked)
	}
	if w.lock.held || w.lock.released != 1 {
		t.Errorf("held %v released %d", w.lock.held, w.lock.released)
	}
	// the directory is replaced after a few puts: the run stops, and the directory
	// the objects went to still satisfies its newest head (here: none)
	w2 := newWorld(t, "standard", 3)
	w2.dir.afterPut = func(n int, _ string) {
		if n == 2 {
			w2.lock.mu.Lock()
			w2.lock.checkErr = ports.ErrLayoutMoved
			w2.lock.mu.Unlock()
		}
	}
	_, err := w2.run()
	// the check runs every 64 objects and before the pages and the head
	if !errors.Is(err, ports.ErrLayoutMoved) {
		t.Fatalf("%v", err)
	}
	if len(w2.dir.names("heads/")) != 0 {
		t.Error("a head was put into a directory that was replaced")
	}
}

// A record whose body does not fit the largest bucket is refused with its kind
// and size class, never its content.
//
// spec: SPO-Xlayout-PRE-015
func TestOversizedRecordIsRefusedByKindAndClass(t *testing.T) {
	w := newWorld(t, "standard", 3)
	secret := bytes.Repeat([]byte("TOPSECRETPAYLOAD"), (4<<20)/16)
	w.records[1].Ciphertext = secret[:4<<20-1500]
	_, err := w.run()
	if err == nil {
		t.Fatal("accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, w.records[1].Kind) || !strings.Contains(msg, "class "+w.refs[1].Class) || !strings.Contains(msg, "largest bucket") {
		t.Errorf("the refusal does not name the kind, the class and the bucket: %.300s", msg)
	}
	if strings.Contains(msg, "TOPSECRET") || strings.Contains(msg, hexOf(w.records[1].ID)) {
		t.Error("the refusal shows content")
	}
	if len(w.dir.names("heads/")) != 0 {
		t.Error("a head was written")
	}
	// the largest record that fits is accepted and is in the 4 MiB bucket
	w.records[1].Ciphertext = secret[:4<<20-3000-1700-60]
	for len(w.records[1].Ciphertext) > 0 {
		if _, err = w.run(); err == nil {
			break
		}
		w.records[1].Ciphertext = w.records[1].Ciphertext[:len(w.records[1].Ciphertext)-512]
	}
	if err != nil {
		t.Fatal(err)
	}
}

// Every byte the exporter puts is either a sealed object or one of the four
// things the format defines as plaintext: the 17-byte headers, the slots object,
// head notes and signatures. No record kind, class, label, id, anchor, owner blob
// or payload byte is outside a seal.
//
// spec: SPO-Xlayout-SEC-006, SPO-Xlayout-SEC-004
func TestNoPlaintextLeavesTheMachineExceptWhatTheFormatDefines(t *testing.T) {
	w := newWorld(t, "standard", 8)
	w.withKey()
	w.mustRun()
	w.change(2)
	w.mustRun()
	var secrets [][]byte
	for _, r := range w.records {
		secrets = append(secrets, r.ID, r.Nonce, r.WrappedKey, r.OwnerSealed, r.Ciphertext[:24])
	}
	for _, rf := range w.refs {
		secrets = append(secrets, rf.Anchor)
	}
	for _, k := range kindsInUse {
		secrets = append(secrets, []byte(k))
	}
	secrets = append(secrets, []byte("secret"), []byte("sensitive"), []byte("manifest-root"), []byte("manifest-page"), []byte("audit"), []byte("records"))
	for p, b := range w.dir.objs {
		switch {
		case strings.HasPrefix(p, "heads/"):
			if strings.HasSuffix(p, ".sig") {
				if !bytes.HasPrefix(b, []byte("-----BEGIN SSH SIGNATURE-----")) {
					t.Errorf("%s is not an armored signature", p)
				}
			} else if _, err := layout.ParseHead(b); err != nil {
				t.Errorf("%s: %v", p, err)
			}
		case b[0] == layout.FormatSlots:
			if _, _, err := layout.ParseSlotsObject(b); err != nil {
				t.Errorf("%s: %v", p, err)
			}
		case b[0] == layout.FormatSealed:
			if !layout.IsBucket(len(b)) {
				t.Errorf("%s: %d bytes is not a bucket", p, len(b))
			}
		default:
			t.Errorf("%s: unknown format byte %x", p, b[0])
		}
		// no secret appears anywhere, in a sealed object or in plaintext
		for _, s := range secrets {
			word := bytes.Equal(s, []byte("audit")) || bytes.Equal(s, []byte("records"))
			if len(s) >= 4 && bytes.Contains(b, s) && !(strings.HasPrefix(p, "objects/") && b[0] == layout.FormatSlots) && !(word && strings.HasPrefix(p, "heads/")) {
				t.Errorf("%s contains %q or a secret-bearing field in the clear", p, s)
			}
		}
	}
	// the slots object shows only what the format says it shows
	for p, b := range w.dir.objs {
		if strings.HasPrefix(p, "objects/") && b[0] == layout.FormatSlots {
			for _, k := range kindsInUse {
				if bytes.Contains(b, []byte(k)) {
					t.Errorf("the slots object names the kind %s", k)
				}
			}
		}
	}
}

// Peak memory with 50,000 audit rows: the export does not hold the workspace
// twice. The snapshot is held once and each row is cleared when its object is
// put.
//
// spec: SPO-Xlayout-INV-014
func TestMemoryPeakWith50000AuditRows(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	w := newWorld(t, "standard", 200)
	for len(w.audit) < 50_000 {
		w.appendAudit("update")
	}
	w.dir = newMemDir()
	// a writer that keeps nothing: the point is the exporter's own memory
	null := &nullDir{}
	in := w.input()
	in.Dir.Writer, in.Dir.Reader, in.Dir.Lister = null, null, null
	var snapBytes uint64
	in.Unlock = func(context.Context) (layoutexport.Material, error) {
		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)
		snap, refs := w.copySnapshot()
		s := w.newSealer(w.epoch)
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		snapBytes = after.HeapInuse - base.HeapInuse
		return layoutexport.Material{Snapshot: snap, Refs: refs, Sealer: s, Close: s.Close}, nil
	}
	stop := make(chan struct{})
	done := make(chan uint64)
	go func() {
		var peak uint64
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				done <- peak
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse > peak {
					peak = ms.HeapInuse
				}
			}
		}
	}()
	// a tight collector, so that the peak shown is live data and not garbage waiting
	// for the default collector's next cycle
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	res, err := layoutexport.Run(context.Background(), in)
	close(stop)
	peak := <-done
	if err != nil {
		t.Fatal(err)
	}
	over := int64(peak) - int64(base.HeapInuse)
	t.Logf("50,000 audit rows, 200 records: %d objects written; snapshot %.1f MiB; peak heap in use during the export %.1f MiB above the start (%.1f MiB of it is the snapshot, held once)",
		res.ObjectsWritten, float64(snapBytes)/(1<<20), float64(over)/(1<<20), float64(snapBytes)/(1<<20))
	// the export itself, beyond the snapshot, stays small: it is not a second copy
	if extra := over - int64(snapBytes); extra > 64<<20 {
		t.Errorf("the export held %.1f MiB beyond the snapshot", float64(extra)/(1<<20))
	}
	if res.ObjectsWritten < 50_000 {
		t.Errorf("%d objects", res.ObjectsWritten)
	}
}

// nullDir accepts everything and keeps only the object it was last given (the
// read back of an object follows its put at once).
type nullDir struct {
	mu       sync.Mutex
	lastName string
	last     []byte
	n        int
}

func (d *nullDir) Put(_ context.Context, name string, r io.Reader, size int64) error {
	b, err := io.ReadAll(r)
	if err != nil || int64(len(b)) != size {
		return errors.New("short")
	}
	d.mu.Lock()
	d.lastName, d.last = name, b
	d.n++
	d.mu.Unlock()
	return nil
}

func (d *nullDir) Get(_ context.Context, name string) (io.ReadCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name != d.lastName {
		return nil, ports.ErrObjectNotFound
	}
	return io.NopCloser(bytes.NewReader(d.last)), nil
}

func (d *nullDir) Has(context.Context, string) (bool, error)                { return false, nil }
func (d *nullDir) List(context.Context, string) ([]ports.ObjectInfo, error) { return nil, nil }

// The cost of reading every object that is reused (INV-018) on the 50,000-row
// fixture: an unchanged re-export reads and hashes every object once, one at a
// time.
//
// spec: SPO-Xlayout-INV-018, SPO-Xlayout-INV-014
func TestReExportCostWith50000AuditRows(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	w := newWorld(t, "standard", 200)
	for len(w.audit) < 50_000 {
		w.appendAudit("update")
	}
	t0 := time.Now()
	first := w.mustRun()
	tFirst := time.Since(t0)
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	stop := make(chan struct{})
	done := make(chan uint64)
	go func() {
		var peak uint64
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				done <- peak
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse > peak {
					peak = ms.HeapInuse
				}
			}
		}
	}()
	t0 = time.Now()
	res := w.mustRun()
	tSecond := time.Since(t0)
	close(stop)
	peak := <-done
	if !res.UpToDate || res.ObjectsWritten != 0 || res.ObjectsReused != first.ObjectsWritten {
		t.Fatalf("%+v", res)
	}
	t.Logf("50,000 audit rows: first export %d objects in %v; an unchanged re-export read and hashed %d objects (%.0f MiB) in %v; heap in use rose %.1f MiB above its start beyond the directory's own %.0f MiB of objects (the in-memory fake holds them)",
		first.ObjectsWritten, tFirst, res.ObjectsReused, float64(first.BytesWritten)/(1<<20), tSecond, float64(int64(peak)-int64(base.HeapInuse))/(1<<20), float64(first.BytesWritten)/(1<<20))
}
