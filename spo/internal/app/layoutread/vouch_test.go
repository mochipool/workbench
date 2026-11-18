package layoutread_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/layoutfix"
)

// the two exact forms of a pin of head seq: what the export printed, and the pin
// this machine keeps beside the workspace file
func exactPins(w *layoutfix.World, seq uint64) map[string]string {
	return map[string]string{"the exact pin": w.Pin(seq), "the local pin": "local"}
}

func pinFor(t *testing.T, w *layoutfix.World, form string, seq uint64) layoutread.Pin {
	t.Helper()
	if form == "local" {
		return layoutread.PinFromLocal(w.WS, ports.LayoutPin{Sequence: seq, HeadHash: layout.HeadHash(w.Dir.Objs[layout.HeadPath(seq)])})
	}
	return mustPin(t, form)
}

// forgeTable appends an unsigned head 3 (above the pin of head 2) that names a
// slots object made by change from the pinned one, with the head's recovery key
// field made to match.
func forgeTable(t *testing.T, w *layoutfix.World, change func(so *layout.SlotsObject)) {
	t.Helper()
	w.Forge(func(p *layoutfix.Parts) {
		_, so, err := layout.ParseSlotsObject(p.SlotsStored)
		if err != nil {
			t.Fatal(err)
		}
		change(&so)
		if p.SlotsStored, err = layout.EncodeSlotsObject(so.Meta.KeyEpoch, so); err != nil {
			t.Fatal(err)
		}
		p.Head.RecoveryKey = so.Meta.RecoveryPubHash
	}, nil)
}

func tableOf(t *testing.T, policy string) ([]layout.Slot, layout.Meta) {
	t.Helper()
	o := layoutfix.NewWorld(t, policy, 0)
	_, so, err := layout.ParseSlotsObject(func() []byte { o.MustExport(); return o.ObjectOf(o.Head(1).Slots) }())
	if err != nil {
		t.Fatal(err)
	}
	return so.Slots, so.Meta
}

func twoHeads(t *testing.T, policy string) *layoutfix.World {
	t.Helper()
	w := layoutfix.NewWorld(t, policy, 3)
	w.MustExport()
	w.Change(1)
	w.MustExport()
	return w
}

// The slot table that decides the credential and the authenticator request is one
// the pin vouches for: the pinned head's, or a later one that is not weaker, binds
// the same recovery key and (in the store's check) names only the store's own RP id.
//
// spec: SPO-Xlayout-PRE-028
func TestTheSlotTableThatDecidesTheCredentialIsOneThePinVouchesFor(t *testing.T) {
	std, _ := tableOf(t, "standard")
	_ = std
	for form := range exactPins(twoHeads(t, "standard"), 2) {
		t.Run(form, func(t *testing.T) {
			// hardware pinned, a standard table offered by an unsigned head above the pin
			w := twoHeads(t, "hardware")
			stdSlots, _ := tableOf(t, "standard")
			forgeTable(t, w, func(so *layout.SlotsObject) { so.Meta.Policy, so.Slots = "standard", stdSlots })
			tables := &layoutfix.Tables{}
			_, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: pinFor(t, w, exactPins(w, 2)[form], 2), Tables: tables})
			wantErr(t, err, layoutread.ErrSlots, "weaker", "--at 2", "heads/00000000000000000003")

			// a stronger table, the same recovery key: accepted before any prompt
			w = twoHeads(t, "standard")
			hwSlots, _ := tableOf(t, "hardware")
			forgeTable(t, w, func(so *layout.SlotsObject) { so.Meta.Policy, so.Slots = "hardware", hwSlots })
			lr, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: pinFor(t, w, exactPins(w, 2)[form], 2), Tables: &layoutfix.Tables{}})
			if err != nil || lr.Used.Head.Sequence != 3 || lr.Slots.Meta.Policy != "hardware" || lr.Vouched != "standard" {
				t.Fatalf("%v %+v", err, lr)
			}

			// another recovery key
			w = twoHeads(t, "hardware")
			forgeTable(t, w, func(so *layout.SlotsObject) {
				pub := layoutfix.Pat(0x77, 32)
				h := sha256.Sum256(pub)
				so.Meta.RecoveryPub, so.Meta.RecoveryPubHash = pub, h[:]
			})
			_, err = layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: pinFor(t, w, exactPins(w, 2)[form], 2), Tables: &layoutfix.Tables{}})
			wantErr(t, err, layoutread.ErrSlots, "recovery key", "--at 2")

			// a table the store's own check refuses (a FIDO2 slot naming another RP id)
			w = twoHeads(t, "hardware")
			forgeTable(t, w, func(so *layout.SlotsObject) { so.Slots[0].Nonce = layoutfix.Pat(0xEE, 24) })
			tb := &layoutfix.Tables{Reject: func(s []ports.SnapshotSlot) bool { return s[0].Nonce[0] == 0xEE }}
			_, err = layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: pinFor(t, w, exactPins(w, 2)[form], 2), Tables: tb})
			wantErr(t, err, layoutread.ErrSlots, "policy")
		})
	}
}

// The pinned head's own table is fetched and checked too, so the table of an
// exact pin is always one that passed its own policy.
//
// spec: SPO-Xlayout-PRE-028
func TestThePinnedHeadsSlotsObjectIsFetchedAndChecked(t *testing.T) {
	w := twoHeads(t, "standard")
	forgeTable(t, w, func(so *layout.SlotsObject) { so.Slots[0].Nonce = layoutfix.Pat(0x44, 24) }) // head 3 names another object
	w.Dir.Delete(pathOf(w.Head(2).Slots))                                                          // the pinned head's own is gone
	_, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: mustPin(t, w.Pin(2)), Tables: &layoutfix.Tables{}})
	wantErr(t, err, layoutread.ErrObject, "is not in the directory", "the pinned head's own slots object")
}

// With a key pin the head, and so the hash of its slots object, is signed: the
// table is fetched and matched to the signed head before any credential is asked.
//
// spec: SPO-Xlayout-PRE-028
func TestUnderAKeyPinTheTableIsMatchedToTheSignedHead(t *testing.T) {
	w := threeHeads(t, true)
	good := w.Dir.Clone()
	p := pathOf(w.Head(3).Slots)
	b := append([]byte(nil), w.Dir.Objs[p]...)
	b[200] ^= 1
	w.Dir.Set(p, b)
	o := w.Opener()
	_, err := checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrObject, "wrong content")
	if o.Opens.Load() != 0 {
		t.Fatal("a credential was used")
	}
	// another table under a signed head cannot be named: the head would need a new signature
	w.Dir = good.Clone()
	h := w.Head(3)
	h.Slots = w.Head(3).Manifest
	w.RePutHead(h)
	_, err = checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature)
}

// A key cannot appear after the pin without the pin vouching for it, and a
// signature counts as one only when the key is one the pin vouches for.
//
// spec: SPO-Xlayout-PRE-021, SPO-Xlayout-PRE-029
func TestAKeyThePinDoesNotVouchForIsNeverCounted(t *testing.T) {
	other := layoutfix.NewWorld(t, "standard", 5)
	other.WithKey()
	// the pinned head names no key; a later head names one (and is signed by it)
	w := threeHeads(t, false)
	h := w.Head(3)
	h.CheckpointKey = other.KeyRec.Hash()
	note := w.RePutHead(h)
	w.Dir.Set(layout.HeadPath(3)+".sig", other.SignWith(note))
	_, err := checkLocked(t, w, w.Pin(2), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "names a checkpoint key", "newer exact pin")
	// the pinned head names K; a later head names another key and is signed by K
	w = threeHeads(t, true)
	h = w.Head(3)
	h.CheckpointKey = other.KeyRec.Hash()
	w.Dir.Set(layout.HeadPath(3), mustEncode(t, h))
	w.Dir.Set(layout.HeadPath(3)+".sig", w.SignWith(w.Dir.Objs[layout.HeadPath(3)]))
	_, err = checkLocked(t, w, w.Pin(2), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "names another checkpoint key")
	// a valid signature by a key that is not the pin's, on a head that names none: not counted, said so
	w = threeHeads(t, false)
	w.Dir.Set(layout.HeadPath(3)+".sig", other.SignWith(w.Dir.Objs[layout.HeadPath(3)]))
	lr, err := checkLocked(t, w, w.Pin(2), layoutread.Options{})
	if err != nil || lr.Used.Signed {
		t.Fatalf("%v %+v", err, lr.Used)
	}
	if !strings.Contains(strings.Join(lr.Notices, "\n"), "does not vouch for") {
		t.Errorf("%v", lr.Notices)
	}
}

// The slots object is read to its bound and no further, and decoded only within it.
//
// spec: SPO-Xlayout-PRE-027
func TestAnOversizedSlotsObjectIsRefusedBeforeItIsDecoded(t *testing.T) {
	w := threeHeads(t, false)
	huge := make([]byte, layout.MaxBucket)
	huge[0] = layout.FormatSlots
	copy(huge[1:], w.Epoch)
	binary.BigEndian.PutUint32(huge[layout.HeaderSize:], uint32(layout.MaxBucket-layout.HeaderSize-4))
	h := w.Head(3)
	h.Slots = w.PutObject(huge)
	w.RePutHead(h)
	p := mustPin(t, w.Pin(3))
	var err error
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	_, err = layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: p, Tables: &layoutfix.Tables{}})
	runtime.ReadMemStats(&b)
	wantErr(t, err, layoutread.ErrObject, "larger than")
	if grew := b.TotalAlloc - a.TotalAlloc; grew > 2<<20 {
		t.Errorf("%d bytes were allocated to refuse an oversized slots object", grew)
	}
}

// The sizes the locked pass reports are the sizes of the objects it names.
//
// spec: SPO-Xlayout-OUT-020
func TestTheReportedSizesAreTheSizesOfTheObjects(t *testing.T) {
	w := twoHeads(t, "standard")
	w.Forge(func(p *layoutfix.Parts) {
		_, so, _ := layout.ParseSlotsObject(p.SlotsStored)
		for len(so.Slots) < 40 {
			i := len(so.Slots)
			id := make([]byte, 16)
			id[0] = 0x80 + byte(i)
			so.Slots = append(so.Slots, layout.Slot{ID: id, Kind: "passphrase", KDFMemoryKiB: layoutfixI64(65536), KDFPasses: layoutfixI64(3), KDFLanes: layoutfixI64(1),
				Salt: layoutfix.Pat(1, 16), KeyCommit: layoutfix.Pat(1, 32), Nonce: layoutfix.Pat(2, 24), WrappedKey: layoutfix.Pat(3, 48), Bound: 1, RecHash: so.Meta.RecoveryPubHash, Factors: nil})
		}
		sortSlots(so.Slots)
		var err error
		p.SlotsStored, err = layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			t.Fatal(err)
		}
	}, nil)
	lr, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: mustPin(t, w.Pin(2)), Tables: &layoutfix.Tables{}})
	if err != nil {
		t.Fatal(err)
	}
	slotsLen := len(w.ObjectOf(w.Head(3).Slots))
	manLen := len(w.ObjectOf(w.Head(3).Manifest))
	if slotsLen == manLen {
		t.Fatalf("the fixture cannot tell the two sizes apart (%d)", slotsLen)
	}
	joined := strings.Join(lr.Established, "\n")
	if !strings.Contains(joined, fmt.Sprintf("the slots object (%d bytes)", slotsLen)) || !strings.Contains(joined, fmt.Sprintf("the manifest root (%d bytes)", manLen)) {
		t.Errorf("slots %d, manifest %d:\n%s", slotsLen, manLen, joined)
	}
}

// With an exact pin the head used is the newest the directory offers, not
// necessarily the newest there is.
//
// spec: SPO-Xlayout-OUT-020
func TestAnExactPinSaysTheNewestHeadIsOnlyTheNewestOffered(t *testing.T) {
	w := threeHeads(t, false)
	lr, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(lr.Notices, "\n"), "not necessarily the newest that exists") {
		t.Errorf("%v", lr.Notices)
	}
	w = threeHeads(t, true)
	lr, err = checkLocked(t, w, w.LongPin()+":3", layoutread.Options{})
	if err != nil || strings.Contains(strings.Join(lr.Notices, "\n"), "not necessarily the newest") {
		t.Errorf("a key pin with a minimum sequence: %v %v", err, lr.Notices)
	}
}

// What an import records as the pin is a note the importer would have written.
//
// spec: SPO-Xlayout-OUT-024
func TestTheNoteTheImporterPinsMatchesTheWorkspaceItInstalled(t *testing.T) {
	w := twoHeads(t, "standard")
	snap := w.Snapshot()
	h := w.Head(2)
	key := layoutfix.Pat(0x31, 32)
	if err := layoutread.NoteMatchesSnapshot(h, snap, nil); err != nil {
		t.Fatalf("an authentic head: %v", err)
	}
	for name, edit := range map[string]func(h *layout.Head){
		"a key the installed workspace does not hold": func(h *layout.Head) { h.CheckpointKey = key },
		"another audit sequence":                      func(h *layout.Head) { h.AuditSeq++ },
		"another audit MAC":                           func(h *layout.Head) { h.AuditMAC = layoutfix.Pat(1, 32) },
		"another epoch":                               func(h *layout.Head) { h.Epoch = layoutfix.Pat(1, 16) },
		"another recovery key":                        func(h *layout.Head) { h.RecoveryKey = layoutfix.Pat(1, 32) },
		"another workspace":                           func(h *layout.Head) { h.Workspace = layoutfix.Pat(1, 16) },
	} {
		x := h
		edit(&x)
		if err := layoutread.NoteMatchesSnapshot(x, snap, nil); err == nil {
			t.Errorf("%s: matched", name)
		}
	}
	// the installed workspace's own key is fine
	x := h
	x.CheckpointKey = key
	if err := layoutread.NoteMatchesSnapshot(x, snap, key); err != nil {
		t.Errorf("the installed key: %v", err)
	}
	// time is not compared
	x = h
	x.Time = x.Time.Add(3600e9)
	if err := layoutread.NoteMatchesSnapshot(x, snap, nil); err != nil {
		t.Errorf("time: %v", err)
	}
	_ = errors.New
}

func layoutfixI64(v int64) *int64 { return &v }

func sortSlots(s []layout.Slot) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && string(s[j-1].ID) > string(s[j].ID); j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
