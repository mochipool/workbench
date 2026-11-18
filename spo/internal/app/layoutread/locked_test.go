package layoutread_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/layoutfix"
)

func lockedIn(t *testing.T, w *layoutfix.World, pin string, opt layoutread.Options) layoutread.LockedInput {
	t.Helper()
	p, err := layoutread.ParsePin(pin)
	if err != nil {
		t.Fatalf("pin %q: %v", pin, err)
	}
	return layoutread.LockedInput{Reader: w.Dir, Pin: p, Opt: opt, Tables: &layoutfix.Tables{}}
}

func checkLocked(t *testing.T, w *layoutfix.World, pin string, opt layoutread.Options) (*layoutread.Locked, error) {
	t.Helper()
	return layoutread.CheckLocked(context.Background(), lockedIn(t, w, pin, opt))
}

// three heads: a change after each export
func threeHeads(t *testing.T, signed bool) *layoutfix.World {
	t.Helper()
	w := layoutfix.NewWorld(t, "standard", 5)
	if signed {
		w.WithKey()
	}
	w.MustExport()
	w.Change(1)
	w.MustExport()
	w.Change(2)
	w.MustExport()
	return w
}

func wantErr(t *testing.T, err error, is error, contains ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error; wanted %v", is)
	}
	if !errors.Is(err, is) {
		t.Fatalf("error %q is not %v", err, is)
	}
	for _, c := range contains {
		if !strings.Contains(err.Error(), c) {
			t.Errorf("the error lacks %q: %v", c, err)
		}
	}
}

// spec: SPO-Xlayout-PRE-020
func TestParsePinFormsAndRefusals(t *testing.T) {
	ws := strings.Repeat("ab", 16)
	hash := strings.Repeat("cd", 32)
	key := strings.Repeat("ef", 32)
	p, err := layoutread.ParsePin(ws + ":layout:7:" + hash)
	if err != nil || p.Kind != layoutread.PinExact || p.Sequence != 7 || fmt.Sprintf("%x", p.HeadHash) != hash || fmt.Sprintf("%x", p.WorkspaceID) != ws {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = layoutread.ParsePin(ws + ":ck:" + key)
	if err != nil || p.Kind != layoutread.PinKey || p.HasMin || fmt.Sprintf("%x", p.KeyHash) != key {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = layoutread.ParsePin(ws + ":ck:" + key + ":9")
	if err != nil || !p.HasMin || p.MinSeq != 9 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := layoutread.ParsePin(""); !errors.Is(err, layoutread.ErrNoPin) {
		t.Fatalf("an empty pin: %v", err)
	}
	for _, bad := range []string{
		"x", ws + ":layout:7", ws + ":layout:0:" + hash, ws + ":layout:07:" + hash, ws + ":layout:7:" + strings.ToUpper(hash),
		ws[:30] + ":layout:7:" + hash, ws + ":layout:7:" + hash[:62], ws + ":layout:99999999999999999999999:" + hash,
		ws + ":ck:" + key[:60], ws + ":other:7:" + hash, ws + ":layout:7:" + hash + ":x",
	} {
		if _, err := layoutread.ParsePin(bad); !errors.Is(err, layoutread.ErrBadPin) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	lp := layoutread.PinFromLocal([]byte{1, 2}, ports.LayoutPin{Sequence: 4, HeadHash: []byte{9}})
	if lp.Kind != layoutread.PinExact || lp.Sequence != 4 || len(lp.WorkspaceID) != 2 {
		t.Fatalf("%+v", lp)
	}
}

// spec: SPO-Xlayout-OUT-020, SPO-Xlayout-PRE-021
func TestExactPinAcceptsThePinnedHeadAndAnyLaterHeadThatChainsFromIt(t *testing.T) {
	w := threeHeads(t, false)
	lr, err := checkLocked(t, w, w.Pin(2), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if lr.Used.Head.Sequence != 3 || !lr.Newest || len(lr.Chain) != 2 {
		t.Fatalf("used %d newest %v chain %d", lr.Used.Head.Sequence, lr.Newest, len(lr.Chain))
	}
	if lr.Used.Signed {
		t.Fatal("an unsigned head reported as signed")
	}
	joined := strings.Join(lr.Notices, "\n")
	if !strings.Contains(joined, "not signed") || !strings.Contains(joined, "forgery") {
		t.Errorf("the notices do not say the head is unsigned and what that means:\n%s", joined)
	}
	if lr.Slots.Meta.Policy != "standard" {
		t.Fatalf("policy %q", lr.Slots.Meta.Policy)
	}
	// the pinned head itself, by --at
	lr, err = checkLocked(t, w, w.Pin(2), layoutread.Options{At: 2, HasAt: true})
	if err != nil || lr.Used.Head.Sequence != 2 || lr.Newest {
		t.Fatalf("at 2: %v %+v", err, lr)
	}
	// the exporter's own pin of the newest head
	if lr, err = checkLocked(t, w, w.Pin(3), layoutread.Options{}); err != nil || lr.Used.Head.Sequence != 3 {
		t.Fatalf("pin 3: %v", err)
	}
}

// spec: SPO-Xlayout-PRE-021
func TestExactPinRefusesARolledBackDirectoryAndAnotherHeadAtThePinnedSequence(t *testing.T) {
	w := threeHeads(t, false)
	pin3 := w.Pin(3)
	good := w.Dir.Clone()
	// rolled back: head 3 and the objects only it names are gone
	w.Dir.Delete(layout.HeadPath(3))
	_, err := checkLocked(t, w, pin3, layoutread.Options{})
	wantErr(t, err, layoutread.ErrRolledBack, "heads/00000000000000000003")
	// another head at the pinned sequence
	w.Dir = good.Clone()
	h := w.Head(3)
	h.Time = h.Time.Add(time.Second)
	w.RePutHead(h)
	_, err = checkLocked(t, w, pin3, layoutread.Options{})
	wantErr(t, err, layoutread.ErrPinHash)
	// the whole directory older: heads 1 and 2 only, with a pin of 3
	w.Dir = good.Clone()
	w.Dir.Delete(layout.HeadPath(3))
	_, err = checkLocked(t, w, pin3, layoutread.Options{At: 2, HasAt: true})
	wantErr(t, err, layoutread.ErrRolledBack)
	// --at below the pin is never accepted
	w.Dir = good.Clone()
	_, err = checkLocked(t, w, pin3, layoutread.Options{At: 2, HasAt: true})
	wantErr(t, err, layoutread.ErrRolledBack, "pin")
}

// spec: SPO-Xlayout-PRE-022
func TestKeyPinNeedsEverySignatureAndTheMinimumSequence(t *testing.T) {
	w := threeHeads(t, true)
	lr, err := checkLocked(t, w, w.LongPin(), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if lr.Used.Head.Sequence != 3 || !lr.Used.Signed || string(lr.Used.SignedBy) != string(w.KeyRec.Hash()) || len(lr.Chain) != 3 {
		t.Fatalf("%+v", lr.Used)
	}
	joined := strings.Join(lr.Notices, "\n")
	if !strings.Contains(joined, "newest") {
		t.Errorf("a key pin with no minimum sequence must say it does not prove the head is the newest:\n%s", joined)
	}
	// a minimum above the newest head: the directory is behind the pin
	_, err = checkLocked(t, w, w.LongPin()+":4", layoutread.Options{})
	wantErr(t, err, layoutread.ErrRolledBack, "4")
	// a minimum at the newest head is satisfied, and then it is said to prove it
	lr, err = checkLocked(t, w, w.LongPin()+":3", layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(lr.Notices, "\n"), "does not prove") {
		t.Errorf("a pin with a minimum sequence is told it does not prove the newest")
	}
	// an older head by --at, which the minimum refuses
	_, err = checkLocked(t, w, w.LongPin()+":3", layoutread.Options{At: 2, HasAt: true})
	wantErr(t, err, layoutread.ErrRolledBack)
	// and which a pin without a minimum allows, saying it may not be the newest
	lr, err = checkLocked(t, w, w.LongPin(), layoutread.Options{At: 2, HasAt: true})
	if err != nil || lr.Used.Head.Sequence != 2 || lr.Newest {
		t.Fatalf("%v %+v", err, lr)
	}
}

// spec: SPO-Xlayout-PRE-022
func TestKeyPinRefusesAnUnsignedHeadAnotherKeyAndAWrongNamespace(t *testing.T) {
	w := threeHeads(t, true)
	good := w.Dir.Clone()
	sigPath := layout.HeadPath(3) + ".sig"

	// no signature on head 3
	w.Dir.Delete(sigPath)
	_, err := checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "heads/00000000000000000003", "--at 2")

	// a signature by another key
	other := layoutfix.NewWorld(t, "standard", 5)
	other.WithKey()
	w.Dir = good.Clone()
	w.Dir.Set(sigPath, other.SignWith(w.Dir.Objs[layout.HeadPath(3)]))
	_, err = checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "heads/00000000000000000003")

	// a genuine signature over another note: head 3's signature on head 2
	w.Dir = good.Clone()
	w.Dir.Set(layout.HeadPath(2)+".sig", good.Objs[sigPath])
	_, err = checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "heads/00000000000000000002")

	// garbage and an oversized signature file
	for _, junk := range [][]byte{[]byte("not a signature"), make([]byte, 20<<10)} {
		w.Dir = good.Clone()
		w.Dir.Set(sigPath, junk)
		_, err = checkLocked(t, w, w.LongPin(), layoutread.Options{})
		wantErr(t, err, layoutread.ErrSignature)
	}

	// the verifier names the failing head and tells how to use the ones below it
	w.Dir = good.Clone()
	w.Dir.Delete(sigPath)
	lr, err := checkLocked(t, w, w.LongPin(), layoutread.Options{At: 2, HasAt: true})
	if err != nil || lr.Used.Head.Sequence != 2 {
		t.Fatalf("--at 2 must still work after head 3 failed: %v", err)
	}
}

// spec: SPO-Xlayout-PRE-023
func TestASquattedNextHeadStopsTheVerifierAndAtUsesTheHeadBelowIt(t *testing.T) {
	w := threeHeads(t, false)
	pin := w.Pin(3)
	w.Dir.Set(layout.HeadPath(4), []byte("junk, not a head note\n"))
	_, err := checkLocked(t, w, pin, layoutread.Options{})
	wantErr(t, err, layoutread.ErrChain, "heads/00000000000000000004", "--at 3")
	lr, err := checkLocked(t, w, pin, layoutread.Options{At: 3, HasAt: true})
	if err != nil || lr.Used.Head.Sequence != 3 {
		t.Fatalf("%v", err)
	}
	// a head 4 that parses but does not link
	h := w.Head(3)
	h.Sequence = 4
	h.Previous = make([]byte, 32)
	h.Previous[0] = 1
	w.RePutHead(h)
	_, err = checkLocked(t, w, pin, layoutread.Options{})
	wantErr(t, err, layoutread.ErrChain, "previous")
	// a head of another workspace
	h = w.Head(3)
	h.Sequence = 4
	h.Previous = layout.HeadHash(w.Dir.Objs[layout.HeadPath(3)])
	h.Workspace = layoutfix.Pat(0x77, 16)
	w.RePutHead(h)
	_, err = checkLocked(t, w, pin, layoutread.Options{})
	wantErr(t, err, layoutread.ErrWorkspace)
	// a note stored under another sequence number
	h = w.Head(3)
	w.Dir.Set(layout.HeadPath(4), w.Dir.Objs[layout.HeadPath(3)])
	_ = h
	_, err = checkLocked(t, w, pin, layoutread.Options{})
	wantErr(t, err, layoutread.ErrChain, "sequence")
}

// spec: SPO-Xlayout-PRE-021
func TestExactPinWithASignedPinnedHeadNeedsTheSameKeyOnLaterHeads(t *testing.T) {
	w := threeHeads(t, true)
	pin2 := w.Pin(2)
	good := w.Dir.Clone()
	lr, err := checkLocked(t, w, pin2, layoutread.Options{})
	if err != nil || lr.Used.Head.Sequence != 3 || !lr.Used.Signed {
		t.Fatalf("%v", err)
	}
	// head 3 appended by someone else, unsigned
	w.Dir.Delete(layout.HeadPath(3) + ".sig")
	_, err = checkLocked(t, w, pin2, layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "heads/00000000000000000003", "--at 2")
	// head 3 signed by another key
	other := layoutfix.NewWorld(t, "standard", 5)
	other.WithKey()
	w.Dir = good.Clone()
	w.Dir.Set(layout.HeadPath(3)+".sig", other.SignWith(w.Dir.Objs[layout.HeadPath(3)]))
	_, err = checkLocked(t, w, pin2, layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature)
}

// spec: SPO-Xlayout-PRE-024
func TestTheSlotsObjectAndTheManifestAreFetchedByHashAndChecked(t *testing.T) {
	base := threeHeads(t, false)
	newest := func(w *layoutfix.World) layout.Head { return w.Head(3) }
	path := func(h []byte) string { p, _ := layout.ObjectPath(fmt.Sprintf("%x", h)); return p }
	cases := []struct {
		name   string
		edit   func(w *layoutfix.World)
		is     error
		expect string
	}{
		{"slots object missing", func(w *layoutfix.World) { w.Dir.Delete(path(newest(w).Slots)) }, layoutread.ErrObject, "slots"},
		{"manifest missing", func(w *layoutfix.World) { w.Dir.Delete(path(newest(w).Manifest)) }, layoutread.ErrObject, "manifest"},
		{"slots object flipped", func(w *layoutfix.World) {
			p := path(newest(w).Slots)
			b := append([]byte(nil), w.Dir.Objs[p]...)
			b[100] ^= 1
			w.Dir.Set(p, b)
		}, layoutread.ErrObject, "wrong content"},
		{"manifest flipped", func(w *layoutfix.World) {
			p := path(newest(w).Manifest)
			b := append([]byte(nil), w.Dir.Objs[p]...)
			b[len(b)-1] ^= 1
			w.Dir.Set(p, b)
		}, layoutread.ErrObject, "wrong content"},
		{"slots object truncated", func(w *layoutfix.World) {
			p := path(newest(w).Slots)
			w.Dir.Set(p, w.Dir.Objs[p][:len(w.Dir.Objs[p])-1])
		}, layoutread.ErrObject, ""},
		{"manifest with a trailing byte", func(w *layoutfix.World) {
			p := path(newest(w).Manifest)
			w.Dir.Set(p, append(append([]byte(nil), w.Dir.Objs[p]...), 0))
		}, layoutread.ErrObject, ""},
		{"manifest of a size that is no bucket, under its own name", func(w *layoutfix.World) {
			// the bytes hash to the name (the attacker can name them so), but the size is not a bucket
			h := newest(w)
			junk := make([]byte, 5000)
			junk[0] = layout.FormatSealed
			copy(junk[1:], h.Epoch)
			name := layout.ObjectName(junk)
			w.Dir.Set(path(layoutHashOf(name)), junk)
			h.Manifest = layoutHashOf(name)
			w.RePutHead(h)
		}, layoutread.ErrObject, "bucket"},
		{"slots object that is a sealed object", func(w *layoutfix.World) {
			h := newest(w)
			h.Slots = h.Manifest
			w.RePutHead(h)
		}, layoutread.ErrSlots, ""},
		{"manifest that is the slots object", func(w *layoutfix.World) {
			h := newest(w)
			h.Manifest = h.Slots
			w.RePutHead(h)
		}, layoutread.ErrManifest, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := *base
			w.Dir = base.Dir.Clone()
			c.edit(&w)
			_, err := checkLockedAnyPin(t, &w)
			wantErr(t, err, c.is, c.expect)
		})
	}
}

func layoutHashOf(name string) []byte {
	b, _ := hex.DecodeString(name)
	return b
}

// checkLockedAnyPin pins the head the directory now has at sequence 3, which an
// attacker who rewrote head 3 would present, to reach the object checks.
func checkLockedAnyPin(t *testing.T, w *layoutfix.World) (*layoutread.Locked, error) {
	t.Helper()
	return checkLocked(t, w, w.Pin(3), layoutread.Options{})
}

// spec: SPO-Xlayout-PRE-024
func TestASlotsObjectOfAnotherEpochOrWorkspaceOrPolicyIsRefused(t *testing.T) {
	w := threeHeads(t, false)
	h := w.Head(3)
	stored := w.ObjectOf(h.Slots)
	_, so, err := layout.ParseSlotsObject(stored)
	if err != nil {
		t.Fatal(err)
	}
	good := w.Dir.Clone()
	rehead := func(w *layoutfix.World, h layout.Head, st []byte) {
		h.Slots = w.PutObject(st)
		w.RePutHead(h)
	}

	// another epoch: the header and meta say so, the head does not
	so2 := so
	so2.Meta.KeyEpoch = layoutfix.Pat(0x11, 16)
	st2, err := layout.EncodeSlotsObject(so2.Meta.KeyEpoch, so2)
	if err != nil {
		t.Fatal(err)
	}
	rehead(w, h, st2)
	_, err = checkLockedAnyPin(t, w)
	wantErr(t, err, layoutread.ErrSlots, "epoch")

	// another workspace
	w.Dir = good.Clone()
	so3 := so
	so3.Meta.WorkspaceID = layoutfix.Pat(0x55, 16)
	st3, err := layout.EncodeSlotsObject(so3.Meta.KeyEpoch, so3)
	if err != nil {
		t.Fatal(err)
	}
	rehead(w, h, st3)
	_, err = checkLockedAnyPin(t, w)
	wantErr(t, err, layoutread.ErrSlots, "workspace")

	// a recovery key that is not the one the head names
	w.Dir = good.Clone()
	so4 := so
	pub := layoutfix.Pat(0x66, 32)
	so4.Meta.RecoveryPub = pub
	so4.Meta.RecoveryPubHash = layoutfix.Sha(pub)
	st4, err := layout.EncodeSlotsObject(so4.Meta.KeyEpoch, so4)
	if err != nil {
		t.Fatal(err)
	}
	rehead(w, h, st4)
	_, err = checkLockedAnyPin(t, w)
	wantErr(t, err, layoutread.ErrSlots, "recovery")

	// a slot table that breaks its own policy (the daily slot removed)
	w.Dir = good.Clone()
	so5 := so
	so5.Slots = so.Slots[1:]
	st5, err := layout.EncodeSlotsObject(so5.Meta.KeyEpoch, so5)
	if err != nil {
		t.Fatal(err)
	}
	rehead(w, h, st5)
	tables := &layoutfix.Tables{}
	_, err = layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: mustPin(t, w.Pin(3)), Tables: tables})
	wantErr(t, err, layoutread.ErrSlots, "policy")
	if tables.Calls.Load() != 1 {
		t.Errorf("the policy check was called %d times", tables.Calls.Load())
	}
}

func mustPin(t *testing.T, s string) layoutread.Pin {
	t.Helper()
	p, err := layoutread.ParsePin(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: SPO-Xlayout-PRE-023, SPO-Xlayout-INV-024
func TestTheNumberOfHeadsExaminedIsBounded(t *testing.T) {
	w := layoutfix.NewWorld(t, "standard", 2)
	w.MustExport()
	for i := 0; i < 4; i++ {
		w.Change(0)
		w.MustExport()
	}
	old := layoutread.MaxHeads
	layoutread.MaxHeads = 3
	defer func() { layoutread.MaxHeads = old }()
	_, err := checkLocked(t, w, w.Pin(1), layoutread.Options{})
	wantErr(t, err, layoutread.ErrLimit, "3")
}

// spec: SPO-Xlayout-OUT-020, SPO-Xlayout-PRE-020
func TestTheLockedPassAsksNoCredentialAndReportsWhatItCannotEstablish(t *testing.T) {
	w := threeHeads(t, false)
	o := w.Opener()
	lr, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Opens.Load() != 0 {
		t.Fatal("the locked pass unlocked something")
	}
	joined := strings.Join(lr.Cannot, "\n")
	for _, want := range []string{"sealed", "audit chain", "records"} {
		if !strings.Contains(joined, want) {
			t.Errorf("what a locked check cannot establish lacks %q:\n%s", want, joined)
		}
	}
	if len(lr.Established) == 0 {
		t.Error("nothing established")
	}
}

// endless serves an unending stream for the names it is asked to, counting what
// is read.
type endless struct {
	inner ports.ObjectReader
	match func(name string) bool
	read  atomic.Int64
}

func (e *endless) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if e.match(name) {
		return io.NopCloser(&countingZeros{&e.read}), nil
	}
	return e.inner.Get(ctx, name)
}
func (e *endless) Has(ctx context.Context, name string) (bool, error) { return e.inner.Has(ctx, name) }

type countingZeros struct{ n *atomic.Int64 }

// endlessCap ends the stream with an error after this many bytes, so that a
// reader without its bound fails the test in a small, known amount of memory
// instead of exhausting the machine.
const endlessCap = 48 << 20

func (c *countingZeros) Read(p []byte) (int, error) {
	if c.n.Load() >= endlessCap {
		return 0, errors.New("the test stream was read past any bound")
	}
	for i := range p {
		p[i] = 0
	}
	c.n.Add(int64(len(p)))
	return len(p), nil
}

// spec: SPO-Xlayout-INV-024
func TestAHostileFileNeverCostsMoreThanItsBound(t *testing.T) {
	w := threeHeads(t, true)
	slotsPath := pathOf(w.Head(3).Slots)
	cases := map[string]struct {
		match func(string) bool
		bound int64
		pin   string
	}{
		"a head":      {func(n string) bool { return n == layout.HeadPath(2) }, int64(layout.MaxHeadSize), w.Pin(1)},
		"a signature": {func(n string) bool { return n == layout.HeadPath(3)+".sig" }, 16 << 10, w.LongPin()},
		"an object":   {func(n string) bool { return n == slotsPath }, int64(layout.MaxBucket), w.Pin(3)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := &endless{inner: w.Dir, match: c.match}
			p, _ := layoutread.ParsePin(c.pin)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: e, Pin: p, Tables: &layoutfix.Tables{}})
			if err == nil {
				t.Fatal("accepted")
			}
			// read in chunks of at most 32 KiB by io.ReadAll; allow one chunk over the bound
			runtime.ReadMemStats(&after)
			if grew := int64(after.TotalAlloc - before.TotalAlloc); grew > 3*c.bound+(8<<20) {
				t.Errorf("%d bytes were allocated to refuse a file of a bound of %d", grew, c.bound)
			}
			if got := e.read.Load(); got > c.bound+64<<10 {
				t.Errorf("read %d bytes of an endless file; the bound is %d", got, c.bound)
			}
		})
	}
}

// spec: SPO-Xlayout-PRE-020
func TestAKeyPinWithAShortWorkspaceIdAndAnOutOfRangeSequenceAreRefused(t *testing.T) {
	key := strings.Repeat("ef", 32)
	for _, bad := range []string{
		strings.Repeat("ab", 8) + ":ck:" + key,
		strings.Repeat("ab", 16) + ":layout:4294967297:" + strings.Repeat("cd", 32),
	} {
		if _, err := layoutread.ParsePin(bad); !errors.Is(err, layoutread.ErrBadPin) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := layoutread.ParsePin(strings.Repeat("ab", 16) + ":layout:4294967296:" + strings.Repeat("cd", 32)); err != nil {
		t.Errorf("the largest sequence number: %v", err)
	}
}

// spec: SPO-Xlayout-PRE-023
func TestTheAdviceToUseAtNamesNoHeadTheMinimumRefuses(t *testing.T) {
	w := threeHeads(t, true)
	w.Dir.Delete(layout.HeadPath(3) + ".sig")
	_, err := checkLocked(t, w, w.LongPin()+":3", layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "heads/00000000000000000003")
	if strings.Contains(err.Error(), "--at") {
		t.Errorf("the advice names a head the pin refuses: %v", err)
	}
}

// spec: SPO-Xlayout-PRE-021
func TestASignatureFileNextToAHeadThatNamesNoKeyIsNotCounted(t *testing.T) {
	w := threeHeads(t, false)
	pin := w.Pin(1)
	w.Dir.Set(layout.HeadPath(2)+".sig", []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"))
	lr, err := checkLocked(t, w, pin, layoutread.Options{})
	if err != nil || lr.Used.Head.Sequence != 3 {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(strings.Join(lr.Notices, "\n"), "does not verify") {
		t.Errorf("the notices do not mention the signature that does not count:\n%v", lr.Notices)
	}
	// a signature file on the pinned head itself
	w.Dir.Set(layout.HeadPath(1)+".sig", []byte("not a signature"))
	lr, err = checkLocked(t, w, pin, layoutread.Options{})
	if err != nil || !strings.Contains(strings.Join(lr.Notices, "\n"), "heads/00000000000000000001.sig does not verify") {
		t.Fatalf("%v %v", err, lr)
	}
}

// ---- the survivors of the first mutation pass ----

// spec: SPO-Xlayout-PRE-020, SPO-Xlayout-INV-024
func TestMissingInputsAreRefusedNotRun(t *testing.T) {
	w := threeHeads(t, false)
	good := lockedIn(t, w, w.Pin(3), layoutread.Options{})
	ctx := context.Background()
	in := good
	in.Reader = nil
	if _, err := layoutread.CheckLocked(ctx, in); err == nil {
		t.Error("no reader")
	}
	in = good
	in.Tables = nil
	if _, err := layoutread.CheckLocked(ctx, in); err == nil {
		t.Error("no table check")
	}
	in = good
	in.Pin = layoutread.Pin{}
	if _, err := layoutread.CheckLocked(ctx, in); !errors.Is(err, layoutread.ErrNoPin) {
		t.Errorf("a zero pin: %v", err)
	}
	in = good
	in.Pin.WorkspaceID = []byte{1}
	if _, err := layoutread.CheckLocked(ctx, in); !errors.Is(err, layoutread.ErrBadPin) {
		t.Errorf("a short workspace id: %v", err)
	}
	if _, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: w.Dir, Keys: w.Opener()}); err == nil {
		t.Error("no locked result")
	}
	lr, _ := layoutread.CheckLocked(ctx, good)
	if _, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Locked: lr, Keys: w.Opener()}); err == nil {
		t.Error("no reader")
	}
	if _, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: w.Dir, Locked: lr}); err == nil {
		t.Error("no keys")
	}
	if _, err := layoutread.BuildScratch(ctx, nil, &fileWriter{}, ports.Snapshot{}); err == nil {
		t.Error("no scratch")
	}
}

// --at that names no head is refused, naming the sequence: it never falls back to
// the newest head.
//
// spec: SPO-Xlayout-PRE-023
func TestAtNamingAHeadThatIsNotThereIsRefused(t *testing.T) {
	w := threeHeads(t, false)
	_, err := checkLocked(t, w, w.Pin(2), layoutread.Options{At: 7, HasAt: true})
	wantErr(t, err, layoutread.ErrNoHead, "heads/00000000000000000007", "--at 7")
	_, err = checkLocked(t, w, w.Pin(2), layoutread.Options{At: 1 << 33, HasAt: true})
	wantErr(t, err, layoutread.ErrBadPin, "--at")
}

// spec: SPO-Xlayout-INV-024
func TestAnIOErrorOnTheHeadPastTheLimitIsStillTheLimit(t *testing.T) {
	w := layoutfix.NewWorld(t, "standard", 2)
	w.MustExport()
	for i := 0; i < 3; i++ {
		w.Change(0)
		w.MustExport()
	}
	old := layoutread.MaxHeads
	layoutread.MaxHeads = 3
	defer func() { layoutread.MaxHeads = old }()
	w.Dir.GetErr[layout.HeadPath(4)] = errors.New("input/output error")
	_, err := checkLocked(t, w, w.Pin(1), layoutread.Options{})
	wantErr(t, err, layoutread.ErrLimit)
	// exactly MaxHeads heads is not over the limit
	w.Dir.Delete(layout.HeadPath(4))
	delete(w.Dir.GetErr, layout.HeadPath(4))
	if lr, err := checkLocked(t, w, w.Pin(1), layoutread.Options{}); err != nil || lr.Used.Head.Sequence != 3 || !lr.Newest {
		t.Fatalf("%v", err)
	}
}

// A signature on a head that names no checkpoint key is not counted, whoever made
// it: there is no key to verify it against.
//
// spec: SPO-Xlayout-PRE-021
func TestASignatureOnAHeadThatNamesNoKeyDoesNotCount(t *testing.T) {
	w := threeHeads(t, false)
	other := layoutfix.NewWorld(t, "standard", 5)
	other.WithKey()
	w.Dir.Set(layout.HeadPath(3)+".sig", other.SignWith(w.Dir.Objs[layout.HeadPath(3)]))
	lr, err := checkLocked(t, w, w.Pin(2), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if lr.Used.Signed || lr.Used.SignedBy != nil {
		t.Fatalf("a signature of an unnamed key counted: %+v", lr.Used)
	}
	if !strings.Contains(strings.Join(lr.Notices, "\n"), "names no checkpoint key") {
		t.Errorf("%v", lr.Notices)
	}
}

// spec: SPO-Xlayout-PRE-021, SPO-Xlayout-PRE-022
func TestAHeadThatNamesAnotherKeyAndIsSignedByItIsRefused(t *testing.T) {
	other := layoutfix.NewWorld(t, "standard", 5)
	other.WithKey()
	for _, pinOf := range []func(w *layoutfix.World) string{func(w *layoutfix.World) string { return w.Pin(2) }, func(w *layoutfix.World) string { return w.LongPin() }} {
		w := threeHeads(t, true)
		h := w.Head(3)
		h.CheckpointKey = other.KeyRec.Hash()
		note := w.RePutHead(h)
		w.Dir.Set(layout.HeadPath(3)+".sig", other.SignWith(note))
		_, err := checkLocked(t, w, pinOf(w), layoutread.Options{})
		wantErr(t, err, layoutread.ErrSignature, "heads/00000000000000000003")
	}
	// signed by the pinned key itself, but the note names another key
	w := threeHeads(t, true)
	h := w.Head(3)
	h.CheckpointKey = other.KeyRec.Hash()
	w.Dir.Set(layout.HeadPath(3), mustEncode(t, h))
	w.Dir.Set(layout.HeadPath(3)+".sig", w.SignWith(w.Dir.Objs[layout.HeadPath(3)]))
	_, err := checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "names another checkpoint key")
}

// The messages say which fact failed.
//
// spec: SPO-Xlayout-PRE-021, SPO-Xlayout-PRE-022, SPO-Xlayout-PRE-023, SPO-Xlayout-PRE-024, SPO-Xlayout-OUT-020
func TestTheRefusalsSayWhichFactFailed(t *testing.T) {
	// the pinned head is another note: no advice about heads below it
	w := threeHeads(t, false)
	h := w.Head(3)
	h.Time = h.Time.Add(time.Second)
	pin3 := w.Pin(3)
	w.RePutHead(h)
	_, err := checkLocked(t, w, pin3, layoutread.Options{})
	wantErr(t, err, layoutread.ErrPinHash, "not the head the pin names")
	if strings.Contains(err.Error(), "--at") {
		t.Errorf("advice for the pinned head: %v", err)
	}
	// a head that is not a note
	w = threeHeads(t, false)
	w.Dir.Set(layout.HeadPath(4), []byte("junk\n"))
	_, err = checkLocked(t, w, w.Pin(3), layoutread.Options{})
	wantErr(t, err, layoutread.ErrChain, "not a valid head note")
	// a signature that does not verify against the pinned key
	w = threeHeads(t, true)
	w.Dir.Set(layout.HeadPath(3)+".sig", []byte("not a signature"))
	_, err = checkLocked(t, w, w.LongPin(), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "does not verify against the pinned key")
	w = threeHeads(t, true)
	w.Dir.Set(layout.HeadPath(3)+".sig", []byte("not a signature"))
	_, err = checkLocked(t, w, w.Pin(2), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSignature, "does not verify against the key the pinned head names")
	// a missing object
	w = threeHeads(t, false)
	w.Dir.Delete(pathOf(w.Head(3).Slots))
	_, err = checkLocked(t, w, w.Pin(3), layoutread.Options{})
	wantErr(t, err, layoutread.ErrObject, "is not in the directory")
	// the notices
	w = threeHeads(t, false)
	lr, err := checkLocked(t, w, w.Pin(1), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lr.Notices, "\n")
	if !strings.Contains(joined, "chain from it by hash only") || !strings.Contains(joined, "--at 1") {
		t.Errorf("heads above an exact pin that names no key are not flagged:\n%s", joined)
	}
	lr, err = checkLocked(t, w, w.Pin(1), layoutread.Options{At: 2, HasAt: true})
	if err != nil || !strings.Contains(strings.Join(lr.Notices, "\n"), "may hold newer heads") {
		t.Fatalf("%v %v", err, lr)
	}
}

// spec: SPO-Xlayout-PRE-024
func TestAManifestUnderAnotherEpochOrOfAnUnknownFormatIsRefused(t *testing.T) {
	w := threeHeads(t, false)
	h := w.Head(3)
	good := w.Dir.Clone()
	// the same bytes with another epoch in the plaintext header, named by their own hash
	other := append([]byte(nil), w.ObjectOf(h.Manifest)...)
	other[1] ^= 0xff
	h.Manifest = w.PutObject(other)
	w.RePutHead(h)
	_, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
	wantErr(t, err, layoutread.ErrManifest, "another export")
	// an unknown format byte
	w.Dir = good.Clone()
	h = w.Head(3)
	odd := append([]byte(nil), w.ObjectOf(h.Manifest)...)
	odd[0] = 0x07
	h.Manifest = w.PutObject(odd)
	w.RePutHead(h)
	_, err = checkLocked(t, w, w.Pin(3), layoutread.Options{})
	wantErr(t, err, layoutread.ErrManifest, "format byte")
	// a slots object that is not one
	w.Dir = good.Clone()
	h = w.Head(3)
	h.Slots = w.Head(3).Manifest
	w.RePutHead(h)
	_, err = checkLocked(t, w, w.Pin(3), layoutread.Options{})
	wantErr(t, err, layoutread.ErrSlots, "not a slots object")
}

// a reader whose Get cancels the context while the body is being read
type cancelling struct {
	inner  ports.ObjectReader
	cancel context.CancelFunc
	name   string
}

type cancelBody struct {
	io.Reader
	cancel context.CancelFunc
	done   bool
}

func (c *cancelBody) Read(p []byte) (int, error) {
	if !c.done {
		c.done = true
		c.cancel()
	}
	return c.Reader.Read(p)
}
func (c *cancelBody) Close() error { return nil }

func (c *cancelling) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	rc, err := c.inner.Get(ctx, name)
	if err != nil || name != c.name {
		return rc, err
	}
	b, _ := io.ReadAll(rc)
	return &cancelBody{Reader: &slowReader{b: b}, cancel: c.cancel}, nil
}
func (c *cancelling) Has(ctx context.Context, name string) (bool, error) {
	return c.inner.Has(ctx, name)
}

type slowReader struct {
	b   []byte
	pos int
}

func (s *slowReader) Read(p []byte) (int, error) {
	if s.pos >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), 100)], s.b[s.pos:])
	s.pos += n
	return n, nil
}

// spec: SPO-Xlayout-INV-024
func TestACancelledContextStopsAReadInTheMiddle(t *testing.T) {
	w := threeHeads(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancelling{inner: w.Dir, cancel: cancel, name: pathOf(w.Head(3).Slots)}
	p, _ := layoutread.ParsePin(w.Pin(3))
	_, err := layoutread.CheckLocked(ctx, layoutread.LockedInput{Reader: r, Pin: p, Tables: &layoutfix.Tables{}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// spec: SPO-Xlayout-PRE-020
func TestAPinWithACapitalWorkspaceIdIsRefused(t *testing.T) {
	if _, err := layoutread.ParsePin(strings.Repeat("AB", 16) + ":layout:7:" + strings.Repeat("cd", 32)); !errors.Is(err, layoutread.ErrBadPin) {
		t.Fatal(err)
	}
}

func mustEncode(t *testing.T, h layout.Head) []byte {
	t.Helper()
	b, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
