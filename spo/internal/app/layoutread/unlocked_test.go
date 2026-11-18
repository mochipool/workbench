package layoutread_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/layoutfix"
)

func openUnlocked(t *testing.T, w *layoutfix.World, o *layoutfix.Opener, pin string) (*layoutread.Unlocked, error) {
	t.Helper()
	lr, err := checkLocked(t, w, pin, layoutread.Options{})
	if err != nil {
		t.Fatalf("the locked pass: %v", err)
	}
	return layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: w.Dir, Locked: lr, Keys: o})
}

func pathOf(h []byte) string { p, _ := layout.ObjectPath(fmt.Sprintf("%x", h)); return p }

// the forged head 4 is pinned by an exact pin of head 3 and is unsigned: the
// locked pass accepts it, which is the strongest an attacker can make it.
func forged(t *testing.T, w *layoutfix.World, pre, post func(*layoutfix.Parts)) string {
	t.Helper()
	w.Forge(pre, post)
	return w.Pin(3)
}

func baseWorld(t *testing.T) *layoutfix.World {
	t.Helper()
	w := layoutfix.NewWorld(t, "standard", 6)
	w.MustExport()
	w.Change(1)
	w.MustExport()
	w.Change(2)
	w.MustExport()
	return w
}

func sameSnapshot(t *testing.T, got, want ports.Snapshot) {
	t.Helper()
	got.Meta.SchemaVersion, want.Meta.SchemaVersion = 0, 0
	if !reflect.DeepEqual(got.Meta, want.Meta) {
		t.Errorf("meta differs:\n%+v\n%+v", got.Meta, want.Meta)
	}
	if !reflect.DeepEqual(got.Slots, want.Slots) {
		t.Errorf("slots differ")
	}
	if len(got.Records) != len(want.Records) || len(got.Audit) != len(want.Audit) {
		t.Fatalf("%d/%d records, %d/%d audit rows", len(got.Records), len(want.Records), len(got.Audit), len(want.Audit))
	}
	for i := range want.Records {
		if !reflect.DeepEqual(got.Records[i], want.Records[i]) {
			t.Errorf("record %d differs", i)
		}
	}
	for i := range want.Audit {
		if !reflect.DeepEqual(got.Audit[i], want.Audit[i]) {
			t.Errorf("audit row %d differs", i)
		}
	}
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-016, SPO-Xlayout-INV-015, SPO-Xlayout-INV-026
func TestTheUnlockedPassRebuildsTheSnapshotForEveryPolicy(t *testing.T) {
	for _, policy := range []string{"standard", "hardware", "strict"} {
		t.Run(policy, func(t *testing.T) {
			w := layoutfix.NewWorld(t, policy, 6)
			w.MustExport()
			w.Change(3)
			w.MustExport()
			o := w.Opener()
			u, err := openUnlocked(t, w, o, w.Pin(2))
			if err != nil {
				t.Fatal(err)
			}
			sameSnapshot(t, u.Snapshot, w.Snapshot())
			if u.Records != 6 || u.Audit != len(w.Audit) {
				t.Fatalf("counts %d %d", u.Records, u.Audit)
			}
			if o.Opens.Load() != 1 || o.Closed.Load() != 1 {
				t.Errorf("opens %d closed %d", o.Opens.Load(), o.Closed.Load())
			}
		})
	}
}

// spec: SPO-Xlayout-INV-024
func TestAManyPageLayoutIsReadWithBoundedConcurrency(t *testing.T) {
	w := layoutfix.NewWorld(t, "standard", 1100) // three record pages and two audit pages
	w.MustExport()
	o := w.Opener()
	w.Dir.MaxLive = 0
	u, err := openUnlocked(t, w, o, w.Pin(1))
	if err != nil {
		t.Fatal(err)
	}
	sameSnapshot(t, u.Snapshot, w.Snapshot())
	if w.Dir.MaxLive > int64(layoutread.Workers) || w.Dir.MaxLive < 2 {
		t.Fatalf("up to %d reads were open at once; the bound is %d and the work is parallel", w.Dir.MaxLive, layoutread.Workers)
	}
	if got := w.Dir.Gets.Load(); got < int64(u.Objects) {
		t.Errorf("%d reads for %d objects", got, u.Objects)
	}
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-007, SPO-Xlayout-INV-008, SPO-Xlayout-INV-016
func TestAnObjectSwappedForAnotherValidObjectOfTheSameWorkspaceIsRefused(t *testing.T) {
	// by name: the bytes of record 1 under the name of record 0
	w := baseWorld(t)
	root := w.Root(3)
	rp := w.OpenStored(w.ObjectOf(root.RecordPages[0])).(layout.RecordPage)
	w.Dir.Set(pathOf(rp.Entries[0].Hash), w.ObjectOf(rp.Entries[1].Hash))
	_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrObject, "wrong content")

	// by entry: the page names record 1's object for record 0 (the attacker can re-seal pages)
	w = baseWorld(t)
	pin := forged(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = p.RecordPages[0].Entries[3].Hash }, nil) // records 0 and 3 are both at version 1
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrRecord, "but it is the object of record")

	// an older version of the same record, named for the newer one
	w = baseWorld(t)
	oldRoot := w.Root(1)
	oldPage := w.OpenStored(w.ObjectOf(oldRoot.RecordPages[0])).(layout.RecordPage)
	pin = forged(t, w, func(p *layoutfix.Parts) {
		for i, e := range p.RecordPages[0].Entries {
			if e.Version > 1 {
				p.RecordPages[0].Entries[i].Hash = oldPage.Entries[i].Hash
			}
		}
	}, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrRecord, "version")

	// an audit row named for another sequence number
	w = baseWorld(t)
	pin = forged(t, w, func(p *layoutfix.Parts) {
		e := p.AuditPages[0].Entries
		e[2].Hash, e[3].Hash = e[3].Hash, e[2].Hash
	}, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrAudit, "sequence")
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-016
func TestAPageThatOmitsDuplicatesOrReordersAnEntryIsRefused(t *testing.T) {
	// 1100 records: three record pages (512, 512, 76) and two audit pages (1000, 101)
	cases := map[string]struct{ pre, post func(p *layoutfix.Parts) }{
		"an omitted record":    {pre: func(p *layoutfix.Parts) { e := p.RecordPages[2].Entries; p.RecordPages[2].Entries = e[:len(e)-1] }},
		"an omitted audit row": {pre: func(p *layoutfix.Parts) { e := p.AuditPages[1].Entries; p.AuditPages[1].Entries = e[:len(e)-1] }},
		"a record page named twice": {post: func(p *layoutfix.Parts) {
			r := p.Root.RecordPages
			p.Root.RecordPages = [][]byte{r[0], r[0], r[1], r[2]}
		}},
		"an omitted record page":    {post: func(p *layoutfix.Parts) { r := p.Root.RecordPages; p.Root.RecordPages = [][]byte{r[0], r[2]} }},
		"reordered record pages":    {post: func(p *layoutfix.Parts) { r := p.Root.RecordPages; r[0], r[1] = r[1], r[0] }},
		"reordered audit pages":     {post: func(p *layoutfix.Parts) { r := p.Root.AuditPages; r[0], r[1] = r[1], r[0] }},
		"an audit page named twice": {post: func(p *layoutfix.Parts) { r := p.Root.AuditPages; p.Root.AuditPages = [][]byte{r[0], r[0]} }},
	}
	base := layoutfix.NewWorld(t, "standard", 1100)
	base.MustExport()
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w := *base
			w.Dir = base.Dir.Clone()
			w.Forge(c.pre, c.post)
			_, err := openUnlocked(t, &w, w.Opener(), w.Pin(1))
			wantErr(t, err, layoutread.ErrManifest)
		})
	}
	// the counts of the root changed to match an omitted record: the pages verify, so it is the
	// audit chain of the store (the scratch file's verification) that finds it; here the
	// snapshot simply has one record fewer than the audit chain names
	w := baseWorld(t)
	pin := forged(t, w, func(p *layoutfix.Parts) {
		e := p.RecordPages[0].Entries
		p.RecordPages[0].Entries = append(e[:2:2], e[3:]...)
	},
		func(p *layoutfix.Parts) { p.Root.Records-- })
	u, err := openUnlocked(t, w, w.Opener(), pin)
	if err != nil || len(u.Snapshot.Records) != 5 {
		t.Fatalf("%v", err)
	}
}

// spec: SPO-Xlayout-INV-009, SPO-Xlayout-INV-016
func TestTheRootAndTheHeadMustAgree(t *testing.T) {
	cases := []struct {
		name string
		post func(p *layoutfix.Parts)
		is   error
		in   string
	}{
		{"root audit MAC is not the head's", func(p *layoutfix.Parts) { p.Root.AuditMAC = layoutfix.Pat(0x44, 32) }, layoutread.ErrManifest, "audit"},
		{"root audit sequence is not the head's", func(p *layoutfix.Parts) { p.Head.AuditSeq-- }, layoutread.ErrManifest, "audit"},
		{"root slots object is not the head's", func(p *layoutfix.Parts) { p.Root.Slots = layoutfix.Pat(0x45, 32) }, layoutread.ErrManifest, "slots"},
		{"root belongs to another export", func(p *layoutfix.Parts) { p.Root.Parent.Seq = 2 }, layoutread.ErrManifest, "export"},
		{"root names another previous head", func(p *layoutfix.Parts) { p.Root.Parent.PreviousHead = layoutfix.Pat(0x46, 32) }, layoutread.ErrManifest, "export"},
		{"head and root both name a MAC that is not the last audit row's", func(p *layoutfix.Parts) {
			bad := layoutfix.Pat(0x47, 32)
			p.Root.AuditMAC, p.Head.AuditMAC = bad, bad
		}, layoutread.ErrAudit, "MAC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := baseWorld(t)
			h := w.Forge(nil, func(p *layoutfix.Parts) {
				c.post(p)
			})
			_ = h
			// Forge writes the head with the post-edited fields; the root's parent edit needs the root sealed after
			_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
			wantErr(t, err, c.is, c.in)
		})
	}
	// a manifest of another export of the same workspace under the newest head
	w := baseWorld(t)
	h := w.Head(3)
	h.Manifest = w.Head(2).Manifest
	w.RePutHead(h)
	_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrManifest, "export")
}

// spec: SPO-Xlayout-INV-010, SPO-Xlayout-INV-015, SPO-Xlayout-INV-016
func TestARecordWhoseAnchorOrNumberIsNotThatOfItsOwnerBlobIsRefused(t *testing.T) {
	for name, edit := range map[string]func(r *layout.Record){
		"anchor": func(r *layout.Record) { r.Anchor = append([]byte{0}, layoutfix.Pat(0x99, 28)...) },
		"number": func(r *layout.Record) { r.Num += 7 },
	} {
		t.Run(name, func(t *testing.T) {
			w := baseWorld(t)
			pin := forged(t, w, func(p *layoutfix.Parts) {
				e := &p.RecordPages[0].Entries[0]
				rec := w.OpenStored(w.ObjectOf(e.Hash)).(layout.Record)
				edit(&rec)
				e.Hash = w.PutObject(w.SealObject(rec))
			}, nil)
			_, err := openUnlocked(t, w, w.Opener(), pin)
			wantErr(t, err, layoutread.ErrRecord, "owner")
		})
	}
	// the lookup tag the importer writes is recomputed, never taken from the object
	w := baseWorld(t)
	u, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range u.Snapshot.Records {
		if !bytes.Equal(r.LookupTag, w.Records[i].LookupTag) {
			t.Errorf("record %d: lookup tag", i)
		}
	}
}

// spec: SPO-Xlayout-INV-011, SPO-Xlayout-INV-017, SPO-Xlayout-INV-016
func TestTheSlotsObjectMustMatchTheNewestSlotTableRowAndTheEpochMAC(t *testing.T) {
	w := baseWorld(t)
	pin := forged(t, w, func(p *layoutfix.Parts) {
		_, so, err := layout.ParseSlotsObject(p.SlotsStored)
		if err != nil {
			t.Fatal(err)
		}
		so.Slots[0].Nonce = layoutfix.Pat(0x13, 24) // a slot table the newest slots row did not record
		p.SlotsStored, err = layout.EncodeSlotsObject(so.Meta.KeyEpoch, so)
		if err != nil {
			t.Fatal(err)
		}
	}, nil)
	_, err := openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrSlots, "slot-set")

	w = baseWorld(t)
	o := w.Opener()
	o.BadEpochMAC = true
	_, err = openUnlocked(t, w, o, w.Pin(3))
	wantErr(t, err, layoutread.ErrSlots, "epoch MAC")
	if o.Closed.Load() != o.Opens.Load() {
		t.Error("the opener was not closed after a refusal")
	}

	// a workspace with no slot-table audit row at all
	w = baseWorld(t)
	pin = forged(t, w, func(p *layoutfix.Parts) {}, nil)
	_ = pin
}

// spec: SPO-Xlayout-OUT-021
func TestAnObjectThatIsMissingFlippedOversizedOrOfAnotherEpochIsRefused(t *testing.T) {
	rec0 := func(w *layoutfix.World) string {
		rp := w.OpenStored(w.ObjectOf(w.Root(3).RecordPages[0])).(layout.RecordPage)
		return pathOf(rp.Entries[0].Hash)
	}
	cases := map[string]func(w *layoutfix.World){
		"missing": func(w *layoutfix.World) { w.Dir.Delete(rec0(w)) },
		"flipped": func(w *layoutfix.World) {
			b := append([]byte(nil), w.Dir.Objs[rec0(w)]...)
			b[500] ^= 1
			w.Dir.Set(rec0(w), b)
		},
		"oversized":   func(w *layoutfix.World) { w.Dir.Set(rec0(w), make([]byte, 5<<20)) },
		"a directory": func(w *layoutfix.World) { w.Dir.GetErr[rec0(w)] = errors.New("is a directory") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			w := baseWorld(t)
			edit(w)
			_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
			wantErr(t, err, layoutread.ErrObject)
		})
	}
	// renamed to match: the bytes hash to the name, the size is a bucket, and nothing opens it
	w := baseWorld(t)
	junk := make([]byte, 4096)
	junk[0] = layout.FormatSealed
	copy(junk[1:], w.Epoch)
	pin := forged(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = w.PutObject(junk) }, nil)
	_, err := openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "open")
	// sealed under another epoch
	w = baseWorld(t)
	other := append([]byte(nil), w.Dir.Objs[rec0(w)]...)
	other[1] ^= 0xff
	pin = forged(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = w.PutObject(other) }, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "open")
}

// spec: SPO-Xlayout-INV-024
func TestHugeCountsAreRefusedBeforeAnythingIsFetched(t *testing.T) {
	for name, post := range map[string]func(p *layoutfix.Parts){
		"records": func(p *layoutfix.Parts) { p.Root.Records = ports.SnapshotMaxRecords + 1 },
		"audit rows": func(p *layoutfix.Parts) {
			p.Root.Audits, p.Root.AuditSeq, p.Head.AuditSeq = ports.SnapshotMaxAudit+1, ports.SnapshotMaxAudit+1, ports.SnapshotMaxAudit+1
		},
		"pages": func(p *layoutfix.Parts) {
			for len(p.Root.RecordPages) < 5000 {
				p.Root.RecordPages = append(p.Root.RecordPages, layoutfix.Pat(byte(len(p.Root.RecordPages)), 32))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := baseWorld(t)
			w.Forge(nil, post)
			lr, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
			if err != nil {
				t.Fatal(err)
			}
			before := w.Dir.Gets.Load()
			_, err = layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: w.Dir, Locked: lr, Keys: w.Opener()})
			wantErr(t, err, layoutread.ErrLimit)
			if n := w.Dir.Gets.Load() - before; n > 2 {
				t.Errorf("%d objects were fetched before the refusal", n)
			}
		})
	}
	// the bytes a pass may read
	w := baseWorld(t)
	old := layoutread.MaxStoredBytes
	layoutread.MaxStoredBytes = 40 << 10
	defer func() { layoutread.MaxStoredBytes = old }()
	_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrLimit, "bytes")
}

// spec: SPO-Xlayout-INV-025
func TestADirectoryThatChangesWhileItIsReadFailsClosed(t *testing.T) {
	// an object read the second time is not what it was
	w := baseWorld(t)
	var n atomic.Int32
	w.Dir.GetHook = func(name string, b []byte) []byte {
		if strings.HasPrefix(name, "objects/") && n.Add(1) == 9 {
			b[len(b)/2] ^= 1
		}
		return b
	}
	_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrObject)

	// the head it settled on is not the head at the end
	w = baseWorld(t)
	var reads atomic.Int32
	hn := layout.HeadPath(3)
	w.Dir.GetHook = func(name string, b []byte) []byte {
		if name == hn && reads.Add(1) == 2 {
			b = append([]byte(nil), b...)
			b[len(b)-2] ^= 1
		}
		return b
	}
	_, err = openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrChanged)
}

// spec: SPO-Xlayout-PRE-026
func TestACredentialFailureIsReturnedAsItIsAndNothingIsLeftOpen(t *testing.T) {
	w := baseWorld(t)
	o := w.Opener()
	sentinel := errors.New("the authenticator refused the PIN")
	o.Err = sentinel
	lr, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	before := w.Dir.Gets.Load()
	_, err = layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: w.Dir, Locked: lr, Keys: o})
	if !errors.Is(err, sentinel) {
		t.Fatalf("%v", err)
	}
	if n := w.Dir.Gets.Load() - before; n != 0 {
		t.Errorf("%d objects were fetched although no key could be had", n)
	}
}

// spec: SPO-Xlayout-SEC-008
func TestTheReaderHoldsNoPayloadOpener(t *testing.T) {
	// ports.ObjectOpener has no method that returns a payload, and the use case calls only
	// the metadata operations: a cold-role record is carried as bytes
	typ := reflect.TypeOf((*ports.ObjectOpener)(nil)).Elem()
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	want := "Close EpochMACValid Epoch LookupTag Open OwnerRef WorkspaceID"
	got := strings.Fields(want)
	if len(names) != len(got) {
		t.Fatalf("the opener's methods are %v", names)
	}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, n := range got {
		if !have[n] {
			t.Errorf("missing %s", n)
		}
	}
	w := layoutfix.NewWorld(t, "hardware", 4)
	w.MustExport()
	u, err := openUnlocked(t, w, w.Opener(), w.Pin(1))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range u.Snapshot.Records {
		if !bytes.Equal(r.Ciphertext, w.Records[i].Ciphertext) || !bytes.Equal(r.WrappedKey, w.Records[i].WrappedKey) || !bytes.Equal(r.OwnerSealed, w.Records[i].OwnerSealed) || !bytes.Equal(r.Nonce, w.Records[i].Nonce) {
			t.Errorf("record %d was not carried byte for byte", i)
		}
	}
}

// A snapshot read from a file with no record has no record slice at all, and an
// import must hand the store the same value (the store compares what it wrote
// with what it was given).
//
// spec: SPO-Xlayout-INV-026
func TestAnEmptyLayoutRebuildsAnEmptySnapshotThatEqualsTheStores(t *testing.T) {
	w := layoutfix.NewWorld(t, "standard", 0)
	w.MustExport()
	u, err := openUnlocked(t, w, w.Opener(), w.Pin(1))
	if err != nil {
		t.Fatal(err)
	}
	if u.Snapshot.Records != nil || len(u.Snapshot.Audit) != 1 {
		t.Fatalf("records %#v", u.Snapshot.Records)
	}
	sameSnapshot(t, u.Snapshot, w.Snapshot())
}

// ---- the checks that the tests above do not reach ----

func forgedRecordPins(t *testing.T, w *layoutfix.World, edit func(p *layoutfix.Parts)) string {
	t.Helper()
	w.Forge(edit, nil)
	return w.Pin(3)
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-016
func TestAnObjectOfTheWrongKindForItsPlaceIsRefused(t *testing.T) {
	// an audit object named as a record
	w := baseWorld(t)
	pin := forgedRecordPins(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = p.AuditPages[0].Entries[0].Hash })
	_, err := openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "not a record")
	// a record object named as an audit row
	w = baseWorld(t)
	pin = forgedRecordPins(t, w, func(p *layoutfix.Parts) { p.AuditPages[0].Entries[0].Hash = p.RecordPages[0].Entries[0].Hash })
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "not an audit row")
	// pages named in the wrong list, and a page named as the manifest root
	w = baseWorld(t)
	w.Forge(nil, func(p *layoutfix.Parts) {
		p.Root.RecordPages, p.Root.AuditPages = p.Root.AuditPages, p.Root.RecordPages
	})
	_, err = openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrManifest, "is not a record page")
	w = baseWorld(t)
	h := w.Head(3)
	h.Manifest = w.Root(3).RecordPages[0]
	w.RePutHead(h)
	_, err = openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrManifest, "not a manifest root")
	// a record page named as an audit page
	w = baseWorld(t)
	w.Forge(nil, func(p *layoutfix.Parts) { p.Root.AuditPages = [][]byte{p.Root.RecordPages[0]} })
	_, err = openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrManifest, "is not an audit page")
	// an audit page named as a record page
	w = baseWorld(t)
	w.Forge(nil, func(p *layoutfix.Parts) { p.Root.RecordPages = [][]byte{p.Root.AuditPages[0]} })
	_, err = openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrManifest, "is not a record page")
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-024
func TestTheAuditPageCountOfARootIsBounded(t *testing.T) {
	w := baseWorld(t)
	w.Forge(nil, func(p *layoutfix.Parts) {
		for len(p.Root.AuditPages) < 600 {
			p.Root.AuditPages = append(p.Root.AuditPages, layoutfix.Pat(byte(len(p.Root.AuditPages)), 32))
		}
	})
	lr, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: w.Dir, Locked: lr, Keys: w.Opener()})
	wantErr(t, err, layoutread.ErrLimit)
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-010
func TestAKeyOfAnotherEpochOrWorkspaceAndATagThatCannotBeMadeAreRefused(t *testing.T) {
	for name, set := range map[string]func(o *layoutfix.Opener){
		"another epoch":     func(o *layoutfix.Opener) { o.WrongEpoch = true },
		"another workspace": func(o *layoutfix.Opener) { o.WrongWorkspace = true },
	} {
		w := baseWorld(t)
		o := w.Opener()
		set(o)
		_, err := openUnlocked(t, w, o, w.Pin(3))
		if name == "another epoch" || name == "another workspace" {
			wantErr(t, err, layoutread.ErrSlots, "epoch or workspace")
		}
	}
	w := baseWorld(t)
	o := w.Opener()
	o.TagErr = errors.New("the anchor is not an identity")
	_, err := openUnlocked(t, w, o, w.Pin(3))
	wantErr(t, err, layoutread.ErrRecord, "lookup tag")
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-011
func TestARootWithNoSlotTableRowInItsAuditChainIsRefused(t *testing.T) {
	w := baseWorld(t)
	pin := forgedRecordPins(t, w, func(p *layoutfix.Parts) {
		a := w.OpenStored(w.ObjectOf(p.AuditPages[0].Entries[0].Hash)).(layout.Audit)
		a.Kind, a.SlotSet = "update", []byte{}
		p.AuditPages[0].Entries[0].Hash = w.PutObject(w.SealObject(a))
	})
	_, err := openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrSlots, "no slot-table row")
}

// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-015
func TestARecordVersionBeyondTheStoresRangeAndARepeatedLookupTagAreRefused(t *testing.T) {
	w := baseWorld(t)
	pin := forgedRecordPins(t, w, func(p *layoutfix.Parts) {
		e := &p.RecordPages[0].Entries[0]
		rec := w.OpenStored(w.ObjectOf(e.Hash)).(layout.Record)
		rec.Version, e.Version = 1<<63, 1<<63
		e.Hash = w.PutObject(w.SealObject(rec))
	})
	_, err := openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrRecord, "version")

	// two records with the same anchor, kind and number would have one lookup tag
	w = baseWorld(t)
	pin = forgedRecordPins(t, w, func(p *layoutfix.Parts) {
		es := p.RecordPages[0].Entries
		var a, b *layout.Record
		var ea *layout.RecordEntry
		for i := range es {
			rec := w.OpenStored(w.ObjectOf(es[i].Hash)).(layout.Record)
			if rec.Kind == "node.skey" {
				if a == nil {
					a = &rec
				} else if b == nil {
					b, ea = &rec, &es[i]
				}
			}
		}
		b.Anchor, b.Num = a.Anchor, a.Num
		b.Inner.Owner = layoutfix.OwnerBlob(w.WS, b.ID, b.Kind, b.Anchor, b.Num)
		ea.Hash = w.PutObject(w.SealObject(*b))
	})
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrSnapshot, "lookup tag")
}

// spec: SPO-Xlayout-INV-024
func TestACancelledContextStopsTheCheck(t *testing.T) {
	w := baseWorld(t)
	lr, err := checkLocked(t, w, w.Pin(3), layoutread.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: w.Dir, Locked: lr, Keys: w.Opener()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if _, err := layoutread.CheckLocked(ctx, lockedIn(t, w, w.Pin(3), layoutread.Options{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}

// ---- survivors of the first mutation pass, and the allocation bounds ----

func allocated(f func()) int64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return int64(b.TotalAlloc - a.TotalAlloc)
}

func cborText(s string) []byte { return append([]byte{0x60 + byte(len(s))}, s...) }

// A structure that CLAIMS a billion entries and holds none is refused without
// allocating for the claim: a root with a billion records, a root whose page list
// claims a billion hashes, and a page that claims a billion entries.
//
// spec: SPO-Xlayout-INV-024
func TestAHostileClaimOfABillionEntriesCostsAlmostNothing(t *testing.T) {
	const bound = 32 << 20
	cases := map[string]func(w *layoutfix.World) string{
		"a root that counts a billion records": func(w *layoutfix.World) string {
			w.Forge(nil, func(p *layoutfix.Parts) { p.Root.Records = 1_000_000_000 })
			return w.Pin(3)
		},
		"a root whose page list claims a billion hashes": func(w *layoutfix.World) string {
			raw := append([]byte{0x89}, cborText("manifest-root")...)
			raw = append(raw, layoutfix.CBORClaiming(1_000_000_000)...)
			h := w.Head(3)
			h.Manifest = w.SealRaw(raw)
			w.RePutHead(h)
			return w.Pin(3)
		},
		"a page that claims a billion entries": func(w *layoutfix.World) string {
			raw := append([]byte{0x83}, cborText("manifest-page")...)
			raw = append(raw, cborText("records")...)
			raw = append(raw, layoutfix.CBORClaiming(1_000_000_000)...)
			hash := w.SealRaw(raw)
			w.Forge(nil, func(p *layoutfix.Parts) { p.Root.RecordPages = [][]byte{hash} })
			return w.Pin(3)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			w := baseWorld(t)
			pin := mk(w)
			lr, err := checkLocked(t, w, pin, layoutread.Options{})
			if err != nil {
				t.Fatal(err)
			}
			var uerr error
			grew := allocated(func() {
				_, uerr = layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: w.Dir, Locked: lr, Keys: w.Opener()})
			})
			if uerr == nil {
				t.Fatal("accepted")
			}
			if grew > bound {
				t.Errorf("%d bytes were allocated to refuse the claim; the bound is %d", grew, bound)
			}
		})
	}
}

// The fields of the rows are counted as they are read: a layout cannot make the
// reader hold more than the snapshot limit before the snapshot is validated.
//
// spec: SPO-Xlayout-INV-024
func TestTheBytesOfTheRowsAreBoundedWhileTheyAreRead(t *testing.T) {
	w := baseWorld(t)
	old := layoutread.MaxFieldBytes
	layoutread.MaxFieldBytes = 3000
	defer func() { layoutread.MaxFieldBytes = old }()
	_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrLimit, "fields")
}

// spec: SPO-Xlayout-INV-011
func TestTheNewestSlotTableRowMayBeARollover(t *testing.T) {
	w := layoutfix.NewWorld(t, "standard", 4)
	w.Rekey()
	w.MustExport()
	u, err := openUnlocked(t, w, w.Opener(), w.Pin(1))
	if err != nil {
		t.Fatal(err)
	}
	sameSnapshot(t, u.Snapshot, w.Snapshot())
}

// The refusals say which object and which fact.
//
// spec: SPO-Xlayout-OUT-021, SPO-Xlayout-INV-016
func TestTheObjectRefusalsSayWhichFactFailed(t *testing.T) {
	rec0 := func(w *layoutfix.World) string {
		rp := w.OpenStored(w.ObjectOf(w.Root(3).RecordPages[0])).(layout.RecordPage)
		return pathOf(rp.Entries[0].Hash)
	}
	w := baseWorld(t)
	w.Dir.Set(rec0(w), make([]byte, 5<<20))
	_, err := openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrObject, "larger than")
	w = baseWorld(t)
	w.Dir.Delete(rec0(w))
	_, err = openUnlocked(t, w, w.Opener(), w.Pin(3))
	wantErr(t, err, layoutread.ErrObject, "is not in the directory")
	// opens badly: right bucket, named by its hash, not sealed under the keys
	w = baseWorld(t)
	junk := make([]byte, 4096)
	junk[0] = layout.FormatSealed
	copy(junk[1:], w.Epoch)
	pin := forged(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = w.PutObject(junk) }, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "does not open under the keys")
	// opens, and is not a well-formed object
	w = baseWorld(t)
	bad := w.SealRaw([]byte{0xa0}) // an empty map where an array is required
	pin = forged(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = bad }, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "not a well-formed object")
	// an owner blob that does not authenticate
	w = baseWorld(t)
	pin = forged(t, w, func(p *layoutfix.Parts) {
		e := &p.RecordPages[0].Entries[0]
		rec := w.OpenStored(w.ObjectOf(e.Hash)).(layout.Record)
		rec.Inner.Owner = append([]byte(nil), rec.Inner.Owner...)
		rec.Inner.Owner[len(rec.Inner.Owner)-1] ^= 1
		e.Hash = w.PutObject(w.SealObject(rec))
	}, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrRecord, "does not open")
	// an audit row and a record each in the other's place: the right sentinel and type
	w = baseWorld(t)
	pin = forged(t, w, func(p *layoutfix.Parts) { p.RecordPages[0].Entries[0].Hash = p.AuditPages[0].Entries[0].Hash }, nil)
	_, err = openUnlocked(t, w, w.Opener(), pin)
	wantErr(t, err, layoutread.ErrObject, "not a record")
}

// spec: SPO-Xlayout-PRE-024
func TestTheRecoveryKeyAndAnotherWorkspaceOfAKeyPinAreRefusedByName(t *testing.T) {
	w := threeHeads(t, true)
	lp := mustPin(t, w.LongPin())
	lp.WorkspaceID = layoutfix.Pat(0x66, 16)
	_, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: w.Dir, Pin: lp, Tables: &layoutfix.Tables{}})
	wantErr(t, err, layoutread.ErrWorkspace, "pinned workspace")
}
