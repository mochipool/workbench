package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/layoutdir"
	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// THE DIFFERENTIAL SUITE (ADR 0012 stage 3, the last work package).
//
// A scripted list of operations runs on one real SQLite workspace. After EVERY step
// the workspace is exported to a layout directory (incrementally), the layout is
// verified locked and unlocked, imported into a fresh directory, and the import is
// compared with the source: every row of every table (the only difference allowed
// is the transient cleanup marker), the deep verification of the import, the
// records, the non-secret reads and the cold status, and a read-only handle opened
// from the layout over the same records. The incremental property is asserted too:
// a step that changes k records writes the objects of those records, the objects of
// the audit rows it added, the pages whose entries changed, a root, and a head.
//
// It lives in this package, not in a package of its own, because the fixtures it
// needs (the fake authenticator, the cold-role fixtures and the generators of the
// format 2 and legacy files) are tests of this package, and because the command
// wiring is the main package's and cannot be imported.

// dtrack is one workspace the script runs on.
type dtrack struct {
	t    *testing.T
	path string // the workspace file
	root string // the layout directory
	pass string // the passphrase (standard)
	fake *fakeSource
	// dev and pin are the daily authenticator (hardware, strict)
	dev, pin string
	coldPass string

	// pbuf is the passphrase as a guarded buffer, made once for each passphrase and
	// destroyed at the end of the test: the locked-memory budget of the process is
	// shared by every test, and a buffer made for each call would use it up.
	pbuf    *secret.Buffer
	pbufFor string

	prev   *ports.Snapshot
	tree   map[string]bool
	heads  uint64
	checks int
	// lastWritten is what the last export wrote; objects/heads are its headline.
	lastWritten int
}

func newTrack(t *testing.T, path, pass string) *dtrack {
	t.Helper()
	w := &dtrack{t: t, path: path, pass: pass, coldPass: "a cold sub-key passphrase", root: filepath.Join(t.TempDir(), "layout")}
	t.Cleanup(func() { w.pbuf.Destroy() })
	return w
}

func (w *dtrack) cred() SnapshotCredential {
	if w.fake != nil {
		in := w.fake.inputs(w.dev, w.pin)
		return SnapshotCredential{Factors: &in}
	}
	return SnapshotCredential{Passphrase: w.passBuf()}
}

func (w *dtrack) passBuf() *secret.Buffer {
	if w.pbuf == nil || w.pbufFor != w.pass {
		w.pbuf.Destroy()
		w.pbuf, w.pbufFor = passphrase(w.pass), w.pass
	}
	return w.pbuf
}

func (w *dtrack) coldSource() *ColdSource {
	if w.fake != nil {
		in := w.fake.inputs(w.dev, w.pin)
		return &ColdSource{Factors: &in, Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}}
	}
	src := coldPass(w.coldPass)
	src.Deriver = fakeDeriver{}
	src.Mnemonic = fakeMnemonic{}
	return src
}

func (w *dtrack) open() *Store {
	w.t.Helper()
	var s *Store
	var err error
	if w.fake != nil {
		s, err = openHW(w.path, w.fake, w.dev, w.pin)
	} else {
		s, err = Open(w.path, w.passBuf())
	}
	if err != nil {
		w.t.Fatalf("opening the workspace: %v", err)
	}
	s.SetColdSource(w.coldSource())
	return s
}

// step runs fn on the open workspace, closes it and checks everything.
func (w *dtrack) step(name string, fn func(s *Store)) {
	w.t.Helper()
	s := w.open()
	fn(s)
	if err := s.Close(); err != nil {
		w.t.Fatalf("%s: closing: %v", name, err)
	}
	w.check(name)
}

func sameRow[T any](a, b T) bool { return reflect.DeepEqual(a, b) }

// expectedNewObjects is how many objects an export writes for the change from prev
// to cur: the record objects of the records that are new or changed, the audit
// objects of the rows added, the record page and the audit page when their entries
// changed, the manifest root, and the slots object when the table or meta changed.
//
// Every object is sealed under the key epoch of the workspace, so a step that
// changes the epoch (a rotation, a rekey, a recovery) writes every object again:
// the incremental property holds within a key epoch.
func expectedNewObjects(prev, cur ports.Snapshot) (n, changed int) {
	if !bytes.Equal(prev.Meta.KeyEpoch, cur.Meta.KeyEpoch) {
		return len(cur.Records) + len(cur.Audit) + 4, len(cur.Records)
	}
	old := map[string]ports.SnapshotRecord{}
	for _, r := range prev.Records {
		old[string(r.ID)] = r
	}
	now := map[string]bool{}
	for _, r := range cur.Records {
		now[string(r.ID)] = true
		if o, ok := old[string(r.ID)]; !ok || !sameRow(o, r) {
			changed++
		}
	}
	deleted := 0
	for id := range old {
		if !now[id] {
			deleted++
		}
	}
	// an audit row is new when its sequence number is new or its row differs: a
	// rotation or a rekey MACs the whole chain again under the new audit key
	added := 0
	for i, r := range cur.Audit {
		if i >= len(prev.Audit) || !sameRow(prev.Audit[i], r) {
			added++
		}
	}
	n = changed + added + 1
	if changed > 0 || deleted > 0 {
		n++
	}
	if added > 0 {
		n++
	}
	pm, cm := prev.Meta, cur.Meta
	pm.CleanupPending, cm.CleanupPending = 0, 0
	if !reflect.DeepEqual(pm, cm) || !reflect.DeepEqual(prev.Slots, cur.Slots) {
		n++
	}
	return n, changed
}

func auditChanged(prev, cur ports.Snapshot) int {
	if !bytes.Equal(prev.Meta.KeyEpoch, cur.Meta.KeyEpoch) {
		return len(cur.Audit)
	}
	n := 0
	for i, r := range cur.Audit {
		if i >= len(prev.Audit) || !sameRow(prev.Audit[i], r) {
			n++
		}
	}
	return n
}

func objectNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for p := range readTree(t, root) {
		if strings.HasPrefix(p, "objects/") {
			out[p] = true
		}
	}
	return out
}

func (w *dtrack) export(root string) layoutexport.Result {
	w.t.Helper()
	d, err := layoutdir.Open(root, w.path)
	if err != nil {
		w.t.Fatal(err)
	}
	defer d.Close()
	ref, _, err := ReadSnapshot(ctx, w.path, w.cred())
	if err != nil {
		w.t.Fatal(err)
	}
	res, err := layoutexport.Run(ctx, layoutexport.Input{
		Dir:         layoutexport.Dir{Writer: d, Reader: d, Lister: d, Locker: d, Pins: d},
		WorkspaceID: ref.Meta.WorkspaceID,
		Now:         func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
		Unlock: func(ctx context.Context) (layoutexport.Material, error) {
			m, err := TakeExport(ctx, w.path, w.cred())
			if err != nil {
				return layoutexport.Material{}, err
			}
			return layoutexport.Material{Snapshot: m.Snapshot, Refs: m.Refs, Sealer: m.Sealer, Notices: m.Facts.Notices, Close: m.Sealer.Close}, nil
		},
	})
	if err != nil {
		w.t.Fatalf("export: %v", err)
	}
	return res
}

func restoreInto(w *dtrack, scratch, dest string) error {
	c := w.cred()
	if c.Factors != nil {
		return RestoreWithFactors(scratch, dest, *c.Factors, RestoreOptions{})
	}
	return RestoreWithOptions(scratch, dest, c.Passphrase, RestoreOptions{})
}

func verifyDeep(w *dtrack, path string) error {
	c := w.cred()
	if c.Factors != nil {
		_, err := VerifyFileFactors(path, *c.Factors, true)
		return err
	}
	_, err := VerifyFilePayloads(path, c.Passphrase)
	return err
}

func openCred(w *dtrack, path string) *Store {
	w.t.Helper()
	var s *Store
	var err error
	if w.fake != nil {
		s, err = openHW(path, w.fake, w.dev, w.pin)
	} else {
		s, err = Open(path, w.passBuf())
	}
	if err != nil {
		w.t.Fatalf("opening %s: %v", path, err)
	}
	return s
}

// check is the pipeline run after every step.
func (w *dtrack) check(name string) {
	w.t.Helper()
	w.checks++
	fail := func(format string, a ...any) {
		w.t.Helper()
		w.t.Fatalf("[%s, step %d: %s] %s", w.t.Name(), w.checks, name, fmt.Sprintf(format, a...))
	}
	cur, _, err := ReadSnapshot(ctx, w.path, w.cred())
	if err != nil {
		fail("reading the workspace: %v", err)
	}

	// 1. the export, incrementally
	res := w.export(w.root)
	names := objectNames(w.t, w.root)
	if w.prev != nil {
		want, changed := expectedNewObjects(*w.prev, cur)
		fresh := 0
		for n := range names {
			if !w.tree[n] {
				fresh++
			}
		}
		if !res.HeadWritten || res.HeadSequence != w.heads+1 {
			fail("no new head after a change: %+v", res)
		}
		if res.ObjectsWritten != want || fresh != want {
			fail("the export wrote %d objects (%d names are new); a step that changed or added %d records and %d audit rows should write %d", res.ObjectsWritten, fresh, changed, auditChanged(*w.prev, cur), want)
		}
		for n := range w.tree {
			if !names[n] {
				fail("object %s went away", n)
			}
		}
	}
	w.heads = res.HeadSequence
	// a second export finds everything and writes nothing
	again := w.export(w.root)
	if !again.UpToDate || again.HeadWritten || again.ObjectsWritten != 0 {
		fail("a second export of the same state wrote something: %+v", again)
	}
	w.tree = objectNames(w.t, w.root)
	snap := cur
	w.prev = &snap

	// 2. the locked pass
	d, err := layoutdir.OpenExisting(w.root, w.path)
	if err != nil {
		fail("%v", err)
	}
	defer d.Close()
	pin, err := layoutread.ParsePin(res.Pin)
	if err != nil {
		fail("%v", err)
	}
	lr, err := layoutread.CheckLocked(ctx, layoutread.LockedInput{Reader: d, Pin: pin, Tables: realTables{}})
	if err != nil {
		fail("locked verify: %v", err)
	}
	// 3. the unlocked pass
	un, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: d, Locked: lr, Keys: realKeys{w.cred}})
	if err != nil {
		fail("unlocked verify: %v", err)
	}
	// 4. import into a fresh directory, through the scratch file and a restore
	tmp := w.t.TempDir()
	scratch := filepath.Join(tmp, "scratch.spo")
	if err := WriteLayoutFile(ctx, scratch, un.Snapshot, w.cred()); err != nil {
		fail("the scratch file: %v", err)
	}
	dest := filepath.Join(tmp, "imported")
	if err := os.Mkdir(dest, 0o700); err != nil {
		fail("%v", err)
	}
	imported := filepath.Join(dest, "workspace.spo")
	if err := restoreInto(w, scratch, imported); err != nil {
		fail("the import: %v", err)
	}
	// 5. every row of every table
	back, _, err := ReadSnapshot(ctx, imported, w.cred())
	if err != nil {
		fail("reading the import: %v", err)
	}
	a, b := cur, back
	a.Meta.CleanupPending, b.Meta.CleanupPending = 0, 0
	a.Meta.SchemaVersion, b.Meta.SchemaVersion = 0, 0
	if !reflect.DeepEqual(a.Meta, b.Meta) {
		fail("meta differs:\n%+v\n%+v", a.Meta, b.Meta)
	}
	if !reflect.DeepEqual(a.Slots, b.Slots) {
		fail("keyslots differ")
	}
	if len(a.Records) != len(b.Records) || len(a.Audit) != len(b.Audit) {
		fail("%d/%d records, %d/%d audit rows", len(a.Records), len(b.Records), len(a.Audit), len(b.Audit))
	}
	for i := range a.Records {
		if !reflect.DeepEqual(a.Records[i], b.Records[i]) {
			fail("record %d (%s) differs", i, a.Records[i].Kind)
		}
	}
	for i := range a.Audit {
		if !reflect.DeepEqual(a.Audit[i], b.Audit[i]) {
			fail("audit row %d differs", i)
		}
	}
	// 6. the import verifies, every payload decrypts
	if err := verifyDeep(w, imported); err != nil {
		fail("store verify --deep on the import: %v", err)
	}
	// 7. what a command reads: the records, the non-secret reads, the cold status,
	// the counters (they are records), the checkpoint key record (a record)
	src, imp := openCred(w, w.path), openCred(w, imported)
	sa, sb := summarise(w.t, src), summarise(w.t, imp)
	src.Close()
	imp.Close()
	if !reflect.DeepEqual(sa, sb) {
		fail("what the commands read differs:\n%+v\n%+v", sa, sb)
	}
	// 8. the read-only opener over the same layout lists the same records
	meta, slots := SnapshotOfSlots(lr)
	op, u, err := UnlockLayout(ctx, meta, slots, w.cred())
	if err != nil {
		fail("unlocking for the read-only open: %v", err)
	}
	op.Close()
	defer u.Close()
	roFile := filepath.Join(tmp, "readonly.spo")
	if err := u.WriteFile(ctx, roFile, un.Snapshot); err != nil {
		fail("%v", err)
	}
	ro, err := u.OpenReadOnly(roFile)
	if err != nil {
		fail("the read-only open: %v", err)
	}
	defer ro.Close()
	refs, err := ro.ListRecords(ctx)
	if err != nil || !reflect.DeepEqual(refs, sa.Refs) {
		fail("the read-only handle lists other records: %v\n%v\n%v", err, refs, sa.Refs)
	}
	for _, r := range refs {
		if r.Kind.Secret() {
			continue
		}
		got, gerr := get(ro, r)
		if gerr != nil || string(got) != sa.Gets[fmt.Sprint(r)] {
			fail("the read-only handle reads %s differently: %v", r, gerr)
		}
	}
	if st, err := ro.ColdStatus(ctx); err != nil || !reflect.DeepEqual(st, sa.Cold) {
		fail("the read-only handle's cold status differs: %v", err)
	}
	w.lastWritten = res.ObjectsWritten
}

// SnapshotOfSlots is the meta and slots of the locked result, as the unlocked pass
// uses them.
func SnapshotOfSlots(lr *layoutread.Locked) (ports.SnapshotMeta, []ports.SnapshotSlot) {
	return layoutread.SnapshotOf(lr.Slots)
}

// takeText returns the text of a recovery key and destroys the buffer (nil: "").
func takeText(b *secret.Buffer) string {
	if b == nil {
		return ""
	}
	var s string
	b.Use(func(x []byte) error { s = string(x); return nil })
	b.Destroy()
	return s
}

// tmpPass is a passphrase buffer destroyed at the end of the test.
func tmpPass(t *testing.T, p string) *secret.Buffer {
	t.Helper()
	b := passphrase(p)
	t.Cleanup(b.Destroy)
	return b
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

var _ = sort.Strings

// ---- the scripts ----

// Standard policy, no cold-role record: every kind family, put, update and delete,
// the operational certificate and KES counters, a slot added and removed, a
// passphrase change, a rekey, the checkpoint key enrolled and replaced, and a
// restore of an older backup (the counters carried).
//
// spec: SPO-Xlayout-INV-026, SPO-Xlayout-INV-015, SPO-Xlayout-OUT-021, SPO-Xlayout-OUT-022, SPO-Xlayout-INV-016, SPO-Xlayout-MODE-008
func TestDifferentialStandardWorkspace(t *testing.T) {
	s0, path, rec := scratch(t)
	s0.Close()
	w := newTrack(t, path, testPass)
	w.check("init")

	w.step("records of every kind family (hot keys, non-secret, a provider token)", func(s *Store) {
		put(t, s, rf("alpha", ports.AddrVKey), "v")
		put(t, s, rf("alpha", ports.AddrFile), "addr_test1alpha\n")
		put(t, s, rf("alpha", ports.KesVKey, 0), "k0")
		put(t, s, rf("alpha", ports.KesVKey, 1), "k1")
		put(t, s, rf("alpha", ports.OpCert, 0), "opcert-0")
		putSecret(t, s, rf("alpha", ports.KesSKey, 0), "kes-secret-0")
		putSecret(t, s, rf("zed", ports.PolicySKey), "policy-secret")
		must(t, s.Update(ctx, func(wr ports.Writer) error {
			return wr.PutSecret(rf("koios", ports.ProviderToken), secret.Take([]byte("a provider token")))
		}))
	})
	w.step("put, update", func(s *Store) {
		put(t, s, rf("beta", ports.AddrFile), "addr_test1beta\n")
		put(t, s, rf("alpha", ports.AddrFile), "addr_test1alpha-updated\n")
	})
	w.step("delete", func(s *Store) {
		must(t, s.Update(ctx, func(wr ports.Writer) error { return wr.Delete(rf("alpha", ports.AddrVKey)) }))
	})
	w.step("operational certificate issued and a KES key generated (the counters)", func(s *Store) {
		putCounters(t, s, "alpha", cstate{issue: 1, kesCur: 0, kesNext: 1})
		put(t, s, rf("alpha", ports.OpCert, 1), "opcert-1")
	})
	w.step("the next KES key", func(s *Store) {
		putCounters(t, s, "alpha", cstate{issue: 2, kesCur: 1, kesNext: 2})
		putKes(t, s, "alpha", 1)
	})
	f := newFake()
	var slotID []byte
	w.step("slot added (a fido2-hmac slot under standard)", func(s *Store) {
		fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		must(t, err)
		slotID, err = s.AddFactorSlot(ctx, []FactorPlan{fa})
		must(t, err)
		fa.Output.Destroy()
	})
	w.step("slot removed (a rotation with the recovery proof)", func(s *Store) {
		req := RemoveRequest{SlotID: slotID, Daily: f.inputs("devA", "1234"), Proof: presentStd(t, s, rec)}
		req.Daily.Passphrase = pinOf(w.pass)
		txt, _, err := s.RemoveSlotByRotation(ctx, req)
		must(t, err)
		rec = takeText(txt)
	})
	w.step("a second passphrase slot", func(s *Store) {
		_, err := s.AddPassphraseSlot(ctx, tmpPass(t, "a second passphrase"))
		must(t, err)
	})
	w.step("passphrase change (a rekey with the new passphrase)", func(s *Store) {
		presentStd(t, s, rec)
		txt, err := s.ChangePassphraseRekey(ctx, tmpPass(t, "the changed passphrase"))
		must(t, err)
		rec = takeText(txt)
		must(t, s.Cleanup(ctx))
		w.pass = "the changed passphrase" // what the check opens the workspace with
	})
	w.step("rekey keeping the passphrase", func(s *Store) {
		presentStd(t, s, rec)
		txt, err := s.Rekey(ctx, []Credential{PassphraseCredential(w.passBuf())})
		must(t, err)
		rec = takeText(txt)
		must(t, s.Cleanup(ctx))
	})
	// a backup now, for the restore at the end
	backup := filepath.Join(t.TempDir(), "old.bak")
	{
		s := w.open()
		must(t, s.Backup(ctx, backup))
		s.Close()
	}
	raw1, _ := ckRecord(t)
	w.step("checkpoint key enrolled", func(s *Store) { putCK(t, s, raw1) })
	raw2, _ := ckRecord(t)
	w.step("checkpoint key replaced", func(s *Store) { putCK(t, s, raw2) })
	w.step("more writes after the replacement", func(s *Store) {
		put(t, s, rf("gamma", ports.AddrFile), "addr_test1gamma\n")
		putCounters(t, s, "alpha", cstate{issue: 3, kesCur: 2, kesNext: 3})
	})

	// restore --allow-older of the old backup: the workspace goes back, the counters are
	// carried; the layout of the restored workspace is a new directory (the old one
	// holds heads of the chain that was replaced)
	must(t, RestoreWithOptions(backup, w.path, w.passBuf(), RestoreOptions{Overwrite: true, AllowOlder: true}))
	w.prev, w.tree, w.heads = nil, nil, 0
	w.root = filepath.Join(t.TempDir(), "layout-after-restore")
	w.check("restore --allow-older of an old backup")
	s := w.open()
	if c, found := readC(t, s, "alpha"); !found || c.issue != 3 || c.kesNext != 3 {
		t.Errorf("the restore did not carry the counters (the opcert issue counter and the next KES number): %+v %v", c, found)
	}
	s.Close()
	w.step("a write after the restore (a new head on the new layout)", func(s *Store) { put(t, s, rf("delta", ports.AddrFile), "addr_test1delta\n") })
}

// Cold-role records: a pool cold key and a cold mnemonic under the standard policy,
// opened (the salt of the cold factor rotates and the previous wrap stays), a rekey
// with the cold records, then the workspace rotated with the recovery proof to
// hardware and on to strict, the cold records opened with the authenticator after
// each (a faulty answer makes a previous wrap, the next open heals it).
//
// spec: SPO-Xlayout-INV-026, SPO-Xlayout-INV-010, SPO-Xlayout-OUT-021, SPO-Xlayout-MODE-003, SPO-Xlayout-MODE-008
func TestDifferentialColdRolesAndPolicyChanges(t *testing.T) {
	s0, path, rec := scratch(t)
	s0.Close()
	w := newTrack(t, path, testPass)
	w.check("init")
	w.step("a pool cold key and a cold mnemonic, and hot keys", func(s *Store) {
		putSecret(t, s, coldRef, "cold-secret-one")
		putMnemonic(t, s, "alpha bravo charlie")
		putSecret(t, s, rf("pool", ports.KesSKey, 1), "hot-secret")
		put(t, s, rf("pool", ports.OpCert, 0), "opcert-0")
	})
	w.step("a cold-role open (the salt of the cold factor rotates)", func(s *Store) {
		if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
			t.Fatalf("%q %v", v, err)
		}
	})
	w.step("a second cold-role open (the previous wrap stays)", func(s *Store) {
		if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
			t.Fatalf("%q %v", v, err)
		}
	})
	w.step("rekey with the cold records (the passphrase changes)", func(s *Store) {
		presentStd(t, s, rec)
		txt, err := s.ChangePassphraseRekeyCold(ctx, tmpPass(t, "the cold-era passphrase"), w.coldSource())
		must(t, err)
		rec = takeText(txt)
		must(t, s.Cleanup(ctx))
		w.pass = "the cold-era passphrase"
	})
	f := newFake()
	w.step("workspace rotate to hardware, with the recovery proof", func(s *Store) {
		plan, _ := hardwarePlan(t, s, f, presentStd(t, s, rec))
		plan.ColdNew.Mnemonic = fakeMnemonic{}
		txt, _, err := s.Rotate(ctx, plan)
		must(t, err)
		rec = takeText(txt)
		w.fake, w.dev, w.pin = f, "devA", "1234"
	})
	w.step("a write under hardware", func(s *Store) {
		put(t, s, rf("pool", ports.AddrFile), "addr_test1pool\n")
		putSecret(t, s, rf("pool", ports.VrfSKey), "vrf-secret")
	})
	w.step("a faulty authenticator answer: the cold open leaves a previous wrap", func(s *Store) {
		f.corruptNext = 1
		if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
			t.Fatalf("%q %v", v, err)
		}
	})
	w.step("the next cold open heals it", func(s *Store) {
		if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
			t.Fatalf("%q %v", v, err)
		}
	})
	w.step("workspace policy set strict (a rotation, no recovery path)", func(s *Store) {
		fa, _, err := EnrolFactor(ctx, f.inputs("devA", "1234"), s.ws, nil)
		must(t, err)
		in := f.inputs("devA", "1234")
		txt, _, err := s.Rotate(ctx, RotatePlan{Policy: unlock.Strict, Proof: presentHW(t, s, f, rec),
			Slots:   []SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []FactorPlan{fa}}},
			ColdNew: &ColdSource{Factors: &in, Deriver: fakeDeriver{}, Mnemonic: fakeMnemonic{}}})
		must(t, err)
		if txt != nil {
			t.Fatal("a strict rotation made a recovery key")
		}
	})
	w.step("a write under strict, and a cold-role open", func(s *Store) {
		put(t, s, rf("pool", ports.AddrFile), "addr_test1pool-strict\n")
		if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-one" {
			t.Fatalf("%q %v", v, err)
		}
	})
}

// A cold record left under its old cold factor on request is the one state that
// cannot be exported: store verify fails by design, so no snapshot is taken and the
// export is refused and writes nothing. Re-establishing the record makes the export
// work.
//
// spec: SPO-Xsnapshot-PRE-001, SPO-Xlayout-MODE-008
func TestDifferentialALeftMarkedColdRecordIsRefusedUntilItIsReestablished(t *testing.T) {
	fx := leftFixture(t)
	w := newTrack(t, fx.path, "the recovered workspace passphrase")
	d, err := layoutdir.Open(w.root, w.path)
	must(t, err)
	_, err = layoutexport.Run(ctx, layoutexport.Input{
		Dir: layoutexport.Dir{Writer: d, Reader: d, Lister: d, Locker: d, Pins: d}, WorkspaceID: make([]byte, 16),
		Now: func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
		Unlock: func(ctx context.Context) (layoutexport.Material, error) {
			m, err := TakeExport(ctx, w.path, w.cred())
			if err != nil {
				return layoutexport.Material{}, err
			}
			return layoutexport.Material{Snapshot: m.Snapshot, Refs: m.Refs, Sealer: m.Sealer, Close: m.Sealer.Close}, nil
		},
	})
	d.Close()
	if err == nil || !errors.Is(err, ErrVerify) {
		t.Fatalf("the export of a workspace that fails verification: %v", err)
	}
	if n := len(objectNames(t, w.root)); n != 0 {
		t.Errorf("a refused export wrote %d objects", n)
	}
	// re-establish: `workspace rotate` with the old cold factor of the left record
	// present, so that it is opened and sealed again under the new one
	r, err := Open(w.path, w.passBuf())
	must(t, err)
	r.SetColdSource(coldPass("sub-key passphrase one"))
	txt, _, err := r.Rotate(ctx, RotatePlan{Policy: unlock.Standard, Proof: presentStd(t, r, fx.secrets[1]),
		Slots: []SlotPlan{{Kind: seal.SlotPassphrase, Passphrase: tmpPass(t, "the re-established passphrase")}, {Kind: seal.SlotRecovery}},
		ColdNew: &ColdSource{Deriver: fakeDeriver{}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
			return secret.Take([]byte("a new cold passphrase")), nil
		}}})
	must(t, err)
	txt.Destroy()
	if st, err := r.ColdStatus(ctx); err != nil || len(st.Problems) != 0 {
		t.Fatalf("the record is still out of step: %+v %v", st, err)
	}
	r.Close()
	w.pass, w.coldPass = "the re-established passphrase", "a new cold passphrase"
	w.check("the left-marked cold record re-established: the export works")
}

// A workspace migrated from store format 2 and one migrated from the legacy
// format, exported and imported after the migration and after further writes. A
// file that is not of the current format is not exported: the migration comes
// first.
//
// spec: SPO-Xlayout-INV-026, SPO-Xlayout-INV-015, SPO-Xlayout-MODE-008
func TestDifferentialMigratedWorkspaces(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    func(t *testing.T) string
		migrate func(t *testing.T, path string)
	}{
		{"format 2", format2Copy, func(t *testing.T, p string) {
			old, err := OpenFormat2(p, legacyPW())
			must(t, err)
			old.SetColdSource(coldPass("a cold sub-key passphrase"))
			_, err = old.Migrate3(ctx, "")
			must(t, err)
			old.Close()
		}},
		{"the legacy format", func(t *testing.T) string { return legacyCopy(t, "store.db") }, func(t *testing.T, p string) {
			old, err := OpenLegacy(p, legacyPW())
			must(t, err)
			old.SetColdSource(coldPass("a cold sub-key passphrase"))
			_, err = old.Migrate(ctx, MigrateOptions{})
			must(t, err)
			old.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.path(t)
			w := newTrack(t, p, legacyPass)
			// before the migration the file is refused by the export, and nothing is written
			if _, err := TakeExport(ctx, p, w.cred()); err == nil {
				t.Fatal("a file of an old store format was taken for an export")
			}
			tc.migrate(t, p)
			w.check("workspace migrate")
			w.step("a write after the migration", func(s *Store) {
				put(t, s, rf("migrated", ports.AddrFile), "addr_test1migrated\n")
				putCounters(t, s, "migrated", cstate{issue: 1, kesCur: 0, kesNext: 1})
			})
			w.step("a delete", func(s *Store) {
				must(t, s.Update(ctx, func(wr ports.Writer) error { return wr.Delete(rf("migrated", ports.AddrFile)) }))
			})
		})
	}
}
