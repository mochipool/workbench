package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/layoutdir"
	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The store side of the layout reader: the slot-table policy check, the unlock
// from a slot table alone, and the scratch file. Real workspaces of every
// fixture family, real authenticator fakes.

func slotsOnly(s ports.Snapshot) (ports.SnapshotMeta, []ports.SnapshotSlot) { return s.Meta, s.Slots }

// spec: SPO-Xlayout-INV-016, SPO-Xlayout-PRE-011
func TestCheckLayoutSlotTableAcceptsTheFixturesAndRefusesABrokenOne(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			snap, _, err := ReadSnapshot(context.Background(), f.path, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			m, s := slotsOnly(snap)
			if err := CheckLayoutSlotTable(m, s); err != nil {
				t.Fatalf("a real slot table: %v", err)
			}
			// a table that breaks its policy: the daily slot is gone
			var rest []ports.SnapshotSlot
			for _, sl := range s {
				if sl.Kind == "recovery" || sl.Kind == "composite" {
					rest = append(rest, sl)
				}
			}
			if len(rest) == 0 || len(rest) == len(s) {
				return
			}
			if err := CheckLayoutSlotTable(m, rest); !errors.Is(err, ErrPolicyViolated) {
				t.Fatalf("a table without its daily slot passed: %v", err)
			}
		})
	}
}

// spec: SPO-Xlayout-INV-016, SPO-Xlayout-INV-010, SPO-Xlayout-INV-017, SPO-Xlayout-SEC-003
func TestOpenLayoutKeysOpensObjectsOfEveryFixtureFamily(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			m, err := TakeExport(context.Background(), f.path, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			defer m.Sealer.Close()
			meta, slots := slotsOnly(m.Snapshot)
			op, err := OpenLayoutKeys(context.Background(), meta, slots, f.cred())
			if err != nil {
				t.Fatalf("unlock from the slot table alone: %v", err)
			}
			defer op.Close()
			if !bytes.Equal(op.Epoch(), meta.KeyEpoch) || !bytes.Equal(op.WorkspaceID(), meta.WorkspaceID) {
				t.Fatal("epoch or workspace id")
			}
			if ok, err := op.EpochMACValid(meta.WorkspaceID, meta.KeyEpoch, meta.EpochMAC); err != nil || !ok {
				t.Fatalf("epoch mac %v %v", ok, err)
			}
			bad := append([]byte(nil), meta.EpochMAC...)
			bad[0] ^= 1
			if ok, _ := op.EpochMACValid(meta.WorkspaceID, meta.KeyEpoch, bad); ok {
				t.Fatal("a changed epoch MAC passed")
			}
			body, err := layout.EncodeBody(layout.Audit{Seq: 1, At: 5, Kind: "update", Event: []byte{1}, Touched: []byte{2}, MAC: make([]byte, 32), PrevMAC: make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			stored, err := m.Sealer.Seal(body)
			if err != nil {
				t.Fatal(err)
			}
			got, err := op.Open(stored)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("an object sealed with the workspace keys does not open: %v", err)
			}
			stored[len(stored)-1] ^= 1
			if _, err := op.Open(stored); err == nil {
				t.Fatal("a flipped byte opened")
			}
			for i, r := range m.Snapshot.Records {
				anchor, num, err := op.OwnerRef(r.ID, r.Kind, r.OwnerSealed)
				if err != nil {
					t.Fatalf("owner blob %d: %v", i, err)
				}
				if !bytes.Equal(anchor, m.Refs[i].Anchor) || num != m.Refs[i].Num {
					t.Fatalf("record %d: owner blob says another anchor or number", i)
				}
				tag, err := op.LookupTag(anchor, r.Kind, num)
				if err != nil || !bytes.Equal(tag, r.LookupTag) {
					t.Fatalf("record %d: lookup tag %v", i, err)
				}
				if _, _, err := op.OwnerRef(r.ID, "node.skey"+"x", r.OwnerSealed); err == nil {
					t.Fatal("an owner blob opened under another kind")
				}
			}
		})
	}
}

// spec: SPO-Xlayout-INV-016, SPO-Xlayout-INV-017
func TestOpenLayoutKeysRefusesAWrongCredentialAndAWrongEpochMAC(t *testing.T) {
	std := snapBuilders()[0].build(t)
	snap, _, err := ReadSnapshot(context.Background(), std.path, std.cred())
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := slotsOnly(snap)
	if _, err := OpenLayoutKeys(context.Background(), meta, slots, SnapshotCredential{Passphrase: passphrase("not the passphrase")}); !errors.Is(err, ErrWrongCredential) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	bad := meta
	bad.EpochMAC = append([]byte(nil), meta.EpochMAC...)
	bad.EpochMAC[3] ^= 0x40
	if _, err := OpenLayoutKeys(context.Background(), bad, slots, std.cred()); err == nil {
		t.Fatal("a slot table with another epoch MAC unlocked")
	}
	// a hardware workspace takes no passphrase, however right
	for _, b := range snapBuilders() {
		if b.name != "hardware cold record" {
			continue
		}
		hw := b.build(t)
		hs, _, err := ReadSnapshot(context.Background(), hw.path, hw.cred())
		if err != nil {
			t.Fatal(err)
		}
		hm, hsl := slotsOnly(hs)
		if _, err := OpenLayoutKeys(context.Background(), hm, hsl, SnapshotCredential{Passphrase: passphrase(testPass)}); err == nil {
			t.Fatal("a passphrase opened a hardware slot table")
		}
		op, err := OpenLayoutKeys(context.Background(), hm, hsl, hw.cred())
		if err != nil {
			t.Fatalf("the daily authenticator: %v", err)
		}
		op.Close()
	}
}

var _ = ports.ErrSnapshot

// ---- the whole round trip with the real store, every fixture family ----

type realTables struct{}

func (realTables) CheckSlotTable(m ports.SnapshotMeta, s []ports.SnapshotSlot) error {
	return CheckLayoutSlotTable(m, s)
}

type realKeys struct {
	c func() SnapshotCredential
}

func (k realKeys) OpenLayoutKeys(ctx context.Context, m ports.SnapshotMeta, s []ports.SnapshotSlot) (ports.ObjectOpener, error) {
	return OpenLayoutKeys(ctx, m, s, k.c())
}

func (k realKeys) WriteSnapshotFile(ctx context.Context, path string, snap ports.Snapshot) error {
	return WriteLayoutFile(ctx, path, snap, k.c())
}

// readBack exports the fixture to a real directory, reads it back with the
// layout reader, and returns the rebuilt snapshot, the original and the pieces.
func readBack(t *testing.T, f snapFix) (un *layoutread.Unlocked, lr *layoutread.Locked, want ports.Snapshot, root string, d *layoutdir.Dir) {
	t.Helper()
	d, root, res, want := exportFixture(t, f)
	pin, err := layoutread.ParsePin(res.Pin)
	if err != nil {
		t.Fatal(err)
	}
	lr, err = layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: d, Pin: pin, Tables: realTables{}})
	if err != nil {
		t.Fatalf("locked: %v", err)
	}
	un, err = layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: d, Locked: lr, Keys: realKeys{f.cred}})
	if err != nil {
		t.Fatalf("unlocked: %v", err)
	}
	return un, lr, want, root, d
}

// spec: SPO-Xlayout-INV-026, SPO-Xlayout-INV-015, SPO-Xlayout-INV-016, SPO-Xlayout-OUT-021, SPO-Xlayout-OUT-022, SPO-Xlayout-SEC-008
func TestALayoutReadBackEqualsTheWorkspaceRowForRowForEveryFixtureFamily(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			un, _, want, _, _ := readBack(t, f)
			got := un.Snapshot
			got.Meta.SchemaVersion, want.Meta.SchemaVersion = 0, 0
			got.Meta.CleanupPending, want.Meta.CleanupPending = 0, 0
			if !reflect.DeepEqual(got.Meta, want.Meta) {
				t.Errorf("meta:\n%+v\n%+v", got.Meta, want.Meta)
			}
			if !reflect.DeepEqual(got.Slots, want.Slots) {
				t.Errorf("slots differ")
			}
			if len(got.Records) != len(want.Records) || len(got.Audit) != len(want.Audit) {
				t.Fatalf("%d/%d records, %d/%d audit rows", len(got.Records), len(want.Records), len(got.Audit), len(want.Audit))
			}
			for i := range want.Records {
				if !reflect.DeepEqual(got.Records[i], want.Records[i]) {
					t.Errorf("record %d (%s) differs", i, want.Records[i].Kind)
				}
			}
			for i := range want.Audit {
				if !reflect.DeepEqual(got.Audit[i], want.Audit[i]) {
					t.Errorf("audit row %d differs", i)
				}
			}
			// the scratch file: written through the store's full verification, and read back equal
			path := filepath.Join(t.TempDir(), "scratch.spo")
			if err := WriteLayoutFile(context.Background(), path, un.Snapshot, f.cred()); err != nil {
				t.Fatalf("the scratch file does not verify: %v", err)
			}
			back, _, err := ReadSnapshot(context.Background(), path, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			back.Meta.CleanupPending, want.Meta.CleanupPending = 0, 0
			back.Meta.SchemaVersion, want.Meta.SchemaVersion = 0, 0
			if !reflect.DeepEqual(back.Meta, want.Meta) || !reflect.DeepEqual(back.Slots, want.Slots) || !reflect.DeepEqual(back.Records, want.Records) || !reflect.DeepEqual(back.Audit, want.Audit) {
				t.Error("the scratch file is not the workspace row for row")
			}
		})
	}
}

// forgeHead2 appends an unsigned head 2 to the real layout after changing its
// manifest with edit, as someone who holds the workspace keys (a compromised
// exporter) would. The pin of head 1 accepts it (an exact pin does not
// authenticate a later head and head 1 names no key).
func forgeHead2(t *testing.T, f snapFix, edit func(rp *[]layout.RecordPage, root *layout.Root, open func([]byte) layout.Object, sealPut func(layout.Object) []byte)) (*layoutdir.Dir, layoutread.Pin) {
	t.Helper()
	d, _, res, _ := exportFixture(t, f)
	m, err := TakeExport(context.Background(), f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Sealer.Close()
	pin, _ := layoutread.ParsePin(res.Pin)
	lr, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: d, Pin: pin, Tables: realTables{}})
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := layoutread.SnapshotOf(lr.Slots)
	op, err := OpenLayoutKeys(context.Background(), meta, slots, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	put := func(stored []byte) []byte {
		name := layout.ObjectName(stored)
		p, _ := layout.ObjectPath(name)
		if err := d.Put(context.Background(), p, bytes.NewReader(stored), int64(len(stored))); err != nil {
			t.Fatal(err)
		}
		return layout.ObjectHash(stored)
	}
	sealObj := func(o layout.Object) []byte {
		body, err := layout.EncodeBody(o)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := m.Sealer.Seal(body)
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	open := func(h []byte) layout.Object {
		p, _ := layout.ObjectPath(hexString(h))
		rc, err := d.Get(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b := new(bytes.Buffer)
		b.ReadFrom(rc)
		body, err := op.Open(b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		o, err := layout.DecodeBody(body, classRule)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	root := open(lr.Used.Head.Manifest).(layout.Root)
	var rp []layout.RecordPage
	for _, h := range root.RecordPages {
		rp = append(rp, open(h).(layout.RecordPage))
	}
	edit(&rp, &root, open, func(o layout.Object) []byte { return put(sealObj(o)) })
	root.RecordPages = nil
	for _, p := range rp {
		root.RecordPages = append(root.RecordPages, put(sealObj(p)))
	}
	root.Parent = layout.Parent{Format: layout.ParentFormat, Seq: 2, PreviousHead: lr.Used.Hash}
	h2 := lr.Used.Head
	h2.Sequence, h2.Previous, h2.CheckpointKey = 2, lr.Used.Hash, nil
	h2.Manifest = put(sealObj(root))
	h2.Time = h2.Time.Add(time.Minute)
	note, err := h2.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Put(context.Background(), layout.HeadPath(2), bytes.NewReader(note), int64(len(note))); err != nil {
		t.Fatal(err)
	}
	return d, pin
}

func firstFixture(t *testing.T) snapFix { return snapBuilders()[0].build(t) }

// A forged manifest whose pages and counts agree but which leaves out a record, or
// holds a record object changed after sealing, passes every check of the layout
// reader and is stopped by the store's own verification of the scratch file: the
// audit chain records every record's hash. The reader does not re-implement that
// chain.
//
// spec: SPO-Xlayout-OUT-022, SPO-Xlayout-INV-016
func TestTheStoresVerificationOfTheScratchFileFindsWhatTheLayoutChecksCannot(t *testing.T) {
	type forge struct {
		name string
		edit func(rp *[]layout.RecordPage, root *layout.Root, open func([]byte) layout.Object, sealPut func(layout.Object) []byte)
		want string
	}
	omit := forge{"an omitted record with the counts of the root made to agree", func(rp *[]layout.RecordPage, root *layout.Root, _ func([]byte) layout.Object, _ func(layout.Object) []byte) {
		(*rp)[0].Entries = (*rp)[0].Entries[1:]
		root.Records--
	}, "audit chain"}
	changed := forge{"a record object changed after sealing, named by a page that was made to agree", func(rp *[]layout.RecordPage, _ *layout.Root, open func([]byte) layout.Object, sealPut func(layout.Object) []byte) {
		e := &(*rp)[0].Entries[0]
		rec := open(e.Hash).(layout.Record)
		rec.Inner.Ciphertext = append([]byte(nil), rec.Inner.Ciphertext...)
		rec.Inner.Ciphertext[0] ^= 1
		e.Hash = sealPut(rec)
	}, "audit chain"}
	f := firstFixture(t)
	for _, c := range []forge{omit, changed} {
		t.Run(c.name, func(t *testing.T) {
			d, pin := forgeHead2(t, f, c.edit)
			lr, err := layoutread.CheckLocked(context.Background(), layoutread.LockedInput{Reader: d, Pin: pin, Tables: realTables{}})
			if err != nil || lr.Used.Head.Sequence != 2 {
				t.Fatalf("the forged head is refused by the locked pass: %v", err)
			}
			un, err := layoutread.CheckUnlocked(context.Background(), layoutread.UnlockedInput{Reader: d, Locked: lr, Keys: realKeys{f.cred}})
			if err != nil {
				t.Fatalf("the reader's own checks cannot see this: %v", err)
			}
			path := filepath.Join(t.TempDir(), "scratch.spo")
			err = WriteLayoutFile(context.Background(), path, un.Snapshot, f.cred())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("the store accepted a forged layout: %v", err)
			}
			if _, serr := os.Stat(path); serr == nil {
				t.Error("a scratch file was left behind")
			}
		})
	}
}

// The reader and the importer never open a record payload: a cold-role record is
// carried as bytes, and the keys the reader holds do not open it.
//
// spec: SPO-Xlayout-SEC-008, SPO-Xlayout-SEC-003
func TestAColdRoleRecordIsCarriedAndStaysClosedToTheReader(t *testing.T) {
	for _, b := range snapBuilders() {
		if !strings.Contains(b.name, "cold record") {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			f := b.build(t)
			un, _, want, _, _ := readBack(t, f)
			meta, slots := slotsOnly(want)
			op, err := OpenLayoutKeys(context.Background(), meta, slots, f.cred())
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			lo := op.(*layoutOpener)
			cold := 0
			for i, r := range want.Records {
				sr := seal.SealedRecord{Nonce: r.Nonce, WrappedKey: r.WrappedKey, Owner: r.OwnerSealed, Ciphertext: r.Ciphertext}
				got := un.Snapshot.Records[i]
				if !bytes.Equal(got.WrappedKey, r.WrappedKey) || !bytes.Equal(got.Ciphertext, r.Ciphertext) || !bytes.Equal(got.OwnerSealed, r.OwnerSealed) || !bytes.Equal(got.Nonce, r.Nonce) {
					t.Fatalf("record %d was not carried byte for byte", i)
				}
				if !seal.IsColdSealed(sr) {
					continue
				}
				cold++
				anchor, num, err := lo.OwnerRef(r.ID, r.Kind, r.OwnerSealed)
				if err != nil {
					t.Fatal(err)
				}
				m := seal.RecordMeta{WorkspaceID: meta.WorkspaceID, RecordID: r.ID, Kind: r.Kind, Anchor: anchor, Num: num, Class: seal.ClassSecret, Version: uint64(r.Version), Format: seal.RecordFormat}
				sb, oerr := openSecretBuf(lo.keys, m, sr)
				sb.destroy()
				if oerr == nil {
					t.Fatal("the reader's keys opened a cold-role payload")
				}
			}
			if cold == 0 {
				t.Fatal("no cold-role record in the fixture")
			}
		})
	}
}

// spec: SPO-Xlayout-INV-016, SPO-Xlayout-PRE-011
func TestOpenLayoutKeysRefusesATableThatBreaksItsPolicyBeforeTheCredentialIsTried(t *testing.T) {
	f := firstFixture(t)
	snap, _, err := ReadSnapshot(context.Background(), f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := slotsOnly(snap)
	var rec []ports.SnapshotSlot
	for _, s := range slots {
		if s.Kind == "recovery" {
			rec = append(rec, s)
		}
	}
	if _, err := OpenLayoutKeys(context.Background(), meta, rec, f.cred()); !errors.Is(err, ErrPolicyViolated) {
		t.Fatalf("a standard table with no passphrase slot: %v", err)
	}
	// a store format this binary does not read, and malformed meta fields
	bad := meta
	bad.FormatVersion = 2
	if err := CheckLayoutSlotTable(bad, slots); err == nil {
		t.Error("store format 2 accepted")
	}
	if _, err := OpenLayoutKeys(context.Background(), bad, slots, f.cred()); err == nil {
		t.Error("store format 2 unlocked")
	}
	for name, edit := range map[string]func(m *ports.SnapshotMeta){
		"a short workspace id": func(m *ports.SnapshotMeta) { m.WorkspaceID = m.WorkspaceID[:8] },
		"a short key epoch":    func(m *ports.SnapshotMeta) { m.KeyEpoch = m.KeyEpoch[:8] },
		"a short epoch MAC":    func(m *ports.SnapshotMeta) { m.EpochMAC = m.EpochMAC[:8] },
	} {
		m := meta
		m.WorkspaceID, m.KeyEpoch, m.EpochMAC = append([]byte(nil), meta.WorkspaceID...), append([]byte(nil), meta.KeyEpoch...), append([]byte(nil), meta.EpochMAC...)
		edit(&m)
		if _, err := OpenLayoutKeys(context.Background(), m, slots, f.cred()); err == nil || !strings.Contains(err.Error(), "bad workspace id or key epoch") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a slot whose key-derivation parameters are out of range is skipped, not run
	odd := append([]ports.SnapshotSlot(nil), slots...)
	huge := int64(1) << 40
	for i := range odd {
		if odd[i].Kind == "passphrase" {
			odd[i].KDFMemoryKiB = &huge
		}
	}
	if _, err := OpenLayoutKeys(context.Background(), meta, odd, f.cred()); err == nil {
		t.Error("a slot with absurd key-derivation parameters unlocked")
	}
	// a value that wraps to the real parameters is out of range, not those parameters
	wrap := append([]ports.SnapshotSlot(nil), slots...)
	for i := range wrap {
		if wrap[i].Kind == "passphrase" {
			v := *wrap[i].KDFMemoryKiB + 1<<32
			wrap[i].KDFMemoryKiB = &v
		}
	}
	if _, err := OpenLayoutKeys(context.Background(), meta, wrap, f.cred()); err == nil {
		t.Error("a key-derivation parameter that wraps to the real one unlocked")
	}
}

// The opener holds the locked buffers of an open workspace and no more (the master
// key is destroyed once the keys are derived), and releases them on Close and on
// every failure.
//
// spec: SPO-Xlayout-SEC-005, SPO-Xlayout-SEC-008
func TestTheLayoutOpenerHoldsNoMoreLockedBuffersThanAnOpenWorkspace(t *testing.T) {
	f := firstFixture(t)
	snap, _, err := ReadSnapshot(context.Background(), f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := slotsOnly(snap)
	cred := f.cred() // the caller's own credential buffer is counted
	base := secret.Budget().Live
	op, err := OpenLayoutKeys(context.Background(), meta, slots, cred)
	if err != nil {
		t.Fatal(err)
	}
	if held := secret.Budget().Live - base; held != lockedBuffersOfAnOpenWorkspace {
		t.Errorf("the opener holds %d locked buffers, want %d", held, lockedBuffersOfAnOpenWorkspace)
	}
	op.Close()
	op.Close()
	if got := secret.Budget().Live; got != base {
		t.Errorf("Close left %d buffers", got-base)
	}
	bad := meta
	bad.EpochMAC = append([]byte(nil), meta.EpochMAC...)
	bad.EpochMAC[0] ^= 1
	if _, err := OpenLayoutKeys(context.Background(), bad, slots, cred); err == nil {
		t.Fatal("unlocked")
	}
	if got := secret.Budget().Live; got != base {
		t.Errorf("a refused unlock left %d buffers", got-base)
	}
}

// An object sealed under another key epoch does not open as one of this workspace.
//
// spec: SPO-Xlayout-PRE-004, SPO-Xlayout-INV-016
func TestTheLayoutOpenerRefusesAnObjectOfAnotherEpoch(t *testing.T) {
	f := firstFixture(t)
	m, err := TakeExport(context.Background(), f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	defer m.Sealer.Close()
	meta, slots := slotsOnly(m.Snapshot)
	op, err := OpenLayoutKeys(context.Background(), meta, slots, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	lo := op.(*layoutOpener)
	body, _ := layout.EncodeBody(layout.Audit{Seq: 1, At: 5, Kind: "update", Event: []byte{1}, Touched: []byte{2}, MAC: make([]byte, 32), PrevMAC: make([]byte, 32)})
	other := bytes.Repeat([]byte{7}, 16)
	stored, err := lo.sealer.Seal(other, meta.WorkspaceID, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Open(stored); err == nil {
		t.Fatal("an object of another epoch opened")
	}
}

// A FIDO2 slot of a layout names the RP id of the workspace and no other: the
// authenticator is asked with the credential id and RP id the slot names, so a
// table that names another is refused by the same check that refuses a table that
// breaks its policy, before any credential is asked.
//
// spec: SPO-Xlayout-PRE-028
func TestASlotNamingAnotherRPIDIsRefused(t *testing.T) {
	var f snapFix
	for _, b := range snapBuilders() {
		if b.name == "hardware cold record" {
			f = b.build(t)
		}
	}
	snap, _, err := ReadSnapshot(context.Background(), f.path, f.cred())
	if err != nil {
		t.Fatal(err)
	}
	meta, slots := slotsOnly(snap)
	if err := CheckLayoutSlotTable(meta, slots); err != nil {
		t.Fatalf("the real table: %v", err)
	}
	edited := false
	changed := append([]ports.SnapshotSlot(nil), slots...)
	for i, s := range changed {
		if s.Factors == nil {
			continue
		}
		fl, err := seal.DecodeFactors(s.Factors)
		if err != nil {
			t.Fatal(err)
		}
		for j := range fl {
			if fl[j].Kind == seal.FactorFIDO2 {
				fl[j].RPID = "attacker.example"
				edited = true
			}
		}
		if changed[i].Factors, err = seal.EncodeFactors(fl); err != nil {
			t.Fatal(err)
		}
	}
	if !edited {
		t.Fatal("no FIDO2 factor to edit")
	}
	err = CheckLayoutSlotTable(meta, changed)
	if err == nil || !strings.Contains(err.Error(), "RP id") {
		t.Fatalf("a table naming another RP id: %v", err)
	}
	if _, err := OpenLayoutKeys(context.Background(), meta, changed, f.cred()); err == nil || !strings.Contains(err.Error(), "RP id") {
		t.Fatalf("it unlocked: %v", err)
	}
}
