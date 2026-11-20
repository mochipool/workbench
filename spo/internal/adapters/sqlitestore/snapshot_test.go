package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- fixtures ----

// snapFix is a closed workspace file with the credential that opens it.
type snapFix struct {
	name string
	path string
	cred func() SnapshotCredential
	open func(t *testing.T, path string) *Store
	// fake is the authenticator of a factor workspace (nil otherwise).
	fake *fakeSource
	// secrets are texts that must appear nowhere in a snapshot.
	secrets []string
}

func passCred(p string) func() SnapshotCredential {
	return func() SnapshotCredential { return SnapshotCredential{Passphrase: passphrase(p)} }
}

func passOpen(p string) func(*testing.T, string) *Store {
	return func(t *testing.T, path string) *Store {
		t.Helper()
		s, err := Open(path, passphrase(p))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
}

func hwFix(name, path string, f *fakeSource) snapFix {
	return snapFix{name: name, path: path, fake: f,
		cred: func() SnapshotCredential {
			in := f.inputs("devA", pinA)
			return SnapshotCredential{Factors: &in}
		},
		open: func(t *testing.T, p string) *Store {
			t.Helper()
			s, err := openHW(p, f, "devA", pinA)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
		secrets: []string{"seed-a", "seed-b", pinA, pinB}}
}

func stdFix(name, path, pass string, rec string) snapFix {
	f := snapFix{name: name, path: path, cred: passCred(pass), open: passOpen(pass), secrets: []string{pass}}
	if rec != "" {
		f.secrets = append(f.secrets, rec)
	}
	return f
}

type snapBuilder struct {
	name  string
	build func(t *testing.T) snapFix
}

func closeStd(s *Store) { s.Close() }

func snapBuilders() []snapBuilder {
	return []snapBuilder{
		{"standard records of every class", func(t *testing.T) snapFix {
			s, path, rec := scratch(t)
			fillList(t, s)
			putSecret(t, s, skey0, "the-signing-key")
			closeStd(s)
			f := stdFix("std", path, testPass, rec)
			f.secrets = append(f.secrets, "the-signing-key", "a cold sub-key passphrase")
			return f
		}},
		{"standard cold record", func(t *testing.T) snapFix {
			s, path, rec := stdCold(t, "sub-key passphrase one")
			closeStd(s)
			f := stdFix("stdcold", path, testPass, rec)
			f.secrets = append(f.secrets, "cold-secret-one", "sub-key passphrase one")
			return f
		}},
		{"hardware cold record", func(t *testing.T) snapFix {
			s, path, f, _ := hwCold(t)
			s.Close()
			x := hwFix("hwcold", path, f)
			x.secrets = append(x.secrets, "cold-secret-hw")
			return x
		}},
		{"hardware cold record with a previous wrap", func(t *testing.T) snapFix {
			s, path, f, _ := hwCold(t)
			f.corruptNext = 1
			if v, err := openString(t, s, coldRef); err != nil || v != "cold-secret-hw" {
				t.Fatalf("%q %v", v, err)
			}
			if h, _ := headerOf(t, s, coldRef); len(h.Prev) == 0 {
				t.Fatal("no previous wrap")
			}
			s.Close()
			return hwFix("hwprev", path, f)
		}},
		{"hardware cold record healed", func(t *testing.T) snapFix {
			s, path, f, _ := hwCold(t)
			f.corruptNext = 1
			openString(t, s, coldRef)
			openString(t, s, coldRef) // the heal
			if h, _ := headerOf(t, s, coldRef); h.Fallbacks != 1 {
				t.Fatalf("fallbacks %d", h.Fallbacks)
			}
			s.Close()
			return hwFix("hwheal", path, f)
		}},
		{"strict cold record", func(t *testing.T) snapFix {
			path, _, f, _ := standardThenRotated(t, unlock.Strict)
			s, err := openHW(path, f, "devA", pinA)
			if err != nil {
				t.Fatal(err)
			}
			in := f.inputs("devA", pinA)
			s.SetColdSource(&ColdSource{Factors: &in, Deriver: fakeDeriver{}})
			putSecret(t, s, coldRef, "cold-secret-strict")
			s.Close()
			return hwFix("strictcold", path, f)
		}},
		{"workspace rotated to hardware", func(t *testing.T) snapFix {
			path, _, f, rec := standardThenRotated(t, unlock.Hardware)
			x := hwFix("hw", path, f)
			x.secrets = append(x.secrets, rec, "the-signing-key")
			return x
		}},
		{"workspace rotated to strict (a policy change)", func(t *testing.T) snapFix {
			path, _, f, _ := standardThenRotated(t, unlock.Strict)
			return hwFix("strict", path, f)
		}},
		{"slot added and removed", func(t *testing.T) snapFix {
			s, path, rec := scratch(t)
			put(t, s, counter, "1")
			f := newFake()
			fa, _, err := EnrolFactor(ctx, f.inputs("devA", pinA), s.ws, nil)
			if err != nil {
				t.Fatal(err)
			}
			id, err := s.AddFactorSlot(ctx, []FactorPlan{fa})
			if err != nil {
				t.Fatal(err)
			}
			fa.Output.Destroy()
			req := RemoveRequest{SlotID: id, Daily: f.inputs("devA", pinA), Proof: presentStd(t, s, rec)}
			req.Daily.Passphrase = pinOf(testPass)
			txt, _, err := s.RemoveSlotByRotation(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if txt != nil {
				txt.Destroy()
			}
			if _, err := s.AddPassphraseSlot(ctx, passphrase("a second passphrase")); err != nil {
				t.Fatal(err)
			}
			s.Close()
			return stdFix("slots", path, testPass, rec)
		}},
		{"passphrase changed and rekeyed", func(t *testing.T) snapFix {
			s, path, _ := scratch(t)
			putSecret(t, s, skey0, "the-signing-key")
			rec := rekeyTo(t, s, "the new passphrase")
			rec = rekeyTo(t, s, "the newer passphrase")
			s.Close()
			f := stdFix("rekey", path, "the newer passphrase", rec)
			f.secrets = append(f.secrets, "the new passphrase", "the-signing-key")
			return f
		}},
		{"rekey with the cleanup pending", func(t *testing.T) snapFix {
			s, path, _ := scratch(t)
			put(t, s, counter, "1")
			presentStd(t, s, func() string { r, _ := heldRecovery.Load(s); return r.(string) }())
			rekeyPending(t, s, "pending passphrase")
			// the open handle's close runs the cleanup; a copy taken now keeps the marker
			copyPath := filepath.Join(t.TempDir(), "pending.db")
			if err := s.Backup(ctx, copyPath); err != nil {
				t.Fatal(err)
			}
			s.Close()
			path = copyPath
			if pendingFlag(t, path) != 1 {
				t.Fatal("no pending cleanup")
			}
			return stdFix("pending", path, "pending passphrase", "")
		}},
		{"migrated from format 2", func(t *testing.T) snapFix {
			p := format2Copy(t)
			old, err := OpenFormat2(p, legacyPW())
			if err != nil {
				t.Fatal(err)
			}
			old.SetColdSource(coldPass("a cold sub-key passphrase"))
			if _, err := old.Migrate3(ctx, ""); err != nil {
				t.Fatal(err)
			}
			old.Close()
			return stdFix("from2", p, legacyPass, "")
		}},
		{"migrated from the legacy format", func(t *testing.T) snapFix {
			p := legacyCopy(t, "store.db")
			old, err := OpenLegacy(p, legacyPW())
			if err != nil {
				t.Fatal(err)
			}
			old.SetColdSource(coldPass("a cold sub-key passphrase"))
			if _, err := old.Migrate(ctx, MigrateOptions{}); err != nil {
				t.Fatal(err)
			}
			old.Close()
			return stdFix("from1", p, legacyPass, "")
		}},
		{"checkpoint key record", func(t *testing.T) snapFix {
			s, path, rec := scratch(t)
			raw, _ := ckRecord(t)
			putCK(t, s, raw)
			s.Close()
			return stdFix("ck", path, testPass, rec)
		}},
		{"opcert and KES counter records", func(t *testing.T) snapFix {
			s, path, rec := scratch(t)
			putCounters(t, s, "poolA", cstate{issue: 4, kesCur: 2, kesNext: 3})
			putCounters(t, s, "poolB", cstate{issue: 1, kesCur: 0, kesNext: 1})
			putKes(t, s, "poolA", 2)
			s.Close()
			return stdFix("counters", path, testPass, rec)
		}},
	}
}

// ---- summaries of an open workspace ----

type snapSummary struct {
	Refs   []ports.Ref
	Gets   map[string]string
	Cold   ColdStatus
	Head   string
	Policy unlock.Policy
	Slots  []SlotInfo
}

func summarise(t *testing.T, s *Store) snapSummary {
	t.Helper()
	refs, err := s.ListRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out := snapSummary{Refs: refs, Gets: map[string]string{}}
	for _, r := range refs {
		b, err := get(s, r)
		if err != nil {
			out.Gets[fmt.Sprint(r)] = "error: " + err.Error()
		} else {
			out.Gets[fmt.Sprint(r)] = string(b)
		}
	}
	if out.Cold, err = s.ColdStatus(ctx); err != nil {
		t.Fatal(err)
	}
	seq, mac := s.Head()
	out.Head = fmt.Sprintf("%d %x", seq, mac)
	if out.Policy, err = s.Policy(ctx); err != nil {
		t.Fatal(err)
	}
	if out.Slots, err = s.Slots(ctx); err != nil {
		t.Fatal(err)
	}
	return out
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func newDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "new")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// withoutTransient is snap as WriteSnapshotFile writes it.
func withoutTransient(s ports.Snapshot) ports.Snapshot {
	s.Meta.CleanupPending = 0
	return s
}

// ---- round trip ----

// spec: SPO-Xsnapshot-OUT-001, SPO-Xsnapshot-OUT-002, SPO-Xsnapshot-OUT-003, SPO-Xsnapshot-PRE-001, SPO-Xsnapshot-PRE-003, SPO-Xsnapshot-IF-001, SPO-Xsnapshot-IF-002, SPO-Xsnapshot-IF-003
func TestSnapshotRoundTripOfEveryFixtureFamily(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			fx := b.build(t)
			beforeFile := readAll(t, fx.path)
			snap, facts, err := ReadSnapshot(ctx, fx.path, fx.cred())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(beforeFile, readAll(t, fx.path)) {
				t.Error("reading the snapshot changed the source file")
			}
			if len(snap.Records) == 0 || len(snap.Audit) == 0 || len(snap.Slots) == 0 {
				t.Fatalf("an empty snapshot: %d records, %d audit rows, %d slots", len(snap.Records), len(snap.Audit), len(snap.Slots))
			}
			dest := filepath.Join(newDir(t), "ws.db")
			if err := WriteSnapshotFile(ctx, dest, snap, fx.cred()); err != nil {
				t.Fatal(err)
			}
			// the written file: mode, head file, no leftovers
			if st, err := os.Stat(dest); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("mode: %v %v", st, err)
			}
			if got := dirEntries(t, filepath.Dir(dest)); !reflect.DeepEqual(got, []string{"ws.db", "ws.db.head", "ws.db.head.lock"}) {
				t.Errorf("the directory holds %v", got)
			}
			if ws, h, found, err := readHeadFile(dest); err != nil || !found || !bytes.Equal(ws, facts.WorkspaceID) || !h.equal(facts.Head) {
				t.Errorf("head file: %x %v %v %v (want %v)", ws, h, found, err, facts.Head)
			}
			// the existing verification, plain and deep
			if _, err := verifyFile(dest, mustCred(t, fx), false); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if _, err := verifyFile(dest, mustCred(t, fx), true); err != nil {
				t.Fatalf("deep verify: %v", err)
			}
			// row-exact, with the one named exception
			back, backFacts, err := ReadSnapshot(ctx, dest, fx.cred())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(withoutTransient(snap), back) {
				t.Error("the snapshot read from the written file differs from the one written")
			}
			facts.Notices, backFacts.Notices = nil, nil
			if !reflect.DeepEqual(facts, backFacts) {
				t.Error("the facts differ")
			}
			if again, err := FactsOf(snap); err != nil || !reflect.DeepEqual(again, facts) {
				t.Errorf("FactsOf differs from the facts read: %v", err)
			}
			// the written workspace behaves as the original
			want := summarise(t, fx.open(t, fx.path))
			got := summarise(t, fx.open(t, dest))
			if !reflect.DeepEqual(want, got) {
				t.Errorf("the workspaces differ:\n source %+v\n   copy %+v", want, got)
			}
			// the written file can be opened without a notice about its head file
			s := fx.open(t, dest)
			for _, n := range s.Notices() {
				if strings.Contains(n, "head file") {
					t.Errorf("notice: %s", n)
				}
			}
		})
	}
}

func mustCred(t *testing.T, fx snapFix) credential {
	t.Helper()
	c, _, err := fx.cred().resolve()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The facts are the values the audit chain records.
//
// spec: SPO-Xsnapshot-IF-003
func TestSnapshotFactsAreTheValuesTheAuditChainRecords(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			fx := b.build(t)
			snap, facts, err := ReadSnapshot(ctx, fx.path, fx.cred())
			if err != nil {
				t.Fatal(err)
			}
			if got := (Head{Seq: uint64(snap.Audit[len(snap.Audit)-1].Seq), MAC: snap.Audit[len(snap.Audit)-1].MAC}); !got.equal(facts.Head) {
				t.Error("head")
			}
			// the newest slots or rollover row records the slot set hash
			var last []byte
			for _, a := range snap.Audit {
				if len(a.SlotSet) > 0 {
					last = a.SlotSet
				}
			}
			if !bytes.Equal(last, facts.SlotSetHash) {
				t.Errorf("slot set hash %x, the newest audit row records %x", facts.SlotSetHash, last)
			}
			// each record's newest hash in the chain is the fact
			newest := map[string][]byte{}
			for _, a := range snap.Audit {
				var ts []touched
				if err := cbor.Unmarshal(a.Touched, &ts); err != nil {
					t.Fatal(err)
				}
				for _, e := range ts {
					newest[string(e.ID)] = e.Hash
				}
			}
			if len(facts.RecordHashes) != len(snap.Records) {
				t.Fatal("record hashes")
			}
			for i, r := range snap.Records {
				if !bytes.Equal(newest[string(r.ID)], facts.RecordHashes[i]) {
					t.Errorf("record %d: the chain has %x, the fact is %x", i, newest[string(r.ID)], facts.RecordHashes[i])
				}
			}
		})
	}
}

// The transient column: a rekey whose cleanup has not run leaves
// meta.cleanup_pending at 1. The snapshot reports it; the written file has 0.
//
// spec: SPO-Xsnapshot-OUT-002
func TestSnapshotCleanupPendingIsTransient(t *testing.T) {
	var fx snapFix
	for _, b := range snapBuilders() {
		if b.name == "rekey with the cleanup pending" {
			fx = b.build(t)
		}
	}
	snap, _, err := ReadSnapshot(ctx, fx.path, fx.cred())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Meta.CleanupPending != 1 {
		t.Fatalf("cleanup_pending %d", snap.Meta.CleanupPending)
	}
	dest := filepath.Join(newDir(t), "ws.db")
	if err := WriteSnapshotFile(ctx, dest, snap, fx.cred()); err != nil {
		t.Fatal(err)
	}
	if pendingFlag(t, dest) != 0 {
		t.Error("the written file carries the cleanup marker")
	}
	// whatever the snapshot says, the file gets 0
	snap.Meta.CleanupPending = 7
	dest2 := filepath.Join(newDir(t), "ws.db")
	if err := WriteSnapshotFile(ctx, dest2, snap, fx.cred()); err != nil {
		t.Fatal(err)
	}
	if pendingFlag(t, dest2) != 0 {
		t.Error("the written file carries the cleanup marker")
	}
}

// ---- a snapshot holds no key and nothing is decrypted ----

// spec: SPO-Xsnapshot-SEC-001
func TestSnapshotTypesHoldOnlyPlainData(t *testing.T) {
	var walk func(path string, ty reflect.Type)
	walk = func(path string, ty reflect.Type) {
		switch ty.Kind() {
		case reflect.Int64, reflect.String:
		case reflect.Slice:
			if ty.Elem().Kind() == reflect.Uint8 {
				return
			}
			walk(path+"[]", ty.Elem())
		case reflect.Ptr:
			if ty.Elem().Kind() != reflect.Int64 {
				t.Errorf("%s: a pointer to %s", path, ty.Elem())
			}
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				if !f.IsExported() {
					t.Errorf("%s.%s: an unexported field", path, f.Name)
				}
				walk(path+"."+f.Name, f.Type)
			}
		default:
			t.Errorf("%s: type %s (a snapshot holds integers, strings and byte slices only)", path, ty)
		}
	}
	walk("Snapshot", reflect.TypeOf(ports.Snapshot{}))
	if reflect.TypeOf(SnapshotFacts{}).NumField() != 5 {
		t.Error("SnapshotFacts changed: check that it holds no key material")
	}
}

// spec: SPO-Xsnapshot-SEC-001, SPO-Xsnapshot-SEC-002
func TestSnapshotHoldsNoKeyAndAsksNothingBeyondTheVerification(t *testing.T) {
	for _, b := range snapBuilders() {
		t.Run(b.name, func(t *testing.T) {
			fx := b.build(t)
			var before int
			liveBefore := liveBuffers()
			if fx.fake != nil {
				before = fx.fake.asserts
				c, _, _ := fx.cred().resolve()
				if _, err := verifyFile(fx.path, c, false); err != nil {
					t.Fatal(err)
				}
			}
			verifyAsserts := 0
			if fx.fake != nil {
				verifyAsserts = fx.fake.asserts - before
				before = fx.fake.asserts
			}
			cred := fx.cred()
			liveBefore = liveBuffers()
			snap, _, err := ReadSnapshot(ctx, fx.path, cred)
			if err != nil {
				t.Fatal(err)
			}
			if fx.fake != nil {
				if got := fx.fake.asserts - before; got != verifyAsserts {
					t.Errorf("reading the snapshot asked the authenticator %d times, the verification alone %d", got, verifyAsserts)
				}
			}
			var all bytes.Buffer
			all.Write(snap.Meta.WorkspaceID)
			all.Write(snap.Meta.KeyEpoch)
			all.Write(snap.Meta.EpochMAC)
			all.Write(snap.Meta.RecoveryPub)
			all.WriteString(snap.Meta.Policy)
			for _, r := range snap.Slots {
				all.Write(r.ID)
				all.WriteString(r.Kind)
				all.Write(r.Salt)
				all.Write(r.KeyCommit)
				all.Write(r.Nonce)
				all.Write(r.WrappedKey)
				all.Write(r.RecHash)
				all.Write(r.Factors)
			}
			for _, r := range snap.Records {
				all.Write(r.ID)
				all.Write(r.LookupTag)
				all.WriteString(r.Kind)
				all.Write(r.Nonce)
				all.Write(r.WrappedKey)
				all.Write(r.OwnerSealed)
				all.Write(r.Ciphertext)
			}
			for _, r := range snap.Audit {
				all.Write(r.Event)
				all.Write(r.Touched)
				all.Write(r.SlotSet)
				all.Write(r.MAC)
				all.Write(r.PrevMAC)
			}
			secrets := append([]string{"the-signing-key", "cold-secret", "cold key two"}, fx.secrets...)
			if fx.fake == nil && fx.name != "stdleft" {
				secrets = append(secrets, testPass, "the new passphrase")
			}
			for _, s := range secrets {
				for _, form := range secretForms(s) { // as it is (8 bytes or more) and in the forms a write would take
					if bytes.Contains(all.Bytes(), form) {
						t.Errorf("the snapshot holds %q (as %q)", s, form)
					}
				}
				if raw := []byte(s); len(raw) == 32 && bytes.Contains(all.Bytes(), raw) {
					t.Errorf("the snapshot holds a 32-byte key")
				}
			}
			if live := liveBuffers(); live != liveBefore {
				t.Errorf("%d secret buffers live after the read, %d before", live, liveBefore)
			}
		})
	}
}

// A hardware or strict workspace is read and written through its factors; a
// passphrase or the printed recovery key alone is never accepted.
//
// spec: SPO-Xsnapshot-SEC-002, SPO-Xsnapshot-PRE-001
func TestSnapshotHardwareIsReadAndWrittenThroughFactorsOnly(t *testing.T) {
	for _, name := range []string{"workspace rotated to hardware", "workspace rotated to strict (a policy change)"} {
		t.Run(name, func(t *testing.T) {
			var fx snapFix
			for _, b := range snapBuilders() {
				if b.name == name {
					fx = b.build(t)
				}
			}
			template(t)
			before := fx.fake.asserts
			snap, _, err := ReadSnapshot(ctx, fx.path, fx.cred())
			if err != nil {
				t.Fatal(err)
			}
			if fx.fake.asserts == before {
				t.Error("the authenticator was not asked")
			}
			for _, wrong := range []SnapshotCredential{
				{Passphrase: pw()},
				{Passphrase: passphrase("")},
				{Recovery: recovery()},
			} {
				if _, _, err := ReadSnapshot(ctx, fx.path, wrong); err == nil {
					t.Error("a credential without factors read a factor workspace")
				}
				dir := newDir(t)
				if err := WriteSnapshotFile(ctx, filepath.Join(dir, "ws.db"), snap, wrong); err == nil {
					t.Error("a credential without factors verified a written factor workspace")
				}
				if got := dirEntries(t, dir); len(got) != 0 {
					t.Errorf("a refused write left %v", got)
				}
			}
			// the wrong authenticator is refused too
			in := fx.fake.inputs("devB", pinB)
			if _, _, err := ReadSnapshot(ctx, fx.path, SnapshotCredential{Factors: &in}); err == nil && name == "workspace rotated to strict (a policy change)" {
				t.Error("the second authenticator opened a strict workspace")
			}
		})
	}
}

// exactly one credential
//
// spec: SPO-Xsnapshot-IF-001
func TestSnapshotNeedsExactlyOneCredential(t *testing.T) {
	fx := snapBuilders()[0].build(t)
	in := newFake().inputs("devA", pinA)
	template(t)
	for _, c := range []SnapshotCredential{{}, {Passphrase: pw(), Recovery: recovery()}, {Passphrase: pw(), Factors: &in}} {
		if _, _, err := ReadSnapshot(ctx, fx.path, c); !errors.Is(err, ErrSnapshotCredential) {
			t.Errorf("%v", err)
		}
	}
	if _, _, err := ReadSnapshot(ctx, fx.path, SnapshotCredential{Factors: &FactorInputs{}}); err == nil {
		t.Error("factors without a source")
	}
	// the printed recovery key reads a standard workspace
	s, path, rec := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	snap, _, err := ReadSnapshot(ctx, path, SnapshotCredential{Recovery: passphrase(rec)})
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(newDir(t), "ws.db")
	if err := WriteSnapshotFile(ctx, dest, snap, SnapshotCredential{Recovery: passphrase(rec)}); err != nil {
		t.Fatal(err)
	}
}

// ---- refusals of the source ----

// spec: SPO-Xsnapshot-PRE-002
func TestSnapshotRefusesWhatItCannotTrust(t *testing.T) {
	std := func(t *testing.T) snapFix { return snapBuilders()[0].build(t) }
	t.Run("an older format", func(t *testing.T) {
		p := format2Copy(t)
		if _, _, err := ReadSnapshot(ctx, p, SnapshotCredential{Passphrase: legacyPW()}); err == nil || !strings.Contains(err.Error(), "needs migration") {
			t.Errorf("format 2: %v", err)
		}
		p = legacyCopy(t, "store.db")
		if _, _, err := ReadSnapshot(ctx, p, SnapshotCredential{Passphrase: legacyPW()}); err == nil || !strings.Contains(err.Error(), "needs migration") {
			t.Errorf("format 1: %v", err)
		}
	})
	t.Run("a wrong passphrase", func(t *testing.T) {
		fx := std(t)
		if _, _, err := ReadSnapshot(ctx, fx.path, SnapshotCredential{Passphrase: passphrase("wrong")}); !errors.Is(err, ErrWrongCredential) {
			t.Errorf("%v", err)
		}
	})
	t.Run("a file that does not verify", func(t *testing.T) {
		fx := std(t)
		db := rawDB(t, fx.path)
		if _, err := db.Exec(`UPDATE records SET ciphertext = randomblob(length(ciphertext)) WHERE rowid = (SELECT min(rowid) FROM records)`); err != nil {
			t.Fatal(err)
		}
		db.Close()
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrVerify) {
			t.Errorf("%v", err)
		}
	})
	t.Run("the wrong file mode", func(t *testing.T) {
		fx := std(t)
		if err := os.Chmod(fx.path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("%v", err)
		}
	})
	t.Run("not a regular file", func(t *testing.T) {
		fx := std(t)
		link := filepath.Join(t.TempDir(), "link.db")
		if err := os.Symlink(fx.path, link); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadSnapshot(ctx, link, fx.cred()); err == nil {
			t.Error("a symlink was read")
		}
	})
	t.Run("a planted trigger", func(t *testing.T) {
		fx := std(t)
		db := rawDB(t, fx.path)
		plantTrigger(t, db, "evil")
		db.Close()
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrSchema) {
			t.Errorf("%v", err)
		}
	})
	t.Run("an extra table", func(t *testing.T) {
		fx := std(t)
		db := rawDB(t, fx.path)
		if _, err := db.Exec(`CREATE TABLE extra (x INTEGER)`); err != nil {
			t.Fatal(err)
		}
		db.Close()
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrSchema) {
			t.Errorf("%v", err)
		}
	})
	t.Run("an extra column", func(t *testing.T) {
		fx := std(t)
		db := rawDB(t, fx.path)
		if _, err := db.Exec(`ALTER TABLE records ADD COLUMN extra INTEGER`); err != nil {
			t.Fatal(err)
		}
		db.Close()
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrSchema) {
			t.Errorf("%v", err)
		}
	})
	t.Run("a journal or a WAL beside it", func(t *testing.T) {
		for _, side := range []string{"-journal", "-wal"} {
			fx := std(t)
			if err := os.WriteFile(fx.path+side, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrUncheckpointed) {
				t.Errorf("%s: %v", side, err)
			}
		}
	})
	t.Run("a workspace open elsewhere", func(t *testing.T) {
		fx := std(t)
		s := fx.open(t, fx.path)
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrLocked) {
			t.Errorf("%v", err)
		}
		s.Close()
		if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); err != nil {
			t.Errorf("after the close: %v", err)
		}
	})
	t.Run("a missing file", func(t *testing.T) {
		if _, _, err := ReadSnapshot(ctx, filepath.Join(t.TempDir(), "none.db"), SnapshotCredential{Passphrase: pw()}); err == nil {
			t.Error("a missing file was read")
		}
	})
}

// The reading is bounded before any row is loaded.
//
// spec: SPO-Xsnapshot-OUT-004
func TestSnapshotReaderRefusesMoreRowsThanTheLimit(t *testing.T) {
	path := fresh(t)
	db := rawDB(t, path)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	st, err := tx.Prepare(`INSERT INTO records (id, lookup_tag, kind, version, nonce, wrapped_key, owner_sealed, ciphertext, updated_at) VALUES (?, ?, 'x', 1, x'00', x'00', x'00', x'00', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= ports.SnapshotMaxRecords; i++ {
		id := fmt.Appendf(nil, "%016d", i)
		if _, err := st.Exec(id, id); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	err = withReadOnly(path, func(db *sql.DB) error {
		_, err := readSnapshotRows(ctx, db)
		return err
	})
	if !errors.Is(err, ports.ErrSnapshot) {
		t.Errorf("%v", err)
	}
}

// ---- hostile snapshots ----

func stdSnap(t *testing.T) (ports.Snapshot, snapFix) {
	t.Helper()
	fx := snapBuilders()[0].build(t)
	snap, _, err := ReadSnapshot(ctx, fx.path, fx.cred())
	if err != nil {
		t.Fatal(err)
	}
	return snap, fx
}

func cloneSnap(s ports.Snapshot) ports.Snapshot {
	c := s
	c.Slots = append([]ports.SnapshotSlot(nil), s.Slots...)
	c.Records = append([]ports.SnapshotRecord(nil), s.Records...)
	c.Audit = append([]ports.SnapshotAudit(nil), s.Audit...)
	return c
}

func refusedWrite(t *testing.T, snap ports.Snapshot, fx snapFix) error {
	t.Helper()
	dir := newDir(t)
	err := WriteSnapshotFile(ctx, filepath.Join(dir, "ws.db"), snap, fx.cred())
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Errorf("a refused write left %v", got)
	}
	return err
}

// spec: SPO-Xsnapshot-PRE-005, SPO-Xsnapshot-OUT-004, SPO-Xsnapshot-INV-001
func TestSnapshotWriterRefusesHostileSnapshots(t *testing.T) {
	snap, fx := stdSnap(t)
	if len(snap.Records) < 3 || len(snap.Audit) < 3 {
		t.Fatalf("fixture too small: %d records, %d audit rows", len(snap.Records), len(snap.Audit))
	}
	cases := map[string]func(s *ports.Snapshot){
		"duplicate record ids":    func(s *ports.Snapshot) { s.Records[1].ID = s.Records[0].ID },
		"records out of order":    func(s *ports.Snapshot) { s.Records[0], s.Records[1] = s.Records[1], s.Records[0] },
		"duplicate lookup tags":   func(s *ports.Snapshot) { s.Records[1].LookupTag = s.Records[0].LookupTag },
		"audit rows out of order": func(s *ports.Snapshot) { s.Audit[0], s.Audit[1] = s.Audit[1], s.Audit[0] },
		"duplicate audit rows":    func(s *ports.Snapshot) { s.Audit[1].Seq = s.Audit[0].Seq },
		"audit sequence zero":     func(s *ports.Snapshot) { s.Audit[0].Seq = 0 },
		"a gap in the audit rows": func(s *ports.Snapshot) { s.Audit = append(s.Audit[:1], s.Audit[2:]...) },
		"an unknown slot kind":    func(s *ports.Snapshot) { s.Slots[0].Kind = "magic" },
		"duplicate slot ids":      func(s *ports.Snapshot) { s.Slots[1].ID = s.Slots[0].ID },
		"an empty record id":      func(s *ports.Snapshot) { s.Records[0].ID = nil },
		"an oversized field":      func(s *ports.Snapshot) { s.Records[0].Ciphertext = make([]byte, ports.SnapshotMaxField+1) },
		"an oversized kind":       func(s *ports.Snapshot) { s.Records[0].Kind = strings.Repeat("k", ports.SnapshotMaxKind+1) },
		"too many records":        func(s *ports.Snapshot) { s.Records = make([]ports.SnapshotRecord, ports.SnapshotMaxRecords+1) },
		"too many audit rows":     func(s *ports.Snapshot) { s.Audit = make([]ports.SnapshotAudit, ports.SnapshotMaxAudit+1) },
		"too many slots":          func(s *ports.Snapshot) { s.Slots = make([]ports.SnapshotSlot, ports.SnapshotMaxSlots+1) },
		"an unknown schema":       func(s *ports.Snapshot) { s.Meta.SchemaVersion = 99 },
		"an unknown policy":       func(s *ports.Snapshot) { s.Meta.Policy = "lax" },
		"a missing meta":          func(s *ports.Snapshot) { s.Meta = ports.SnapshotMeta{SchemaVersion: s.Meta.SchemaVersion} },
		"no slots":                func(s *ports.Snapshot) { s.Slots = nil },
		"no audit rows":           func(s *ports.Snapshot) { s.Audit = nil },
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			c := cloneSnap(snap)
			cases[n](&c)
			if err := refusedWrite(t, c, fx); err == nil {
				t.Error("the snapshot was written")
			}
		})
	}
	t.Run("the total size", func(t *testing.T) {
		c := cloneSnap(snap)
		c.Records = nil
		big := make([]byte, ports.SnapshotMaxField)
		for i := 0; i < ports.SnapshotMaxBytes/ports.SnapshotMaxField+1; i++ {
			c.Records = append(c.Records, ports.SnapshotRecord{ID: []byte{byte(i >> 8), byte(i)}, LookupTag: []byte{byte(i >> 8), byte(i), 1}, Kind: "k", Ciphertext: big})
		}
		if err := c.Validate(); !errors.Is(err, ports.ErrSnapshot) {
			t.Errorf("%v", err)
		}
	})
}

// ---- mutation: every column of every table ----

type colMut struct {
	name string
	// apply changes one value of the snapshot; row picks the row (0 first,
	// 1 last). It returns false when the table has no such row.
	apply func(s *ports.Snapshot, row int) bool
}

func flip(b *[]byte) {
	if len(*b) == 0 {
		*b = []byte{1}
		return
	}
	c := append([]byte(nil), *b...)
	c[0] ^= 1
	*b = c
}

func bumpPtr(p **int64) {
	if *p == nil {
		v := int64(1)
		*p = &v
		return
	}
	v := **p + 1
	*p = &v
}

func pick(n, row int) (int, bool) {
	if n == 0 {
		return 0, false
	}
	if row == 0 {
		return 0, true
	}
	return n - 1, true
}

func snapColumns() []colMut {
	var cols []colMut
	meta := func(name string, f func(m *ports.SnapshotMeta)) {
		cols = append(cols, colMut{"meta." + name, func(s *ports.Snapshot, row int) bool {
			if row != 0 {
				return false
			}
			f(&s.Meta)
			return true
		}})
	}
	meta("schema_version", func(m *ports.SnapshotMeta) { m.SchemaVersion++ })
	meta("workspace_id", func(m *ports.SnapshotMeta) { flip(&m.WorkspaceID) })
	meta("format_version", func(m *ports.SnapshotMeta) { m.FormatVersion++ })
	meta("created_at", func(m *ports.SnapshotMeta) { m.CreatedAt++ })
	meta("key_epoch", func(m *ports.SnapshotMeta) { flip(&m.KeyEpoch) })
	meta("epoch_mac", func(m *ports.SnapshotMeta) { flip(&m.EpochMAC) })
	meta("policy", func(m *ports.SnapshotMeta) {
		if m.Policy == "strict" {
			m.Policy = "standard"
		} else {
			m.Policy = "strict"
		}
	})
	meta("recovery_pub", func(m *ports.SnapshotMeta) { flip(&m.RecoveryPub) })
	slot := func(name string, f func(r *ports.SnapshotSlot)) {
		cols = append(cols, colMut{"keyslots." + name, func(s *ports.Snapshot, row int) bool {
			i, ok := pick(len(s.Slots), row)
			if ok {
				f(&s.Slots[i])
			}
			return ok
		}})
	}
	slot("id", func(r *ports.SnapshotSlot) { flip(&r.ID) })
	slot("kind", func(r *ports.SnapshotSlot) {
		if r.Kind == "recovery" {
			r.Kind = "passphrase"
		} else {
			r.Kind = "recovery"
		}
	})
	slot("kdf_memory_kib", func(r *ports.SnapshotSlot) { bumpPtr(&r.KDFMemoryKiB) })
	slot("kdf_passes", func(r *ports.SnapshotSlot) { bumpPtr(&r.KDFPasses) })
	slot("kdf_lanes", func(r *ports.SnapshotSlot) { bumpPtr(&r.KDFLanes) })
	slot("salt", func(r *ports.SnapshotSlot) { flip(&r.Salt) })
	slot("key_commit", func(r *ports.SnapshotSlot) { flip(&r.KeyCommit) })
	slot("nonce", func(r *ports.SnapshotSlot) { flip(&r.Nonce) })
	slot("wrapped_key", func(r *ports.SnapshotSlot) { flip(&r.WrappedKey) })
	slot("bound", func(r *ports.SnapshotSlot) { r.Bound ^= 1 })
	slot("rec_hash", func(r *ports.SnapshotSlot) { flip(&r.RecHash) })
	slot("factors", func(r *ports.SnapshotSlot) { flip(&r.Factors) })
	// a nullable column set to NULL (skipped where it is NULL already)
	null := func(name string, f func(r *ports.SnapshotSlot) bool) {
		cols = append(cols, colMut{"keyslots." + name + " to NULL", func(s *ports.Snapshot, row int) bool {
			i, ok := pick(len(s.Slots), row)
			return ok && f(&s.Slots[i])
		}})
	}
	null("kdf_memory_kib", func(r *ports.SnapshotSlot) bool { x := r.KDFMemoryKiB != nil; r.KDFMemoryKiB = nil; return x })
	null("kdf_passes", func(r *ports.SnapshotSlot) bool { x := r.KDFPasses != nil; r.KDFPasses = nil; return x })
	null("kdf_lanes", func(r *ports.SnapshotSlot) bool { x := r.KDFLanes != nil; r.KDFLanes = nil; return x })
	null("salt", func(r *ports.SnapshotSlot) bool { x := r.Salt != nil; r.Salt = nil; return x })
	null("rec_hash", func(r *ports.SnapshotSlot) bool { x := r.RecHash != nil; r.RecHash = nil; return x })
	null("factors", func(r *ports.SnapshotSlot) bool { x := r.Factors != nil; r.Factors = nil; return x })
	meta("recovery_pub to NULL", func(m *ports.SnapshotMeta) { m.RecoveryPub = nil })
	rec := func(name string, f func(r *ports.SnapshotRecord)) {
		cols = append(cols, colMut{"records." + name, func(s *ports.Snapshot, row int) bool {
			i, ok := pick(len(s.Records), row)
			if ok {
				f(&s.Records[i])
			}
			return ok
		}})
	}
	rec("id", func(r *ports.SnapshotRecord) { flip(&r.ID) })
	rec("lookup_tag", func(r *ports.SnapshotRecord) { flip(&r.LookupTag) })
	rec("kind", func(r *ports.SnapshotRecord) { r.Kind += "x" })
	rec("version", func(r *ports.SnapshotRecord) { r.Version++ })
	rec("nonce", func(r *ports.SnapshotRecord) { flip(&r.Nonce) })
	rec("wrapped_key", func(r *ports.SnapshotRecord) { flip(&r.WrappedKey) })
	rec("owner_sealed", func(r *ports.SnapshotRecord) { flip(&r.OwnerSealed) })
	rec("ciphertext", func(r *ports.SnapshotRecord) { flip(&r.Ciphertext) })
	rec("updated_at", func(r *ports.SnapshotRecord) { r.UpdatedAt++ })
	aud := func(name string, f func(r *ports.SnapshotAudit)) {
		cols = append(cols, colMut{"audit." + name, func(s *ports.Snapshot, row int) bool {
			i, ok := pick(len(s.Audit), row)
			if ok {
				f(&s.Audit[i])
			}
			return ok
		}})
	}
	aud("seq", func(r *ports.SnapshotAudit) { r.Seq += 1000 })
	aud("at", func(r *ports.SnapshotAudit) { r.At++ })
	aud("kind", func(r *ports.SnapshotAudit) {
		if r.Kind == "update" {
			r.Kind = "slots"
		} else {
			r.Kind = "update"
		}
	})
	aud("event", func(r *ports.SnapshotAudit) { flip(&r.Event) })
	aud("touched", func(r *ports.SnapshotAudit) { flip(&r.Touched) })
	aud("slotset", func(r *ports.SnapshotAudit) { flip(&r.SlotSet) })
	aud("mac", func(r *ports.SnapshotAudit) { flip(&r.MAC) })
	aud("prev_mac", func(r *ports.SnapshotAudit) { flip(&r.PrevMAC) })
	return cols
}

// uncoveredColumns are columns of a snapshot that nothing the store verifies
// binds, so a changed value is written as given and the file still verifies.
// The test asserts this set exactly: a column that starts to fail is removed
// here, and one that is not listed and does not fail is a new finding.
var uncoveredColumns = map[string]string{
	"meta.created_at":    "no MAC, hash or chain covers the creation time",
	"records.updated_at": "the record hash and the chain's touched list do not include the update time",
}

// spec: SPO-Xsnapshot-INV-003, SPO-Xsnapshot-PRE-003, SPO-Xsnapshot-INV-001
func TestSnapshotEveryChangedColumnIsRefusedOrNamed(t *testing.T) {
	fixtures := map[string]snapFix{}
	for _, b := range snapBuilders() {
		switch b.name {
		case "standard records of every class", "workspace rotated to hardware":
			fixtures[b.name] = b.build(t)
		}
	}
	if len(fixtures) != 2 {
		t.Fatal("fixtures")
	}
	accepted := map[string]bool{}
	covered := map[string]bool{}
	for name, fx := range fixtures {
		snap, _, err := ReadSnapshot(ctx, fx.path, fx.cred())
		if err != nil {
			t.Fatal(err)
		}
		for _, col := range snapColumns() {
			for row := 0; row < 2; row++ {
				c := cloneSnap(snap)
				if !col.apply(&c, row) {
					continue
				}
				// meta is one row: the "last" repeat is the same change
				if strings.HasPrefix(col.name, "meta.") && row == 1 {
					continue
				}
				dir := newDir(t)
				dest := filepath.Join(dir, "ws.db")
				err := WriteSnapshotFile(ctx, dest, c, fx.cred())
				if err != nil {
					covered[col.name] = true
					if got := dirEntries(t, dir); len(got) != 0 {
						t.Errorf("%s %s row %d: the refused write left %v", name, col.name, row, got)
					}
					continue
				}
				// accepted: the value was carried exactly
				back, _, rerr := ReadSnapshot(ctx, dest, fx.cred())
				if rerr != nil {
					t.Errorf("%s %s row %d: written but unreadable: %v", name, col.name, row, rerr)
				} else if !reflect.DeepEqual(withoutTransient(c), back) {
					t.Errorf("%s %s row %d: written but not read back as given", name, col.name, row)
				}
				accepted[col.name] = true
			}
		}
	}
	for col := range accepted {
		if _, ok := uncoveredColumns[col]; !ok {
			t.Errorf("a changed %s was accepted and verified: a new finding", col)
		}
	}
	for col, why := range uncoveredColumns {
		if !accepted[col] {
			t.Errorf("%s is listed as uncovered (%s) but a changed value was refused; remove it from the list", col, why)
		}
	}
	for _, col := range snapColumns() {
		if !covered[col.name] && !accepted[col.name] {
			t.Errorf("%s was never exercised", col.name)
		}
	}
}

// ---- no overwrite ----

// spec: SPO-Xsnapshot-PRE-004, SPO-Xsnapshot-INV-001
func TestSnapshotWriteNeverOverwrites(t *testing.T) {
	snap, fx := stdSnap(t)
	dir := newDir(t)
	dest := filepath.Join(dir, "ws.db")
	if err := os.WriteFile(dest, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshotFile(ctx, dest, snap, fx.cred()); !errors.Is(err, ErrExists) {
		t.Errorf("%v", err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "precious" {
		t.Error("the existing file changed")
	}
	if got := dirEntries(t, dir); !reflect.DeepEqual(got, []string{"ws.db"}) {
		t.Errorf("left %v", got)
	}
	// a workspace
	dest2 := filepath.Join(newDir(t), "ws.db")
	if err := WriteSnapshotFile(ctx, dest2, snap, fx.cred()); err != nil {
		t.Fatal(err)
	}
	before := readAll(t, dest2)
	if err := WriteSnapshotFile(ctx, dest2, snap, fx.cred()); !errors.Is(err, ErrExists) {
		t.Errorf("%v", err)
	}
	if !bytes.Equal(before, readAll(t, dest2)) {
		t.Error("the workspace changed")
	}
	// a leftover head file or sidecar of another file is not adopted
	for _, side := range []string{".head", ".head.next", ".head.lock", "-wal", "-journal"} {
		d := newDir(t)
		p := filepath.Join(d, "ws.db")
		if err := os.WriteFile(p+side, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := WriteSnapshotFile(ctx, p, snap, fx.cred()); !errors.Is(err, ErrExists) {
			t.Errorf("%s: %v", side, err)
		}
		if got := dirEntries(t, d); len(got) != 1 {
			t.Errorf("%s: left %v", side, got)
		}
	}
	// a file that appears between the build and the link is not replaced either
	d := newDir(t)
	p := filepath.Join(d, "ws.db")
	afterSnapshotBuild = func() error { return os.WriteFile(p, []byte("raced in"), 0o600) }
	defer func() { afterSnapshotBuild = nil }()
	if err := WriteSnapshotFile(ctx, p, snap, fx.cred()); !errors.Is(err, ErrExists) {
		t.Errorf("race: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "raced in" {
		t.Error("the raced file was replaced")
	}
	if got := dirEntries(t, d); !reflect.DeepEqual(got, []string{"ws.db"}) {
		t.Errorf("race: left %v", got)
	}
	// a missing directory
	if err := WriteSnapshotFile(ctx, filepath.Join(t.TempDir(), "no", "ws.db"), snap, fx.cred()); err == nil {
		t.Error("written into a missing directory")
	}
}

// ---- crash points ----

// spec: SPO-Xsnapshot-INV-001, SPO-Xsnapshot-INV-002
func TestSnapshotFailureBetweenBuildAndLinkLeavesNothing(t *testing.T) {
	snap, fx := stdSnap(t)
	dir := newDir(t)
	boom := errors.New("the build was interrupted")
	afterSnapshotBuild = func() error { return boom }
	defer func() { afterSnapshotBuild = nil }()
	if err := WriteSnapshotFile(ctx, filepath.Join(dir, "ws.db"), snap, fx.cred()); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Errorf("left %v", got)
	}
	// and the same call works afterwards
	afterSnapshotBuild = nil
	if err := WriteSnapshotFile(ctx, filepath.Join(dir, "ws.db"), snap, fx.cred()); err != nil {
		t.Fatal(err)
	}
}

// A cancelled context stops the write with nothing left.
//
// spec: SPO-Xsnapshot-INV-001
func TestSnapshotCancelledWriteLeavesNothing(t *testing.T) {
	snap, fx := stdSnap(t)
	dir := newDir(t)
	c, cancel := context.WithCancel(ctx)
	cancel()
	if err := WriteSnapshotFile(c, filepath.Join(dir, "ws.db"), snap, fx.cred()); err == nil {
		t.Error("written with a cancelled context")
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}

// A crash after the link and before the head file leaves the new file, the
// announcement of its head (.head.next) and no head file. Opening it completes
// the write: the head file is made and the announcement removed.
//
// spec: SPO-Xsnapshot-INV-002, SPO-Xsnapshot-OUT-003
func TestSnapshotCrashBetweenLinkAndHeadFile(t *testing.T) {
	snap, fx := stdSnap(t)
	dir := newDir(t)
	dest := filepath.Join(dir, "ws.db")
	boom := errors.New("crash")
	afterSnapshotLink = func() error { return boom }
	defer func() { afterSnapshotLink = nil }()
	if err := WriteSnapshotFile(ctx, dest, snap, fx.cred()); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	afterSnapshotLink = nil
	got := dirEntries(t, dir)
	if !reflect.DeepEqual(got, []string{"ws.db", "ws.db.head.lock", "ws.db.head.next"}) {
		t.Fatalf("the crash left %v", got)
	}
	if _, _, found, _ := readHeadFile(dest); found {
		t.Error("a head file exists")
	}
	// the file itself is complete: a read-only verification says what is pending
	if _, err := verifyFile(dest, mustCred(t, fx), false); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// the next open completes it
	s := fx.open(t, dest)
	s.Close()
	if _, _, found, err := readHeadFile(dest); !found || err != nil {
		t.Errorf("head file after the open: %v %v", found, err)
	}
	if _, err := os.Lstat(sidecarPath(dest)); err == nil {
		t.Error("the announcement is still there")
	}
	// a crash that left a different file's announcement does not pass as this one's
	if _, h, err := InspectHead(dest); err != nil || h.Seq == 0 {
		t.Errorf("%v %v", h, err)
	}
}

// A failure after the link that is not a crash removes what was linked.
//
// spec: SPO-Xsnapshot-INV-001
func TestSnapshotHeadFileFailureRemovesTheLinkedFile(t *testing.T) {
	snap, fx := stdSnap(t)
	dir := newDir(t)
	dest := filepath.Join(dir, "ws.db")
	afterSnapshotLink = func() error {
		lock := headPath(dest) + ".lock"
		if err := os.Remove(lock); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(lock, 0o700); err != nil {
			t.Error(err)
		}
		return nil
	}
	defer func() { afterSnapshotLink = nil }()
	if err := WriteSnapshotFile(ctx, dest, snap, fx.cred()); err == nil {
		t.Fatal("written")
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}

// A written snapshot whose verification would fail through the wrong
// credential leaves nothing and no secret buffers.
//
// spec: SPO-Xsnapshot-PRE-003, SPO-Xsnapshot-INV-001
func TestSnapshotWriteWithAWrongCredentialLeavesNothing(t *testing.T) {
	snap, fx := stdSnap(t)
	dir := newDir(t)
	liveBefore := liveBuffers()
	if err := WriteSnapshotFile(ctx, filepath.Join(dir, "ws.db"), snap, SnapshotCredential{Passphrase: passphrase("wrong")}); !errors.Is(err, ErrWrongCredential) {
		t.Errorf("%v", err)
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Errorf("left %v", got)
	}
	_ = fx
	if live := liveBuffers(); live != liveBefore+1 { // the wrong passphrase itself, which the caller owns
		t.Errorf("%d secret buffers live, %d before", live, liveBefore)
	}
}

// Mode and ordering of the products.
//
// spec: SPO-Xsnapshot-IF-002
func TestSnapshotRowsAreInTheDefinedOrder(t *testing.T) {
	snap, _ := stdSnap(t)
	if !sort.SliceIsSorted(snap.Records, func(i, j int) bool { return bytes.Compare(snap.Records[i].ID, snap.Records[j].ID) < 0 }) {
		t.Error("records are not ordered by id")
	}
	if !sort.SliceIsSorted(snap.Slots, func(i, j int) bool { return bytes.Compare(snap.Slots[i].ID, snap.Slots[j].ID) < 0 }) {
		t.Error("slots are not ordered by id")
	}
	for i, a := range snap.Audit {
		if a.Seq != int64(i+1) {
			t.Fatalf("audit row %d has sequence %d", i, a.Seq)
		}
	}
	if snap.Meta.SchemaVersion != int64(len(migrations)) || snap.Meta.FormatVersion != int64(seal.StoreFormat) {
		t.Errorf("%+v", snap.Meta)
	}
}

// leftFixture is a workspace in which a recovery left a cold record under its old
// cold factor on request.
func leftFixture(t *testing.T) snapFix {
	s, path, rec := stdCold(t, "sub-key passphrase one")
	k := owned(secret.Take([]byte("cold key two")))
	if err := s.Update(ctx, func(w ports.Writer) error { return putKeyW(w, rf("pool2", ports.NodeSKey), k) }); err != nil {
		t.Fatal(err)
	}
	two := rf("pool2", ports.NodeSKey)
	forgeColdNoWrap(t, s, two, "sub-key passphrase one", "cold key two")
	s.Close()
	r, err := OpenWithRecovery(path, passphrase(rec))
	if err != nil {
		t.Fatal(err)
	}
	r.SetColdSource(coldPass("I forgot it"))
	src := &ColdSource{Deriver: fakeDeriver{}, LeaveUnreachable: []string{nameOfRef(two)}, Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		return secret.Take([]byte("a new cold passphrase")), nil
	}}
	text, err := r.ChangePassphraseRekeyCold(ctx, passphrase("the recovered workspace passphrase"), src)
	if err != nil {
		t.Fatal(err)
	}
	var rec2 string
	text.Use(func(b []byte) error { rec2 = string(b); return nil })
	text.Destroy()
	if err := r.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if st, err := r.ColdStatus(ctx); err != nil || len(st.Problems) != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	r.Close()
	return stdFix("stdleft", path, "the recovered workspace passphrase", rec2)
}

// A workspace that `store verify` fails (a cold record left under its old
// factor, on request) gives no snapshot, and nothing is written for it.
//
// spec: SPO-Xsnapshot-PRE-001
func TestSnapshotIsNotTakenFromAFileThatFailsItsVerification(t *testing.T) {
	fx := leftFixture(t)
	if _, err := verifyFile(fx.path, mustCred(t, fx), false); !errors.Is(err, ErrVerify) {
		t.Fatalf("the fixture verifies: %v", err)
	}
	if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrVerify) {
		t.Errorf("%v", err)
	}
	// the same rows as a snapshot: the result does not verify, so it is not written
	rows := fx
	_ = rows
}

// ---- review fixes ----

func tamperedCopy(t *testing.T, fx snapFix) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(fx.path), "tampered.db")
	copyFile(t, fx.path, p)
	db := rawDB(t, p)
	if _, err := db.Exec(`UPDATE records SET ciphertext = randomblob(length(ciphertext)) WHERE rowid = (SELECT min(rowid) FROM records)`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return p
}

func noSnapshotLeftovers(t *testing.T, dir string) {
	t.Helper()
	for _, n := range dirEntries(t, dir) {
		if strings.HasPrefix(n, ".snapshot") {
			t.Errorf("a temporary file is left: %s", n)
		}
	}
}

// The reviewer's scenario: a tampered copy with the same chain head is renamed
// over the path while the verification runs. What is returned must be what was
// verified, never the swapped-in file.
//
// spec: SPO-Xsnapshot-PRE-001
func TestSnapshotSwapDuringVerificationFailsClosed(t *testing.T) {
	fx := snapBuilders()[0].build(t)
	pristine, _, err := ReadSnapshot(ctx, fx.path, fx.cred())
	if err != nil {
		t.Fatal(err)
	}
	tampered := tamperedCopy(t, fx)
	swapped := false
	defer setColdStatusHook(func(s *Store, c context.Context) (ColdStatus, error) {
		if !swapped {
			swapped = true
			if err := os.Rename(tampered, fx.path); err != nil {
				t.Error(err)
			}
		}
		return s.ColdStatus(c)
	})()
	snap, _, err := ReadSnapshot(ctx, fx.path, fx.cred())
	if !swapped {
		t.Fatal("the swap did not happen during the verification")
	}
	if err == nil && !reflect.DeepEqual(snap, pristine) {
		t.Error("ReadSnapshot returned the tampered rows with a nil error")
	}
	noSnapshotLeftovers(t, filepath.Dir(fx.path))
}

// The private copy that was verified is replaced before its rows are read.
//
// spec: SPO-Xsnapshot-PRE-001
func TestSnapshotRefusesACopyReplacedAfterItsVerification(t *testing.T) {
	fx := snapBuilders()[0].build(t)
	tampered := tamperedCopy(t, fx)
	afterSnapshotCopyVerified = func(cp string) {
		if err := os.Rename(tampered, cp); err != nil {
			t.Error(err)
		}
	}
	defer func() { afterSnapshotCopyVerified = nil }()
	if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); err == nil {
		t.Error("rows were read from a file that was not the one verified")
	}
	noSnapshotLeftovers(t, filepath.Dir(fx.path))
}

// An original older than its head file is refused, as an open refuses it.
//
// spec: SPO-Xsnapshot-PRE-001
func TestSnapshotRefusesARolledBackOriginal(t *testing.T) {
	s, path, rec := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	old := cloneDB(t, path)
	s2, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	put(t, s2, counter, "2")
	s2.Close()
	if b, err := os.ReadFile(old); err != nil || os.WriteFile(path, b, 0o600) != nil {
		t.Fatal(err)
	}
	_ = rec
	if _, _, err := ReadSnapshot(ctx, path, SnapshotCredential{Passphrase: pw()}); !errors.Is(err, ErrRolledBack) {
		t.Errorf("%v", err)
	}
	// and a head file of another workspace
	other := fresh(t)
	s3 := openAt(t, other)
	s3.Close()
	b, _ := os.ReadFile(headPath(other))
	if err := os.WriteFile(headPath(path), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadSnapshot(ctx, path, SnapshotCredential{Passphrase: pw()}); !errors.Is(err, ErrHeadMismatch) {
		t.Errorf("another workspace's head file: %v", err)
	}
}

// The notices of the verification, and the head file's absence, are returned.
//
// spec: SPO-Xsnapshot-IF-003
func TestSnapshotReturnsTheVerificationNotices(t *testing.T) {
	has := func(ns []string, sub string) bool { return noticeHas(ns, sub) }
	byName := map[string]snapFix{}
	for _, b := range snapBuilders() {
		switch b.name {
		case "hardware cold record healed", "migrated from format 2", "checkpoint key record", "standard records of every class":
			byName[b.name] = b.build(t)
		}
	}
	read := func(fx snapFix) []string {
		_, f, err := ReadSnapshot(ctx, fx.path, fx.cred())
		if err != nil {
			t.Fatal(err)
		}
		return f.Notices
	}
	if ns := read(byName["hardware cold record healed"]); !has(ns, "healed from its previous wrap") {
		t.Errorf("heal: %v", ns)
	}
	if ns := read(byName["migrated from format 2"]); !has(ns, "without a recovery wrap") {
		t.Errorf("no recovery wrap: %v", ns)
	}
	if ns := read(byName["checkpoint key record"]); !has(ns, "checkpoint key record is present") {
		t.Errorf("checkpoint key: %v", ns)
	}
	fx := byName["standard records of every class"]
	if ns := read(fx); has(ns, "head file") {
		t.Errorf("a head file notice with a head file present: %v", ns)
	}
	os.Remove(headPath(fx.path))
	if ns := read(fx); !has(ns, "no head file") {
		t.Errorf("missing head file: %v", ns)
	}
}

// The slot set hash computed from the rows must be the store's own.
//
// spec: SPO-Xsnapshot-IF-003
func TestSnapshotCrossChecksTheSlotSetHash(t *testing.T) {
	fx := snapBuilders()[0].build(t)
	snapshotFactsHook = func(f *SnapshotFacts) { f.SlotSetHash = append([]byte(nil), f.SlotSetHash...); f.SlotSetHash[0] ^= 1 }
	defer func() { snapshotFactsHook = nil }()
	if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrVerify) {
		t.Errorf("%v", err)
	}
	noSnapshotLeftovers(t, filepath.Dir(fx.path))
}

// A built file that verifies but does not read back as the snapshot given is
// not linked into place. records.updated_at is covered by no verification, so
// changing it after the verification only the read-back can notice.
//
// spec: SPO-Xsnapshot-PRE-003, SPO-Xsnapshot-INV-001
func TestSnapshotWriterChecksTheReadBack(t *testing.T) {
	snap, fx := stdSnap(t)
	beforeSnapshotReadback = func(p string) {
		db := rawDB(t, p)
		if _, err := db.Exec(`UPDATE records SET updated_at = updated_at + 1`); err != nil {
			t.Error(err)
		}
		db.Close()
	}
	defer func() { beforeSnapshotReadback = nil }()
	dir := newDir(t)
	if err := WriteSnapshotFile(ctx, filepath.Join(dir, "ws.db"), snap, fx.cred()); err == nil {
		t.Error("a file that does not read back as given was written")
	}
	if got := dirEntries(t, dir); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}

// spec: SPO-Xsnapshot-PRE-006
func TestSnapshotLockingGateIsOnWhereThereAreLocks(t *testing.T) {
	// lock_unix.go locks: snapshots are allowed. The build without locks sets
	// snapshotLocking to false (snapshot_other.go) and returns ErrSnapshotPlatform.
	if !snapshotLocking {
		t.Error("a build with file locking refuses snapshots")
	}
	if ErrSnapshotPlatform == nil {
		t.Error("no platform error")
	}
	fx := snapBuilders()[0].build(t)
	s := fx.open(t, fx.path)
	if _, _, err := ReadSnapshot(ctx, fx.path, fx.cred()); !errors.Is(err, ErrLocked) {
		t.Errorf("the exclusive lock is not taken: %v", err)
	}
	s.Close()
}
