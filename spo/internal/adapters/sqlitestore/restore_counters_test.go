package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// cstate is the counters of one pool: the opcert issue counter (the number the
// next certificate takes) and the two KES counters (the newest key and the
// number the next key must have).
type cstate struct {
	issue    uint64
	kesCur   int
	kesNext  int
	noKesCur bool
}

func coldKeyOf(name string) [32]byte {
	var k [32]byte
	copy(k[:], name)
	k[31] = 0x42
	return k
}

func putCounters(t *testing.T, s *Store, name string, c cstate) {
	t.Helper()
	err := s.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(rf(name, ports.NodeCounter), pool.IssueCounter{Next: c.issue, ColdVKey: coldKeyOf(name)}.Envelope()); err != nil {
			return err
		}
		if !c.noKesCur {
			if err := w.Put(rf(name, ports.KesCounter), pool.FormatCounter(c.kesCur)); err != nil {
				return err
			}
		}
		return w.Put(rf(name, ports.KesCounterNext), pool.FormatCounter(c.kesNext))
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readC(t *testing.T, s *Store, name string) (c cstate, found bool) {
	t.Helper()
	err := s.View(ctx, func(r ports.Reader) error {
		b, err := r.Get(rf(name, ports.NodeCounter))
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		ic, err := pool.ParseIssueCounter(b)
		if err != nil {
			return err
		}
		c.issue = ic.Next
		if b, err := r.Get(rf(name, ports.KesCounter)); err == nil {
			c.kesCur, _ = pool.ParseCounter(b)
		} else {
			c.noKesCur = true
		}
		if b, err := r.Get(rf(name, ports.KesCounterNext)); err == nil {
			c.kesNext, _ = pool.ParseCounter(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return
}

// crig makes a workspace holding backupState for the pools, backs it up, then
// moves the workspace on to liveState. It returns the path and the backup.
func crig(t *testing.T, backupState, liveState map[string]cstate) (path, backup string) {
	t.Helper()
	s, path, _ := scratch(t)
	for n, c := range backupState {
		putCounters(t, s, n, c)
	}
	backup = filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	for n, c := range liveState {
		putCounters(t, s, n, c)
	}
	s.Close()
	return path, backup
}

func restoreOlder(t *testing.T, backup, path string, o RestoreOptions) error {
	t.Helper()
	o.Overwrite, o.AllowOlder = true, true
	return RestoreWithOptions(backup, path, pw(), o)
}

func openPlain(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func noRestoreLeftovers(t *testing.T, path string) {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".restore-*"))
	if len(m) != 0 {
		t.Errorf("leftover files: %v", m)
	}
}

// A restore of an older backup never lowers a counter of the workspace it
// replaces: for each, the larger value is carried into the restored file by an
// audited write, or the restore refuses.
//
// spec: SPO-Xbackup-PRE-011
func TestRestoreCarriesTheLargerCounters(t *testing.T) {
	cases := []struct {
		name         string
		backup, live cstate
		wantIssue    uint64
		wantKesCur   int
		wantKesNext  int
		carried      int
	}{
		{"live higher on the issue counter only", cstate{issue: 3, kesCur: 2, kesNext: 3}, cstate{issue: 7, kesCur: 2, kesNext: 3}, 7, 2, 3, 1},
		{"live higher on KES only", cstate{issue: 3, kesCur: 2, kesNext: 3}, cstate{issue: 3, kesCur: 4, kesNext: 6}, 3, 2, 6, 1},
		{"live higher on both", cstate{issue: 3, kesCur: 2, kesNext: 3}, cstate{issue: 9, kesCur: 5, kesNext: 8}, 9, 2, 8, 2},
		{"equal", cstate{issue: 3, kesCur: 2, kesNext: 3}, cstate{issue: 3, kesCur: 2, kesNext: 3}, 3, 2, 3, 0},
		{"backup higher", cstate{issue: 9, kesCur: 5, kesNext: 8}, cstate{issue: 3, kesCur: 2, kesNext: 3}, 9, 5, 8, 0},
	}
	for _, c := range cases {
		path, backup := crig(t, map[string]cstate{"poolA": c.backup}, map[string]cstate{"poolA": c.live})
		// the equal case still needs a head the backup lacks: one more write
		s := openPlain(t, path)
		put(t, s, rf("other", ports.AddrFile), "x")
		s.Close()
		var rep RestoreReport
		if err := restoreOlder(t, backup, path, RestoreOptions{Report: &rep}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, found := readC(t, openPlain(t, path), "poolA")
		if !found || got.issue != c.wantIssue || got.kesCur != c.wantKesCur || got.kesNext != c.wantKesNext {
			t.Errorf("%s: restored %+v, want issue %d, kes %d/%d", c.name, got, c.wantIssue, c.wantKesCur, c.wantKesNext)
		}
		if len(rep.Carried) != c.carried {
			t.Errorf("%s: report %+v", c.name, rep.Carried)
		}
		if c.carried > 0 && !auditHas(t, openPlain(t, path), "counter-carried") {
			t.Errorf("%s: no audit event", c.name)
		}
		if c.carried == 0 && auditHas(t, openPlain(t, path), "counter-carried") {
			t.Errorf("%s: an audit event without a carry", c.name)
		}
		// the installed file verifies and its head is what the head file records
		if _, err := VerifyFileDetailed(path, pw()); err != nil {
			t.Errorf("%s: the restored file does not verify: %v", c.name, err)
		}
		noRestoreLeftovers(t, path)
	}
}

// Each pool is compared on its own; a pool that exists only in the replaced
// workspace has its counter carried too.
//
// spec: SPO-Xbackup-PRE-011
func TestRestoreCountersAreCarriedPerPool(t *testing.T) {
	path, backup := crig(t,
		map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}, "poolB": {issue: 10, kesCur: 4, kesNext: 5}},
		map[string]cstate{"poolA": {issue: 8, kesCur: 1, kesNext: 2}, "poolB": {issue: 10, kesCur: 4, kesNext: 5}, "poolC": {issue: 5, kesCur: 0, kesNext: 1}})
	var rep RestoreReport
	if err := restoreOlder(t, backup, path, RestoreOptions{Report: &rep}); err != nil {
		t.Fatal(err)
	}
	s := openPlain(t, path)
	a, _ := readC(t, s, "poolA")
	b, _ := readC(t, s, "poolB")
	c, foundC := readC(t, s, "poolC")
	if a.issue != 8 || b.issue != 10 || !foundC || c.issue != 5 {
		t.Fatalf("A %+v B %+v C %+v (found %v)", a, b, c, foundC)
	}
	if len(rep.Carried) != 3 { // A's issue counter; C's issue counter and KES next
		t.Fatalf("carried: %+v", rep.Carried)
	}
	var pools = map[string]bool{}
	for _, cc := range rep.Carried {
		pools[cc.Pool] = true
	}
	if len(pools) != 2 {
		t.Fatalf("pools carried: %v", pools)
	}
}

// A backup that contains the destination's head cannot lower anything: no
// counter is touched and nothing is carried.
//
// spec: SPO-Xbackup-PRE-011
func TestRestoreOfANewerBackupCarriesNothing(t *testing.T) {
	s, path, _ := scratch(t)
	putCounters(t, s, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	putCounters(t, s, "poolA", cstate{issue: 5, kesCur: 1, kesNext: 2})
	backup := filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	s.Close()
	var rep RestoreReport
	if err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if len(rep.Carried) != 0 {
		t.Fatalf("%+v", rep.Carried)
	}
	if got, _ := readC(t, openPlain(t, path), "poolA"); got.issue != 5 {
		t.Fatalf("%+v", got)
	}
}

// The destination whose credentials changed since the backup is opened with its
// own recovery material, or the restore refuses without printing any value.
//
// spec: SPO-Xbackup-PRE-012
func TestRestoreDestinationOpensWithADifferentCredential(t *testing.T) {
	s, path, rec := scratchPresented(t)
	putCounters(t, s, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	backup := filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	putCounters(t, s, "poolA", cstate{issue: 11, kesCur: 1, kesNext: 2})
	newRec, err := s.ChangePassphraseRekey(ctx, passphrase("a passphrase set after the backup"))
	if err != nil {
		t.Fatal(err)
	}
	var newText string
	newRec.Use(func(b []byte) error { newText = string(b); return nil })
	s.Close()
	_ = rec
	before, _ := os.ReadFile(path)
	// the backup's passphrase does not open the destination
	err = restoreOlder(t, backup, path, RestoreOptions{})
	if !errors.Is(err, ErrCountersNeedCredential) {
		t.Fatalf("%v", err)
	}
	for _, v := range []string{"11", "3"} {
		if strings.Contains(strings.NewReplacer("counter", "", "(", "", ")", "").Replace(err.Error()), " "+v+" ") {
			t.Errorf("the refusal shows a counter value: %v", err)
		}
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("the destination changed")
	}
	noRestoreLeftovers(t, path)
	// with the destination's own recovery key
	var rep RestoreReport
	if err := restoreOlder(t, backup, path, RestoreOptions{Report: &rep, CurrentRecovery: &FactorInputs{Recovery: recoveryRaw(t, newText)}}); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if got, _ := readC(t, st, "poolA"); got.issue != 11 {
		t.Fatalf("%+v", got)
	}
	if len(rep.Carried) != 1 {
		t.Fatalf("%+v", rep)
	}
}

// A destination that cannot be opened at all: the restore refuses, naming the
// risk; --accept-lower-counters proceeds with a warning and an audit event.
//
// spec: SPO-Xbackup-PRE-013
func TestRestoreOverADamagedDestination(t *testing.T) {
	path, backup := crig(t, map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}}, map[string]cstate{"poolA": {issue: 9, kesCur: 1, kesNext: 2}})
	if err := os.WriteFile(path, []byte("this is not a workspace"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(headPath(path))
	err := restoreOlder(t, backup, path, RestoreOptions{AllowOtherWorkspace: true, AllowWeakerPolicy: true})
	if !errors.Is(err, ErrCountersUnknown) || !strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("%v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "this is not a workspace" {
		t.Fatal("the destination changed")
	}
	noRestoreLeftovers(t, path)
	var rep RestoreReport
	if err := restoreOlder(t, backup, path, RestoreOptions{AllowOtherWorkspace: true, AllowWeakerPolicy: true, AcceptLowerCounters: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if !rep.LowerAccepted {
		t.Fatalf("%+v", rep)
	}
	s := openPlain(t, path)
	if got, _ := readC(t, s, "poolA"); got.issue != 3 {
		t.Fatalf("%+v", got)
	}
	if !auditHas(t, s, "counters-not-carried") {
		t.Fatal("no audit event in the restored copy")
	}
}

// --accept-lower-counters never applies when the destination can be opened: the
// counters are carried whatever it says.
//
// spec: SPO-Xbackup-PRE-013
func TestAcceptLowerCountersDoesNotApplyToAnOpenableDestination(t *testing.T) {
	path, backup := crig(t, map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}}, map[string]cstate{"poolA": {issue: 9, kesCur: 1, kesNext: 2}})
	var rep RestoreReport
	if err := restoreOlder(t, backup, path, RestoreOptions{AcceptLowerCounters: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if rep.LowerAccepted || len(rep.Carried) != 1 {
		t.Fatalf("%+v", rep)
	}
	if got, _ := readC(t, openPlain(t, path), "poolA"); got.issue != 9 {
		t.Fatalf("%+v", got)
	}
}

// A crash between the carry and the swap leaves the destination as it was.
//
// spec: SPO-Xbackup-PRE-014
func TestCrashAfterTheCarryLeavesTheDestinationUntouched(t *testing.T) {
	path, backup := crig(t, map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}}, map[string]cstate{"poolA": {issue: 9, kesCur: 1, kesNext: 2}})
	before, _ := os.ReadFile(path)
	headBefore, _ := os.ReadFile(headPath(path))
	afterCarry = func() error { return errors.New("simulated crash after the carry") }
	err := restoreOlder(t, backup, path, RestoreOptions{})
	afterCarry = nil
	if err == nil {
		t.Fatal("the crash did not stop the restore")
	}
	after, _ := os.ReadFile(path)
	headAfter, _ := os.ReadFile(headPath(path))
	if !bytes.Equal(before, after) || !bytes.Equal(headBefore, headAfter) {
		t.Fatal("the destination or its head file changed")
	}
	noRestoreLeftovers(t, path)
	if _, err := os.Stat(sidecarPath(path)); err == nil {
		t.Fatal("a sidecar was left")
	}
	if got, _ := readC(t, openPlain(t, path), "poolA"); got.issue != 9 {
		t.Fatalf("%+v", got)
	}
}

var _ = context.Background

// The counter rule under the hardware policy: the destination is opened
// read-only through the same daily authenticator that verifies the backup.
//
// spec: SPO-Xbackup-PRE-011, SPO-Xbackup-PRE-012
func TestCounterRuleThroughFactors(t *testing.T) {
	path, f, _ := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	putCounters(t, s, "poolA", cstate{issue: 2, kesCur: 1, kesNext: 2})
	bk := filepath.Join(t.TempDir(), "hw.bak")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	putCounters(t, s, "poolA", cstate{issue: 6, kesCur: 3, kesNext: 4})
	s.Close()
	var rep RestoreReport
	if err := RestoreWithFactors(bk, path, f.inputs("devA", "1234"), RestoreOptions{Overwrite: true, AllowOlder: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if len(rep.Carried) != 2 {
		t.Fatalf("%+v", rep)
	}
	r, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if got, _ := readC(t, r, "poolA"); got.issue != 6 || got.kesNext != 4 || got.kesCur != 1 {
		t.Fatalf("%+v", got)
	}
	// a wrong PIN is not "the destination cannot be opened": it is refused as it is
	if err := RestoreWithFactors(bk, path, f.inputs("devA", "0000"), RestoreOptions{Overwrite: true, AllowOlder: true, AcceptLowerCounters: true}); err == nil {
		t.Fatal("a wrong PIN restored")
	}
}

func putKes(t *testing.T, s *Store, name string, n int) {
	t.Helper()
	put(t, s, rf(name, ports.KesVKey, n), "kes-vkey-"+strings.Repeat("x", n+1))
}

func cloneWS(t *testing.T, path string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "clone.db")
	for _, suf := range []string{"", ".head"} {
		b, err := os.ReadFile(path + suf)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst+suf, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// B2: even when the backup contains the destination's head, the destination's
// head is rechecked under the lock: a certificate issued between the check and
// the lock is not overwritten.
//
// spec: SPO-Xbackup-PRE-014
func TestRestoreRechecksTheDestinationHeadEvenForABackupThatContainsIt(t *testing.T) {
	s, path, _ := scratch(t)
	putCounters(t, s, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	backup := filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	s.Close()
	afterPolicyCheck = func() {
		afterPolicyCheck = nil
		w, err := Open(path, pw())
		if err != nil {
			t.Error(err)
			return
		}
		putCounters(t, w, "poolA", cstate{issue: 9, kesCur: 1, kesNext: 2}) // a certificate issued meanwhile
		w.Close()
	}
	defer func() { afterPolicyCheck = nil }()
	err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true})
	if !errors.Is(err, ErrConflictRestore) {
		t.Fatalf("%v", err)
	}
	if got, _ := readC(t, openPlain(t, path), "poolA"); got.issue != 9 {
		t.Fatalf("the concurrent issue was overwritten: %+v", got)
	}
}

// B2b: a chain that contains the destination's head can still hold a lower
// counter (`pool opcert issue --counter N` writes N+1 whatever was stored, and an
// import can replace a record), so a newer backup is compared too.
//
// spec: SPO-Xbackup-PRE-011
func TestANewerBackupWithALowerCounterStillCannotLowerIt(t *testing.T) {
	s, path, _ := scratch(t)
	putCounters(t, s, "poolA", cstate{issue: 9, kesCur: 1, kesNext: 2})
	s.Close()
	dest := cloneWS(t, path) // the destination: the state with issue 9
	s = openPlain(t, path)
	putCounters(t, s, "poolA", cstate{issue: 4, kesCur: 1, kesNext: 2}) // lowered later in the same chain
	backup := filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	s.Close()
	var rep RestoreReport
	if err := RestoreWithOptions(backup, dest, pw(), RestoreOptions{Overwrite: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readC(t, openPlain(t, dest), "poolA"); got.issue != 9 || len(rep.Carried) != 1 {
		t.Fatalf("restored %+v, report %+v", got, rep)
	}
}

// S1: the same pool can be in two workspaces (its anchor is its pool id), so the
// counter is compared whatever the workspace id.
//
// spec: SPO-Xbackup-PRE-011
func TestCounterRuleAppliesToAnotherWorkspaceWithTheSamePool(t *testing.T) {
	a, _, _ := scratch(t)
	putCounters(t, a, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	backup := filepath.Join(t.TempDir(), "other.bak")
	if err := a.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b, pathB, _ := scratch(t)
	putCounters(t, b, "poolA", cstate{issue: 9, kesCur: 1, kesNext: 2})
	b.Close()
	var rep RestoreReport
	if err := RestoreWithOptions(backup, pathB, pw(), RestoreOptions{Overwrite: true, AllowOtherWorkspace: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readC(t, openPlain(t, pathB), "poolA"); got.issue != 9 || len(rep.Carried) != 1 {
		t.Fatalf("restored %+v, report %+v", got, rep)
	}
}

// S2: a KES key generated and not yet used for a certificate (current == next)
// is not in an older backup; the restored workspace must not generate the same
// number again.
//
// spec: SPO-Xbackup-PRE-011
func TestCarryMovesTheKesNumberPastAWaitingKey(t *testing.T) {
	s, path, _ := scratch(t)
	putCounters(t, s, "poolA", cstate{issue: 1, kesCur: 0, kesNext: 1})
	putKes(t, s, "poolA", 0)
	backup := filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	putKes(t, s, "poolA", 1)
	putCounters(t, s, "poolA", cstate{issue: 1, kesCur: 1, kesNext: 1}) // key 1 generated, waiting
	s.Close()
	if err := restoreOlder(t, backup, path, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	got, _ := readC(t, openPlain(t, path), "poolA")
	if got.kesNext != 2 || got.kesCur != 0 {
		t.Fatalf("restored kes %d/%d: the next key would reuse number %d", got.kesCur, got.kesNext, got.kesNext)
	}
	// a waiting key that the backup holds too is not moved
	s2, path2, _ := scratch(t)
	putCounters(t, s2, "poolB", cstate{issue: 0, kesCur: 3, kesNext: 3})
	putKes(t, s2, "poolB", 3)
	bk2 := filepath.Join(t.TempDir(), "b2.bak")
	s2.Backup(ctx, bk2)
	put(t, s2, rf("other", ports.AddrFile), "x")
	s2.Close()
	if err := restoreOlder(t, bk2, path2, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readC(t, openPlain(t, path2), "poolB"); got.kesCur != 3 || got.kesNext != 3 {
		t.Fatalf("a waiting key present in the backup was moved: %+v", got)
	}
}

// S3: only structural damage is "damaged". A destination that cannot be opened
// for another reason (here its file mode) is returned as it is and
// --accept-lower-counters never satisfies it.
//
// spec: SPO-Xbackup-PRE-013
func TestOnlyStructuralDamageSatisfiesTheFlag(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a file mode does not stop root")
	}
	path, backup := crig(t, map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}}, map[string]cstate{"poolA": {issue: 9, kesCur: 1, kesNext: 2}})
	before, _ := os.ReadFile(path)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0o600)
	err := restoreOlder(t, backup, path, RestoreOptions{AcceptLowerCounters: true})
	if err == nil {
		t.Fatal("an unreadable but intact workspace was replaced under --accept-lower-counters")
	}
	if errors.Is(err, ErrCountersUnknown) {
		t.Fatalf("a permission error was treated as damage: %v", err)
	}
	os.Chmod(path, 0o600)
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("the destination changed")
	}
}

// S4: a destination of the same workspace that is damaged inside (a record fails
// its verification) is the damaged case: it refuses, naming the flag, and the flag
// goes on with an audit event.
//
// spec: SPO-Xbackup-PRE-013
func TestSameWorkspaceDamagedDestination(t *testing.T) {
	path, backup := crig(t, map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}}, map[string]cstate{"poolA": {issue: 9, kesCur: 1, kesNext: 2}})
	db := rawDB(t, path)
	if _, err := db.Exec(`UPDATE records SET ciphertext = zeroblob(length(ciphertext)) WHERE kind = 'node.counter'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	err := restoreOlder(t, backup, path, RestoreOptions{})
	if !errors.Is(err, ErrCountersUnknown) || !strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("%v", err)
	}
	var rep RestoreReport
	if err := restoreOlder(t, backup, path, RestoreOptions{AcceptLowerCounters: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if !rep.LowerAccepted || !auditHas(t, openPlain(t, path), "counters-not-carried") {
		t.Fatalf("%+v", rep)
	}
}

// A refusal for a credential problem never names or honours the flag.
//
// spec: SPO-Xbackup-PRE-012
func TestACredentialProblemNeverSuggestsOrHonoursTheFlag(t *testing.T) {
	s, path, _ := scratchPresented(t)
	putCounters(t, s, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	backup := filepath.Join(t.TempDir(), "b.bak")
	s.Backup(ctx, backup)
	putCounters(t, s, "poolA", cstate{issue: 11, kesCur: 1, kesNext: 2})
	if _, err := s.ChangePassphraseRekey(ctx, passphrase("changed after the backup")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	before, _ := os.ReadFile(path)
	for _, accept := range []bool{false, true} {
		err := restoreOlder(t, backup, path, RestoreOptions{AcceptLowerCounters: accept})
		if err == nil || errors.Is(err, ErrCountersUnknown) || strings.Contains(err.Error(), "--accept-lower-counters") || !strings.Contains(err.Error(), "--recovery-key-in-fd") {
			t.Fatalf("accept=%v: %v", accept, err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatal("the destination changed")
		}
	}
}

// S5(a): a destination older than its head file: the counters of the state the
// head file records are not in the file, so they cannot be compared: damaged.
//
// spec: SPO-Xbackup-PRE-013
func TestRolledBackDestinationCountersAreUnknown(t *testing.T) {
	s, path, _ := scratch(t)
	putCounters(t, s, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	s.Close()
	old := cloneWS(t, path)
	oldBytes, _ := os.ReadFile(old)
	s = openPlain(t, path)
	backup := filepath.Join(t.TempDir(), "b.bak")
	s.Backup(ctx, backup)
	putCounters(t, s, "poolA", cstate{issue: 9, kesCur: 1, kesNext: 2})
	s.Close()
	// the file goes back to the older state; the head file still records the newer
	if err := os.WriteFile(path, oldBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(path + "-wal")
	os.Remove(path + "-shm")
	err := restoreOlder(t, backup, path, RestoreOptions{})
	if !errors.Is(err, ErrCountersUnknown) || !strings.Contains(err.Error(), "older than its head file") {
		t.Fatalf("%v", err)
	}
	var rep RestoreReport
	if err := restoreOlder(t, backup, path, RestoreOptions{AcceptLowerCounters: true, Report: &rep}); err != nil || !rep.LowerAccepted {
		t.Fatalf("%v %+v", err, rep)
	}
}

// A restore that died past the swap leaves a sidecar; the file's counters are
// the carried ones, and a re-run without any flag completes it.
//
// spec: SPO-Xbackup-PRE-009
func TestRerunAfterACrashedRestoreNeedsNoFlag(t *testing.T) {
	path, backup := crig(t, map[string]cstate{"poolA": {issue: 3, kesCur: 1, kesNext: 2}}, map[string]cstate{"poolA": {issue: 9, kesCur: 1, kesNext: 2}})
	crashingRestore(t, backup, path, RestoreOptions{Overwrite: true, AllowOlder: true})
	if err := restoreOlder(t, backup, path, RestoreOptions{}); err != nil {
		t.Fatalf("the re-run: %v", err)
	}
	if got, _ := readC(t, openPlain(t, path), "poolA"); got.issue != 9 {
		t.Fatalf("%+v", got)
	}
}

// S5(b): the carry writes through the private copy opened with the credential
// presented for the backup; through the recovery key (the store API; no command
// reaches it) that is a write through a recovery-unlocked handle. The store has
// no guard that forbids ordinary writes through such a handle: the ADR 0011
// restriction is a restriction of which commands accept the recovery unlock.
//
// spec: SPO-Xbackup-PRE-011
func TestCarryThroughARecoveryUnlockedCopy(t *testing.T) {
	s, path, rec := scratch(t)
	putCounters(t, s, "poolA", cstate{issue: 3, kesCur: 1, kesNext: 2})
	backup := filepath.Join(t.TempDir(), "b.bak")
	s.Backup(ctx, backup)
	putCounters(t, s, "poolA", cstate{issue: 9, kesCur: 1, kesNext: 2})
	s.Close()
	var rep RestoreReport
	if err := RestoreWithRecoveryOptions(backup, path, secret.Take([]byte(rec)), RestoreOptions{Overwrite: true, AllowOlder: true, Report: &rep}); err != nil {
		t.Fatal(err)
	}
	if got, _ := readC(t, openPlain(t, path), "poolA"); got.issue != 9 || len(rep.Carried) != 1 {
		t.Fatalf("%+v %+v", got, rep)
	}
}

// S4: the destination's factor fails after the backup verified: not "cannot be
// opened", and never the flag's business.
//
// spec: SPO-Xbackup-PRE-012
func TestADestinationFactorThatFailsIsReturnedAsItIs(t *testing.T) {
	path, f, _ := hardwareWS(t)
	s, err := openHW(path, f, "devA", "1234")
	if err != nil {
		t.Fatal(err)
	}
	putCounters(t, s, "poolA", cstate{issue: 2, kesCur: 1, kesNext: 2})
	bk := filepath.Join(t.TempDir(), "hw.bak")
	s.Backup(ctx, bk)
	putCounters(t, s, "poolA", cstate{issue: 6, kesCur: 1, kesNext: 2})
	s.Close()
	// how many assertions does verifying the backup take? a restore into a fresh file
	before := f.asserts
	if err := RestoreWithFactors(bk, filepath.Join(t.TempDir(), "fresh.db"), f.inputs("devA", "1234"), RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	verifyAsserts := f.asserts - before
	b := &budgetSource{FactorSource: f, left: verifyAsserts}
	in := FactorInputs{Source: b, Device: "devA", PIN: pinOf("1234")}
	err = RestoreWithFactors(bk, path, in, RestoreOptions{Overwrite: true, AllowOlder: true, AcceptLowerCounters: true})
	if !errors.Is(err, ports.ErrFactorTimeout) {
		t.Fatalf("the destination's factor failure was not returned as it is: %v", err)
	}
	if got, _ := readC(t, func() *Store { r, _ := openHW(path, f, "devA", "1234"); t.Cleanup(func() { r.Close() }); return r }(), "poolA"); got.issue != 6 {
		t.Fatalf("the destination changed: %+v", got)
	}
}

// budgetSource lets the first `left` assertions through, then answers that the
// authenticator was not touched in time.
type budgetSource struct {
	ports.FactorSource
	left int
}

func (b *budgetSource) Assert(ctx context.Context, req ports.AssertRequest) (ports.Assertion, error) {
	if b.left <= 0 {
		return ports.Assertion{}, ports.ErrFactorTimeout
	}
	b.left--
	return b.FactorSource.Assert(ctx, req)
}
