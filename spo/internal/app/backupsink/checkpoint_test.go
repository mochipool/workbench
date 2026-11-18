package backupsink

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakesk"
)

const skDev, skPIN = "/dev/sk0", "2468"

func pinFn(p string) func(context.Context) (*ports.Secret, error) {
	return func(context.Context) (*ports.Secret, error) { return ports.TakeSecret([]byte(p)) }
}

// ckRig is a sink rig with a checkpoint key on a fake authenticator.
type ckRig struct {
	*rig
	sk     *fakesk.Source
	record checkpoint.KeyRecord
	sign   Signing
	clock  time.Time
}

func newCkRig(t *testing.T, kind ports.SinkKind, policy string) *ckRig {
	t.Helper()
	r := newRig(t, kind, policy)
	sk := fakesk.New(map[string]string{skDev: skPIN})
	p, _ := ports.TakeSecret([]byte(skPIN))
	en, err := sk.EnrolSigner(context.Background(), ports.SignerEnrolRequest{Device: skDev, RPID: checkpoint.Application, PIN: p})
	if err != nil {
		t.Fatal(err)
	}
	rec := checkpoint.KeyRecord{Key: sshsig.Key{Q: en.PublicKey, Application: checkpoint.Application}, CredentialID: en.CredentialID, Enrolled: time.Now().UTC().Truncate(time.Second)}
	c := &ckRig{rig: r, sk: sk, record: rec, clock: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)}
	c.sign = Signing{Record: rec, Source: sk, Device: skDev, PIN: pinFn(skPIN), Now: func() time.Time { return c.clock }}
	r.cp = &CheckpointPush{Writer: r.sink, Reader: r.sink, Signing: c.sign}
	return c
}

// backupAt pushes a fake backup of the given head sequence.
func (c *ckRig) backupAt(seq uint64) (PushResult, error) {
	c.content = fakeFile(wsHex, seq, macHex, fmt.Sprintf("payload-%d", seq))
	c.clock = c.clock.Add(time.Hour)
	return c.push()
}

func (c *ckRig) longPin() checkpoint.LongPin {
	return checkpoint.LongPin{WorkspaceID: mustHex(wsHex), KeyHash: c.record.Hash()}
}

func (c *ckRig) latest(pin checkpoint.LongPin) (LatestResult, []string, error) {
	return c.latestBelow(pin, nil)
}

func (c *ckRig) latestBelow(pin checkpoint.LongPin, below *uint64) (LatestResult, []string, error) {
	c.restored = nil
	var notes []string
	in := LatestInput{
		Reader: c.sink, Ranger: c.ranger(), Lister: c.sink, Scratch: c.scratch, Pin: pin,
		Inspect: inspectFake,
		Facts: func(path string) (Facts, error) {
			id, h, err := inspectFake(path)
			return Facts{WorkspaceID: id, Head: h, SlotTable: HashBytes([]byte("slot table"))}, err
		},
		Restore: func(_, path string, _ []byte) error {
			b, _ := os.ReadFile(path)
			c.restored = append(c.restored, b)
			return c.restore
		},
		Report: func(name, why string) { notes = append(notes, name+": "+why) },
	}
	if below != nil {
		in.Below, in.HasBelow = *below, true
	}
	res, err := FetchLatest(context.Background(), in)
	return res, notes, err
}

func (c *ckRig) objectGets() int {
	n := 0
	for _, g := range c.sink.getLog {
		if strings.HasSuffix(g, ".spo") {
			n++
		}
	}
	return n
}

// A push with a key signs after the object is read back, and puts the checkpoint
// beside it; the checkpoint verifies against the key hash alone.
//
// spec: SPO-Xbackup-OUT-013
func TestPushSignsAfterTheObjectIsVerifiedAndPutsTheCheckpoint(t *testing.T) {
	c := newCkRig(t, ports.SinkS3, "hardware")
	var sawObjectBeforeSigning bool
	c.sk.OnSign = func() {
		// at the moment of the touch the object is already in the sink and was
		// read back (a Get of it happened)
		_, has := c.sink.objs[ObjectName(mustHex(wsHex), 7, mustHex(sum(c.content)))]
		sawObjectBeforeSigning = has && c.objectGets() >= 1
	}
	res, err := c.push()
	if err != nil {
		t.Fatal(err)
	}
	if !sawObjectBeforeSigning {
		t.Error("the authenticator was asked before the object was in the sink and read back")
	}
	if c.sk.Signs != 1 {
		t.Errorf("%d signatures; one PIN and one touch", c.sk.Signs)
	}
	name, _ := CheckpointName(res.Name)
	if strings.HasSuffix(name, ".spo") || !strings.HasSuffix(name, ".checkpoint") || strings.TrimSuffix(name, ".checkpoint")+".spo" != res.Name {
		t.Fatalf("checkpoint name %q for %q", name, res.Name)
	}
	obj, ok := c.sink.objs[name]
	if !ok || c.sink.cpPuts != 1 || res.Checkpoint == nil || res.Checkpoint.Name != name {
		t.Fatalf("no checkpoint put: %v %+v", ok, res.Checkpoint)
	}
	st, err := VerifyObject(obj, res.Name, c.longPin())
	if err != nil {
		t.Fatal(err)
	}
	if st.Seq != 7 || !bytes.Equal(st.SHA256, res.Pin.SHA256) || st.Size != uint64(len(c.content)) || !bytes.Equal(st.HeadMAC, mustHex(macHex)) || !bytes.Equal(st.KeyHash, c.record.Hash()) {
		t.Fatalf("%+v", st)
	}
	if !st.Time.Equal(c.clock) {
		t.Errorf("time %v", st.Time)
	}
	// the stage-1 pin is unchanged
	if res.Pin.String() != pinOf(c.content).String() {
		t.Error("the exact pin changed")
	}
	c.noTemp()
}

// With no checkpoint requested a push is exactly stage 1: no authenticator, no
// second object.
//
// spec: SPO-Xbackup-OUT-013
func TestPushWithoutAKeyIsStageOne(t *testing.T) {
	c := newCkRig(t, ports.SinkS3, "hardware")
	c.rig.cp = nil
	res, err := c.push()
	if err != nil {
		t.Fatal(err)
	}
	if res.Checkpoint != nil || c.sk.Signs != 0 || len(c.sink.objs) != 1 || c.sink.puts != 1 {
		t.Fatalf("%+v signs=%d objects=%d", res.Checkpoint, c.sk.Signs, len(c.sink.objs))
	}
}

// A signing failure after a verified upload is reported as "NOT signed", and a
// re-run signs without uploading again.
//
// spec: SPO-Xbackup-OUT-014
func TestSigningFailureAfterUploadThenRerunSignsWithoutUploading(t *testing.T) {
	c := newCkRig(t, ports.SinkS3, "hardware")
	c.sk.FailSign = ports.ErrFactorTimeout
	res, err := c.push()
	if err == nil || !errors.Is(err, ErrNotSigned) || !strings.Contains(err.Error(), "uploaded and verified, but NOT signed") || !strings.Contains(err.Error(), "does not upload it again") && !strings.Contains(err.Error(), "without uploading") && !strings.Contains(err.Error(), "not upload it again") {
		t.Fatalf("%v", err)
	}
	if !res.Uploaded || res.Name == "" || res.Pin.String() == "" {
		t.Fatalf("the result of a half-done push is not usable: %+v", res)
	}
	if len(c.sink.objs) != 1 || c.sink.puts != 1 || c.sink.cpPuts != 0 {
		t.Fatalf("objects %d puts %d", len(c.sink.objs), c.sink.puts)
	}
	c.sk.FailSign = nil
	signsBefore := c.sk.Signs
	res, err = c.push()
	if err != nil {
		t.Fatal(err)
	}
	if res.Uploaded || c.sink.puts != 2 /* the checkpoint, not the object */ || c.sink.cpPuts != 1 || c.sk.Signs != signsBefore+1 {
		t.Fatalf("uploaded=%v puts=%d cpPuts=%d signs=%d", res.Uploaded, c.sink.puts, c.sink.cpPuts, c.sk.Signs)
	}
	// a third run finds the valid checkpoint: no prompt, no put
	res, err = c.push()
	if err != nil {
		t.Fatal(err)
	}
	if c.sk.Signs != signsBefore+1 || c.sink.puts != 2 || res.Checkpoint == nil || !res.Checkpoint.Existing {
		t.Fatalf("signs=%d puts=%d %+v", c.sk.Signs, c.sink.puts, res.Checkpoint)
	}
}

// A checkpoint already under the name that is not this file's is refused and
// never replaced; a checkpoint put that the sink keeps wrong is noticed.
//
// spec: SPO-Xbackup-OUT-014
func TestPushRefusesAForeignCheckpointUnderTheName(t *testing.T) {
	c := newCkRig(t, ports.SinkS3, "hardware")
	res, err := c.push()
	if err != nil {
		t.Fatal(err)
	}
	name, _ := CheckpointName(res.Name)
	c.sink.objs[name] = []byte("not a checkpoint")
	_, err = c.push()
	if err == nil || !strings.Contains(err.Error(), "does not verify") || !strings.Contains(err.Error(), "never deletes") {
		t.Fatalf("%v", err)
	}
	if string(c.sink.objs[name]) != "not a checkpoint" || c.sk.Signs != 1 {
		t.Error("the foreign object was touched or a prompt was made")
	}
}

// Signing needs a valid answer from the authenticator: a missing flag stops the
// push before anything is put.
//
// spec: SPO-Xbackup-OUT-014
func TestAnAuthenticatorWithoutVerificationFlagPutsNothing(t *testing.T) {
	for name, set := range map[string]func(*fakesk.Source){
		"no presence":     func(s *fakesk.Source) { s.DropUP = true },
		"no verification": func(s *fakesk.Source) { s.DropUV = true },
	} {
		t.Run(name, func(t *testing.T) {
			c := newCkRig(t, ports.SinkS3, "hardware")
			set(c.sk)
			_, err := c.push()
			if err == nil || !errors.Is(err, ErrNotSigned) {
				t.Fatalf("%v", err)
			}
			if c.sink.cpPuts != 0 {
				t.Error("a checkpoint without the flag was put")
			}
		})
	}
}

// The long-lived pin restores the newest valid candidate.
//
// spec: SPO-Xbackup-OUT-015
func TestRestoreWithTheLongLivedPinPicksTheNewestValidBackup(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	for _, seq := range []uint64{3, 5, 9} {
		if _, err := c.backupAt(seq); err != nil {
			t.Fatal(err)
		}
	}
	c.sink.getLog = nil
	res, notes, err := c.latest(c.longPin())
	if err != nil {
		t.Fatalf("%v %v", err, notes)
	}
	if res.Statement.Seq != 9 || len(c.restored) != 1 || !bytes.Contains(c.restored[0], []byte("payload-9")) {
		t.Fatalf("%+v %q", res, c.restored)
	}
	if c.objectGets() != 1 {
		t.Errorf("%d objects downloaded; the newest only", c.objectGets())
	}
	c.noTemp()
}

// A forged newer checkpoint is skipped and its object is never downloaded.
//
// spec: SPO-Xbackup-OUT-015
func TestAForgedNewerCheckpointIsSkippedWithoutDownloadingItsObject(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	for _, seq := range []uint64{3, 5} {
		if _, err := c.backupAt(seq); err != nil {
			t.Fatal(err)
		}
	}
	// the attacker's newer backup, signed by their own key
	evil := newCkRig(t, ports.SinkDir, "hardware")
	forged := fakeFile(wsHex, 9, macHex, "payload-evil")
	evil.content = forged
	res, err := evil.push()
	if err != nil {
		t.Fatal(err)
	}
	for n, b := range evil.sink.objs {
		c.sink.objs[n] = b
	}
	got, notes, err := c.latest(c.longPin())
	if err != nil {
		t.Fatalf("%v %v", err, notes)
	}
	if got.Statement.Seq != 5 || !bytes.Contains(c.restored[0], []byte("payload-5")) {
		t.Fatalf("%+v", got)
	}
	for _, g := range c.sink.getLog {
		if g == res.Name {
			t.Fatal("the object of a forged checkpoint was downloaded")
		}
	}
	found := false
	for _, n := range notes {
		found = found || strings.Contains(n, res.Name) && strings.Contains(n, "refused")
	}
	if !found {
		t.Errorf("the skip was not reported: %v", notes)
	}
	// a candidate with no checkpoint at all is skipped too
	c.sink.objs[ObjectName(mustHex(wsHex), 11, mustHex(sum([]byte("x"))))] = []byte("x")
	if got, _, err := c.latest(c.longPin()); err != nil || got.Statement.Seq != 5 {
		t.Fatalf("%v %+v", err, got)
	}
}

// A pin with a minimum sequence refuses what is below it; with none valid the
// refusal says so.
//
// spec: SPO-Xbackup-OUT-015
func TestRestoreRefusesBelowTheMinimumSequence(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	for _, seq := range []uint64{3, 5} {
		if _, err := c.backupAt(seq); err != nil {
			t.Fatal(err)
		}
	}
	if got, _, err := c.latest(c.longPin().WithMin(5)); err != nil || got.Statement.Seq != 5 {
		t.Fatalf("%v", err)
	}
	c.sink.getLog = nil
	_, _, err := c.latest(c.longPin().WithMin(6))
	if err == nil || !strings.Contains(err.Error(), "no backup of this workspace") || len(c.restored) != 0 {
		t.Fatalf("%v", err)
	}
	if c.objectGets() != 0 {
		t.Error("an object below the minimum was downloaded")
	}
}

// A sink that serves other bytes under a verified checkpoint is refused: the
// verified sequence is a floor, the restore does not fall back to an older backup,
// and says so; an explicit --below chooses the older one knowingly.
//
// spec: SPO-Xbackup-OUT-015
func TestAnObjectThatDiffersFromItsStatementIsRefusedAndSetsAFloor(t *testing.T) {
	for name, mut := range map[string]func(b []byte) []byte{
		"other bytes of the same length": func(b []byte) []byte { b = append([]byte(nil), b...); b[len(b)-1] ^= 1; return b },
		"a longer object":                func(b []byte) []byte { return append(append([]byte(nil), b...), 'x') },
	} {
		t.Run(name, func(t *testing.T) {
			c := newCkRig(t, ports.SinkDir, "hardware")
			var newer PushResult
			for _, seq := range []uint64{4, 8} {
				r, err := c.backupAt(seq)
				if err != nil {
					t.Fatal(err)
				}
				newer = r
			}
			c.sink.objs[newer.Name] = mut(c.sink.objs[newer.Name])
			_, notes, err := c.latest(c.longPin())
			if err == nil || len(c.restored) != 0 || !strings.Contains(err.Error(), "sequence 8") || !strings.Contains(err.Error(), "--below 8") {
				t.Fatalf("an altered object under a verified checkpoint: %v %v restored=%d", err, notes, len(c.restored))
			}
			below := uint64(8)
			got, _, err := c.latestBelow(c.longPin(), &below)
			if err != nil || got.Statement.Seq != 4 || !bytes.Contains(c.restored[0], []byte("payload-4")) {
				t.Fatalf("--below 8: %v %+v", err, got)
			}
			c.noTemp()
		})
	}
	// an unverified (forged) checkpoint sets no floor: the next valid one is used
	c := newCkRig(t, ports.SinkDir, "hardware")
	if _, err := c.backupAt(4); err != nil {
		t.Fatal(err)
	}
	n := ObjectName(mustHex(wsHex), 9, mustHex(sum([]byte("z"))))
	c.sink.objs[n] = []byte("z")
	cp, _ := CheckpointName(n)
	c.sink.objs[cp] = []byte("forged")
	if got, _, err := c.latest(c.longPin()); err != nil || got.Statement.Seq != 4 {
		t.Fatalf("a forged checkpoint set a floor: %v", err)
	}
}

// Candidates with no checkpoint do not use up the candidate limit: a sink that
// lists many bare newer names cannot hide a valid backup.
//
// spec: SPO-Xbackup-SEC-018
func TestBareNewerNamesDoNotHideAValidBackup(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	if _, err := c.backupAt(5); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxCandidates+4; i++ {
		c.sink.objs[ObjectName(mustHex(wsHex), uint64(100+i), mustHex(sum([]byte(fmt.Sprint("bare", i)))))] = []byte("x")
	}
	got, _, err := c.latest(c.longPin())
	if err != nil || got.Statement.Seq != 5 {
		t.Fatalf("bare names hid the valid backup: %v", err)
	}
}

// A search that stops at a limit says how many candidates were not examined and
// that a valid backup may exist below them; --below starts the search lower.
//
// spec: SPO-Xbackup-SEC-018
func TestALimitStopNamesTheUnexaminedCountAndBelowStartsLower(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	if _, err := c.backupAt(1); err != nil {
		t.Fatal(err)
	}
	ws := mustHex(wsHex)
	for i := 0; i < 20; i++ {
		name := ObjectName(ws, uint64(100+i), mustHex(sum([]byte(fmt.Sprint(i)))))
		c.sink.objs[name] = []byte("x")
		cp, _ := CheckpointName(name)
		c.sink.objs[cp] = []byte("garbage")
	}
	_, _, err := c.latest(c.longPin())
	if err == nil || !strings.Contains(err.Error(), "5 candidates were not examined") || !strings.Contains(err.Error(), "may exist below") || !strings.Contains(err.Error(), "--below") {
		t.Fatalf("%v", err)
	}
	below := uint64(104)
	got, _, err := c.latestBelow(c.longPin(), &below)
	if err != nil || got.Statement.Seq != 1 {
		t.Fatalf("--below 104: %v", err)
	}
}

// The slot table the statement names must be the file's.
//
// spec: SPO-Xbackup-OUT-015
func TestTheSlotTableOfTheFileMustMatchTheStatement(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	if _, err := c.backupAt(6); err != nil {
		t.Fatal(err)
	}
	var notes []string
	_, err := FetchLatest(context.Background(), LatestInput{
		Reader: c.sink, Ranger: c.ranger(), Lister: c.sink, Scratch: c.scratch, Pin: c.longPin(), Inspect: inspectFake,
		Facts: func(path string) (Facts, error) {
			id, h, err := inspectFake(path)
			return Facts{WorkspaceID: id, Head: h, SlotTable: HashBytes([]byte("another table"))}, err
		},
		Restore: func(string, string, []byte) error {
			t.Error("restored a file whose slot table is not the statement's")
			return nil
		},
		Report: func(n, w string) { notes = append(notes, w) },
	})
	if err == nil || !strings.Contains(strings.Join(notes, "\n"), "slot table") {
		t.Fatalf("%v %v", err, notes)
	}
	c.noTemp()
}

// A transport failure ends the search: an older backup is never restored
// because a newer one could not be downloaded.
//
// spec: SPO-Xbackup-OUT-015
func TestATransportFailureDoesNotFallBackToAnOlderBackup(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	for _, seq := range []uint64{3, 7} {
		if _, err := c.backupAt(seq); err != nil {
			t.Fatal(err)
		}
	}
	c.sink.cutAfter = 10
	_, _, err := c.latest(c.longPin())
	if err == nil || len(c.restored) != 0 {
		t.Fatalf("%v", err)
	}
	// a refusal of the restore itself is not a reason to try an older backup either
	c.sink.cutAfter = 0
	c.restore = errors.New("wrong passphrase")
	c.sink.getLog = nil
	_, _, err = c.latest(c.longPin())
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase") || c.objectGets() != 1 {
		t.Fatalf("%v gets=%d", err, c.objectGets())
	}
}

// The search is bounded: at most MaxCandidates backups are examined, and nothing
// beyond that is read.
//
// spec: SPO-Xbackup-SEC-018
func TestTheSearchIsBounded(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	ws := mustHex(wsHex)
	// 40 newer backups with a checkpoint that does not verify, then one good one
	if _, err := c.backupAt(1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		seq := uint64(100 + i)
		name := ObjectName(ws, seq, mustHex(sum([]byte(fmt.Sprint(i)))))
		c.sink.objs[name] = []byte("x")
		cp, _ := CheckpointName(name)
		c.sink.objs[cp] = []byte("garbage that is not a checkpoint")
	}
	c.sink.getLog = nil
	_, notes, err := c.latest(c.longPin())
	if err == nil || !strings.Contains(err.Error(), "no backup of this workspace") {
		t.Fatalf("%v", err)
	}
	if n := len(c.sink.getLog); n > MaxCandidates {
		t.Fatalf("%d reads for %d candidates", n, MaxCandidates)
	}
	if c.objectGets() != 0 {
		t.Error("an object was downloaded")
	}
	if !strings.Contains(strings.Join(notes, "\n"), "stopped after") {
		t.Errorf("%v", notes)
	}
	// an oversized checkpoint is refused at the bound, not read whole
	c.sink.getLog = nil
	big := ObjectName(ws, 500, mustHex(sum([]byte("big"))))
	c.sink.objs[big] = []byte("x")
	bigCp, _ := CheckpointName(big)
	c.sink.objs[bigCp] = bytes.Repeat([]byte("y"), 10*checkpoint.MaxObjectSize)
	_, notes, _ = c.latest(c.longPin())
	if !strings.Contains(strings.Join(notes, "\n"), "too large") {
		t.Errorf("%v", notes)
	}
}

// A sink that replays an OLD valid checkpoint and object, hiding the newer ones,
// is accepted by a pin without a sequence and refused by a pin with the newer
// sequence: without a sequence the pin proves authenticity, not freshness.
//
// spec: SPO-Xbackup-SEC-019
func TestReplayOfAnOldValidBackupNeedsASequenceInThePin(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	for _, seq := range []uint64{3, 12} {
		if _, err := c.backupAt(seq); err != nil {
			t.Fatal(err)
		}
	}
	// the hostile sink hides everything newer than sequence 3
	for n := range c.sink.objs {
		if strings.Contains(n, fmt.Sprintf("%020d", 12)) {
			delete(c.sink.objs, n)
		}
	}
	got, _, err := c.latest(c.longPin())
	if err != nil || got.Statement.Seq != 3 {
		t.Fatalf("the replay of the old backup: %v %+v (accepted, because the pin has no sequence)", err, got)
	}
	if _, _, err := c.latest(c.longPin().WithMin(12)); err == nil {
		t.Fatal("a pin with the newer sequence accepted the replayed backup")
	}
}

// The listing marks a checkpoint beside a backup and does not list it as
// unrecognised; an orphan checkpoint is unrecognised.
//
// spec: SPO-Xbackup-OUT-016
func TestListShowsCheckpointsAndPinnedVerification(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	for _, seq := range []uint64{3, 5} {
		if _, err := c.backupAt(seq); err != nil {
			t.Fatal(err)
		}
	}
	// the newer backup's checkpoint is replaced by garbage in the listing's eyes
	var newer string
	for n := range c.sink.objs {
		if strings.Contains(n, fmt.Sprintf("%020d", 5)) && strings.HasSuffix(n, ".checkpoint") {
			newer = n
		}
	}
	c.sink.objs[newer] = []byte("garbage")
	// an orphan
	c.sink.objs[ObjectName(mustHex(wsHex), 77, mustHex(sum([]byte("orphan"))))[:len("backups/")+len(wsHex)+1+20+1+64]+".checkpoint"] = []byte("x")
	// a backup with no checkpoint
	nocp := ObjectName(mustHex(wsHex), 2, mustHex(sum([]byte("nocp"))))
	c.sink.objs[nocp] = []byte("y")
	l, err := List(context.Background(), c.sink, mustHex(wsHex))
	if err != nil {
		t.Fatal(err)
	}
	has := map[uint64]bool{}
	for _, b := range l.Backups {
		has[b.Seq] = b.HasCheckpoint
	}
	if !has[3] || !has[5] || has[2] || len(l.Unrecognised) != 1 || !strings.Contains(l.Unrecognised[0], "77") {
		t.Fatalf("%+v %v", has, l.Unrecognised)
	}
	st := CheckPinned(context.Background(), c.sink, l, c.longPin())
	var good, bad int
	for _, b := range l.Backups {
		s := st[b.Name]
		switch {
		case b.Seq == 3 && s.Present && s.Examined && s.Err == nil && s.Seq == 3:
			good++
		case b.Seq == 5 && s.Present && s.Examined && s.Err != nil:
			bad++
		case b.Seq == 2 && !s.Present && !s.Examined:
		default:
			t.Errorf("seq %d: %+v", b.Seq, s)
		}
	}
	if good != 1 || bad != 1 {
		t.Fatalf("%v", st)
	}
}

// A checkpoint is accepted only beside the object it names: a genuine checkpoint
// copied under another object's name is skipped and sets no floor.
//
// spec: SPO-Xbackup-OUT-015
func TestACheckpointMustNameTheObjectItSitsBeside(t *testing.T) {
	c := newCkRig(t, ports.SinkDir, "hardware")
	var five PushResult
	for _, seq := range []uint64{3, 5} {
		r, err := c.backupAt(seq)
		if err != nil {
			t.Fatal(err)
		}
		five = r
	}
	other := ObjectName(mustHex(wsHex), 9, mustHex(sum([]byte("another object"))))
	c.sink.objs[other] = []byte("another object")
	cp5, _ := CheckpointName(five.Name)
	cp9, _ := CheckpointName(other)
	c.sink.objs[cp9] = c.sink.objs[cp5]
	got, notes, err := c.latest(c.longPin())
	if err != nil || got.Statement.Seq != 5 {
		t.Fatalf("%v %v", err, notes)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "does not name the object it sits beside") {
		t.Errorf("%v", notes)
	}
}

// A verified statement whose size is zero or above the limit is a floor, not a
// reason to restore something older.
//
// spec: SPO-Xbackup-SEC-018
func TestAStatementWithAnImpossibleSizeSetsAFloor(t *testing.T) {
	for _, size := range []uint64{0, uint64(DefaultMaxObjectSize) + 1} {
		c := newCkRig(t, ports.SinkDir, "hardware")
		if _, err := c.backupAt(2); err != nil {
			t.Fatal(err)
		}
		h := mustHex(sum([]byte(fmt.Sprint("big", size))))
		sg, err := c.sign.SignFacts(context.Background(), Facts{WorkspaceID: mustHex(wsHex), Head: Head{Seq: 20, MAC: mustHex(macHex)}, SlotTable: HashBytes([]byte("slot table")), SHA256: h, Size: size})
		if err != nil {
			t.Fatal(err)
		}
		name := ObjectName(mustHex(wsHex), 20, h)
		c.sink.objs[name] = []byte("x")
		cp, _ := CheckpointName(name)
		c.sink.objs[cp] = sg.EncodeObject()
		_, _, err = c.latest(c.longPin())
		if err == nil || !strings.Contains(err.Error(), "sequence 20") || !strings.Contains(err.Error(), "size outside the limits") || len(c.restored) != 0 {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}
