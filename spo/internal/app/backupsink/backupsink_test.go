package backupsink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// memSink is an in-memory sink that counts what is written.
type memSink struct {
	kind      ports.SinkKind
	objs      map[string][]byte
	puts      int
	probes    int
	props     ports.SinkProperties
	probeErr  error
	overwrite bool // a store that lets a put replace silently
	putErr    error
	cutAfter  int // Get and GetRange fail after this many bytes (0: never)
	ranges    []int64
	gets      int
	lists     int
	hasLies   bool
	getErrs   int  // the next Gets fail (a read-back interrupted)
	corrupt   bool // a store that keeps different bytes than it was given
	cpPuts    int
	getLog    []string // names of every Get
}

func newMem(kind ports.SinkKind) *memSink {
	m := &memSink{kind: kind, objs: map[string][]byte{}}
	m.props = ports.SinkProperties{Kind: kind, Versioning: true, ObjectLockMode: "COMPLIANCE", ObjectLockDefaultRetention: true, ShortLivedCredentials: true}
	return m
}

func (m *memSink) Put(_ context.Context, name string, r io.Reader, size int64) error {
	m.puts++
	if m.putErr != nil {
		return m.putErr
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return errors.New("size")
	}
	// nothing may be put that was not hashed from the verified local file; a
	// checkpoint is the one other kind of object, named beside a backup
	if strings.HasSuffix(name, ".checkpoint") {
		m.cpPuts++
	} else if _, _, want, ok := ParseName(name); !ok || hex.EncodeToString(want) != sum(b) {
		return errors.New("test sink: the bytes put are not the bytes the name hashes")
	}
	if old, ok := m.objs[name]; ok && !m.overwrite {
		if bytes.Equal(old, b) {
			return nil
		}
		return ports.ErrObjectExists
	}
	if m.corrupt {
		b = append([]byte("x"), b[1:]...)
	}
	m.objs[name] = b
	return nil
}

func (m *memSink) Get(_ context.Context, name string) (io.ReadCloser, error) {
	m.gets++
	m.getLog = append(m.getLog, name)
	if m.getErrs > 0 {
		m.getErrs--
		return nil, errors.New("connection reset")
	}
	b, ok := m.objs[name]
	if !ok {
		return nil, ports.ErrObjectNotFound
	}
	return m.reader(b), nil
}

func (m *memSink) reader(b []byte) io.ReadCloser {
	if m.cutAfter > 0 && len(b) > m.cutAfter {
		return io.NopCloser(io.MultiReader(bytes.NewReader(b[:m.cutAfter]), errReader{errors.New("connection reset")}))
	}
	return io.NopCloser(bytes.NewReader(b))
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func (m *memSink) GetRange(_ context.Context, name string, off int64) (io.ReadCloser, error) {
	b, ok := m.objs[name]
	if !ok {
		return nil, ports.ErrObjectNotFound
	}
	m.ranges = append(m.ranges, off)
	if off >= int64(len(b)) {
		return nil, ports.ErrRangeNotSatisfiable
	}
	return m.reader(b[off:]), nil
}

func (m *memSink) Has(_ context.Context, name string) (bool, error) {
	_, ok := m.objs[name]
	return ok || m.hasLies, nil
}

func (m *memSink) List(_ context.Context, prefix string) ([]ports.ObjectInfo, error) {
	m.lists++
	var out []ports.ObjectInfo
	for n, b := range m.objs {
		if strings.HasPrefix(n, prefix) {
			out = append(out, ports.ObjectInfo{Name: n, Size: int64(len(b))})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *memSink) Check(context.Context) (ports.SinkProperties, error) {
	m.probes++
	return m.props, m.probeErr
}

// A fake backup file is "<ws hex>:<seq>:<mac hex>:<payload>".
// a head MAC is 32 bytes
const macHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

const wsHex = "aabbccddeeff00112233445566778899aabbccddeeff0011223344"

func fakeFile(ws string, seq uint64, mac, payload string) []byte {
	return []byte(fmt.Sprintf("%s:%d:%s:%s", ws, seq, mac, payload))
}

func inspectFake(path string) ([]byte, Head, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, Head{}, err
	}
	p := strings.SplitN(string(b), ":", 4)
	if len(p) != 4 {
		return nil, Head{}, errors.New("not a backup")
	}
	id, _ := hex.DecodeString(p[0])
	seq, _ := strconv.ParseUint(p[1], 10, 64)
	mac, _ := hex.DecodeString(p[2])
	return id, Head{Seq: seq, MAC: mac}, nil
}

type rig struct {
	t        *testing.T
	dir      string // the workspace directory
	sink     *memSink
	backups  int
	verifies int
	verify   error
	policy   string
	content  []byte
	restored [][]byte
	restore  error
	noRange  bool
	scratch  *tScratch
	// cp, when set, makes push sign a checkpoint after the object is verified.
	cp *CheckpointPush
}

func newRig(t *testing.T, kind ports.SinkKind, policy string) *rig {
	t.Helper()
	dir := t.TempDir()
	return &rig{t: t, dir: dir, scratch: &tScratch{root: dir, notOwned: map[string]bool{}}, sink: newMem(kind), policy: policy, content: fakeFile(wsHex, 7, macHex, "payload")}
}

func (r *rig) push() (PushResult, error) {
	id, _ := hex.DecodeString(wsHex)
	return Push(context.Background(), PushInput{
		Kind: r.sink.kind, Writer: r.sink, Reader: r.sink, Probe: r.sink, Scratch: r.scratch,
		Policy: r.policy, WorkspaceID: id,
		Backup: func(_ context.Context, dest string) (Head, error) {
			r.backups++
			if err := os.WriteFile(dest, r.content, 0o600); err != nil {
				return Head{}, err
			}
			_, h, _ := inspectFake(dest)
			return h, nil
		},
		Verify:  func(string) error { r.verifies++; return r.verify },
		Inspect: inspectFake,
		SlotTable: func(string) ([]byte, error) {
			return HashBytes([]byte("slot table")), nil
		},
		Checkpoint: r.cp,
	})
}

func (r *rig) noTemp() {
	r.t.Helper()
	ents, _ := os.ReadDir(r.dir)
	if len(ents) != 0 {
		r.t.Errorf("temporary files left in the workspace directory: %v", ents)
	}
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// spec: SPO-Xbackup-OUT-001
func TestObjectNameIsStrict(t *testing.T) {
	name := ObjectName(mustHex(wsHex), 7, mustHex(sum([]byte("x"))))
	want := "backups/" + wsHex + "/00000000000000000007-" + sum([]byte("x")) + ".spo"
	if name != want {
		t.Fatalf("%s\n%s", name, want)
	}
	if ws, seq, sh, ok := ParseName(name); !ok || hex.EncodeToString(ws) != wsHex || seq != 7 || hex.EncodeToString(sh) != sum([]byte("x")) {
		t.Fatal("round trip")
	}
	bad := []string{
		"", "backups/" + wsHex + "/7-" + sum(nil) + ".spo", // not 20 digits
		"backups/" + wsHex + "/00000000000000000007-" + sum(nil) + ".spo.bak",
		"backups/" + wsHex + "/00000000000000000007-" + strings.ToUpper(sum(nil)) + ".spo",
		"backups/" + wsHex + "/00000000000000000007-" + sum(nil)[:62] + ".spo",
		"backups/" + wsHex + "/+0000000000000000007-" + sum(nil) + ".spo",
		"backups/" + wsHex + "/99999999999999999999-" + sum(nil) + ".spo", // beyond uint64
		"backups/zz/00000000000000000007-" + sum(nil) + ".spo",
		"backups/" + wsHex + "/../00000000000000000007-" + sum(nil) + ".spo",
		"other/" + wsHex + "/00000000000000000007-" + sum(nil) + ".spo",
		"backups/" + wsHex + "/00000000000000000007-" + sum(nil) + ".spo\n",
	}
	for _, n := range bad {
		if _, _, _, ok := ParseName(n); ok {
			t.Errorf("%q parsed", n)
		}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// spec: SPO-Xbackup-OUT-002
func TestPinRoundTripAndStrictParse(t *testing.T) {
	p := Pin{WorkspaceID: mustHex(wsHex), Seq: 12, HeadMAC: mustHex(macHex), SHA256: mustHex(sum([]byte("a")))}
	got, err := ParsePin(p.String())
	if err != nil || got.String() != p.String() {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "a:b", p.String() + ":x", strings.Replace(p.String(), ":12:", ":-1:", 1), strings.Replace(p.String(), wsHex, "zz", 1), strings.ToUpper(p.String()), p.String()[:len(p.String())-2]} {
		if _, err := ParsePin(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// Every refusal happens before any byte is sent, and before a backup is made.
//
// spec: SPO-Xbackup-PRE-001, SPO-Xbackup-PRE-002
func TestPushRefusalsSendNothing(t *testing.T) {
	cases := []struct {
		name   string
		policy string
		mod    func(*memSink)
		want   []string
	}{
		{"standard to s3", "standard", nil, []string{"spo workspace rotate --policy hardware", "directory"}},
		{"no versioning", "hardware", func(m *memSink) { m.props.Versioning = false }, []string{"versioning"}},
		{"no lock", "hardware", func(m *memSink) { m.props.ObjectLockMode = ""; m.props.ObjectLockDefaultRetention = false }, []string{"Object Lock", "COMPLIANCE"}},
		{"governance mode", "strict", func(m *memSink) { m.props.ObjectLockMode = "GOVERNANCE" }, []string{"COMPLIANCE"}},
		{"no default retention", "hardware", func(m *memSink) { m.props.ObjectLockDefaultRetention = false }, []string{"retention"}},
		{"static credentials", "hardware", func(m *memSink) { m.props.ShortLivedCredentials = false }, []string{"short-lived", "SSO", "static access keys"}},
		{"unknown policy", "", nil, []string{"hardware"}},
	}
	for _, c := range cases {
		r := newRig(t, ports.SinkS3, c.policy)
		if c.mod != nil {
			c.mod(r.sink)
		}
		_, err := r.push()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: message lacks %q: %v", c.name, w, err)
			}
		}
		if r.sink.puts != 0 || len(r.sink.objs) != 0 {
			t.Errorf("%s: %d writes reached the sink", c.name, r.sink.puts)
		}
		if r.backups != 0 {
			t.Errorf("%s: a backup was made before the refusal", c.name)
		}
		if c.name == "standard to s3" && r.sink.probes != 0 {
			t.Errorf("standard to s3 asked the sink before refusing")
		}
		r.noTemp()
	}
}

func TestPushProbeFailureSendsNothing(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	r.sink.probeErr = errors.New("no route")
	if _, err := r.push(); err == nil || r.sink.puts != 0 {
		t.Fatalf("%v %d", err, r.sink.puts)
	}
}

// spec: SPO-Xbackup-PRE-003
func TestPushToADirectoryIsAllowedForEveryPolicy(t *testing.T) {
	for _, pol := range []string{"standard", "hardware", "strict"} {
		r := newRig(t, ports.SinkDir, pol)
		r.sink.props = ports.SinkProperties{Kind: ports.SinkDir}
		res, err := r.push()
		if err != nil {
			t.Fatalf("%s: %v", pol, err)
		}
		if res.StandardWarning != (pol == "standard") {
			t.Errorf("%s: warning flag %v", pol, res.StandardWarning)
		}
		r.noTemp()
	}
}

// spec: SPO-Xbackup-OUT-001, SPO-Xbackup-OUT-002, SPO-Xbackup-OUT-003
func TestPushNamesVerifiesPutsAndReadsBack(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, err := r.push()
	if err != nil {
		t.Fatal(err)
	}
	wantName := "backups/" + wsHex + "/00000000000000000007-" + sum(r.content) + ".spo"
	if res.Name != wantName {
		t.Fatalf("name %s", res.Name)
	}
	if b := r.sink.objs[wantName]; !bytes.Equal(b, r.content) {
		t.Fatal("the stored object differs")
	}
	if r.verifies != 1 {
		t.Fatalf("verify ran %d times", r.verifies)
	}
	wantPin := wsHex + ":7:" + macHex + ":" + sum(r.content)
	if res.Pin.String() != wantPin {
		t.Fatalf("pin %s", res.Pin)
	}
	r.noTemp()
	// pushing the same backup again is not an error
	if _, err := r.push(); err != nil {
		t.Fatalf("identical re-push: %v", err)
	}
}

// spec: SPO-Xbackup-PRE-004
func TestPushStopsOnFailureAndLeavesNoTemporaryFile(t *testing.T) {
	// the copy fails verification: nothing is sent
	r := newRig(t, ports.SinkDir, "hardware")
	r.verify = errors.New("bad copy")
	if _, err := r.push(); err == nil || !strings.Contains(err.Error(), "FAILED verification") || r.sink.puts != 0 {
		t.Fatalf("%v %d", err, r.sink.puts)
	}
	r.noTemp()
	// the sink keeps different bytes than it was given: caught by the read-back
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.corrupt = true
	if _, err := r.push(); err == nil || !strings.Contains(err.Error(), "read back") {
		t.Fatalf("read-back did not catch it: %v", err)
	}
	r.noTemp()
	// a store that overwrites silently: a name taken by other bytes is caught
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.overwrite = true
	name := "backups/" + wsHex + "/00000000000000000007-" + sum(r.content) + ".spo"
	r.sink.objs[name] = []byte("older")
	if _, err := r.push(); err == nil {
		t.Fatal("success with a silent overwrite of other bytes")
	}
	r.noTemp()
	// the name is taken by other bytes: ErrObjectExists
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.objs[name] = []byte("older")
	if _, err := r.push(); err == nil || !strings.Contains(err.Error(), "faulty or hostile") || r.sink.puts != 0 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
	// the sink refuses the put because the name holds other content
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.putErr = ports.ErrObjectExists
	if _, err := r.push(); !errors.Is(err, ports.ErrObjectExists) {
		t.Fatalf("%v", err)
	}
	r.noTemp()
	// the inspection disagrees with the backup call
	r = newRig(t, ports.SinkDir, "hardware")
	id, _ := hex.DecodeString(wsHex)
	_, err := Push(context.Background(), PushInput{Kind: ports.SinkDir, Writer: r.sink, Reader: r.sink, Probe: r.sink, Scratch: r.scratch, Policy: "hardware", WorkspaceID: id,
		Backup: func(_ context.Context, d string) (Head, error) {
			os.WriteFile(d, r.content, 0o600)
			return Head{Seq: 99}, nil
		},
		Verify:  func(string) error { return nil },
		Inspect: inspectFake})
	if err == nil || r.sink.puts != 0 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
	// the file names another workspace
	r = newRig(t, ports.SinkDir, "hardware")
	r.content = fakeFile("00112233", 7, "01", "p")
	if _, err := r.push(); err == nil || r.sink.puts != 0 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
}

// spec: SPO-Xbackup-OUT-004
func TestListIsNewestFirstAndNeverTrustsAnUnparsedName(t *testing.T) {
	m := newMem(ports.SinkDir)
	other := "ffff" + wsHex[4:]
	for _, seq := range []uint64{3, 11, 7} {
		c := []byte{byte(seq)}
		m.objs[ObjectName(mustHex(wsHex), seq, mustHex(sum(c)))] = c
	}
	m.objs[ObjectName(mustHex(other), 99, mustHex(sum([]byte("o"))))] = []byte("o")
	m.objs["backups/"+wsHex+"/garbage.spo"] = []byte("g")
	m.objs["backups/"+wsHex+"/7-"+sum(nil)+".spo"] = []byte("g")
	res, err := List(context.Background(), m, mustHex(wsHex))
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for _, e := range res.Backups {
		seqs = append(seqs, e.Seq)
	}
	if fmt.Sprint(seqs) != "[11 7 3]" {
		t.Fatalf("%v", seqs)
	}
	if len(res.Unrecognised) != 2 {
		t.Fatalf("unrecognised: %v", res.Unrecognised)
	}
	for _, e := range res.Backups {
		if hex.EncodeToString(e.WorkspaceID) != wsHex {
			t.Errorf("another workspace's backup listed")
		}
	}
}

func (r *rig) fetch(pin Pin, name string, max int64) error {
	r.restored = nil
	return Fetch(context.Background(), FetchInput{
		Reader: r.sink, Ranger: r.ranger(), Pin: pin, Name: name, Scratch: r.scratch, MaxSize: max, Inspect: inspectFake,
		Restore: func(path string, _ []byte) error {
			b, _ := os.ReadFile(path)
			r.restored = append(r.restored, b)
			return r.restore
		},
	})
}

func pinOf(content []byte) Pin {
	ws, seq, mac := mustHex(wsHex), uint64(7), mustHex(macHex)
	return Pin{WorkspaceID: ws, Seq: seq, HeadMAC: mac, SHA256: mustHex(sum(content))}
}

// spec: SPO-Xbackup-OUT-005
func TestPushThenFetchRoundTrip(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, err := r.push()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.fetch(res.Pin, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	if len(r.restored) != 1 || !bytes.Equal(r.restored[0], r.content) {
		t.Fatal("the restore did not get the pushed file")
	}
	r.noTemp()
	// naming the object explicitly gives the same
	if err := r.fetch(res.Pin, res.Name, 1<<20); err != nil || len(r.restored) != 1 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
}

// spec: SPO-Xbackup-PRE-005, SPO-Xbackup-PRE-006
func TestFetchRefusesWhatThePinDoesNotDescribe(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	good := res.Pin
	name := res.Name
	mut := map[string]func(p *Pin){
		"workspace id": func(p *Pin) { p.WorkspaceID = append([]byte{0x01}, p.WorkspaceID[1:]...) },
		"sequence":     func(p *Pin) { p.Seq++ },
		"head mac":     func(p *Pin) { p.HeadMAC = []byte{9, 9, 9} },
		"file hash":    func(p *Pin) { p.SHA256 = mustHex(sum([]byte("other"))) },
	}
	for field, f := range mut {
		p := good
		p.WorkspaceID = append([]byte(nil), good.WorkspaceID...)
		p.HeadMAC = append([]byte(nil), good.HeadMAC...)
		f(&p)
		for _, n := range []string{name, ""} { // by the object's own name, and by the name the bad pin derives
			if err := r.fetch(p, n, 1<<20); err == nil {
				t.Errorf("a pin with a wrong %s was accepted (name %q)", field, n)
			}
		}
		if len(r.restored) != 0 {
			t.Errorf("%s: the restore ran", field)
		}
		r.noTemp()
	}
	// a pin and a name that disagree about the file
	other := ObjectName(mustHex(wsHex), 7, mustHex(sum([]byte("zzz"))))
	if err := r.fetch(good, other, 1<<20); err == nil {
		t.Error("a name that is not the pin's file was accepted")
	}
	if err := r.fetch(good, "../etc/passwd", 1<<20); err == nil {
		t.Error("a bad name was accepted")
	}
}

// spec: SPO-Xbackup-PRE-005
func TestFetchRefusesATamperedObject(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	b := append([]byte(nil), r.sink.objs[res.Name]...)
	b[len(b)-1] ^= 1
	r.sink.objs[res.Name] = b
	if err := r.fetch(res.Pin, "", 1<<20); err == nil || len(r.restored) != 0 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
}

// An older backup stored under the name the pin gives: the hash differs.
//
// spec: SPO-Xbackup-PRE-005
func TestFetchRefusesAnOlderObjectUnderThePinnedName(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	older := fakeFile(wsHex, 3, "0a0b", "payload-old")
	r.sink.objs[res.Name] = older
	if err := r.fetch(res.Pin, "", 1<<20); err == nil || len(r.restored) != 0 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
	// and one whose hash is made to match the pin cannot exist, but a file that
	// says another head than the pin does is refused even then
	r = newRig(t, ports.SinkS3, "hardware")
	content := fakeFile(wsHex, 3, "0a0b", "payload-old")
	p := Pin{WorkspaceID: mustHex(wsHex), Seq: 7, HeadMAC: mustHex(macHex), SHA256: mustHex(sum(content))}
	r.sink.objs[ObjectName(p.WorkspaceID, p.Seq, p.SHA256)] = content
	if err := r.fetch(p, "", 1<<20); err == nil || !strings.Contains(err.Error(), "head") {
		t.Fatalf("a file with another head than the pin: %v", err)
	}
	r.noTemp()
}

// spec: SPO-Xbackup-SEC-005
func TestFetchRefusesAnOversizeObject(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	if err := r.fetch(res.Pin, "", int64(len(r.content))-1); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("%v", err)
	}
	if len(r.restored) != 0 {
		t.Fatal("restore ran")
	}
	r.noTemp()
	// a store that streams more than its listing said is bounded as well
	big := bytes.Repeat([]byte("a"), 1<<16)
	r.sink.objs[res.Name] = big
	if err := r.fetch(res.Pin, "", 1<<10); err == nil {
		t.Fatal("accepted")
	}
	r.noTemp()
	// the default cap is 1 GiB
	if DefaultMaxObjectSize != 1<<30 {
		t.Fatal(DefaultMaxObjectSize)
	}
}

// spec: SPO-Xbackup-PRE-006
func TestFetchPassesTheRestoreRefusalOnAndRemovesTheFile(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	r.restore = errors.New("backup older than the workspace")
	err := r.fetch(res.Pin, "", 1<<20)
	if err == nil || !strings.Contains(err.Error(), "older than the workspace") {
		t.Fatalf("%v", err)
	}
	r.noTemp()
}

func TestFetchMissingObject(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	if err := r.fetch(pinOf(r.content), "", 1<<20); !errors.Is(err, ports.ErrObjectNotFound) {
		t.Fatalf("%v", err)
	}
	r.noTemp()
}

// noRange is a sink whose ranges cannot be served: a fetch starts again.
type noRange struct{ *memSink }

func (noRange) GetRange(context.Context, string, int64) (io.ReadCloser, error) {
	return nil, ports.ErrRangeNotSatisfiable
}

func (r *rig) ranger() ports.ObjectRangeReader {
	if r.noRange {
		return noRange{r.sink}
	}
	return r.sink
}

func (r *rig) partials() []string {
	ents, _ := os.ReadDir(r.dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func endsWithState(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: no error", what)
		return
	}
	m := err.Error()
	if !strings.HasSuffix(m, ".") || !(strings.Contains(m, "can be run again") || strings.Contains(m, "cannot succeed") || strings.Contains(m, "treat this backup as not made")) {
		t.Errorf("%s: the error does not end with the state sentence: %q", what, m)
	}
}

// Every failure of push and fetch ends with one sentence on the state left.
//
// spec: SPO-Xbackup-OUT-006
func TestEveryFailureEndsWithTheStateSentence(t *testing.T) {
	r := newRig(t, ports.SinkS3, "standard")
	_, err := r.push()
	endsWithState(t, "refusal", err)
	r = newRig(t, ports.SinkDir, "hardware")
	r.verify = errors.New("bad")
	_, err = r.push()
	endsWithState(t, "verify", err)
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.putErr = errors.New("connection reset")
	_, err = r.push()
	endsWithState(t, "put", err)
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.putErr = ports.ErrObjectExists
	_, err = r.push()
	endsWithState(t, "exists", err)
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.getErrs = 1
	_, err = r.push()
	endsWithState(t, "readback", err)
	r = newRig(t, ports.SinkDir, "hardware")
	r.sink.corrupt = true
	_, err = r.push()
	endsWithState(t, "mismatch", err)
	r = newRig(t, ports.SinkDir, "hardware")
	endsWithState(t, "fetch missing", r.fetch(pinOf(r.content), "", 1<<20))
	res, _ := r.push()
	r.restore = errors.New("backup older than the workspace")
	endsWithState(t, "fetch restore", r.fetch(res.Pin, "", 1<<20))
	r.restore = nil
	r.sink.cutAfter = 5
	endsWithState(t, "fetch cut", r.fetch(res.Pin, "", 1<<20))
}

// Upload done, read-back interrupted: "uploaded but not verified", and a re-run
// verifies without uploading again.
//
// spec: SPO-Xbackup-OUT-007
func TestPushReadBackInterruptedThenRerunVerifiesWithoutUploading(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	r.sink.getErrs = 1
	_, err := r.push()
	if err == nil || !strings.Contains(err.Error(), "uploaded but not verified") || !strings.Contains(err.Error(), "without uploading it again") {
		t.Fatalf("%v", err)
	}
	if r.sink.puts != 1 || len(r.sink.objs) != 1 {
		t.Fatalf("%d puts, %d objects", r.sink.puts, len(r.sink.objs))
	}
	r.noTemp()
	res, err := r.push()
	if err != nil {
		t.Fatal(err)
	}
	if r.sink.puts != 1 || res.Uploaded || len(r.sink.objs) != 1 {
		t.Fatalf("the re-run uploaded again: %d puts, uploaded %v", r.sink.puts, res.Uploaded)
	}
}

// Ctrl-C: a cancelled context at each stage leaves the same state and sentence.
//
// spec: SPO-Xbackup-OUT-006
func TestCancelledContextBehavesLikeAFailure(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	ctx, cancel := context.WithCancel(context.Background())
	id, _ := hex.DecodeString(wsHex)
	_, err := Push(ctx, PushInput{Kind: ports.SinkS3, Writer: r.sink, Reader: r.sink, Probe: r.sink, Scratch: r.scratch, Policy: "hardware", WorkspaceID: id,
		Backup: func(c context.Context, d string) (Head, error) {
			os.WriteFile(d, r.content, 0o600)
			cancel()
			return Head{Seq: 7, MAC: mustHex(macHex)}, c.Err()
		},
		Verify:  func(string) error { return nil },
		Inspect: inspectFake})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	endsWithState(t, "cancel", err)
	if r.sink.puts != 0 {
		t.Fatal("sent after cancel")
	}
	r.noTemp()
	// cancelled during the download of a fetch: the partial file stays
	r = newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	err = Fetch(ctx2, FetchInput{Reader: r.sink, Ranger: r.sink, Pin: res.Pin, Scratch: r.scratch, Inspect: inspectFake, Restore: func(string, []byte) error { t.Fatal("restore ran"); return nil }})
	endsWithState(t, "fetch cancel", err)
}

func partialPath(r *rig, p Pin) string { return r.dir + "/" + PartialName(p.SHA256) }

// An interrupted download leaves a private partial file; the next run with the
// same pin resumes it with a range request.
//
// spec: SPO-Xbackup-OUT-009, SPO-Xbackup-SEC-008
func TestFetchResumesAPartialDownload(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	r.content = fakeFile(wsHex, 7, macHex, strings.Repeat("p", 200))
	res, _ := r.push()
	r.sink.cutAfter = 40
	if err := r.fetch(res.Pin, "", 1<<20); err == nil || len(r.restored) != 0 {
		t.Fatalf("%v", err)
	}
	st, err := os.Stat(partialPath(r, res.Pin))
	if err != nil || st.Size() != 40 || st.Mode().Perm() != 0o600 {
		t.Fatalf("partial: %v %v", st, err)
	}
	r.sink.cutAfter = 0
	if err := r.fetch(res.Pin, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	if len(r.sink.ranges) != 1 || r.sink.ranges[0] != 40 {
		t.Fatalf("ranges %v", r.sink.ranges)
	}
	if len(r.restored) != 1 || !bytes.Equal(r.restored[0], r.content) {
		t.Fatal("the resumed download is not the file")
	}
	r.noTemp()
	// without a range reader the download restarts and still ends right
	r.noRange = true
	r.sink.cutAfter = 40
	r.fetch(res.Pin, "", 1<<20)
	r.sink.cutAfter = 0
	r.restored = nil
	if err := r.fetch(res.Pin, "", 1<<20); err != nil || len(r.restored) != 1 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
}

// A wrong or stale partial file can only cause a refusal; it is deleted; a
// partial of another pin is removed; one longer than the object restarts.
//
// spec: SPO-Xbackup-SEC-008
func TestFetchPartialFileIsNeverTrusted(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	r.content = fakeFile(wsHex, 7, macHex, strings.Repeat("p", 200))
	res, _ := r.push()
	// wrong bytes of the right length so far
	os.WriteFile(partialPath(r, res.Pin), bytes.Repeat([]byte("z"), 40), 0o600)
	err := r.fetch(res.Pin, "", 1<<20)
	if err == nil || !strings.Contains(err.Error(), "partial file was deleted") || len(r.restored) != 0 {
		t.Fatalf("%v", err)
	}
	r.noTemp()
	// the next run starts clean and succeeds
	if err := r.fetch(res.Pin, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	// a partial of another pin goes away
	other := partialPath(r, Pin{SHA256: mustHex(sum([]byte("other pin")))})
	os.WriteFile(other, []byte("zzz"), 0o600)
	if err := r.fetch(res.Pin, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err == nil {
		t.Fatal("a partial file of another pin was kept")
	}
	// a partial longer than the object (a 416): start again
	os.WriteFile(partialPath(r, res.Pin), bytes.Repeat([]byte("z"), len(r.content)+50), 0o600)
	if err := r.fetch(res.Pin, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	r.noTemp()
}

// tScratch is a test scratch space on a real directory.
type tScratch struct {
	root     string
	notOwned map[string]bool
}

func (s *tScratch) MakeDir(prefix string) (string, error) {
	p, err := os.MkdirTemp(s.root, prefix)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(p, s.root+"/"), nil
}
func (s *tScratch) Path(n string) string { return s.root + "/" + n }
func (s *tScratch) Open(n string) (ports.ScratchFile, error) {
	f, err := os.OpenFile(s.Path(n), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return f, nil
}
func (s *tScratch) Remove(n string) error { return os.RemoveAll(s.Path(n)) }
func (s *tScratch) Entries() ([]ports.ScratchEntry, error) {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var out []ports.ScratchEntry
	for _, e := range ents {
		st, err := os.Lstat(s.Path(e.Name()))
		if err != nil {
			continue
		}
		en := ports.ScratchEntry{Name: e.Name(), ModTime: st.ModTime(), Owned: !s.notOwned[e.Name()]}
		switch m := st.Mode(); {
		case m&os.ModeSymlink != 0:
			en.Kind = ports.ScratchSymlink
		case m.IsDir():
			en.Kind = ports.ScratchDirectory
		case m.IsRegular():
			en.Kind = ports.ScratchRegular
		default:
			en.Kind = ports.ScratchOther
		}
		out = append(out, en)
	}
	return out, nil
}

// F1: a hostile sink that lists many objects of the head's sequence causes no
// download of them, no verification beyond the local one, and no leftover.
//
// spec: SPO-Xbackup-OUT-008
func TestPushNeverDownloadsObjectsItDidNotNameItself(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	for i := 0; i < 20; i++ {
		c := []byte(fmt.Sprintf("planted-%d", i))
		r.sink.objs[ObjectName(mustHex(wsHex), 7, mustHex(sum(c)))] = c
	}
	res, err := r.push()
	if err != nil {
		t.Fatal(err)
	}
	if r.sink.gets != 1 { // only the read-back of its own object
		t.Fatalf("%d downloads", r.sink.gets)
	}
	if r.verifies != 1 {
		t.Fatalf("verify ran %d times", r.verifies)
	}
	if r.sink.lists != 0 {
		t.Fatalf("the sink was listed %d times", r.sink.lists)
	}
	if !res.Uploaded || len(r.sink.objs) != 21 {
		t.Fatalf("uploaded %v, %d objects", res.Uploaded, len(r.sink.objs))
	}
	r.noTemp()
	// a second backup of the same head with other bytes is a second object
	r.content = fakeFile(wsHex, 7, macHex, "same head, other bytes")
	if res2, err := r.push(); err != nil || !res2.Uploaded || len(r.sink.objs) != 22 {
		t.Fatalf("%v", err)
	}
}

// F11: a sink that says an object exists and cannot return it is faulty or
// hostile; the run says so and does not tell the operator to run again forever.
//
// spec: SPO-Xbackup-OUT-007
func TestPushDistinguishesASinkThatLiesAboutHas(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	r.sink.hasLies = true
	_, err := r.push()
	if err == nil || !strings.Contains(err.Error(), "faulty or hostile") || !strings.Contains(err.Error(), "cannot return") || r.sink.puts != 0 {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "without uploading it again") {
		t.Fatalf("the message tells the operator to run again: %v", err)
	}
	r.noTemp()
}

// F13: a pin has one spelling.
//
// spec: SPO-Xbackup-OUT-002
func TestPinHasOneSpelling(t *testing.T) {
	p := Pin{WorkspaceID: mustHex(wsHex), Seq: 12, HeadMAC: mustHex(macHex), SHA256: mustHex(sum([]byte("a")))}
	for _, bad := range []string{
		strings.Replace(p.String(), ":12:", ":012:", 1),
		strings.Replace(p.String(), ":12:", ":+12:", 1),
		strings.Replace(p.String(), ":12:", ":00:", 1) + "",
		strings.ToUpper(p.String()),
		strings.Replace(p.String(), ":"+macHex+":", ":"+macHex+" :", 1),
	} {
		if g, err := ParsePin(bad); err == nil && g.String() != bad {
			t.Errorf("%q parsed as %q", bad, g)
		} else if err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	zero := Pin{WorkspaceID: mustHex(wsHex), Seq: 0, HeadMAC: mustHex(macHex), SHA256: mustHex(sum([]byte("a")))}
	if g, err := ParsePin(zero.String()); err != nil || g.String() != zero.String() {
		t.Errorf("sequence 0: %v", err)
	}
}

// F12: stale leftovers are swept at the start of push and fetch: exact own
// pattern, older than an hour, regular files or directories of this user, never
// a symlink or the wrong type.
//
// spec: SPO-Xbackup-SEC-007
func TestStaleLeftoversAreSweptOnlyByPatternAgeTypeAndOwner(t *testing.T) {
	for _, op := range []string{"push", "fetch"} {
		r := newRig(t, ports.SinkS3, "hardware")
		res, _ := r.push() // makes an object to fetch; also sweeps nothing yet
		old := time.Now().Add(-2 * time.Hour)
		recent := time.Now().Add(-5 * time.Minute)
		otherSum := hex.EncodeToString(mustHex(sum([]byte("another pin"))))
		mkDir := func(n string, at time.Time) {
			os.Mkdir(r.dir+"/"+n, 0o700)
			os.WriteFile(r.dir+"/"+n+"/f", []byte("x"), 0o600)
			os.Chtimes(r.dir+"/"+n, at, at)
		}
		mkFile := func(n string, at time.Time) {
			os.WriteFile(r.dir+"/"+n, []byte("x"), 0o600)
			os.Chtimes(r.dir+"/"+n, at, at)
		}
		mkDir(".spo-backup-111", old)    // swept
		mkDir(".spo-backup-222", recent) // too young
		mkDir(".spo-backup-abc", old)    // not the pattern (not digits)
		mkDir("x.spo-backup-333", old)   // not the pattern
		mkFile(".spo-backup-444", old)   // wrong type: a file
		mkDir(".spo-backup-555", old)    // not owned
		r.scratch.notOwned[".spo-backup-555"] = true
		mkFile(".spo-fetch-"+otherSum+".partial", old)                                          // swept (other pin, old)
		mkFile(".spo-fetch-"+hex.EncodeToString(mustHex(sum([]byte("p2"))))+".partial", recent) // young: kept by the sweep
		mkDir(".spo-fetch-"+hex.EncodeToString(mustHex(sum([]byte("p3"))))+".partial", old)     // wrong type: a directory
		mkFile(".spo-fetch-short.partial", old)                                                 // not the pattern
		victim := t.TempDir() + "/victim"
		os.WriteFile(victim, []byte("keep"), 0o600)
		os.Symlink(victim, r.dir+"/.spo-backup-666") // a symlink named like a leftover
		if op == "push" {
			if _, err := r.push(); err != nil {
				t.Fatal(err)
			}
		} else {
			r.fetch(res.Pin, "", 1<<20)
		}
		gone := []string{".spo-backup-111", ".spo-fetch-" + otherSum + ".partial"}
		kept := []string{".spo-backup-222", ".spo-backup-abc", "x.spo-backup-333", ".spo-backup-444", ".spo-backup-555", ".spo-fetch-short.partial", ".spo-backup-666",
			".spo-fetch-" + hex.EncodeToString(mustHex(sum([]byte("p3")))) + ".partial"}
		for _, n := range gone {
			if _, err := os.Lstat(r.dir + "/" + n); err == nil {
				t.Errorf("%s: %s was not swept", op, n)
			}
		}
		for _, n := range kept {
			if _, err := os.Lstat(r.dir + "/" + n); err != nil {
				t.Errorf("%s: %s was removed", op, n)
			}
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Errorf("%s: a symlink target was touched", op)
		}
	}
}

// F10: a restore refusal that is not about the file keeps the verified file, so
// a re-run does not download again; a refusal about the content deletes it.
//
// spec: SPO-Xbackup-OUT-010
func TestFetchKeepsAVerifiedFileOnlyForRefusalsNotAboutIt(t *testing.T) {
	r := newRig(t, ports.SinkS3, "hardware")
	res, _ := r.push()
	r.sink.gets = 0
	r.restore = NotAboutTheFile(errors.New("wrong passphrase"))
	err := r.fetch(res.Pin, "", 1<<20)
	if err == nil || !strings.Contains(err.Error(), "wrong passphrase") || !strings.Contains(err.Error(), "kept") {
		t.Fatalf("%v", err)
	}
	if _, serr := os.Stat(partialPath(r, res.Pin)); serr != nil {
		t.Fatal("the verified file was not kept")
	}
	if r.sink.gets != 1 {
		t.Fatalf("%d downloads", r.sink.gets)
	}
	r.restore = nil
	r.restored = nil
	if err := r.fetch(res.Pin, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	if r.sink.gets != 1 || len(r.sink.ranges) != 0 {
		t.Fatalf("the re-run downloaded again: %d gets, ranges %v", r.sink.gets, r.sink.ranges)
	}
	if len(r.restored) != 1 {
		t.Fatal("restore did not run")
	}
	r.noTemp()
	// a content refusal deletes it
	r.restore = errors.New("backup older than the workspace")
	if err := r.fetch(res.Pin, "", 1<<20); err == nil {
		t.Fatal("accepted")
	}
	r.noTemp()
}

// G5: the head MAC in a pin has exactly the length of an audit MAC.
//
// spec: SPO-Xbackup-OUT-002
func TestPinHeadMACLengthIsStrict(t *testing.T) {
	ok := Pin{WorkspaceID: mustHex(wsHex), Seq: 1, HeadMAC: mustHex(macHex), SHA256: mustHex(sum([]byte("a")))}
	if _, err := ParsePin(ok.String()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 5, 16, 31, 33, 64} {
		p := ok
		p.HeadMAC = bytes.Repeat([]byte{7}, n)
		if _, err := ParsePin(p.String()); err == nil {
			t.Errorf("a head MAC of %d bytes parsed", n)
		}
	}
}
