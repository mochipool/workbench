package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A sealed store for `init --policy hardware`: Init makes a standard file,
// Describe reads its policy, and the rotation does what the test says.
type initFake struct {
	policy      string // what Describe reports; "" with describeErr
	describeErr error
	rotateErr   error // returned with the key (ErrOutcomeUnknown) or alone
	rotateKey   bool
	rotates     int
	records     int  // what Describe reports besides a fresh file
	extraSlot   bool // a third slot
	otherID     bool // the file's id is not the marker's
	// onRotate runs when the rotation is asked, to move the file's policy.
	onRotate func()
}

type initStore struct {
	SealedStore
	f *initFake
}

func (initStore) Close() error { return nil }
func (s initStore) Policy(context.Context) (string, error) {
	return s.f.policy, nil
}
func (s initStore) Rotate(context.Context, RotateRequest) (*secret.Buffer, string, error) {
	s.f.rotates++
	if s.f.onRotate != nil {
		s.f.onRotate()
	}
	var key *secret.Buffer
	if s.f.rotateKey {
		key = secret.Take([]byte("ABCD-EFGH-IJKL-MNOP"))
	}
	return key, "", s.f.rotateErr
}
func (initStore) AddFIDO2Slot(context.Context, FactorOpen) ([]byte, error) { return nil, nil }
func (initStore) RemoveSlot(context.Context, RemoveSlotRequest) (*secret.Buffer, string, error) {
	return nil, "", nil
}

type nilFactors struct{ ports.FactorSource }

func initRun(t *testing.T, dir string, f *initFake, args ...string) (out string, keyOut string, err error) {
	t.Helper()
	var o, e bytes.Buffer
	rf, rfd := tokenFileKeep(t)
	cfgs := map[string]WorkspaceConfig{}
	cfg := memConfig(cfgs)
	create := cfg.Create
	cfg.Create = func(d string, c WorkspaceConfig) error {
		if err := os.WriteFile(filepath.Join(d, configFile), []byte("x"), 0o600); err != nil {
			return err
		}
		return create(d, c)
	}
	root := NewRoot(Deps{
		Out: &o, Err: &e, Config: cfg, Factors: nilFactors{},
		Sealed: SealedOps{
			Init: func(path string, _ *secret.Buffer) (*secret.Buffer, error) {
				if err := os.WriteFile(path, []byte("sealed"), 0o600); err != nil {
					return nil, err
				}
				f.policy = "standard"
				return secret.Take([]byte("WXYZ-WXYZ-WXYZ-WXYZ")), nil
			},
			Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return initStore{f: f}, nil },
			Describe: func(path string) (WorkspaceInfo, error) {
				if _, err := os.Stat(path); err != nil {
					return WorkspaceInfo{}, err
				}
				if f.describeErr != nil {
					return WorkspaceInfo{}, f.describeErr
				}
				id := []byte{1, 2, 3, 4}
				if f.otherID {
					id = []byte{9, 9, 9, 9}
				}
				sl := []Slot{{Kind: "passphrase"}, {Kind: "recovery"}}
				if f.extraSlot {
					sl = append(sl, Slot{Kind: "fido2-hmac"})
				}
				return WorkspaceInfo{Policy: f.policy, ID: id, Records: f.records, AuditRows: 1, Slots: sl}, nil
			},
		},
	})
	all := append([]string{"-C", dir, "init", "--network", "preview", "--policy", "hardware", "--fido2-device", "/dev/a", "--recovery-device", "/dev/b", "--recovery-key-fd", rfd}, args...)
	root.SetArgs(all)
	err = root.ExecuteContext(context.Background())
	return o.String() + e.String(), drainPipe(rf), err
}

func present(p string) bool { _, err := os.Lstat(p); return err == nil }

// spec: SPO-Xunlock-PRE-035
func TestInitUnderPolicyResolvesAnUnknownOutcomeFromTheFile(t *testing.T) {
	ws := func(dir string) string { return filepath.Join(dir, WorkspaceFile) }
	t.Run("the rotation took effect: kept, key delivered", func(t *testing.T) {
		dir := t.TempDir()
		f := &initFake{rotateErr: ErrOutcomeUnknown, rotateKey: true}
		f.onRotate = func() { f.policy = "hardware" }
		out, key, err := initRun(t, dir, f)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !present(ws(dir)) || present(filepath.Join(dir, initPendingFile)) {
			t.Error("the finished workspace was removed or the marker stayed")
		}
		if !strings.Contains(key, "ABCD-EFGH") {
			t.Errorf("the recovery key was not delivered: %q", key)
		}
	})
	t.Run("the rotation did not take effect: removed, key not delivered", func(t *testing.T) {
		dir := t.TempDir()
		f := &initFake{rotateErr: ErrOutcomeUnknown, rotateKey: true}
		out, key, err := initRun(t, dir, f)
		if err == nil || !strings.Contains(err.Error(), "did not take effect") {
			t.Fatalf("%v\n%s", err, out)
		}
		for _, p := range []string{ws(dir), filepath.Join(dir, configFile), filepath.Join(dir, initPendingFile)} {
			if present(p) {
				t.Errorf("%s was left", p)
			}
		}
		if key != "" {
			t.Errorf("a void recovery key was delivered: %q", key)
		}
	})
	t.Run("the file cannot be read: nothing removed, key marked uncertain", func(t *testing.T) {
		dir := t.TempDir()
		f := &initFake{rotateErr: ErrOutcomeUnknown, rotateKey: true}
		f.onRotate = func() { f.describeErr = errors.New("locked") }
		out, key, err := initRun(t, dir, f)
		if err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("%v\n%s", err, out)
		}
		if !present(ws(dir)) || !present(filepath.Join(dir, initPendingFile)) {
			t.Error("a workspace of unknown state was removed")
		}
		if !strings.Contains(key, "ABCD-EFGH") || !strings.Contains(out, "valid ONLY IF") {
			t.Errorf("key %q\n%s", key, out)
		}
	})
	t.Run("a plain failure removes everything this run made", func(t *testing.T) {
		dir := t.TempDir()
		f := &initFake{rotateErr: errors.New("the authenticator was removed")}
		if _, _, err := initRun(t, dir, f); err == nil {
			t.Fatal("no error")
		}
		for _, p := range []string{ws(dir), filepath.Join(dir, configFile), filepath.Join(dir, initPendingFile)} {
			if present(p) {
				t.Errorf("%s was left", p)
			}
		}
	})
}

// A file left by a run that was killed between Init and the rotation's commit is
// recognised by the marker, and removed only after an explicit confirmation.
//
// spec: SPO-Xunlock-PRE-035
func TestInitFindsAnInterruptedPolicyInit(t *testing.T) {
	left := func(t *testing.T, policy string) (string, *initFake) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, WorkspaceFile), []byte("throwaway"), 0o600)
		os.WriteFile(filepath.Join(dir, configFile), []byte("x"), 0o600)
		os.WriteFile(filepath.Join(dir, initPendingFile), []byte(`{"policy":"hardware","id":"01020304"}`), 0o600)
		return dir, &initFake{policy: policy}
	}
	t.Run("without confirmation nothing is removed", func(t *testing.T) {
		dir, f := left(t, "standard")
		_, _, err := initRun(t, dir, f)
		if err == nil || !strings.Contains(err.Error(), "--remove-unfinished") {
			t.Fatalf("%v", err)
		}
		for _, n := range []string{WorkspaceFile, configFile, initPendingFile} {
			if !present(filepath.Join(dir, n)) {
				t.Errorf("%s was removed without confirmation", n)
			}
		}
		if f.rotates != 0 {
			t.Error("a rotation ran")
		}
	})
	t.Run("with confirmation it is removed and the init completes", func(t *testing.T) {
		dir, f := left(t, "standard")
		f.onRotate = func() { f.policy = "hardware" }
		f.rotateKey = true
		out, _, err := initRun(t, dir, f, "--remove-unfinished")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, WorkspaceFile)); string(b) != "sealed" {
			t.Errorf("the throwaway file is still there: %q", b)
		}
		if present(filepath.Join(dir, initPendingFile)) {
			t.Error("the marker stayed after a successful init")
		}
	})
	t.Run("a file with the policy of the marker is a finished workspace", func(t *testing.T) {
		dir, f := left(t, "hardware")
		_, _, err := initRun(t, dir, f, "--remove-unfinished")
		if err == nil || !strings.Contains(err.Error(), "complete workspace") {
			t.Fatalf("%v", err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, WorkspaceFile)); string(b) != "throwaway" {
			t.Error("a finished workspace was touched")
		}
		if present(filepath.Join(dir, initPendingFile)) {
			t.Error("the stale marker stayed")
		}
	})
	t.Run("a marker with no workspace file is stale and only the marker goes", func(t *testing.T) {
		dir, f := left(t, "standard")
		os.Remove(filepath.Join(dir, WorkspaceFile))
		os.Remove(filepath.Join(dir, configFile))
		f.onRotate = func() { f.policy = "hardware" }
		f.rotateKey = true
		if out, _, err := initRun(t, dir, f); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	})
	// A planted or stale marker beside a real standard workspace must not make
	// init delete it, whatever is answered.
	for name, mod := range map[string]func(f *initFake){
		"a real workspace with records": func(f *initFake) { f.records = 3 },
		"a marker naming another id":    func(f *initFake) { f.otherID = true },
		"a table with another slot":     func(f *initFake) { f.extraSlot = true },
	} {
		t.Run("marker beside "+name+" is refused, file intact", func(t *testing.T) {
			dir, f := left(t, "standard")
			mod(f)
			_, _, err := initRun(t, dir, f, "--remove-unfinished")
			if err == nil || !strings.Contains(err.Error(), "by hand") {
				t.Fatalf("%v", err)
			}
			if b, _ := os.ReadFile(filepath.Join(dir, WorkspaceFile)); string(b) != "throwaway" {
				t.Error("the workspace was touched")
			}
			if f.rotates != 0 {
				t.Error("a rotation ran")
			}
		})
	}
	t.Run("a marker that names nothing is refused", func(t *testing.T) {
		dir, f := left(t, "standard")
		os.WriteFile(filepath.Join(dir, initPendingFile), []byte(`{"policy":"hardware"}`), 0o600)
		if _, _, err := initRun(t, dir, f, "--remove-unfinished"); err == nil || !strings.Contains(err.Error(), "does not name") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a standard init with a stray marker beside a real workspace is not a removal", func(t *testing.T) {
		dir, f := left(t, "standard")
		_, _, err := initRun(t, dir, f) // no --remove-unfinished, no terminal
		if err == nil {
			t.Fatal("init replaced a workspace")
		}
	})
}
