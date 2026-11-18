package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// scriptedStore is a sealed store whose notices, close error and cleanup are
// scripted. Only what the store commands call is implemented.
type scriptedStore struct {
	SealedStore
	notices    []string
	rekeyAdds  string // a notice the rekey adds
	rekeyErr   error
	keyErr     error  // returned together with the key (an unknown outcome)
	closeAdds  string // a notice Close adds
	closeErr   error
	cleanupErr error
	calls      []string
	keyFile    *os.File // the file the recovery key is written to; read when Cleanup runs
	keyAtClean string
	problems   []string // what ColdProblems reports
}

func (s *scriptedStore) ColdProblems(context.Context) ([]string, error) { return s.problems, nil }

func (s *scriptedStore) Notices() []string { return append([]string(nil), s.notices...) }

func (s *scriptedStore) rekey() (*secret.Buffer, error) {
	s.calls = append(s.calls, "rekey")
	if s.rekeyErr != nil {
		return nil, s.rekeyErr
	}
	if s.keyErr != nil {
		return secret.Take([]byte("ABCD-EFGH-IJKL-MNOP")), s.keyErr
	}
	if s.rekeyAdds != "" {
		s.notices = append(s.notices, s.rekeyAdds)
	}
	return secret.Take([]byte("ABCD-EFGH-IJKL-MNOP")), nil
}

func (s *scriptedStore) ChangePassphraseRekey(context.Context, *secret.Buffer) (*secret.Buffer, error) {
	return s.rekey()
}

func (s *scriptedStore) RekeyKeepPassphrase(context.Context, *secret.Buffer) (*secret.Buffer, error) {
	return s.rekey()
}

func (s *scriptedStore) PresentRecovery(context.Context, FactorOpen) error { return nil }

func (s *scriptedStore) ChangePassphraseKeepRecovery(context.Context, *secret.Buffer, *secret.Buffer) error {
	_, err := s.rekey()
	return err
}

func (s *scriptedStore) Cleanup(context.Context) error {
	s.calls = append(s.calls, "cleanup")
	if s.keyFile != nil {
		s.keyAtClean = drainPipe(s.keyFile)
	}
	return s.cleanupErr
}

func (s *scriptedStore) Close() error {
	s.calls = append(s.calls, "close")
	if s.closeAdds != "" {
		s.notices = append(s.notices, s.closeAdds)
	}
	return s.closeErr
}

func (s *scriptedStore) Slots(context.Context) ([]Slot, error) { return nil, nil }

// storeRun runs `spo store ...` against a scripted store and returns stdout,
// stderr and the error.
func storeRun(t *testing.T, st *scriptedStore, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, WorkspaceFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errw bytes.Buffer
	pfd := tokenFile(t, "a passphrase long enough\n")
	nfd := tokenFile(t, "a different passphrase\n")
	rinfd := tokenFile(t, "ABCD-EFGH-IJKL-MNOP\n")
	rf, rfd := tokenFileKeep(t)
	st.keyFile = rf
	root := NewRoot(Deps{
		Out: &out, Err: &errw,
		Sealed: SealedOps{
			Open:         func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return st, nil },
			OpenRecovery: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return st, nil },
			VerifyFile:   func(string, *secret.Buffer) (VerifyReport, error) { return VerifyReport{}, nil },
		},
	})
	all := append([]string{"-C", dir, "--passphrase-fd", pfd}, args...)
	for i, a := range all {
		switch a {
		case "@NEWFD":
			all[i] = nfd
		case "@RINFD":
			all[i] = rinfd
		case "@RKFD":
			all[i] = rfd
		}
	}
	root.SetArgs(all)
	err = root.ExecuteContext(context.Background())
	return out.String(), errw.String(), err
}

// tokenFileKeep is a pipe for the recovery key (a secret is never written to a
// file): the first result is its read end, the second the number of its write
// end, the descriptor flag value. drainPipe reads what was written.
func tokenFileKeep(t *testing.T) (*os.File, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, strconv.Itoa(int(w.Fd()))
}

// drainPipe reads what is in the pipe now, without waiting for it to close.
func drainPipe(r *os.File) string {
	var b bytes.Buffer
	r.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	b.ReadFrom(r)
	return b.String()
}

func TestRekeyCommandsPrintNoticesAndCleanUpAfterTheKey(t *testing.T) {
	for name, args := range map[string][]string{
		"recovery-key new": {"store", "recovery-key", "new", "--recovery-key-in-fd", "@RINFD", "--recovery-key-fd", "@RKFD"},
	} {
		t.Run(name, func(t *testing.T) {
			st := &scriptedStore{notices: []string{"opened with a notice"}, rekeyAdds: "the rekey is committed but the head file could not be written", cleanupErr: errors.New("busy")}
			_, stderr, err := storeRun(t, st, args...)
			if err != nil {
				t.Fatalf("%v\n%s", err, stderr)
			}
			for _, want := range []string{"note: opened with a notice", "note: the rekey is committed but the head file could not be written", "note: the old keys could not be cleaned out"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr)
				}
			}
			if strings.Count(stderr, "opened with a notice") != 1 {
				t.Errorf("a notice was printed more than once:\n%s", stderr)
			}
			if got := strings.Join(st.calls, ","); got != "rekey,cleanup,close" {
				t.Errorf("calls %s, want rekey,cleanup,close", got)
			}
			if !strings.Contains(st.keyAtClean, "ABCD-EFGH-IJKL-MNOP") {
				t.Errorf("Cleanup ran before the recovery key was delivered (file then held %q)", st.keyAtClean)
			}
		})
	}
}

func TestRecoverPrintsNoticesAndCleansUpAfterTheKey(t *testing.T) {
	st := &scriptedStore{notices: []string{"opened with a notice"}, rekeyAdds: "after the rekey"}
	rin := tokenFile(t, "ABCD-EFGH-IJKL-MNOP\n")
	_, stderr, err := storeRunNoPass(t, st, "store", "recover", "--recovery-key-in-fd", rin, "--new-passphrase-fd", "@NEWFD", "--recovery-key-fd", "@RKFD")
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	for _, want := range []string{"note: opened with a notice", "note: after the rekey"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if got := strings.Join(st.calls, ","); got != "rekey,cleanup,close" {
		t.Errorf("calls %s", got)
	}
}

func storeRunNoPass(t *testing.T, st *scriptedStore, args ...string) (string, string, error) {
	t.Helper()
	// storeRun adds --passphrase-fd, which recover refuses; build the same
	// command without it.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, WorkspaceFile), nil, 0o600)
	var out, errw bytes.Buffer
	nfd := tokenFile(t, "a different passphrase\n")
	rf, rfd := tokenFileKeep(t)
	st.keyFile = rf
	root := NewRoot(Deps{
		Out: &out, Err: &errw,
		Sealed: SealedOps{
			OpenRecovery: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { return st, nil },
		},
	})
	all := append([]string{"-C", dir}, args...)
	for i, a := range all {
		switch a {
		case "@NEWFD":
			all[i] = nfd
		case "@RKFD":
			all[i] = rfd
		}
	}
	root.SetArgs(all)
	err := root.ExecuteContext(context.Background())
	return out.String(), errw.String(), err
}

func TestCloseNoticesAndErrorsAreSurfaced(t *testing.T) {
	// A close error ends a command that otherwise succeeded, and Close's notice is printed.
	st := &scriptedStore{closeAdds: "cleaning the old keys out of the file is still pending", closeErr: errors.New("disk on fire")}
	_, stderr, err := storeRun(t, st, "store", "slots")
	if err == nil || !strings.Contains(err.Error(), "disk on fire") || !strings.Contains(err.Error(), "closing the workspace") {
		t.Errorf("a close error did not fail the command: %v", err)
	}
	if !strings.Contains(stderr, "note: cleaning the old keys out of the file is still pending") {
		t.Errorf("Close's notice was not printed:\n%s", stderr)
	}
	// A more specific error is not replaced by it.
	st = &scriptedStore{closeErr: errors.New("disk on fire"), rekeyErr: errors.New("the rekey failed specifically")}
	_, _, err = storeRun(t, st, "store", "recovery-key", "new", "--recovery-key-in-fd", "@RINFD", "--recovery-key-fd", "@RKFD")
	if err == nil || !strings.Contains(err.Error(), "the rekey failed specifically") || strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("the specific error was replaced: %v", err)
	}
	// Close's notice alone (no error) is printed and the command succeeds.
	st = &scriptedStore{closeAdds: "only a notice"}
	_, stderr, err = storeRun(t, st, "store", "slots")
	if err != nil || !strings.Contains(stderr, "note: only a notice") {
		t.Errorf("err %v, stderr:\n%s", err, stderr)
	}
}

func TestStoreVerifyWordingAndDeep(t *testing.T) {
	var deepCalled bool
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, WorkspaceFile), nil, 0o600)
	run := func(args ...string) (string, error) {
		var out, errw bytes.Buffer
		pfd := tokenFile(t, "a passphrase long enough\n")
		root := NewRoot(Deps{
			Out: &out, Err: &errw,
			Sealed: SealedOps{
				VerifyFile: func(string, *secret.Buffer) (VerifyReport, error) { return VerifyReport{}, nil },
				VerifyFileDeep: func(string, *secret.Buffer) (VerifyReport, error) {
					deepCalled = true
					return VerifyReport{}, nil
				},
			},
		})
		root.SetArgs(append([]string{"-C", dir, "--passphrase-fd", pfd, "store", "verify"}, args...))
		err := root.ExecuteContext(context.Background())
		return out.String(), err
	}
	out, err := run()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "every record authenticates") {
		t.Errorf("verify claims more than it checks:\n%s", out)
	}
	if !strings.Contains(out, "stored bytes of every record match the authenticated audit chain") || !strings.Contains(out, "not decrypted") {
		t.Errorf("verify does not say what it checked:\n%s", out)
	}
	if deepCalled {
		t.Error("--deep code ran without --deep")
	}
	out, err = run("--deep")
	if err != nil || !deepCalled || !strings.Contains(out, "decrypted under the current keys") {
		t.Errorf("--deep: %v called=%v\n%s", err, deepCalled, out)
	}
}

func TestUnknownRekeyOutcomeShowsTheKeyWithGuidance(t *testing.T) {
	for name, args := range map[string][]string{
		"recovery-key new": {"store", "recovery-key", "new", "--recovery-key-in-fd", "@RINFD", "--recovery-key-fd", "@RKFD"},
	} {
		t.Run(name, func(t *testing.T) {
			st := &scriptedStore{keyErr: ErrOutcomeUnknown}
			stdout, _, err := storeRun(t, st, args...)
			if err == nil || !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("err %v", err)
			}
			for _, want := range []string{"valid ONLY IF the change took effect", "recovery key was written to file descriptor"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}
			wants := []string{"Reopen the workspace with the NEW", "OLD recovery key no longer works", "keep the key just shown", "the key just shown is void"}
			if name == "recovery-key new" {
				wants = []string{"Run `spo store recovery-key new` again", "valid key either way"}
			}
			for _, want := range wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("guidance lacks %q: %v", want, err)
				}
			}
			if st.keyFile == nil {
				t.Fatal("no key file")
			}
			if got := drainPipe(st.keyFile); !strings.Contains(got, "ABCD-EFGH-IJKL-MNOP") {
				t.Errorf("the key was not delivered: %q", got)
			}
			// explain keeps the specific advice.
			if got := explain(err); got.Error() != err.Error() {
				t.Errorf("explain replaced the advice: %v", got)
			}
		})
	}
}

func TestOutcomeUnknownAdviceForOrdinaryCommands(t *testing.T) {
	err := explain(ErrOutcomeUnknown)
	for _, want := range []string{"may or may not have been stored", "spo store verify", "twice"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("advice lacks %q: %v", want, err)
		}
	}
}

// R6-F4: wording of the unknown-outcome path for `store recover`, which no
// longer has an OLD passphrase to refer to.
func TestUnknownRecoverOutcomeAdvice(t *testing.T) {
	st := &scriptedStore{keyErr: ErrOutcomeUnknown}
	rin := tokenFile(t, "ABCD-EFGH-IJKL-MNOP\n")
	_, _, err := storeRunNoPass(t, st, "store", "recover", "--recovery-key-in-fd", rin, "--new-passphrase-fd", "@NEWFD", "--recovery-key-fd", "@RKFD")
	if err == nil || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("err %v", err)
	}
	for _, want := range []string{"Try the NEW passphrase", "keep the key just shown", "run `spo store recover` again with the recovery key you used"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("advice lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "OLD passphrase") {
		t.Errorf("advice mentions the lost OLD passphrase: %v", err)
	}
}

// R6-F4: a failed type-back in the unknown-outcome path does not call the key
// "the valid key of the workspace".
type wrongGroupTerm struct{}

func (wrongGroupTerm) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	return secret.Take([]byte("ZZZZ")), nil
}
func (wrongGroupTerm) ReadLine(context.Context, string) (string, error) { return "", ErrNoTerminal }

func TestUnconfirmedKeyInUnknownOutcomeIsNotCalledValid(t *testing.T) {
	var out, errw bytes.Buffer
	a := newApp(Deps{Out: &out, Err: &errw})
	a.term = wrongGroupTerm{}
	key := secret.Take([]byte("ABCD-EFGH-IJKL-MNOP"))
	err := a.deliverUnknownRekey(context.Background(), key, -1, "recovery key", ErrOutcomeUnknown)
	if err == nil {
		t.Fatal("no error")
	}
	if strings.Contains(err.Error(), "valid key of the workspace") || !strings.Contains(err.Error(), "valid only if the change took effect") {
		t.Errorf("wording: %v", err)
	}
}

// `store slots` names the cold records the workspace key shows to be out of step.
//
// spec: SPO-Xcustody-INV-023
func TestStoreSlotsNamesColdRecordsOutOfStep(t *testing.T) {
	st := &scriptedStore{problems: []string{"node.skey/pool-a: sealed under a cold passphrase, but the policy is hardware"}}
	out, _, err := storeRun(t, st, "store", "slots")
	if err != nil || !strings.Contains(out, "1 cold-role record(s) are out of step") || !strings.Contains(out, "node.skey/pool-a: sealed under a cold passphrase") {
		t.Fatalf("%v\n%s", err, out)
	}
}
