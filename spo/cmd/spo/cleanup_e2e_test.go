package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Every command, on success and on failure, leaves no guarded buffer behind: the
// PINs, cold-key passphrases and the recovery key it read are destroyed when it ends.
//
// spec: SPO-Xcustody-SEC-005
func TestEveryCommandLeavesNoGuardedBufferBehind(t *testing.T) {
	_, oldRec := template(t)
	type tc struct {
		name string
		run  func(t *testing.T) error
	}
	freshWith := func(t *testing.T, args ...string) (string, error) { return exec(t, nil, args...) }
	cases := []tc{
		{"store recover, success", func(t *testing.T) error {
			return recoverWith(t, copyWorkspace(t), oldRec, "a recovered workspace passphrase", nil)
		}},
		{"store recover, wrong key", func(t *testing.T) error {
			return recoverWith(t, copyWorkspace(t), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", "a recovered workspace passphrase", nil)
		}},
		{"store verify --deep --with-cold-factor, success", func(t *testing.T) error {
			dir := coldWorkspace(t)
			pf, pfd := fdIn(t, testPass+"\n")
			cf, cfd := fdIn(t, testColdPass+"\n")
			defer func() { pf.Close(); cf.Close() }()
			_, err := freshWith(t, "-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "store", "verify", "--deep", "--with-cold-factor")
			return err
		}},
		{"store verify --deep --with-cold-factor, wrong cold passphrase", func(t *testing.T) error {
			dir := coldWorkspace(t)
			pf, pfd := fdIn(t, testPass+"\n")
			cf, cfd := fdIn(t, "not the cold passphrase at all\n")
			defer func() { pf.Close(); cf.Close() }()
			_, err := freshWith(t, "-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "store", "verify", "--deep", "--with-cold-factor")
			return err
		}},
		{"init, success", func(t *testing.T) error {
			pf, pfd := fdIn(t, testPass+"\n")
			rf, rfd := fdOut(t)
			defer pf.Close()
			_, err := freshWith(t, "-C", t.TempDir(), "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd)
			_ = rf
			return err
		}},
		{"init, refused (a workspace exists)", func(t *testing.T) error {
			pf, pfd := fdIn(t, testPass+"\n")
			rf, rfd := fdOut(t)
			defer pf.Close()
			_, err := freshWith(t, "-C", copyWorkspace(t), "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd)
			_ = rf
			return err
		}},
		{"store restore, success", func(t *testing.T) error {
			dir := copyWorkspace(t)
			backup := filepath.Join(t.TempDir(), "b.spo")
			if out, err := withPass(t, dir, testPass, "store", "backup", backup); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			_, err := withPass(t, filepath.Join(t.TempDir(), "restored"), testPass, "store", "restore", backup, "--network", "preview")
			return err
		}},
		{"store restore, refused", func(t *testing.T) error {
			_, err := withPass(t, filepath.Join(t.TempDir(), "restored"), testPass, "store", "restore", filepath.Join(t.TempDir(), "missing.spo"), "--network", "preview")
			return err
		}},
		{"workspace rotate --policy standard, success", func(t *testing.T) error {
			dir := copyWorkspace(t)
			pf, pfd := fdIn(t, testPass+"\n")
			kf, kfd := fdIn(t, oldRec+"\n")
			npf, npfd := fdIn(t, "a rotated workspace passphrase\n")
			rf, rfd := fdOut(t)
			defer func() { pf.Close(); kf.Close(); npf.Close() }()
			_, err := freshWith(t, "-C", dir, "--passphrase-fd", pfd, "workspace", "rotate", "--policy", "standard", "--recovery-key-in-fd", kfd, "--new-passphrase-fd", npfd, "--recovery-key-fd", rfd)
			_ = rf
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := secret.Budget().Live
			err := c.run(t)
			if after := secret.Budget().Live; after != before {
				t.Errorf("%d guarded buffers live after the command (%d before); it returned %v", after, before, err)
			}
			if strings.Contains(c.name, "success") && err != nil {
				t.Errorf("the command failed: %v", err)
			}
		})
	}
}

// coldWorkspace is a standard workspace with a pool cold key.
func coldWorkspace(t *testing.T) string {
	t.Helper()
	dir := copyWorkspace(t)
	pf, pfd := fdIn(t, testPass+"\n")
	cf, cfd := fdIn(t, testColdPass+"\n")
	defer func() { pf.Close(); cf.Close() }()
	if out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return dir
}

var _ = cli.WorkspaceFile

// --unlock recovery-composite is accepted only by the commands the recovery procedure
// uses; any other command refuses it before it asks for anything, so a long-running one
// (party serve) never holds the recovery key.
//
// spec: SPO-Xcustody-PRE-035
func TestRecoveryCompositeIsRefusedByCommandsThatDoNotNeedIt(t *testing.T) {
	dir := copyWorkspace(t)
	for _, args := range [][]string{{"party", "serve"}, {"pool", "kes", "generate", poolName}, {"store", "verify"}} {
		term := &fakeTerm{secrets: []string{"AAAA"}}
		out, err := exec(t, term, append([]string{"-C", dir, "--unlock", "recovery-composite"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "accepted only by workspace rotate") || len(term.asked) != 0 {
			t.Errorf("%v: %v asked=%v\n%s", args, err, term.asked, out)
		}
	}
}
