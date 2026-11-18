package main

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// keptEncryptedColdWorkspace is a standard workspace whose only cold record is a kept
// upstream-encrypted pool cold key: its recovery wrap exists but its plaintext cannot be
// checked against its identity, so only the old cold passphrase re-establishes it.
func keptEncryptedColdWorkspace(t *testing.T) string {
	t.Helper()
	dir := copyWorkspace(t)
	if out, err := withPass(t, dir, testPass, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	enc := keyfile.EncryptedEnvelope("StakePoolSigningKey_ed25519", "Stake Pool Operator Key", []byte(strings.Repeat("ab", 64)))
	err = labels.Named(st).Update(context.Background(), func(w ports.NamedWriter) error {
		if err := w.Delete(ports.NamedRef{Name: poolName, Kind: ports.NodeSKey}); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: poolName + ".node", Kind: ports.UpstreamEncryptedSKey}, secret.Take(append([]byte(nil), enc...)))
	})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

var recordNameRe = regexp.MustCompile(`: ([^\s;:]+/[^\s;:]+)[ ;(]`)

// `store recover` and `workspace rotate` with the cold passphrase lost refuse, naming the
// record that cannot be re-established, and leave it only for --leave-unreachable NAME; the
// workspace then fails `store verify` and lists the record in `store slots`.
//
// spec: SPO-Xcustody-PRE-031, SPO-Xcustody-PRE-034
func TestLeaveUnreachableOnRecoverAndOnRotate(t *testing.T) {
	_, oldRec := template(t)
	type step func(dir string, leave []string) (string, error)
	recoverStep := func(dir string, leave []string) (string, error) {
		kf, kfd := fdIn(t, oldRec+"\n")
		pf, pfd := fdIn(t, "a recovered workspace passphrase\n")
		cf, cfd := fdIn(t, "the cold passphrase I lost\n")
		rf, rfd := fdOut(t)
		defer func() { kf.Close(); pf.Close(); cf.Close() }()
		args := []string{"-C", dir, "--cold-passphrase-fd", cfd, "store", "recover", "--recovery-key-in-fd", kfd, "--new-passphrase-fd", pfd, "--recovery-key-fd", rfd}
		for _, l := range leave {
			args = append(args, "--leave-unreachable", l)
		}
		out, err := exec(t, nil, args...)
		_ = rf
		return out, err
	}
	rotateStep := func(dir string, leave []string) (string, error) {
		pf, pfd := fdIn(t, testPass+"\n")
		kf, kfd := fdIn(t, oldRec+"\n")
		npf, npfd := fdIn(t, "a rotated workspace passphrase\n")
		cf, cfd := fdIn(t, "the cold passphrase I lost\n")
		ncf, ncfd := fdIn(t, "a new cold passphrase of mine\n")
		rf, rfd := fdOut(t)
		defer func() { pf.Close(); kf.Close(); npf.Close(); cf.Close(); ncf.Close() }()
		args := []string{"-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "--new-cold-passphrase-fd", ncfd, "workspace", "rotate", "--policy", "standard",
			"--recovery-key-in-fd", kfd, "--new-passphrase-fd", npfd, "--recovery-key-fd", rfd}
		for _, l := range leave {
			args = append(args, "--leave-unreachable", l)
		}
		out, err := exec(t, nil, args...)
		_ = rf
		return out, err
	}
	for name, run := range map[string]struct {
		do   step
		pass string
	}{"store recover": {recoverStep, "a recovered workspace passphrase"}, "workspace rotate": {rotateStep, "a rotated workspace passphrase"}} {
		t.Run(name, func(t *testing.T) {
			dir := keptEncryptedColdWorkspace(t)
			out, err := run.do(dir, nil)
			if err == nil || !strings.Contains(err.Error(), "would leave cold-role records under the old factor") {
				t.Fatalf("without --leave-unreachable: %v\n%s", err, out)
			}
			m := recordNameRe.FindStringSubmatch(err.Error())
			if m == nil {
				t.Fatalf("the refusal does not name the record: %v", err)
			}
			if out, err := run.do(dir, []string{"nothing/named-this"}); err == nil {
				t.Fatalf("an unknown record in --leave-unreachable: %s", out)
			}
			if out, err := run.do(dir, []string{m[1]}); err != nil {
				t.Fatalf("with --leave-unreachable %s: %v\n%s", m[1], err, out)
			}
			// the workspace now fails store verify and names the record, with no factor
			vout, verr := withPass(t, dir, run.pass, "store", "verify")
			if verr == nil || !strings.Contains(verr.Error()+vout, m[1]) {
				t.Errorf("store verify of a workspace with a left record: %v\n%s", verr, vout)
			}
			sout, serr := withPass(t, dir, run.pass, "store", "slots")
			if serr != nil || !strings.Contains(sout, m[1]) {
				t.Errorf("store slots does not list the left record: %v\n%s", serr, sout)
			}
		})
	}
}
