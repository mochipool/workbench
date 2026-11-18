package main

import (
	"bytes"
	"context"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
)

// ADR 0012 stage 3, work package 3, through the real command tree: `store convert
// --to-layout DIR`. No real authenticator is used.

var (
	layoutPinRE = regexp.MustCompile(`(?m)^Pin: ([0-9a-f]{32}:layout:[0-9]+:[0-9a-f]{64})$`)
)

func readLayout(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(root, p)
			b, _ := os.ReadFile(p)
			out[filepath.ToSlash(rel)] = b
			if info.Mode().Perm() != 0o600 {
				t.Errorf("%s has mode %v", rel, info.Mode().Perm())
			}
		}
		return nil
	})
	return out
}

func newestLayoutHead(t *testing.T, files map[string][]byte) (layout.Head, []byte, string) {
	t.Helper()
	best := ""
	for n := range files {
		if strings.HasPrefix(n, "heads/") && !strings.HasSuffix(n, ".sig") && n > best {
			best = n
		}
	}
	if best == "" {
		t.Fatal("no head")
	}
	h, err := layout.ParseHead(files[best])
	if err != nil {
		t.Fatal(err)
	}
	return h, files[best], best
}

func sha(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pinFileOf(t *testing.T, wsDir string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(wsDir, "workspace.spo.layout-*.pin"))
	if len(m) != 1 {
		t.Fatalf("pin files %v", m)
	}
	return m[0]
}

// A standard workspace is written to a directory, again unchanged, and again after
// a change; the workspace file is not changed by it; nothing secret is in the
// directory.
//
// spec: SPO-Xlayout-IF-001, SPO-Xlayout-OUT-014, SPO-Xlayout-OUT-015, SPO-Xlayout-OUT-017, SPO-Xlayout-OUT-018, SPO-Xlayout-SEC-006
func TestStoreConvertToLayoutStandard(t *testing.T) {
	dir := copyWorkspace(t)
	_, recKey := template(t)
	root := filepath.Join(t.TempDir(), "layout")
	wsBefore := sha(t, filepath.Join(dir, "workspace.spo"))
	out, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", root)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := layoutPinRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no pin line:\n%s", out)
	}
	for _, want := range []string{"Layout written and read back", "objects written", "Head: sequence 1", "not signed", "protected against accidents", "What someone who can read this directory sees", "plaintext", "not a second workspace", "somewhere other than"} {
		if !strings.Contains(strings.ReplaceAll(out, "\n", " "), want) && !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Long-lived pin") {
		t.Error("a long-lived pin for an unsigned head")
	}
	notLeaked(t, out, testPass, recKey)
	if sha(t, filepath.Join(dir, "workspace.spo")) != wsBefore {
		t.Error("the workspace file was changed by an export")
	}
	files := readLayout(t, root)
	h, _, name := newestLayoutHead(t, files)
	if h.Sequence != 1 || name != layout.HeadPath(1) || !strings.HasPrefix(m[1], hexOf(h.Workspace)+":layout:1:") {
		t.Fatalf("%+v %s %s", h, name, m[1])
	}
	for p, b := range files {
		if bytes.Contains(b, []byte(testPass)) || bytes.Contains(b, []byte(recKey)) || bytes.Contains(b, []byte(strings.ReplaceAll(recKey, "-", ""))) {
			t.Errorf("a secret is in %s", p)
		}
		if strings.HasPrefix(p, "objects/") && b[0] == layout.FormatSealed && (bytes.Contains(b, []byte("node.skey")) || bytes.Contains(b, []byte("kes.vkey")) || bytes.Contains(b, []byte("manifest-root"))) {
			t.Errorf("record kinds in the clear in %s", p)
		}
	}
	pin1 := sha(t, pinFileOf(t, dir))
	pinInfo, _ := os.Stat(pinFileOf(t, dir))
	if !strings.Contains(pin1, m[1][strings.Index(m[1], ":layout:")+8:]) && !strings.Contains(pin1, "1 ") {
		t.Errorf("the pin file: %q", pin1)
	}
	if strings.Contains(strings.Join(keys(files), " "), "workspace.spo") {
		t.Error("the pin file is in the layout directory")
	}

	// again, unchanged
	time.Sleep(20 * time.Millisecond)
	out2, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", root)
	if err != nil || !strings.Contains(out2, "already up to date") {
		t.Fatalf("%v\n%s", err, out2)
	}
	if got := layoutPinRE.FindStringSubmatch(out2); got == nil || got[1] != m[1] {
		t.Errorf("the pin changed for an unchanged workspace: %v", got)
	}
	if again, _ := os.Stat(pinFileOf(t, dir)); !os.SameFile(pinInfo, again) || !pinInfo.ModTime().Equal(again.ModTime()) {
		t.Error("the pin file was rewritten for the same head")
	}
	if len(readLayout(t, root)) != len(files) {
		t.Error("an unchanged export changed the directory")
	}

	// after a change: a new head names the old one
	if o, err := withPass(t, dir, testPass, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out3, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", root)
	if err != nil || strings.Contains(out3, "already up to date") {
		t.Fatalf("%v\n%s", err, out3)
	}
	files3 := readLayout(t, root)
	h3, _, _ := newestLayoutHead(t, files3)
	if h3.Sequence != 2 || !bytes.Equal(h3.Previous, layout.HeadHash(files[layout.HeadPath(1)])) {
		t.Fatalf("head 2: %+v", h3)
	}
	for p, b := range files {
		if !bytes.Equal(files3[p], b) {
			t.Errorf("%s changed", p)
		}
	}
	if sha(t, pinFileOf(t, dir)) == pin1 {
		t.Error("the pin did not advance")
	}
	noLeftovers(t, dir)
	for p := range files3 {
		if strings.Contains(p, ".tmp-") {
			t.Errorf("leftover %s", p)
		}
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	o := make([]byte, 2*len(b))
	for i, c := range b {
		o[2*i], o[2*i+1] = d[c>>4], d[c&15]
	}
	return string(o)
}

// Every refusal that needs no secret is made before anything is asked: the
// terminal is never read from.
//
// spec: SPO-Xlayout-PRE-013, SPO-Xlayout-PRE-016
func TestStoreConvertRefusesBeforeAnyPrompt(t *testing.T) {
	dir := copyWorkspace(t)
	base := t.TempDir()
	// a layout of another workspace
	otherDir := t.TempDir()
	pf, pfd := fdIn(t, testPass+"\n")
	rf, rfd := fdOut(t)
	if out, err := exec(t, nil, "-C", otherDir, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pf.Close()
	_ = rf
	foreign := filepath.Join(base, "foreign")
	if out, err := withPass(t, otherDir, testPass, "store", "convert", "--to-layout", foreign); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	foreignBefore := len(readLayout(t, foreign))
	notALayout := filepath.Join(base, "plain")
	os.Mkdir(notALayout, 0o700)
	os.WriteFile(filepath.Join(notALayout, "notes.txt"), []byte("x"), 0o600)
	loose := filepath.Join(base, "loose")
	os.Mkdir(loose, 0o700)
	os.Chmod(loose, 0o777)
	cases := map[string]struct {
		args []string
		want string
	}{
		"an s3 URL":                        {[]string{"--to-layout", "s3://bucket/prefix"}, "local directory only"},
		"no directory":                     {nil, "--to-layout"},
		"a layout of another workspace":    {[]string{"--to-layout", foreign}, "another workspace"},
		"a directory that is not a layout": {[]string{"--to-layout", notALayout}, "not a layout"},
		"the workspace directory":          {[]string{"--to-layout", dir}, "workspace directory"},
		"inside the workspace directory":   {[]string{"--to-layout", filepath.Join(dir, "out")}, "workspace directory"},
		"loose permissions":                {[]string{"--to-layout", loose}, "writable by its group"},
		"the recovery composite":           {[]string{"--unlock", "recovery-composite", "--to-layout", filepath.Join(base, "rc")}, "recovery-composite"},
	}
	for name, c := range cases {
		term := &fakeTerm{}
		argv := append([]string{"-C", dir, "store", "convert"}, c.args...)
		out, err := exec(t, term, argv...)
		if err == nil {
			t.Errorf("%s: accepted:\n%s", name, out)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if len(term.asked) != 0 {
			t.Errorf("%s: the terminal was asked %q", name, term.asked)
		}
	}
	if len(readLayout(t, foreign)) != foreignBefore {
		t.Error("the foreign layout was changed")
	}
	if len(readLayout(t, notALayout)) != 1 {
		t.Error("a directory that is not a layout was written to")
	}
	if _, err := os.Stat(filepath.Join(base, "rc")); err == nil {
		t.Error("the directory of a refused command was created")
	}
	// a damaged pin file is reported and not replaced
	root := filepath.Join(base, "ok")
	if out, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", root); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pf2 := pinFileOf(t, dir)
	os.WriteFile(pf2, []byte("damaged\n"), 0o600)
	term := &fakeTerm{}
	if out, err := exec(t, term, "-C", dir, "store", "convert", "--to-layout", root); err == nil || !strings.Contains(err.Error(), "damaged") || len(term.asked) != 0 {
		t.Errorf("a damaged pin file: %v asked %v\n%s", err, term.asked, out)
	}
	if string(readFile(t, pf2)) != "damaged\n" {
		t.Error("the damaged pin file was replaced")
	}
	// a directory behind the pin: the pin names a sequence the directory lacks
	os.WriteFile(pf2, []byte("spo-layout-pin 1 9 "+strings.Repeat("a", 64)+"\n"), 0o600)
	if out, err := exec(t, &fakeTerm{}, "-C", dir, "store", "convert", "--to-layout", root); err == nil || !strings.Contains(err.Error(), "behind the pin") {
		t.Errorf("a directory behind the pin: %v\n%s", err, out)
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A standard workspace with a checkpoint key: the head is signed once, the
// signature verifies with stock ssh-keygen under the head namespace, and
// --no-checkpoint asks the key nothing.
//
// spec: SPO-Xlayout-OUT-016, SPO-Xlayout-OUT-017
func TestStoreConvertSignsTheHead(t *testing.T) {
	rig := newFidoRig(t, "seed-layout-signed", "")
	dir := copyWorkspace(t)
	c := fidoCmd{t, rig, dir, true}
	out, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	line := sshLineRE.FindStringSubmatch(out)
	lp := longPinRE.FindStringSubmatch(out)
	if line == nil || lp == nil {
		t.Fatalf("%s", out)
	}
	root := filepath.Join(t.TempDir(), "layout")
	before := rig.count("fido2-assert")
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "convert", "--to-layout", root, "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := rig.count("fido2-assert") - before; got != 1 {
		t.Errorf("%d assertions for one export; one PIN and one touch", got)
	}
	if long := longPinRE.FindStringSubmatch(out); long == nil || long[1] != lp[1] || !strings.Contains(out, "signed with the checkpoint key") {
		t.Fatalf("%s", out)
	}
	files := readLayout(t, root)
	h, note, name := newestLayoutHead(t, files)
	sig, ok := files[name+".sig"]
	if !ok || h.CheckpointKey == nil {
		t.Fatalf("no signature, or the head names no key: %v", keys(files))
	}
	oracleVerifyHead(t, line[1], note, sig)
	// a flipped bit in the note does not verify
	bad := append([]byte(nil), note...)
	bad[len(bad)-3] ^= 1
	if sshKeygenOK(t, line[1], bad, sig) {
		t.Error("ssh-keygen accepted a changed note")
	}
	// unchanged: nothing is asked
	before = rig.count("fido2-assert")
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "convert", "--to-layout", root, "--checkpoint-device", dev2)
	if err != nil || rig.count("fido2-assert") != before || !strings.Contains(out, "already up to date") || !strings.Contains(out, "is signed") {
		t.Fatalf("%v\n%s", err, out)
	}
	// --no-checkpoint on a changed workspace: a new, unsigned head, no assertion
	if o, err := c.run(nil, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err = c.run(nil, "store", "convert", "--to-layout", root, "--no-checkpoint")
	if err != nil || rig.count("fido2-assert") != before || !strings.Contains(out, "--no-checkpoint") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, ok := readLayout(t, root)[layout.HeadPath(2)+".sig"]; ok {
		t.Error("head 2 has a signature")
	}
	// a signing failure writes no head: the authenticator is not there
	if o, err := c.run(nil, "pool", "vrf", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": "0"}, "store", "convert", "--to-layout", root, "--checkpoint-device", "/dev/fake-absent")
	if err == nil {
		t.Fatalf("signing with an absent authenticator succeeded:\n%s", out)
	}
	if !strings.Contains(err.Error(), "no head written") {
		t.Errorf("the error does not say no head was written: %v", err)
	}
	if h, _, _ := newestLayoutHead(t, readLayout(t, root)); h.Sequence != 2 {
		t.Errorf("a head was written after a signing failure: %d", h.Sequence)
	}
	// a re-run signs and completes, without putting the objects again
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "convert", "--to-layout", root, "--checkpoint-device", dev2)
	if err != nil || !strings.Contains(out, "0 reused") && !strings.Contains(out, "objects written") {
		t.Fatalf("%v\n%s", err, out)
	}
	if h, _, _ := newestLayoutHead(t, readLayout(t, root)); h.Sequence != 3 {
		t.Errorf("head %d", h.Sequence)
	}
}

func oracleVerifyHead(t *testing.T, pubLine string, note, sig []byte) {
	t.Helper()
	if !sshKeygenOK(t, pubLine, note, sig) {
		t.Fatal("stock ssh-keygen refused the head signature")
	}
}

func sshKeygenOK(t *testing.T, pubLine string, note, sig []byte) bool {
	t.Helper()
	kg := sshKeygenPath(t)
	dir := t.TempDir()
	sf := filepath.Join(dir, "head.sig")
	os.WriteFile(sf, sig, 0o600)
	allowed := filepath.Join(dir, "allowed_signers")
	os.WriteFile(allowed, []byte("operator namespaces=\""+layout.NamespaceHead+"\" "+pubLine+"\n"), 0o600)
	cmd := osexec.Command(kg, "-Y", "verify", "-f", allowed, "-I", "operator", "-n", layout.NamespaceHead, "-s", sf)
	cmd.Stdin = bytes.NewReader(note)
	out, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(out), "Good \""+layout.NamespaceHead+"\" signature for operator")
}

// countingRunner counts the calls the factor source makes of its tools.
type countingRunner struct {
	execx.Runner
	n       atomic.Int32
	asserts atomic.Int32 // calls of fido2-assert: one for each touch of the authenticator
}

func (c *countingRunner) Run(ctx context.Context, cmd execx.Cmd) (execx.Result, error) {
	c.n.Add(1)
	if filepath.Base(cmd.Path) == "fido2-assert" {
		c.asserts.Add(1)
	}
	return c.Runner.Run(ctx, cmd)
}

// A hardware workspace is exported with its daily authenticator; the recovery
// composite is refused before the authenticator is touched; the objects are
// sealed under the workspace's keys and carry no secret.
//
// spec: SPO-Xlayout-IF-001, SPO-Xlayout-PRE-013, SPO-Xlayout-OUT-014
func TestStoreConvertHardware(t *testing.T) {
	rig := newDeviceRunner(t)
	dir, recKey := toHardwareDR(t, rig)
	root := filepath.Join(t.TempDir(), "layout")
	counter := &countingRunner{Runner: rig}
	run := func(fds map[string]string, args ...string) (string, error) {
		t.Helper()
		full := []string{"-C", dir}
		for flag, content := range fds {
			f, fd := fdIn(t, content+"\n")
			defer f.Close()
			full = append(full, flag, fd)
		}
		return runFidoWith(t, counter, nil, append(full, args...)...)
	}
	// the recovery composite is refused, and no authenticator is touched
	out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN2}, "--unlock", "recovery-composite", "--fido2-device", dev1, "store", "convert", "--to-layout", root)
	if err == nil || !strings.Contains(err.Error(), "recovery-composite") {
		t.Fatalf("%v\n%s", err, out)
	}
	if counter.n.Load() != 0 {
		t.Errorf("the authenticator was called %d times for a refused command", counter.n.Load())
	}
	if _, err := os.Stat(root); err == nil {
		t.Error("the directory of a refused command was created")
	}
	callsBefore := counter.n.Load()
	out, err = run(map[string]string{"--fido2-pin-fd": fidoPIN}, "--fido2-device", dev0, "store", "convert", "--to-layout", root)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	exportCalls := counter.n.Load() - callsBefore
	// the export presents the authenticator exactly as one verification of the
	// workspace does: the keys are taken from the one verified copy, with no second
	// presentation
	callsBefore = counter.n.Load()
	if o, err := run(map[string]string{"--fido2-pin-fd": fidoPIN}, "--fido2-device", dev0, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if verifyCalls := counter.n.Load() - callsBefore; exportCalls != verifyCalls {
		t.Errorf("an export made %d calls of the factor tools, a verification %d", exportCalls, verifyCalls)
	}
	m := layoutPinRE.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "Layout written and read back") {
		t.Fatalf("%s", out)
	}
	files := readLayout(t, root)
	h, _, _ := newestLayoutHead(t, files)
	if h.Sequence != 1 || h.RecoveryKey == nil {
		t.Fatalf("%+v", h)
	}
	for p, b := range files {
		for _, s := range []string{testPass, recKey, strings.ReplaceAll(recKey, "-", ""), fidoPIN, fidoPIN2} {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%q is in %s", s, p)
			}
		}
	}
	// unchanged
	out, err = run(map[string]string{"--fido2-pin-fd": fidoPIN}, "--fido2-device", dev0, "store", "convert", "--to-layout", root)
	if err != nil || !strings.Contains(out, "already up to date") {
		t.Fatalf("%v\n%s", err, out)
	}
	// a passphrase does not open a hardware workspace for an export
	if o, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", filepath.Join(t.TempDir(), "x")); err == nil {
		t.Errorf("a passphrase exported a hardware workspace:\n%s", o)
	}
}

// A layout this machine has no pin for is not trusted silently: without a
// checkpoint key it needs --adopt-layout, which says what it trusts. A FIFO in the
// directory is refused before anything is asked.
//
// spec: SPO-Xlayout-PRE-019, SPO-Xlayout-PRE-018
func TestStoreConvertWithoutAPinNeedsAdoptLayout(t *testing.T) {
	dir := copyWorkspace(t)
	root := filepath.Join(t.TempDir(), "layout")
	if out, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", root); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	os.Remove(pinFileOf(t, dir))
	out, err := withPass(t, dir, testPass, "store", "convert", "--to-layout", root)
	if err == nil || !strings.Contains(err.Error(), "--adopt-layout") || !strings.Contains(err.Error(), "sequence 1") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = withPass(t, dir, testPass, "store", "convert", "--to-layout", root, "--adopt-layout")
	if err != nil || !strings.Contains(out, "already up to date") || !strings.Contains(out, "--adopt-layout") {
		t.Fatalf("%v\n%s", err, out)
	}
	pinFileOf(t, dir) // recorded again
	// a FIFO among the objects: refused before the passphrase is asked
	var victim string
	filepath.Walk(filepath.Join(root, "objects"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && victim == "" {
			victim = p
		}
		return nil
	})
	os.Remove(victim)
	if err := syscall.Mkfifo(victim, 0o600); err != nil {
		t.Skip(err)
	}
	term := &fakeTerm{}
	done := make(chan error, 1)
	go func() {
		_, err := exec(t, term, "-C", dir, "store", "convert", "--to-layout", root)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), filepath.Base(victim)) || len(term.asked) != 0 {
			t.Fatalf("%v asked %v", err, term.asked)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a FIFO in the layout hung the command")
	}
}
