package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/test/fakes3"
)

var pinRE = regexp.MustCompile(`(?m)^Pin: (\S+)$`)

func pinOf(t *testing.T, out string) string {
	t.Helper()
	m := pinRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no pin line in:\n%s", out)
	}
	return m[1]
}

// sinkEnv points the SDK's own configuration at a fake S3 on 127.0.0.1 with
// short-lived credentials from a credential_process (a source the adapter
// accepts), and returns the fake.
func sinkEnv(t *testing.T) *fakes3.Server {
	t.Helper()
	srv := fakes3.New("bk")
	t.Cleanup(srv.Close)
	tmp := t.TempDir()
	ca, err := srv.CABundle(tmp) // the fake is https with a throw-away certificate
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(tmp, "creds.sh")
	os.WriteFile(script, []byte("#!/bin/sh\necho '{\"Version\":1,\"AccessKeyId\":\"AKIAFAKETEST\",\"SecretAccessKey\":\"fake-secret\",\"SessionToken\":\"fake-token\",\"Expiration\":\"'$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)'\"}'\n"), 0o700)
	cfg := filepath.Join(tmp, "config")
	os.WriteFile(cfg, []byte("[default]\nregion = us-test-1\ncredential_process = "+script+"\n"), 0o600)
	for k, v := range map[string]string{
		"AWS_CONFIG_FILE": cfg, "AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_ENDPOINT_URL": srv.URL, "AWS_CA_BUNDLE": ca,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": "", "AWS_SESSION_TOKEN": "", "AWS_PROFILE": "", "AWS_REGION": "",
	} {
		t.Setenv(k, v)
	}
	return srv
}

func noLeftovers(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".spo-") || strings.HasPrefix(e.Name(), ".restore-") {
			t.Errorf("leftover %s in %s", e.Name(), dir)
		}
	}
}

// A standard workspace goes to a directory sink and comes back with a pin, into
// a fresh directory; the warning of a standard backup is printed.
//
// spec: SPO-Xbackup-PRE-003, SPO-Xbackup-PRE-005, SPO-Xbackup-PRE-006, SPO-Xbackup-PRE-008, SPO-Xbackup-OUT-003, SPO-Xbackup-OUT-004, SPO-Xbackup-OUT-005
func TestBackupSinkDirStandardRoundTrip(t *testing.T) {
	dir := copyWorkspace(t)
	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	out, err := withPass(t, dir, testPass, "store", "backup", "--sink", url)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "standard policy") || !strings.Contains(out, "rotate --policy hardware") {
		t.Errorf("no standard warning:\n%s", out)
	}
	pin := pinOf(t, out)
	if !strings.Contains(out, "somewhere other than the sink") {
		t.Errorf("no sentence about the pin:\n%s", out)
	}
	noLeftovers(t, dir)
	list, err := exec(t, nil, "-C", dir, "store", "backups", "--sink", url)
	if err != nil || !strings.Contains(list, "sequence ") || !strings.Contains(list, "backups/") {
		t.Fatalf("%v\n%s", err, list)
	}
	// restore into a fresh directory
	fresh := t.TempDir()
	out, err = withPass(t, fresh, testPass, "store", "restore", "--sink", url, "--pin", pin, "--network", "preview")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Restored") {
		t.Fatalf("%s", out)
	}
	noLeftovers(t, fresh)
	if out, err := withPass(t, fresh, testPass, "store", "verify"); err != nil {
		t.Fatalf("the restored workspace does not verify: %v\n%s", err, out)
	}
	// a pin with a wrong field is refused and changes nothing
	fresh2 := t.TempDir()
	f := strings.Split(pin, ":")
	for i, repl := range map[int]string{1: "999", 2: strings.Repeat("0", 63) + "f", 3: strings.Repeat("0", 64)} {
		g := append([]string(nil), f...)
		g[i] = repl
		if out, err := withPass(t, fresh2, testPass, "store", "restore", "--sink", url, "--pin", strings.Join(g, ":"), "--network", "preview"); err == nil {
			t.Fatalf("a wrong pin (field %d) restored:\n%s", i, out)
		}
	}
	if exists(filepath.Join(fresh2, "workspace.spo")) {
		t.Fatal("a workspace file was written")
	}
	noLeftovers(t, fresh2)
	// exactly one of <dest> and --sink; a pin is required
	if _, err := withPass(t, dir, testPass, "store", "backup", filepath.Join(t.TempDir(), "x"), "--sink", url); err == nil {
		t.Error("both <dest> and --sink accepted")
	}
	if _, err := withPass(t, dir, testPass, "store", "backup"); err == nil {
		t.Error("neither <dest> nor --sink accepted")
	}
	if _, err := withPass(t, fresh2, testPass, "store", "restore", "--sink", url, "--network", "preview"); err == nil || !strings.Contains(err.Error(), "--pin") {
		t.Errorf("a restore without a pin: %v", err)
	}
}

// The counter rule through the commands: a workspace that issued operational
// certificates after a backup is restored from the sink with --allow-older, and
// the next certificate it issues takes the live counter, not the backup's.
//
// spec: SPO-Xbackup-PRE-007, SPO-Xbackup-PRE-011
func TestRestoreFromSinkAllowOlderNeverLowersTheOpCertCounter(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	step := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	step("pool", "keys", "generate", poolName)
	step("pool", "vrf", "generate", poolName)
	step("pool", "kes", "generate", poolName)
	step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis) // counter 0
	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	pin := pinOf(t, step("store", "backup", "--sink", url))
	// two more certificates after the backup: the workspace's counter is 3
	for i := 1; i <= 2; i++ {
		step("pool", "kes", "generate", poolName)
		out := step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
		if !strings.Contains(out, "with counter "+strconv.Itoa(i)) {
			t.Fatalf("%s", out)
		}
	}
	// without --allow-older the older backup is refused, as before
	if _, err := withPass(t, dir, testPass, "store", "restore", "--sink", url, "--pin", pin, "--force"); err == nil {
		t.Fatal("an older backup replaced the workspace without --allow-older")
	}
	out := step("store", "restore", "--sink", url, "--pin", pin, "--force", "--allow-older")
	if !strings.Contains(out, "carried forward") || !strings.Contains(out, "node.counter") || !strings.Contains(out, "is 3 in the replaced workspace") {
		t.Fatalf("the restore did not say what it carried:\n%s", out)
	}
	noLeftovers(t, dir)
	step("store", "verify")
	// the restored workspace issues with the live counter plus one, not the backup's,
	// and generates the next KES number, not one already used
	if gen := step("pool", "kes", "generate", poolName); !strings.Contains(gen, "Generated KES key 003") {
		t.Fatalf("the KES number after the restore is not the next one:\n%s", gen)
	}
	out = step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	if !strings.Contains(out, "node-003.opcert with counter 3") {
		t.Fatalf("the certificate after the restore does not take the live counter:\n%s", out)
	}
}

// A standard workspace is refused an S3 sink before any network call, and
// before the passphrase is asked.
//
// spec: SPO-Xbackup-PRE-001
func TestStandardWorkspaceToS3IsRefusedBeforeAnyRequest(t *testing.T) {
	srv := sinkEnv(t)
	dir := copyWorkspace(t)
	out, err := exec(t, nil, "-C", dir, "store", "backup", "--sink", "s3://bk/pfx") // no passphrase offered
	if err == nil || !strings.Contains(err.Error(), "spo workspace rotate --policy hardware") || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("%v\n%s", err, out)
	}
	if n := len(srv.Requests()); n != 0 || srv.Puts() != 0 {
		t.Fatalf("%d requests reached the bucket: %v", n, srv.Requests())
	}
}

// A hardware workspace, with the repository's FIDO2 fake: to a directory sink,
// and to a fake S3 through the SDK's real credential chain (a credential_process
// with an expiry); fetched back into a fresh directory.
//
// spec: SPO-Xbackup-PRE-002, SPO-Xbackup-PRE-003, SPO-Xbackup-OUT-003, SPO-Xbackup-OUT-005
func TestBackupSinkHardwareDirAndS3RoundTrip(t *testing.T) {
	rig := newFidoRig(t, "seed-sink", "")
	dir, _ := toHardware(t, rig)
	srv := sinkEnv(t)
	sinkDir := filepath.Join(t.TempDir(), "sink")
	run := func(d string, args ...string) (string, error) {
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		return runFido(t, rig, nil, append([]string{"-C", d, "--fido2-device", dev0, "--fido2-pin-fd", fd}, args...)...)
	}
	outDir, err := run(dir, "store", "backup", "--sink", "dir:"+sinkDir)
	if err != nil {
		t.Fatalf("%v\n%s", err, outDir)
	}
	if strings.Contains(outDir, "standard policy") {
		t.Error("a hardware backup printed the standard warning")
	}
	outS3, err := run(dir, "store", "backup", "--sink", "s3://bk/pfx")
	if err != nil {
		t.Fatalf("%v\n%s", err, outS3)
	}
	pinS3 := pinOf(t, outS3)
	if len(srv.Keys()) != 1 || !strings.HasPrefix(srv.Keys()[0], "pfx/backups/") {
		t.Fatalf("keys %v", srv.Keys())
	}
	if srv.UnconditionalPuts() != 0 {
		t.Error("a put without If-None-Match")
	}
	if l, err := exec(t, nil, "-C", dir, "store", "backups", "--sink", "s3://bk/pfx"); err != nil || !strings.Contains(l, "sequence") {
		t.Fatalf("%v\n%s", err, l)
	}
	noLeftovers(t, dir)

	for name, c := range map[string][2]string{"dir": {"dir:" + sinkDir, pinOf(t, outDir)}, "s3": {"s3://bk/pfx", pinS3}} {
		fresh := t.TempDir()
		if out, err := run(fresh, "store", "restore", "--sink", c[0], "--pin", c[1], "--network", "preview"); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		if p := policyOf(t, fresh); p != "hardware" {
			t.Errorf("%s: policy %q", name, p)
		}
		noLeftovers(t, fresh)
	}
}

// Fault injection through the whole stack: the read-back fails after the upload
// (non-zero exit, "uploaded but not verified"), and the re-run verifies the
// object without uploading it again; a download cut in the middle leaves a
// private partial file and the re-run resumes it.
//
// spec: SPO-Xbackup-OUT-006, SPO-Xbackup-OUT-007, SPO-Xbackup-OUT-009, SPO-Xbackup-INV-001
func TestBackupSinkInterruptionsThroughTheCommands(t *testing.T) {
	rig := newFidoRig(t, "seed-sink-faults", "")
	dir, _ := toHardware(t, rig)
	srv := sinkEnv(t)
	run := func(d string, args ...string) (string, error) {
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		return runFido(t, rig, nil, append([]string{"-C", d, "--fido2-device", dev0, "--fido2-pin-fd", fd}, args...)...)
	}
	srv.Inject(fakes3.FaultGetBeforeResponse, 50)
	out, err := run(dir, "store", "backup", "--sink", "s3://bk/pfx")
	if err == nil || !strings.Contains(err.Error(), "uploaded but not verified") || !strings.Contains(err.Error(), "without uploading it again") {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(srv.Keys()) != 1 || srv.Puts() != 1 {
		t.Fatalf("%v %d", srv.Keys(), srv.Puts())
	}
	noLeftovers(t, dir)
	srv.Inject(fakes3.FaultGetBeforeResponse, 0)
	out, err = run(dir, "store", "backup", "--sink", "s3://bk/pfx")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if srv.Puts() != 1 || len(srv.Keys()) != 1 {
		t.Fatalf("the re-run uploaded again: %d puts, %v", srv.Puts(), srv.Keys())
	}
	pin := pinOf(t, out)

	// a download cut in the middle
	fresh := t.TempDir()
	srv.Inject(fakes3.FaultMidDownload, 1)
	out, err = run(fresh, "store", "restore", "--sink", "s3://bk/pfx", "--pin", pin, "--network", "preview")
	if err == nil || !strings.Contains(err.Error(), "can be run again") {
		t.Fatalf("%v\n%s", err, out)
	}
	if exists(filepath.Join(fresh, "workspace.spo")) {
		t.Fatal("a workspace was installed from a cut download")
	}
	partials, _ := filepath.Glob(filepath.Join(fresh, ".spo-fetch-*.partial"))
	if len(partials) != 1 {
		t.Fatalf("partial files: %v", partials)
	}
	if st, _ := os.Stat(partials[0]); st.Mode().Perm() != 0o600 {
		t.Errorf("partial file mode %o", st.Mode().Perm())
	}
	out, err = run(fresh, "store", "restore", "--sink", "s3://bk/pfx", "--pin", pin, "--network", "preview")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	noLeftovers(t, fresh)
	var ranged bool
	for _, r := range srv.Requests() {
		ranged = ranged || strings.HasPrefix(r, "GET /bk/pfx/backups/")
	}
	if !ranged {
		t.Error("no download request seen")
	}
}

// Two `store backup` runs of an unchanged workspace: are the files
// byte-identical? The answer decides whether a re-run can recognise its object
// by hash alone (ADR 0012 implementation notes).
func TestTwoBackupsOfAnUnchangedWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	for _, d := range []string{a, b} {
		if out, err := withPass(t, dir, testPass, "store", "backup", d); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	x, _ := os.ReadFile(a)
	y, _ := os.ReadFile(b)
	t.Logf("two backups of an unchanged workspace byte-identical: %v (%d bytes)", bytes.Equal(x, y), len(x))
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func getsOf(srv *fakes3.Server) int {
	n := 0
	for _, r := range srv.Requests() {
		if strings.HasPrefix(r, "GET /bk/pfx/backups/") {
			n++
		}
	}
	return n
}

// F3: every rule about the sink is checked before the workspace is unlocked: no
// factor source call, no prompt and no byte of the PIN descriptor is used when
// the bucket is refused.
//
// spec: SPO-Xbackup-PRE-002
func TestSinkRefusalsComeBeforeAnyUnlock(t *testing.T) {
	cases := []struct {
		name string
		set  func(srv *fakes3.Server)
		want string
	}{
		{"unversioned", func(s *fakes3.Server) { s.Versioning = "" }, "versioning"},
		{"no object lock", func(s *fakes3.Server) { s.LockOff = true }, "Object Lock"},
		{"governance", func(s *fakes3.Server) { s.LockMode = "GOVERNANCE" }, "COMPLIANCE"},
		{"static credentials", func(s *fakes3.Server) {
			t.Setenv("AWS_CONFIG_FILE", "/dev/null")
			t.Setenv("AWS_ACCESS_KEY_ID", "AKIASTATICKEY")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "static-secret")
			t.Setenv("AWS_REGION", "us-test-1")
		}, "short-lived"},
	}
	for _, c := range cases {
		rig := newFidoRig(t, "seed-refusal-"+c.name, "")
		dir, _ := toHardware(t, rig)
		srv := sinkEnv(t)
		c.set(srv)
		callsBefore := rig.calls()
		f, fd := fdIn(t, fidoPIN+"\n")
		term := &fakeTerm{}
		out, err := runFido(t, rig, term, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", fd, "store", "backup", "--sink", "s3://bk/pfx")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v\n%s", c.name, err, out)
		}
		if rig.calls() != callsBefore {
			t.Errorf("%s: the factor source was called %d times", c.name, rig.calls()-callsBefore)
		}
		if len(term.asked) != 0 {
			t.Errorf("%s: the terminal was asked: %v", c.name, term.asked)
		}
		if pos, _ := f.Seek(0, 1); pos != 0 {
			t.Errorf("%s: the PIN descriptor was read (offset %d)", c.name, pos)
		}
		if srv.Puts() != 0 {
			t.Errorf("%s: a write reached the bucket", c.name)
		}
		f.Close()
	}
}

// F2: a name a sink chose never reaches the terminal raw.
//
// spec: SPO-Xbackup-SEC-014
func TestBackupsListingEscapesSinkChosenNames(t *testing.T) {
	dir := copyWorkspace(t)
	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	if out, err := withPass(t, dir, testPass, "store", "backup", "--sink", url); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ents, _ := os.ReadDir(filepath.Join(sink, "backups"))
	wsDir := filepath.Join(sink, "backups", ents[0].Name())
	os.WriteFile(filepath.Join(wsDir, "\x1b]0;pwned\x07\x1b[2Jevil\rhidden.spo"), []byte("x"), 0o600)
	out, err := exec(t, nil, "-C", dir, "store", "backups", "--sink", url)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.ContainsAny(out, "\x1b\r\x07") {
		t.Fatalf("a control character reached the output: %q", out)
	}
	if !strings.Contains(out, "unrecognised") || !strings.Contains(out, "evil") {
		t.Fatalf("the planted name is not listed as unrecognised: %q", out)
	}
}

// F4: a planted symbolic link at the partial file's name is unlinked, never
// written through, and the download starts again.
//
// spec: SPO-Xbackup-SEC-008
func TestFetchReplacesAPlantedPartialSymlink(t *testing.T) {
	dir := copyWorkspace(t)
	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	out, err := withPass(t, dir, testPass, "store", "backup", "--sink", url)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pin := pinOf(t, out)
	sha := strings.Split(pin, ":")[3]
	fresh := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("precious"), 0o600)
	if err := os.Symlink(victim, filepath.Join(fresh, ".spo-fetch-"+sha+".partial")); err != nil {
		t.Fatal(err)
	}
	if out, err := withPass(t, fresh, testPass, "store", "restore", "--sink", url, "--pin", pin, "--network", "preview"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Fatalf("the link's target was written: %q", b)
	}
	noLeftovers(t, fresh)
}

// F10: flag combinations that can be checked without the file are refused
// before any download; a refusal that is not about the file (a wrong PIN) keeps
// the verified download so that a re-run does not download it again; a refusal
// about the content (a weaker policy) deletes it.
//
// spec: SPO-Xbackup-OUT-010
func TestRestoreFromSinkChecksFlagsFirstAndKeepsAVerifiedFileForWrongPIN(t *testing.T) {
	rig := newFidoRig(t, "seed-keep", "")
	dir, _ := toHardware(t, rig)
	srv := sinkEnv(t)
	run := func(d, pinText string, args ...string) (string, error) {
		f, fd := fdIn(t, pinText+"\n")
		defer f.Close()
		return runFido(t, rig, nil, append([]string{"-C", d, "--fido2-device", dev0, "--fido2-pin-fd", fd}, args...)...)
	}
	out, err := run(dir, fidoPIN, "store", "backup", "--sink", "s3://bk/pfx")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pin := pinOf(t, out)
	sha := strings.Split(pin, ":")[3]
	// before any download
	before := getsOf(srv)
	if _, err := run(dir, fidoPIN, "store", "restore", "--sink", "s3://bk/pfx", "--pin", pin); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("an existing workspace without --force: %v", err)
	}
	fresh := t.TempDir()
	if _, err := run(fresh, fidoPIN, "store", "restore", "--sink", "s3://bk/pfx", "--pin", pin, "--allow-weaker-policy", "--network", "preview"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("--allow-weaker-policy without --force: %v", err)
	}
	if getsOf(srv) != before {
		t.Fatalf("a download happened before the flags were checked")
	}
	// a wrong PIN after the download: refused, the verified file is kept
	if _, err := run(fresh, "000000", "store", "restore", "--sink", "s3://bk/pfx", "--pin", pin, "--network", "preview"); err == nil {
		t.Fatal("a wrong PIN restored")
	}
	partial := filepath.Join(fresh, ".spo-fetch-"+sha+".partial")
	if !exists(partial) {
		t.Fatal("the verified download was not kept after a refusal that is not about the file")
	}
	gets := getsOf(srv)
	if _, err := run(fresh, fidoPIN, "store", "restore", "--sink", "s3://bk/pfx", "--pin", pin, "--network", "preview"); err != nil {
		t.Fatal(err)
	}
	if getsOf(srv) != gets {
		t.Fatalf("the re-run downloaded again (%d GETs, was %d)", getsOf(srv), gets)
	}
	noLeftovers(t, fresh)

	// a content refusal: a standard backup over a hardware workspace
	std := copyWorkspace(t)
	sink := filepath.Join(t.TempDir(), "sink")
	o, err := withPass(t, std, testPass, "store", "backup", "--sink", "dir:"+sink)
	if err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	pinStd := pinOf(t, o)
	if _, err := run(dir, fidoPIN, "store", "restore", "--sink", "dir:"+sink, "--pin", pinStd, "--force", "--allow-older"); err == nil {
		t.Fatal("a weaker backup replaced a hardware workspace")
	}
	noLeftovers(t, dir)
}

// The pin's head MAC length is the store's audit MAC length.
//
// spec: SPO-Xbackup-OUT-002
func TestPinMACSizeIsTheStoresMACSize(t *testing.T) {
	if backupsink.HeadMACSize != seal.MACSize {
		t.Fatalf("pin %d, store %d", backupsink.HeadMACSize, seal.MACSize)
	}
}
