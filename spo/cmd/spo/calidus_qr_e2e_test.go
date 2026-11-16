package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// spec: SPO-15-IF-006, SPO-15-EXT-006, SPO-15-OUT-006
// `pool calidus sign` prints the Calidus id, the public key and a plain Ed25519
// signature over the text; nothing secret is printed and nothing is written.
func TestCalidusSignThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	var all strings.Builder
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	mf, mfd := fdIn(t, abandonArt+"\n")
	defer mf.Close()
	if out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "pool", "calidus", "new", "c", "--mnemonic-in-fd", mfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out := stepOn(t, dir, &all, "pool", "calidus", "sign", "c", "hello pool")
	mustHave(t, out, calidusOfAbandonArt)
	pub := regexp.MustCompile(`public key\s+([0-9a-f]{64})`).FindStringSubmatch(out)
	sig := regexp.MustCompile(`signature\s+([0-9a-f]{128})`).FindStringSubmatch(out)
	if pub == nil || sig == nil {
		t.Fatalf("no public key or signature:\n%s", out)
	}
	pk, _ := hex.DecodeString(pub[1])
	sg, _ := hex.DecodeString(sig[1])
	if !ed25519.Verify(pk, []byte("hello pool"), sg) || ed25519.Verify(pk, []byte("hello pool."), sg) {
		t.Error("the signature is not a plain Ed25519 signature over the text")
	}
	notLeaked(t, all.String(), secretHex(t, dir, ports.Ref{Name: "c", Kind: ports.CalidusSKey}), "abandon abandon", "SigningKey")

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"pool", "calidus", "sign", "ghost", "x"}, "calidus.skey"},
		{[]string{"pool", "calidus", "sign", "../c", "x"}, "plain name"},
		{[]string{"pool", "calidus", "new", "hw", "--hardware"}, "cannot be held on a hardware wallet"},
	} {
		if out, err := withPass(t, dir, testPass, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v\n%s", tc.args, err, out)
		}
	}
}

// spec: SPO-09a-IF-004, SPO-09a-EXT-005, SPO-09a-OUT-007, SPO-09a-PRE-009, SPO-09a-PRE-010, SPO-09a-SEC-002
// `catalyst key qrcode` takes the PIN from a descriptor, writes a private PNG
// that it never overwrites, draws the code in the terminal only on request on a
// terminal (never into a pipe), and never prints the PIN or the key.
func TestCatalystQRCodeThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	var all strings.Builder
	stepOn(t, dir, &all, "catalyst", "key", "new", "v")
	png := filepath.Join(t.TempDir(), "v.catalyst-qrcode.png")

	pin := func(p string) []string {
		f, fd := fdIn(t, p+"\n")
		t.Cleanup(func() { f.Close() })
		return []string{"catalyst", "key", "qrcode", "v", "--pin-fd", fd, "--out", png}
	}
	out := stepOn(t, dir, &all, pin("4821")...)
	mustHave(t, out, "mode 0600", "key-equivalent")
	if strings.Contains(out, "█") {
		t.Error("the QR code was drawn by default, into a pipe")
	}
	if strings.Contains(out, "4821") {
		t.Error("the PIN was printed")
	}
	if st, err := os.Stat(png); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("png: %v %v", st, err)
	}
	notLeaked(t, all.String(), secretHex(t, dir, ports.Ref{Name: "v", Kind: ports.VotingSKey}), "SigningKey")

	// No overwrite, whatever the PIN.
	if out, err := withPass(t, dir, testPass, pin("1111")...); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("overwrite: %v\n%s", err, out)
	}
	// A bad PIN, a missing key and a PIN with nowhere to be read from.
	other := filepath.Join(t.TempDir(), "o.png")
	for _, p := range []string{"123", "12345", "12a4"} {
		f, fd := fdIn(t, p+"\n")
		if out, err := withPass(t, dir, testPass, "catalyst", "key", "qrcode", "v", "--pin-fd", fd, "--out", other); err == nil || !strings.Contains(err.Error(), "four digits") {
			t.Errorf("pin %q: %v\n%s", p, err, out)
		}
		f.Close()
	}
	f, fd := fdIn(t, "1234\n")
	defer f.Close()
	if out, err := withPass(t, dir, testPass, "catalyst", "key", "qrcode", "ghost", "--pin-fd", fd, "--out", other); err == nil || !strings.Contains(err.Error(), "voting.skey") {
		t.Errorf("missing key: %v\n%s", err, out)
	}
	if out, err := withPass(t, dir, testPass, "catalyst", "key", "qrcode", "v", "--out", other); err == nil || !strings.Contains(err.Error(), "--pin-fd") {
		t.Errorf("no PIN source: %v\n%s", err, out)
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("a refusal wrote a file")
	}
}
