package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
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
	notLeaked(t, all.String(), secretHex(t, dir, ports.NamedRef{Name: "c", Kind: ports.CalidusSKey}), "abandon abandon", "SigningKey")

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

// spec: SPO-09a-IF-004, SPO-09a-EXT-005, SPO-09a-OUT-007, SPO-09a-SEC-002, SPO-Xcustody-INV-001, SPO-Xcustody-IF-004
// `catalyst key qrcode` in the release binary draws the code on a terminal only:
// into a pipe it is refused, with or without --yes, before the PIN is read, and
// it writes no file, whatever flags the old file mode had.
func TestCatalystQRCodeThroughCommands(t *testing.T) {
	dir := copyWorkspace(t)
	var all strings.Builder
	stepOn(t, dir, &all, "catalyst", "key", "new", "v")
	wd := t.TempDir()
	t.Chdir(wd)
	for _, extra := range [][]string{nil, {"--yes"}} {
		f, fd := fdIn(t, "4821\n")
		out, err := withPass(t, dir, testPass, append([]string{"catalyst", "key", "qrcode", "v", "--pin-fd", fd}, extra...)...)
		f.Close()
		if err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Errorf("%v: %v\n%s", extra, err, out)
		}
		if strings.Contains(out, "█") || strings.Contains(out, "4821") {
			t.Errorf("the code or the PIN reached a pipe:\n%s", out)
		}
	}
	for _, fl := range []string{"--out", "--show"} {
		if out, err := withPass(t, dir, testPass, "catalyst", "key", "qrcode", "v", fl, "x.png"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%s: %v\n%s", fl, err, out)
		}
	}
	if ents, _ := os.ReadDir(wd); len(ents) != 0 {
		t.Errorf("a file was written: %v", ents)
	}
	notLeaked(t, all.String(), secretHex(t, dir, ports.NamedRef{Name: "v", Kind: ports.VotingSKey}), "SigningKey")
}
