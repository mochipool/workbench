package sshsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const app = "ssh:spo-checkpoint"
const ns = "spo/checkpoint/v1"

// softKey is a software stand-in for the authenticator: it signs what a FIDO2
// assertion signs.
type softKey struct {
	priv *ecdsa.PrivateKey
	key  Key
}

func newSoftKey(t *testing.T) softKey {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := p.PublicKey.Bytes()
	return softKey{p, Key{Q: q, Application: app}}
}

func (s softKey) assert(t *testing.T, signedData []byte, flags byte, counter uint32) Assertion {
	t.Helper()
	digest := sha256.Sum256(skSigned(s.key.Application, flags, counter, ClientDataHash(signedData)))
	der, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return Assertion{Flags: flags, Counter: counter, Signature: der}
}

func (s softKey) sign(t *testing.T, namespace string, msg []byte, flags byte, counter uint32) []byte {
	t.Helper()
	sd, err := SignedData(namespace, SHA512, msg)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Encode(s.key, namespace, SHA512, s.assert(t, sd, flags, counter))
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// spec: SPO-Xbackup-SEC-015
func TestSignedSignatureVerifies(t *testing.T) {
	k := newSoftKey(t)
	msg := []byte("spo/checkpoint/v1\nworkspace 00\n")
	blob := k.sign(t, ns, msg, FlagUP|FlagUV, 7)
	res, err := Verify(blob, msg, ns, k.key.Hash(), app)
	if err != nil {
		t.Fatal(err)
	}
	if res.Counter != 7 || res.Flags != FlagUP|FlagUV || !bytes.Equal(res.Key.Q, k.key.Q) {
		t.Fatalf("%+v", res)
	}
	back, err := Dearmor([]byte(Armor(blob)))
	if err != nil || !bytes.Equal(back, blob) {
		t.Fatalf("armor round trip: %v", err)
	}
	if _, err := ParseKeyBlob(k.key.Blob()); err != nil {
		t.Fatal(err)
	}
}

// Each way a signature can be wrong is refused.
//
// spec: SPO-Xbackup-SEC-015, SPO-Xbackup-SEC-016
func TestVerifyRefusals(t *testing.T) {
	k := newSoftKey(t)
	other := newSoftKey(t)
	msg := []byte("the statement\n")
	good := k.sign(t, ns, msg, FlagUP|FlagUV, 3)
	cases := []struct {
		name string
		blob []byte
		msg  []byte
		ns   string
		hash []byte
		want string
	}{
		{"wrong namespace", good, msg, "spo/other/v1", k.key.Hash(), "namespace"},
		{"signed under another namespace", k.sign(t, "spo/other/v1", msg, FlagUP|FlagUV, 3), msg, ns, k.key.Hash(), "namespace"},
		{"wrong key", good, msg, ns, other.key.Hash(), "expected key"},
		{"signature by another key under the expected hash", other.sign(t, ns, msg, FlagUP|FlagUV, 3), msg, ns, k.key.Hash(), "expected key"},
		{"no user presence", k.sign(t, ns, msg, FlagUV, 3), msg, ns, k.key.Hash(), "user-presence"},
		{"no user verification", k.sign(t, ns, msg, FlagUP, 3), msg, ns, k.key.Hash(), "user-verification"},
		{"tampered statement", good, []byte("the statement!\n"), ns, k.key.Hash(), "does not verify"},
		{"trailing bytes", append(append([]byte(nil), good...), 0), msg, ns, k.key.Hash(), "trailing"},
		{"empty namespace", good, msg, "", k.key.Hash(), "namespace"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(c.blob, c.msg, c.ns, c.hash, app)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error with %q", err, c.want)
			}
		})
	}
	if _, err := Verify(good, msg, ns, k.key.Hash(), "ssh:other"); err == nil {
		t.Error("another application was accepted")
	}
}

// The counter is signed: editing it in the blob breaks the signature.
//
// spec: SPO-Xbackup-SEC-016
func TestEditedCounterAndFlagsBreakTheSignature(t *testing.T) {
	k := newSoftKey(t)
	msg := []byte("m")
	blob := k.sign(t, ns, msg, FlagUP|FlagUV, 5)
	edited := append([]byte(nil), blob...)
	binary.BigEndian.PutUint32(edited[len(edited)-4:], 6)
	if _, err := Verify(edited, msg, ns, nil, ""); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("an edited counter: %v", err)
	}
	// a flag the authenticator did not set, added in the blob
	noUV := k.sign(t, ns, msg, FlagUP, 5)
	forged := append([]byte(nil), noUV...)
	forged[len(forged)-5] |= FlagUV
	if _, err := Verify(forged, msg, ns, nil, ""); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a forged UV flag: %v", err)
	}
}

func rebuild(t *testing.T, key Key, version uint32, namespace, reserved, alg string, sig []byte) []byte {
	t.Helper()
	b := []byte(magic)
	b = binary.BigEndian.AppendUint32(b, version)
	b = putString(b, key.Blob())
	b = putString(b, []byte(namespace))
	b = putString(b, []byte(reserved))
	b = putString(b, []byte(alg))
	return putString(b, sig)
}

// spec: SPO-Xbackup-SEC-016
func TestVerifyIsStrictAboutTheFraming(t *testing.T) {
	k := newSoftKey(t)
	msg := []byte("m")
	sd, _ := SignedData(ns, SHA512, msg)
	a := k.assert(t, sd, FlagUP|FlagUV, 1)
	r, s, _ := parseDER(a.Signature)
	sig := signatureBlob(r, s, a.Flags, a.Counter)
	if _, err := Verify(rebuild(t, k.key, 1, ns, "", "sha512", sig), msg, ns, nil, ""); err != nil {
		t.Fatalf("the rebuilt blob is the good one: %v", err)
	}
	for name, blob := range map[string][]byte{
		"version 2":          rebuild(t, k.key, 2, ns, "", "sha512", sig),
		"reserved not empty": rebuild(t, k.key, 1, ns, "x", "sha512", sig),
		"unknown hash":       rebuild(t, k.key, 1, ns, "", "md5", sig),
		"sha1":               rebuild(t, k.key, 1, ns, "", "sha1", sig),
		"signature trailing": rebuild(t, k.key, 1, ns, "", "sha512", append(append([]byte(nil), sig...), 9)),
		"truncated":          rebuild(t, k.key, 1, ns, "", "sha512", sig)[:20],
		"wrong preamble":     append([]byte("SSHSIX"), rebuild(t, k.key, 1, ns, "", "sha512", sig)[6:]...),
	} {
		if _, err := Verify(blob, msg, ns, nil, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the signature's own key type must be the sk type
	var bad []byte
	bad = putString(bad, []byte("ssh-ed25519"))
	bad = append(bad, sig[len(sig)-0:]...)
	if _, err := Verify(rebuild(t, k.key, 1, ns, "", "sha512", bad), msg, ns, nil, ""); err == nil {
		t.Error("a signature of another type was accepted")
	}
	// the key blob must be the sk-ecdsa type
	var edKey []byte
	edKey = putString(edKey, []byte("ssh-ed25519"))
	edKey = putString(edKey, make([]byte, 32))
	b := []byte(magic)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = putString(b, edKey)
	b = putString(b, []byte(ns))
	b = putString(b, nil)
	b = putString(b, []byte("sha512"))
	b = putString(b, sig)
	if _, err := Verify(b, msg, ns, nil, ""); err == nil || !strings.Contains(err.Error(), "key type") {
		t.Errorf("an ed25519 key: %v", err)
	}
}

func TestDearmorIsStrict(t *testing.T) {
	good := Armor([]byte("hello"))
	for name, text := range map[string]string{
		"no begin":    strings.Replace(good, ArmorBegin, "x", 1),
		"text before": "junk\n" + good,
		"text after":  good + "junk\n",
		"spaces":      strings.Replace(good, "aGVs", "aG Vs", 1),
		"empty":       "",
	} {
		if _, err := Dearmor([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- the oracle: stock OpenSSH ----

// sshKeygen finds ssh-keygen. Inside the Nix check (SPO_REQUIRE_SSH_KEYGEN set
// by the derivation) a missing tool is a failure; elsewhere the test skips.
func sshKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("SPO_REQUIRE_SSH_KEYGEN") != "" {
			t.Fatal("ssh-keygen is not on PATH, and SPO_REQUIRE_SSH_KEYGEN says the check must run it")
		}
		t.Skip("ssh-keygen is not installed")
	}
	return p
}

// A signature made by this package verifies with `ssh-keygen -Y verify`, for the
// key given as an allowed_signers line, and does not for another namespace or
// another message. Stock ssh-keygen has no way to require user verification
// (allowed_signers takes no verify-required option, -Y verify no such -O), so the
// UV check is this package's alone; the test records what ssh-keygen does with a
// signature that lacks a flag.
//
// spec: SPO-Xbackup-SEC-017
func TestOracleSSHKeygenVerifiesOurSignature(t *testing.T) {
	kg := sshKeygen(t)
	k := newSoftKey(t)
	msg := []byte("spo/checkpoint/v1\nworkspace aa\nsequence 4\n")
	dir := t.TempDir()
	sig := filepath.Join(dir, "msg.sig")
	if err := os.WriteFile(sig, []byte(Armor(k.sign(t, ns, msg, FlagUP|FlagUV, 9))), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "allowed_signers")
	line := "operator namespaces=\"" + ns + "\" " + k.key.AuthorizedLine() + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(namespace string, message []byte) (string, error) {
		cmd := exec.Command(kg, "-Y", "verify", "-f", allowed, "-I", "operator", "-n", namespace, "-s", sig)
		cmd.Stdin = bytes.NewReader(message)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(ns, msg); err != nil || !strings.Contains(out, "Good \""+ns+"\" signature for operator") || !strings.Contains(out, k.key.Fingerprint()) {
		t.Fatalf("ssh-keygen refused our signature: %v\n%s", err, out)
	}
	if out, err := run("spo/other/v1", msg); err == nil {
		t.Errorf("ssh-keygen accepted another namespace:\n%s", out)
	}
	if out, err := run(ns, append(msg, 'x')); err == nil {
		t.Errorf("ssh-keygen accepted another message:\n%s", out)
	}
	for name, flags := range map[string]byte{"no user presence": FlagUV, "no user verification": FlagUP} {
		os.WriteFile(sig, []byte(Armor(k.sign(t, ns, msg, flags, 9))), 0o600)
		out, err := run(ns, msg)
		// The how-to says stock OpenSSH's check is weaker than spo's: it accepts a
		// signature with either flag cleared. If this fails, OpenSSH now checks them.
		if err != nil || !strings.Contains(out, "Good \""+ns+"\" signature") {
			t.Errorf("OpenSSH changed: revisit the how-to. ssh-keygen -Y verify now refuses a signature with %s: %v %s", name, err, strings.TrimSpace(out))
		}
	}
	os.WriteFile(sig, []byte(Armor(k.sign(t, ns, msg, FlagUP|FlagUV, 9))), 0o600)
	// the fingerprint ssh-keygen prints is our key hash
	fp := filepath.Join(dir, "k.pub")
	os.WriteFile(fp, []byte(k.key.AuthorizedLine()+"\n"), 0o600)
	out, err := exec.Command(kg, "-lf", fp).CombinedOutput()
	if err != nil || !strings.Contains(string(out), k.key.Fingerprint()) {
		t.Errorf("the key hash is not ssh-keygen's fingerprint: %v\n%s", err, out)
	}
}

// A signature made by ssh-keygen with a plain key is refused for its type, and
// ssh-keygen's own plain signature parses far enough to say so.
//
// spec: SPO-Xbackup-SEC-017
func TestOracleAPlainKeySignatureIsRefusedForItsType(t *testing.T) {
	kg := sshKeygen(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "id")
	if out, err := exec.Command(kg, "-q", "-t", "ed25519", "-N", "", "-f", keyFile).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	msg := []byte("a message")
	data := filepath.Join(dir, "data")
	os.WriteFile(data, msg, 0o600)
	if out, err := exec.Command(kg, "-Y", "sign", "-f", keyFile, "-n", ns, data).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	armored, err := os.ReadFile(data + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := Dearmor(armored)
	if err != nil {
		t.Fatalf("our armor reader cannot read ssh-keygen's armor: %v", err)
	}
	_, err = Verify(blob, msg, ns, nil, "")
	if err == nil || !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "key type") {
		t.Fatalf("a plain ed25519 signature was not refused for its key type: %v", err)
	}
}

func withKeyBlob(keyBlob []byte, sig []byte) []byte {
	b := []byte(magic)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = putString(b, keyBlob)
	b = putString(b, []byte(ns))
	b = putString(b, nil)
	b = putString(b, []byte("sha512"))
	return putString(b, sig)
}

// The key blob, the inner integer blob and the armor are parsed strictly.
//
// spec: SPO-Xbackup-SEC-016
func TestKeyBlobIntegerBlobAndArmorStrictness(t *testing.T) {
	k := newSoftKey(t)
	msg := []byte("m")
	sd, _ := SignedData(ns, SHA512, msg)
	a := k.assert(t, sd, FlagUP|FlagUV, 1)
	r, s, _ := parseDER(a.Signature)
	sig := signatureBlob(r, s, a.Flags, a.Counter)
	if _, err := Verify(withKeyBlob(k.key.Blob(), sig), msg, ns, nil, ""); err != nil {
		t.Fatalf("the control blob: %v", err)
	}
	// key blob: trailing bytes, another curve name, a point not on the curve, a compressed point
	blob := k.key.Blob()
	offCurve := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	var wrongCurve []byte
	wrongCurve = putString(wrongCurve, []byte(KeyType))
	wrongCurve = putString(wrongCurve, []byte("nistp384"))
	wrongCurve = putString(wrongCurve, k.key.Q)
	wrongCurve = putString(wrongCurve, []byte(app))
	for name, kb := range map[string][]byte{
		"trailing bytes in the key blob": append(append([]byte(nil), blob...), 0),
		"another curve name":             wrongCurve,
		"a point off the curve":          Key{Q: offCurve, Application: app}.Blob(),
		"a compressed point":             Key{Q: append([]byte{2}, k.key.Q[1:33]...), Application: app}.Blob(),
	} {
		if _, err := Verify(withKeyBlob(kb, sig), msg, ns, nil, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the inner blob of the two integers: trailing bytes, a negative integer, a third integer
	rb, sb := mpint(r), mpint(s)
	mk := func(inner []byte) []byte {
		var b []byte
		b = putString(b, []byte(KeyType))
		b = putString(b, inner)
		b = append(b, a.Flags)
		return binary.BigEndian.AppendUint32(b, a.Counter)
	}
	two := putString(putString(nil, rb), sb)
	neg := putString(putString(nil, append([]byte{0x80}, rb[1:]...)), sb)
	for name, inner := range map[string][]byte{
		"trailing bytes in the integer blob": append(append([]byte(nil), two...), 0),
		"a third integer":                    putString(append([]byte(nil), two...), []byte{1}),
		"a negative integer":                 neg,
		"one integer":                        putString(nil, rb),
	} {
		if _, err := Verify(withKeyBlob(blob, mk(inner)), msg, ns, nil, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the armor: CRLF line ends, two blocks in one text, text between the lines
	good := Armor(withKeyBlob(blob, sig))
	if _, err := Dearmor([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"CRLF line ends":  strings.ReplaceAll(good, "\n", "\r\n"),
		"two blocks":      good + good,
		"a blank line":    strings.Replace(good, "\n", "\n\n", 1),
		"no final marker": strings.TrimSuffix(strings.TrimSuffix(good, "\n"), ArmorEnd),
	} {
		if _, err := Dearmor([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
