package relayconfig_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

func keyDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// init-key makes a private file of exactly the key form; a second create is
// refused and leaves the first key; the key loads back equal.
//
// spec: SPO-Xmailbox-SEC-077, SPO-Xmailbox-OUT-103
func TestAKeyIsCreatedPrivateOnceAndLoadsBack(t *testing.T) {
	p := filepath.Join(keyDir(t), "relay.key")
	k, err := relayconfig.CreateKey(p, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 || st.Size() != int64(relayconfig.KeyFileBytes) {
		t.Fatalf("mode %o size %d", st.Mode().Perm(), st.Size())
	}
	b, _ := os.ReadFile(p)
	if !bytes.HasPrefix(b, []byte("spo-relay-key-v1\nnode ")) || !bytes.Contains(b, []byte("\npsk ")) || !bytes.HasSuffix(b, []byte("\n")) {
		t.Fatalf("the key file %q", b)
	}
	got, err := relayconfig.LoadKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *k {
		t.Fatal("the loaded key differs from the created one")
	}
	if _, err := relayconfig.CreateKey(p, rand.Reader); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("a second create: %v", err)
	}
	again, _ := relayconfig.LoadKey(p)
	if *again != *k {
		t.Fatal("a refused create changed the key")
	}
	got.Destroy()
	if got.Node != [32]byte{} || got.PSK != [32]byte{} {
		t.Fatal("Destroy left key bytes")
	}
}

// A source of randomness that fails or gives zeros makes no key file.
//
// spec: SPO-Xmailbox-SEC-077
func TestABadRandomSourceMakesNoKey(t *testing.T) {
	d := keyDir(t)
	p := filepath.Join(d, "relay.key")
	if _, err := relayconfig.CreateKey(p, strings.NewReader("short")); err == nil {
		t.Fatal("a short random source made a key")
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed create left a file: %v", err)
	}
	if _, err := relayconfig.CreateKey(p, zeros{}); err == nil || !strings.Contains(err.Error(), "zero") {
		t.Fatalf("an all-zero key: %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused key left a file: %v", err)
	}
	if err := os.Chmod(d, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := relayconfig.CreateKey(p, rand.Reader); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("a key in a directory others can write: %v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

var _ io.Reader = zeros{}

func writeKey(t *testing.T, text string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(keyDir(t), "relay.key")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

const h64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func keyText(node, psk string) string {
	return "spo-relay-key-v1\nnode " + node + "\npsk " + psk + "\n"
}

// A key file is used only when it is a regular file of the user that nobody
// else can read, exactly 156 bytes, in exactly the form, with neither key zero.
//
// spec: SPO-Xmailbox-SEC-077
func TestAKeyFileIsUsedOnlyWhenPrivateAndExact(t *testing.T) {
	good := keyText(h64, strings.Repeat("ab", 32))
	if len(good) != relayconfig.KeyFileBytes {
		t.Fatalf("the form is %d bytes, the bound %d", len(good), relayconfig.KeyFileBytes)
	}
	if _, err := relayconfig.LoadKey(writeKey(t, good, 0o600)); err != nil {
		t.Fatalf("a good key: %v", err)
	}
	if _, err := relayconfig.LoadKey(writeKey(t, good, 0o400)); err != nil {
		t.Fatalf("a read-only key: %v", err)
	}
	for _, c := range []struct {
		name, text string
		perm       os.FileMode
		want       string
	}{
		{"group-readable", good, 0o640, "permission"},
		{"world-readable", good, 0o604, "permission"},
		{"one byte short", good[:len(good)-1], 0o600, "bytes"},
		{"one byte more", good + "\n", 0o600, "bytes"},
		{"another header", strings.Replace(good, "v1", "v2", 1), 0o600, "form"},
		{"upper-case hex", keyText(strings.ToUpper(h64), strings.Repeat("ab", 32)), 0o600, "form"},
		{"upper-case pre-shared key", keyText(h64, strings.Repeat("AB", 32)), 0o600, "form"},
		{"no final line feed", good[:len(good)-1] + "x", 0o600, "form"},
		{"lines swapped", "spo-relay-key-v1\npsk " + h64 + "\nnode " + strings.Repeat("ab", 32) + "\n", 0o600, "form"},
		{"CRLF", strings.ReplaceAll(good, "\n", "\r")[:len(good)], 0o600, "form"},
		{"zero node key", keyText(strings.Repeat("0", 64), h64), 0o600, "zero"},
		{"zero pre-shared key", keyText(h64, strings.Repeat("0", 64)), 0o600, "zero"},
	} {
		if _, err := relayconfig.LoadKey(writeKey(t, c.text, c.perm)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// the decoder checks the length itself, not only the loader
	for _, b := range []string{good[:len(good)-1], good + "\n", good[:100], ""} {
		if _, err := relayconfig.DecodeKey([]byte(b)); err == nil || !strings.Contains(err.Error(), "bytes") {
			t.Errorf("DecodeKey of %d bytes: %v", len(b), err)
		}
	}
	p := writeKey(t, good, 0o600)
	me := os.Geteuid()
	restore := relayconfig.SetEuid(func() int { return me + 1 })
	_, err := relayconfig.LoadKey(p)
	restore()
	if err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Errorf("a key of another user: %v", err)
	}
	if _, err := relayconfig.LoadKey(filepath.Dir(p)); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("a directory: %v", err)
	}
	if _, err := relayconfig.LoadKey(filepath.Join(filepath.Dir(p), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing key: %v", err)
	}
	fifo := filepath.Join(filepath.Dir(p), "fifo")
	if err := mkfifo(fifo); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := relayconfig.LoadKey(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO loaded as a key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadKey waited on a FIFO")
	}
}

// The encoding round-trips and is the only one: what decodes encodes to the
// same bytes.
//
// spec: SPO-Xmailbox-SEC-077
func FuzzDecodeKey(f *testing.F) {
	f.Add([]byte(keyText(h64, strings.Repeat("ab", 32))))
	f.Add([]byte(keyText(strings.Repeat("0", 64), h64)))
	f.Add([]byte("spo-relay-key-v1\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := relayconfig.DecodeKey(b)
		if err != nil {
			return
		}
		if !bytes.Equal(relayconfig.EncodeKey(k), b) {
			t.Fatalf("%q decodes but encodes as %q", b, relayconfig.EncodeKey(k))
		}
		if k.Valid() != nil {
			t.Fatal("a zero key decoded")
		}
		var _ relayconf.Key = *k
	})
}
