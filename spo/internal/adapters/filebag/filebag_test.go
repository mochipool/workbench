package filebag

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

func open(t *testing.T, dir string) *Bag {
	t.Helper()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	b.SetPoll(10 * time.Millisecond)
	t.Cleanup(func() { b.Close() })
	return b
}

// The interface contract suite (concern T1).
func TestContract(t *testing.T) {
	porttest.Run(t, func(t *testing.T) porttest.Pair {
		b := open(t, t.TempDir())
		return porttest.Pair{Sender: b, Receiver: b, To: party.Fingerprint{1}, Via: ports.ViaFile}
	})
}

func recvNow(t *testing.T, b *Bag) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := b.Receive(ctx)
	if err != nil || got.Via() != ports.ViaFile {
		t.Fatalf("Receive = %v, %v", got.Via(), err)
	}
	return got.Envelope
}

func expectNothing(t *testing.T, b *Bag) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if got, err := b.Receive(ctx); err == nil {
		t.Fatalf("received %d bytes", len(got.Envelope))
	}
}

// spec: SPO-Xparty-IF-004
func TestWriteNamingModeAndAtomicity(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir)
	name := party.FileName(party.TypeSigningRequest, party.CollectionID{0xab, 0xcd, 0xef, 0x01}, 3)
	if err := b.Write(name, []byte("env")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, name))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat = %v, %v", st, err)
	}
	// No temporary file is left behind.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("directory has %d entries", len(ents))
	}
	// A failed write (over the limit) leaves nothing.
	if err := b.Write("big.spo", make([]byte, party.MaxEnvelopeBytes+1)); err == nil {
		t.Fatal("oversize write succeeded")
	}
	if ents, _ = os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("directory has %d entries after a refused write", len(ents))
	}
	if got := recvNow(t, b); string(got) != "env" {
		t.Fatalf("got %q", got)
	}
	// Delivered is not read: the file is marked only once it was handled.
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("a delivered file was moved before it was handled: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, name+".read")); err == nil {
		t.Fatal("marked read before Ack")
	}
	expectNothing(t, b) // not delivered twice by this process either
	if err := b.Ack(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, name+".read")); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, b)
}

// A file that was delivered and never acknowledged (the handler failed or the
// process died) is delivered again by the next bag on that directory.
// spec: SPO-Xparty-IF-004
func TestUnhandledFileIsDeliveredAgain(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir)
	if err := b.Write("a-one.spo", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if got := recvNow(t, b); string(got) != "one" {
		t.Fatalf("got %q", got)
	}
	b.Close()
	b2 := open(t, dir)
	if got := recvNow(t, b2); string(got) != "one" {
		t.Fatalf("after a restart got %q", got)
	}
	if err := b2.Ack(); err != nil {
		t.Fatal(err)
	}
	expectNothing(t, b2)
}

// A FIFO in the place of an envelope file does not block the bag, and is not
// delivered. The file is opened without blocking and the opened descriptor
// is checked.
// spec: SPO-Ptransfer-SEC-001
func TestFIFOIsRejectedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir)
	if err := syscall.Mkfifo(filepath.Join(dir, "a-fifo.spo"), 0o600); err != nil {
		t.Skip("no fifo")
	}
	if err := b.Write("b-ok.spo", []byte("fine")); err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() { done <- recvNow(t, b) }()
	select {
	case got := <-done:
		if string(got) != "fine" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bag blocked on a FIFO")
	}
	if r := b.Rejected(); len(r) != 1 || r[0].Name != "a-fifo.spo" {
		t.Fatalf("rejected = %+v", r)
	}
}

// The file transport states its own kind.
// spec: SPO-Xparty-PRE-004, SPO-Xparty-INV-024
func TestTransportKind(t *testing.T) {
	if k := open(t, t.TempDir()).Transport().Kind(); k != ports.ViaFile {
		t.Fatalf("kind = %v", k)
	}
}

// spec: SPO-Xparty-IF-004, SPO-Ptransfer-SEC-001
func TestNamesAreConfined(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	b := open(t, dir)
	for _, name := range []string{"../x.spo", "/etc/x.spo", "a/b.spo", "..spo", ".hidden.spo", "x", "x.txt", "", "a..b.spo", "a\\b.spo", strings.Repeat("a", 200) + ".spo"} {
		if err := b.Write(name, []byte("x")); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("wrote outside")
	}
}

// A symbolic link is never followed, on read or on write.
// spec: SPO-Ptransfer-SEC-001
func TestSymlinks(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	secretFile := filepath.Join(outside, "secret")
	os.WriteFile(secretFile, []byte("TOP SECRET"), 0o600)
	b := open(t, dir)

	// Read: a link to a file outside is refused and not read.
	if err := os.Symlink(secretFile, filepath.Join(dir, "evil.spo")); err != nil {
		t.Skip("symlinks unavailable")
	}
	// A link to a directory outside, and a dangling link.
	os.Symlink(outside, filepath.Join(dir, "dir.spo"))
	os.Symlink(filepath.Join(outside, "nope"), filepath.Join(dir, "dangling.spo"))
	expectNothing(t, b)
	if r := b.Rejected(); len(r) != 3 {
		t.Fatalf("rejected = %+v", r)
	}
	if got, _ := os.ReadFile(secretFile); string(got) != "TOP SECRET" {
		t.Fatal("target changed")
	}
	for _, n := range []string{"evil.spo", "dir.spo", "dangling.spo"} {
		if _, err := os.Lstat(filepath.Join(dir, n+".rejected")); err != nil {
			t.Fatalf("%s not set aside: %v", n, err)
		}
	}

	// Write: a link in the way is replaced, its target untouched.
	os.Symlink(secretFile, filepath.Join(dir, "target.spo"))
	if err := b.Write("target.spo", []byte("envelope")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(secretFile); string(got) != "TOP SECRET" {
		t.Fatal("write followed a link")
	}
	if st, _ := os.Lstat(filepath.Join(dir, "target.spo")); !st.Mode().IsRegular() {
		t.Fatal("link not replaced")
	}
}

// spec: SPO-Xparty-INV-008
func TestImportLimits(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir)
	os.WriteFile(filepath.Join(dir, "a-big.spo"), make([]byte, party.MaxEnvelopeBytes+1), 0o600)
	os.WriteFile(filepath.Join(dir, "b-empty.spo"), nil, 0o600)
	os.Mkdir(filepath.Join(dir, "c-dir.spo"), 0o700)
	os.WriteFile(filepath.Join(dir, "d-ok.spo"), []byte("fine"), 0o600)
	os.WriteFile(filepath.Join(dir, "ignored.txt"), []byte("nope"), 0o600)
	if got := recvNow(t, b); !bytes.Equal(got, []byte("fine")) {
		t.Fatalf("got %q", got)
	}
	if r := b.Rejected(); len(r) != 3 {
		t.Fatalf("rejected = %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "ignored.txt")); err != nil {
		t.Fatal("touched a file that is not an envelope")
	}
	expectNothing(t, b)
}

// A partly written file is never seen: writers rename into place.
func TestTempFilesAreInvisible(t *testing.T) {
	dir := t.TempDir()
	b := open(t, dir)
	os.WriteFile(filepath.Join(dir, ".tmp-1234"), []byte("half"), 0o600)
	expectNothing(t, b)
}
