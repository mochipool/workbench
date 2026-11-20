package relayconfig

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/platform/mountfile"
)

// The relay's key file (SPO-Xmailbox-SEC-077): three lines,
//
//	spo-relay-key-v1
//	node <64 lower-case hex digits: the node private key>
//	psk <64 lower-case hex digits: the pre-shared key>
//
// each ended by a line feed, 156 bytes in all. It is not a party secret and the
// relay links no store encryption, so the file system protects it: it is made
// with O_EXCL and mode 0600, and read only when it is a regular file of the
// effective user with no group or other permission bit.
const (
	keyHeader = "spo-relay-key-v1\n"
	// KeyFileBytes is the exact size of a key file.
	KeyFileBytes = len(keyHeader) + len("node \n") + 2*relayconf.KeyLen + len("psk \n") + 2*relayconf.KeyLen
)

// EncodeKey is the bytes of the key file.
func EncodeKey(k *relayconf.Key) []byte {
	var b bytes.Buffer
	b.Grow(KeyFileBytes)
	b.WriteString(keyHeader)
	b.WriteString("node ")
	b.WriteString(hex.EncodeToString(k.Node[:]))
	b.WriteString("\npsk ")
	b.WriteString(hex.EncodeToString(k.PSK[:]))
	b.WriteString("\n")
	return b.Bytes()
}

// DecodeKey reads the bytes of a key file strictly: exactly the form, lower-case
// hex, neither key zero.
func DecodeKey(b []byte) (*relayconf.Key, error) {
	if len(b) != KeyFileBytes {
		return nil, bad("the key file is %d bytes; a key file is %d", len(b), KeyFileBytes)
	}
	k := &relayconf.Key{}
	rest, ok := bytes.CutPrefix(b, []byte(keyHeader+"node "))
	if ok {
		ok = lowerHex(rest[:64], k.Node[:])
		rest = rest[64:]
	}
	if ok {
		rest, ok = bytes.CutPrefix(rest, []byte("\npsk "))
	}
	if ok {
		ok = lowerHex(rest[:64], k.PSK[:]) && string(rest[64:]) == "\n"
	}
	if !ok {
		k.Destroy()
		return nil, bad("the key file is not in the form of a relay key (spo-relay-key-v1, then node and psk in lower-case hex)")
	}
	if err := k.Valid(); err != nil {
		k.Destroy()
		return nil, err
	}
	return k, nil
}

// lowerHex decodes exactly 2*len(dst) lower-case hex digits.
func lowerHex(src, dst []byte) bool {
	if len(src) != 2*len(dst) {
		return false
	}
	for _, c := range src {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	_, err := hex.Decode(dst, src)
	return err == nil
}

// rootUID is the uid of a root-owned key (a test's seam); readMounted reads one
// by the rules of a mounted Secret (platform/mountfile Key).
var (
	rootUID     = 0
	readMounted = func(path string) ([]byte, error) { return mountfile.Read(path, mountfile.Key(int64(KeyFileBytes))) }
)

// rootOwned reports whether a key file is the Secret volume's form (ADR 0015
// decision 6, source 1): owned by root while the relay is not root.
func rootOwned(st os.FileInfo) bool { return fileUID(st) == rootUID && rootUID != geteuid() }

// loadMounted reads a root-owned key file by the mounted-Secret rules.
func loadMounted(path string) (*relayconf.Key, error) {
	b, err := readMounted(path)
	if err != nil {
		return nil, fmt.Errorf("%w: key_file: %w", ErrConfig, err)
	}
	defer clear(b)
	return DecodeKey(b)
}

// LoadKey reads the relay's key file. A file of the effective user is refused
// unless it is a regular file with no group or other permission bit and of
// exactly KeyFileBytes, checked on the opened descriptor before it is read; a
// link is followed, a FIFO is refused without being waited on. A file of root
// is the Secret volume of a cluster (ADR 0015 decision 6, source 1) and is
// read by platform/mountfile's Key rule instead: only through kubelet's layout
// (a link only to "..<date>/<name>" in the same directory; a plain root-owned
// file on a host, or a subPath mount, is refused with the remedy: chown it to
// the relay's user, mode 0400), mode 0400 or 0440 with the group the relay's
// effective group, the directory root's (sticky if others may write it). A
// missing file is an error that satisfies os.ErrNotExist.
func LoadKey(path string) (*relayconf.Key, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if rootOwned(st) {
		f.Close()
		return loadMounted(path)
	}
	if err := keyMode(path, st); err != nil {
		return nil, err
	}
	if st.Size() != int64(KeyFileBytes) {
		return nil, bad("the key file %s is %d bytes; a key file is %d", path, st.Size(), KeyFileBytes)
	}
	buf := make([]byte, KeyFileBytes+1)
	defer clear(buf)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	return DecodeKey(buf[:n])
}

// CreateKey makes a new key from rnd and writes it to path, which must not
// exist, with mode 0600, in a directory owned by the user or by root that its
// group and others cannot write. A failure leaves no file.
func CreateKey(path string, rnd io.Reader) (*relayconf.Key, error) {
	if err := checkParent("key_file", filepath.Dir(path)); err != nil {
		return nil, err
	}
	k := &relayconf.Key{}
	if _, err := io.ReadFull(rnd, k.Node[:]); err != nil {
		return nil, fmt.Errorf("%w: no random bytes for the key: %w", ErrConfig, err)
	}
	if _, err := io.ReadFull(rnd, k.PSK[:]); err != nil {
		k.Destroy()
		return nil, fmt.Errorf("%w: no random bytes for the key: %w", ErrConfig, err)
	}
	if err := k.Valid(); err != nil {
		k.Destroy()
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if errors.Is(err, os.ErrExist) {
		k.Destroy()
		return nil, bad("the key file %s exists; a relay key is made once (remove it only to give the relay a new address, which every device must be told)", path)
	}
	if err != nil {
		k.Destroy()
		return nil, err
	}
	b := EncodeKey(k)
	defer clear(b)
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		k.Destroy()
		return nil, werr
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		d.Sync() //nolint:errcheck // the directory entry; the file itself is synced
		d.Close()
	}
	return k, nil
}
