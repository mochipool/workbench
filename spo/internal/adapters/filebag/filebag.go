// Package filebag is the file transport (SPO-Xparty-IF-004, MODE-001): an
// envelope per file in one directory. It implements ports.EnvelopeSender and
// ports.EnvelopeReceiver and reports every envelope it reads as arriving by
// file.
//
// Hazards (SPO-Ptransfer-SEC-001). Upstream's import trusts names found in a
// transfer file and writes where they point. Here the bag works inside an
// os.Root opened on its directory: no path with a separator or ".." is ever
// accepted, the OS refuses any lookup that would leave the directory, and a
// symbolic link is never followed (it is refused, and renamed aside with
// ".rejected" so it is not seen again). A file is read only if it is a
// regular file of at most party.MaxEnvelopeBytes.
//
// The bag does not look inside an envelope. What it returns is unchecked
// bytes; the caller opens them with adapters/envelope.
package filebag

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Ext is the extension of an envelope file.
const Ext = ".spo"

// Suffixes the bag gives files it has dealt with. Neither ends in Ext, so
// they are never offered again.
const (
	readSuffix     = ".read"
	rejectedSuffix = ".rejected"
)

// DefaultPoll is how often Receive looks at the directory.
const DefaultPoll = 100 * time.Millisecond

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.spo$`)

// ErrName: the file name is not a plain envelope file name.
var ErrName = errors.New("filebag: not a plain envelope file name")

// Rejection records a file Receive refused, for the audit log.
type Rejection struct {
	Name   string
	Reason string
}

// Bag is a directory of envelope files.
type Bag struct {
	root *os.Root
	poll time.Duration

	mu       sync.Mutex // one Receive at a time; guards rejected
	rejected []Rejection
}

var (
	_ ports.EnvelopeSender   = (*Bag)(nil)
	_ ports.EnvelopeReceiver = (*Bag)(nil)
)

// Open opens the bag on an existing directory.
func Open(dir string) (*Bag, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Bag{root: root, poll: DefaultPoll}, nil
}

// SetPoll changes the polling interval.
func (b *Bag) SetPoll(d time.Duration) { b.poll = d }

// Close releases the directory.
func (b *Bag) Close() error { return b.root.Close() }

// Rejected lists the files Receive refused so far.
func (b *Bag) Rejected() []Rejection {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Rejection(nil), b.rejected...)
}

func checkSize(envelope []byte) error {
	if len(envelope) == 0 || len(envelope) > party.MaxEnvelopeBytes {
		return ports.ErrEnvelopeSize
	}
	return nil
}

// Send writes the envelope to a file named after the recipient and a hash of
// the envelope. Use Write to give it the spec's name.
func (b *Bag) Send(ctx context.Context, to party.Fingerprint, envelope []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sum := sha256.Sum256(envelope)
	name := fmt.Sprintf("envelope-%s-%s%s", strings.ReplaceAll(to.String(), "-", "")[:8], hex.EncodeToString(sum[:4]), Ext)
	return b.Write(name, envelope)
}

// Write writes one envelope to the named file, atomically: the bytes go to a
// temporary file of mode 0600 which is synced and renamed into place, so a
// reader sees the whole envelope or none. A file already there is replaced
// (a symbolic link of that name is replaced, not followed). Name is a plain
// file name ending in ".spo"; party.FileName builds the spec's.
func (b *Bag) Write(name string, envelope []byte) (err error) {
	if !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	if err := checkSize(envelope); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return err
	}
	tmp := ".tmp-" + hex.EncodeToString(rnd[:])
	f, err := b.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			b.root.Remove(tmp)
		}
	}()
	if _, err = f.Write(envelope); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return b.root.Rename(tmp, name)
}

// Receive returns the next unread envelope file, in name order, marking it
// read (renamed with ".read"). It waits, polling, until one exists or ctx
// ends. A file that is not a regular file, is too large or cannot be read is
// renamed with ".rejected", noted in Rejected, and skipped.
func (b *Bag) Receive(ctx context.Context) ([]byte, ports.TransportKind, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		data, found, err := b.next()
		if err != nil {
			return nil, 0, err
		}
		if found {
			return data, ports.ViaFile, nil
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(b.poll):
		}
	}
}

func (b *Bag) reject(name, reason string) {
	b.rejected = append(b.rejected, Rejection{Name: name, Reason: reason})
	b.root.Rename(name, name+rejectedSuffix) // renames the link itself, never its target
}

// next takes the first acceptable file, or reports found false.
func (b *Bag) next() (data []byte, found bool, err error) {
	entries, err := fs.ReadDir(b.root.FS(), ".")
	if err != nil {
		return nil, false, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), Ext) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		st, err := b.root.Lstat(name)
		if err != nil {
			continue
		}
		switch {
		case !st.Mode().IsRegular():
			b.reject(name, "not a regular file")
			continue
		case st.Size() > party.MaxEnvelopeBytes || st.Size() == 0:
			b.reject(name, "empty or larger than the envelope limit")
			continue
		}
		data, err := b.read(name)
		if err != nil {
			b.reject(name, err.Error())
			continue
		}
		if err := b.root.Rename(name, name+readSuffix); err != nil {
			return nil, false, err // would be delivered again: stop
		}
		return data, true, nil
	}
	return nil, false, nil
}

// read opens the file without following a link, checks it is still a
// regular file within the limit, and reads at most one byte past the limit.
func (b *Bag) read(name string) ([]byte, error) {
	f, err := b.root.OpenFile(name, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, party.MaxEnvelopeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > party.MaxEnvelopeBytes {
		return nil, errors.New("empty or larger than the envelope limit")
	}
	return data, nil
}
