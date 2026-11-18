// Package exportdir is where `spo workspace export` writes: a directory in the
// upstream file layout, for upstream's scripts to read.
//
// It writes non-secret artefacts and signing keys in upstream's ENCRYPTED
// form, and nothing else. PutSecret refuses every secret that is not a signing
// key envelope in its encrypted form (a plain key, a mnemonic, a QR code), so
// whatever the caller asks, no secret reaches the directory in clear
// (SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003; ADR 0011 (proposed)). The check
// is on the bytes about to be written, in the one place that writes them.
//
// Every file is written to a temporary name and renamed into place, locked at
// the mode upstream gives the kind.
package exportdir

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNotEncrypted is the refusal to write a secret that is not an encrypted
// signing key envelope.
var ErrNotEncrypted = errors.New("exportdir: only a signing key in upstream's encrypted form may be written; nothing secret is ever written in clear")

// Dir is a destination directory.
type Dir struct {
	dir string
	mu  sync.Mutex
}

// Open returns a Dir over an existing directory.
func Open(dir string) (*Dir, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("exportdir: %s is not a directory", abs)
	}
	return &Dir{dir: abs}, nil
}

type staged struct {
	data []byte
	mode os.FileMode
	del  bool
}

type tx struct {
	d     *Dir
	ops   map[string]*staged
	order []string
}

func (t *tx) path(r ports.NamedRef) (string, error) {
	name, err := upstreamdir.FileName(r)
	if err != nil {
		return "", err
	}
	return filepath.Join(t.d.dir, name), nil
}

func (t *tx) Get(r ports.NamedRef) ([]byte, error) {
	if r.Kind.Secret() {
		return nil, ports.ErrSecretKind
	}
	p, err := t.path(r)
	if err != nil {
		return nil, err
	}
	if st := t.ops[p]; st != nil {
		if st.del {
			return nil, ports.ErrNotFound
		}
		return append([]byte(nil), st.data...), nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	return b, err
}

func (t *tx) Exists(r ports.NamedRef) (bool, error) {
	p, err := t.path(r)
	if err != nil {
		return false, err
	}
	if st := t.ops[p]; st != nil {
		return !st.del, nil
	}
	_, err = os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (t *tx) stage(p string, st *staged) {
	if _, ok := t.ops[p]; !ok {
		t.order = append(t.order, p)
	}
	t.ops[p] = st
}

func (t *tx) Put(r ports.NamedRef, data []byte) error {
	if r.Kind.Secret() {
		return ports.ErrSecretKind
	}
	p, err := t.path(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{data: append([]byte(nil), data...), mode: upstreamdir.ModeOf(r.Kind)})
	return nil
}

// PutSecret accepts a signing key envelope in upstream's encrypted form only.
func (t *tx) PutSecret(r ports.NamedRef, sec *secret.Buffer) error {
	if !r.Kind.Secret() {
		return fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, r.Kind)
	}
	if !r.Kind.IsSigningKey() {
		return ErrNotEncrypted
	}
	p, err := t.path(r)
	if err != nil {
		return err
	}
	var cp []byte
	encrypted := false
	if err := sec.Use(func(b []byte) error {
		info, cerr := keyfile.Classify(b)
		encrypted = cerr == nil && info.Form == keyfile.FormEncrypted
		if encrypted {
			// The shape is not enough: the ciphertext must be an OpenPGP
			// password-encrypted message with an integrity packet and
			// nothing else (SPO-Xcustody-INV-001).
			enc, perr := keyfile.ParseEncrypted(b)
			raw, herr := hex.DecodeString(string(enc.EncrHex))
			if perr != nil || herr != nil {
				encrypted = false
			} else if _, merr := keyfile.CheckSymmetricMessage(raw); merr != nil {
				encrypted = false
			}
		}
		if encrypted {
			// The envelope holds only the ciphertext, which is not secret.
			cp = append([]byte(nil), b...)
		}
		return nil
	}); err != nil {
		return err
	}
	if !encrypted {
		return ErrNotEncrypted
	}
	t.stage(p, &staged{data: cp, mode: upstreamdir.ModeOf(r.Kind)})
	return nil
}

func (t *tx) Delete(r ports.NamedRef) error {
	p, err := t.path(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{del: true})
	return nil
}

// View implements ports.NamedStore.
func (d *Dir) View(_ context.Context, fn func(ports.NamedReader) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fn(&tx{d: d, ops: map[string]*staged{}})
}

// Update implements ports.NamedStore: all the files are written beside their
// destinations first, then renamed into place.
func (d *Dir) Update(_ context.Context, fn func(ports.NamedWriter) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := &tx{d: d, ops: map[string]*staged{}}
	if err := fn(t); err != nil {
		return err
	}
	tmpOf := map[string]string{}
	cleanup := func() {
		for _, tmp := range tmpOf {
			os.Remove(tmp)
		}
	}
	for _, p := range t.order {
		st := t.ops[p]
		if st.del {
			continue
		}
		tmp, err := writeTemp(p, st)
		if err != nil {
			cleanup()
			return err
		}
		tmpOf[p] = tmp
	}
	for _, p := range t.order {
		st := t.ops[p]
		if st.del {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				cleanup()
				return err
			}
			continue
		}
		if err := os.Rename(tmpOf[p], p); err != nil {
			cleanup()
			return err
		}
		delete(tmpOf, p)
	}
	return nil
}

func writeTemp(dest string, st *staged) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(dest), ".spo-tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if _, err := f.Write(st.data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Chmod(st.mode); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

var _ ports.NamedStore = (*Dir)(nil)
