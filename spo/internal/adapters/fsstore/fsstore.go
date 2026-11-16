// Package fsstore implements ports.Store and ports.Vault over a directory in
// the upstream file layout (spec/upstream/patterns/Pfiles.md).
//
// It exists for parity tests, import and export (concern S4). Signing keys
// are stored as upstream stores them, in plaintext at mode 0400
// (SPO-Pfiles-SEC-002), so the composition root offers this adapter only
// behind an explicit flag.
//
// An Update stages every write in memory and applies it on success: each
// file is written to a temporary name and renamed into place. A crash in the
// middle of applying can leave some files updated and others not; a plain
// directory cannot do better. The sealed store commits atomically.
package fsstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// modeLocked is upstream's file_lock mode. A rewrite replaces the file by
// rename, so no unlock step is needed (SPO-Pfiles-INV-003).
const modeLocked = 0o400

// layout maps a kind to its upstream file name.
// spec: SPO-Pfiles-OUT-010 to SPO-Pfiles-OUT-015, SPO-04c-INV-001
var layout = map[ports.Kind]func(r ports.Ref) string{
	ports.NodeVKey:       func(r ports.Ref) string { return r.Name + ".node.vkey" },
	ports.NodeSKey:       func(r ports.Ref) string { return r.Name + ".node.skey" },
	ports.NodeCounter:    func(r ports.Ref) string { return r.Name + ".node.counter" },
	ports.NodeHwsFile:    func(r ports.Ref) string { return r.Name + ".node.hwsfile" },
	ports.VrfVKey:        func(r ports.Ref) string { return r.Name + ".vrf.vkey" },
	ports.VrfSKey:        func(r ports.Ref) string { return r.Name + ".vrf.skey" },
	ports.KesVKey:        func(r ports.Ref) string { return fmt.Sprintf("%s.kes-%03d.vkey", r.Name, r.Num) },
	ports.KesSKey:        func(r ports.Ref) string { return fmt.Sprintf("%s.kes-%03d.skey", r.Name, r.Num) },
	ports.KesCounter:     func(r ports.Ref) string { return r.Name + ".kes.counter" },
	ports.KesCounterNext: func(r ports.Ref) string { return r.Name + ".kes.counter-next" },
	ports.OpCert:         func(r ports.Ref) string { return fmt.Sprintf("%s.node-%03d.opcert", r.Name, r.Num) },
	ports.KesExpire:      func(r ports.Ref) string { return r.Name + ".kes-expire.json" },
}

// Store is a workspace directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open returns a Store over an existing directory.
func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("fsstore: %s is not a directory", abs)
	}
	return &Store{dir: abs}, nil
}

func (s *Store) path(r ports.Ref) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	name, ok := layout[r.Kind]
	if !ok {
		return "", fmt.Errorf("%w: %s has no upstream file name", ports.ErrInvalidRef, r.Kind)
	}
	return filepath.Join(s.dir, name(r)), nil
}

type staged struct {
	path   string
	data   []byte         // non-secret content
	secret *secret.Buffer // secret content (a private copy)
	delete bool
}

type tx struct {
	s        *Store
	writable bool
	ops      map[string]*staged
	order    []string
}

func (t *tx) lookup(r ports.Ref) (string, *staged, error) {
	p, err := t.s.path(r)
	if err != nil {
		return "", nil, err
	}
	return p, t.ops[p], nil
}

func (t *tx) Get(r ports.Ref) ([]byte, error) {
	if r.Kind.Secret() {
		return nil, ports.ErrSecretKind
	}
	p, st, err := t.lookup(r)
	if err != nil {
		return nil, err
	}
	if st != nil {
		if st.delete {
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

func (t *tx) Exists(r ports.Ref) (bool, error) {
	p, st, err := t.lookup(r)
	if err != nil {
		return false, err
	}
	if st != nil {
		return !st.delete, nil
	}
	_, err = os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (t *tx) stage(p string, st *staged) {
	if old, ok := t.ops[p]; ok {
		old.secret.Destroy()
	} else {
		t.order = append(t.order, p)
	}
	st.path = p
	t.ops[p] = st
}

func (t *tx) Put(r ports.Ref, data []byte) error {
	if r.Kind.Secret() {
		return ports.ErrSecretKind
	}
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{data: append([]byte(nil), data...)})
	return nil
}

func (t *tx) PutSecret(r ports.Ref, sec *secret.Buffer) error {
	if !r.Kind.Secret() {
		return fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, r.Kind)
	}
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	var cp *secret.Buffer
	if err := sec.Use(func(b []byte) error {
		cp = secret.Take(append([]byte(nil), b...))
		return nil
	}); err != nil {
		return err
	}
	t.stage(p, &staged{secret: cp})
	return nil
}

func (t *tx) Delete(r ports.Ref) error {
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{delete: true})
	return nil
}

func (t *tx) discard() {
	for _, st := range t.ops {
		st.secret.Destroy()
	}
}

// View implements ports.Store.
func (s *Store) View(_ context.Context, fn func(ports.Reader) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&tx{s: s, ops: map[string]*staged{}})
}

// Update implements ports.Store.
func (s *Store) Update(_ context.Context, fn func(ports.Writer) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &tx{s: s, writable: true, ops: map[string]*staged{}}
	defer t.discard()
	if err := fn(t); err != nil {
		return err
	}
	// Stage every file under a temporary name first, so a failure here
	// leaves the workspace untouched.
	var temps []string
	cleanup := func() {
		for _, tmp := range temps {
			os.Remove(tmp)
		}
	}
	tmpOf := map[string]string{}
	for _, p := range t.order {
		st := t.ops[p]
		if st.delete {
			continue
		}
		tmp, err := writeTemp(p, st)
		if err != nil {
			cleanup()
			return err
		}
		temps = append(temps, tmp)
		tmpOf[p] = tmp
	}
	for _, p := range t.order {
		st := t.ops[p]
		if st.delete {
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
	}
	return nil
}

// writeTemp writes the staged content beside its destination with the
// locked mode already set, so the rename publishes a finished file.
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
	if st.secret != nil {
		if _, err := st.secret.WriteTo(f); err != nil {
			return fail(err)
		}
	} else if _, err := f.Write(st.data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Chmod(modeLocked); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// Open implements ports.Vault: it reads a signing key file into guarded
// memory.
func (s *Store) Open(_ context.Context, r ports.Ref) (*secret.Buffer, error) {
	if !r.Kind.Secret() {
		return nil, fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, r.Kind)
	}
	p, err := s.path(r)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return secret.Read(f)
}

var (
	_ ports.Store = (*Store)(nil)
	_ ports.Vault = (*Store)(nil)
)
