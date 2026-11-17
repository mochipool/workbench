// Package plainstore is a writable store over a directory in the upstream file
// layout (spec/upstream/patterns/Pfiles.md). It is TEST-ONLY.
//
// Signing keys are written as upstream writes them, in clear at mode 0400
// (SPO-Pfiles-SEC-002). The release binary must be unable to do that
// (SPO-Xcustody-INV-001; ADR 0011 (proposed)), so this package lives under
// spo/test, and internal/archtest refuses an import of it from any package that
// is not a test, and from cmd/spo outside a file built with the `plainlayout`
// tag. Open opens a directory only when its spo.toml exists, parses and names a
// network that is not mainnet; absence, an unreadable file and mainnet are all
// refused, and OpenNetwork also refuses the mainnet network magic: no key in
// clear is ever written for real funds.
//
// An Update stages every write in memory and applies it on success: each
// file is written to a temporary name and renamed into place. A crash in the
// middle of applying can leave some files updated and others not; a plain
// directory cannot do better. The sealed store commits atomically.
package plainstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// MainnetMagic is the network magic of mainnet.
const MainnetMagic = 764824073

// ErrMainnet is the refusal to hold keys in clear for mainnet.
var ErrMainnet = errors.New("plainstore: refused: this directory is for mainnet, and keys in clear are never written there")

// ErrNoNetwork is the refusal of a directory whose network is unknown: it has
// no spo.toml, or one that cannot be read.
var ErrNoNetwork = errors.New("plainstore: refused: the directory has no spo.toml that can be read, so its network is unknown")

// Store is a workspace directory.
type Store struct {
	*upstreamdir.Source // List and Subdirs; View and Open are redefined below
	dir                 string
	mu                  sync.Mutex
}

// OpenNetwork is Open for a caller that also knows the network magic of the
// directory; mainnet's magic is refused here as well, and the directory's own
// spo.toml is checked as in Open.
func OpenNetwork(dir string, magic uint32) (*Store, error) {
	if magic == MainnetMagic {
		return nil, ErrMainnet
	}
	return Open(dir)
}

// OpenTestnet is the test helper for a bare directory. When dir has no
// spo.toml it writes one that names a test network (preview), opens the
// directory through Open, and removes the file it wrote, so a test that lists
// the directory sees only the artefacts. A directory that has an spo.toml is
// opened as it is, so a mainnet one is still refused.
func OpenTestnet(dir string) (*Store, error) {
	if _, err := config.Load(dir); errors.Is(err, os.ErrNotExist) {
		if err := config.Create(dir, config.Config{Network: "preview", Mode: "offline"}); err != nil {
			return nil, err
		}
		defer os.Remove(config.Path(dir))
	}
	return Open(dir)
}

// Open returns a Store over an existing directory. It is the one constructor,
// and it checks the network unconditionally (SPO-Xcustody-SEC-002): the
// directory must hold an spo.toml that can be read and names a network that is
// not mainnet. A missing file, one that cannot be read and one that names
// mainnet are all refused, because the network is then unknown or is the one
// where keys in clear are never written.
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
		return nil, fmt.Errorf("plainstore: %s is not a directory", abs)
	}
	c, err := config.Load(abs)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoNetwork, abs, err)
	}
	if p, ok := config.PresetFor(c.Network); c.Network == "mainnet" || !ok || p.Magic == "mainnet" {
		return nil, ErrMainnet
	}
	src, err := upstreamdir.Open(abs)
	if err != nil {
		return nil, err
	}
	return &Store{Source: src, dir: abs}, nil
}

func (s *Store) path(r ports.Ref) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	name, err := upstreamdir.FileName(r)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, name), nil
}

type staged struct {
	path   string
	data   []byte         // non-secret content
	secret *secret.Buffer // secret content (a private copy)
	delete bool
	mode   os.FileMode // 0 means upstreamdir.ModeLocked
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
	t.stage(p, &staged{data: append([]byte(nil), data...), mode: upstreamdir.ModeOf(r.Kind)})
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

func (st *staged) fileMode() os.FileMode {
	if st.mode != 0 {
		return st.mode
	}
	return upstreamdir.ModeLocked
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
	if err := f.Chmod(st.fileMode()); err != nil {
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
	_ ports.Store        = (*Store)(nil)
	_ ports.Vault        = (*Store)(nil)
	_ ports.SourceLister = (*Store)(nil)
	_ ports.SourceTree   = (*Store)(nil)
)
