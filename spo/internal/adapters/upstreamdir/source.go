package upstreamdir

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

// Source is a directory in the upstream layout, opened to be read. It has no
// Update and no method that writes a file: the type cannot change the
// directory, and the architecture test keeps a writable plain store out of the
// release build (SPO-Xcustody-INV-001).
type Source struct {
	dir string
	mu  sync.Mutex
}

// Open returns a Source over an existing directory.
func Open(dir string) (*Source, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("upstreamdir: %s is not a directory", abs)
	}
	return &Source{dir: abs}, nil
}

// Dir is the absolute path of the directory.
func (s *Source) Dir() string { return s.dir }

func (s *Source) path(r ports.NamedRef) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	if _, isID := ports.IdentityName(r.Name); isID {
		return "", fmt.Errorf("%w: a directory has file names, not identities", ports.ErrInvalidRef)
	}
	name, ok := layout[r.Kind]
	if !ok {
		return "", fmt.Errorf("%w: %s has no upstream file name", ports.ErrInvalidRef, r.Kind)
	}
	return filepath.Join(s.dir, name(r)), nil
}

type reader struct{ s *Source }

func (t reader) Get(r ports.NamedRef) ([]byte, error) {
	if r.Kind.Secret() {
		return nil, ports.ErrSecretKind
	}
	p, err := t.s.path(r)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	return b, err
}

func (t reader) Exists(r ports.NamedRef) (bool, error) {
	p, err := t.s.path(r)
	if err != nil {
		return false, err
	}
	_, err = os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// View implements ports.NamedReadStore.
func (s *Source) View(_ context.Context, fn func(ports.NamedReader) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(reader{s})
}

// Open implements ports.NamedVault: it reads a key or other secret file into
// guarded memory, for an import to seal it.
func (s *Source) Open(_ context.Context, r ports.NamedRef) (*secret.Buffer, error) {
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
	_ ports.NamedReadStore = (*Source)(nil)
	_ ports.NamedVault     = (*Source)(nil)
)
