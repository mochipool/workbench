// Package dir is a backup sink on a local directory (ADR 0012 decisions 4 and
// 9). An object is a file of mode 0600 below directories of mode 0700. It is
// written to a temporary name in its own directory, fsynced, and linked into
// place with link(2), which fails when the name exists, so no object is ever
// overwritten; the directory is then fsynced.
//
// The directory must be on a local file system (ADR 0003).
package dir

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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

const tmpPrefix = ".tmp-"

// Store is a directory sink. It implements ports.ObjectWriter, ObjectReader,
// ObjectLister and SinkProbe.
type Store struct {
	root string
}

var (
	_ ports.ObjectWriter      = (*Store)(nil)
	_ ports.ObjectReader      = (*Store)(nil)
	_ ports.ObjectLister      = (*Store)(nil)
	_ ports.ObjectRangeReader = (*Store)(nil)
	_ ports.SinkProbe         = (*Store)(nil)
)

// Open opens the sink directory at the absolute path root, creating it (mode
// 0700) when it is missing. It refuses a directory that is group- or
// world-writable: another user could then replace objects in it.
func Open(root string) (*Store, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("the sink directory %q is not an absolute path", root)
	}
	root = filepath.Clean(root)
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, err
		}
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("the sink %s is not a directory", root)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("the sink directory %s is writable by its group or by everyone (mode %o); another user could replace a backup in it. Run: chmod 700 %s", root, st.Mode().Perm(), root)
	}
	return &Store{root: real}, nil
}

// Check reports a directory sink: no versioning, no lock, no credentials.
func (s *Store) Check(context.Context) (ports.SinkProperties, error) {
	return ports.SinkProperties{Kind: ports.SinkDir}, nil
}

// walk resolves name below the root, refusing a symlink at any component. With
// create it makes the missing directories (0700). It returns the directory of
// the object and the full path.
func (s *Store) walk(name string, create bool) (dirPath, full string, err error) {
	if err := ports.ValidObjectName(name); err != nil {
		return "", "", err
	}
	parts := strings.Split(name, "/")
	cur := s.root
	for i, p := range parts {
		next := filepath.Join(cur, p)
		st, lerr := os.Lstat(next)
		last := i == len(parts)-1
		switch {
		case errors.Is(lerr, fs.ErrNotExist):
			if last {
				return cur, next, nil
			}
			if !create {
				return "", "", ports.ErrObjectNotFound
			}
			if err := os.Mkdir(next, 0o700); err != nil {
				return "", "", err
			}
			if err := syncDir(cur); err != nil {
				return "", "", err
			}
		case lerr != nil:
			return "", "", lerr
		case st.Mode()&fs.ModeSymlink != 0:
			return "", "", fmt.Errorf("%q passes through a symbolic link", name)
		case !last && !st.IsDir():
			return "", "", fmt.Errorf("%q passes through a file", name)
		}
		if !last {
			cur = next
		}
	}
	return cur, filepath.Join(cur, parts[len(parts)-1]), nil
}

func syncDir(p string) error {
	d, err := os.Open(p)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Put creates the object name. See ports.ObjectWriter.
func (s *Store) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	dirPath, full, err := s.walk(name, true)
	if err != nil {
		return err
	}
	removeStaleTemps(dirPath)
	var tmpName [8]byte
	if _, err := rand.Read(tmpName[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dirPath, tmpPrefix+hex.EncodeToString(tmpName[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp) // the link keeps the data; the temporary name always goes
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(&ctxReader{ctx, r}, size+1))
	if err == nil && n != size {
		err = fmt.Errorf("the reader gave %d bytes where %d were declared", n, size)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Link(tmp, full); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return sameContent(full, size, h.Sum(nil))
		}
		return err
	}
	return syncDir(dirPath)
}

var ownTmpRE = regexp.MustCompile(`^\.tmp-[0-9a-f]{16}$`)

// removeStaleTemps removes the temporary files of a previous crashed run: only
// regular files of this adapter's own pattern, older than an hour.
func removeStaleTemps(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !ownTmpRE.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// sameContent is nil when the existing file has the size and SHA-256 given and
// ErrObjectExists when it differs.
func sameContent(path string, size int64, sum []byte) error {
	f, err := openRegular(path)
	if err != nil {
		if errors.Is(err, errNotRegular) {
			return fmt.Errorf("%w (the name holds something that is not a regular file)", ports.ErrObjectExists)
		}
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != size {
		return ports.ErrObjectExists
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(sum) {
		return ports.ErrObjectExists
	}
	return nil
}

// Get opens the object name.
func (s *Store) Get(_ context.Context, name string) (io.ReadCloser, error) {
	_, full, err := s.walk(name, false)
	if err != nil {
		return nil, err
	}
	f, err := openRegular(full)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrObjectNotFound
	}
	if errors.Is(err, errNotRegular) {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

var errNotRegular = errors.New("not a regular file")

// openRegular opens path for reading without ever blocking and without following
// a link, and requires a regular file: a FIFO, a socket, a device, a directory
// or a link is refused at once (O_NONBLOCK so that opening a FIFO cannot wait
// for a writer, O_NOFOLLOW, then fstat on the descriptor that was opened).
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNotRegular
		}
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

// GetRange opens the object name at offset. An offset at or beyond its end is
// ports.ErrRangeNotSatisfiable.
func (s *Store) GetRange(ctx context.Context, name string, offset int64) (io.ReadCloser, error) {
	rc, err := s.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	f := rc.(*os.File)
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if offset < 0 || offset >= st.Size() {
		f.Close()
		return nil, ports.ErrRangeNotSatisfiable
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// Has reports whether the object name exists.
func (s *Store) Has(ctx context.Context, name string) (bool, error) {
	r, err := s.Get(ctx, name)
	if errors.Is(err, ports.ErrObjectNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	r.Close()
	return true, nil
}

// List returns the regular files whose names start with prefix, sorted by name.
// Temporary files and symbolic links are not listed.
func (s *Store) List(ctx context.Context, prefix string) ([]ports.ObjectInfo, error) {
	if prefix != "" {
		trial := strings.TrimSuffix(prefix, "/")
		if trial != "" {
			if err := ports.ValidObjectName(trial); err != nil {
				return nil, err
			}
		}
	}
	var out []ports.ObjectInfo
	start := s.root
	if i := strings.LastIndex(prefix, "/"); i >= 0 {
		start = filepath.Join(s.root, filepath.FromSlash(prefix[:i]))
		if _, err := os.Lstat(start); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
	}
	err := filepath.WalkDir(start, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), tmpPrefix) || !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(s.root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, prefix) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		out = append(out, ports.ObjectInfo{Name: rel, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
