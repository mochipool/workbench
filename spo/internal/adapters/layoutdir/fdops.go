//go:build unix

package layoutdir

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Every operation below is relative to the directory descriptor opened by Open
// (openat, linkat, unlinkat, fstatat), with O_NOFOLLOW on every component and
// O_NONBLOCK on every file, and requires a regular file by fstat on the
// descriptor that was opened.

const tmpPrefix = ".tmp-"

var (
	objDirRE  = regexp.MustCompile(`^[0-9a-f]{2}$`)
	objFileRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	headFile  = regexp.MustCompile(`^[0-9]{20}(\.sig)?$`)
	tmpRE     = regexp.MustCompile(`^\.tmp-[0-9a-f]{16}$`)
)

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
)

// openDir walks parts below the root descriptor and returns a new descriptor for
// the last one. With create the missing directories are made (0700).
func (d *Dir) openDir(parts []string, create bool) (int, error) {
	cur := int(d.rootFile.Fd())
	own := false
	for _, p := range parts {
		fd, err := unix.Openat(cur, p, dirFlags, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(cur, p, 0o700); err == nil || errors.Is(err, unix.EEXIST) {
				unix.Fsync(cur)
				fd, err = unix.Openat(cur, p, dirFlags, 0)
			}
		}
		if own {
			unix.Close(cur)
		}
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				return -1, ports.ErrObjectNotFound
			}
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return -1, fmt.Errorf("%q passes through a link or a file", strings.Join(parts, "/"))
			}
			return -1, err
		}
		cur, own = fd, true
	}
	if !own {
		return unix.Dup(cur)
	}
	return cur, nil
}

func split(name string) (dir []string, base string, err error) {
	if err := ports.ValidObjectName(name); err != nil {
		return nil, "", err
	}
	parts := strings.Split(name, "/")
	return parts[:len(parts)-1], parts[len(parts)-1], nil
}

// openRegularAt opens name below dfd for reading and requires a regular file.
func openRegularAt(dfd int, name string) (*os.File, error) {
	fd, err := unix.Openat(dfd, name, fileFlags, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, ports.ErrObjectNotFound
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, errNotRegular
		}
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, errNotRegular
	}
	return os.NewFile(uintptr(fd), name), nil
}

var errNotRegular = errors.New("not a regular file")

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

// Put creates the object name (ports.ObjectWriter): create-if-absent, never an
// overwrite. The bytes go to a temporary file in the directory, are synced, and
// are linked into place with linkat, which fails when the name exists.
func (d *Dir) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	dirParts, base, err := split(name)
	if err != nil {
		return err
	}
	dfd, err := d.openDir(dirParts, true)
	if err != nil {
		return err
	}
	defer unix.Close(dfd)
	d.sweepOnce(dfd, strings.Join(dirParts, "/"))
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	tfd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(tfd), tmp)
	defer unix.Unlinkat(dfd, tmp, 0) // the link keeps the data; the temporary name always goes
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
	if err := unix.Linkat(dfd, tmp, dfd, base, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return sameContentAt(dfd, base, size, h.Sum(nil))
		}
		return err
	}
	return unix.Fsync(dfd)
}

func sameContentAt(dfd int, base string, size int64, sum []byte) error {
	f, err := openRegularAt(dfd, base)
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

// Get opens the object name (ports.ObjectReader).
func (d *Dir) Get(_ context.Context, name string) (io.ReadCloser, error) {
	dirParts, base, err := split(name)
	if err != nil {
		return nil, err
	}
	dfd, err := d.openDir(dirParts, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	f, err := openRegularAt(dfd, base)
	if errors.Is(err, errNotRegular) {
		return nil, fmt.Errorf("%q is not a regular file", name)
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// GetRange opens the object name at offset (ports.ObjectRangeReader).
func (d *Dir) GetRange(ctx context.Context, name string, offset int64) (io.ReadCloser, error) {
	rc, err := d.Get(ctx, name)
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
func (d *Dir) Has(ctx context.Context, name string) (bool, error) {
	r, err := d.Get(ctx, name)
	if errors.Is(err, ports.ErrObjectNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	r.Close()
	return true, nil
}

// entry is one thing found by a walk.
type entry struct {
	rel  string // slash-separated, below the root
	mode uint32 // the file type bits of lstat
	size int64
}

// walk visits every entry below the root, depth first in name order, up to
// MaxEntries entries and a depth of 3. It never follows a link and never opens a
// file.
func (d *Dir) walk(ctx context.Context, visit func(entry) error) error {
	count := 0
	var rec func(fd int, rel string, depth int) error
	rec = func(fd int, rel string, depth int) error {
		// a new open file description: a duplicate would share the read position
		dup, err := unix.Openat(fd, ".", dirFlags, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(dup), rel)
		defer f.Close()
		for {
			// in chunks, so that a directory with an enormous number of names is
			// abandoned at the cap and never read whole
			names, rerr := f.Readdirnames(readChunk)
			if readChunkHook != nil {
				readChunkHook(len(names))
			}
			if rerr != nil && rerr != io.EOF {
				return rerr
			}
			for _, n := range names {
				if err := ctx.Err(); err != nil {
					return err
				}
				if count++; count > MaxEntries {
					return fmt.Errorf("the directory holds more than %d entries; it is not a layout this tool will scan", MaxEntries)
				}
				var st unix.Stat_t
				if err := unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				e := entry{rel: rel + n, mode: st.Mode & unix.S_IFMT, size: st.Size}
				if err := visit(e); err != nil {
					return err
				}
				if e.mode == unix.S_IFDIR {
					if depth >= 3 {
						return fmt.Errorf("%q is nested deeper than a layout is", e.rel)
					}
					sub, err := unix.Openat(fd, n, dirFlags, 0)
					if err != nil {
						return err
					}
					err = rec(sub, e.rel+"/", depth+1)
					unix.Close(sub)
					if err != nil {
						return err
					}
				}
			}
			if len(names) == 0 {
				return nil
			}
		}
	}
	return rec(int(d.rootFile.Fd()), "", 1)
}

// List returns the regular files whose names start with prefix, sorted by name.
// Temporary files and everything that is not a regular file are not listed.
func (d *Dir) List(ctx context.Context, prefix string) ([]ports.ObjectInfo, error) {
	if prefix != "" {
		if trial := strings.TrimSuffix(prefix, "/"); trial != "" {
			if err := ports.ValidObjectName(trial); err != nil {
				return nil, err
			}
		}
	}
	var out []ports.ObjectInfo
	err := d.walk(ctx, func(e entry) error {
		base := e.rel[strings.LastIndex(e.rel, "/")+1:]
		if e.mode == unix.S_IFREG && !strings.HasPrefix(base, tmpPrefix) && strings.HasPrefix(e.rel, prefix) {
			out = append(out, ports.ObjectInfo{Name: e.rel, Size: e.size})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func typeName(mode uint32) string {
	switch mode {
	case unix.S_IFIFO:
		return "a FIFO"
	case unix.S_IFLNK:
		return "a symbolic link"
	case unix.S_IFDIR:
		return "a directory"
	case unix.S_IFSOCK:
		return "a socket"
	case unix.S_IFBLK, unix.S_IFCHR:
		return "a device"
	}
	return "not a regular file"
}

// scan refuses a directory that holds anything a layout does not: any entry under
// objects/ or heads/ that is not a regular file of the right name (or, in
// objects, a two-digit directory), and anything at the top that is not objects,
// heads or the lock file. It names the first such entry. It runs at Open, before
// the lock file is made and before anything is asked.
func (d *Dir) scan() error {
	return d.walk(context.Background(), func(e entry) error {
		parts := strings.Split(e.rel, "/")
		bad := func(why string) error {
			return fmt.Errorf("%q in the layout directory %s: %w", e.rel, why, ErrNotALayout)
		}
		switch parts[0] {
		case LockName:
			if len(parts) == 1 && e.mode != unix.S_IFREG {
				return bad("is " + typeName(e.mode))
			}
			if len(parts) == 1 {
				return nil
			}
		case "objects":
			switch len(parts) {
			case 1:
				if e.mode != unix.S_IFDIR {
					return bad("is " + typeName(e.mode) + ", not a directory")
				}
				return nil
			case 2:
				if !objDirRE.MatchString(parts[1]) {
					return bad("is not a two-digit object directory")
				}
				if e.mode != unix.S_IFDIR {
					return bad("is " + typeName(e.mode) + ", not a directory")
				}
				return nil
			case 3:
				if !(objFileRE.MatchString(parts[2]) && strings.HasPrefix(parts[2], parts[1])) && !tmpRE.MatchString(parts[2]) {
					return bad("is not the name of an object")
				}
				if e.mode != unix.S_IFREG {
					return bad("is " + typeName(e.mode) + ", not a regular file")
				}
				return nil
			}
		case "heads":
			switch len(parts) {
			case 1:
				if e.mode != unix.S_IFDIR {
					return bad("is " + typeName(e.mode) + ", not a directory")
				}
				return nil
			case 2:
				if !headFile.MatchString(parts[1]) && !tmpRE.MatchString(parts[1]) {
					return bad("is not the name of a head")
				}
				if e.mode != unix.S_IFREG {
					return bad("is " + typeName(e.mode) + ", not a regular file")
				}
				return nil
			}
		}
		return bad("is not part of a layout")
	})
}

// readChunk is how many names one read of a directory asks for.
const readChunk = 1024

// sweepOnce removes the tool's own stale temporary files from the directory dfd,
// once for each directory in the life of d: regular files named .tmp-<16 hex>,
// owned by this user, older than an hour. A link or anything else of that name is
// never touched (fstatat without following links).
func (d *Dir) sweepOnce(dfd int, key string) {
	d.sweepMu.Lock()
	if d.swept == nil {
		d.swept = map[string]bool{}
	}
	done := d.swept[key]
	d.swept[key] = true
	d.sweepMu.Unlock()
	if done {
		return
	}
	dup, err := unix.Openat(dfd, ".", dirFlags, 0)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(dup), key)
	defer f.Close()
	for {
		names, err := f.Readdirnames(readChunk)
		for _, n := range names {
			if !tmpRE.MatchString(n) {
				continue
			}
			var st unix.Stat_t
			if unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
				continue
			}
			if st.Mode&unix.S_IFMT == unix.S_IFREG && int(st.Uid) == os.Geteuid() && time.Since(time.Unix(st.Mtim.Sec, st.Mtim.Nsec)) > time.Hour {
				unix.Unlinkat(dfd, n, 0)
			}
		}
		if err != nil || len(names) == 0 {
			return
		}
	}
}
