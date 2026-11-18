//go:build unix

// Package layoutdir is the directory a sealed layout is exported to (ADR 0012
// stage 3): the object ports of the directory sink (adapters/objstore/dir) plus
// what the exporter needs beside them: a single-writer lock on the directory and
// a forward-only pin file next to the workspace file.
//
// The directory must be a local directory that is not the workspace directory
// and not inside it, owned by the user running the program, and not writable by
// its group or by others (the directory sink's own rule).
package layoutdir

import (
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	objdir "github.com/mochipool/workbench/spo/internal/adapters/objstore/dir"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// LockName is the name of the lock file in the layout directory. It is not part
// of the layout; the exporter ignores it.
const LockName = ".spo-export.lock"

// Dir is an opened layout directory.
type Dir struct {
	// rootFile is the layout directory, opened once (O_DIRECTORY|O_NOFOLLOW) at
	// Open. Every later open, link and listing is relative to it, so replacing the
	// directory afterwards (by another directory or a link) cannot redirect a read
	// or a write.
	rootFile *os.File
	sweepMu  sync.Mutex
	swept    map[string]bool
	root     string // the real path at Open, for the lock's check
	pinPath  string
}

var (
	_ ports.ObjectWriter = (*Dir)(nil)
	_ ports.ObjectReader = (*Dir)(nil)
	_ ports.ObjectLister = (*Dir)(nil)
	_ ports.LayoutLocker = (*Dir)(nil)
	_ ports.LayoutPins   = (*Dir)(nil)
)

// ErrInsideWorkspace is returned for a directory that is the workspace
// directory or is inside it (or holds it).
var ErrInsideWorkspace = errors.New("the layout directory must not be the workspace directory or inside it; a layout is an artefact to keep elsewhere")

// ErrNotALayout is returned for a directory that is not empty and holds
// something that is not part of a layout.
var ErrNotALayout = errors.New("the directory is not empty and is not a layout; use an empty or new directory")

// Open opens (and creates, mode 0700, when absent) the layout directory root,
// an absolute path, for the workspace whose file is workspaceFile.
func Open(root, workspaceFile string) (*Dir, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("the layout directory %q is not an absolute path", root)
	}
	root = filepath.Clean(root)
	wsAbs, err := filepath.Abs(workspaceFile)
	if err != nil {
		return nil, err
	}
	wsDir, err := filepath.EvalSymlinks(filepath.Dir(wsAbs))
	if errors.Is(err, fs.ErrNotExist) {
		// a machine with no workspace yet (reading a layout to import it): the pin
		// file would sit where the workspace will be
		wsDir, err = filepath.Dir(wsAbs), nil
	}
	if err != nil {
		return nil, err
	}
	// where root will be, with every existing part resolved
	probe := root
	var tail []string
	for {
		if _, lerr := os.Lstat(probe); lerr == nil {
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		tail = append([]string{filepath.Base(probe)}, tail...)
		probe = parent
	}
	realProbe, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return nil, err
	}
	want := filepath.Join(append([]string{realProbe}, tail...)...)
	if inside(want, wsDir) || inside(wsDir, want) {
		return nil, ErrInsideWorkspace
	}
	if _, err := objdir.Open(root); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return nil, err
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("the layout directory %s is not owned by the user running this program", root)
	}
	sum := sha256.Sum256([]byte(real))
	pin := filepath.Join(wsDir, filepath.Base(wsAbs)+".layout-"+hex.EncodeToString(sum[:8])+".pin")
	if afterRootChecks != nil {
		afterRootChecks(real)
	}
	fd, err := unix.Open(real, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	// the owner and the mode again, on the descriptor that was opened (the checks
	// by path above could have been about another directory)
	var rst unix.Stat_t
	if err := unix.Fstat(fd, &rst); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if int(rst.Uid) != os.Geteuid() {
		unix.Close(fd)
		return nil, fmt.Errorf("the layout directory %s is not owned by the user running this program", root)
	}
	if rst.Mode&0o022 != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("the layout directory %s is writable by its group or by everyone (mode %o); another user could replace an object in it. Run: chmod 700 %s", root, rst.Mode&0o777, root)
	}
	d := &Dir{rootFile: os.NewFile(uintptr(fd), real), root: real, pinPath: pin}
	if err := d.scan(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// OpenExisting is Open for a layout that must already be there: it never creates
// the directory. It is what the reader of a layout uses (store verify --layout,
// store convert --from-layout).
func OpenExisting(root, workspaceFile string) (*Dir, error) {
	// a name that is not a directory is refused by Open (the directory is opened
	// with O_DIRECTORY)
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("the layout directory %s cannot be read: %w", root, err)
	}
	return Open(root, workspaceFile)
}

// Close releases the directory descriptor.
func (d *Dir) Close() error { return d.rootFile.Close() }

// inside reports whether p is dir or below it.
func inside(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// PinPath is the file the pin is kept in.
func (d *Dir) PinPath() string { return d.pinPath }

// ---- the pin ----

var pinRE = regexp.MustCompile(`^spo-layout-pin 1 ([0-9]{1,20}) ([0-9a-f]{64})\n$`)

// Load reads the pin file. A file that does not parse is ErrLayoutPinCorrupt.
func (d *Dir) Load() (ports.LayoutPin, bool, error) {
	f, err := os.OpenFile(d.pinPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return ports.LayoutPin{}, false, nil
	}
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return ports.LayoutPin{}, false, fmt.Errorf("%w: %s is a link; move it away if you are sure, then run the command again", ports.ErrLayoutPinCorrupt, d.pinPath)
		}
		return ports.LayoutPin{}, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ports.LayoutPin{}, false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > 200 {
		return ports.LayoutPin{}, false, fmt.Errorf("%w: %s is not a small regular file; move it away if you are sure, then run the command again", ports.ErrLayoutPinCorrupt, d.pinPath)
	}
	b, err := io.ReadAll(io.LimitReader(f, 201))
	if err != nil {
		return ports.LayoutPin{}, false, err
	}
	m := pinRE.FindSubmatch(b)
	if m == nil {
		return ports.LayoutPin{}, false, fmt.Errorf("%w: %s does not parse; this tool does not replace it by itself. Check it, move it away if you are sure, then run the command again", ports.ErrLayoutPinCorrupt, d.pinPath)
	}
	seq, err := strconv.ParseUint(string(m[1]), 10, 64)
	if err != nil || seq == 0 {
		return ports.LayoutPin{}, false, fmt.Errorf("%w: the sequence number in %s is not valid", ports.ErrLayoutPinCorrupt, d.pinPath)
	}
	h, _ := hex.DecodeString(string(m[2]))
	return ports.LayoutPin{Sequence: seq, HeadHash: h}, true, nil
}

// Advance records pin atomically (a temporary file in the same directory,
// synced, renamed over the pin, the directory synced). It writes nothing when
// pin is the recorded one and refuses to move backwards.
func (d *Dir) Advance(pin ports.LayoutPin) error {
	if pin.Sequence == 0 || len(pin.HeadHash) != 32 {
		return errors.New("the pin is not a head sequence number and a 32-byte hash")
	}
	cur, found, err := d.Load()
	if err != nil {
		return err
	}
	if found {
		if cur.Sequence == pin.Sequence && hex.EncodeToString(cur.HeadHash) == hex.EncodeToString(pin.HeadHash) {
			return nil
		}
		if cur.Sequence >= pin.Sequence {
			return fmt.Errorf("%w: recorded sequence %d, offered %d", ports.ErrLayoutPinBackwards, cur.Sequence, pin.Sequence)
		}
	}
	dir := filepath.Dir(d.pinPath)
	sweepPinTemps(dir)
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".spo-pin-"+hex.EncodeToString(r[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	line := fmt.Sprintf("spo-layout-pin 1 %d %s\n", pin.Sequence, hex.EncodeToString(pin.HeadHash))
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, d.pinPath); err != nil {
		return err
	}
	ok = true
	dd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dd.Close()
	return dd.Sync()
}

// MaxEntries bounds how many entries the preflight scan looks at.
var MaxEntries = 1_000_000

// Test hooks (unexported variables, as elsewhere in this repository). readChunkHook
// is told how many names each read of a directory returned; afterRootChecks runs
// between the checks of the directory by path and its opening.
var (
	readChunkHook   func(n int)
	afterRootChecks func(path string)
)

var pinTmpRE = regexp.MustCompile(`^\.spo-pin-[0-9a-f]{16}$`)

// sweepPinTemps removes the tool's own stale pin temporary files beside the
// workspace file: regular files named .spo-pin-<16 hex>, owned by this user, older
// than an hour. A link or anything else is left alone.
func sweepPinTemps(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !pinTmpRE.MatchString(e.Name()) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || time.Since(fi.ModTime()) <= time.Hour {
			continue
		}
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok && int(sys.Uid) == os.Geteuid() {
			os.Remove(p)
		}
	}
}
