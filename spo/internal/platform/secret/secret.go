// Package secret holds key material in locked, guarded memory.
//
// Secret bytes never become a Go string and are never copied into ordinary
// heap memory by this package. Callers get access through Buffer.Use, which
// lends the bytes for the duration of a function.
//
// MEMORY BUDGET. Every buffer locks whole pages with mlock, and a process may
// lock only RLIMIT_MEMLOCK bytes. memguard does not return an error when the
// limit is hit: it wipes every live buffer and panics. This package therefore
// counts the pages its buffers lock (see Budget) and refuses with
// ErrMemoryLimit before calling memguard when a request would not fit. Use
// the Try functions (TryNew, TryTake, TryRead) and Fill wherever a failure
// can be handled; New and Take cannot return an error, so they panic with
// ErrMemoryLimit in the message. The count covers buffers made through this
// package; pages locked by memguard itself (its internal key) are covered by
// a fixed reserve.
package secret

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/awnumar/memguard"
)

// Buffer is a secret value in guarded memory. The zero value is unusable;
// build one with New, Take, Read or Fill.
type Buffer struct {
	b     *memguard.LockedBuffer
	cost  uint64 // locked bytes charged to the budget
	epoch uint64 // budget generation the charge belongs to
	once  sync.Once
}

// ErrDestroyed is returned when a destroyed buffer is used.
var ErrDestroyed = errors.New("secret: buffer destroyed")

// ErrMemoryLimit is returned when locking one more buffer would exceed the
// process's locked-memory budget.
var ErrMemoryLimit = errors.New("secret: locked-memory limit reached (destroy unused secrets or raise RLIMIT_MEMLOCK)")

// reservePages is kept free for pages memguard locks for its own use.
const reservePages = 8

// Stats is a snapshot of the locked-memory budget.
type Stats struct {
	Limit     uint64 // bytes this package may lock; meaningless when Unlimited
	Unlimited bool   // no RLIMIT_MEMLOCK, or a platform without one
	Used      uint64 // locked bytes charged to live buffers
	Live      int    // live buffers that lock memory
}

var acct struct {
	mu    sync.Mutex
	done  bool
	stats Stats
	epoch uint64
}

// MinimumBudget is the smallest RLIMIT_MEMLOCK, in bytes, with which one open
// sealed store can open one secret of maxSecret bytes (seal.MaxSecret, 1 MiB).
// It adds, in whole pages:
//
//   - 6 pages: the master key and the three keys derived from it, the
//     operator's credential, and the data key of the record being opened;
//   - the padded plaintext, which the seal framing rounds up to the next power
//     of two of maxSecret+4 bytes, and the payload copied out of it (for 1 MiB
//     that is 2 MiB and 1 MiB);
//   - the reserve for pages memguard locks for itself (reservePages).
//
// With 4 KiB pages and maxSecret = 1 MiB that is 14 pages plus 3 MiB:
// 3,203,072 bytes. With 64 KiB pages it is 4,063,232. The limit most systems
// grant an ordinary user is far above this (typically 8 MiB or more), but
// containers and some service managers set it to 64 KiB, which is too little:
// raise it (LimitMEMLOCK=, ulimit -l) or the store reports ErrMemoryLimit.
// Writing a secret needs more (the padded copy, the staged copy and the
// caller's own buffer: about twice this).
func MinimumBudget(maxSecret int) uint64 {
	ps := uint64(os.Getpagesize())
	framed := 256
	for framed < maxSecret+4 {
		framed <<= 1
	}
	return (6+reservePages)*ps + pagesFor(framed) + pagesFor(maxSecret)
}

// Init reads RLIMIT_MEMLOCK, raises the soft limit to the hard limit, and
// sets the budget from the result. It runs once; later calls return nil.
// Every constructor calls it, so calling Init explicitly only matters to see
// its error. The budget is set even when raising the limit failed (from the
// limit in force), and the error says so.
func Init() error {
	acct.mu.Lock()
	defer acct.mu.Unlock()
	return initLocked()
}

func initLocked() error {
	if acct.done {
		return nil
	}
	acct.done = true
	limit, unlimited, err := raiseMemlock()
	if !unlimited {
		reserve := uint64(reservePages * os.Getpagesize())
		if limit > reserve {
			limit -= reserve
		} else {
			limit = 0
		}
	}
	acct.stats.Limit, acct.stats.Unlimited = limit, unlimited
	return err
}

// Budget returns the current state of the locked-memory budget.
func Budget() Stats {
	acct.mu.Lock()
	defer acct.mu.Unlock()
	initLocked()
	return acct.stats
}

// pagesFor is the number of bytes mlock covers for an n-byte buffer: whole
// pages. memguard adds two guard pages that are not locked.
func pagesFor(n int) uint64 {
	if n < 1 {
		return 0
	}
	ps := uint64(os.Getpagesize())
	return (uint64(n) + ps - 1) / ps * ps
}

// charge reserves budget for n bytes, or returns ErrMemoryLimit.
func charge(n int) (cost, epoch uint64, err error) {
	acct.mu.Lock()
	defer acct.mu.Unlock()
	initLocked()
	cost = pagesFor(n)
	if cost == 0 {
		return 0, acct.epoch, nil
	}
	if !acct.stats.Unlimited && acct.stats.Used+cost > acct.stats.Limit {
		return 0, 0, ErrMemoryLimit
	}
	acct.stats.Used += cost
	acct.stats.Live++
	return cost, acct.epoch, nil
}

func uncharge(cost, epoch uint64) {
	acct.mu.Lock()
	defer acct.mu.Unlock()
	if cost == 0 || epoch != acct.epoch {
		return
	}
	acct.stats.Used -= cost
	acct.stats.Live--
}

func wrap(b *memguard.LockedBuffer, cost, epoch uint64) *Buffer {
	return &Buffer{b: b, cost: cost, epoch: epoch}
}

// TryNew returns a buffer of n random bytes, or ErrMemoryLimit.
func TryNew(n int) (*Buffer, error) {
	cost, epoch, err := charge(n)
	if err != nil {
		return nil, err
	}
	return wrap(memguard.NewBufferRandom(n), cost, epoch), nil
}

// New is TryNew that panics with ErrMemoryLimit when the budget is exhausted.
func New(n int) *Buffer {
	b, err := TryNew(n)
	if err != nil {
		panic(fmt.Sprintf("secret.New(%d): %v", n, err))
	}
	return b
}

// TryTake moves src into guarded memory and wipes src. It wipes src also when
// it fails, so a refused secret does not linger in the caller's slice.
func TryTake(src []byte) (*Buffer, error) {
	cost, epoch, err := charge(len(src))
	if err != nil {
		clear(src)
		return nil, err
	}
	return wrap(memguard.NewBufferFromBytes(src), cost, epoch), nil
}

// Take is TryTake that panics with ErrMemoryLimit when the budget is
// exhausted.
func Take(src []byte) *Buffer {
	b, err := TryTake(src)
	if err != nil {
		panic(fmt.Sprintf("secret.Take(%d bytes): %v", len(src), err))
	}
	return b
}

// Fill returns a buffer of n bytes that fn writes into directly, so a value
// that is computed (a decryption, a derived key) never exists outside
// guarded memory. The buffer is destroyed, and its charge released, when fn
// fails or panics. It returns ErrMemoryLimit, without calling fn, when the
// budget is exhausted.
func Fill(n int, fn func(b []byte) error) (*Buffer, error) {
	cost, epoch, err := charge(n)
	if err != nil {
		return nil, err
	}
	b := memguard.NewBuffer(n)
	ok := false
	defer func() {
		if !ok {
			b.Destroy()
			uncharge(cost, epoch)
		}
	}()
	if err := fn(b.Bytes()); err != nil {
		return nil, err
	}
	b.Freeze()
	ok = true
	return wrap(b, cost, epoch), nil
}

// alloc charges the budget for n bytes and then allocates a zeroed buffer.
func alloc(n int) (*memguard.LockedBuffer, uint64, uint64, error) {
	cost, epoch, err := charge(n)
	if err != nil {
		return nil, 0, 0, err
	}
	return memguard.NewBuffer(n), cost, epoch, nil
}

func drop(b *memguard.LockedBuffer, cost, epoch uint64) {
	b.Destroy()
	uncharge(cost, epoch)
}

// maxEmptyReads is how many consecutive reads that return neither data nor an
// error TryRead tolerates before it gives up with io.ErrNoProgress (the same
// rule as bufio).
const maxEmptyReads = 100

// TryRead fills a new buffer from r until EOF. The data never leaves guarded
// memory: it is read into a buffer of one page that doubles when full
// (guarded to guarded copy, the old buffer destroyed), and at EOF it is
// copied once more into a buffer of exactly its size. Every allocation is
// charged to the budget before it is made, so a reader that delivers more
// than the budget allows gets ErrMemoryLimit and nothing is locked beyond the
// limit. At its peak the read holds the full buffer and its double (and, at
// the end, the exact-size copy), all charged. On a read error the data read
// so far is wiped and the error returned; so it is when the reader panics. A
// reader that returns (0, nil) maxEmptyReads times in a row makes no progress
// and fails with io.ErrNoProgress.
func TryRead(r io.Reader) (*Buffer, error) {
	size := os.Getpagesize()
	cur, cost, epoch, err := alloc(size)
	if err != nil {
		return nil, err
	}
	defer func() { drop(cur, cost, epoch) }() // whichever buffer is current when we leave
	n, empty := 0, 0
	var rerr error
	for rerr == nil {
		if n == size {
			next, nc, ne, err := alloc(2 * size)
			if err != nil {
				return nil, err
			}
			copy(next.Bytes(), cur.Bytes())
			drop(cur, cost, epoch)
			cur, cost, epoch, size = next, nc, ne, 2*size
		}
		var m int
		m, rerr = r.Read(cur.Bytes()[n:])
		n += m
		if m == 0 && rerr == nil {
			if empty++; empty >= maxEmptyReads {
				rerr = io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
	if rerr != io.EOF {
		return nil, rerr
	}
	exact, ec, ee, err := alloc(n)
	if err != nil {
		return nil, err
	}
	copy(exact.Bytes(), cur.Bytes()[:n])
	if n > 0 {
		exact.Freeze()
	}
	return wrap(exact, ec, ee), nil
}

// Read is TryRead. It returns ErrMemoryLimit rather than panicking.
func Read(r io.Reader) (*Buffer, error) { return TryRead(r) }

// Use lends the secret bytes to fn. The slice is valid only until fn returns
// and must not be retained or copied into ordinary memory.
func (s *Buffer) Use(fn func(b []byte) error) error {
	if s == nil || s.b == nil || !s.b.IsAlive() {
		return ErrDestroyed
	}
	return fn(s.b.Bytes())
}

// Len returns the size in bytes, or 0 when destroyed.
func (s *Buffer) Len() int {
	if s == nil || s.b == nil {
		return 0
	}
	return s.b.Size()
}

// WriteTo writes the secret to w. It exists so a secret can be sent down a
// pipe to a child process without an intermediate copy.
func (s *Buffer) WriteTo(w io.Writer) (int64, error) {
	var n int
	err := s.Use(func(b []byte) error {
		var werr error
		n, werr = w.Write(b)
		return werr
	})
	return int64(n), err
}

// Destroy wipes and releases the memory. It is safe to call twice.
func (s *Buffer) Destroy() {
	if s == nil || s.b == nil {
		return
	}
	s.once.Do(func() {
		s.b.Destroy()
		uncharge(s.cost, s.epoch)
	})
}

// String never reveals the content, so a Buffer is safe in a format verb.
func (s *Buffer) String() string { return "[secret]" }

// GoString never reveals the content.
func (s *Buffer) GoString() string { return "[secret]" }

// MarshalText refuses, so a Buffer cannot be serialised by accident.
func (s *Buffer) MarshalText() ([]byte, error) {
	return nil, errors.New("secret: refusing to serialise")
}

// Purge wipes every live buffer and resets the budget. Call it before the
// process exits.
func Purge() {
	memguard.Purge()
	acct.mu.Lock()
	defer acct.mu.Unlock()
	acct.epoch++
	acct.stats.Used, acct.stats.Live = 0, 0
}
