package sqlitestore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
)

// Head is the end of the audit chain: the sequence number and MAC of the
// newest row. An empty chain is (0, 32 zero bytes).
type Head struct {
	Seq uint64
	MAC []byte
}

func (h Head) String() string { return fmt.Sprintf("seq %d mac %s", h.Seq, hex.EncodeToString(h.MAC)) }

func (h Head) equal(o Head) bool { return h.Seq == o.Seq && bytes.Equal(h.MAC, o.MAC) }

// The head file.
//
// ROLLBACK DEFENCE. Records are authenticated and the audit chain covers
// them, but a copy of the whole file from an earlier day is internally
// consistent and verifies. To notice one, the store writes <path>.head after
// every committed write: four text lines
//
//	spo-workbench-head 1
//	workspace <32 hex digits>
//	seq <decimal>
//	mac <64 hex digits>
//
// written to a temporary file (mode 0600) in the same directory, synced,
// renamed over the old head file, and the directory synced.
//
// The head file only moves forward. Writers take an exclusive flock on
// <path>.head.lock around reading the current head file and replacing it, and
// replace it only when the new sequence number is greater (advanceHeadFile);
// two handles committing at once cannot leave the older head behind. Three
// callers replace it unconditionally, under the same lock: a restore (a
// deliberate change of state, possibly of workspace), Open with
// AcceptRollback, and Init. A rekey needs no special case: its rollover row
// has the next sequence number.
//
// Reading is hardened: the head file is opened with O_NOFOLLOW|O_NONBLOCK and
// the opened descriptor must be a regular file owned by the current user, at most headMaxSize bytes, and in exactly the
// canonical text form (decimal without leading zeros, lower-case hex). A head
// file that is not is treated as unreadable (ErrHeadMismatch at Open). Open refuses a
// workspace whose chain does not contain that (seq, mac), that is, a file
// older than the last recorded state, unless OpenOptions.AcceptRollback is
// set. A missing head file is recreated by a read-write Open and reported in
// Store.Notices; a read-only open or verification reports it and creates
// nothing.
//
// WHAT THIS DOES NOT DO. The head file is not secret and not authenticated
// (it cannot be: anyone who can write it can also read the file's MACs).
// Someone who can replace both the workspace file and its head file with an
// older matching pair defeats this check, as does deleting the head file
// together with rolling the workspace back (it is then recreated from the
// older state). It catches the common accident and the attacker who restores
// one file only. For more, record Head() (printed by Verify and Backup)
// somewhere the attacker cannot write, and compare.
const (
	headMagic   = "spo-workbench-head 1"
	headMaxSize = 256
)

func headPath(path string) string { return path + ".head" }

func encodeHead(ws []byte, h Head) []byte {
	return fmt.Appendf(nil, "%s\nworkspace %s\nseq %d\nmac %s\n", headMagic, hex.EncodeToString(ws), h.Seq, hex.EncodeToString(h.MAC))
}

// decodeHead parses the head file strictly.
func decodeHead(b []byte) (ws []byte, h Head, err error) {
	lines := strings.Split(string(b), "\n")
	if len(lines) != 5 || lines[4] != "" || lines[0] != headMagic {
		return nil, h, errors.New("not a head file")
	}
	field := func(i int, name string) (string, error) {
		v, ok := strings.CutPrefix(lines[i], name+" ")
		if !ok {
			return "", fmt.Errorf("missing %s", name)
		}
		return v, nil
	}
	w, err := field(1, "workspace")
	if err != nil {
		return nil, h, err
	}
	sq, err := field(2, "seq")
	if err != nil {
		return nil, h, err
	}
	m, err := field(3, "mac")
	if err != nil {
		return nil, h, err
	}
	if ws, err = hex.DecodeString(w); err != nil || len(ws) != seal.IDSize || hex.EncodeToString(ws) != w {
		return nil, h, errors.New("bad workspace id")
	}
	if h.Seq, err = strconv.ParseUint(sq, 10, 64); err != nil || strconv.FormatUint(h.Seq, 10) != sq {
		return nil, h, errors.New("bad sequence number")
	}
	if h.MAC, err = hex.DecodeString(m); err != nil || len(h.MAC) != seal.MACSize || hex.EncodeToString(h.MAC) != m {
		return nil, h, errors.New("bad mac")
	}
	return ws, h, nil
}

// writeHeadFile records h, replacing whatever head file there is, under the
// head lock.
func writeHeadFile(path string, ws []byte, h Head) error {
	return withHeadLock(path, func() error { return replaceHeadFile(path, ws, h) })
}

// advanceHeadFile records h unless the head file already names this workspace
// at the same or a later sequence number.
func advanceHeadFile(path string, ws []byte, h Head) error {
	return withHeadLock(path, func() error {
		if hws, cur, found, err := readHeadFile(path); found && err == nil && bytes.Equal(hws, ws) && cur.Seq >= h.Seq {
			return nil
		}
		return replaceHeadFile(path, ws, h)
	})
}

// replaceHeadFile writes the head file atomically. The caller holds the lock.
func replaceHeadFile(path string, ws []byte, h Head) error {
	hp := headPath(path)
	tmp, err := os.CreateTemp(filepath.Dir(hp), ".head-*") // mode 0600
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp.Name())
		}
	}()
	if _, err := tmp.Write(encodeHead(ws, h)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), hp); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(hp))
}

// readHeadFile returns found=false when there is no head file. A head file
// that is a symlink or other non-regular file, belongs to another user, is
// larger than headMaxSize, or does not parse strictly is found with an error.
// The file is opened once, without following a symlink and without blocking,
// and the checks are made on the opened descriptor (there is no window between
// checking a path and opening it).
func readHeadFile(path string) (ws []byte, h Head, found bool, err error) {
	hp := headPath(path)
	f, err := os.OpenFile(hp, os.O_RDONLY|openHeadFlags, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, h, false, nil
	}
	if err != nil {
		return nil, h, true, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, h, true, err
	}
	if !st.Mode().IsRegular() {
		return nil, h, true, fmt.Errorf("%s is not a regular file", hp)
	}
	if err := checkOwner(hp, st); err != nil {
		return nil, h, true, err
	}
	b, err := io.ReadAll(io.LimitReader(f, headMaxSize+1))
	if err != nil {
		return nil, h, true, err
	}
	if len(b) > headMaxSize {
		return nil, h, true, fmt.Errorf("%s is larger than %d bytes", hp, headMaxSize)
	}
	ws, h, err = decodeHead(b)
	return ws, h, true, err
}

// chainHead returns the newest audit row's (seq, mac), or (0, zeros).
func chainHead(ctx context.Context, q dbq) (Head, error) {
	var seq int64
	var mac []byte
	err := q.QueryRowContext(ctx, `SELECT seq, mac FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&seq, &mac)
	if errors.Is(err, sql.ErrNoRows) {
		return Head{MAC: zeroMAC}, nil
	}
	if err != nil {
		return Head{}, err
	}
	return Head{Seq: uint64(seq), MAC: mac}, nil
}

// chainContains reports whether the audit chain has a row with h's sequence
// number and MAC. Every chain contains (0, zeros).
func chainContains(ctx context.Context, q dbq, h Head) (bool, error) {
	if h.Seq == 0 {
		return bytes.Equal(h.MAC, zeroMAC), nil
	}
	var mac []byte
	err := q.QueryRowContext(ctx, `SELECT mac FROM audit WHERE seq = ?`, int64(h.Seq)).Scan(&mac)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil && bytes.Equal(mac, h.MAC), err
}

// Head returns the end of the audit chain as this handle last saw or wrote
// it. Record it somewhere an attacker cannot write to defeat a rollback that
// replaces both the workspace file and its head file.
func (s *Store) Head() (seq uint64, mac []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head.Seq, append([]byte(nil), s.head.MAC...)
}

// Notices returns non-fatal messages from opening the store (a recreated head
// file, key slots that were skipped) for the caller to display.
func (s *Store) Notices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.notices...)
}

// notice records a non-fatal message for Notices.
func (s *Store) notice(msg string) {
	s.mu.Lock()
	s.notices = append(s.notices, msg)
	s.mu.Unlock()
}

func (s *Store) setHead(h Head) {
	s.mu.Lock()
	s.head = h
	s.mu.Unlock()
}
