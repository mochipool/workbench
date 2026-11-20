//go:build unix

package relaydir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func dirs(t *testing.T) (m, r string) {
	t.Helper()
	root := t.TempDir()
	m, r = filepath.Join(root, "mail"), filepath.Join(root, "registry")
	for _, d := range []string{filepath.Join(m, "mailbox"), filepath.Join(r, "tombstones"), filepath.Join(r, "bindings")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return m, r
}

// The reader refuses what the directory stores refuse, takes both locks, and
// writes nothing but a missing lock file.
//
// spec: SPO-Xobjstore-IF-905
func TestTheReaderRefusesWhatTheStoresRefuse(t *testing.T) {
	m, r := dirs(t)
	s, err := Open(m, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(m, r); !errors.Is(err, ErrLocked) {
		t.Errorf("a second open: %v", err)
	}
	if ts, err := s.Tombstones(); err != nil || len(ts) != 0 {
		t.Errorf("tombstones of an empty store: %v %v", ts, err)
	}
	s.Close()
	for name, plant := range map[string]func(){
		"a stray tombstone name": func() { os.WriteFile(filepath.Join(r, "tombstones", "x"), []byte("x"), 0o600) },
		"a short tombstone": func() {
			os.WriteFile(filepath.Join(r, "tombstones", "d-"+string(make40('a'))), []byte("SPORT1\n"), 0o600)
		},
		"a link": func() { os.Symlink("/etc/passwd", filepath.Join(r, "bindings", string(make40('b')))) },
	} {
		t.Run(name, func(t *testing.T) {
			m, r2 := dirs(t)
			r = r2
			plant()
			s, err := Open(m, r)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			_, terr := s.Tombstones()
			_, berr := s.Bindings()
			if terr == nil && berr == nil {
				t.Error("nothing was refused")
			}
		})
	}
	m, r = dirs(t)
	if err := os.Chmod(r, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(m, r); !errors.Is(err, ErrNotAStore) {
		t.Errorf("a group-writable directory: %v", err)
	}
}

// Of two entries with one sender and id the earlier is read and the later
// skipped and noted, as the mailbox store keeps the earlier; temporary files
// are skipped.
//
// spec: SPO-Xobjstore-IF-905
func TestTheReaderKeepsTheEarlierOfTwoCopies(t *testing.T) {
	m, r := dirs(t)
	box := filepath.Join(m, "mailbox", string(make40('c')))
	if err := os.MkdirAll(box, 0o700); err != nil {
		t.Fatal(err)
	}
	mid, snd := make([]byte, 64), make40('d')
	for i := range mid {
		mid[i] = 'e'
	}
	for _, n := range []string{"00000000000000000200", "00000000000000000100"} {
		if err := os.WriteFile(filepath.Join(box, n+"-"+string(mid)+"-"+string(snd)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(box, ".tmp-0123456789abcdef"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(m, r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	es, err := s.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].Arrival != 100 || len(s.Notes()) != 2 {
		t.Errorf("entries %+v, notes %v", es, s.Notes())
	}
	if b, err := s.Read(es[0]); err != nil || string(b) != "x" {
		t.Errorf("read: %q %v", b, err)
	}
}

func make40(c byte) []byte {
	b := make([]byte, 40)
	for i := range b {
		b[i] = c
	}
	return b
}
