package sqlitestore

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func listRefs(t *testing.T, s *Store) []ports.Ref {
	t.Helper()
	l, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Unknown) != 0 {
		t.Fatalf("unknown entries: %v", l.Unknown)
	}
	var out []ports.Ref
	for _, e := range l.Entries {
		out = append(out, e.Ref)
	}
	return out
}

func listWant() []ports.Ref {
	// sorted by name, kind, number
	return []ports.Ref{
		{Name: "alpha", Kind: ports.AddrVKey},
		{Name: "alpha", Kind: ports.KesSKey, Num: 2},
		{Name: "alpha", Kind: ports.KesVKey, Num: 0},
		{Name: "alpha", Kind: ports.KesVKey, Num: 1},
		{Name: "pool.one", Kind: ports.NodeSKey},
		{Name: "zed", Kind: ports.PolicySKey},
	}
}

func fillList(t *testing.T, s *Store) {
	t.Helper()
	put(t, s, ports.Ref{Name: "alpha", Kind: ports.AddrVKey}, "v")
	put(t, s, ports.Ref{Name: "alpha", Kind: ports.KesVKey, Num: 1}, "k1")
	put(t, s, ports.Ref{Name: "alpha", Kind: ports.KesVKey, Num: 0}, "k0")
	putSecret(t, s, ports.Ref{Name: "alpha", Kind: ports.KesSKey, Num: 2}, "s")
	putSecret(t, s, ports.Ref{Name: "pool.one", Kind: ports.NodeSKey}, "n")
	putSecret(t, s, ports.Ref{Name: "zed", Kind: ports.PolicySKey}, "p")
}

func TestListSeveralKinds(t *testing.T) {
	s, _, _ := scratch(t)
	fillList(t, s)
	if got := listRefs(t, s); !reflect.DeepEqual(got, listWant()) {
		t.Fatalf("got %v\nwant %v", got, listWant())
	}
	// A delete and an overwrite are reflected, and List writes nothing.
	rows := count(t, s, "audit")
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Delete(ports.Ref{Name: "alpha", Kind: ports.AddrVKey}) }); err != nil {
		t.Fatal(err)
	}
	want := listWant()[1:]
	if got := listRefs(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("after delete: got %v", got)
	}
	before := count(t, s, "audit")
	listRefs(t, s)
	if count(t, s, "audit") != before || before != rows+1 {
		t.Fatalf("List wrote audit rows: %d -> %d", before, count(t, s, "audit"))
	}
}

func TestListEmpty(t *testing.T) {
	s, _, _ := scratch(t)
	l, err := s.List(ctx)
	if err != nil || len(l.Entries) != 0 {
		t.Fatalf("%v %v", l, err)
	}
}

func TestListAfterRekey(t *testing.T) {
	s, _, _ := scratch(t)
	fillList(t, s)
	rekeyTo(t, s, "np")
	if got := listRefs(t, s); !reflect.DeepEqual(got, listWant()) {
		t.Fatalf("after rekey: got %v", got)
	}
}

func TestListTamperedOwnerBlobIsVerifyError(t *testing.T) {
	s, _, _ := scratch(t)
	fillList(t, s)
	exec(t, s, `UPDATE records SET owner_sealed = zeroblob(length(owner_sealed)) WHERE kind = 'addr.vkey'`)
	_, err := s.List(ctx)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("got %v, want ErrVerify", err)
	}
	for _, n := range []string{"alpha", "pool.one", "zed"} {
		if err != nil && strings.Contains(err.Error(), n) {
			t.Fatalf("the error names %q: %v", n, err)
		}
	}
}

func TestListRowMissingFromTableIsVerifyError(t *testing.T) {
	s, _, _ := scratch(t)
	fillList(t, s)
	exec(t, s, `DELETE FROM records WHERE kind = 'addr.vkey'`)
	if _, err := s.List(ctx); !errors.Is(err, ErrVerify) {
		t.Fatalf("got %v, want ErrVerify", err)
	}
}

func TestListOnStaleHandle(t *testing.T) {
	a, path, _ := scratch(t)
	put(t, a, counter, "1")
	b, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.lock.Close()
	b.lock, _ = os.Open(path) // no flock: lets the rekey through, as review2's test does
	rekeyTo(t, a, "np")
	if _, err := b.List(ctx); !errors.Is(err, ErrStaleHandle) {
		t.Fatalf("got %v, want ErrStaleHandle", err)
	}
}
