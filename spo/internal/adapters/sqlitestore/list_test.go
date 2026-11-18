package sqlitestore

import (
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func listRefs(t *testing.T, s *Store) []ports.Ref {
	t.Helper()
	all, err := s.ListRecords(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// the role histories the fixture writes for its signing keys are not what these tests list
	var out []ports.Ref
	for _, r := range all {
		if r.Kind != ports.RoleHistory {
			out = append(out, r)
		}
	}
	return out
}

func listWant() []ports.Ref {
	// sorted by anchor, kind, number
	want := []ports.Ref{
		rf("alpha", ports.AddrVKey),
		rf("alpha", ports.KesSKey, 2),
		rf("alpha", ports.KesVKey, 0),
		rf("alpha", ports.KesVKey, 1),
		rf("alpha", ports.KesVKey, 2), // written beside the signing key kes.skey#2
		rf("pool.one", ports.NodeSKey),
		rf("pool.one", ports.NodeVKey), // written beside the signing key
		rf("zed", ports.PolicySKey),
		rf("zed", ports.PolicyVKey), // written beside the signing key
	}
	sort.Slice(want, func(i, j int) bool {
		a, b := want[i], want[j]
		if c := a.Anchor.Compare(b.Anchor); c != 0 {
			return c < 0
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Num < b.Num
	})
	return want
}

func fillList(t *testing.T, s *Store) {
	t.Helper()
	s.SetColdSource(coldPass("a cold sub-key passphrase")) // node.skey is a pool cold key
	put(t, s, rf("alpha", ports.AddrVKey), "v")
	put(t, s, rf("alpha", ports.KesVKey, 1), "k1")
	put(t, s, rf("alpha", ports.KesVKey, 0), "k0")
	putSecret(t, s, rf("alpha", ports.KesSKey, 2), "s")
	putSecret(t, s, rf("pool.one", ports.NodeSKey), "n")
	putSecret(t, s, rf("zed", ports.PolicySKey), "p")
}

func TestListSeveralKinds(t *testing.T) {
	s, _, _ := scratch(t)
	fillList(t, s)
	if got := listRefs(t, s); !reflect.DeepEqual(got, listWant()) {
		t.Fatalf("got %v\nwant %v", got, listWant())
	}
	// A delete and an overwrite are reflected, and List writes nothing.
	rows := count(t, s, "audit")
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Delete(rf("alpha", ports.AddrVKey)) }); err != nil {
		t.Fatal(err)
	}
	var want []ports.Ref
	for _, r := range listWant() {
		if r != rf("alpha", ports.AddrVKey) {
			want = append(want, r)
		}
	}
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
	l, err := s.ListRecords(ctx)
	if err != nil || len(l) != 0 {
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
	_, err := s.ListRecords(ctx)
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
	if _, err := s.ListRecords(ctx); !errors.Is(err, ErrVerify) {
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
	if _, err := b.ListRecords(ctx); !errors.Is(err, ErrStaleHandle) {
		t.Fatalf("got %v, want ErrStaleHandle", err)
	}
}
