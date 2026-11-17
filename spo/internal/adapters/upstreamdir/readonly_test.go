package upstreamdir

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The read-only source has no method that writes: its whole method set is
// listed here, and a new one fails the test and must be argued for. The type is
// also not a ports.Store (no Update), so a use case that writes cannot be handed
// one.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-IN-001
func TestSourceHasNoWriteMethod(t *testing.T) {
	typ := reflect.TypeOf(&Source{})
	var got []string
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	sort.Strings(got)
	want := []string{"Dir", "List", "Open", "Subdirs", "View"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("methods %v, want %v", got, want)
	}
	if _, isStore := any(&Source{}).(ports.Store); isStore {
		t.Error("Source implements ports.Store")
	}
	// The reader a View hands out has Get and Exists only.
	rt := reflect.TypeOf(reader{})
	for i := 0; i < rt.NumMethod(); i++ {
		if n := rt.Method(i).Name; n != "Get" && n != "Exists" {
			t.Errorf("reader has the method %s", n)
		}
	}
	if _, ok := any(reader{}).(ports.Writer); ok {
		t.Error("the reader of a View is a Writer")
	}
}

// Reading, listing and opening a source leaves every file as it was.
func TestReadingASourceChangesNothing(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{"p.node.vkey": "v", "p.node.skey": "{}", "p.pool.json": "{}", "notes.txt": "x"}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	snap := func() map[string]string {
		out := map[string]string{}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			st, _ := os.Stat(filepath.Join(dir, e.Name()))
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			out[e.Name()] = st.Mode().String() + string(b)
		}
		return out
	}
	before := snap()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.List(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Subdirs(ctx); err != nil {
		t.Fatal(err)
	}
	if buf, err := s.Open(ctx, ports.Ref{Name: "p", Kind: ports.NodeSKey}); err != nil {
		t.Fatal(err)
	} else {
		buf.Destroy()
	}
	_ = s.View(ctx, func(r ports.Reader) error {
		_, _ = r.Get(ports.Ref{Name: "p", Kind: ports.NodeVKey})
		_, _ = r.Get(ports.Ref{Name: "p", Kind: ports.NodeSKey}) // refused: a secret kind
		_, _ = r.Exists(ports.Ref{Name: "q", Kind: ports.NodeVKey})
		return nil
	})
	if !reflect.DeepEqual(before, snap()) {
		t.Error("reading the source changed it")
	}
}
