package cli

import (
	"reflect"
	"testing"
)

// What the wiring opened lazily (a node connection) is released when the
// command's Env is closed: last registered first, once, and a nil Env is safe.
func TestEnvCloseRunsTheRegisteredClosersOnceLastFirst(t *testing.T) {
	var order []string
	e := &Env{}
	e.OnClose(func() { order = append(order, "first") })
	e.OnClose(func() { order = append(order, "second") })
	e.Close()
	e.Close()
	if want := []string{"second", "first"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("closed in order %v, want %v", order, want)
	}
	var none *Env
	none.Close()
}

// A second source that is the same provider as the answering one is refused
// for the opcert counter as for the other harmful-class reads.
func TestSameProviderCannotCorroborateTheOpcertCounter(t *testing.T) {
	same := cliCounters{}
	e := &Env{OpCertCounters: same, OpCertCross: same}
	if err := e.CheckIndependentSources(); err == nil {
		t.Fatal("one provider was accepted as its own second source")
	}
}
