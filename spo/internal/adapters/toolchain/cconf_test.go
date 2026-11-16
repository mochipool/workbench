package toolchain

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// cardano-node is located and its version read from `<node> version` (the
// second word of the first line, like the cli's), then held to the same
// minimum, maximum and pin. A node that is not there fails the lookup. The
// port asks for the node only when the composition needs one (SPO-Cconf-MODE-002
// is about which mode asks: the Tool call is made by the node adapter).
//
// spec: SPO-Cconf-PRE-009, SPO-Cconf-EXT-003, SPO-Cconf-PRE-010, SPO-Cconf-PRE-011, SPO-Cconf-INV-008, SPO-Cconf-OUT-004
func TestNodeGates(t *testing.T) {
	node := exe(t, "cardano-node")
	const out = "cardano-node 11.0.1 - linux-x86_64 - ghc-9.6\ngit rev abc\n"
	tool := func(e Entry, o string) (ports.Tool, error) {
		e.Path = node
		tc := New(Manifest{Release: "test", Tools: map[ports.ToolName]Entry{ports.CardanoNode: e}}, &fakeRunner{out: map[string]string{node: o}})
		return tc.Tool(context.Background(), ports.CardanoNode)
	}
	if got, err := tool(Entry{Min: "11.0.0", Max: "99.99.9"}, out); err != nil || got.Version != "11.0.1" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := tool(Entry{Min: "11.1.0"}, out); !errors.Is(err, ErrVersion) {
		t.Errorf("below the minimum: %v", err)
	}
	if _, err := tool(Entry{Min: "10.0.0", Max: "11.0.0"}, out); !errors.Is(err, ErrVersion) {
		t.Errorf("above the maximum: %v", err)
	}
	// The pins come from the release set the binary was built with; the
	// installed tool must equal the pinned version, which no user file can change.
	if _, err := tool(Entry{Version: "11.0.0", Min: "11.0.0"}, out); !errors.Is(err, ErrVersion) {
		t.Errorf("differs from the pin: %v", err)
	}
	tc := New(Manifest{Tools: map[ports.ToolName]Entry{ports.CardanoNode: {Path: "/nonexistent/cardano-node"}}}, &fakeRunner{})
	if _, err := tc.Tool(context.Background(), ports.CardanoNode); !errors.Is(err, ErrMissing) {
		t.Errorf("a missing node: %v", err)
	}
}
