package n2c

import (
	"context"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c/n2ctest"
)

const testMagic = n2ctest.Magic // preview

// A fakeNode is the in-process node of n2ctest with the lower-case helpers
// these tests were written against.
type fakeNode struct {
	*n2ctest.Node
	path string
}

func startFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	n := n2ctest.Start(t)
	return &fakeNode{Node: n, path: n.Path()}
}

func (n *fakeNode) set(name string, v any)             { n.Set(name, v) }
func (n *fakeNode) setRaw(name, hexBytes string)       { n.SetRaw(name, hexBytes) }
func (n *fakeNode) setFn(name string, f func(any) any) { n.SetFn(name, f) }
func (n *fakeNode) fail(name string, err error)        { n.Fail(name, err) }
func (n *fakeNode) questions() []string                { return n.Questions() }
func (n *fakeNode) stop()                              { n.Stop() }

func (n *fakeNode) config() Config {
	return Config{Address: n.path, NetworkMagic: testMagic, Network: "preview", Timeout: 5 * time.Second}
}

func (n *fakeNode) dial(t *testing.T) *Client {
	t.Helper()
	c, err := Dial(context.Background(), n.config())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
