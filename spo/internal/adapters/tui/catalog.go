package tui

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// node is one entry of the menu: a group of commands or a command. The menu
// is generated from the command tree and holds no knowledge of any command.
type node struct {
	cmd      *cobra.Command
	path     []string // command names below the root
	children []*node
}

func (n *node) name() string { return n.cmd.Name() }
func (n *node) runnable() bool {
	return n.cmd.Runnable()
}
func (n *node) pathString() string { return strings.Join(n.path, " ") }

// visible reports whether a command appears in the menu: hidden commands and
// the ones cobra adds itself (help, completion) do not.
func visible(c *cobra.Command, atRoot bool) bool {
	if c.Hidden || c.Deprecated != "" {
		return false
	}
	if atRoot && (c.Name() == "help" || c.Name() == "completion") {
		return false
	}
	return true
}

// buildTree walks the command tree.
func buildTree(root *cobra.Command) *node {
	var walk func(c *cobra.Command, path []string) *node
	walk = func(c *cobra.Command, path []string) *node {
		n := &node{cmd: c, path: path}
		subs := append([]*cobra.Command(nil), c.Commands()...)
		sort.SliceStable(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
		for _, s := range subs {
			if !visible(s, c == root) {
				continue
			}
			n.children = append(n.children, walk(s, append(append([]string(nil), path...), s.Name())))
		}
		return n
	}
	return walk(root, nil)
}

// leaves lists every runnable node below n (and n itself when runnable and
// not the root), in menu order.
func (n *node) leaves() []*node {
	var out []*node
	var walk func(x *node)
	walk = func(x *node) {
		if len(x.path) > 0 && x.runnable() {
			out = append(out, x)
		}
		for _, c := range x.children {
			walk(c)
		}
	}
	walk(n)
	return out
}

// Paths returns the path of every command the menu offers for root, as
// space-joined names ("wallet send"). It is what the reachability check
// compares with the command tree itself (concern U1).
func Paths(root *cobra.Command) []string {
	var out []string
	for _, l := range buildTree(root).leaves() {
		out = append(out, l.pathString())
	}
	return out
}

// find returns the node at path.
func (n *node) find(path []string) *node {
	cur := n
	for _, p := range path {
		var next *node
		for _, c := range cur.children {
			if c.name() == p {
				next = c
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}
