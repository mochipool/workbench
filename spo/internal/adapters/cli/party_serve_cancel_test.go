package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// cancelOnWrite cancels the command's context in the same call that writes
// the line it waits for, so the cancel arrives exactly at the next step of the
// command: a deterministic stand-in for Ctrl-C at that moment.
type cancelOnWrite struct {
	w      io.Writer
	text   string
	cancel context.CancelFunc
}

func (c cancelOnWrite) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if strings.Contains(string(p), c.text) {
		c.cancel()
	}
	return n, err
}

// A serve stopped right after it wrote the last invitation (the listener is
// up) stops cleanly: the step after the invitations must not turn the cancel
// into an error.
//
// spec: SPO-Xparty-IF-005
func TestServeStopsCleanlyWhenCancelledRightAfterTheInvitations(t *testing.T) {
	n := newNetScene(t, ModeLight)
	outbox := filepath.Join(t.TempDir(), "invites")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := n.coord.deps(n.coord.term())
	d.Out = cancelOnWrite{w: d.Out, text: "invitation for bob written", cancel: cancel}
	root := NewRoot(d)
	root.SetArgs([]string{"-C", n.coord.dir, "party", "serve", "--invite", "bob", "--outbox", outbox})
	if err := root.ExecuteContext(ctx); err != nil {
		t.Fatalf("a serve stopped after start-up returned %v; out:\n%s", err, n.coord.out.String())
	}
	if !strings.Contains(n.coord.out.String(), "Stopped serving.") {
		t.Errorf("no clean stop; out:\n%s", n.coord.out.String())
	}
}
