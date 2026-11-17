package toolchain

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// stderrRunner answers a probe as fido2-token -V does: on stderr, nothing on stdout.
type stderrRunner struct {
	out   string
	calls int
}

func (f *stderrRunner) Run(_ context.Context, c execx.Cmd) (execx.Result, error) {
	f.calls++
	return execx.Result{Stderr: []byte(f.out)}, nil
}

// `fido2-token -V` prints the libfido2 version alone; the release set pins it.
// spec: SPO-Xunlock-IF-003
func TestFIDO2TokenVersionIsPinned(t *testing.T) {
	tok := exe(t, "fido2-token")
	for _, c := range []struct {
		name, pin, out string
		want           error
	}{
		{"pinned and equal", "1.17.0", "1.17.0\n", nil},
		{"differs from the pin", "1.16.0", "1.17.0\n", ErrVersion},
		{"prints nothing", "1.17.0", "", ErrVersion},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &stderrRunner{out: c.out}
			tc := New(Manifest{Release: "test", Tools: map[ports.ToolName]Entry{ports.FIDO2Token: {Path: tok, Version: c.pin}}}, f)
			got, err := tc.Tool(context.Background(), ports.FIDO2Token)
			if !errors.Is(err, c.want) || (c.want == nil && got.Version != c.pin) {
				t.Fatalf("%q, %v", got.Version, err)
			}
			if f.calls != 1 {
				t.Fatalf("the probe ran %d times", f.calls)
			}
		})
	}
}
