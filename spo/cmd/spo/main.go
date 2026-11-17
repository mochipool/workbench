// Command spo is the composition root: it wires adapters to use cases and
// does nothing else.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// minLockedBuffers is the least number of page-sized secret buffers the
// locked-memory budget must allow.
const minLockedBuffers = 64

// version is set at build time with -ldflags.
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	// Before anything can hold a key: no core dumps, not ptrace-able (E4).
	if err := secret.HardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "spo: cannot harden the process:", err)
		return 1
	}
	// Locked memory: every secret lives in locked pages, so the limit is
	// read once, up front, and a budget too small to work with is refused
	// with the remedy instead of failing in the middle of a command.
	if err := secret.Init(); err != nil {
		fmt.Fprintln(os.Stderr, "spo:", cli.MemlockAdvice+": "+err.Error())
		return 1
	}
	if b := secret.Budget(); !b.Unlimited && b.Limit < minLockedBuffers*uint64(os.Getpagesize()) {
		fmt.Fprintf(os.Stderr, "spo: the locked-memory limit (RLIMIT_MEMLOCK) leaves %d bytes for secrets, fewer than the %d buffers spo needs. %s\n",
			b.Limit, minLockedBuffers, cli.MemlockAdvice)
		return 1
	}
	defer secret.Purge()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	deps, err := buildDeps(os.Stdout, os.Stderr, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spo:", err)
		return 1
	}

	root := cli.NewRoot(deps)
	cli.MarkForUI(root)
	cli.AttachCompletion(root, deps)
	root.AddCommand(tuiCommand(buildDeps))
	if err := root.ExecuteContext(ctx); err != nil {
		if errors.Is(err, secret.ErrMemoryLimit) {
			err = errors.New(cli.MemlockAdvice)
		}
		fmt.Fprintln(os.Stderr, "spo:", cli.SafeMessage(err))
		return cli.ExitCode(err)
	}
	return 0
}

// buildDeps wires the adapters to the command tree and loads the toolchain.
// The TUI calls it for every command it runs, with its own terminal and
// output, so a command's output and progress lines reach the TUI and never
// the real terminal.
func buildDeps(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) {
	deps := newDeps(out, errw, term)
	manifest, err := toolchain.Load(os.Getenv(toolchain.EnvVar))
	switch {
	case err == nil:
		tc := toolchain.New(manifest, execx.OS{})
		deps.Toolchain, deps.Tools, deps.Release = tc, tc.Names(), tc.Release()
		deps.Genesis = func(network string) (string, string, bool) {
			n, ok := tc.Genesis(network)
			return n.ShelleyGenesis, n.ByronGenesis, ok
		}
	case errors.Is(err, toolchain.ErrNoManifest):
		deps.Toolchain = noToolchain{err: err}
	default:
		return deps, err
	}
	return deps, nil
}

// noToolchain refuses every tool when the binary runs without a manifest.
type noToolchain struct{ err error }

func (n noToolchain) Tool(context.Context, ports.ToolName) (ports.Tool, error) {
	if n.err != nil {
		return ports.Tool{}, n.err
	}
	return ports.Tool{}, toolchain.ErrNoManifest
}
