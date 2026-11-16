package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/tui"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// depsBuilder makes the dependencies of one command tree with the given
// output and terminal.
type depsBuilder func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error)

// tuiFactory is what the TUI is given to build the command tree: the same
// cli.NewRoot the binary runs, over dependencies whose terminal and output
// are the TUI's (ADR 0009). It builds nothing else, so a command added to
// the CLI is in the TUI.
func tuiFactory(build depsBuilder) tui.Factory {
	return func(t tui.Terminal, out, errw io.Writer) (*cobra.Command, error) {
		deps, err := build(out, errw, t)
		if err != nil {
			return nil, err
		}
		root := cli.NewRoot(deps)
		cli.MarkForUI(root)
		return root, nil
	}
}

// tuiCommand is `spo tui`.
func tuiCommand(build depsBuilder) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the terminal UI: the same commands as menus and forms",
		Long: `Open a full-screen terminal UI over the command tree. Every command is a menu
entry; a form is generated from its usage line and flags; running it asks its
questions (passphrase, confirmations) in a modal, exactly as the command
phrases them. The TUI has no behaviour of its own: whatever a command refuses,
confirms or records is what you get on the command line.

The global flags (-C DIR, --upstream-layout, --accept-rollback) apply to the
whole session. The workspace is not opened until a command needs it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isTerminal(int(os.Stdin.Fd())) || !isTerminal(int(os.Stdout.Fd())) {
				return errors.New("spo tui needs a terminal on standard input and output; use the commands directly in scripts")
			}
			globals, dir, err := sessionFlags(cmd)
			if err != nil {
				return err
			}
			return tui.Run(cmd.Context(), tui.Options{
				Factory:  tuiFactory(build),
				Globals:  globals,
				Status:   func() tui.Status { return workspaceStatus(dir, globals) },
				StartDir: dir,
				Names:    tuiNames(build, dir, globals),
			})
		},
	}
}

// tuiNames is how the TUI learns the names the workspace holds, for
// completion: the CLI's own listing (names only), over the session's global
// flags. It gets a passphrase only when the operator asks the TUI to unlock
// the names; without one a sealed workspace is not opened.
func tuiNames(build depsBuilder, dir string, globals []string) tui.NameLister {
	has := func(flag string) bool {
		for _, g := range globals {
			if g == flag+"=true" {
				return true
			}
		}
		return false
	}
	upstream, rollback := has("--upstream-layout"), has("--accept-rollback")
	return func(ctx context.Context, pass *secret.Buffer) (map[string][]string, error) {
		deps, err := build(io.Discard, io.Discard, nil)
		if err != nil {
			return nil, err
		}
		names, err := cli.WorkspaceNames(ctx, deps, dir, upstream, rollback, pass)
		if errors.Is(err, cli.ErrSealed) {
			return nil, tui.ErrLocked
		}
		return names, err
	}
}

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// sessionFlags turns the global flags given on the command line into the
// arguments every command of the session starts with, and returns the
// workspace directory.
func sessionFlags(cmd *cobra.Command) (args []string, dir string, err error) {
	dir = "."
	cmd.Flags().Visit(func(f *pflag.Flag) {
		if f.Name == "help" {
			return
		}
		if f.Name == "passphrase-fd" {
			err = errors.New("--passphrase-fd does not apply to the TUI: it asks for the passphrase when a command needs it")
			return
		}
		args = append(args, "--"+f.Name+"="+f.Value.String())
		if f.Name == "workspace" {
			dir = f.Value.String()
		}
	})
	return args, dir, err
}

// workspaceStatus reads the header without opening the workspace: spo.toml is
// public, and whether the sealed file exists is a stat.
func workspaceStatus(dir string, globals []string) tui.Status {
	s := tui.Status{Workspace: dir}
	for _, g := range globals {
		if g == "--upstream-layout=true" {
			s.State = "upstream layout (keys unsealed)"
		}
	}
	cfg, err := loadConfig(dir)
	switch {
	case err == nil:
		s.Network, s.Mode = cfg.Network, cfg.Mode
	case errors.Is(err, os.ErrNotExist):
		s.State = "no workspace here: run init"
	default:
		s.State = "spo.toml: " + err.Error()
	}
	if s.State == "" || s.State == "no workspace here: run init" {
		if _, err := os.Lstat(filepath.Join(dir, cli.WorkspaceFile)); err == nil {
			s.State = "sealed: opened only while a command runs"
		}
	}
	return s
}
