// Package tui is the terminal UI: a second driver of the same command tree
// the CLI builds (ADR 0009). It generates menus and forms from the tree,
// runs a command's own RunE in-process, and implements the terminal and
// output the command talks to. It has no behaviour of its own: a command
// that exists in the tree appears here, and every refusal, confirmation and
// audit record is the command's.
package tui

import (
	"context"
	"errors"
	"fmt"

	tea "charm.land/bubbletea/v2"
)

// ErrNoFactory is returned when Run has no way to build the command tree.
var ErrNoFactory = errors.New("tui: no command tree factory")

// Run shows the TUI until the operator quits. It uses the alternate screen,
// enables neither mouse reporting nor a debug log, and restores the terminal
// on every way out, a panic included (bubbletea recovers, restores, and
// re-raises as an error); everything secret the model holds is wiped.
func Run(ctx context.Context, o Options) (err error) {
	if o.Factory == nil {
		return ErrNoFactory
	}
	var prog *tea.Program
	send := func(msg tea.Msg) {
		if prog != nil {
			prog.Send(msg)
		}
	}
	m, err := newModel(o, send)
	if err != nil {
		return err
	}
	defer m.Wipe()
	opts := []tea.ProgramOption{tea.WithContext(ctx)}
	if o.Input != nil {
		opts = append(opts, tea.WithInput(o.Input))
	}
	if o.Output != nil {
		opts = append(opts, tea.WithOutput(o.Output))
	}
	prog = tea.NewProgram(m, opts...)
	defer func() {
		if p := recover(); p != nil {
			prog.Kill()
			m.Wipe()
			err = fmt.Errorf("tui: %v", p)
		}
	}()
	if _, err := prog.Run(); err != nil && !errors.Is(err, tea.ErrProgramKilled) && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
