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
	"os"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
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
	_, perr := prog.Run()
	if err := m.endSession(); err != nil {
		return err
	}
	if perr != nil && !errors.Is(perr, tea.ErrProgramKilled) && !errors.Is(perr, context.Canceled) {
		return perr
	}
	return nil
}

// endSession runs when the program has ended (its update no longer runs): the
// host takes no more jobs, and a relay session still running (the program was
// killed, or a second quit did not wait) is ended and waited for within the
// bound. It returns ErrSessionStuck when the session did not end cleanly
// (SPO-Xmailbox-OUT-118).
//
// It says on Notice what it waits for. A session already stuck past the bound
// in the UI is not waited for a second time: only a session that had not
// reached its bound is waited for, for what is left of it.
func (m *model) endSession() error {
	close(m.hostClosed)
	s := &m.sess
	if s.phase == sessNone {
		return m.exitErr
	}
	note := m.opts.Notice
	if note == nil {
		note = os.Stderr
	}
	if s.done == nil {
		fmt.Fprintln(note, "spo: "+ErrSessionStuck.Error())
		return ErrSessionStuck
	}
	s.cancel()
	wait := m.logoutBound()
	switch {
	case s.phase == sessStuck:
		wait = 0 // the bound passed already, or the close failed
	case s.phase == sessLoggingOut:
		wait = max(wait-m.now().Sub(s.logoutAt), 0)
	}
	select {
	case <-s.done:
	default:
		if wait == 0 {
			fmt.Fprintln(note, "spo: "+ErrSessionStuck.Error())
			return ErrSessionStuck
		}
		fmt.Fprintf(note, "spo: waiting up to %v for the relay session to log out of the relays…\n", wait.Round(time.Second))
		select {
		case <-s.done:
		case <-time.After(wait):
			fmt.Fprintln(note, "spo: "+ErrSessionStuck.Error())
			return ErrSessionStuck
		}
	}
	// the update no longer runs, so the last phase is read from the host's
	// cell: a clean close is reported before the command returns
	if p, _ := s.reported.Load().(relayloop.Phase); (p != "" && p != relayloop.PhaseLoggedOut) || s.permanent {
		fmt.Fprintln(note, "spo: "+ErrSessionStuck.Error())
		return ErrSessionStuck
	}
	return m.exitErr
}
