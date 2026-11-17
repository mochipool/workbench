package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// SingleSourceOperation is the audit operation of a read that rested on one
// chain source because the operator gave --single-source (ADR 0006).
const SingleSourceOperation = "single-source-read"

// singleSourceHook is the ports.SingleSourceHook of a command: the use case
// calls it at the point where it accepts one chain source, before anything is
// signed, submitted, queued or written, and it appends the record ADR 0006
// promises: the command, what was read, the one provider it rested on, and that
// --single-source was given. One record is written per accepted read (a command
// that reads twice, as stake deregister does for the certificate and for the
// transaction, writes two). A run that had two agreeing sources, or that was
// refused, writes nothing. The record goes to the workspace's audit log (the
// sealed store's MAC-chained log). When it cannot be written the hook fails and the
// use case stops with nothing done: an acknowledgement that cannot be recorded
// is not accepted.
func (a *app) singleSourceHook(s *session, command string) ports.SingleSourceHook {
	return func(ctx context.Context, read, source string) error {
		return a.auditSingleSource(ctx, s, command, read, source)
	}
}

func (a *app) auditSingleSource(ctx context.Context, s *session, command, read, source string) error {
	if a.d.WorkspaceAuditor == nil {
		// Only a test harness has no recorder; cmd/spo's TestProductionDepsRecordSingleSource
		// pins that the real wiring has one. Say so rather than skip silently.
		fmt.Fprintln(a.d.Err, "note: this build has no audit log; the single-source acknowledgement was not recorded")
		return nil
	}
	err := a.d.WorkspaceAuditor(a.workspace, s.Store, "").Record(ctx, ports.AuditEvent{
		Operation: SingleSourceOperation, Command: command, Read: read, Source: source,
		SingleSource: true, Acknowledged: true,
	})
	if err != nil {
		return fmt.Errorf("the single-source acknowledgement for %s could not be recorded: %w", command, err)
	}
	return nil
}

// printSingleSourceWarning is the line every command that accepted a single
// source prints in its summary.
func printSingleSourceWarning(w io.Writer, read, source string) {
	fmt.Fprintf(w, "WARNING: %s rests on ONE source (%s), accepted with --single-source and recorded in the audit log.\n",
		read, textsafe.Text(source))
}
