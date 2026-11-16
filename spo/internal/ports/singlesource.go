package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// SingleSourceHook is called by a use case at the point where it accepts one
// chain source for a read of the "harmful if false" class (ADR 0006), because
// the operator acknowledged that. It is called once per accepted read, before
// anything is signed, submitted, queued or written; an error from it aborts the
// use case with nothing done. The command layer passes the function that
// appends the audit record, so the record exists before the effect it permits.
// The arguments are what was read (a short phrase) and the provider the read
// rests on.
type SingleSourceHook func(ctx context.Context, read, source string) error

// ErrNoSingleSourceHook: a use case was told to accept a single source but was
// given no way to record it. The use case refuses instead of going on without
// the record.
var ErrNoSingleSourceHook = errors.New("a single source was acknowledged but this use case has no audit hook to record it: refused (misconfigured)")

// Accept calls the hook for a read that rests on source. A nil hook refuses.
func (h SingleSourceHook) Accept(ctx context.Context, read string, source chain.Source) error {
	if h == nil {
		return ErrNoSingleSourceHook
	}
	return h(ctx, read, string(source))
}
