package parity

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// noopSingle accepts a single-source read without recording it: these tests
// compare bytes with an oracle and have no audit log.
var noopSingle ports.SingleSourceHook = func(context.Context, string, string) error { return nil }
