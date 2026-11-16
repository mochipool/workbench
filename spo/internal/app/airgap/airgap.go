// Package airgap holds the use cases of the air-gap carry bag, the online
// and the offline half of upstream's 01_workOffline: writing the snapshot
// (`new`, `add`), showing the bundle (`info`), carrying files (`attach`,
// `extract`), clearing parts of it, and submitting the queued transactions
// (`execute`). Each is a use case over narrow ports; the bundle itself is the
// pure aggregate in domain/transfer, read and written by an adapter
// (ADR 0005: the Go bundle will later travel in an authenticated envelope;
// the upstream JSON format is still read and written for compatibility, and
// an import never writes outside its own directory).
//
// Where upstream ends with exit 0 after a failed query, a declined prompt or
// a failed read-back, a use case here returns an error (hazard H3).
package airgap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals shared by the use cases.
var (
	// ErrNoChain: the action needs a chain reader and the composition has
	// none, which is how offline mode shows here (SPO-01workOffline-PRE-001).
	ErrNoChain = errors.New("this action needs access to the chain: use the online or the light mode, not the offline mode")
	// ErrNotSynced: the provider has not caught up (SPO-01workOffline-PRE-002).
	ErrNotSynced = errors.New("the node or the provider is not synced with the chain")
	// ErrNoEra: the era of the chain is not known. Upstream stores the
	// literal "auto" or "null" and fails later (SPO-Ptransfer-OUT-003); the
	// port refuses.
	ErrNoEra = errors.New("the era of the chain is not known")
	// ErrMisconfigured: the composition is wrong (a programming error).
	ErrMisconfigured = errors.New("the use case is not wired correctly")
)

// ApprovalPolicy says how the confirmation before a submit is obtained.
// Skipping it is explicit and recorded in the result; it is never the
// default. Upstream never skips it: ENV_SKIP_PROMPT has no effect on
// `execute` (SPO-Ptransfer-PR-001, SPO-01workOffline-PR-001), so a skipped
// confirmation here is a decision of the composition, audited by the result.
type ApprovalPolicy int

const (
	// ApprovalAsk asks the confirmer; the default answer is No. It is the
	// zero value.
	ApprovalAsk ApprovalPolicy = iota
	// ApprovalSkip proceeds without asking.
	ApprovalSkip
)

// Versions are the tool versions written to general.onlineCLI and
// general.onlineNODE (SPO-01workOffline-OUT-005). Node is `light` in the
// light mode.
type Versions struct {
	CLI  string
	Node string
}

// Dates are `date -R`.
func rfc5322(t time.Time) string { return t.Format(time.RFC1123Z) }

func now(c ports.Clock) string {
	if c == nil {
		return rfc5322(time.Now())
	}
	return rfc5322(c.Now())
}

func checkSync(ctx context.Context, s ports.SyncChecker) error {
	if s == nil {
		return nil
	}
	ok, err := s.Synced(ctx)
	if err != nil {
		return fmt.Errorf("the sync state from %s: %w", s.Source(), err)
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotSynced, s.Source())
	}
	return nil
}
