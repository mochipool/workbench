package wallet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// HandleResolver resolves an ADA Handle to the payment address that holds it,
// verified against the chain (satisfied by handles.Resolver). A use case with no
// resolver keeps refusing handle destinations with ErrAdaHandleUnsupported.
type HandleResolver interface {
	Resolve(ctx context.Context, text string) (handles.Resolved, error)
}

// ErrHandleUnverified: the resolver answered an address without saying what it
// was verified against. A wrong destination is harmful (ADR 0006), so an
// unverified answer is refused, not shown.
var ErrHandleUnverified = errors.New("the ADA Handle resolution was not verified against the chain; refusing it")

// HandleDestination is how an operator sees a resolved destination: the handle
// as typed and the address it resolved to, both, so the money's destination is
// never only a name the operator cannot check (ADR 0006).
type HandleDestination struct {
	Handle     string // lower-cased, with the leading `$`
	Address    chain.Address
	Kind       handles.Kind
	VerifiedBy string // "holder utxo" or "inline datum"
}

// resolveHandle resolves the pending handle of a destination. The directory and
// the chain must agree (the resolver's verification); an ambiguous or
// unverifiable answer is an error the caller returns as it is.
//
// spec: SPO-01sendLovelaces-IF-007, SPO-Caddr-IF-001, SPO-Caddr-IF-002, SPO-Caddr-INV-006, SPO-Caddr-SEC-001
func resolveHandle(ctx context.Context, hr HandleResolver, d resolved) (resolved, error) {
	if d.pendingHandle == "" {
		return d, nil
	}
	if hr == nil {
		return resolved{}, fmt.Errorf("%w: %s", ErrAdaHandleUnsupported, d.pendingHandle)
	}
	h := strings.ToLower(d.pendingHandle)
	res, err := hr.Resolve(ctx, h)
	if err != nil {
		return resolved{}, fmt.Errorf("the ADA Handle %s: %w", h, err)
	}
	if res.Address == "" || res.VerifiedBy == "" {
		return resolved{}, fmt.Errorf("%w: %s", ErrHandleUnverified, h)
	}
	return resolved{name: h, addr: res.Address,
		handle: &HandleDestination{Handle: h, Address: res.Address, Kind: res.Kind, VerifiedBy: res.VerifiedBy}}, nil
}
