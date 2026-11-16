// Package handles resolves an ADA Handle to the payment address that holds
// it (spec/upstream/common/Caddr.md, resolveAdahandle). The Handle API is a
// third party; its answer is a claim that this use case verifies against the
// chain before it is returned, because a wrong destination is harmful
// (ADR 0006).
package handles

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/handle"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals. Every one is an error value; the caller decides what it means.
var (
	// ErrOffline: handles resolve online and in light mode only (SPO-Caddr-PRE-002).
	ErrOffline = errors.New("ADA Handles can only be resolved with a chain provider, not offline")
	// ErrNoChainProvider: no asset-holder reader was composed (SPO-Caddr-PRE-003).
	ErrNoChainProvider = errors.New("this network has no chain provider to look a handle up with")
	// ErrNoDirectory: no Handle API for the network, which sub-handles need
	// (SPO-Caddr-PRE-007).
	ErrNoDirectory = errors.New("this network has no Handle API; sub-handles cannot be resolved")
	// ErrNotFound: neither the classic nor the CIP-68 lookup of a root handle
	// found exactly one holder (SPO-Caddr-PRE-006).
	ErrNotFound = errors.New("the handle could not be resolved: no holder found")
	// ErrAmbiguous: the lookups answered several holders. Reported apart from
	// not found (the Caddr port note).
	ErrAmbiguous = errors.New("the handle could not be resolved: several addresses hold it")
	// ErrNotPayment: the resolved address cannot receive a payment (SPO-Caddr-PRE-009).
	ErrNotPayment = errors.New("the handle resolved to an address that is not a payment address")
	// ErrNotSynced: the chain provider is behind (SPO-Caddr-PRE-010).
	ErrNotSynced = errors.New("the chain provider is not synced; the holder of the handle cannot be verified")
	// ErrNotHeld: the resolved address does not hold the handle's asset, or
	// holds it in several outputs (SPO-Caddr-INV-006).
	ErrNotHeld = errors.New("the resolved address does not hold the handle exactly once")
	// ErrDatumMismatch: the address in the datum differs from the directory's
	// (SPO-Caddr-PRE-012).
	ErrDatumMismatch = errors.New("the directory and the chain datum disagree on the address of the handle")
	// ErrUnverifiable: a sub-handle of a kind that cannot be verified, or
	// whose asset name is not the handle's. Upstream trusts such an answer
	// (SPO-Caddr-SEC-001); the port refuses it.
	ErrUnverifiable = errors.New("the handle is of a kind that cannot be verified; refusing the directory's word alone")
)

// Kind says how a handle was resolved and verified.
type Kind string

// Kinds (the table of Caddr).
const (
	RootClassic Kind = "root"        // CIP-25: asset name is the name's bytes
	RootCIP68   Kind = "root-cip68"  // asset name 000de140 + the name's bytes
	SubCIP68    Kind = "sub-cip68"   // on-chain sub-handle, via the Handle API
	SubVirtual  Kind = "sub-virtual" // virtual sub-handle, verified by its datum
)

// Resolved is a verified resolution.
type Resolved struct {
	Address      chain.Address
	Kind         Kind
	AssetNameHex string
	// VerifiedBy says what the answer was checked against: "holder utxo" or
	// "inline datum".
	VerifiedBy string
	// Utxos are the UTxOs of the address as read for the holder check, so a
	// caller can skip its own query (SPO-Caddr-OUT-007). Nil for a virtual
	// sub-handle (upstream does not set them either).
	Utxos []chain.Utxo
}

// Resolver resolves handles. Policy is the network profile's handle policy
// id: the only one trusted, in every query and in the holder check
// (SPO-Caddr-INV-009).
type Resolver struct {
	Policy  [28]byte
	Mainnet bool
	// Offline refuses everything (SPO-Caddr-PRE-002): the composition sets it
	// in offline mode, where no provider is composed at all.
	Offline bool

	Holders   ports.AssetHolderReader // nil: ErrNoChainProvider
	Directory ports.HandleDirectory   // nil: ErrNoDirectory for sub-handles
	Datums    ports.AssetDatumReader  // needed for virtual sub-handles
	Utxos     ports.UtxoReader
	Addresses ports.AddressInspector
	// Sync is the provider's sync gate, composed in online mode and left nil
	// in light mode (SPO-Caddr-PRE-010, SPO-Caddr-MODE-001).
	Sync ports.SyncChecker
}

// Resolve resolves `$name` or `$sub@name` (any letter case).
func (r Resolver) Resolve(ctx context.Context, text string) (Resolved, error) {
	if r.Offline {
		return Resolved{}, ErrOffline
	}
	if r.Holders == nil {
		return Resolved{}, ErrNoChainProvider
	}
	h, err := handle.Parse(text)
	if err != nil {
		return Resolved{}, err
	}
	if h.Sub {
		return r.resolveSub(ctx, h)
	}
	return r.resolveRoot(ctx, h)
}

func (r Resolver) resolveRoot(ctx context.Context, h handle.Handle) (Resolved, error) {
	classic := h.NameHex()
	cip68 := handle.LabelCIP68 + classic
	kind, nameHex := RootClassic, classic
	addrs, err := r.Holders.AssetHolders(ctx, r.Policy, classic)
	if err != nil {
		return Resolved{}, fmt.Errorf("looking up %s: %w", h.Name, err) // no fallback (SPO-Caddr-PRE-005)
	}
	if len(addrs) != 1 {
		first := len(addrs)
		kind, nameHex = RootCIP68, cip68
		if addrs, err = r.Holders.AssetHolders(ctx, r.Policy, cip68); err != nil {
			return Resolved{}, fmt.Errorf("looking up %s: %w", h.Name, err)
		}
		if len(addrs) == 0 && first == 0 {
			return Resolved{}, ErrNotFound
		}
		if len(addrs) != 1 {
			if len(addrs) > 1 || first > 1 {
				return Resolved{}, ErrAmbiguous
			}
			return Resolved{}, ErrNotFound
		}
	}
	addr := addrs[0] // the first holder (SPO-Caddr-INV-004); the asset quantity is not inspected here
	return r.verifiedByHolder(ctx, addr, kind, nameHex)
}

func (r Resolver) resolveSub(ctx context.Context, h handle.Handle) (Resolved, error) {
	if r.Directory == nil {
		return Resolved{}, ErrNoDirectory
	}
	rec, err := r.Directory.ResolveHandle(ctx, h.Name)
	if err != nil {
		return Resolved{}, fmt.Errorf("handle directory: %w", err)
	}
	addr := chain.Address(rec.Address)
	if err := r.requirePayment(addr); err != nil {
		return Resolved{}, err
	}
	name := strings.ToLower(rec.AssetNameHex)
	switch {
	case strings.HasPrefix(name, handle.LabelCIP68) && name[len(handle.LabelCIP68):] == h.NameHex():
		return r.verifiedByHolder(ctx, addr, SubCIP68, name)
	case strings.HasPrefix(name, handle.LabelVirtual) && name[len(handle.LabelVirtual):] == h.NameHex():
		return r.verifiedByDatum(ctx, addr, name)
	}
	return Resolved{}, fmt.Errorf("%w: asset name %q for %s", ErrUnverifiable, rec.AssetNameHex, h.Name)
}

func (r Resolver) requirePayment(a chain.Address) error {
	info, err := r.Addresses.InspectAddress(a)
	if err != nil || !info.Kind.IsPayment() {
		return fmt.Errorf("%w: %q", ErrNotPayment, a)
	}
	return nil
}

// verifiedByHolder checks that the address is a payment address and that
// exactly one of its outputs holds the asset (SPO-Caddr-PRE-009,
// SPO-Caddr-PRE-010, SPO-Caddr-EXT-005, SPO-Caddr-INV-006).
func (r Resolver) verifiedByHolder(ctx context.Context, addr chain.Address, kind Kind, nameHex string) (Resolved, error) {
	if err := r.requirePayment(addr); err != nil {
		return Resolved{}, err
	}
	if r.Sync != nil {
		ok, err := r.Sync.Synced(ctx)
		if err != nil {
			return Resolved{}, fmt.Errorf("%w: %v", ErrNotSynced, err)
		}
		if !ok {
			return Resolved{}, ErrNotSynced
		}
	}
	name, err := hex.DecodeString(nameHex)
	if err != nil {
		return Resolved{}, fmt.Errorf("asset name %q: %w", nameHex, err)
	}
	utxos, err := r.Utxos.Utxos(ctx, addr)
	if err != nil {
		return Resolved{}, fmt.Errorf("reading the outputs of %s: %w", addr, err)
	}
	held := 0
	for _, u := range utxos {
		for _, a := range u.Assets {
			if a.Asset.Policy == r.Policy && string(a.Asset.Name) == string(name) && a.Quantity > 0 {
				held++
				break
			}
		}
	}
	if held != 1 {
		return Resolved{}, fmt.Errorf("%w: %d outputs of %s hold it", ErrNotHeld, held, addr)
	}
	return Resolved{Address: addr, Kind: kind, AssetNameHex: nameHex, VerifiedBy: "holder utxo", Utxos: utxos}, nil
}

// verifiedByDatum checks a virtual sub-handle's address against the inline
// datum of the asset's output (SPO-Caddr-EXT-006, PRE-011, INV-007, PRE-012).
// There is no sync gate for it, as upstream has none.
func (r Resolver) verifiedByDatum(ctx context.Context, addr chain.Address, nameHex string) (Resolved, error) {
	if r.Datums == nil {
		return Resolved{}, fmt.Errorf("%w: no reader of asset datums", ErrNoChainProvider)
	}
	ds, err := r.Datums.AssetInlineDatums(ctx, r.Policy, nameHex)
	if err != nil {
		return Resolved{}, fmt.Errorf("reading the datum of the handle: %w", err)
	}
	if len(ds) != 1 {
		return Resolved{}, fmt.Errorf("%w: %d outputs hold the asset", ErrNotHeld, len(ds))
	}
	got, err := handle.DatumAddress(ds[0].CBORHex, r.Mainnet)
	if err != nil || !strings.EqualFold(got, string(addr)) {
		return Resolved{}, fmt.Errorf("%w: directory %s, datum %q", ErrDatumMismatch, addr, got)
	}
	return Resolved{Address: addr, Kind: SubVirtual, AssetNameHex: nameHex, VerifiedBy: "inline datum"}, nil
}
