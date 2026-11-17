package native

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Signers is the SignerDirectory of this client (ADR 0010 decision 3): it maps
// a key identity to the signers connected now that report holding the key.
//
//   - The local vault answers for the keys it holds, found by identity.
//     With both a signing key and a hardware file the hardware wins, except
//     for an operational certificate (SPO-Pfiles-INV-002, SPO-04d-INV-004).
//   - Each attached hardware device answers for the keys it has exported a
//     verification key for (the stored hardware signing files). The device
//     Profile is the signer's own, so the plan-time capability check of ADR
//     0008 runs on the signer connected now: a device that is unplugged offers
//     an empty profile and a demand for its keys fails in the plan.
//   - Each remote co-signer party answers for the keys ADR 0005's slot
//     assignment gives it, routed by its fingerprint.
//
// Neither the holder nor the owner's name is part of a key reference. Own-client
// remotes, announcements, proofs of possession and blinded handles are not
// here: they come with the server stage (ADR 0010 decision 6) and fit as one
// more kind of Remote.
type Signers struct {
	// Vault is the local vault. A nil vault holds nothing.
	Vault ports.Vault
	// Keys finds the stored records of an identity. When nil, the vault is used
	// as the index when it is a store that can list its artefacts.
	Keys ports.KeyIndex
	// Hardware is the signer of the attached device (hwcli.Lazy), or nil.
	Hardware ports.Signer
	// Remotes are the co-signer parties reachable through the envelope.
	Remotes []Remote
	// Prefer is the single hook for an operator preference among several
	// connected signers of one key. There is no label attribute `prefer` yet
	// (ADR 0010 decision 3, open question); until there is, it stays nil and the
	// default order holds: hardware, then vault, then remote (the vault first for an operational certificate).
	Prefer func(key custody.KeyRef, candidates []ports.ConnectedSigner) []ports.ConnectedSigner
}

// Remote is a co-signer party the directory routes a demand to.
type Remote struct {
	// Party is the ADR 0005 fingerprint the demand is routed by.
	Party []byte
	// Holds reports whether the slot assignment gives the party the key.
	Holds func(identity.Ref) bool
	// Signer is the party's signer: its answers come back through the envelope
	// and are verified by the custody verifiers like any other.
	Signer ports.Signer
	// Network is true when the demand travels over a network transport; a
	// carried file is not one.
	Network bool
}

func (s Signers) index() ports.KeyIndex {
	if s.Keys != nil {
		return s.Keys
	}
	if st, ok := s.Vault.(ports.Store); ok {
		if idx, err := ports.NewStoreKeyIndex(st); err == nil {
			return idx
		}
	}
	return nil
}

func (s Signers) vaultSigner() ports.Signer {
	return VaultRegistry{VaultSignatures: VaultSignatures{VaultSigner: VaultSigner{Vault: s.Vault, Keys: s.Keys}}}
}

// ForPlan implements ports.PlanScoped: the directory answers one plan from
// remembered index lookups, so each verification key is read once per identity.
func (s Signers) ForPlan() ports.SignerDirectory {
	if idx := s.index(); idx != nil {
		s.Keys = ports.MemoIndex(idx)
	}
	return s
}

// Connected implements ports.SignerDirectory, in the default order for a
// signature: hardware, vault, remote (SPO-Pfiles-INV-002: with both a signing
// key and a hardware file, the hardware file wins).
func (s Signers) Connected(key custody.KeyRef) ([]ports.ConnectedSigner, error) {
	return s.connected(key, "")
}

func (s Signers) connected(key custody.KeyRef, op custody.Operation) ([]ports.ConnectedSigner, error) {
	ctx := context.Background()
	var homes []ports.KeyHome
	idx := s.index()
	if idx != nil && !key.Identity.IsZero() {
		var err error
		if homes, err = idx.Homes(ctx, key.Identity); err != nil {
			return nil, err
		}
	}
	var vault, device []ports.ConnectedSigner
	if _, ok := ports.SecretHome(homes, key.Role); ok && s.Vault != nil {
		vault = []ports.ConnectedSigner{{Kind: ports.SignerLocal, Signer: s.vaultSigner()}}
	}
	for _, h := range homes {
		if h.Role == key.Role && h.WrongHardwareFile {
			return nil, fmt.Errorf("%w: %s", ports.ErrWrongHardwareFile, key)
		}
	}
	if _, ok := ports.HardwareHome(homes, key.Role); ok {
		if s.Hardware != nil {
			device = []ports.ConnectedSigner{{Kind: ports.SignerDevice, Signer: s.Hardware}}
		} else if op != custody.OpIssueOpCert {
			// the hardware file wins and no device is connected: the plan refuses,
			// it does not fall back to a signing key stored beside the file
			vault = nil
		}
	}
	var out []ports.ConnectedSigner
	if op == custody.OpIssueOpCert { // SPO-04d-INV-004: the software key wins
		out = append(append(out, vault...), device...)
	} else {
		out = append(append(out, device...), vault...)
	}
	// The cold-key rule fails closed: a cold role in the history, or a history
	// that cannot be read for certain, withholds every network remote.
	cold := key.Role.IsCold()
	for _, h := range homes {
		cold = cold || h.Role.IsCold()
	}
	if !cold && idx != nil && len(s.Remotes) > 0 {
		if ci, ok := idx.(interface {
			Unreadable(context.Context) (int, error)
		}); ok {
			if n, err := ci.Unreadable(ctx); err != nil || n > 0 {
				cold = true
			}
		}
	}
	refused := false
	for _, r := range s.Remotes {
		if r.Holds == nil || !r.Holds(key.Identity) {
			continue
		}
		if cold && r.Network {
			refused = true // never sent over a network, whatever role the demand names
			continue
		}
		out = append(out, ports.ConnectedSigner{Kind: ports.SignerCoSigner, Signer: r.Signer, Network: r.Network, Party: r.Party, Deferred: true})
	}
	if len(out) == 0 && refused {
		return nil, fmt.Errorf("%w: %s", ports.ErrColdOverNetwork, key)
	}
	if s.Prefer != nil && len(out) > 1 {
		out = s.Prefer(key, out)
	}
	return out, nil
}

// SignerFor implements ports.SignerDirectory.
func (s Signers) SignerFor(key custody.KeyRef) (ports.Signer, error) {
	return s.SignerForOperation(key, "")
}

// SignerForOperation implements ports.OperationDirectory.
func (s Signers) SignerForOperation(key custody.KeyRef, op custody.Operation) (ports.Signer, error) {
	conn, err := s.connected(key, op)
	if err != nil {
		return nil, err
	}
	if len(conn) > 0 {
		return conn[0].Signer, nil
	}
	if idx := s.index(); idx != nil && s.Hardware == nil {
		if homes, err := idx.Homes(context.Background(), key.Identity); err == nil {
			if _, ok := ports.HardwareHome(homes, key.Role); ok {
				return nil, ports.ErrNoHardwareSigner
			}
		}
	}
	return nil, fmt.Errorf("%w: %s", ports.ErrNoSignerFor, key)
}

var (
	_ ports.SignerDirectory    = Signers{}
	_ ports.OperationDirectory = Signers{}
	_ ports.PlanScoped         = Signers{}
)

// NewSignatureSigners returns the directory of a vault with the message,
// registration and attestation capabilities: every vault signer has them now.
func NewSignatureSigners(v ports.Vault) Signers { return Signers{Vault: v} }

// RegistrySigners is a directory over a vault.
type RegistrySigners = Signers
