package ports

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Signer is anything that holds keys and signs with them: the vault, a
// hardware wallet, a remote party. It publishes what it can do; the
// operations themselves are separate interfaces below, and a signer
// implements only those it supports (ADR 0008).
type Signer interface {
	Profile() custody.Profile
}

// SignerDirectory finds the signer that holds a key.
type SignerDirectory interface {
	// SignerFor returns the signer for the key, or an error that says why
	// none is configured.
	SignerFor(key custody.KeyRef) (Signer, error)
}

// OpCertRequest is what an operational certificate is issued over. All of it
// is public. The counter is chosen by the caller: a signer does not keep or
// advance it, so a failed issue consumes nothing.
type OpCertRequest struct {
	KesVKey   []byte // raw 32-byte KES verification key
	Counter   uint64
	KesPeriod uint64
}

// OpCertIssuer signs operational certificates with a pool cold key.
type OpCertIssuer interface {
	Signer
	// IssueOpCert returns the certificate as a cardano-cli text envelope.
	IssueOpCert(ctx context.Context, cold custody.Key[custody.PoolCold], req OpCertRequest) ([]byte, error)
}

// CheckSigner verifies that a signer's profile and its interfaces agree: it
// must implement the interface of every operation its profile claims. It
// runs in adapter tests and when the binary wires itself, so a profile that
// promises more than the code can do is caught before any use.
func CheckSigner(s Signer) error {
	p := s.Profile()
	claims := map[custody.Operation]bool{}
	for _, role := range custody.Roles() {
		for _, op := range p.Operations(role) {
			claims[op] = true
		}
	}
	if claims[custody.OpIssueOpCert] {
		if _, ok := s.(OpCertIssuer); !ok {
			return fmt.Errorf("signer %q claims %s but does not implement OpCertIssuer", p.Name(), custody.OpIssueOpCert)
		}
	}
	return nil
}

// PlanSignatures builds the plan for a workflow's signature slots against
// the signers in a directory. It is the only way use cases obtain a Plan.
func PlanSignatures(dir SignerDirectory, slots []custody.Slot) (custody.Plan, error) {
	return custody.NewPlan(slots, func(k custody.KeyRef) (custody.Profile, error) {
		s, err := dir.SignerFor(k)
		if err != nil {
			return custody.Profile{}, err
		}
		return s.Profile(), nil
	})
}
