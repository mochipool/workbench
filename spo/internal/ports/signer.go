package ports

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// Signer is anything that holds keys and signs with them: the vault, a
// hardware wallet, a remote party. It publishes what it can do; the
// operations themselves are separate interfaces below, and a signer
// implements only those it supports (ADR 0008).
type Signer interface {
	Profile() custody.Profile
}

// SignerDirectory maps a key identity to the signers connected now that can
// answer for it: the local vault (keys it holds, found by identity), each
// attached hardware device (keys it has exported verification keys for) and
// each remote co-signer party reachable through the envelope (the keys ADR
// 0005's slot assignment gives it). It is local to the client and is not
// stored (ADR 0010 decision 3). A use case never sees which kind answers.
type SignerDirectory interface {
	// Connected lists the connected signers that report holding the key, in
	// the order the directory prefers them (see the directory's Prefer hook).
	// A demand that may not travel over a network transport has those signers
	// left out already. An empty list is not an error here.
	Connected(key custody.KeyRef) ([]ConnectedSigner, error)
	// SignerFor returns the preferred connected signer, or an error that says
	// why there is none (the same error users see for an unavailable key).
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

// TxWitnesser makes a witness for a transaction body with a key the signer
// holds. A software signer signs the body's id; a device parses the body
// and may refuse it, which the plan has already checked for the features
// the body contains (ADR 0008).
type TxWitnesser interface {
	Signer
	Witness(ctx context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error)
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
	if claims[custody.OpWitnessTx] {
		if _, ok := s.(TxWitnesser); !ok {
			return fmt.Errorf("signer %q claims %s but does not implement TxWitnesser", p.Name(), custody.OpWitnessTx)
		}
	}
	return nil
}

// PlanSignatures builds the plan for a workflow's signature slots against
// the signers in a directory. It is the only way use cases obtain a Plan.
func PlanSignatures(dir SignerDirectory, slots []custody.Slot) (custody.Plan, error) {
	dir = ForPlan(dir)
	return custody.NewPlanFor(slots, func(sl custody.Slot) (custody.Profile, error) {
		s, err := SignerForOperation(dir, sl.Key, sl.Demand.Operation)
		if err != nil {
			return custody.Profile{}, err
		}
		return s.Profile(), nil
	})
}
