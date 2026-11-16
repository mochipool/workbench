package pool

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Lifecycle is where a pool registration is in its life
// (spec/domain/domain-model.md `PoolRegistration`):
//
//	Draft -> CertificateIssued -> CollectingWitnesses -> Registered -> (Updated)
//	      -> RetirementScheduled -> Retired
//
// It is derived from the descriptor, the collection and the clock; the chain
// alone knows Retired (chain.PoolRetired).
type Lifecycle string

// Lifecycle states.
const (
	LifecycleDraft               Lifecycle = "Draft"
	LifecycleCertificateIssued   Lifecycle = "CertificateIssued"
	LifecycleCollecting          Lifecycle = "CollectingWitnesses"
	LifecycleRegistered          Lifecycle = "Registered"
	LifecycleRetirementScheduled Lifecycle = "RetirementScheduled"
)

// LifecycleOf derives the state. A registration record with a new
// certificate waiting is an update in the making (CertificateIssued again).
func LifecycleOf(d *Descriptor, c *Collection, tipSlot uint64) Lifecycle {
	switch {
	case d.Has(FieldDeregSubmit) && !(d.Has(FieldRegCertFile) && !d.Has(FieldRegSubmitted)):
		return LifecycleRetirementScheduled
	case c != nil && (c.State(tipSlot) == CollectionOpenIncomplete || c.State(tipSlot) == CollectionOpenComplete):
		return LifecycleCollecting
	case d.Has(FieldRegCertFile) && !d.Has(FieldRegSubmitted):
		return LifecycleCertificateIssued
	case d.Has(FieldRegSubmitted):
		return LifecycleRegistered
	}
	return LifecycleDraft
}

// Refusals of the registration type decision.
var (
	// ErrChooseType: the pool was retired before; the operator must say
	// whether this is a registration or a re-registration.
	ErrChooseType = errors.New("the pool was retired before: choose PoolRegistration or PoolReRegistration explicitly")
	// ErrAmbiguousPool: the chain lists the pool more than once.
	ErrAmbiguousPool = errors.New("the chain reports the pool more than once")
)

// TypeInput is what decides the registration type.
type TypeInput struct {
	// Forced is the operator's `type:` choice; it wins and the chain is not
	// consulted (SPO-05c-INV-002).
	Forced RegistrationType
	// DeregSubmitted: the descriptor records a retirement.
	DeregSubmitted bool
	// DescriptorRegistered: the descriptor records a registration
	// (`regSubmitted`), the only evidence offline (SPO-05c-MODE-003).
	DescriptorRegistered bool
	// Chain is the pool state read from a provider; nil when there is no
	// provider in this mode.
	Chain *chain.Reading[chain.PoolState]
}

// DecideType gives the registration type: re-registration when the pool is
// registered or retiring, registration when it never was or is retired. An
// Unknown reading is an error, never "not registered".
//
// spec: SPO-05c-INV-002, SPO-05c-PRE-004, SPO-05c-MODE-001, SPO-05c-MODE-002, SPO-05c-MODE-003
func DecideType(in TypeInput) (RegistrationType, error) {
	if in.Forced != "" {
		return in.Forced, nil
	}
	if in.DeregSubmitted {
		return "", ErrChooseType
	}
	if in.Chain == nil {
		if in.DescriptorRegistered {
			return PoolReRegistration, nil
		}
		return PoolRegistration, nil
	}
	r := *in.Chain
	switch {
	case r.IsUnknown():
		return "", fmt.Errorf("the pool registration state is unknown: %s", r.Why())
	case r.IsNone():
		return PoolRegistration, nil
	}
	st, _ := r.Get()
	if st.Status == chain.PoolRetired {
		return PoolRegistration, nil
	}
	return PoolReRegistration, nil
}
