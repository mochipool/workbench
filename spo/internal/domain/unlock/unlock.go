// Package unlock is the unlock policy of a workspace (ADR 0011, decision 6): which
// slots a slot table may hold. It is pure. Slot add, policy change, rekey and
// the opener call Check on the table they have, or would have after the change,
// and refuse when it returns an error.
//
// The package knows slots as a set of factors by kind and id. It does not know
// how a slot key is derived (platform/seal) or where a table is kept. A
// Vault or KMS factor is only a factor kind here; no client of either exists.
package unlock

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// Policy is the unlock policy of a workspace.
type Policy string

const (
	// Standard: at least one passphrase slot and one recovery slot. The
	// weakest slot is the strength of the workspace, so a hardware slot beside
	// them is a convenience.
	Standard Policy = "standard"
	// Hardware: every slot needs a FIDO2 factor. No slot opens from a passphrase
	// alone or from the recovery key alone.
	Hardware Policy = "hardware"
	// Strict: Hardware with no recovery slot at all.
	Strict Policy = "strict"
)

// Valid reports whether p is one of the three policies.
func (p Policy) Valid() bool { return p == Standard || p == Hardware || p == Strict }

// FactorKind is the kind of a factor.
type FactorKind string

const (
	Passphrase FactorKind = "passphrase"
	Recovery   FactorKind = "recovery"
	FIDO2      FactorKind = "fido2"
	// Backend is a Vault or KMS backend: the unwrapped secret B (decision 5).
	Backend FactorKind = "backend"
)

// SlotKind is the kind of a slot.
type SlotKind string

const (
	SlotPassphrase SlotKind = "passphrase"
	SlotRecovery   SlotKind = "recovery"
	SlotFIDO2HMAC  SlotKind = "fido2-hmac"
	SlotComposite  SlotKind = "composite"
)

// Factor is one factor of a slot. ID is the factor id (for FIDO2, ports.FactorIDOf
// of its credential id).
type Factor struct {
	Kind FactorKind
	ID   []byte
}

// Slot is what the policy needs to know of a slot.
type Slot struct {
	ID      []byte
	Kind    SlotKind
	Factors []Factor
	// RecoveryPubKeyHash is the hash of the recovery public key the slot binds.
	RecoveryPubKeyHash []byte
}

// Table is a slot table with its policy.
type Table struct {
	Policy Policy
	Slots  []Slot
}

// Rule names one rule of the policy, for a caller that reacts to a particular
// refusal and for tests.
type Rule string

const (
	RuleTable             Rule = "table"                        // no slot, unknown policy, repeated or empty slot id
	RuleShape             Rule = "slot-shape"                   // a slot's factors do not fit its kind
	RuleStandardSlots     Rule = "standard-slots"               // standard lacks a passphrase or recovery slot
	RuleHardwareFactor    Rule = "hardware-factor"              // a slot of hardware or strict without a FIDO2 factor
	RulePassphraseOnly    Rule = "passphrase-only"              // hardware or strict: passphrase alone opens a slot
	RuleRecoveryOnly      Rule = "recovery-only"                // hardware or strict: recovery key alone opens a slot
	RuleRecoveryComposite Rule = "recovery-composite"           // hardware: recovery composite is not recovery AND a hardware factor with no standalone slot
	RuleBackend           Rule = "backend"                      // Vault/KMS without FIDO2 (hardware, strict) or without another factor (always)
	RuleStandaloneFactor  Rule = "composite-and-single"         // a factor inside a composite is also a standalone slot
	RuleStrictRecovery    Rule = "strict-recovery"              // strict holds a recovery slot
	RuleRecoveryKeyHash   Rule = "recovery-key-hash"            // slots bind different recovery public key hashes
	RuleRecoveryAuthReuse Rule = "recovery-authenticator-reuse" // the recovery composite's authenticator is in another slot
	RuleRecoveryRequired  Rule = "recovery-required"            // hardware with no recovery composite
	RuleMultipleRecovery  Rule = "multiple-recovery"            // more than one distinct recovery factor
	RuleKeyHashMissing    Rule = "recovery-key-hash-missing"    // a slot of a policy with a recovery path binds no hash
	RuleKeyHashPresent    Rule = "strict-key-hash"              // a slot of a strict table binds a recovery key hash
)

// Violation is one refused rule, with the slot it concerns (nil for the table).
type Violation struct {
	Rule   Rule
	SlotID []byte
	Detail string
}

func (v Violation) String() string {
	if v.SlotID != nil {
		return fmt.Sprintf("%s (slot %x): %s", v.Rule, v.SlotID, v.Detail)
	}
	return fmt.Sprintf("%s: %s", v.Rule, v.Detail)
}

// Error is the refusal of Check: every violated rule, not only the first.
type Error struct{ Violations []Violation }

func (e *Error) Error() string {
	parts := make([]string, len(e.Violations))
	for i, v := range e.Violations {
		parts[i] = v.String()
	}
	return "the slot table breaks its unlock policy: " + strings.Join(parts, "; ")
}

// ErrPolicy is matched by errors.Is for every refusal of Check.
var ErrPolicy = errors.New("unlock policy")

// Is makes errors.Is(err, ErrPolicy) true.
func (e *Error) Is(target error) bool { return target == ErrPolicy }

// Rules returns the rules an error of Check violated, in order, without repeats.
func Rules(err error) []Rule {
	var e *Error
	if !errors.As(err, &e) {
		return nil
	}
	var out []Rule
	seen := map[Rule]bool{}
	for _, v := range e.Violations {
		if !seen[v.Rule] {
			seen[v.Rule] = true
			out = append(out, v.Rule)
		}
	}
	return out
}

func (s Slot) has(k FactorKind) bool {
	for _, f := range s.Factors {
		if f.Kind == k {
			return true
		}
	}
	return false
}

func (s Slot) onlyKind(k FactorKind) bool {
	for _, f := range s.Factors {
		if f.Kind != k {
			return false
		}
	}
	return len(s.Factors) > 0
}

// Check checks a whole slot table against its policy and returns nil or an
// *Error that lists every rule it breaks. It is the one function slot add,
// policy change, rekey and the opener use (ADR 0011, decision 6); rekey calls
// it on the table it would write.
func Check(t Table) error {
	var vs []Violation
	add := func(r Rule, s *Slot, format string, a ...any) {
		v := Violation{Rule: r, Detail: fmt.Sprintf(format, a...)}
		if s != nil {
			v.SlotID = s.ID
		}
		vs = append(vs, v)
	}
	finish := func() error {
		if len(vs) == 0 {
			return nil
		}
		return &Error{Violations: vs}
	}

	if !t.Policy.Valid() {
		add(RuleTable, nil, "unknown policy %q", t.Policy)
		return finish()
	}
	if len(t.Slots) == 0 {
		add(RuleTable, nil, "no slot: nothing opens the workspace")
		return finish()
	}
	seenID := map[string]bool{}
	for i := range t.Slots {
		s := &t.Slots[i]
		switch {
		case len(s.ID) == 0:
			add(RuleTable, s, "a slot has no id")
		case seenID[string(s.ID)]:
			add(RuleTable, s, "slot id repeats")
		}
		seenID[string(s.ID)] = true
	}

	// The shape of each slot decides what the rules below may assume.
	shapeOK := make([]bool, len(t.Slots))
	for i := range t.Slots {
		s := &t.Slots[i]
		shapeOK[i] = checkShape(s, add)
	}

	// A factor inside a composite must not also be a standalone slot, by id.
	standalone := map[FactorKind]map[string]bool{}
	for i := range t.Slots {
		s := &t.Slots[i]
		if !shapeOK[i] || s.Kind == SlotComposite {
			continue
		}
		f := s.Factors[0]
		if standalone[f.Kind] == nil {
			standalone[f.Kind] = map[string]bool{}
		}
		standalone[f.Kind][string(f.ID)] = true
	}
	for i := range t.Slots {
		s := &t.Slots[i]
		if !shapeOK[i] || s.Kind != SlotComposite {
			continue
		}
		for _, f := range s.Factors {
			// Two passphrases typed identically cannot be told apart, so the
			// rule is checked where the factor has an id a device or service owns.
			if f.Kind != Passphrase && standalone[f.Kind][string(f.ID)] {
				add(RuleStandaloneFactor, s, "%s factor %x is also a standalone slot", f.Kind, f.ID)
			}
		}
	}

	// A backend needs a factor it does not control, in every policy.
	for i := range t.Slots {
		s := &t.Slots[i]
		if !shapeOK[i] || s.Kind != SlotComposite || !s.has(Backend) {
			continue
		}
		if !s.has(Passphrase) && !s.has(FIDO2) && !s.has(Recovery) {
			add(RuleBackend, s, "a Vault or KMS factor needs another factor the backend does not control")
		}
	}

	var nPass, nRec int
	for i := range t.Slots {
		s := &t.Slots[i]
		if !shapeOK[i] {
			continue
		}
		if s.Kind == SlotPassphrase {
			nPass++
		}
		if s.Kind == SlotRecovery {
			nRec++
		}
	}

	switch t.Policy {
	case Standard:
		if nPass == 0 {
			add(RuleStandardSlots, nil, "standard needs a passphrase slot")
		}
		if nRec == 0 {
			add(RuleStandardSlots, nil, "standard needs a recovery slot")
		}
	case Hardware, Strict:
		for i := range t.Slots {
			s := &t.Slots[i]
			if !shapeOK[i] {
				continue
			}
			switch {
			case s.Kind == SlotPassphrase:
				add(RulePassphraseOnly, s, "a passphrase alone opens this slot")
			case s.Kind == SlotRecovery:
				add(RuleRecoveryOnly, s, "the recovery key alone opens this slot")
			case !s.has(FIDO2):
				if s.has(Backend) {
					add(RuleBackend, s, "a Vault or KMS factor appears only together with a FIDO2 factor")
				} else {
					add(RuleHardwareFactor, s, "the slot needs a FIDO2 factor")
				}
			}
			if s.Kind == SlotComposite && s.has(Recovery) {
				if t.Policy == Strict {
					add(RuleStrictRecovery, s, "strict holds no recovery slot")
					continue
				}
				// recovery key AND a hardware factor, enrolled for this slot only
				if !s.has(FIDO2) {
					add(RuleRecoveryComposite, s, "a recovery composite needs a hardware factor")
				}
				for _, f := range s.Factors {
					if f.Kind != FIDO2 {
						continue
					}
					// the recovery authenticator appears in the recovery composite only
					for k := range t.Slots {
						o := &t.Slots[k]
						if k == i || !shapeOK[k] {
							continue
						}
						for _, of := range o.Factors {
							if of.Kind == FIDO2 && bytes.Equal(of.ID, f.ID) {
								add(RuleRecoveryAuthReuse, s, "the hardware factor %x of the recovery composite is also in slot %x", f.ID, o.ID)
							}
						}
					}
				}
			}
		}
		if t.Policy == Hardware {
			recComposite := false
			for i := range t.Slots {
				if shapeOK[i] && t.Slots[i].Kind == SlotComposite && t.Slots[i].has(Recovery) {
					recComposite = true
				}
			}
			if !recComposite {
				add(RuleRecoveryRequired, nil, "hardware needs a recovery composite (a table with no recovery path is strict)")
			}
		}
		if t.Policy == Strict {
			for i := range t.Slots {
				if s := &t.Slots[i]; shapeOK[i] && s.Kind == SlotRecovery {
					add(RuleStrictRecovery, s, "strict holds no recovery slot")
				}
			}
		}
	}

	// Only one recovery secret derives the bound recovery public key.
	recIDs := map[string]bool{}
	for i := range t.Slots {
		if !shapeOK[i] {
			continue
		}
		for _, f := range t.Slots[i].Factors {
			if f.Kind == Recovery {
				recIDs[string(f.ID)] = true
			}
		}
	}
	if len(recIDs) > 1 {
		add(RuleMultipleRecovery, nil, "%d distinct recovery factors; only one recovery secret derives the bound recovery public key", len(recIDs))
	}

	// A table with a recovery path binds a hash in every slot; a strict table
	// has no recovery key and binds none (the value is absent everywhere).
	for i := range t.Slots {
		s := &t.Slots[i]
		switch {
		case t.Policy == Strict && len(s.RecoveryPubKeyHash) != 0:
			add(RuleKeyHashPresent, s, "strict has no recovery public key; the bound hash must be absent")
		case t.Policy != Strict && len(s.RecoveryPubKeyHash) == 0:
			add(RuleKeyHashMissing, s, "the slot binds no recovery public key hash")
		}
	}

	// Every slot binds the same recovery public key hash.
	for i := 1; i < len(t.Slots); i++ {
		if !bytes.Equal(t.Slots[i].RecoveryPubKeyHash, t.Slots[0].RecoveryPubKeyHash) {
			add(RuleRecoveryKeyHash, &t.Slots[i], "binds another recovery public key hash than slot %x", t.Slots[0].ID)
		}
	}
	return finish()
}

// checkShape reports whether the factors of s fit its kind.
func checkShape(s *Slot, add func(Rule, *Slot, string, ...any)) bool {
	bad := func(format string, a ...any) bool { add(RuleShape, s, format, a...); return false }
	for _, f := range s.Factors {
		switch f.Kind {
		case Passphrase, Recovery, FIDO2, Backend:
		default:
			return bad("unknown factor kind %q", f.Kind)
		}
		if len(f.ID) == 0 {
			return bad("a %s factor has no id", f.Kind)
		}
	}
	switch s.Kind {
	case SlotPassphrase:
		if len(s.Factors) != 1 || !s.onlyKind(Passphrase) {
			return bad("a passphrase slot has exactly one passphrase factor")
		}
	case SlotRecovery:
		if len(s.Factors) != 1 || !s.onlyKind(Recovery) {
			return bad("a recovery slot has exactly one recovery factor")
		}
	case SlotFIDO2HMAC:
		if len(s.Factors) != 1 || !s.onlyKind(FIDO2) {
			return bad("a fido2-hmac slot has exactly one fido2 factor")
		}
	case SlotComposite:
		if len(s.Factors) < 2 {
			return bad("a composite slot has at least two factors")
		}
		seen := map[string]bool{}
		for _, f := range s.Factors {
			k := string(f.Kind) + "/" + string(f.ID)
			if seen[k] {
				return bad("a factor repeats in the slot")
			}
			seen[k] = true
		}
	default:
		return bad("unknown slot kind %q", s.Kind)
	}
	return true
}
