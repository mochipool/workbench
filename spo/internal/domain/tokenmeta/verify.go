package tokenmeta

import (
	"encoding/hex"
	"sort"
)

// PropertyVerdict is the result of checking one property's attestations.
type PropertyVerdict struct {
	Property Property
	// Valid and Invalid count the signatures that do and do not verify.
	Valid, Invalid int
	// PolicySatisfied is true when the entry's policy script is satisfied by
	// the keys of the valid signatures (time locks ignored, CIP-26). It is
	// meaningful only when Verification.PolicyChecked.
	PolicySatisfied bool
}

// Verification is the result of Verify.
type Verification struct {
	Properties []PropertyVerdict
	// PolicyChecked: the entry has a policy property that could be read;
	// PolicyIDMatches: it hashes to the subject's policy id.
	PolicyChecked   bool
	PolicyIDMatches bool
	// PolicyError is why the policy property could not be read.
	PolicyError string
	// OK: every property has a valid signature, and, when the entry has a
	// policy, the policy hashes to the subject's policy id and each property is
	// signed by keys that satisfy it. An entry with no property is not OK.
	OK bool
}

// Verify checks the attestations of every property. A property with no valid
// signature, a policy that does not match the subject, or a policy the signers
// do not satisfy make the entry not OK; the verdicts say which.
//
// The construction is the one the real registry entries verify under (package
// documentation).
//
// spec: SPO-12b-INV-001
func (e Entry) Verify() Verification {
	var v Verification
	var pol script
	if e.Policy != "" {
		s, id, err := parsePolicy(e.Policy)
		switch {
		case err != nil:
			v.PolicyError = err.Error()
		case len(e.Subject) < 56:
			v.PolicyError = "no policy id in the subject"
		default:
			v.PolicyChecked = true
			v.PolicyIDMatches = hex.EncodeToString(id[:]) == e.Subject[:56]
			pol = s
		}
	}
	names := make([]string, 0, len(e.Props))
	for p := range e.Props {
		names = append(names, string(p))
	}
	sort.Strings(names)
	v.OK = len(names) > 0 && v.PolicyError == ""
	for _, n := range names {
		p := Property(n)
		a := e.Props[p]
		msg := Message(e.Subject, p, a.Value, a.Sequence)
		pv := PropertyVerdict{Property: p}
		signers := map[[28]byte]bool{}
		for _, s := range a.Signatures {
			if s.Verify(msg) {
				pv.Valid++
				signers[s.KeyHash()] = true
			} else {
				pv.Invalid++
			}
		}
		if v.PolicyChecked {
			pv.PolicySatisfied = pol.satisfied(signers)
		}
		if pv.Valid == 0 || (v.PolicyChecked && !pv.PolicySatisfied) {
			v.OK = false
		}
		v.Properties = append(v.Properties, pv)
	}
	if v.PolicyChecked && !v.PolicyIDMatches {
		v.OK = false
	}
	return v
}
