package custody

import (
	"errors"
	"fmt"
)

// SoftwareGenerator is the profile of the in-process key generators: it can
// produce the verification key of every role, and holds the key in the vault.
// It says nothing about signing.
func SoftwareGenerator() Profile {
	p := NewProfile("software key generation")
	for _, r := range Roles() {
		p = p.Allow(r, OpExportVKey)
	}
	return p
}

// PlanGeneration builds the plan for generating keys, before anything is
// generated or written. Keys for the vault holder are met by the software
// generators; a key for any other holder is refused with an
// *UnsupportedError, because no generator is configured for it (the
// hardware signer adapter does not exist yet; ADR 0008). A use case never
// has a hardware branch: it calls this first and stops on an error.
func PlanGeneration(keys ...KeyRef) (Plan, error) {
	slots := make([]Slot, len(keys))
	for i, k := range keys {
		slots[i] = Slot{Label: "generate " + string(k.Role) + " key", Key: k,
			Demand: Demand{Role: k.Role, Operation: OpExportVKey}}
	}
	soft := SoftwareGenerator()
	return NewPlan(slots, func(k KeyRef) (Profile, error) {
		if k.Holder == HolderVault || k.Holder == "" {
			return soft, nil
		}
		return Profile{}, fmt.Errorf("no signer is configured that can generate keys held by %s", k.Holder)
	})
}

// ErrMnemonicWords means a mnemonic does not have 24 words.
var ErrMnemonicWords = errors.New("a mnemonic needs exactly 24 words")

// MnemonicWords is the length of every mnemonic this system accepts.
const MnemonicWords = 24

// NormalizeMnemonic lowercases a phrase and squeezes the runs of spaces
// between its words to one, as upstream's 03a does before counting
// (SPO-03a-IF-004). It works on bytes so a phrase held in guarded memory is
// never turned into an immutable string. The result is a new slice the
// caller wipes. The error never contains the phrase.
func NormalizeMnemonic(in []byte) ([]byte, error) {
	out := make([]byte, 0, len(in))
	words := 0
	inWord := false
	for _, c := range in {
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			inWord = false
		default:
			if !inWord {
				if words > 0 {
					out = append(out, ' ')
				}
				words++
				inWord = true
			}
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out = append(out, c)
		}
	}
	if words != MnemonicWords {
		for i := range out {
			out[i] = 0
		}
		return nil, fmt.Errorf("%w (got %d)", ErrMnemonicWords, words)
	}
	return out, nil
}
