package assets

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Unlimited is the value of an asset record's policyValidBeforeSlot for a
// policy without a time lock.
const Unlimited = "unlimited"

// PolicyScript builds the native script file of a policy: `sig` for the
// policy key hash, or, with an expiry slot, `all` of a `before` slot and that
// `sig`. It is one line with a trailing newline, as upstream's `echo` writes it
// (SPO-10-OUT-005). The expiry is
// exclusive: a transaction under the policy must end its validity at or
// before it (SPO-10-INV-004).
//
// spec: SPO-10-OUT-005, SPO-10-INV-004
func PolicyScript(keyHashHex string, expiry uint64, limited bool) []byte {
	if !limited {
		return []byte(fmt.Sprintf("{ \"keyHash\": \"%s\", \"type\": \"sig\" }\n", keyHashHex))
	}
	return []byte(fmt.Sprintf("{ \"type\": \"all\", \"scripts\": [ { \"slot\": %d, \"type\": \"before\" }, { \"keyHash\": \"%s\", \"type\": \"sig\" } ] }\n", expiry, keyHashHex))
}

// ParseLifetime reads the lifetime argument of `10`: a non-negative whole
// number of slots. Zero means unlimited, as a missing argument does. A
// non-numeric word is refused (upstream's shell test fails with an arithmetic
// error).
//
// spec: SPO-10-IF-003
func ParseLifetime(s string) (uint64, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("the policy lifetime %q must be a whole number of slots", s)
	}
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, fmt.Errorf("the policy lifetime %q is too large", s)
	}
	return n, nil
}

// Expiry is the slot of the first `before` entry of the script's top-level
// `scripts` array, if there is one. A plain `sig` script, or a script that
// cannot be read, has none (SPO-11a-INV-001).
//
// spec: SPO-11a-INV-001
func Expiry(scriptJSON []byte) (slot uint64, limited bool) {
	var doc struct {
		Scripts []struct {
			Type string          `json:"type"`
			Slot json.Number     `json:"slot"`
			Raw  json.RawMessage `json:"-"`
		} `json:"scripts"`
	}
	dec := json.NewDecoder(strings.NewReader(string(scriptJSON)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return 0, false
	}
	for _, s := range doc.Scripts {
		if s.Type == "before" {
			n, err := strconv.ParseUint(s.Slot.String(), 10, 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

// ValidBefore is the text of the record's policyValidBeforeSlot.
func ValidBefore(slot uint64, limited bool) string {
	if !limited {
		return Unlimited
	}
	return strconv.FormatUint(slot, 10)
}
