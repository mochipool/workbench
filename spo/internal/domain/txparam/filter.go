package txparam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// ErrNoFunds: every UTxO was filtered out (SPO-Pparam-IF-022 ends in the "no
// funds" refusal of SPO-Ptx-PRE-001; the caller's selection reports it).
var ErrNoFunds = errors.New("no UTxO is left after the filters")

// FilterUtxos narrows the UTxOs of the paying address by the tokens of the
// extras, in the order upstream applies them: the skip filter, the only
// filter, the limit, then the explicit list. The result is a candidate set
// for the selection strategy ("all UTxOs after filters", hazard H4).
//
// The limit keeps the first n UTxOs in the order cardano-cli lists them: by
// transaction id, then index, whatever order the provider answered in.
// Upstream applies the skip, only and limit tokens in online and light mode
// and ignores them offline, and the explicit list in every mode; the port
// applies all of them in every mode (SPO-Pparam-IF-020, IF-022).
//
// spec: SPO-Pparam-IF-019, SPO-Pparam-IF-020, SPO-Pparam-IF-022, SPO-Cutxo-OUT-004, SPO-Cutxo-INV-003
func FilterUtxos(in []chain.Utxo, ex Extras) []chain.Utxo {
	out := append([]chain.Utxo(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].TxID[:], out[j].TxID[:]); c != 0 {
			return c < 0
		}
		return out[i].Index < out[j].Index
	})
	holds := func(u chain.Utxo, ms []AssetMatch) bool {
		for _, a := range u.Assets {
			for _, m := range ms {
				if m.Matches(a.Asset) {
					return true
				}
			}
		}
		return false
	}
	if len(ex.Skip) > 0 {
		kept := out[:0:0]
		for _, u := range out {
			if !holds(u, ex.Skip) {
				kept = append(kept, u)
			}
		}
		out = kept
	}
	if len(ex.Only) > 0 {
		kept := out[:0:0]
		for _, u := range out {
			if holds(u, ex.Only) {
				kept = append(kept, u)
			}
		}
		out = kept
	}
	if ex.UtxoLimit > 0 && len(out) > ex.UtxoLimit {
		out = out[:ex.UtxoLimit]
	}
	if len(ex.Inputs) > 0 {
		var kept []chain.Utxo
		for _, ref := range ex.Inputs {
			for _, u := range out {
				if u.TxID == ref.TxID && u.Index == ref.Index {
					kept = append(kept, u)
					break
				}
			}
		}
		out = kept
	}
	return out
}

// CheckMetadataJSON is upstream's "simple basic check" of a .json metadata
// file: it must be a JSON object whose first key, in file order, is a number
// of digits only in 0..65535. Only the first key is checked; the schema is
// cardano-cli's business (the native adapter checks the rest when it builds
// the body).
//
// spec: SPO-Pparam-IF-014, SPO-Pparam-PRE-005
func CheckMetadataJSON(name string, data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %q is not a valid JSON file: %v", ErrBadMetadataFile, name, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("%w: %q: the top level must be a JSON object from label to value", ErrBadMetadataFile, name)
	}
	if !dec.More() {
		return fmt.Errorf("%w: %q has no metadata label", ErrBadMetadataFile, name)
	}
	tok, err = dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %q is not a valid JSON file: %v", ErrBadMetadataFile, name, err)
	}
	k, _ := tok.(string)
	n, err := strconv.ParseUint(k, 10, 64)
	if !isDigits(k) || err != nil || n > 65535 {
		return fmt.Errorf("%w: the label %q in %q must be in the range of 0..65535", ErrBadMetadataFile, k, name)
	}
	if !json.Valid(data) {
		return fmt.Errorf("%w: %q is not a valid JSON file", ErrBadMetadataFile, name)
	}
	return nil
}

// MessageJSON renders the message metadata of SPO-Pparam-OUT-001 and EXT-001
// as the JSON text upstream writes to its message file: `{"674": {"msg":
// [...]}}`, with `"enc": "basic"` before `msg` when encrypted. It is for
// display; the body is built from the lines, not from this text. Nil when
// there are no lines.
//
// spec: SPO-Pparam-OUT-001, SPO-Pparam-OUT-002, SPO-Pparam-EXT-001
func MessageJSON(lines []string, enc string) []byte {
	if len(lines) == 0 {
		return nil
	}
	m := map[string]any{"msg": lines}
	if enc != "" {
		m["enc"] = enc
	}
	b, _ := json.MarshalIndent(map[string]any{"674": m}, "", "  ")
	return b
}
