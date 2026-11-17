package assets

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Record is the asset record `<policy>.<asset>.asset` (SPO-Pfiles-OUT-033):
// a JSON document that keeps its keys in order, because the operator edits
// the `meta*` keys by hand and the file is read back by the registry
// scripts. The values are kept as they are, so a key the operator added, or a
// value they changed, survives an update.
type Record struct {
	keys []string
	vals map[string]json.RawMessage
}

// ErrBadRecord: an asset record that is not a JSON object.
var ErrBadRecord = errors.New("the asset record is not a JSON object")

// ParseRecord reads a record; empty input is the empty record `{}`.
func ParseRecord(b []byte) (Record, error) {
	r := Record{vals: map[string]json.RawMessage{}}
	if len(bytes.TrimSpace(b)) == 0 {
		return r, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return Record{}, ErrBadRecord
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return Record{}, ErrBadRecord
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return Record{}, ErrBadRecord
		}
		k := kt.(string)
		if _, dup := r.vals[k]; !dup {
			r.keys = append(r.keys, k)
		}
		r.vals[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return Record{}, ErrBadRecord
	}
	return r, nil
}

func jsonString(s string) json.RawMessage {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
}

// Get returns the string value of a key, or "" when it is absent or not a
// string.
func (r Record) Get(k string) string {
	var s string
	if json.Unmarshal(r.vals[k], &s) != nil {
		return ""
	}
	return s
}

func (r *Record) set(k string, v json.RawMessage) {
	if _, ok := r.vals[k]; !ok {
		r.keys = append(r.keys, k)
	}
	r.vals[k] = v
}

// Set sets a string value, keeping the key's place when it exists.
func (r *Record) Set(k, v string) { r.set(k, jsonString(v)) }

// Marshal renders the record as jq prints it: two-space indent, keys in
// order, a newline at the end (the file is `echo -e "$json" > file`).
func (r Record) Marshal() []byte {
	if len(r.keys) == 0 {
		return []byte("{}\n")
	}
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range r.keys {
		b.WriteString("  ")
		b.Write(jsonString(k))
		b.WriteString(": ")
		var v bytes.Buffer
		if err := json.Indent(&v, r.vals[k], "  ", "  "); err != nil {
			v.Write(r.vals[k])
		}
		b.Write(v.Bytes())
		if i < len(r.keys)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// Change is what a mint or a burn does to an asset record.
type Change struct {
	Asset chain.AssetID
	// Name is the asset name as typed (`mytoken` or `{00010203}`); HexTyped is
	// set for the latter.
	HexTyped bool
	// Delta is the signed quantity: positive for a mint, negative for a burn.
	Delta int64
	// ValidBefore is the policy's expiry slot or Unlimited.
	ValidBefore string
	// Action is the text of lastAction: `mint 100` or `burn 5`, with
	// ` (only Offline proof)` for a transaction that was queued.
	Action string
	Date   time.Time
}

// Apply updates the record by the procedure of SPO-11a-OUT-002 and
// SPO-11b-OUT-001: start from the skeleton, let the existing keys win, set
// `minted` to the old value (0 when absent) plus the delta in arbitrary
// precision, and overwrite the identifying keys and the last-action pair.
// The skeleton is the offline form: no `metaDecimals`, and the readable name
// uncut (SPO-11a-OUT-003), whatever the work mode.
//
// spec: SPO-11a-OUT-002, SPO-11a-OUT-003, SPO-11a-INV-005, SPO-11b-OUT-001
func (r Record) Apply(c Change) (Record, error) {
	name := DisplayName(c.Asset.Name)
	skeleton := [][2]string{
		{"metaName", name},
		{"metaDescription", ""},
		{"---", "--- Optional additional info ---"},
		{"metaTicker", ""},
		{"metaUrl", ""},
		{"metaLogoPNG", ""},
		{"===", "--- DO NOT EDIT BELOW THIS LINE !!! ---"},
		{"minted", "0"},
	}
	out := Record{vals: map[string]json.RawMessage{}}
	for _, kv := range skeleton {
		if v, ok := r.vals[kv[0]]; ok {
			out.set(kv[0], v) // an existing key wins, in the skeleton's place
		} else {
			out.Set(kv[0], kv[1])
		}
	}
	for _, k := range r.keys {
		if _, ok := out.vals[k]; !ok {
			out.set(k, r.vals[k])
		}
	}
	old := new(big.Int)
	if s := out.Get("minted"); s != "" {
		if _, ok := old.SetString(s, 10); !ok {
			return Record{}, fmt.Errorf("the asset record's minted %q is not a number", s)
		}
	}
	old.Add(old, big.NewInt(c.Delta))
	hexName := ""
	if c.HexTyped {
		hexName = hex.EncodeToString(c.Asset.Name)
	}
	out.Set("minted", old.String())
	out.Set("name", name)
	out.Set("hexname", hexName)
	out.Set("bechName", Fingerprint(c.Asset))
	out.Set("policyID", hex.EncodeToString(c.Asset.Policy[:]))
	out.Set("policyValidBeforeSlot", c.ValidBefore)
	out.Set("subject", Subject(c.Asset))
	out.Set("lastUpdate", c.Date.Format(time.RFC1123Z))
	out.Set("lastAction", c.Action)
	return out, nil
}

// RecordFields are the fields `01_sendAssets` reads from an asset file
// (SPO-01sendAssets-IF-014).
type RecordFields struct {
	PolicyID, Name, HexName string
}

// Fields reads policyID, name and hexname.
func (r Record) Fields() RecordFields {
	return RecordFields{PolicyID: r.Get("policyID"), Name: r.Get("name"), HexName: r.Get("hexname")}
}

// AssetOf resolves the fields of an asset file into the asset: the name is
// `hexname` when that is 1 to 32 bytes of hex, else `name` when it is purely
// alphanumeric; otherwise the file is not understood.
//
// spec: SPO-01sendAssets-IF-014
func (f RecordFields) AssetOf() (chain.AssetID, error) {
	var id chain.AssetID
	p, err := hex.DecodeString(strings.ToLower(f.PolicyID))
	if err != nil || len(p) != 28 {
		return id, fmt.Errorf("%w: the asset file has no valid policyID", ErrBadSelection)
	}
	copy(id.Policy[:], p)
	hx := strings.ToLower(f.HexName)
	if hexPairsRE.MatchString(hx) && len(hx) <= 2*MaxAssetNameBytes {
		id.Name, _ = hex.DecodeString(hx)
		return id, nil
	}
	if alnumRE.MatchString(f.Name) && len(f.Name) <= MaxAssetNameBytes {
		id.Name = []byte(f.Name)
		return id, nil
	}
	return id, fmt.Errorf("%w: the format of the name in the asset file is not understood", ErrBadSelection)
}

// Kinds of a pending update. A record without a kind is an asset update, which
// is all the first version wrote.
const (
	PendingAsset            = "asset"
	PendingPoolRegistration = "pool-registration"
	PendingPoolRetirement   = "pool-retirement"
)

// Pending is an update of a local record (an asset record, or the registration
// or retirement record of a pool descriptor) that waits for the transaction it
// belongs to to be confirmed in a block (hazard H9, spec/extensions/Xconfirm.md).
// It is stored under the transaction's id when the transaction is submitted or
// queued, and applied once, when the transaction is confirmed. The type keeps
// its name from the asset-only first version; the JSON of such a record has no
// "kind" and is read as an asset update.
type Pending struct {
	// Kind is one of the Pending constants; empty is PendingAsset.
	Kind string `json:"kind,omitempty"`
	TxID string `json:"txid"`
	// ValidUntil is the transaction's validity upper bound (a slot), when it
	// has one: it lets a later settle call the transaction expired.
	ValidUntil *uint64 `json:"validUntil,omitempty"`
	// Queued is true when the transaction was only queued for a later
	// submission (offline mode).
	Queued bool `json:"queued,omitempty"`
	// Date is when the update was recorded as pending (RFC 3339); an asset
	// record's lastUpdate takes it, as the old path stamped the submission.
	Date string `json:"date,omitempty"`

	// Asset updates. Record is the store name of the asset record.
	Record      string `json:"record,omitempty"`
	Policy      string `json:"policy,omitempty"`   // the policy id, hex
	NameHex     string `json:"nameHex,omitempty"`  // the asset name, hex
	HexTyped    bool   `json:"hexTyped,omitempty"` // the name was typed as {hex}
	Delta       string `json:"delta,omitempty"`    // signed decimal
	ValidBefore string `json:"validBefore,omitempty"`
	Action      string `json:"action,omitempty"`

	// Pool updates: the pool's store name, the epoch of a registration and the
	// stamp the descriptor field takes (what the old path wrote when it sent
	// the transaction).
	Pool  string `json:"pool,omitempty"`
	Epoch string `json:"epoch,omitempty"`
	Stamp string `json:"stamp,omitempty"`
}

// KindOrAsset is the kind of the update, an asset update when none is stored.
func (p Pending) KindOrAsset() string {
	if p.Kind == "" {
		return PendingAsset
	}
	return p.Kind
}

// Target names what the update changes, for messages: the asset record or the
// pool.
func (p Pending) Target() string {
	if p.KindOrAsset() == PendingAsset {
		return p.Record
	}
	return p.Pool
}

// Marshal renders the pending update for the store.
func (p Pending) Marshal() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

// ParsePending reads a stored pending update.
func ParsePending(b []byte) (Pending, error) {
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return Pending{}, fmt.Errorf("the pending update is damaged: %w", err)
	}
	switch p.KindOrAsset() {
	case PendingAsset, PendingPoolRegistration, PendingPoolRetirement:
	default:
		return Pending{}, fmt.Errorf("the pending update has an unknown kind %q", p.Kind)
	}
	return p, nil
}

// Change rebuilds the Change a pending update stands for.
func (p Pending) Change(date time.Time) (Change, error) {
	pol, err := hex.DecodeString(p.Policy)
	if err != nil || len(pol) != 28 {
		return Change{}, errors.New("the pending asset update has no valid policy id")
	}
	nm, err := hex.DecodeString(p.NameHex)
	if err != nil {
		return Change{}, errors.New("the pending asset update has no valid asset name")
	}
	d, ok := new(big.Int).SetString(p.Delta, 10)
	if !ok || !d.IsInt64() {
		return Change{}, errors.New("the pending asset update has no valid amount")
	}
	var id chain.AssetID
	copy(id.Policy[:], pol)
	id.Name = nm
	if t, err := time.Parse(time.RFC3339Nano, p.Date); err == nil {
		date = t
	}
	return Change{Asset: id, HexTyped: p.HexTyped, Delta: d.Int64(), ValidBefore: p.ValidBefore, Action: p.Action, Date: date}, nil
}
