// Package transfer is the pure model of the air-gap carry bag: the
// TransferBundle aggregate behind upstream's offlineTransfer.json
// (spec/upstream/patterns/Ptransfer.md, spec/upstream/common/Coffline.md).
//
// A bundle has a snapshot half (protocol parameters, era, the UTxO set and
// reward state of chosen addresses, DRep state) written on an online machine,
// a queue of signed transactions written on the offline machine, attached
// files, and a history. The model keeps the document's key order and every
// value it does not interpret, so a bundle that goes through the port and
// back is byte-equal to what upstream's `jq` would have written. Reading and
// writing the file, locking and atomicity are the adapter's.
//
// The bundle is confidential but holds no signing key (SPO-Ptransfer-SEC-002).
// A bundle read from a file nobody authenticated is untrusted: its attachment
// names, its queue entries' descriptive fields and its snapshot are claims,
// not facts (ADR 0005).
package transfer

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Refusals of the model. Every one is an error; none is upstream's exit 0
// after an echo (hazard H3).
var (
	// ErrNoFile: there is no transfer file (SPO-Coffline-PRE-001).
	ErrNoFile = errors.New("there is no offline transfer file; create it with `new` on the online machine")
	// ErrNotJSON: the file is not a JSON object (SPO-Coffline-PRE-002,
	// SPO-01workOffline-PRE-003). The operator removes it.
	ErrNotJSON = errors.New("the offline transfer file is not valid JSON; delete it and start over")
	// ErrEmpty: the file has no content (SPO-Coffline-PRE-003).
	ErrEmpty = errors.New("the offline transfer file is empty")
	// ErrNoParameters: protocol.parameters is missing or empty
	// (SPO-Coffline-PRE-004).
	ErrNoParameters = errors.New("the offline transfer file has no protocol parameters; create it with `new` on the online machine")
	// ErrNoFunds: a payment address with no UTxO cannot be added
	// (SPO-Ptransfer-OUT-005).
	ErrNoFunds = errors.New("the address has no UTxOs, nothing to add")
	// ErrNotRegistered: a stake address that is not registered cannot be
	// added (SPO-Ptransfer-OUT-006).
	ErrNotRegistered = errors.New("the stake address is not registered on the chain; register it first")
	// ErrAddressNotInBundle: the bundle has no snapshot of the address.
	ErrAddressNotInBundle = errors.New("the address is not in the offline transfer file; include it first on the online machine")
	// ErrUnsafeName: an attachment name could name a place outside the
	// directory it is extracted to (SPO-Ptransfer-SEC-001).
	ErrUnsafeName = errors.New("unsafe attachment name")
	// ErrNoSuchFile: no attached file of that name.
	ErrNoSuchFile = errors.New("no such attached file")
	// ErrNoSuchTransaction: the queue holds no such transaction.
	ErrNoSuchTransaction = errors.New("no such queued transaction")
)

// The transaction types a queue entry may have (SPO-Ptransfer-INV-001).
const (
	TypeTransaction            = "Transaction"
	TypeAssetMinting           = "Asset-Minting"
	TypeAssetBurning           = "Asset-Burning"
	TypeWithdrawal             = "Withdrawal"
	TypeStakeKeyRegistration   = "StakeKeyRegistration"
	TypeStakeKeyDeRegistration = "StakeKeyDeRegistration"
	TypeDelegation             = "DelegationCertRegistration"
	TypeVoteDelegation         = "VoteDelegationCertRegistration"
	TypeDRepRegistration       = "DRepIDRegistration"
	TypeDRepReRegistration     = "DRepIDReRegistration"
	TypeDRepRetirement         = "DRepIDRetirement"
	TypePoolRegistration       = "PoolRegistration"
	TypePoolReRegistration     = "PoolReRegistration"
	TypePoolRetirement         = "PoolRetirement"
)

// Executable reports whether `execute` has a branch for the type
// (SPO-01workOffline-INV-006). The committee types, which no upstream script
// can write, are not among them.
func Executable(t string) bool {
	switch t {
	case TypeTransaction, TypeAssetMinting, TypeAssetBurning, TypeWithdrawal, TypeStakeKeyRegistration,
		TypeStakeKeyDeRegistration, TypeDelegation, TypeVoteDelegation, TypeDRepRegistration,
		TypeDRepReRegistration, TypeDRepRetirement, TypePoolRegistration, TypePoolReRegistration,
		TypePoolRetirement:
		return true
	}
	return false
}

// IsPoolRegistration reports the two types that get the ticker and metadata
// checks before the confirmation (SPO-01workOffline-PRE-012).
func IsPoolRegistration(t string) bool {
	return t == TypePoolRegistration || t == TypePoolReRegistration
}

// Bundle is the aggregate.
type Bundle struct{ root *Object }

// Empty is a bundle with nothing in it: the content of a missing or blank
// file (SPO-01workOffline-IN-001).
func Empty() *Bundle { return &Bundle{root: NewObject()} }

// Parse reads a transfer file. Blank content is an empty bundle; anything
// that is not a JSON object is ErrNotJSON.
func Parse(raw []byte) (*Bundle, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Empty(), nil
	}
	o, err := ParseObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotJSON, err)
	}
	return &Bundle{root: o}, nil
}

// Marshal renders the bundle as `jq` writes it.
func (b *Bundle) Marshal() ([]byte, error) { return b.root.Indented() }

// Clone copies the bundle.
func (b *Bundle) Clone() *Bundle {
	o, _ := ParseObject(b.root.Compact())
	return &Bundle{root: o}
}

// IsEmpty reports a bundle with no keys at all.
func (b *Bundle) IsEmpty() bool { return len(b.root.keys) == 0 }

// Usable applies the checks of upstream's readOfflineFile on the content: it
// is not empty and protocol.parameters is a non-empty object. Nothing else is
// checked (SPO-Coffline-PRE-003, SPO-Coffline-PRE-004).
func (b *Bundle) Usable() error {
	if b.IsEmpty() {
		return ErrEmpty
	}
	p, err := b.root.Child("protocol")
	if err != nil {
		return ErrNoParameters
	}
	raw, ok := p.Get("parameters")
	if !ok {
		return ErrNoParameters
	}
	params, err := ParseObject(raw)
	if err != nil || len(params.keys) == 0 {
		return ErrNoParameters
	}
	return nil
}

// Context is the chain context of a snapshot: what `new` and every `add`
// write at the top of the file (SPO-Ptransfer-OUT-002 to OUT-004).
type Context struct {
	OnlineCLI  string
	OnlineNode string // "light" in light mode
	Parameters json.RawMessage
	Era        string
}

func (c Context) check() error {
	if c.Era == "" {
		return errors.New("the snapshot has no era")
	}
	if o, err := ParseObject(c.Parameters); err != nil || len(o.keys) == 0 {
		return errors.New("the snapshot's protocol parameters are not a non-empty JSON object")
	}
	return nil
}

// StartNew discards everything and writes general, protocol and a history of
// one entry (SPO-Ptransfer-OUT-001, SPO-01workOffline-OUT-004).
func (b *Bundle) StartNew(c Context, workMode, date string) error {
	if err := c.check(); err != nil {
		return err
	}
	b.root = NewObject()
	if err := b.RefreshContext(c); err != nil {
		return err
	}
	return b.AddHistory(date, "new file created - "+workMode+" mode")
}

// RefreshContext overwrites general.onlineCLI, general.onlineNODE,
// protocol.parameters and protocol.era and keeps everything else
// (SPO-Ptransfer-OUT-004, SPO-01workOffline-OUT-006).
func (b *Bundle) RefreshContext(c Context) error {
	if err := c.check(); err != nil {
		return err
	}
	gen, err := b.root.Child("general")
	if err != nil {
		return err
	}
	gen.Set("onlineCLI", Str(c.OnlineCLI))
	gen.Set("onlineNODE", Str(c.OnlineNode))
	b.root.Set("general", gen.Compact())
	proto, err := b.root.Child("protocol")
	if err != nil {
		return err
	}
	proto.Set("parameters", compactJSON(c.Parameters))
	proto.Set("era", Str(c.Era))
	b.root.Set("protocol", proto.Compact())
	return nil
}

// Protocol returns protocol.parameters and protocol.era as stored.
func (b *Bundle) Protocol() (params json.RawMessage, era string, err error) {
	p, err := b.root.Child("protocol")
	if err != nil {
		return nil, "", err
	}
	params, _ = p.Get("parameters")
	if raw, ok := p.Get("era"); ok {
		_ = json.Unmarshal(raw, &era)
	}
	return params, era, nil
}

func compactJSON(raw json.RawMessage) json.RawMessage {
	var out bytes.Buffer
	if json.Compact(&out, raw) != nil {
		return raw
	}
	return out.Bytes()
}

// AddHistory appends `{date, action}` to history.
func (b *Bundle) AddHistory(date, action string) error {
	hist, err := b.root.Array("history")
	if err != nil {
		return err
	}
	e := NewObject()
	e.Set("date", Str(date))
	e.Set("action", Str(action))
	hist = append(hist, e.Compact())
	b.root.Set("history", joinArray(hist))
	return nil
}

// addHistoryWith appends `{date, action, <key>: value}` to history, with the
// extra key/value pairs after it.
func (b *Bundle) addHistoryWith(date, action, key string, value json.RawMessage, extra ...[2]json.RawMessage) error {
	hist, err := b.root.Array("history")
	if err != nil {
		return err
	}
	e := NewObject()
	e.Set("date", Str(date))
	e.Set("action", Str(action))
	e.Set(key, value)
	for _, kv := range extra {
		var k string
		if err := json.Unmarshal(kv[0], &k); err != nil {
			return err
		}
		e.Set(k, kv[1])
	}
	hist = append(hist, e.Compact())
	b.root.Set("history", joinArray(hist))
	return nil
}

// SubmittedAssetUpdates lists the asset record updates that `execute`
// recorded in the history as submitted, as the compact JSON each holds
// (with its `txid`), oldest first.
func (b *Bundle) SubmittedAssetUpdates() ([]string, error) {
	raws, err := b.root.Array("history")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range raws {
		var e map[string]json.RawMessage
		if json.Unmarshal(r, &e) != nil {
			continue
		}
		if v, ok := e[KeyAssetSubmitted]; ok {
			out = append(out, string(compactJSON(v)))
		}
	}
	return out, nil
}

// SubmittedUpdate is a history entry of a submitted transaction that carried
// an update: the update's compact JSON and the signed transaction as `execute`
// stored it (hex; empty in a history written without it). The file is not
// authenticated: a reader derives the transaction id and the validity bound
// from CborHex and refuses an update that disagrees with it.
type SubmittedUpdate struct {
	Update   string
	CborHex  string
	Position int // 0-based position in the history
}

// SubmittedUpdates is SubmittedAssetUpdates with the signed transaction of each
// entry, oldest first.
func (b *Bundle) SubmittedUpdates() ([]SubmittedUpdate, error) {
	raws, err := b.root.Array("history")
	if err != nil {
		return nil, err
	}
	var out []SubmittedUpdate
	for i, r := range raws {
		var e map[string]json.RawMessage
		if json.Unmarshal(r, &e) != nil {
			continue
		}
		v, ok := e[KeyAssetSubmitted]
		if !ok {
			continue
		}
		u := SubmittedUpdate{Update: string(compactJSON(v)), Position: i}
		_ = json.Unmarshal(e[KeyTxCBOR], &u.CborHex)
		out = append(out, u)
	}
	return out, nil
}

// Outcome is what a provider said about a submitted transaction that carried
// an update, recorded by the machine that submitted it so the machine that
// holds the records can act on it (spoConfirmed, spoExpired).
type Outcome struct {
	TxID string `json:"txid"`
	// Expired is true for a transaction that can no longer be included (the
	// strict rule of SPO-Xconfirm-PRE-002), false for a confirmed one.
	Expired bool `json:"-"`
	// Depth is the least confirmation depth the providers stated (confirmed).
	Depth uint64 `json:"depth,omitempty"`
	// Sources are the providers that said it.
	Sources []string `json:"sources,omitempty"`
}

// RecordOutcome appends the outcome as its own history entry, after the entry
// of the submit, and says whether it did: a transaction that already has an
// outcome of that kind records nothing (the entry is not rewritten, so a
// second run changes nothing).
func (b *Bundle) RecordOutcome(o Outcome, date, action string) (bool, error) {
	have, err := b.Outcomes()
	if err != nil {
		return false, err
	}
	if prev, ok := have[o.TxID]; ok && prev.Expired == o.Expired {
		return false, nil
	}
	key := KeyConfirmed
	if o.Expired {
		key = KeyExpired
	}
	raw, err := json.Marshal(o)
	if err != nil {
		return false, err
	}
	return true, b.addHistoryWith(date, action, key, raw)
}

// Outcomes lists the recorded outcomes by transaction id. A confirmation
// wins over an expiry recorded earlier or later: confirmed is a fact about a
// block.
func (b *Bundle) Outcomes() (map[string]Outcome, error) {
	raws, err := b.root.Array("history")
	if err != nil {
		return nil, err
	}
	out := map[string]Outcome{}
	for _, r := range raws {
		var e map[string]json.RawMessage
		if json.Unmarshal(r, &e) != nil {
			continue
		}
		for key, expired := range map[string]bool{KeyConfirmed: false, KeyExpired: true} {
			v, ok := e[key]
			if !ok {
				continue
			}
			var o Outcome
			if json.Unmarshal(v, &o) != nil || o.TxID == "" {
				continue
			}
			o.Expired = expired
			if prev, have := out[o.TxID]; have && !prev.Expired {
				continue
			}
			out[o.TxID] = o
		}
	}
	return out, nil
}

func joinArray(items []json.RawMessage) json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(it)
	}
	b.WriteByte(']')
	return b.Bytes()
}

// ---- Snapshot entries ------------------------------------------------------

// AssetQuantity is an amount of one asset as the file stores it: hex policy
// id, hex asset name, quantity.
type AssetQuantity struct {
	Policy, Name string
	Quantity     uint64
}

// StoredOutput is one entry of a `utxoJSON`.
type StoredOutput struct {
	TxHash    string // 64 hex characters
	Index     uint32
	Lovelace  uint64
	Assets    []AssetQuantity
	DatumHash string // hex; empty when the output carries none
}

// Ref is `<txhash>#<index>`.
func (o StoredOutput) Ref() string { return o.TxHash + "#" + strconv.FormatUint(uint64(o.Index), 10) }

// UtxoJSON renders a `utxoJSON`: `"<hash>#<index>"` to `{address, value}`
// (`datumhash` after `value` when there is one), every number a string, the
// `lovelace` key first and then one key per policy. Entries are sorted
// ascending by transaction hash with ties in the given order, as the
// upstream query functions list them (SPO-Clight-OUT-004). Assets of one
// policy go under one key, in the order given (SPO-Cutxo-OUT-002 would
// repeat a key for a policy that comes back non-adjacently; this does not).
//
// It also returns the total lovelace and the number of distinct assets
// (SPO-01workOffline-OUT-008).
func UtxoJSON(addr string, outs []StoredOutput) (raw json.RawMessage, total uint64, assetTypes int) {
	sorted := append([]StoredOutput(nil), outs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].TxHash < sorted[j].TxHash })
	root := NewObject()
	seen := map[string]bool{}
	for _, o := range sorted {
		total += o.Lovelace
		val := NewObject()
		val.Set("lovelace", Str(strconv.FormatUint(o.Lovelace, 10)))
		pols := map[string]*Object{}
		var order []string
		for _, a := range o.Assets {
			po, ok := pols[a.Policy]
			if !ok {
				po = NewObject()
				pols[a.Policy] = po
				order = append(order, a.Policy)
			}
			po.Set(a.Name, Str(strconv.FormatUint(a.Quantity, 10)))
			if id := a.Policy + "." + a.Name; !seen[id] {
				seen[id] = true
				assetTypes++
			}
		}
		for _, p := range order {
			val.Set(p, pols[p].Compact())
		}
		e := NewObject()
		e.Set("address", Str(addr))
		e.Set("value", val.Compact())
		if o.DatumHash != "" {
			e.Set("datumhash", Str(o.DatumHash))
		}
		root.Set(o.Ref(), e.Compact())
	}
	return root.Compact(), total, assetTypes
}

// PaymentEntry is the snapshot of a payment address.
type PaymentEntry struct {
	Address, Name string
	Outputs       []StoredOutput
}

func (b *Bundle) putAddress(addr string, fields [][2]string, raws map[string]json.RawMessage) error {
	all, err := b.root.Child("address")
	if err != nil {
		return err
	}
	e, err := all.Child(addr)
	if err != nil {
		return err
	}
	for _, f := range fields {
		e.Set(f[0], raws[f[0]])
	}
	all.Set(addr, e.Compact())
	b.root.Set("address", all.Compact())
	return nil
}

// PutPayment stores or overwrites `address.<addr>` with name, totalamount,
// totalassetscnt, date, used = "no", type and utxoJSON, and appends the
// history entry (SPO-Ptransfer-OUT-005, SPO-01workOffline-OUT-009). An
// address with no UTxO is refused and nothing changes (SPO-01workOffline-INV-003).
func (b *Bundle) PutPayment(e PaymentEntry, date string) error {
	if len(e.Outputs) == 0 {
		return ErrNoFunds
	}
	utxo, total, assets := UtxoJSON(e.Address, e.Outputs)
	raws := map[string]json.RawMessage{
		"name": Str(e.Name), "totalamount": Num(total), "totalassetscnt": Num(uint64(assets)),
		"date": Str(date), "used": Str("no"), "type": Str("payment"), "utxoJSON": utxo,
	}
	if err := b.putAddress(e.Address, [][2]string{{"name"}, {"totalamount"}, {"totalassetscnt"}, {"date"}, {"used"}, {"type"}, {"utxoJSON"}}, raws); err != nil {
		return err
	}
	return b.AddHistory(date, "added utxo-info for '"+e.Name+"'")
}

// StakeEntry is the snapshot of a registered stake address. Rewards is the
// array of `stake-address-info` (see RewardsJSON); Balance the sum of its
// rewardAccountBalance.
type StakeEntry struct {
	Address, Name string
	Rewards       json.RawMessage
	Balance       uint64
}

// PutStake stores or overwrites `address.<stake>` with name, totalamount,
// date, used = "no", type and rewardsJSON, and appends the history entry
// (SPO-Ptransfer-OUT-006, SPO-01workOffline-OUT-010).
func (b *Bundle) PutStake(e StakeEntry, date string) error {
	var rows []json.RawMessage
	if err := json.Unmarshal(e.Rewards, &rows); err != nil || len(rows) == 0 {
		return ErrNotRegistered
	}
	raws := map[string]json.RawMessage{
		"name": Str(e.Name), "totalamount": Num(e.Balance), "date": Str(date), "used": Str("no"),
		"type": Str("stake"), "rewardsJSON": compactJSON(e.Rewards),
	}
	if err := b.putAddress(e.Address, [][2]string{{"name"}, {"totalamount"}, {"date"}, {"used"}, {"type"}, {"rewardsJSON"}}, raws); err != nil {
		return err
	}
	return b.AddHistory(date, "added stake address rewards-state for '"+e.Name+"'")
}

// DRepEntry is the snapshot of a DRep. Deposit is nil when the DRep is not
// registered, and State then `[]`.
type DRepEntry struct {
	ID, Name string
	Deposit  *uint64
	State    json.RawMessage
}

// PutDRep stores or overwrites `drep.<id>` with name, deposit, date and
// drepStateJSON, and appends the history entry (SPO-Ptransfer-OUT-007,
// SPO-01workOffline-OUT-011).
func (b *Bundle) PutDRep(e DRepEntry, date string) error {
	all, err := b.root.Child("drep")
	if err != nil {
		return err
	}
	d, err := all.Child(e.ID)
	if err != nil {
		return err
	}
	dep := json.RawMessage("null")
	if e.Deposit != nil {
		dep = Num(*e.Deposit)
	}
	d.Set("name", Str(e.Name))
	d.Set("deposit", dep)
	d.Set("date", Str(date))
	d.Set("drepStateJSON", compactJSON(e.State))
	all.Set(e.ID, d.Compact())
	b.root.Set("drep", all.Compact())
	return b.AddHistory(date, "added drep-id info for '"+e.Name+"'")
}

// StoredUtxos reads `address.<addr>.utxoJSON`.
func (b *Bundle) StoredUtxos(addr string) ([]StoredOutput, error) {
	all, err := b.root.Child("address")
	if err != nil {
		return nil, err
	}
	raw, ok := all.Get(addr)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAddressNotInBundle, addr)
	}
	e, err := ParseObject(raw)
	if err != nil {
		return nil, fmt.Errorf("address %s: %w", addr, err)
	}
	u, ok := e.Get("utxoJSON")
	if !ok {
		return nil, fmt.Errorf("%w: %s has no utxoJSON", ErrAddressNotInBundle, addr)
	}
	uo, err := ParseObject(u)
	if err != nil {
		return nil, fmt.Errorf("address %s: utxoJSON: %w", addr, err)
	}
	var out []StoredOutput
	for _, k := range uo.keys {
		hash, idx, ok := strings.Cut(k, "#")
		n, perr := strconv.ParseUint(idx, 10, 32)
		if !ok || perr != nil || len(hash) != 64 {
			return nil, fmt.Errorf("address %s: UTxO key %q is not hash#index", addr, k)
		}
		var item struct {
			Value     map[string]json.RawMessage `json:"value"`
			DatumHash string                     `json:"datumhash"`
		}
		if err := json.Unmarshal(uo.vals[k], &item); err != nil {
			return nil, fmt.Errorf("address %s: UTxO %s: %w", addr, k, err)
		}
		so := StoredOutput{TxHash: strings.ToLower(hash), Index: uint32(n), DatumHash: item.DatumHash}
		names := make([]string, 0, len(item.Value))
		for name := range item.Value {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			raw := item.Value[name]
			if name == "lovelace" {
				v, err := amount(raw)
				if err != nil {
					return nil, fmt.Errorf("address %s: UTxO %s: lovelace: %w", addr, k, err)
				}
				so.Lovelace = v
				continue
			}
			var as map[string]json.RawMessage
			if err := json.Unmarshal(raw, &as); err != nil {
				return nil, fmt.Errorf("address %s: UTxO %s: policy %s: %w", addr, k, name, err)
			}
			ans := make([]string, 0, len(as))
			for an := range as {
				ans = append(ans, an)
			}
			sort.Strings(ans)
			for _, an := range ans {
				q, err := amount(as[an])
				if err != nil {
					return nil, fmt.Errorf("address %s: UTxO %s: asset %s.%s: %w", addr, k, name, an, err)
				}
				so.Assets = append(so.Assets, AssetQuantity{Policy: strings.ToLower(name), Name: strings.ToLower(an), Quantity: q})
			}
		}
		out = append(out, so)
	}
	return out, nil
}

// amount reads a number or a string of digits.
func amount(raw json.RawMessage) (uint64, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		s = string(bytes.TrimSpace(raw))
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a non-negative whole number: %s", s)
	}
	return v, nil
}

// StoredRewards is what the bundle says about a stake address.
type StoredRewards struct {
	Registered bool
	Balance    uint64
}

// StoredRewardState reads `address.<stake>.rewardsJSON` as `execute` needs
// it: whether the account is registered and its reward balance.
func (b *Bundle) StoredRewardState(stake string) (StoredRewards, error) {
	all, err := b.root.Child("address")
	if err != nil {
		return StoredRewards{}, err
	}
	raw, ok := all.Get(stake)
	if !ok {
		return StoredRewards{}, fmt.Errorf("%w: %s", ErrAddressNotInBundle, stake)
	}
	var e struct {
		Rewards []map[string]json.RawMessage `json:"rewardsJSON"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || e.Rewards == nil {
		return StoredRewards{}, fmt.Errorf("%w: %s has no rewardsJSON", ErrAddressNotInBundle, stake)
	}
	if len(e.Rewards) == 0 {
		return StoredRewards{}, nil
	}
	bal, ok := e.Rewards[0]["rewardAccountBalance"]
	if !ok {
		return StoredRewards{}, fmt.Errorf("address %s: rewardsJSON has no rewardAccountBalance", stake)
	}
	v, err := amount(bal)
	if err != nil {
		return StoredRewards{}, fmt.Errorf("address %s: rewardAccountBalance: %w", stake, err)
	}
	return StoredRewards{Registered: true, Balance: v}, nil
}

// ---- Queue -----------------------------------------------------------------

// QueuedEntry is a queued signed transaction with the fields the display and
// `execute` read. Everything but CborHex is the writer's description and is
// not compared with the transaction (SPO-01workOffline-SEC-002).
type QueuedEntry struct {
	Position                                                         int // 1-based
	Type, Era, Date                                                  string
	FromName, FromAddr, ToName, ToAddr                               string
	StakeName, StakingAddr, DelegName, DRepName                      string
	PoolTicker, PoolMetaURL, PoolMetaHash, RegistrationProtectionKey string
	EnvelopeType, CborHex                                            string
	// AssetPending is the port's own `spoAssetPending` field of a queued
	// mint or burn: the compact JSON of the asset record update that waits
	// for the submission. Empty for every other entry. Upstream's readers
	// ignore a key they do not name.
	AssetPending string
}

// Port-only keys. A transaction entry or a history entry carries them next to
// upstream's fields; upstream reads its own keys by name with jq and ignores
// the rest (SPO-Ptransfer-OUT-010).
const (
	// KeyAssetPending is the queue entry's field.
	KeyAssetPending = "spoAssetPending"
	// KeyAssetSubmitted is the history entry's field, written by `execute`
	// after a submit: the update of the asset record, submitted.
	KeyAssetSubmitted = "spoAssetSubmitted"
	// KeyTxCBOR is the history entry's field that holds the signed transaction
	// (hex) next to KeyAssetSubmitted, so that a later reader can derive the
	// transaction id and the validity bound from the transaction itself.
	KeyTxCBOR = "spoTxCbor"
	// KeyConfirmed and KeyExpired are history fields of their own entry,
	// written by the online machine once a provider has said a submitted
	// transaction is in a block (with the depth and the providers) or can no
	// longer be included. The machine that holds the records applies a carried
	// update only on KeyConfirmed.
	KeyConfirmed = "spoConfirmed"
	KeyExpired   = "spoExpired"
)

// Queue lists the queued transactions in order.
func (b *Bundle) Queue() ([]QueuedEntry, error) {
	raws, err := b.root.Array("transactions")
	if err != nil {
		return nil, err
	}
	out := make([]QueuedEntry, 0, len(raws))
	for i, r := range raws {
		var loose map[string]json.RawMessage
		if err := json.Unmarshal(r, &loose); err != nil {
			return nil, fmt.Errorf("transactions[%d]: %w", i, err)
		}
		str := func(k string) string {
			var s string
			_ = json.Unmarshal(loose[k], &s)
			return s
		}
		e := QueuedEntry{Position: i + 1, Type: str("type"), Era: str("era"), Date: str("date"),
			FromName: str("fromAddr"), FromAddr: str("sendFromAddr"), ToName: str("toAddr"), ToAddr: str("sendToAddr"),
			StakeName: str("stakeAddr"), StakingAddr: str("stakingAddr"), DelegName: str("delegName"), DRepName: str("drepName"),
			PoolTicker: str("poolMetaTicker"), PoolMetaURL: str("poolMetaUrl"), PoolMetaHash: str("poolMetaHash"),
			RegistrationProtectionKey: str("regProtectionKey"), AssetPending: str(KeyAssetPending)}
		if tx, ok := loose["txJSON"]; ok {
			var env struct {
				Type    string `json:"type"`
				CborHex string `json:"cborHex"`
			}
			if json.Unmarshal(tx, &env) == nil {
				e.EnvelopeType, e.CborHex = env.Type, env.CborHex
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// TxBytes decodes the stored signed transaction. It refuses an entry whose
// txJSON is not a transaction envelope; it never decodes the transaction
// itself.
func (e QueuedEntry) TxBytes() ([]byte, error) {
	if !strings.HasPrefix(e.EnvelopeType, "Tx ") && e.EnvelopeType != "Witnessed Tx" && !strings.HasPrefix(e.EnvelopeType, "Witnessed Tx") {
		return nil, fmt.Errorf("queue entry %d: txJSON has type %q, not a transaction envelope", e.Position, e.EnvelopeType)
	}
	b, err := hex.DecodeString(e.CborHex)
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("queue entry %d: txJSON has no valid cborHex", e.Position)
	}
	return b, nil
}

// HistoryText is the history text `execute` appends after a submit
// (SPO-01workOffline-OUT-016): `tx submit <id> - <what>`.
func (e QueuedEntry) HistoryText(txid string) string {
	var what string
	switch e.Type {
	case TypeTransaction, TypeAssetMinting, TypeAssetBurning:
		what = "utxo from '" + e.FromName + "' to '" + e.ToName + "'"
	case TypeWithdrawal:
		what = "withdrawal from '" + e.StakeName + "' to '" + e.ToName + "'"
	case TypeStakeKeyRegistration, TypeStakeKeyDeRegistration:
		what = e.Type + " for '" + e.StakeName + "', payment via '" + e.FromName + "'"
	case TypeDelegation, TypeVoteDelegation:
		what = e.Type + " for '" + e.DelegName + "', payment via '" + e.FromName + "'"
	case TypeDRepRegistration, TypeDRepReRegistration, TypeDRepRetirement:
		what = e.Type + " for '" + e.DRepName + "', payment via '" + e.FromName + "'"
	case TypePoolRegistration, TypePoolReRegistration, TypePoolRetirement:
		what = e.Type + " for Pool '" + e.PoolTicker + "', payment via '" + e.FromName + "'"
	}
	return "tx submit " + txid + " - " + what
}

// UsedAfterSubmit lists the addresses `execute` marks as used after a
// submit: the ones that always are, and the ones that are only when they have
// an entry (SPO-Ptransfer-OUT-014).
func (e QueuedEntry) UsedAfterSubmit() (always, ifPresent []string) {
	always = []string{e.FromAddr}
	switch e.Type {
	case TypeTransaction, TypeAssetMinting, TypeAssetBurning:
		ifPresent = []string{e.ToAddr}
	case TypeWithdrawal:
		always = append(always, e.StakingAddr)
		ifPresent = []string{e.ToAddr}
	}
	return
}

// CompleteSubmit records a submitted queue entry: marks the addresses used,
// appends the history entry and removes the entry, which is found by its
// signed transaction and not by its position (the position shifts, and the
// file may have changed since it was read). ErrNoSuchTransaction when the
// entry is gone.
func (b *Bundle) CompleteSubmit(cborHex, txid, date string) error {
	q, err := b.Queue()
	if err != nil {
		return err
	}
	var entry *QueuedEntry
	for i := range q {
		if q[i].CborHex == cborHex {
			entry = &q[i]
			break
		}
	}
	if entry == nil {
		return ErrNoSuchTransaction
	}
	always, maybe := entry.UsedAfterSubmit()
	all, err := b.root.Child("address")
	if err != nil {
		return err
	}
	mark := func(addr string, onlyIfPresent bool) error {
		raw, ok := all.Get(addr)
		if !ok && onlyIfPresent {
			return nil
		}
		e := NewObject()
		if ok {
			var perr error
			if e, perr = ParseObject(raw); perr != nil {
				return perr
			}
		}
		e.Set("used", Str("yes"))
		all.Set(addr, e.Compact())
		return nil
	}
	for _, a := range always {
		if err := mark(a, false); err != nil {
			return err
		}
	}
	for _, a := range maybe {
		if err := mark(a, true); err != nil {
			return err
		}
	}
	b.root.Set("address", all.Compact())
	if entry.AssetPending == "" {
		if err := b.AddHistory(date, entry.HistoryText(txid)); err != nil {
			return err
		}
	} else {
		// The result of the submit travels back with the file, in the same
		// history entry as upstream's text: the offline machine applies it to
		// its asset record (assets.SettleFromBundle).
		upd, err := ParseObject([]byte(entry.AssetPending))
		if err != nil {
			return fmt.Errorf("the asset update of the queued transaction is damaged: %w", err)
		}
		upd.Set("txid", Str(txid))
		txc, _ := json.Marshal(entry.CborHex)
		if err := b.addHistoryWith(date, entry.HistoryText(txid), KeyAssetSubmitted, upd.Compact(), [2]json.RawMessage{json.RawMessage(`"` + KeyTxCBOR + `"`), txc}); err != nil {
			return err
		}
	}
	raws, _ := b.root.Array("transactions")
	raws = append(raws[:entry.Position-1], raws[entry.Position:]...)
	b.root.Set("transactions", joinArray(raws))
	return nil
}

// ---- Clearing --------------------------------------------------------------

// ClearTransactions removes the queue and records it
// (SPO-01workOffline-OUT-001).
func (b *Bundle) ClearTransactions(date string) error {
	b.root.Delete("transactions")
	return b.AddHistory(date, "cleared all transactions")
}

// ClearHistory replaces the history by one entry; the key moves to the end
// of the document, as `jq` leaves it (SPO-01workOffline-OUT-002).
func (b *Bundle) ClearHistory(date string) error {
	b.root.Delete("history")
	return b.AddHistory(date, "history cleared")
}

// ClearFiles removes the attached files and records it
// (SPO-01workOffline-OUT-003).
func (b *Bundle) ClearFiles(date string) error {
	b.root.Delete("files")
	return b.AddHistory(date, "attached files cleared")
}

// ---- Attachments -----------------------------------------------------------

// MaxNameBytes bounds an attachment name.
const MaxNameBytes = 255

// SafeName checks an attachment name and returns the plain file name to
// extract it as. The key may carry one leading `./`, which `attach ./x` of
// upstream stores; anything else with a path separator, an absolute path, `..`,
// a control character or a NUL is refused (SPO-Ptransfer-SEC-001,
// SPO-01workOffline-SEC-004). The stored key is never used as a path.
func SafeName(key string) (string, error) {
	name := strings.TrimPrefix(key, "./")
	switch {
	case name == "" || name == "." || name == "..":
		return "", fmt.Errorf("%w: %q", ErrUnsafeName, key)
	case strings.ContainsAny(name, "/\\"):
		return "", fmt.Errorf("%w: %q has a path separator", ErrUnsafeName, key)
	case len(name) > MaxNameBytes:
		return "", fmt.Errorf("%w: the name is longer than %d bytes", ErrUnsafeName, MaxNameBytes)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: %q has a control character", ErrUnsafeName, key)
		}
	}
	return name, nil
}

// Attach stores `files.<name>` with date, size (a string) and base64 and
// appends the history entry (SPO-Ptransfer-OUT-017, SPO-01workOffline-OUT-013).
// The name is checked with SafeName and stored as given, so that a bundle
// carries what upstream's `attach ./x` would have stored. Attaching the same
// name again overwrites those three fields in place.
func (b *Bundle) Attach(name string, content []byte, date string) error {
	if _, err := SafeName(name); err != nil {
		return err
	}
	files, err := b.root.Child("files")
	if err != nil {
		return err
	}
	e, err := files.Child(name)
	if err != nil {
		return err
	}
	e.Set("date", Str(date))
	e.Set("size", Str(strconv.Itoa(len(content))))
	e.Set("base64", Str(base64.StdEncoding.EncodeToString(content)))
	files.Set(name, e.Compact())
	b.root.Set("files", files.Compact())
	return b.AddHistory(date, "attached file '"+name+"'")
}

// FileInfo describes an attachment without its content.
type FileInfo struct {
	Key  string
	Date string
	Size uint64 // bytes, as stored
}

// Files lists the attachments, ascending by key.
func (b *Bundle) Files() ([]FileInfo, error) {
	files, err := b.root.Child("files")
	if err != nil {
		return nil, err
	}
	keys := files.Keys()
	sort.Strings(keys)
	out := make([]FileInfo, 0, len(keys))
	for _, k := range keys {
		var e struct{ Date, Size string }
		if err := json.Unmarshal(files.vals[k], &e); err != nil {
			return nil, fmt.Errorf("files.%s: %w", k, err)
		}
		n, _ := strconv.ParseUint(e.Size, 10, 64)
		out = append(out, FileInfo{Key: k, Date: e.Date, Size: n})
	}
	return out, nil
}

// FileContent decodes an attachment.
func (b *Bundle) FileContent(key string) ([]byte, error) {
	files, err := b.root.Child("files")
	if err != nil {
		return nil, err
	}
	raw, ok := files.Get(key)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSuchFile, key)
	}
	var e struct{ Base64 string }
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("files.%s: %w", key, err)
	}
	c, err := base64.StdEncoding.DecodeString(e.Base64)
	if err != nil {
		return nil, fmt.Errorf("files.%s: base64: %w", key, err)
	}
	return c, nil
}

// MarkExtracted records that an attachment was extracted: the history entry
// is appended and the entry removed; `files` stays, as an empty object when
// it was the last one (SPO-01workOffline-OUT-014).
func (b *Bundle) MarkExtracted(key, date string) error {
	files, err := b.root.Child("files")
	if err != nil {
		return err
	}
	if !files.Has(key) {
		return fmt.Errorf("%w: %q", ErrNoSuchFile, key)
	}
	if err := b.AddHistory(date, "extracted file '"+key+"'"); err != nil {
		return err
	}
	files.Delete(key)
	b.root.Set("files", files.Compact())
	return nil
}

// ---- The read model --------------------------------------------------------

// AddressInfo is one address of the snapshot as the display reads it
// (SPO-Coffline-IN-007).
type AddressInfo struct {
	Key, Name, Type, Date string
	TotalAmount           uint64
	TotalAssets           uint64
	Used                  bool // used == "yes"
}

// DRepInfo is one DRep of the snapshot (SPO-Coffline-IN-008).
type DRepInfo struct {
	Key, Name, Date string
	Deposit         *uint64 // nil: not registered
}

// Info is the read model of a bundle (SPO-Coffline-IN-002 to IN-011): general
// information, the addresses with their balances, the queue, the history and
// the attachments by name and size only.
type Info struct {
	// Usable is nil when upstream's readOfflineFile would accept the content.
	Usable             error
	ParametersPresent  bool
	Era                string // empty: missing
	HistoryEntries     int
	LastAction         string
	LastActionDate     string
	TokenMetaEntries   int
	OnlineCLI          string // empty: unknown
	OnlineNode         string
	OfflineCLI         string
	Addresses          []AddressInfo // ascending by key
	DReps              []DRepInfo    // ascending by key
	Files              []FileInfo    // ascending by key; no content
	Transactions       []QueuedEntry
	UnknownTransaction []int // positions of entries whose type has no branch
}

// Info reads the display model.
func (b *Bundle) Info() (Info, error) {
	in := Info{Usable: b.Usable()}
	params, era, err := b.Protocol()
	if err != nil {
		return in, err
	}
	if o, perr := ParseObject(params); perr == nil && len(o.keys) > 0 {
		in.ParametersPresent = true
	}
	in.Era = era
	hist, err := b.root.Array("history")
	if err != nil {
		return in, err
	}
	in.HistoryEntries = len(hist)
	if n := len(hist); n > 0 {
		var h struct{ Action, Date string }
		_ = json.Unmarshal(hist[n-1], &h)
		in.LastAction, in.LastActionDate = h.Action, h.Date
	}
	tm, err := b.root.Child("tokenMetaServer")
	if err != nil {
		return in, err
	}
	in.TokenMetaEntries = len(tm.keys)
	gen, err := b.root.Child("general")
	if err != nil {
		return in, err
	}
	gs := func(k string) string {
		var s string
		if raw, ok := gen.Get(k); ok {
			_ = json.Unmarshal(raw, &s)
		}
		return s
	}
	in.OnlineCLI, in.OnlineNode, in.OfflineCLI = gs("onlineCLI"), gs("onlineNODE"), gs("offlineCLI")

	addrs, err := b.root.Child("address")
	if err != nil {
		return in, err
	}
	keys := addrs.Keys()
	sort.Strings(keys)
	for _, k := range keys {
		var e struct {
			Name, Type, Date, Used string
			TotalAmount            json.RawMessage `json:"totalamount"`
			TotalAssets            json.RawMessage `json:"totalassetscnt"`
		}
		if err := json.Unmarshal(addrs.vals[k], &e); err != nil {
			return in, fmt.Errorf("address %s: %w", k, err)
		}
		ai := AddressInfo{Key: k, Name: e.Name, Type: e.Type, Date: e.Date, Used: e.Used == "yes"}
		ai.TotalAmount, _ = amount(e.TotalAmount)
		ai.TotalAssets, _ = amount(e.TotalAssets)
		in.Addresses = append(in.Addresses, ai)
	}
	dreps, err := b.root.Child("drep")
	if err != nil {
		return in, err
	}
	keys = dreps.Keys()
	sort.Strings(keys)
	for _, k := range keys {
		var e struct {
			Name, Date string
			Deposit    json.RawMessage
		}
		if err := json.Unmarshal(dreps.vals[k], &e); err != nil {
			return in, fmt.Errorf("drep %s: %w", k, err)
		}
		d := DRepInfo{Key: k, Name: e.Name, Date: e.Date}
		if v, err := amount(e.Deposit); err == nil && len(e.Deposit) > 0 && string(e.Deposit) != "null" {
			d.Deposit = &v
		}
		in.DReps = append(in.DReps, d)
	}
	if in.Files, err = b.Files(); err != nil {
		return in, err
	}
	if in.Transactions, err = b.Queue(); err != nil {
		return in, err
	}
	for _, t := range in.Transactions {
		if !Executable(t.Type) {
			in.UnknownTransaction = append(in.UnknownTransaction, t.Position)
		}
	}
	return in, nil
}
