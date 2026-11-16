package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PoolRelay is a relay as a provider states it: the members that are not null
// and are not the port (`ipv4`, `ipv6`, `dns` or `srv`), and the port as text
// (empty when null). Koios documents one member per relay (SPO-0x-OUT-005); the
// import refuses any other number.
type PoolRelay struct {
	Members map[string]string
	Port    string
}

// PoolInfo is the registration data of a pool that the import of an existing
// pool reads (spec/upstream/scripts/0x_importHelper, SPO-0x-IN-003): the names
// are those of Koios `pool_info`, and `LastUpdate*` and `Metadata` are what the
// import adds from `pool_updates` and the published metadata document.
type PoolInfo struct {
	IDBech, IDHex string
	Status        string // registered, retiring or retired
	Pledge        string // lovelace, decimal text
	FixedCost     string // lovelace, decimal text
	Margin        string // the JSON number as the provider wrote it
	MetaURL       string
	MetaHash      string
	VRFKeyHash    string
	// OpCertCounter: Value is the counter of the last block, None that the pool
	// made no block (an explicit null), Unknown that the provider did not say.
	OpCertCounter Reading[uint64]
	Relays        []PoolRelay
	Owners        []string
	RewardAddr    string

	// LastUpdateTime (unix seconds) and LastUpdateEpoch (the active epoch) of
	// the latest pool update; HasLastUpdate says they were read.
	HasLastUpdate   bool
	LastUpdateTime  uint64
	LastUpdateEpoch uint64
	// Metadata is the published metadata document, as fetched (compacted JSON).
	Metadata json.RawMessage
}

// PoolUpdate is the latest registration update of a pool, `pool_updates`
// (SPO-0x-EXT-002).
type PoolUpdate struct {
	BlockTime   uint64
	ActiveEpoch uint64
}

// ErrBadPoolInfo: an info document that is not a JSON object of the shape
// ParsePoolInfo reads.
var ErrBadPoolInfo = errors.New("invalid pool info")

type poolInfoWire struct {
	IDBech     string          `json:"pool_id_bech32"`
	IDHex      string          `json:"pool_id_hex"`
	Status     string          `json:"pool_status"`
	Pledge     json.RawMessage `json:"pledge"`
	FixedCost  json.RawMessage `json:"fixed_cost"`
	Margin     json.RawMessage `json:"margin"`
	MetaURL    *string         `json:"meta_url"`
	MetaHash   *string         `json:"meta_hash"`
	VRF        string          `json:"vrf_key_hash"`
	Counter    json.RawMessage `json:"op_cert_counter"`
	Relays     []wireRelay     `json:"relays"`
	Owners     []string        `json:"owners"`
	RewardAddr *string         `json:"reward_addr"`
	UpdTime    json.RawMessage `json:"lastupdate_time"`
	UpdEpoch   json.RawMessage `json:"lastupdate_epoch"`
	Metadata   json.RawMessage `json:"metadata"`
}

type wireRelay map[string]json.RawMessage

func rawText(r json.RawMessage) string {
	s := string(bytes.TrimSpace(r))
	if s == "" || s == "null" {
		return ""
	}
	if s[0] == '"' {
		var v string
		if json.Unmarshal(r, &v) == nil {
			return v
		}
	}
	return s
}

func rawUint(r json.RawMessage) (uint64, bool) {
	s := strings.Trim(string(bytes.TrimSpace(r)), `"`)
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && s != "" && (len(s) == 1 || s[0] != '0')
}

// ParsePoolInfo reads an info document: the JSON object `pool_info` answers
// (an element of its array), with the members the export adds. It is strict
// about the members it reads (a number where a number belongs) and ignores the
// rest.
func ParsePoolInfo(b []byte) (PoolInfo, error) {
	if len(b) > 1<<20 {
		return PoolInfo{}, fmt.Errorf("%w: larger than 1 MiB", ErrBadPoolInfo)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var w poolInfoWire
	if err := dec.Decode(&w); err != nil {
		return PoolInfo{}, fmt.Errorf("%w: %v", ErrBadPoolInfo, err)
	}
	if dec.More() {
		return PoolInfo{}, fmt.Errorf("%w: trailing data", ErrBadPoolInfo)
	}
	return w.info()
}

func (w poolInfoWire) info() (PoolInfo, error) {
	in := PoolInfo{IDBech: w.IDBech, IDHex: w.IDHex, Status: w.Status, VRFKeyHash: w.VRF,
		Pledge: rawText(w.Pledge), FixedCost: rawText(w.FixedCost), Margin: rawText(w.Margin),
		Owners: w.Owners, Metadata: w.Metadata}
	if w.MetaURL != nil {
		in.MetaURL = *w.MetaURL
	}
	if w.MetaHash != nil {
		in.MetaHash = *w.MetaHash
	}
	if w.RewardAddr != nil {
		in.RewardAddr = *w.RewardAddr
	}
	switch s := strings.TrimSpace(string(w.Counter)); {
	case s == "":
		in.OpCertCounter = Unknown[uint64]("the info has no op_cert_counter")
	case s == "null":
		in.OpCertCounter = None[uint64]()
	default:
		n, ok := rawUint(w.Counter)
		if !ok {
			return PoolInfo{}, fmt.Errorf("%w: op_cert_counter is not a number", ErrBadPoolInfo)
		}
		in.OpCertCounter = Value(n)
	}
	for _, r := range w.Relays {
		pr := PoolRelay{Members: map[string]string{}}
		for k, v := range r {
			s := strings.TrimSpace(string(v))
			switch {
			case s == "null":
			case k == "port":
				pr.Port = rawText(v)
			default:
				pr.Members[k] = rawText(v)
			}
		}
		in.Relays = append(in.Relays, pr)
	}
	if t, ok := rawUint(w.UpdTime); ok {
		if e, ok := rawUint(w.UpdEpoch); ok {
			in.HasLastUpdate, in.LastUpdateTime, in.LastUpdateEpoch = true, t, e
		}
	}
	return in, nil
}

// JSON renders the info as the export file: Koios's member names, the members
// the import reads, and the added `lastupdate_time`, `lastupdate_epoch` and
// `metadata` when they are known. All of it is public chain data.
//
// spec: SPO-0x-OUT-001
func (in PoolInfo) JSON() []byte {
	obj := map[string]any{
		"pool_id_bech32": in.IDBech, "pool_id_hex": in.IDHex, "pool_status": in.Status,
		"pledge": in.Pledge, "fixed_cost": in.FixedCost, "vrf_key_hash": in.VRFKeyHash,
		"meta_url": in.MetaURL, "owners": in.Owners,
	}
	obj["margin"] = json.RawMessage(in.Margin)
	if in.Margin == "" {
		obj["margin"] = nil
	}
	if in.MetaHash != "" {
		obj["meta_hash"] = in.MetaHash
	}
	if in.RewardAddr != "" {
		obj["reward_addr"] = in.RewardAddr
	}
	if n, ok := in.OpCertCounter.Get(); ok {
		obj["op_cert_counter"] = n
	} else if in.OpCertCounter.IsNone() {
		obj["op_cert_counter"] = nil
	}
	relays := []map[string]any{}
	for _, r := range in.Relays {
		m := map[string]any{"port": nil}
		for _, k := range []string{"ipv4", "ipv6", "dns", "srv"} {
			m[k] = nil
		}
		keys := make([]string, 0, len(r.Members))
		for k := range r.Members {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			m[k] = r.Members[k]
		}
		if r.Port != "" {
			if n, err := strconv.ParseUint(r.Port, 10, 64); err == nil {
				m["port"] = n
			} else {
				m["port"] = r.Port
			}
		}
		relays = append(relays, m)
	}
	obj["relays"] = relays
	if in.HasLastUpdate {
		obj["lastupdate_time"] = in.LastUpdateTime
		obj["lastupdate_epoch"] = in.LastUpdateEpoch
	}
	if len(in.Metadata) > 0 {
		obj["metadata"] = in.Metadata
	}
	b, _ := json.MarshalIndent(obj, "", "  ")
	return append(b, '\n')
}
