// Package transferfile reads and appends to upstream's offlineTransfer.json
// (spec/upstream/patterns/Ptransfer.md), the carry bag between an online
// and an air-gapped machine.
//
// Read as a snapshot it serves the offline machine's UTxOs, protocol
// parameters and era (ports.UtxoReader, ports.ProtocolParametersReader).
// Written as a queue it appends the signed transaction in upstream's
// format (ports.TxQueue). The file is read strictly and the only file ever
// written is the one given.
package transferfile

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Source is the name of this provider.
const Source chain.Source = "offline transfer file"

// File is an offlineTransfer.json.
type File struct {
	// Path of the file.
	Path string
	// OfflineCLI is written to general.offlineCLI when a transaction is
	// queued (SPO-Ptransfer-OUT-011). Empty leaves the value as it is.
	OfflineCLI string
	// Now gives the time of an entry; nil means the system clock.
	Now func() time.Time

	mu sync.Mutex
}

// Errors of the transfer file.
var (
	// ErrInvalidFile: the file is missing, not JSON, empty, or has no
	// protocol parameters (SPO-Ptransfer-IN-001).
	ErrInvalidFile = errors.New("the offline transfer file is not usable; create it with `01_workOffline.sh new` on the online machine")
	// ErrAddressNotInFile: the address has no snapshot in the file
	// (SPO-Ptx-MODE-004).
	ErrAddressNotInFile = errors.New("the address is not in the offline transfer file; include it on the online machine first (`01_workOffline.sh add`)")
	// ErrReadBack: the entry read back from the file is not the one written
	// (SPO-Ptransfer-OUT-012). Upstream prints an error and exits 0.
	ErrReadBack = errors.New("the queued transaction read back from the transfer file differs from the one written")
)

// ordered is a JSON object that keeps the order of its keys, so a rewrite
// leaves every other part of the document as it was.
type ordered struct {
	keys []string
	vals map[string]json.RawMessage
}

func parseOrdered(b []byte) (*ordered, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	o := &ordered{vals: map[string]json.RawMessage{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := kt.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if _, dup := o.vals[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		o.keys = append(o.keys, k)
		o.vals[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON document")
	}
	return o, nil
}

func (o *ordered) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// marshal writes the object with two-space indentation, as jq does.
func (o *ordered) marshal() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, buf.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// load reads the file and applies SPO-Ptransfer-IN-001.
//
// spec: SPO-Ptransfer-IN-001
func (f *File) load() (*ordered, error) {
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	doc, err := parseOrdered(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	proto, err := f.protocol(doc)
	if err != nil {
		return nil, err
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(proto.vals["parameters"], &params); err != nil || len(params) == 0 {
		return nil, fmt.Errorf("%w: protocol.parameters is missing or empty", ErrInvalidFile)
	}
	return doc, nil
}

func (f *File) protocol(doc *ordered) (*ordered, error) {
	p, ok := doc.vals["protocol"]
	if !ok {
		return nil, fmt.Errorf("%w: no protocol section", ErrInvalidFile)
	}
	o, err := parseOrdered(p)
	if err != nil {
		return nil, fmt.Errorf("%w: protocol: %v", ErrInvalidFile, err)
	}
	return o, nil
}

// Source implements ports.ChainSource.
func (*File) Source() chain.Source { return Source }

// Era returns protocol.era: the era name the transactions are built for
// (SPO-Ptx-MODE-007).
func (f *File) Era(context.Context) (string, error) {
	doc, err := f.load()
	if err != nil {
		return "", err
	}
	proto, _ := f.protocol(doc)
	var era string
	if err := json.Unmarshal(proto.vals["era"], &era); err != nil || era == "" {
		return "", fmt.Errorf("%w: protocol.era is missing", ErrInvalidFile)
	}
	return era, nil
}

type uval struct{ v uint64 }

func (u *uval) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		var s string
		if json.Unmarshal(b, &s) != nil {
			return fmt.Errorf("not a whole number: %s", b)
		}
		n = json.Number(s)
	}
	v, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil {
		return fmt.Errorf("not a non-negative whole number: %s", n)
	}
	u.v = v
	return nil
}

// ProtocolParameters implements ports.ProtocolParametersReader: it reads
// protocol.parameters, which holds cardano-cli's protocol-parameters JSON
// (SPO-Ptransfer-OUT-002, SPO-Ptx-MODE-006). Epoch is not in the file and
// stays zero.
func (f *File) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	doc, err := f.load()
	if err != nil {
		return chain.ProtocolParameters{}, err
	}
	proto, _ := f.protocol(doc)
	raw := proto.vals["parameters"]
	var d struct {
		FeePerByte *uval `json:"txFeePerByte"`
		FeeFixed   *uval `json:"txFeeFixed"`
		CostPerB   *uval `json:"utxoCostPerByte"`
		KeyDeposit *uval `json:"stakeAddressDeposit"`
		PoolDep    *uval `json:"stakePoolDeposit"`
		DRepDep    *uval `json:"dRepDeposit"`
		GovDep     *uval `json:"govActionDeposit"`
		MaxTx      *uval `json:"maxTxSize"`
		MaxVal     *uval `json:"maxValueSize"`
		MinPool    *uval `json:"minPoolCost"`
		EMax       *uval `json:"poolRetireMaxEpoch"`
		Version    *struct {
			Major *uval `json:"major"`
			Minor *uval `json:"minor"`
		} `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: protocol.parameters: %v", ErrInvalidFile, err)
	}
	var miss []string
	need := func(name string, v *uval) uint64 {
		if v == nil {
			miss = append(miss, name)
			return 0
		}
		return v.v
	}
	opt := func(v *uval) uint64 {
		if v == nil {
			return 0
		}
		return v.v
	}
	out := chain.ProtocolParameters{
		TxFeePerByte:        chain.Lovelace(need("txFeePerByte", d.FeePerByte)),
		TxFeeFixed:          chain.Lovelace(need("txFeeFixed", d.FeeFixed)),
		CoinsPerUTxOByte:    chain.Lovelace(need("utxoCostPerByte", d.CostPerB)),
		MaxTxSize:           need("maxTxSize", d.MaxTx),
		StakeAddressDeposit: chain.Lovelace(opt(d.KeyDeposit)),
		StakePoolDeposit:    chain.Lovelace(opt(d.PoolDep)),
		DRepDeposit:         chain.Lovelace(opt(d.DRepDep)),
		GovActionDeposit:    chain.Lovelace(opt(d.GovDep)),
		MaxValueSize:        opt(d.MaxVal),
		MinPoolCost:         chain.Lovelace(opt(d.MinPool)),
		PoolRetireMaxEpoch:  opt(d.EMax),
		Raw:                 append(json.RawMessage(nil), raw...),
	}
	if d.Version == nil || d.Version.Major == nil {
		miss = append(miss, "protocolVersion.major")
	} else {
		out.ProtocolMajor = d.Version.Major.v
		out.ProtocolMinor = opt(d.Version.Minor)
	}
	if len(miss) > 0 {
		return chain.ProtocolParameters{}, fmt.Errorf("%w: protocol.parameters lacks %s", ErrInvalidFile, strings.Join(miss, ", "))
	}
	return out, nil
}

// Utxos implements ports.UtxoReader from address."<bech32>".utxoJSON
// (SPO-Ptransfer-OUT-005). An address that is not in the file is refused.
// The filters of Pparam are not applied here.
//
// spec: SPO-Ptx-MODE-004
func (f *File) Utxos(_ context.Context, addr chain.Address) ([]chain.Utxo, error) {
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	var addrs map[string]struct {
		UtxoJSON map[string]struct {
			Value     map[string]json.RawMessage `json:"value"`
			DatumHash *string                    `json:"datumhash"`
		} `json:"utxoJSON"`
	}
	if raw, ok := doc.vals["address"]; ok {
		if err := json.Unmarshal(raw, &addrs); err != nil {
			return nil, fmt.Errorf("%w: address: %v", ErrInvalidFile, err)
		}
	}
	entry, ok := addrs[string(addr)]
	if !ok || entry.UtxoJSON == nil {
		return nil, fmt.Errorf("%w: %s", ErrAddressNotInFile, addr)
	}
	keys := make([]string, 0, len(entry.UtxoJSON))
	for k := range entry.UtxoJSON {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]chain.Utxo, 0, len(keys))
	for _, k := range keys {
		hash, idx, ok := strings.Cut(k, "#")
		if !ok {
			return nil, fmt.Errorf("%w: UTxO key %q is not hash#index", ErrInvalidFile, k)
		}
		id, err := chain.ParseTxID(hash)
		if err != nil {
			return nil, fmt.Errorf("%w: UTxO key %q: %v", ErrInvalidFile, k, err)
		}
		n, err := strconv.ParseUint(idx, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: UTxO key %q: bad index", ErrInvalidFile, k)
		}
		u := chain.Utxo{TxID: id, Index: uint32(n), HasDatumHash: entry.UtxoJSON[k].DatumHash != nil}
		sawLovelace := false
		names := make([]string, 0, len(entry.UtxoJSON[k].Value))
		for name := range entry.UtxoJSON[k].Value {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			raw := entry.UtxoJSON[k].Value[name]
			if name == "lovelace" {
				var v uval
				if err := v.UnmarshalJSON(raw); err != nil {
					return nil, fmt.Errorf("%w: UTxO %s: lovelace: %v", ErrInvalidFile, k, err)
				}
				u.Lovelace, sawLovelace = chain.Lovelace(v.v), true
				continue
			}
			pol, err := hex.DecodeString(name)
			if err != nil || len(pol) != 28 {
				return nil, fmt.Errorf("%w: UTxO %s: %q is not a policy id", ErrInvalidFile, k, name)
			}
			var assets map[string]uval
			if err := json.Unmarshal(raw, &assets); err != nil {
				return nil, fmt.Errorf("%w: UTxO %s: policy %s: %v", ErrInvalidFile, k, name, err)
			}
			ans := make([]string, 0, len(assets))
			for an := range assets {
				ans = append(ans, an)
			}
			sort.Strings(ans)
			for _, an := range ans {
				nb, err := hex.DecodeString(an)
				if err != nil || len(nb) > 32 {
					return nil, fmt.Errorf("%w: UTxO %s: asset name %q", ErrInvalidFile, k, an)
				}
				a := chain.AssetAmount{Asset: chain.AssetID{Name: nb}, Quantity: assets[an].v}
				copy(a.Asset.Policy[:], pol)
				u.Assets = append(u.Assets, a)
			}
		}
		if !sawLovelace {
			return nil, fmt.Errorf("%w: UTxO %s has no lovelace", ErrInvalidFile, k)
		}
		out = append(out, u)
	}
	return out, nil
}

func (f *File) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// rfc5322 is `date -R`.
func rfc5322(t time.Time) string { return t.Format(time.RFC1123Z) }

// Enqueue implements ports.TxQueue: it appends the signed transaction to
// transactions[], a line to history[] and sets general.offlineCLI, writes
// the whole file atomically (a temporary file in the same directory, synced
// and renamed over the original, keeping its mode: hazard H10), reads it back
// and compares the stored transaction with the one written.
//
// spec: SPO-Ptx-MODE-010, SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-011, SPO-Ptransfer-OUT-012,
// spec: SPO-Ptransfer-INV-002
func (f *File) Enqueue(_ context.Context, q ports.QueuedTx) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return err
	}
	proto, _ := f.protocol(doc)
	var era string
	if err := json.Unmarshal(proto.vals["era"], &era); err != nil || era == "" {
		return fmt.Errorf("%w: protocol.era is missing", ErrInvalidFile)
	}

	// The signed transaction as cardano-cli writes it.
	txJSON, _ := json.Marshal(struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{"Tx ConwayEra", "Ledger Cddl Format", hex.EncodeToString(q.Tx.CBOR)})
	date := rfc5322(f.now())

	entry := &ordered{vals: map[string]json.RawMessage{}}
	put := func(k string, v any) {
		b, _ := json.Marshal(v)
		entry.set(k, b)
	}
	put("date", date)
	put("type", q.Type)
	put("era", era)
	// The type's own fields follow the era (stakeAddr, delegName, ...).
	for _, f := range q.Extra {
		put(f.Key, f.Value)
	}
	put("fromAddr", q.FromName)
	put("sendFromAddr", string(q.FromAddr))
	put("toAddr", q.ToName)
	put("sendToAddr", string(q.ToAddr))
	entry.set("txJSON", txJSON)
	entryJSON, err := entry.marshalCompact()
	if err != nil {
		return err
	}

	appendTo := func(key string, item json.RawMessage) error {
		var arr []json.RawMessage
		if raw, ok := doc.vals[key]; ok && string(bytes.TrimSpace(raw)) != "null" {
			if err := json.Unmarshal(raw, &arr); err != nil {
				return fmt.Errorf("%w: %s is not an array", ErrInvalidFile, key)
			}
		}
		arr = append(arr, item)
		b, _ := json.Marshal(arr)
		doc.set(key, b)
		return nil
	}
	if err := appendTo("transactions", entryJSON); err != nil {
		return err
	}
	hist, _ := json.Marshal(struct {
		Date   string `json:"date"`
		Action string `json:"action"`
	}{date, q.Description})
	if err := appendTo("history", hist); err != nil {
		return err
	}
	if f.OfflineCLI != "" {
		gen := &ordered{vals: map[string]json.RawMessage{}}
		if raw, ok := doc.vals["general"]; ok && string(bytes.TrimSpace(raw)) != "null" {
			if gen, err = parseOrdered(raw); err != nil {
				return fmt.Errorf("%w: general: %v", ErrInvalidFile, err)
			}
		}
		v, _ := json.Marshal(f.OfflineCLI)
		gen.set("offlineCLI", v)
		g, err := gen.marshalCompact()
		if err != nil {
			return err
		}
		doc.set("general", g)
	}
	out, err := doc.marshal()
	if err != nil {
		return err
	}
	if err := writeAtomic(f.Path, out); err != nil {
		return err
	}

	// Read back (SPO-Ptransfer-OUT-012): an error, not upstream's exit 0.
	back, err := os.ReadFile(f.Path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReadBack, err)
	}
	bd, err := parseOrdered(back)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrReadBack, err)
	}
	var txs []struct {
		TxJSON json.RawMessage `json:"txJSON"`
	}
	if err := json.Unmarshal(bd.vals["transactions"], &txs); err != nil || len(txs) == 0 {
		return ErrReadBack
	}
	if !sameJSON(txs[len(txs)-1].TxJSON, txJSON) {
		return ErrReadBack
	}
	return nil
}

func (o *ordered) marshalCompact() (json.RawMessage, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(o.vals[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

// writeAtomic replaces path with data: write and sync a temporary file in
// the same directory, give it the original's mode, rename it over the
// original and sync the directory. A crash leaves the old file or the new
// one, never a truncated one.
func writeAtomic(path string, data []byte) error {
	mode := fs.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".transfer-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

var (
	_ ports.UtxoReader               = (*File)(nil)
	_ ports.ProtocolParametersReader = (*File)(nil)
	_ ports.TxQueue                  = (*File)(nil)
	_ ports.RewardAccountReader      = (*File)(nil)
	_ ports.DRepStateReader          = (*File)(nil)
)
