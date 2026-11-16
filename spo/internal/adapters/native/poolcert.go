package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/blinklabs-io/bursa"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The pool certificates are encoded here by hand, as the transaction body
// is: gouroboros' PoolRegistrationCertificate does not encode until
// SetRewardAccountCredential is called, and its owner and relay fields are
// not the set and the nullable fields cardano-cli writes. The bytes are
// compared with `cardano-cli stake-pool registration-certificate` under the
// oracle (spo/test/parity/pool_oracle_test.go).
const (
	poolRegDescription    = "Stake Pool Registration Certificate"
	poolRetireDescription = "Stake Pool Retirement Certificate"
)

// ErrUnsupportedPoolCertificate: a pool certificate this adapter does not read.
var ErrUnsupportedPoolCertificate = errors.New("unsupported pool certificate")

func poolEnvelope(description string, raw []byte) []byte {
	return pool.MarshalEnvelope(pool.Envelope{Type: certEnvelopeType, Description: description, CborHex: hex.EncodeToString(raw)})
}

// normalizeOwners orders the owners by key hash and drops repeats: the
// certificate holds a set.
func normalizeOwners(in []stake.KeyHash) []stake.KeyHash {
	out := append([]stake.KeyHash(nil), in...)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	w := 0
	for i, o := range out {
		if i == 0 || o != out[w-1] {
			out[w] = o
			w++
		}
	}
	return out[:w]
}

// swapWords reverses the bytes of every 4-byte word, the order cardano-cli
// 11.2.3.0 writes relay addresses in (oracle: 203.0.113.7 is 077100cb, and
// 2001:db8::1 is b80d0120 00000000 00000000 01000000).
func swapWords(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i+4 <= len(b); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return out
}

func appendNullOrUint(b []byte, v uint64, ok bool) []byte {
	if !ok {
		return append(b, 0xf6)
	}
	return cborUint(b, v)
}

func encodeRelay(b []byte, r pool.Relay) ([]byte, error) {
	switch r.Kind {
	case pool.RelayIPv4:
		a, err := netip.ParseAddr(r.Host)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("relay %q is not an IPv4 address", r.Host)
		}
		// The ledger keeps the address as a little-endian 32-bit word.
		ip := a.As4()
		b = cborArray(b, 4)
		b = cborUint(b, 0)
		b = appendNullOrUint(b, uint64(r.Port), r.HasPort)
		b = cborBytes(b, swapWords(ip[:]))
		return append(b, 0xf6), nil
	case pool.RelayIPv6:
		a, err := netip.ParseAddr(r.Host)
		if err != nil || !a.Is6() {
			return nil, fmt.Errorf("relay %q is not an IPv6 address", r.Host)
		}
		// Four little-endian 32-bit words.
		ip := a.As16()
		b = cborArray(b, 4)
		b = cborUint(b, 0)
		b = appendNullOrUint(b, uint64(r.Port), r.HasPort)
		b = append(b, 0xf6)
		return cborBytes(b, swapWords(ip[:])), nil
	case pool.RelayDNS:
		b = cborArray(b, 3)
		b = cborUint(b, 1)
		b = appendNullOrUint(b, uint64(r.Port), r.HasPort)
		return cborText(b, r.Host), nil
	case pool.RelaySRV:
		b = cborArray(b, 2)
		b = cborUint(b, 2)
		return cborText(b, r.Host), nil
	}
	return nil, fmt.Errorf("relay kind %q", r.Kind)
}

// BuildPoolRegistration implements ports.PoolCertificateBuilder: the
// certificate of Conway type 3, as cardano-cli 11.2.3.0 writes it. The
// owners are a tag-258 set in hash order, the margin a tag-30 fraction in
// lowest terms, the reward account a 29-byte address (`e0`/`e1` and the key
// hash), the metadata a pair or null. The certificate is read back and must
// say what it was made from.
//
// spec: SPO-05a-EXT-005, SPO-05a-EXT-001, SPO-Pfiles-OUT-019
func (Ledger) BuildPoolRegistration(spec pool.RegistrationSpec) (pool.Certificate, error) {
	if spec.Margin.Den == 0 || spec.Margin.Num > spec.Margin.Den {
		return pool.Certificate{}, errors.New("the margin is not a fraction from 0 to 1")
	}
	if spec.NetworkID > 1 {
		return pool.Certificate{}, fmt.Errorf("network id %d", spec.NetworkID)
	}
	spec.Owners = normalizeOwners(spec.Owners)
	if spec.MetaURL == "" {
		spec.MetaHash = [32]byte{} // no metadata: the hash means nothing
	}
	var b []byte
	b = cborArray(b, 10)
	b = cborUint(b, 3)
	b = cborBytes(b, spec.Operator[:])
	b = cborBytes(b, spec.VrfKeyHash[:])
	b = cborUint(b, uint64(spec.Pledge))
	b = cborUint(b, uint64(spec.Cost))
	b = cborTag(b, 30)
	b = cborArray(b, 2)
	b = cborUint(b, spec.Margin.Num)
	b = cborUint(b, spec.Margin.Den)
	b = cborBytes(b, append([]byte{0xe0 | spec.NetworkID}, spec.RewardAccount[:]...))
	b = cborTag(b, 258)
	b = cborArray(b, len(spec.Owners))
	for _, o := range spec.Owners {
		b = cborBytes(b, o[:])
	}
	b = cborArray(b, len(spec.Relays))
	for _, r := range spec.Relays {
		var err error
		if b, err = encodeRelay(b, r); err != nil {
			return pool.Certificate{}, err
		}
	}
	if spec.MetaURL == "" {
		b = append(b, 0xf6)
	} else {
		b = cborArray(b, 2)
		b = cborText(b, spec.MetaURL)
		b = cborBytes(b, spec.MetaHash[:])
	}
	out := pool.Certificate{Registration: &spec, CBOR: b, Envelope: poolEnvelope(poolRegDescription, b)}
	back, err := Ledger{}.DecodePoolCertificate(out.Envelope)
	if err != nil {
		return pool.Certificate{}, fmt.Errorf("the encoded pool certificate does not read back: %w", err)
	}
	if !samePoolSpec(*back.Registration, spec) {
		return pool.Certificate{}, errors.New("the encoded pool certificate reads back as another certificate")
	}
	return out, nil
}

func samePoolSpec(a, b pool.RegistrationSpec) bool {
	if len(a.Owners) != len(b.Owners) || len(a.Relays) != len(b.Relays) {
		return false
	}
	for i := range a.Owners {
		if a.Owners[i] != b.Owners[i] {
			return false
		}
	}
	for i := range a.Relays {
		if a.Relays[i] != b.Relays[i] {
			return false
		}
	}
	return a.Operator == b.Operator && a.VrfKeyHash == b.VrfKeyHash && a.Pledge == b.Pledge && a.Cost == b.Cost &&
		a.Margin == b.Margin && a.RewardAccount == b.RewardAccount && a.NetworkID == b.NetworkID &&
		a.MetaURL == b.MetaURL && a.MetaHash == b.MetaHash
}

// BuildPoolRetirement implements ports.PoolCertificateBuilder: [4, pool
// key hash, epoch].
//
// spec: SPO-07a-EXT-001, SPO-Pfiles-OUT-020
func (Ledger) BuildPoolRetirement(spec pool.RetirementSpec) (pool.Certificate, error) {
	var b []byte
	b = cborArray(b, 3)
	b = cborUint(b, 4)
	b = cborBytes(b, spec.Pool[:])
	b = cborUint(b, spec.Epoch)
	return pool.Certificate{Retirement: &spec, CBOR: b, Envelope: poolEnvelope(poolRetireDescription, b)}, nil
}

// ---- decoding --------------------------------------------------------------

// cv is a decoded CBOR value of the shapes a pool certificate has.
type cv struct {
	kind  byte // 0 uint, 2 bytes, 3 text, 4 array, 6 tag, 7 null
	n     uint64
	b     []byte
	items []cv
}

func readCV(b []byte, depth int) (cv, []byte, error) {
	if len(b) == 0 || depth > 8 {
		return cv{}, nil, errors.New("truncated or too deep")
	}
	if b[0] == 0xf6 {
		return cv{kind: 7}, b[1:], nil
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info >= 24 && info <= 27:
		size := 1 << (info - 24)
		if len(b) < size {
			return cv{}, nil, errors.New("truncated")
		}
		for _, c := range b[:size] {
			n = n<<8 | uint64(c)
		}
		b = b[size:]
	default:
		return cv{}, nil, errors.New("indefinite or unsupported item")
	}
	switch major {
	case 0:
		return cv{kind: 0, n: n}, b, nil
	case 2, 3:
		if uint64(len(b)) < n {
			return cv{}, nil, errors.New("truncated")
		}
		return cv{kind: major, b: b[:n]}, b[n:], nil
	case 4:
		if n > 1024 {
			return cv{}, nil, errors.New("array too long")
		}
		v := cv{kind: 4}
		for i := uint64(0); i < n; i++ {
			it, rest, err := readCV(b, depth+1)
			if err != nil {
				return cv{}, nil, err
			}
			v.items, b = append(v.items, it), rest
		}
		return v, b, nil
	case 6:
		it, rest, err := readCV(b, depth+1)
		if err != nil {
			return cv{}, nil, err
		}
		return cv{kind: 6, n: n, items: []cv{it}}, rest, nil
	}
	return cv{}, nil, fmt.Errorf("unsupported CBOR major type %d", major)
}

// DecodePoolCertificate implements ports.PoolCertificateDecoder.
//
// spec: SPO-05c-PRE-006
func (Ledger) DecodePoolCertificate(envelope []byte) (pool.Certificate, error) {
	var e struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(envelope, &e); err != nil || e.CborHex == "" {
		return pool.Certificate{}, errors.New("the file is not a text envelope with a cborHex")
	}
	if e.Type != certEnvelopeType {
		return pool.Certificate{}, fmt.Errorf("%w: the envelope type is %q", ErrUnsupportedPoolCertificate, e.Type)
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil {
		return pool.Certificate{}, errors.New("the certificate cborHex is not hex")
	}
	v, rest, err := readCV(raw, 0)
	if err != nil || len(rest) != 0 || v.kind != 4 || len(v.items) == 0 || v.items[0].kind != 0 {
		return pool.Certificate{}, fmt.Errorf("%w: not a certificate", ErrUnsupportedPoolCertificate)
	}
	bad := func(what string) (pool.Certificate, error) {
		return pool.Certificate{}, fmt.Errorf("%w: %s", ErrUnsupportedPoolCertificate, what)
	}
	it := v.items
	switch it[0].n {
	case 4:
		if len(it) != 3 || it[1].kind != 2 || len(it[1].b) != 28 || it[2].kind != 0 {
			return bad("a retirement certificate has a pool key hash and an epoch")
		}
		spec := pool.RetirementSpec{Epoch: it[2].n}
		copy(spec.Pool[:], it[1].b)
		return pool.Certificate{Retirement: &spec, CBOR: raw, Envelope: append([]byte(nil), envelope...)}, nil
	case 3:
	default:
		return bad(fmt.Sprintf("certificate type %d is not a pool certificate", it[0].n))
	}
	if len(it) != 10 || it[1].kind != 2 || len(it[1].b) != 28 || it[2].kind != 2 || len(it[2].b) != 32 ||
		it[3].kind != 0 || it[4].kind != 0 || it[5].kind != 6 || it[5].n != 30 || it[6].kind != 2 || len(it[6].b) != 29 ||
		it[7].kind != 6 || it[7].n != 258 || it[8].kind != 4 {
		return bad("not a Conway pool registration certificate")
	}
	spec := pool.RegistrationSpec{Pledge: chain.Lovelace(it[3].n), Cost: chain.Lovelace(it[4].n)}
	copy(spec.Operator[:], it[1].b)
	copy(spec.VrfKeyHash[:], it[2].b)
	r := it[5].items[0]
	if r.kind != 4 || len(r.items) != 2 || r.items[0].kind != 0 || r.items[1].kind != 0 || r.items[1].n == 0 {
		return bad("the margin is not a fraction")
	}
	spec.Margin = chain.Rational{Num: r.items[0].n, Den: r.items[1].n}
	spec.NetworkID = it[6].b[0] & 0x0f
	if it[6].b[0]&0xf0 != 0xe0 {
		return bad("the reward account is not a key-hash stake address")
	}
	copy(spec.RewardAccount[:], it[6].b[1:])
	owners := it[7].items[0]
	if owners.kind != 4 {
		return bad("the owners are not a set")
	}
	for _, o := range owners.items {
		if o.kind != 2 || len(o.b) != 28 {
			return bad("an owner is not a key hash")
		}
		var k stake.KeyHash
		copy(k[:], o.b)
		spec.Owners = append(spec.Owners, k)
	}
	for _, rl := range it[8].items {
		pr, err := decodeRelay(rl)
		if err != nil {
			return bad(err.Error())
		}
		spec.Relays = append(spec.Relays, pr)
	}
	switch m := it[9]; {
	case m.kind == 7:
	case m.kind == 4 && len(m.items) == 2 && m.items[0].kind == 3 && m.items[1].kind == 2 && len(m.items[1].b) == 32:
		spec.MetaURL = string(m.items[0].b)
		copy(spec.MetaHash[:], m.items[1].b)
	default:
		return bad("the pool metadata is neither null nor a URL and hash")
	}
	return pool.Certificate{Registration: &spec, CBOR: raw, Envelope: append([]byte(nil), envelope...)}, nil
}

func decodeRelay(rl cv) (pool.Relay, error) {
	if rl.kind != 4 || len(rl.items) < 2 || rl.items[0].kind != 0 {
		return pool.Relay{}, errors.New("a relay is not an array")
	}
	it := rl.items
	port := func(p cv) (uint16, bool, error) {
		switch {
		case p.kind == 7:
			return 0, false, nil
		case p.kind == 0 && p.n <= 0xffff:
			return uint16(p.n), true, nil
		}
		return 0, false, errors.New("a relay port is not a number from 0 to 65535")
	}
	var out pool.Relay
	var err error
	switch it[0].n {
	case 0:
		if len(it) != 4 {
			return out, errors.New("an address relay has four fields")
		}
		if out.Port, out.HasPort, err = port(it[1]); err != nil {
			return out, err
		}
		switch {
		case it[2].kind == 2 && len(it[2].b) == 4 && it[3].kind == 7:
			out.Kind, out.Host = pool.RelayIPv4, netip.AddrFrom4([4]byte(swapWords(it[2].b))).String()
		case it[3].kind == 2 && len(it[3].b) == 16 && it[2].kind == 7:
			out.Kind, out.Host = pool.RelayIPv6, netip.AddrFrom16([16]byte(swapWords(it[3].b))).String()
		default:
			return out, errors.New("an address relay has one address")
		}
	case 1:
		if len(it) != 3 || it[2].kind != 3 {
			return out, errors.New("a DNS relay has a port and a name")
		}
		if out.Port, out.HasPort, err = port(it[1]); err != nil {
			return out, err
		}
		out.Kind, out.Host = pool.RelayDNS, string(it[2].b)
	case 2:
		if len(it) != 2 || it[1].kind != 3 {
			return out, errors.New("a multi-host relay has a name")
		}
		out.Kind, out.Host = pool.RelaySRV, string(it[1].b)
	default:
		return out, fmt.Errorf("relay type %d", it[0].n)
	}
	return out, nil
}

// ---- metadata hash and transaction id --------------------------------------

// MetadataHash implements ports.PoolMetadataHasher: the blake2b-256 of the
// file's bytes, after the checks `cardano-cli stake-pool metadata-hash` makes
// (a JSON object of at most 512 bytes with string `name`, `description`,
// `ticker` and `homepage`).
//
// spec: SPO-05a-EXT-004, SPO-05a-OUT-008, SPO-05c-EXT-002
func (Ledger) MetadataHash(doc []byte) ([32]byte, error) {
	if len(doc) > pool.MaxMetadataBytes {
		return [32]byte{}, fmt.Errorf("the pool metadata is %d bytes, the limit is %d", len(doc), pool.MaxMetadataBytes)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil {
		return [32]byte{}, fmt.Errorf("the pool metadata is not a JSON object: %w", err)
	}
	for _, k := range []string{"name", "description", "ticker", "homepage"} {
		var s string
		if json.Unmarshal(m[k], &s) != nil {
			return [32]byte{}, fmt.Errorf("the pool metadata has no string %q", k)
		}
	}
	return blake256(doc), nil
}

// TransactionID implements ports.TxIDCalculator.
func (Ledger) TransactionID(cbor []byte) (chain.TxID, error) {
	id, err := bursa.TransactionID(cbor)
	if err != nil {
		return chain.TxID{}, err
	}
	return chain.ParseTxID(id)
}

var (
	_ ports.PoolCertificateBuilder = Ledger{}
	_ ports.PoolCertificateDecoder = Ledger{}
	_ ports.PoolMetadataHasher     = Ledger{}
	_ ports.TxIDCalculator         = Ledger{}
)
