package native

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/ledger/babbage"
	"github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Ledger implements the ledger-side ports of transaction construction on
// gouroboros and bursa: addresses, minimum output values, fees, body
// building and assembly. It holds no state.
//
// The body is encoded here, by hand, and checked against gouroboros'
// decoder on every build. gouroboros' Conway body type cannot produce what
// cardano-cli 11.2.3.0 writes: it encodes the input set without the tag 258
// unless it decoded one, and its outputs in the map form, where cardano-cli
// writes the legacy array form when there is no datum or script. The bytes
// are compared with cardano-cli's under the oracle (spo/test/parity).
type Ledger struct{}

// ErrUnsupportedAddress: the address is of a kind the pipeline does not
// use.
var ErrUnsupportedAddress = errors.New("unsupported address")

// InspectAddress implements ports.AddressInspector.
//
// spec: SPO-Caddr-PRE-001, SPO-Caddr-OUT-002
func (Ledger) InspectAddress(addr chain.Address) (ports.AddressInfo, error) {
	a, err := common.NewAddress(string(addr))
	if err != nil {
		return ports.AddressInfo{}, fmt.Errorf("%q is not a valid address: %w", string(addr), err)
	}
	info := ports.AddressInfo{NetworkID: uint8(a.NetworkId())}
	pay := func() {
		h := a.PaymentKeyHash()
		kh := txbuild.KeyHash(h)
		info.PaymentKeyHash = &kh
	}
	stake := func() {
		h := a.StakeKeyHash()
		kh := txbuild.KeyHash(h)
		info.StakeKeyHash = &kh
	}
	switch a.Type() {
	case common.AddressTypeKeyKey:
		info.Kind = ports.AddrBase
		pay()
		stake()
	case common.AddressTypeScriptKey:
		info.Kind, info.PaymentIsScript = ports.AddrBase, true
		stake()
	case common.AddressTypeKeyScript:
		info.Kind = ports.AddrBase
		pay()
	case common.AddressTypeScriptScript:
		info.Kind, info.PaymentIsScript = ports.AddrBase, true
	case common.AddressTypeKeyPointer:
		info.Kind = ports.AddrPointer
		pay()
	case common.AddressTypeScriptPointer:
		info.Kind, info.PaymentIsScript = ports.AddrPointer, true
	case common.AddressTypeKeyNone:
		info.Kind = ports.AddrEnterprise
		pay()
	case common.AddressTypeScriptNone:
		info.Kind, info.PaymentIsScript = ports.AddrEnterprise, true
	case common.AddressTypeNoneKey:
		info.Kind = ports.AddrReward
		stake()
	case common.AddressTypeNoneScript:
		info.Kind = ports.AddrReward
	case common.AddressTypeByron:
		info.Kind = ports.AddrByron
	default:
		return ports.AddressInfo{}, fmt.Errorf("%w: type %d", ErrUnsupportedAddress, a.Type())
	}
	return info, nil
}

// ---- CBOR encoding of bodies and outputs --------------------------------

func cborTag(b []byte, n uint64) []byte  { return cborHead(b, 6, n) }
func cborArray(b []byte, n int) []byte   { return cborHead(b, 4, uint64(n)) }
func cborMap(b []byte, n int) []byte     { return cborHead(b, 5, uint64(n)) }
func cborText(b []byte, s string) []byte { return append(cborHead(b, 3, uint64(len(s))), s...) }

// encodeOutput writes an output in the legacy array form
// [address, value], the form cardano-cli writes for an output without a
// datum or a script, with assets grouped per policy in ascending order.
func encodeOutput(b []byte, o txbuild.Output) ([]byte, error) {
	a, err := common.NewAddress(string(o.Address))
	if err != nil {
		return nil, fmt.Errorf("output address %q: %w", string(o.Address), err)
	}
	raw, err := a.Bytes()
	if err != nil {
		return nil, err
	}
	assets, err := txbuild.SortAssets(o.Assets)
	if err != nil {
		return nil, err
	}
	b = cborArray(b, 2)
	b = cborBytes(b, raw)
	if len(assets) == 0 {
		return cborUint(b, uint64(o.Lovelace)), nil
	}
	b = cborArray(b, 2)
	b = cborUint(b, uint64(o.Lovelace))
	var policies [][]chain.AssetAmount
	for _, as := range assets {
		if n := len(policies); n > 0 && policies[n-1][0].Asset.Policy == as.Asset.Policy {
			policies[n-1] = append(policies[n-1], as)
		} else {
			policies = append(policies, []chain.AssetAmount{as})
		}
	}
	b = cborMap(b, len(policies))
	for _, p := range policies {
		pid := p[0].Asset.Policy
		b = cborBytes(b, pid[:])
		b = cborMap(b, len(p))
		for _, as := range p {
			b = cborBytes(b, as.Asset.Name)
			b = cborUint(b, as.Quantity)
		}
	}
	return b, nil
}

// sortedSigners returns the required-signer hashes ascending and without
// duplicates: the ledger's set.
func sortedSigners(in []txbuild.KeyHash) []txbuild.KeyHash {
	out := append([]txbuild.KeyHash(nil), in...)
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	w := 0
	for i, h := range out {
		if i == 0 || h != out[w-1] {
			out[w] = h
			w++
		}
	}
	return out[:w]
}

func blake256(b []byte) [32]byte {
	var out [32]byte
	h, _ := blake2b.New256(nil)
	h.Write(b)
	copy(out[:], h.Sum(nil))
	return out
}

// BuildBody implements ports.TxBodyBuilder.
//
// The inputs go in as a tag-258 set sorted by transaction id and index, the
// outputs in the order given, the keys of the body map in ascending order,
// and every length is definite and every integer is the shortest form: what
// the ledger's canonical encoder writes. The witness set is empty, the
// validity flag true and the auxiliary data null unless there is a message.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-004, SPO-Ptx-INV-002, SPO-01sendLovelaces-OUT-006
func (Ledger) BuildBody(spec txbuild.BodySpec) (txbuild.TxBody, error) {
	if len(spec.Inputs) == 0 {
		return txbuild.TxBody{}, errors.New("a transaction needs at least one input")
	}
	ins := append([]chain.Utxo(nil), spec.Inputs...)
	sort.Slice(ins, func(i, j int) bool {
		if c := bytes.Compare(ins[i].TxID[:], ins[j].TxID[:]); c != 0 {
			return c < 0
		}
		return ins[i].Index < ins[j].Index
	})
	for _, in := range ins {
		// gouroboros reads an input index as 16 bits; a transaction has
		// nowhere near 65536 outputs to spend (maxTxSize), so this is a
		// refusal of a malformed input, not a limit anyone meets.
		if in.Index > 0xffff {
			return txbuild.TxBody{}, fmt.Errorf("input %s#%d: the output index is above 65535", in.TxID, in.Index)
		}
	}
	for i := 1; i < len(ins); i++ {
		if ins[i].TxID == ins[i-1].TxID && ins[i].Index == ins[i-1].Index {
			return txbuild.TxBody{}, fmt.Errorf("input %s#%d appears twice", ins[i].TxID, ins[i].Index)
		}
	}
	aux, err := composeAuxData(spec.MetadataFiles, spec.Message, spec.MessageEncryption)
	if err != nil {
		return txbuild.TxBody{}, err
	}
	var mint []byte
	var scripts []byte
	if len(spec.Mint) > 0 {
		if mint, err = encodeMint(spec.Mint); err != nil {
			return txbuild.TxBody{}, err
		}
		if scripts, err = mintScriptSet(spec.MintScripts); err != nil {
			return txbuild.TxBody{}, err
		}
	}
	n := 4
	if len(spec.Certificates) > 0 {
		n++
	}
	if len(spec.Withdrawals) > 0 {
		n++
	}
	if aux != nil {
		n++
	}
	if mint != nil {
		n++
	}
	var votes []byte
	if len(spec.Votes) > 0 {
		var err error
		if votes, err = encodeVotingProcedures(spec.Votes); err != nil {
			return txbuild.TxBody{}, err
		}
		n++
	}
	if len(spec.Proposals) > 0 {
		n++
	}
	signers := sortedSigners(spec.RequiredSigners)
	if len(signers) > 0 {
		n++
	}
	var body []byte
	body = cborMap(body, n)
	body = cborUint(body, 0)
	body = cborTag(body, 258)
	body = cborArray(body, len(ins))
	for _, in := range ins {
		body = cborArray(body, 2)
		body = cborBytes(body, in.TxID[:])
		body = cborUint(body, uint64(in.Index))
	}
	body = cborUint(body, 1)
	body = cborArray(body, len(spec.Outputs))
	for _, o := range spec.Outputs {
		var err error
		if body, err = encodeOutput(body, o); err != nil {
			return txbuild.TxBody{}, err
		}
	}
	body = cborUint(body, 2)
	body = cborUint(body, uint64(spec.Fee))
	body = cborUint(body, 3)
	body = cborUint(body, spec.TTL)
	if len(spec.Certificates) > 0 {
		// Key 4: the certificates as a tag-258 set in the order given, each
		// as its own bytes (cardano-cli keeps the order).
		body = cborUint(body, 4)
		body = cborTag(body, 258)
		body = cborArray(body, len(spec.Certificates))
		for _, c := range spec.Certificates {
			if len(c.CBOR) == 0 {
				return txbuild.TxBody{}, errors.New("a certificate has no encoding")
			}
			body = append(body, c.CBOR...)
		}
	}
	if len(spec.Withdrawals) > 0 {
		// Key 5: reward address bytes to lovelace, keys ascending.
		type wd struct {
			addr []byte
			amt  chain.Lovelace
		}
		ws := make([]wd, len(spec.Withdrawals))
		for i, w := range spec.Withdrawals {
			a, err := common.NewAddress(string(w.Reward))
			if err != nil {
				return txbuild.TxBody{}, fmt.Errorf("withdrawal address %q: %w", string(w.Reward), err)
			}
			if a.Type() != common.AddressTypeNoneKey && a.Type() != common.AddressTypeNoneScript {
				return txbuild.TxBody{}, fmt.Errorf("withdrawal address %q is not a reward address", string(w.Reward))
			}
			raw, err := a.Bytes()
			if err != nil {
				return txbuild.TxBody{}, err
			}
			ws[i] = wd{raw, w.Amount}
		}
		sort.Slice(ws, func(i, j int) bool { return bytes.Compare(ws[i].addr, ws[j].addr) < 0 })
		for i := 1; i < len(ws); i++ {
			if bytes.Equal(ws[i].addr, ws[i-1].addr) {
				return txbuild.TxBody{}, errors.New("a reward address is withdrawn from twice")
			}
		}
		body = cborUint(body, 5)
		body = cborMap(body, len(ws))
		for _, w := range ws {
			body = cborBytes(body, w.addr)
			body = cborUint(body, uint64(w.amt))
		}
	}
	if len(signers) > 0 {
		// Key 14: the required signers as a tag-258 set of 28-byte key hashes,
		// sorted and without duplicates (`--required-signer-hash`).
		body = cborUint(body, 14)
		body = cborTag(body, 258)
		body = cborArray(body, len(signers))
		for _, h := range signers {
			body = cborBytes(body, h[:])
		}
	}
	if mint != nil {
		// Key 9: the mint field, policy -> asset name -> signed amount. cardano-cli
		// writes it before the auxiliary data hash (key 7).
		body = cborUint(body, 9)
		body = append(body, mint...)
	}
	if aux != nil {
		h := blake256(aux)
		body = cborUint(body, 7)
		body = cborBytes(body, h[:])
	}
	if len(spec.Votes) > 0 {
		// Key 19: the voting procedures of every vote file, merged under one map.
		body = cborUint(body, 19)
		body = append(body, votes...)
	}
	if len(spec.Proposals) > 0 {
		// Key 20: the proposal procedures as a tag-258 set in the order given.
		props := make([][]byte, len(spec.Proposals))
		for i, p := range spec.Proposals {
			if len(p.CBOR) == 0 {
				return txbuild.TxBody{}, errors.New("a proposal has no encoding")
			}
			props[i] = p.CBOR
		}
		body = cborUint(body, 20)
		body = encodeProposals(body, props)
	}

	tx := cborArray(nil, 4)
	tx = append(tx, body...)
	if scripts != nil {
		// The native scripts the mint field refers to travel in the witness
		// set (key 1), as cardano-cli writes them into the body file; the
		// signers add key 0.
		tx = append(tx, 0xa1, 0x01)
		tx = append(tx, scripts...)
		tx = append(tx, 0xf5)
	} else {
		tx = append(tx, 0xa0, 0xf5) // empty witness set, valid
	}
	if aux != nil {
		tx = append(tx, aux...)
	} else {
		tx = append(tx, 0xf6)
	}

	id := blake256(body)
	// Cross-check with the library: it must read our bytes as a Conway
	// transaction with the same id.
	if libID, err := bursa.TransactionID(tx); err != nil {
		return txbuild.TxBody{}, fmt.Errorf("the built body does not decode: %w", err)
	} else if libID != hex.EncodeToString(id[:]) {
		return txbuild.TxBody{}, errors.New("the built body's id differs from the library's")
	}
	return txbuild.TxBody{CBOR: tx, ID: chain.TxID(id)}, nil
}

// ---- fees and minimum values ---------------------------------------------

// EstimateSize implements ports.FeeEstimator. The unsigned transaction
// omits its witnesses, so the size is the one with placeholder witnesses of
// the real shape (bursa.EstimateWitnessedTxSize); conway.MinFeeTx on the
// unsigned transaction would leave them out.
func (Ledger) EstimateSize(body txbuild.TxBody, witnesses uint) (int, error) {
	return bursa.EstimateWitnessedTxSize(body.CBOR, witnesses, 0)
}

// EstimateFee implements ports.FeeEstimator.
//
// spec: SPO-Ptx-EXT-002
func (l Ledger) EstimateFee(p chain.ProtocolParameters, body txbuild.TxBody, witnesses uint) (chain.Lovelace, error) {
	size, err := l.EstimateSize(body, witnesses)
	if err != nil {
		return 0, err
	}
	// The ledger leaves the one-byte is_valid flag out of the size the fee
	// is charged on (toCBORForSizeComputation); bursa's estimate counts it.
	// The oracle shows cardano-cli charging for one byte less (44 lovelace).
	size--
	fee, err := bursa.MinFee(size, bursa.ProtocolParams{TxFeePerByte: uint64(p.TxFeePerByte), TxFeeFixed: uint64(p.TxFeeFixed)})
	return chain.Lovelace(fee), err
}

// MinOutput implements ports.MinOutputCalculator: the least lovelace an
// output to this address with these assets can hold. The output is encoded
// as it will appear in the body and handed to the library's CIP-55 rule
// (coinsPerUTxOByte * (160 + size)).
//
// The size depends on how many bytes the lovelace amount takes, and the
// amount is the answer. cardano-cli's calculate-min-required-utxo therefore
// ignores the amount in the tx-out text and finds the fixed point: the
// smallest amount whose own encoding it pays for (oracle: the same value for
// 5000, 1000000 and 9000000000 lovelace). So does this function; out.Lovelace
// is not used. The map form of an output (two bytes larger) is not what the
// ledger sizes: the array form is (SPO-Cutxo-INV-007, settled by the oracle).
//
// spec: SPO-Ptx-EXT-003, SPO-Cutxo-INV-006, SPO-Cutxo-INV-007
func (Ledger) MinOutput(p chain.ProtocolParameters, out txbuild.Output) (chain.Lovelace, error) {
	params := &conway.ConwayProtocolParameters{AdaPerUtxoByte: uint64(p.CoinsPerUTxOByte)}
	probe := out
	probe.Lovelace = 0
	for i := 0; i < 4; i++ {
		enc, err := encodeOutput(nil, probe)
		if err != nil {
			return 0, err
		}
		var txo babbage.BabbageTransactionOutput
		if err := txo.UnmarshalCBOR(enc); err != nil {
			return 0, fmt.Errorf("the output does not decode: %w", err)
		}
		min, err := conway.MinCoinTxOut(&txo, params)
		if err != nil {
			return 0, err
		}
		if chain.Lovelace(min) == probe.Lovelace {
			return probe.Lovelace, nil
		}
		probe.Lovelace = chain.Lovelace(min)
	}
	return 0, errors.New("the minimum output value did not settle")
}

// Assemble implements ports.TxAssembler.
func (Ledger) Assemble(body txbuild.TxBody, ws []txbuild.Witness) (txbuild.SignedTx, error) {
	if len(ws) == 0 {
		return txbuild.SignedTx{}, errors.New("no witnesses to assemble")
	}
	// The witness set is a set: the ledger orders it by the hash of the
	// verification key (as cardano-cli writes it), not by the order the
	// signers answered in. Two witnesses are the common case here.
	ws = append([]txbuild.Witness(nil), ws...)
	sort.SliceStable(ws, func(i, j int) bool {
		a, b := txbuild.HashKey(ws[i].VKey[:]), txbuild.HashKey(ws[j].VKey[:])
		return bytes.Compare(a[:], b[:]) < 0
	})
	for i := 1; i < len(ws); i++ {
		if ws[i].VKey == ws[i-1].VKey {
			return txbuild.SignedTx{}, errors.New("two witnesses are made with the same key")
		}
	}
	vk := make([]common.VkeyWitness, len(ws))
	for i, w := range ws {
		vk[i] = common.VkeyWitness{Vkey: append([]byte(nil), w.VKey[:]...), Signature: append([]byte(nil), w.Signature[:]...)}
	}
	cbor, err := bursa.AssembleTransaction(body.CBOR, vk)
	if err != nil {
		return txbuild.SignedTx{}, err
	}
	id, err := bursa.TransactionID(cbor)
	if err != nil {
		return txbuild.SignedTx{}, err
	}
	if id != body.ID.String() {
		return txbuild.SignedTx{}, errors.New("assembly changed the transaction id")
	}
	return txbuild.SignedTx{CBOR: cbor, ID: body.ID}, nil
}

var (
	_ ports.AddressInspector    = Ledger{}
	_ ports.MinOutputCalculator = Ledger{}
	_ ports.FeeEstimator        = Ledger{}
	_ ports.TxBodyBuilder       = Ledger{}
	_ ports.TxAssembler         = Ledger{}
)

// encodeMint writes the mint field: policies ascending, asset names ascending
// within a policy, each amount a signed integer. An asset named twice is one
// entry whose amounts are added; a policy-asset whose amounts cancel is
// refused.
func encodeMint(entries []txbuild.MintEntry) ([]byte, error) {
	type key struct {
		p [28]byte
		n string
	}
	sum := map[key]int64{}
	for _, e := range entries {
		k := key{e.Asset.Policy, string(e.Asset.Name)}
		s := sum[k]
		if (e.Quantity > 0 && s > math.MaxInt64-e.Quantity) || (e.Quantity < 0 && s < math.MinInt64-e.Quantity) {
			return nil, fmt.Errorf("%w: the mint of %x.%x", txbuild.ErrOverflow, e.Asset.Policy, e.Asset.Name)
		}
		sum[k] = s + e.Quantity
	}
	var keys []key
	for k, v := range sum {
		if v == 0 {
			return nil, fmt.Errorf("the mint of %x.%x adds up to zero", k.p, k.n)
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := bytes.Compare(keys[i].p[:], keys[j].p[:]); c != 0 {
			return c < 0
		}
		return keys[i].n < keys[j].n
	})
	var policies [][]key
	for _, k := range keys {
		if n := len(policies); n > 0 && policies[n-1][0].p == k.p {
			policies[n-1] = append(policies[n-1], k)
		} else {
			policies = append(policies, []key{k})
		}
	}
	var b []byte
	b = cborMap(b, len(policies))
	for _, p := range policies {
		pid := p[0].p
		b = cborBytes(b, pid[:])
		b = cborMap(b, len(p))
		for _, k := range p {
			b = cborBytes(b, []byte(k.n))
			if q := sum[k]; q > 0 {
				b = cborUint(b, uint64(q))
			} else {
				b = cborHead(b, 1, uint64(-(q + 1)))
			}
		}
	}
	return b, nil
}
