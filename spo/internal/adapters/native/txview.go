package native

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// TxViewer implements ports.TxViewer: it decodes a Conway transaction body
// into a party.TxView for a signer to read before signing
// (SPO-Xparty-PR-002).
//
// The decoder is whole or it fails. Every key of the body map is either
// decoded into the view or the decoding stops with an error: a key it does
// not know, a certificate tag it does not know, an output form it does not
// know, an indefinite-length item, a duplicate key, text that is not clean
// UTF-8. A signer is never shown a body with a part left out. Governance
// actions are the one thing it does not take apart: a proposal is shown with
// its kind and the CBOR of the action itself.
type TxViewer struct{}

var _ ports.TxViewer = TxViewer{}

// ErrBodyView is returned for a body the viewer cannot display in full.
var ErrBodyView = errors.New("the transaction body cannot be displayed in full")

func viewErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBodyView, fmt.Sprintf(format, a...))
}

// BodyOf implements ports.TxViewer: the first element of the transaction
// array, byte for byte.
func (TxViewer) BodyOf(tx []byte) ([]byte, error) {
	it, err := parseOne(tx)
	if err != nil {
		return nil, err
	}
	if it.major != 4 || len(it.arr) != 4 || it.arr[0].major != 5 {
		return nil, viewErr("not a transaction [body, witnesses, valid, auxiliary data]")
	}
	return append([]byte(nil), it.arr[0].raw...), nil
}

// View implements ports.TxViewer.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PRE-006
func (TxViewer) View(body []byte) (party.TxView, error) {
	it, err := parseOne(body)
	if err != nil {
		return party.TxView{}, err
	}
	if it.major != 5 {
		return party.TxView{}, viewErr("the body is not a map")
	}
	var v party.TxView
	seen := map[uint64]bool{}
	have := func(k uint64) bool { return seen[k] }
	for i, kit := range it.keys {
		if kit.major != 0 {
			return party.TxView{}, viewErr("a body key is not an unsigned integer")
		}
		k, val := kit.u, it.vals[i]
		if seen[k] {
			return party.TxView{}, viewErr("body key %d appears twice", k)
		}
		seen[k] = true
		var err error
		switch k {
		case 0:
			v.Inputs, err = inputs(val)
		case 1:
			v.Outputs, err = outputs(val)
		case 2:
			v.Fee, err = uintOf(val)
		case 3:
			v.TTL, err = optUint(val)
		case 4:
			v.Certificates, err = certificates(val)
		case 5:
			v.Withdrawals, err = withdrawals(val)
		case 7:
			v.AuxDataHash, err = hash32(val)
		case 8:
			v.ValidFrom, err = optUint(val)
		case 9:
			v.Mint, err = assets(val, true)
		case 11:
			v.ScriptDataHash, err = hash32(val)
		case 13:
			v.CollateralInputs, err = inputs(val)
		case 14:
			v.RequiredSigners, err = requiredSigners(val)
		case 15:
			var n *uint64
			if n, err = optUint(val); err == nil && *n > 1 {
				err = viewErr("network id %d", *n)
			}
			if err == nil {
				id := uint8(*n)
				v.NetworkID = &id
			}
		case 16:
			var o party.ViewOutput
			if o, err = output(val); err == nil {
				v.CollateralReturn = &o
			}
		case 17:
			v.TotalCollateral, err = optUint(val)
		case 18:
			v.ReferenceInputs, err = inputs(val)
		case 19:
			v.Votes, err = votes(val)
		case 20:
			v.Proposals, err = proposals(val)
		case 21:
			v.TreasuryValue, err = optUint(val)
		case 22:
			v.Donation, err = optUint(val)
		default:
			return party.TxView{}, viewErr("the body has key %d, which this signer does not know how to display", k)
		}
		if err != nil {
			return party.TxView{}, fmt.Errorf("body key %d: %w", k, err)
		}
	}
	// A transaction needs inputs, outputs and a fee (keys 0, 1, 2).
	if !have(0) || !have(1) || !have(2) {
		return party.TxView{}, viewErr("the body has no inputs, outputs or fee")
	}
	return v, nil
}

// ---- primitives ---------------------------------------------------------

func uintOf(it cborItem) (uint64, error) {
	if it.major != 0 {
		return 0, viewErr("expected an unsigned integer")
	}
	return it.u, nil
}

func optUint(it cborItem) (*uint64, error) {
	n, err := uintOf(it)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func bytesN(it cborItem, n int) ([]byte, error) {
	if it.major != 2 || len(it.b) != n {
		return nil, viewErr("expected a %d-byte string", n)
	}
	return it.b, nil
}

func hash32(it cborItem) (*[32]byte, error) {
	b, err := bytesN(it, 32)
	if err != nil {
		return nil, err
	}
	var h [32]byte
	copy(h[:], b)
	return &h, nil
}

func hash28(it cborItem) (h [28]byte, err error) {
	b, err := bytesN(it, 28)
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}

// clean refuses text that is not valid UTF-8 or holds control or format
// characters (terminal escapes, bidirectional overrides), or the line and
// paragraph separators U+2028 and U+2029.
func clean(it cborItem) (string, error) {
	if it.major != 3 || !utf8.Valid(it.b) {
		return "", viewErr("expected UTF-8 text")
	}
	for _, r := range string(it.b) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return "", viewErr("text with a control character or a line separator")
		}
	}
	return string(it.b), nil
}

// setOf returns the elements of an array or of a tag-258 set.
func setOf(it cborItem) ([]cborItem, error) {
	if it.major == 6 && it.u == 258 && it.inner != nil {
		it = *it.inner
	}
	if it.major != 4 {
		return nil, viewErr("expected an array or a set")
	}
	// A set with a member twice is read differently by different decoders:
	// refused, tagged (258) or not.
	seen := map[string]bool{}
	for _, e := range it.arr {
		if seen[string(e.raw)] {
			return nil, viewErr("a set has a member twice")
		}
		seen[string(e.raw)] = true
	}
	return it.arr, nil
}

// addrString decodes an address and returns its text and the network id it
// carries (0 test, 1 main).
func addrString(it cborItem) (string, uint8, error) {
	if it.major != 2 {
		return "", 0, viewErr("an address is not a byte string")
	}
	a, err := common.NewAddressFromBytes(it.b)
	if err != nil {
		return "", 0, viewErr("an address does not decode: %v", err)
	}
	if a.NetworkId() > 1 {
		return "", 0, viewErr("an address with network id %d", a.NetworkId())
	}
	return a.String(), uint8(a.NetworkId()), nil
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

func credential(it cborItem) (string, error) {
	if it.major != 4 || len(it.arr) != 2 || it.arr[0].major != 0 {
		return "", viewErr("a credential is [kind, hash]")
	}
	h, err := bytesN(it.arr[1], 28)
	if err != nil {
		return "", err
	}
	switch it.arr[0].u {
	case 0:
		return "key:" + hexOf(h), nil
	case 1:
		return "script:" + hexOf(h), nil
	}
	return "", viewErr("credential kind %d", it.arr[0].u)
}

func anchor(it cborItem) (*party.ViewAnchor, error) {
	if it.isNull() {
		return nil, nil
	}
	if it.major != 4 || len(it.arr) != 2 {
		return nil, viewErr("an anchor is [url, hash]")
	}
	url, err := clean(it.arr[0])
	if err != nil {
		return nil, err
	}
	h, err := hash32(it.arr[1])
	if err != nil {
		return nil, err
	}
	return &party.ViewAnchor{URL: url, Hash: *h}, nil
}

// ---- inputs, outputs, values -------------------------------------------

func inputs(it cborItem) ([]party.ViewInput, error) {
	els, err := setOf(it)
	if err != nil {
		return nil, err
	}
	out := make([]party.ViewInput, 0, len(els))
	for _, e := range els {
		in, err := input(e)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, nil
}

func input(e cborItem) (party.ViewInput, error) {
	var in party.ViewInput
	if e.major != 4 || len(e.arr) != 2 {
		return in, viewErr("an input is [transaction id, index]")
	}
	id, err := bytesN(e.arr[0], 32)
	if err != nil {
		return in, err
	}
	ix, err := uintOf(e.arr[1])
	if err != nil || ix > math.MaxUint32 {
		return in, viewErr("an input index")
	}
	copy(in.TxID[:], id)
	in.Index = uint32(ix)
	return in, nil
}

// assets reads a multi-asset map. Quantities are positive in an output and
// non-zero integers in a mint.
func assets(it cborItem, mint bool) ([]party.ViewAsset, error) {
	if it.major != 5 {
		return nil, viewErr("a multi-asset value is a map")
	}
	var out []party.ViewAsset
	for i, pk := range it.keys {
		pol, err := hash28(pk)
		if err != nil {
			return nil, err
		}
		names := it.vals[i]
		if names.major != 5 {
			return nil, viewErr("a policy maps to a map of asset names")
		}
		for j, nk := range names.keys {
			if nk.major != 2 || len(nk.b) > 32 {
				return nil, viewErr("an asset name is at most 32 bytes")
			}
			q := names.vals[j]
			var n int64
			switch {
			case q.major == 0 && q.u <= math.MaxInt64:
				n = int64(q.u)
			case q.major == 1 && mint && q.u <= math.MaxInt64:
				n = -1 - int64(q.u)
			default:
				return nil, viewErr("an asset quantity")
			}
			if n == 0 || (!mint && n < 0) {
				return nil, viewErr("an asset quantity of %d", n)
			}
			out = append(out, party.ViewAsset{Policy: pol, Name: append([]byte(nil), nk.b...), Quantity: n})
		}
	}
	return out, nil
}

func value(it cborItem) (lovelace uint64, as []party.ViewAsset, err error) {
	if it.major == 0 {
		return it.u, nil, nil
	}
	if it.major != 4 || len(it.arr) != 2 {
		return 0, nil, viewErr("a value is a coin or [coin, assets]")
	}
	if lovelace, err = uintOf(it.arr[0]); err != nil {
		return 0, nil, err
	}
	as, err = assets(it.arr[1], false)
	return lovelace, as, err
}

func outputs(it cborItem) ([]party.ViewOutput, error) {
	if it.major != 4 {
		return nil, viewErr("the outputs are an array")
	}
	out := make([]party.ViewOutput, 0, len(it.arr))
	for _, e := range it.arr {
		o, err := output(e)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// output reads the legacy array form [address, value, datum hash?] and the
// map form {0: address, 1: value, 2: datum option, 3: script reference}.
func output(it cborItem) (party.ViewOutput, error) {
	var o party.ViewOutput
	var err error
	switch it.major {
	case 4:
		if len(it.arr) != 2 && len(it.arr) != 3 {
			return o, viewErr("an output has 2 or 3 elements")
		}
		if o.Address, o.Network, err = addrString(it.arr[0]); err != nil {
			return o, err
		}
		if o.Lovelace, o.Assets, err = value(it.arr[1]); err != nil {
			return o, err
		}
		if len(it.arr) == 3 {
			if o.DatumHash, err = hash32(it.arr[2]); err != nil {
				return o, err
			}
		}
	case 5:
		seen := map[uint64]bool{}
		for i, kit := range it.keys {
			if kit.major != 0 || seen[kit.u] {
				return o, viewErr("an output map key")
			}
			seen[kit.u] = true
			val := it.vals[i]
			switch kit.u {
			case 0:
				o.Address, o.Network, err = addrString(val)
			case 1:
				o.Lovelace, o.Assets, err = value(val)
			case 2:
				err = datumOption(val, &o)
			case 3:
				if val.major != 6 || val.u != 24 {
					err = viewErr("a script reference is tag 24")
				}
				o.ScriptRef = true
			default:
				err = viewErr("the output has key %d", kit.u)
			}
			if err != nil {
				return o, err
			}
		}
		if !seen[0] || !seen[1] {
			return o, viewErr("an output without an address or value")
		}
	default:
		return o, viewErr("an output is an array or a map")
	}
	return o, nil
}

func datumOption(it cborItem, o *party.ViewOutput) error {
	if it.major != 4 || len(it.arr) != 2 || it.arr[0].major != 0 {
		return viewErr("a datum option is [kind, datum]")
	}
	switch it.arr[0].u {
	case 0:
		h, err := hash32(it.arr[1])
		o.DatumHash = h
		return err
	case 1:
		if it.arr[1].major != 6 || it.arr[1].u != 24 {
			return viewErr("an inline datum is tag 24")
		}
		o.InlineDatum = true
		return nil
	}
	return viewErr("datum option kind %d", it.arr[0].u)
}

func withdrawals(it cborItem) ([]party.ViewWithdrawal, error) {
	if it.major != 5 {
		return nil, viewErr("withdrawals are a map")
	}
	var out []party.ViewWithdrawal
	for i, k := range it.keys {
		acct, network, err := addrString(k)
		if err != nil {
			return nil, err
		}
		n, err := uintOf(it.vals[i])
		if err != nil {
			return nil, err
		}
		out = append(out, party.ViewWithdrawal{Account: acct, Network: network, Lovelace: n})
	}
	return out, nil
}

func requiredSigners(it cborItem) ([][28]byte, error) {
	els, err := setOf(it)
	if err != nil {
		return nil, err
	}
	var out [][28]byte
	for _, e := range els {
		h, err := hash28(e)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// ---- certificates -------------------------------------------------------

func certificates(it cborItem) ([]party.ViewCert, error) {
	els, err := setOf(it)
	if err != nil {
		return nil, err
	}
	out := make([]party.ViewCert, 0, len(els))
	for _, e := range els {
		c, err := certificate(e)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func drepOf(it cborItem) (string, error) {
	if it.major != 4 || len(it.arr) == 0 || it.arr[0].major != 0 {
		return "", viewErr("a DRep is [kind, ...]")
	}
	switch it.arr[0].u {
	case 0, 1:
		c, err := credential(it)
		return c, err
	case 2:
		if len(it.arr) == 1 {
			return "always-abstain", nil
		}
	case 3:
		if len(it.arr) == 1 {
			return "always-no-confidence", nil
		}
	}
	return "", viewErr("a DRep")
}

// certificate reads the Conway certificate forms by tag. Every field is
// read; a tag or a length it does not know is an error.
func certificate(it cborItem) (party.ViewCert, error) {
	var c party.ViewCert
	if it.major != 4 || len(it.arr) == 0 || it.arr[0].major != 0 {
		return c, viewErr("a certificate is [tag, ...]")
	}
	c.Tag = uint(it.arr[0].u)
	a := it.arr
	need := func(n int) error {
		if len(a) != n {
			return viewErr("certificate tag %d has %d elements, expected %d", c.Tag, len(a), n)
		}
		return nil
	}
	var err error
	cred := func() { c.Credential, err = credential(a[1]) }
	pool := func(x cborItem) {
		if err != nil {
			return
		}
		c.Pool, err = hash28(x)
		c.HasPool = err == nil
	}
	coin := func(x cborItem) {
		if err != nil {
			return
		}
		c.Deposit, err = optUint(x)
	}
	drep := func(x cborItem) {
		if err != nil {
			return
		}
		c.DRep, err = drepOf(x)
	}
	switch c.Tag {
	case 0, 1:
		c.Kind = map[uint]string{0: party.CertStakeRegistration, 1: party.CertStakeDeregistration}[c.Tag]
		if err = need(2); err == nil {
			cred()
		}
	case 2:
		c.Kind = party.CertStakeDelegation
		if err = need(3); err == nil {
			cred()
			pool(a[2])
		}
	case 3:
		c.Kind = party.CertPoolRegistration
		if err = need(10); err == nil {
			c.PoolReg, err = poolParams(a[1:])
		}
	case 4:
		c.Kind = party.CertPoolRetirement
		if err = need(3); err == nil {
			pool(a[1])
			if err == nil {
				c.Epoch, err = optUint(a[2])
			}
		}
	case 7, 8:
		c.Kind = map[uint]string{7: party.CertStakeRegistration, 8: party.CertStakeDeregistration}[c.Tag]
		if err = need(3); err == nil {
			cred()
			coin(a[2])
		}
	case 9:
		c.Kind = party.CertVoteDelegation
		if err = need(3); err == nil {
			cred()
			drep(a[2])
		}
	case 10:
		c.Kind = party.CertStakeVoteDelegation
		if err = need(4); err == nil {
			cred()
			pool(a[2])
			drep(a[3])
		}
	case 11:
		c.Kind = party.CertStakeRegDelegation
		if err = need(4); err == nil {
			cred()
			pool(a[2])
			coin(a[3])
		}
	case 12:
		c.Kind = party.CertVoteRegDelegation
		if err = need(4); err == nil {
			cred()
			drep(a[2])
			coin(a[3])
		}
	case 13:
		c.Kind = party.CertStakeVoteRegDeleg
		if err = need(5); err == nil {
			cred()
			pool(a[2])
			drep(a[3])
			coin(a[4])
		}
	case 14:
		c.Kind = party.CertCommitteeAuthorize
		if err = need(3); err == nil {
			cred()
			if err == nil {
				c.HotCredential, err = credential(a[2])
			}
		}
	case 15:
		c.Kind = party.CertCommitteeResign
		if err = need(3); err == nil {
			cred()
			if err == nil {
				c.Anchor, err = anchor(a[2])
			}
		}
	case 16:
		c.Kind = party.CertDRepRegistration
		if err = need(4); err == nil {
			cred()
			coin(a[2])
			if err == nil {
				c.Anchor, err = anchor(a[3])
			}
		}
	case 17:
		c.Kind = party.CertDRepDeregistration
		if err = need(3); err == nil {
			cred()
			coin(a[2])
		}
	case 18:
		c.Kind = party.CertDRepUpdate
		if err = need(3); err == nil {
			cred()
			if err == nil {
				c.Anchor, err = anchor(a[2])
			}
		}
	default:
		return c, viewErr("certificate tag %d is not one this signer knows", c.Tag)
	}
	return c, err
}

// poolParams reads the nine fields of a pool registration after its tag:
// operator, VRF key hash, pledge, cost, margin, reward account, owners,
// relays, metadata.
func poolParams(a []cborItem) (*party.ViewPoolRegistration, error) {
	var p party.ViewPoolRegistration
	var err error
	if p.Operator, err = hash28(a[0]); err != nil {
		return nil, err
	}
	vrf, err := hash32(a[1])
	if err != nil {
		return nil, err
	}
	p.VRFKeyHash = *vrf
	if p.Pledge, err = uintOf(a[2]); err != nil {
		return nil, err
	}
	if p.Cost, err = uintOf(a[3]); err != nil {
		return nil, err
	}
	m := a[4]
	if m.major != 6 || m.u != 30 || m.inner == nil || m.inner.major != 4 || len(m.inner.arr) != 2 {
		return nil, viewErr("the margin is a tag-30 fraction")
	}
	if p.MarginNum, err = uintOf(m.inner.arr[0]); err != nil {
		return nil, err
	}
	if p.MarginDen, err = uintOf(m.inner.arr[1]); err != nil {
		return nil, err
	}
	if p.MarginDen == 0 || p.MarginNum > p.MarginDen {
		return nil, viewErr("the margin is not a fraction from 0 to 1")
	}
	if p.RewardAccount, p.RewardNetwork, err = addrString(a[5]); err != nil {
		return nil, err
	}
	owners, err := setOf(a[6])
	if err != nil {
		return nil, err
	}
	for _, o := range owners {
		h, err := hash28(o)
		if err != nil {
			return nil, err
		}
		p.Owners = append(p.Owners, h)
	}
	if a[7].major != 4 {
		return nil, viewErr("the relays are an array")
	}
	for _, r := range a[7].arr {
		rl, err := relay(r)
		if err != nil {
			return nil, err
		}
		p.Relays = append(p.Relays, rl)
	}
	if !a[8].isNull() {
		if a[8].major != 4 || len(a[8].arr) != 2 {
			return nil, viewErr("pool metadata is [url, hash]")
		}
		if p.MetaURL, err = clean(a[8].arr[0]); err != nil {
			return nil, err
		}
		h, err := hash32(a[8].arr[1])
		if err != nil {
			return nil, err
		}
		p.MetaHash, p.HasMeta = *h, true
	}
	return &p, nil
}

func optPort(it cborItem) (port uint16, has bool, err error) {
	if it.isNull() {
		return 0, false, nil
	}
	n, err := uintOf(it)
	if err != nil || n > math.MaxUint16 {
		return 0, false, viewErr("a relay port")
	}
	return uint16(n), true, nil
}

// relay reads a relay. cardano-cli 11.2.3.0 writes addresses as
// little-endian 32-bit words (see swapWords); they are shown in the usual
// order.
func relay(it cborItem) (party.ViewRelay, error) {
	var r party.ViewRelay
	if it.major != 4 || len(it.arr) == 0 || it.arr[0].major != 0 {
		return r, viewErr("a relay is [kind, ...]")
	}
	a := it.arr
	var err error
	switch a[0].u {
	case 0:
		if len(a) != 4 {
			return r, viewErr("an address relay has 4 elements")
		}
		r.Kind = "ipv4"
		if r.Port, r.HasPort, err = optPort(a[1]); err != nil {
			return r, err
		}
		switch {
		case !a[2].isNull() && a[3].isNull():
			b, err := bytesN(a[2], 4)
			if err != nil {
				return r, err
			}
			r.Host = fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
		case a[2].isNull() && !a[3].isNull():
			r.Kind = "ipv6"
			b, err := bytesN(a[3], 16)
			if err != nil {
				return r, err
			}
			r.Host = netip.AddrFrom16([16]byte(swapWords(b))).String()
		default:
			return r, viewErr("an address relay has exactly one of an IPv4 and an IPv6 address")
		}
	case 1:
		if len(a) != 3 {
			return r, viewErr("a name relay has 3 elements")
		}
		r.Kind = "dns"
		if r.Port, r.HasPort, err = optPort(a[1]); err != nil {
			return r, err
		}
		r.Host, err = clean(a[2])
	case 2:
		if len(a) != 2 {
			return r, viewErr("a multi-host relay has 2 elements")
		}
		r.Kind = "srv"
		r.Host, err = clean(a[1])
	default:
		return r, viewErr("relay kind %d", a[0].u)
	}
	return r, err
}

// ---- governance ---------------------------------------------------------

var voters = map[uint64]string{0: "committee-key", 1: "committee-script", 2: "drep-key", 3: "drep-script", 4: "pool"}

func votes(it cborItem) ([]party.ViewVote, error) {
	if it.major != 5 {
		return nil, viewErr("voting procedures are a map")
	}
	var out []party.ViewVote
	for i, vk := range it.keys {
		if vk.major != 4 || len(vk.arr) != 2 || vk.arr[0].major != 0 {
			return nil, viewErr("a voter is [kind, hash]")
		}
		kind, ok := voters[vk.arr[0].u]
		if !ok {
			return nil, viewErr("voter kind %d", vk.arr[0].u)
		}
		h, err := hash28(vk.arr[1])
		if err != nil {
			return nil, err
		}
		procs := it.vals[i]
		if procs.major != 5 {
			return nil, viewErr("a voter maps to a map of votes")
		}
		for j, ak := range procs.keys {
			id, err := input(ak) // a governance action id is [transaction id, index] too
			if err != nil {
				return nil, err
			}
			pr := procs.vals[j]
			if pr.major != 4 || len(pr.arr) != 2 || pr.arr[0].major != 0 || pr.arr[0].u > 2 {
				return nil, viewErr("a voting procedure is [vote, anchor]")
			}
			an, err := anchor(pr.arr[1])
			if err != nil {
				return nil, err
			}
			out = append(out, party.ViewVote{Voter: kind + ":" + hexOf(h[:]), ActionTx: id.TxID, ActionIx: id.Index,
				Vote: []string{"no", "yes", "abstain"}[pr.arr[0].u], Anchor: an})
		}
	}
	return out, nil
}

var actionKinds = []string{"parameter-change", "hard-fork", "treasury-withdrawals", "no-confidence", "update-committee", "new-constitution", "info"}

func proposals(it cborItem) ([]party.ViewProposal, error) {
	els, err := setOf(it)
	if err != nil {
		return nil, err
	}
	var out []party.ViewProposal
	for _, e := range els {
		if e.major != 4 || len(e.arr) != 4 {
			return nil, viewErr("a proposal is [deposit, reward account, action, anchor]")
		}
		var p party.ViewProposal
		if p.Deposit, err = uintOf(e.arr[0]); err != nil {
			return nil, err
		}
		if p.RewardAccount, p.RewardNetwork, err = addrString(e.arr[1]); err != nil {
			return nil, err
		}
		act := e.arr[2]
		if act.major != 4 || len(act.arr) == 0 || act.arr[0].major != 0 || act.arr[0].u >= uint64(len(actionKinds)) {
			return nil, viewErr("a governance action")
		}
		p.ActionTag, p.ActionKind, p.Action = uint(act.arr[0].u), actionKinds[act.arr[0].u], append([]byte(nil), act.raw...)
		an, err := anchor(e.arr[3])
		if err != nil || an == nil {
			return nil, viewErr("a proposal anchor")
		}
		p.Anchor = *an
		out = append(out, p)
	}
	return out, nil
}

// Witnesses returns the verification-key witnesses of a signed transaction,
// in the order it carries them. A test and a check before submission read
// them with it; nothing here signs or verifies.
func (TxViewer) Witnesses(tx []byte) ([]txbuild.Witness, error) {
	it, err := parseOne(tx)
	if err != nil {
		return nil, err
	}
	if it.major != 4 || len(it.arr) != 4 || it.arr[1].major != 5 {
		return nil, viewErr("not a transaction [body, witnesses, valid, auxiliary data]")
	}
	var out []txbuild.Witness
	set := it.arr[1]
	for i, k := range set.keys {
		if k.major != 0 || k.u != 0 {
			continue
		}
		els, err := setOf(set.vals[i])
		if err != nil {
			return nil, err
		}
		for _, e := range els {
			if e.major != 4 || len(e.arr) != 2 {
				return nil, viewErr("a vkey witness is [key, signature]")
			}
			vk, err := bytesN(e.arr[0], 32)
			if err != nil {
				return nil, err
			}
			sig, err := bytesN(e.arr[1], 64)
			if err != nil {
				return nil, err
			}
			var w txbuild.Witness
			copy(w.VKey[:], vk)
			copy(w.Signature[:], sig)
			out = append(out, w)
		}
	}
	return out, nil
}

// ---- auxiliary data -----------------------------------------------------

// AuxOf implements ports.TxViewer: the fourth element of the transaction
// array, byte for byte, or nil when it is null.
func (TxViewer) AuxOf(tx []byte) ([]byte, error) {
	it, err := parseOne(tx)
	if err != nil {
		return nil, err
	}
	if it.major != 4 || len(it.arr) != 4 || it.arr[0].major != 5 {
		return nil, viewErr("not a transaction [body, witnesses, valid, auxiliary data]")
	}
	if it.arr[3].isNull() {
		return nil, nil
	}
	return append([]byte(nil), it.arr[3].raw...), nil
}

// cip20Label is the metadata label of transaction messages (CIP-20).
const cip20Label = 674

// ViewAux implements ports.TxViewer. Only metadata is shown, in one of the
// three forms it has: the plain map of unsigned integer labels to metadata,
// the Alonzo tag 259 over a map whose only key is 0 (the metadata), and the
// Shelley-MA pair [metadata, []] with no scripts. Auxiliary data with scripts
// alongside, or in any other form, is refused.
//
// spec: SPO-Xparty-PR-002
func (TxViewer) ViewAux(aux []byte) (party.AuxView, error) {
	it, err := parseOne(aux)
	if err != nil {
		return party.AuxView{}, err
	}
	switch {
	case it.major == 6 && it.u == 259 && it.inner != nil && it.inner.major == 5 && len(it.inner.keys) == 1 &&
		it.inner.keys[0].major == 0 && it.inner.keys[0].u == 0:
		it = it.inner.vals[0]
	case it.major == 4 && len(it.arr) == 2 && it.arr[1].major == 4 && len(it.arr[1].arr) == 0:
		it = it.arr[0]
	}
	if it.major != 5 {
		return party.AuxView{}, viewErr("auxiliary data is not metadata alone")
	}
	var v party.AuxView
	for i, k := range it.keys {
		if k.major != 0 {
			return party.AuxView{}, viewErr("a metadata label is not an unsigned integer")
		}
		text, err := metadatum(it.vals[i], 0)
		if err != nil {
			return party.AuxView{}, err
		}
		l := party.AuxLabel{Label: k.u, Value: text}
		if k.u == cip20Label {
			l.Messages = cip20(it.vals[i])
		}
		v.Labels = append(v.Labels, l)
	}
	return v, nil
}

// metadatum renders one metadatum: integers, 0x-prefixed bytes, quoted text,
// [..] and {..}. Anything else (a tag, a simple value) is refused.
func metadatum(it cborItem, depth int) (string, error) {
	if depth > 8 {
		return "", viewErr("metadata nested too deeply")
	}
	switch it.major {
	case 0:
		return fmt.Sprintf("%d", it.u), nil
	case 1:
		n := new(big.Int).SetUint64(it.u)
		return "-" + n.Add(n, big.NewInt(1)).String(), nil
	case 2:
		return "0x" + hexOf(it.b), nil
	case 3:
		s, err := clean(it)
		return strconv.Quote(s), err
	case 4:
		parts := make([]string, 0, len(it.arr))
		for _, e := range it.arr {
			p, err := metadatum(e, depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, p)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case 5:
		parts := make([]string, 0, len(it.keys))
		for i, k := range it.keys {
			ks, err := metadatum(k, depth+1)
			if err != nil {
				return "", err
			}
			vs, err := metadatum(it.vals[i], depth+1)
			if err != nil {
				return "", err
			}
			parts = append(parts, ks+": "+vs)
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	}
	return "", viewErr("a metadatum of a kind the signer does not show")
}

// cip20 reads {"msg": [text, ...]} (CIP-20); nil when the value is not that.
func cip20(it cborItem) []string {
	if it.major != 5 {
		return nil
	}
	for i, k := range it.keys {
		if k.major != 3 || string(k.b) != "msg" {
			continue
		}
		list := it.vals[i]
		if list.major == 3 { // CIP-20 allows a single string
			list = cborItem{major: 4, arr: []cborItem{list}}
		}
		if list.major != 4 {
			return nil
		}
		var out []string
		for _, e := range list.arr {
			s, err := clean(e)
			if err != nil {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}
