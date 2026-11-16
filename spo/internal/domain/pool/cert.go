package pool

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// RelayKind is one of the three relay forms of a pool registration
// certificate.
type RelayKind string

// The relay kinds: a host with a port (IPv4 or IPv6 address, or a DNS name
// that is an A or AAAA record) and a multi-host name (a DNS SRV record).
const (
	RelayIPv4 RelayKind = "ipv4"
	RelayIPv6 RelayKind = "ipv6"
	RelayDNS  RelayKind = "dns"
	RelaySRV  RelayKind = "srv"
)

// Relay is a relay as the certificate carries it.
type Relay struct {
	Kind    RelayKind
	Host    string // the address or the name
	Port    uint16 // meaningful when HasPort
	HasPort bool   // an SRV relay has none
}

// MaxDNSName is the longest relay name the ledger accepts.
const MaxDNSName = 64

// RegistrationSpec is what a pool registration certificate says
// (spec/upstream/scripts/05a, SPO-05a-EXT-005), without its encoding.
type RegistrationSpec struct {
	Operator chain.PoolID // blake2b-224 of the cold verification key
	// VrfKeyHash is blake2b-256 of the raw VRF verification key.
	VrfKeyHash [32]byte
	Pledge     chain.Lovelace
	Cost       chain.Lovelace
	Margin     chain.Rational // reduced
	// RewardAccount is the stake key hash of the reward account; NetworkID
	// goes into its address header.
	RewardAccount stake.KeyHash
	NetworkID     uint8
	// Owners are the owner stake key hashes in descriptor order. The
	// certificate holds them as a set, ordered by hash.
	Owners   []stake.KeyHash
	Relays   []Relay
	MetaURL  string
	MetaHash [32]byte
}

// RetirementSpec is what a pool retirement certificate says.
type RetirementSpec struct {
	Pool  chain.PoolID
	Epoch uint64
}

// Certificate is a pool certificate with the bytes the ledger adapter made
// of it: CBOR as it appears in a transaction body, Envelope as cardano-cli
// writes the file. Exactly one of Registration and Retirement is set.
type Certificate struct {
	Registration *RegistrationSpec
	Retirement   *RetirementSpec
	CBOR         []byte
	Envelope     []byte
}

// Attachment is the certificate as a transaction draft attaches it. The
// deposit is the pool deposit of a first registration and zero for a
// re-registration (SPO-05c-INV-009); the certificate bytes are the same.
func (c Certificate) Attachment(deposit chain.Lovelace) stake.Certificate {
	var spec stake.Spec
	switch {
	case c.Registration != nil:
		spec = stake.Spec{Kind: stake.CertPoolRegistration, Pool: c.Registration.Operator, Deposit: deposit}
	case c.Retirement != nil:
		spec = stake.Spec{Kind: stake.CertPoolRetirement, Pool: c.Retirement.Pool, Epoch: c.Retirement.Epoch}
	}
	return stake.Certificate{Spec: spec, CBOR: c.CBOR, Envelope: c.Envelope}
}

// VrfHash is the VRF key hash the certificate carries for a raw VRF
// verification key.
func VrfHash(raw []byte) [32]byte {
	var out [32]byte
	h, _ := blake2b.New256(nil)
	h.Write(raw)
	copy(out[:], h.Sum(nil))
	return out
}

// Refusals of the descriptor's values.
var (
	// ErrBadMargin: the margin is not a decimal number from 0 to 1.
	ErrBadMargin = errors.New("the pool margin must be a decimal number from 0.00 to 1.00")
	// ErrBadRelay: a relay entry does not describe a relay.
	ErrBadRelay = errors.New("invalid pool relay")
	// ErrBadLovelace: pledge or cost is not a lovelace amount.
	ErrBadLovelace = errors.New("the amount must be a whole number of lovelace")
)

// ParseMargin reads the margin as a decimal and gives the exact reduced
// fraction the certificate carries (cardano-cli 11.2.3.0 writes 0.01 as
// 1/100 and 1.00 as 1/1). The range is 0 to 1 inclusive. Upstream evaluates
// the text with `bc`, which also accepts expressions such as `1/3`, where
// integer division makes the check pass for any fraction; a margin must be a
// plain decimal here.
//
// spec: SPO-05a-PRE-005
func ParseMargin(s string) (chain.Rational, error) {
	i := strings.IndexByte(s, '.')
	whole, frac := s, ""
	if i >= 0 {
		whole, frac = s[:i], s[i+1:]
	}
	digits := func(t string) bool {
		if t == "" {
			return false
		}
		for _, c := range t {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}
	if !digits(whole) || (i >= 0 && !digits(frac)) {
		return chain.Rational{}, fmt.Errorf("%w: %q", ErrBadMargin, s)
	}
	num, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok {
		return chain.Rational{}, fmt.Errorf("%w: %q", ErrBadMargin, s)
	}
	den := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(frac))), nil)
	if num.Cmp(den) > 0 {
		return chain.Rational{}, fmt.Errorf("%w: %q is above 1", ErrBadMargin, s)
	}
	g := new(big.Int).GCD(nil, nil, num, den)
	num.Div(num, g)
	den.Div(den, g)
	if !num.IsUint64() || !den.IsUint64() {
		return chain.Rational{}, fmt.Errorf("%w: %q has too many digits", ErrBadMargin, s)
	}
	return chain.Rational{Num: num.Uint64(), Den: den.Uint64()}, nil
}

// ParseLovelace reads a decimal amount. Upstream passes pledge and cost on
// unchecked and cardano-cli refuses what is not a number (SPO-05a-INV-002).
func ParseLovelace(s string) (chain.Lovelace, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || s == "" || s[0] == '+' {
		return 0, fmt.Errorf("%w: %q", ErrBadLovelace, s)
	}
	return chain.Lovelace(n), nil
}

// ParseRelay maps a descriptor relay (`relayType`, `relayEntry`,
// `relayPort`) to a certificate relay. The type is case-insensitive.
//
// spec: SPO-05a-EXT-001, SPO-05a-PRE-006, SPO-05a-PRE-007, SPO-05a-PRE-008
func ParseRelay(r DescriptorRelay) (Relay, error) {
	if r.Entry == "" || utf8.RuneCountInString(r.Entry) > 128 || r.Type == "" {
		return Relay{}, fmt.Errorf("%w: a relay needs a type and an entry of at most 128 characters", ErrBadRelay)
	}
	var out Relay
	needPort := true
	switch strings.ToUpper(r.Type) {
	case "IP", "IP4", "IPV4":
		out.Kind = RelayIPv4
		a, err := netip.ParseAddr(r.Entry)
		if err != nil || !a.Is4() {
			return Relay{}, fmt.Errorf("%w: %q is not an IPv4 address", ErrBadRelay, r.Entry)
		}
	case "IP6", "IPV6":
		out.Kind = RelayIPv6
		a, err := netip.ParseAddr(r.Entry)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return Relay{}, fmt.Errorf("%w: %q is not an IPv6 address", ErrBadRelay, r.Entry)
		}
	case "DNS":
		out.Kind = RelayDNS
	case "MULTISRV", "SRV":
		out.Kind, needPort = RelaySRV, false
	default:
		return Relay{}, fmt.Errorf("%w: relay type %q is not one of IP, IP4, IPV4, IP6, IPV6, DNS, SRV, MULTISRV", ErrBadRelay, r.Type)
	}
	if out.Kind == RelayDNS || out.Kind == RelaySRV {
		if len(r.Entry) > MaxDNSName {
			return Relay{}, fmt.Errorf("%w: a relay name is at most %d bytes", ErrBadRelay, MaxDNSName)
		}
	}
	out.Host = r.Entry
	if needPort {
		if r.Port == "" {
			return Relay{}, fmt.Errorf("%w: a %s relay needs a port", ErrBadRelay, r.Type)
		}
		p, err := strconv.ParseUint(r.Port, 10, 16)
		if err != nil {
			return Relay{}, fmt.Errorf("%w: the port %q is not a number from 0 to 65535", ErrBadRelay, r.Port)
		}
		out.Port, out.HasPort = uint16(p), true
	}
	return out, nil
}

// CheckRelays refuses what cardano-cli 11.2.3.0 cannot encode: an IPv4 relay
// next to an IPv6 relay. Its option parser reads `--pool-relay-ipv4 a
// --pool-relay-ipv6 b` as one relay with both addresses and then fails on the
// second port ("Please enter either an IPv4 or IPv6 address"); a relay of
// another kind between them parses. The upstream scripts hit the same
// refusal, so a descriptor that has it never produced a certificate.
//
// spec: SPO-05a-EXT-001
func CheckRelays(rs []Relay) error {
	for i := 1; i < len(rs); i++ {
		a, b := rs[i-1].Kind, rs[i].Kind
		if (a == RelayIPv4 && b == RelayIPv6) || (a == RelayIPv6 && b == RelayIPv4) {
			return fmt.Errorf("%w: relays %d and %d are an IPv4 and an IPv6 address next to each other; put a DNS relay between them or use names", ErrBadRelay, i, i+1)
		}
	}
	return nil
}
