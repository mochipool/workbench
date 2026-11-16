// Package stake is the stake-delegation bounded context (spec/domain/
// domain-model.md): a stake credential, the certificates that register it,
// delegate its stake and its votes, and retire it, and the account state
// those certificates move through.
//
//	Unregistered -> Registered(deposit) -> Delegated(pool?, drep?) -> Deregistered(refund)
//
// The package is pure. A certificate's CBOR and its cardano-cli text
// envelope are opaque bytes produced by the ledger adapter
// (ports.CertificateBuilder); nothing here encodes or decodes them.
package stake

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// KeyHash is the blake2b-224 hash of a stake verification key: the stake
// credential of a reward address.
type KeyHash [28]byte

// CertKind is what a certificate does.
type CertKind string

// The four certificates this context issues, all in the Conway forms:
// registration and deregistration carry the deposit (certificate types 7
// and 8), a delegation names a pool (type 2), a vote delegation a DRep
// (type 9).
const (
	CertRegistration   CertKind = "registration"
	CertDeregistration CertKind = "deregistration"
	CertPoolDelegation CertKind = "pool-delegation"
	CertVoteDelegation CertKind = "vote-delegation"
)

// The pool certificates (spec/upstream/scripts/05a, 07a). Their fields live
// in domain/pool; here a certificate is only what a transaction attaches:
// the operator in Pool, the deposit it pays (zero for a re-registration) and,
// for a retirement, the epoch.
const (
	CertPoolRegistration CertKind = "pool-registration"
	CertPoolRetirement   CertKind = "pool-retirement"
)

// DRepKind is the target of a vote delegation.
type DRepKind string

// DRep targets.
const (
	DRepKey          DRepKind = "key"
	DRepScript       DRepKind = "script"
	DRepAbstain      DRepKind = "always-abstain"
	DRepNoConfidence DRepKind = "always-no-confidence"
)

// DRep is a vote-delegation target: a DRep credential, or one of the two
// predefined DReps.
type DRep struct {
	Kind DRepKind
	Hash [28]byte // set for DRepKey and DRepScript
}

// ChainID is the DRep as the chain names it; the predefined DReps have no
// registration and no id.
func (d DRep) ChainID() (chain.DRepID, bool) {
	switch d.Kind {
	case DRepKey:
		return chain.DRepID{Hash: d.Hash}, true
	case DRepScript:
		return chain.DRepID{Script: true, Hash: d.Hash}, true
	}
	return chain.DRepID{}, false
}

// Predefined reports always-abstain and always-no-confidence.
func (d DRep) Predefined() bool { return d.Kind == DRepAbstain || d.Kind == DRepNoConfidence }

func (d DRep) String() string {
	switch d.Kind {
	case DRepKey, DRepScript:
		return fmt.Sprintf("%s %x", d.Kind, d.Hash[:])
	}
	return string(d.Kind)
}

// Spec is what a certificate says, without its encoding.
type Spec struct {
	Kind  CertKind
	Stake KeyHash
	// Deposit is the key deposit a registration pays and the amount a
	// deregistration refunds. It is zero for the delegations.
	Deposit chain.Lovelace
	Pool    chain.PoolID // CertPoolDelegation, CertPoolRegistration, CertPoolRetirement
	DRep    DRep         // CertVoteDelegation
	Epoch   uint64       // CertPoolRetirement
}

// ErrBadSpec: a certificate spec that does not describe a certificate.
var ErrBadSpec = errors.New("invalid certificate")

// Validate refuses a spec that the ledger would not accept as a
// certificate. A deregistration or registration with no deposit is a
// pre-Conway certificate and is not issued.
func (s Spec) Validate() error {
	switch s.Kind {
	case CertRegistration, CertDeregistration:
		if s.Deposit == 0 {
			return fmt.Errorf("%w: a %s certificate carries the key deposit, which is zero", ErrBadSpec, s.Kind)
		}
	case CertPoolDelegation:
		if s.Deposit != 0 {
			return fmt.Errorf("%w: a delegation carries no deposit", ErrBadSpec)
		}
	case CertVoteDelegation:
		if s.Deposit != 0 {
			return fmt.Errorf("%w: a vote delegation carries no deposit", ErrBadSpec)
		}
		switch s.DRep.Kind {
		case DRepKey, DRepScript, DRepAbstain, DRepNoConfidence:
		default:
			return fmt.Errorf("%w: vote delegation target %q", ErrBadSpec, s.DRep.Kind)
		}
	case CertPoolRegistration:
		// The deposit is the pool deposit of a first registration, zero
		// for a re-registration (SPO-05c-INV-009).
	case CertPoolRetirement:
		if s.Deposit != 0 {
			return fmt.Errorf("%w: a retirement carries no deposit", ErrBadSpec)
		}
	default:
		return fmt.Errorf("%w: kind %q", ErrBadSpec, s.Kind)
	}
	return nil
}

// Certificate is a certificate with the bytes the ledger adapter made of
// it. CBOR is the certificate as it appears in a transaction body;
// Envelope is the cardano-cli text envelope file, byte for byte.
type Certificate struct {
	Spec
	CBOR     []byte
	Envelope []byte
}

// Feature is the transaction feature the certificate adds, which a signer
// has to understand to witness the body.
func (c Spec) Feature() custody.Feature {
	switch c.Kind {
	case CertRegistration:
		return custody.FeatStakeRegistration
	case CertDeregistration:
		return custody.FeatStakeDeregistration
	case CertPoolDelegation:
		return custody.FeatStakeDelegation
	case CertPoolRegistration:
		return custody.FeatPoolRegistrationOper
	case CertPoolRetirement:
		return custody.FeatPoolRetirement
	default:
		return custody.FeatVoteDelegation
	}
}

// Features lists every feature the certificate adds. A pool registration is
// witnessed by the operator (cold key) and by every owner, and a device
// signs those two roles in different modes, so the draft reports both.
func (c Spec) Features() []custody.Feature {
	if c.Kind == CertPoolRegistration {
		return []custody.Feature{custody.FeatPoolRegistrationOper, custody.FeatPoolRegistrationOwner}
	}
	return []custody.Feature{c.Feature()}
}

// IsPool reports a pool certificate: its witnesses are the pool's cold key
// and owners, not a stake credential of its own.
func (c Spec) IsPool() bool { return c.Kind == CertPoolRegistration || c.Kind == CertPoolRetirement }

// Paid is the deposit a transaction with this certificate pays.
func (c Spec) Paid() chain.Lovelace {
	if c.Kind == CertRegistration || c.Kind == CertPoolRegistration {
		return c.Deposit
	}
	return 0
}

// Refunded is the deposit a transaction with this certificate gets back.
func (c Spec) Refunded() chain.Lovelace {
	if c.Kind == CertDeregistration {
		return c.Deposit
	}
	return 0
}

// StakeWitnesses is the witness count of a transaction that pays with one
// payment key and proves one stake key (SPO-Ptx-INV-006: 03b, 06, 08b,
// 22b and 01_claimRewards). The ledger requires the stake credential's
// witness for the Conway registration and deregistration, both delegations
// and a withdrawal.
const StakeWitnesses uint = 2

// ---- words ---------------------------------------------------------------

func isHex56(s string) bool {
	if len(s) != 56 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func decodeHex28(s string) (h [28]byte) {
	for i := 0; i < 28; i++ {
		h[i] = hexVal(s[2*i])<<4 | hexVal(s[2*i+1])
	}
	return
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// PoolWord is a classified pool argument of 05b.
type PoolWord struct {
	// Pool is set when the word is a pool id.
	Pool chain.PoolID
	IsID bool
	// Name is the local pool whose `<name>.node.vkey` names the pool when
	// the word is not an id.
	Name string
}

// ParsePoolWord classifies the pool word as 05b does, first match wins: 56
// hex characters (a pool id), `pool1...` of 56 characters (bech32 id, whose
// checksum and human-readable part are verified: upstream decodes only),
// else a local pool name.
//
// spec: SPO-05b-IF-002, SPO-05b-IF-003, SPO-05b-PRE-001
func ParsePoolWord(word string) (PoolWord, error) {
	lower := strings.ToLower(word)
	if isHex56(lower) {
		return PoolWord{Pool: chain.PoolID(decodeHex28(lower)), IsID: true}, nil
	}
	if strings.HasPrefix(lower, "pool1") && len(lower) == 56 {
		id, err := chain.ParsePoolBech32(lower)
		if err != nil {
			return PoolWord{}, fmt.Errorf("%q is not a valid bech32 pool id: %w", word, err)
		}
		return PoolWord{Pool: id, IsID: true}, nil
	}
	name := strings.TrimPrefix(word, "./")
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".json"), ".pool")
	return PoolWord{Name: name}, nil
}

// DRepWord is a classified DRep argument of 22a.
type DRepWord struct {
	// DRep is set when the word is an id (forms 1 to 4).
	DRep DRep
	IsID bool
	// Name is the local DRep (`<name>.drep.vkey`) the word may name, tried
	// before the keywords; Keyword is the predefined DRep it spells, if any.
	Name    string
	Keyword DRepKind
}

// CIP-129 headers of a DRep id: key 0x22, script 0x23.
const (
	cip129DRepKey    = 0x22
	cip129DRepScript = 0x23
)

// ParseDRepWord classifies the target word of 22a in upstream's order: 56
// hex characters, `drep1...` of 56 (legacy key id), `drep_script1...` of 63
// (legacy script id), `drep1...` of 58 (CIP-129); any other word is a local
// DRep name (the use case looks for its key file) and possibly a keyword.
// The bech32 forms are verified structurally: checksum, human-readable part
// and payload length.
//
// spec: SPO-22a-IF-002, SPO-22a-PRE-002, SPO-22a-EXT-001, SPO-22a-EXT-002, SPO-22a-EXT-003
func ParseDRepWord(word string) (DRepWord, error) {
	lower := strings.ToLower(word)
	bech := func(wantHRP string, wantLen int) ([]byte, error) {
		hrp, data, err := chain.Bech32Decode(lower)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid bech32 DRep id: %w", word, err)
		}
		if hrp != wantHRP || len(data) != wantLen {
			return nil, fmt.Errorf("%q is not a DRep id: want human-readable part %q and %d bytes, got %q and %d", word, wantHRP, wantLen, hrp, len(data))
		}
		return data, nil
	}
	switch {
	case isHex56(lower):
		return DRepWord{DRep: DRep{Kind: DRepKey, Hash: decodeHex28(lower)}, IsID: true}, nil
	case strings.HasPrefix(lower, "drep1") && len(lower) == 56:
		d, err := bech("drep", 28)
		if err != nil {
			return DRepWord{}, err
		}
		w := DRepWord{DRep: DRep{Kind: DRepKey}, IsID: true}
		copy(w.DRep.Hash[:], d)
		return w, nil
	case strings.HasPrefix(lower, "drep_script1") && len(lower) == 63:
		d, err := bech("drep_script", 28)
		if err != nil {
			return DRepWord{}, err
		}
		w := DRepWord{DRep: DRep{Kind: DRepScript}, IsID: true}
		copy(w.DRep.Hash[:], d)
		return w, nil
	case strings.HasPrefix(lower, "drep1") && len(lower) == 58:
		d, err := bech("drep", 29)
		if err != nil {
			return DRepWord{}, err
		}
		w := DRepWord{IsID: true}
		switch d[0] {
		case cip129DRepKey:
			w.DRep.Kind = DRepKey
		case cip129DRepScript:
			w.DRep.Kind = DRepScript
		default:
			return DRepWord{}, fmt.Errorf("%q is a CIP-129 id with header %#02x: not a DRep key or script", word, d[0])
		}
		copy(w.DRep.Hash[:], d[1:])
		return w, nil
	}
	name := strings.TrimPrefix(word, "./")
	name = strings.TrimSuffix(strings.TrimSuffix(name, ".id"), ".drep")
	w := DRepWord{Name: name}
	switch lower {
	case "always-abstain":
		w.Keyword = DRepAbstain
	case "always-no-confidence":
		w.Keyword = DRepNoConfidence
	}
	return w, nil
}
