package governance

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Credential is a key hash or a script hash: the identity of a DRep or of a
// committee member's cold or hot key.
type Credential struct {
	Script bool
	Hash   [28]byte
}

func (c Credential) String() string {
	if c.Script {
		return "script-" + hex.EncodeToString(c.Hash[:])
	}
	return "key-" + hex.EncodeToString(c.Hash[:])
}

// ParseHash28 reads 56 hex digits (case-insensitive, trimmed).
func ParseHash28(s string) ([28]byte, error) {
	var out [28]byte
	s = strings.ToLower(strings.TrimSpace(s))
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 28 {
		return out, fmt.Errorf("%q is not a 56-digit hex hash", s)
	}
	copy(out[:], b)
	return out, nil
}

// CIP-129 header bytes (type nibble, credential nibble).
const (
	hdrCCHotKey     byte = 0x02
	hdrCCHotScript  byte = 0x03
	hdrDRepKey      byte = 0x22
	hdrDRepScript   byte = 0x23
	hdrCCColdKey    byte = 0x12
	hdrCCColdScript byte = 0x13
)

// ---- DRep ids ----------------------------------------------------------------

// DRepIDs are the spellings of a DRep id. Legacy is the CIP-105 bech32 id
// `cardano-cli governance drep id` prints (`drep1...` of 56 characters, or
// `drep_script1...`), CIP129 the 29-byte form with a header byte.
type DRepIDs struct {
	Hex    string
	Legacy string
	CIP129 string
}

// DRepIDsOf spells a DRep credential in all three forms.
//
// spec: SPO-21a-EXT-005, SPO-21a-INV-003, SPO-21c-INV-001
func DRepIDsOf(c Credential) (DRepIDs, error) {
	hrp, hdr := "drep", hdrDRepKey
	if c.Script {
		hrp, hdr = "drep_script", hdrDRepScript
	}
	legacy, err := chain.Bech32Encode(hrp, c.Hash[:])
	if err != nil {
		return DRepIDs{}, err
	}
	cip, err := chain.Bech32Encode("drep", append([]byte{hdr}, c.Hash[:]...))
	if err != nil {
		return DRepIDs{}, err
	}
	return DRepIDs{Hex: hex.EncodeToString(c.Hash[:]), Legacy: legacy, CIP129: cip}, nil
}

// ---- committee ids ------------------------------------------------------------

// CommitteeIDs are the spellings of a committee member's cold or hot
// credential: the hash, the CIP-105 bech32 id (`cc_cold1...`, `cc_hot1...`)
// and the CIP-129 id.
type CommitteeIDs struct {
	Hex    string
	Legacy string
	CIP129 string
}

// CommitteeIDsOf spells a committee credential; hot selects `cc_hot` and its
// header bytes, else `cc_cold`.
//
// spec: SPO-23c-IN-002, SPO-23d-INV-001
func CommitteeIDsOf(c Credential, hot bool) (CommitteeIDs, error) {
	hrp, hdr := "cc_cold", hdrCCColdKey
	switch {
	case hot && c.Script:
		hrp, hdr = "cc_hot_script", hdrCCHotScript
	case hot:
		hrp, hdr = "cc_hot", hdrCCHotKey
	case c.Script:
		hrp, hdr = "cc_cold_script", hdrCCColdScript
	}
	legacy, err := chain.Bech32Encode(hrp, c.Hash[:])
	if err != nil {
		return CommitteeIDs{}, err
	}
	base := "cc_cold"
	if hot {
		base = "cc_hot"
	}
	cip, err := chain.Bech32Encode(base, append([]byte{hdr}, c.Hash[:]...))
	if err != nil {
		return CommitteeIDs{}, err
	}
	return CommitteeIDs{Hex: hex.EncodeToString(c.Hash[:]), Legacy: legacy, CIP129: cip}, nil
}

// ErrCommitteeWord: a word that is no committee hash or id.
var ErrCommitteeWord = errors.New("not a committee credential hash or id")

// ParseCommitteeWord resolves the hash or bech32 id forms of 23d (first match
// wins): 56 hex digits; a `cc_cold1`/`cc_hot1` id of 58 or 59 characters
// (CIP-105) or one with a CIP-129 header byte. A name that resolves to a file
// is the use case's business: IsID is false then. Unlike upstream, the CIP-129
// hot id of 60 characters is recognised too (SPO-23d-INV-002), and the credential
// type is kept, not dropped.
//
// spec: SPO-23d-IF-002, SPO-23d-IN-001, SPO-23d-INV-001, SPO-23d-INV-002
func ParseCommitteeWord(word string) (c Credential, isID bool, err error) {
	lower := strings.ToLower(strings.TrimSpace(word))
	if h, herr := ParseHash28(lower); herr == nil {
		return Credential{Hash: h}, true, nil
	}
	if !strings.HasPrefix(lower, "cc_cold") && !strings.HasPrefix(lower, "cc_hot") {
		return Credential{}, false, nil
	}
	hrp, data, derr := chain.Bech32Decode(lower)
	if derr != nil {
		return Credential{}, true, fmt.Errorf("%w: %q: %v", ErrCommitteeWord, word, derr)
	}
	switch {
	case len(data) == 28 && (hrp == "cc_cold" || hrp == "cc_hot"):
		copy(c.Hash[:], data)
	case len(data) == 28 && (hrp == "cc_cold_script" || hrp == "cc_hot_script"):
		c.Script = true
		copy(c.Hash[:], data)
	case len(data) == 29 && (hrp == "cc_cold" || hrp == "cc_hot"):
		switch data[0] {
		case hdrCCColdKey, hdrCCHotKey:
		case hdrCCColdScript, hdrCCHotScript:
			c.Script = true
		default:
			return Credential{}, true, fmt.Errorf("%w: %q has the CIP-129 header %#02x", ErrCommitteeWord, word, data[0])
		}
		copy(c.Hash[:], data[1:])
	default:
		return Credential{}, true, fmt.Errorf("%w: %q (human-readable part %q, %d bytes)", ErrCommitteeWord, word, hrp, len(data))
	}
	return c, true, nil
}

// ---- action ids ----------------------------------------------------------------

// ActionID names a governance action: the id of the transaction that
// proposed it and the index of the proposal in it.
type ActionID struct {
	TxID  chain.TxID
	Index uint32
}

// Hex is `<txid>#<index>`.
func (a ActionID) Hex() string { return fmt.Sprintf("%s#%d", a.TxID, a.Index) }

// CIP129 is the bech32 `gov_action1...` id: the 32 id bytes and the index as
// one byte.
//
// spec: SPO-Cconv-OUT-017
func (a ActionID) CIP129() (string, error) {
	if a.Index > 255 {
		return "", fmt.Errorf("action index %d does not fit the CIP-129 id", a.Index)
	}
	return chain.Bech32Encode("gov_action", append(append([]byte(nil), a.TxID[:]...), byte(a.Index)))
}

// ErrActionID: a word that is no governance action id.
var ErrActionID = errors.New("not a governance action id: want <64 hex>#<index> or a gov_action1... id")

// ParseActionID reads `<64 hex>#<digits>` (case-insensitive, the index
// normalised to a plain number) or a CIP-129 `gov_action1...` id.
//
// spec: SPO-24a-IF-003, SPO-24c-IF-003
func ParseActionID(s string) (ActionID, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "gov_action1") {
		hrp, data, err := chain.Bech32Decode(s)
		if err != nil || hrp != "gov_action" || len(data) < 33 || len(data) > 36 {
			return ActionID{}, fmt.Errorf("%w: %q", ErrActionID, s)
		}
		var id ActionID
		copy(id.TxID[:], data[:32])
		for _, b := range data[32:] {
			id.Index = id.Index<<8 | uint32(b)
		}
		return id, nil
	}
	tx, ix, ok := strings.Cut(s, "#")
	if !ok || ix == "" || len(ix) > 5 {
		return ActionID{}, fmt.Errorf("%w: %q", ErrActionID, s)
	}
	id, err := chain.ParseTxID(tx)
	if err != nil {
		return ActionID{}, fmt.Errorf("%w: %q", ErrActionID, s)
	}
	var n uint32
	for _, c := range ix {
		if c < '0' || c > '9' {
			return ActionID{}, fmt.Errorf("%w: %q", ErrActionID, s)
		}
		n = n*10 + uint32(c-'0')
	}
	if n > 0xffff {
		return ActionID{}, fmt.Errorf("%w: the index is above 65535", ErrActionID)
	}
	return ActionID{TxID: id, Index: n}, nil
}
