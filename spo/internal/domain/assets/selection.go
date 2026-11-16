package assets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Errors of selections.
var (
	// ErrBadSelection: the asset selection word is malformed (SPO-01sendAssets-IF-003,
	// IF-004, IF-007 .. IF-013).
	ErrBadSelection = errors.New("invalid asset selection")
	// ErrAssetAbsent: a selection is not on the candidate inputs
	// (SPO-01sendAssets-PRE-002).
	ErrAssetAbsent = errors.New("the asset is not available on this address or the selected UTxOs")
	// ErrAmountTooHigh: more asked than the inputs hold (SPO-01sendAssets-PRE-003).
	ErrAmountTooHigh = errors.New("the amount is more than the inputs hold")
	// ErrDuplicateAsset: an asset named twice without agreement to sum the
	// amounts (SPO-01sendAssets-PR-001).
	ErrDuplicateAsset = errors.New("the asset is selected more than once")
	// ErrNoAssets: ALLASSETS on inputs with no asset (SPO-01sendAssets-IF-013).
	ErrNoAssets = errors.New("the inputs hold no asset to send")
)

// Kind is the form of an asset reference (SPO-01sendAssets-IF-007).
type Kind int

// Reference forms, in the order they are tried.
const (
	KindFingerprint Kind = iota + 1 // asset1...
	KindHexID                       // policy id and hex name
	KindNamed                       // <policy hex>.<name>
	KindBulkHex                     // <policy and hex name prefix>*
	KindBulkText                    // <policy hex>.<prefix>*
	KindAllAssets                   // ALLASSETS
	KindForceAda                    // FORCEADA
	KindFile                        // <name>.asset
)

// Selection is one asset selection of `01_sendAssets`: a reference and an
// amount. For an asset reference Fingerprint is set and matching is by
// fingerprint (SPO-01sendAssets-INV-001); a bulk selection names a policy and
// a name prefix; a keyword selects every asset.
type Selection struct {
	Input       string // the reference as typed
	Kind        Kind
	Fingerprint string
	// Policy and Prefix describe a bulk selection.
	Policy [28]byte
	Prefix []byte
	// File is the `.asset` reference of a KindFile selection, resolved by the
	// use case into a Fingerprint.
	File string
	// All is the keyword amount; Amount is the quantity otherwise.
	All    bool
	Amount uint64
}

var (
	fingerprintLen = 44
	hexIDRE        = regexp.MustCompile(`^([0-9a-fA-F]{2}){28,60}$`)
	namedRE        = regexp.MustCompile(`^[0-9a-fA-F]{56}\.[0-9A-Za-z]{1,32}$`)
	bulkHexRE      = regexp.MustCompile(`^([0-9a-fA-F]{2}){28,59}\*$`)
	bulkTextRE     = regexp.MustCompile(`^[0-9a-fA-F]{56}\.([0-9A-Za-z]{0,31})\*$`)
)

func badSel(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadSelection, fmt.Sprintf(format, a...))
}

// ParseAmountWord reads a selection amount: a positive integer or `ALL`
// (case-insensitive).
//
// spec: SPO-01sendAssets-IF-004
func parseAmountWord(w string) (all bool, n uint64, err error) {
	if strings.EqualFold(w, "ALL") {
		return true, 0, nil
	}
	if w == "" || strings.Trim(w, "0123456789") != "" {
		return false, 0, badSel("the amount %q is not a number or the keyword ALL", w)
	}
	if len(w) > 1 && w[0] == '0' {
		return false, 0, badSel("the amount %q has leading zeros", w)
	}
	n, err = strconv.ParseUint(w, 10, 64)
	if err != nil {
		return false, 0, badSel("the amount %q does not fit in 64 bits", w)
	}
	if n < 1 {
		return false, 0, badSel("please input a positive sending amount")
	}
	return false, n, nil
}

// classify turns one asset reference into a Selection (without its amount).
func classify(ref string) (Selection, error) {
	s := Selection{Input: ref}
	switch {
	case len(ref) == fingerprintLen && strings.HasPrefix(ref, "asset"):
		hrp, data, err := chain.Bech32Decode(ref)
		if err != nil || hrp != "asset" || len(data) != 20 {
			return Selection{}, badSel("%q is not a valid bech32 asset fingerprint", ref)
		}
		s.Kind, s.Fingerprint = KindFingerprint, ref
	case hexIDRE.MatchString(ref):
		raw, _ := hex.DecodeString(ref)
		var id chain.AssetID
		copy(id.Policy[:], raw[:28])
		id.Name = raw[28:]
		s.Kind, s.Fingerprint = KindHexID, Fingerprint(id)
	case namedRE.MatchString(ref):
		p, name, _ := strings.Cut(ref, ".")
		raw, _ := hex.DecodeString(p)
		var id chain.AssetID
		copy(id.Policy[:], raw)
		id.Name = []byte(name)
		s.Kind, s.Fingerprint = KindNamed, Fingerprint(id)
	case bulkHexRE.MatchString(ref):
		raw, _ := hex.DecodeString(ref[:len(ref)-1])
		copy(s.Policy[:], raw[:28])
		s.Prefix = raw[28:]
		s.Kind = KindBulkHex
	case bulkTextRE.MatchString(ref):
		p, rest, _ := strings.Cut(ref, ".")
		raw, _ := hex.DecodeString(p)
		copy(s.Policy[:], raw)
		s.Prefix = []byte(strings.TrimSuffix(rest, "*"))
		s.Kind = KindBulkText
	case strings.EqualFold(ref, "ALLASSETS"):
		s.Kind = KindAllAssets
	case strings.EqualFold(ref, "FORCEADA"):
		s.Kind = KindForceAda
	default:
		s.Kind, s.File = KindFile, strings.TrimSuffix(ref, ".asset")
	}
	return s, nil
}

// ParseSelections reads the asset selection word of `01_sendAssets` and its
// optional separate amount word. The word holds one or more selections
// separated by `|`, each a reference and an amount separated by blanks; when
// there is exactly one selection with only its reference, the amount is the
// separate word. A bulk selection needs the amount ALL, a keyword selection
// needs none. A reference that fits no form is taken as the name of an asset
// file (KindFile) for the use case to resolve.
//
// spec: SPO-01sendAssets-IF-003, SPO-01sendAssets-IF-004, SPO-01sendAssets-IF-007, SPO-01sendAssets-IF-008,
// spec: SPO-01sendAssets-IF-009, SPO-01sendAssets-IF-010, SPO-01sendAssets-IF-011, SPO-01sendAssets-IF-012,
// spec: SPO-01sendAssets-IF-013, SPO-01sendAssets-IF-014
func ParseSelections(word, amountWord string) ([]Selection, error) {
	if strings.TrimSpace(word) == "" {
		return nil, badSel("no asset is selected")
	}
	entries := strings.Split(word, "|")
	var out []Selection
	for _, e := range entries {
		f := strings.Fields(e)
		if len(f) == 0 || len(f) > 2 {
			return nil, badSel("two parameters are needed per asset, the asset and the amount; the issue is with %q", e)
		}
		sel, err := classify(f[0])
		if err != nil {
			return nil, err
		}
		keyword := sel.Kind == KindAllAssets || sel.Kind == KindForceAda
		bulk := sel.Kind == KindBulkHex || sel.Kind == KindBulkText
		amt := ""
		switch {
		case len(f) == 2:
			amt = f[1]
		case len(entries) == 1 && amountWord != "":
			amt = amountWord
		case keyword:
			amt = "ALL"
		default:
			if len(entries) == 1 {
				return nil, badSel("the amount is missing for %q", f[0])
			}
			return nil, badSel("a selection other than the sole one must carry its own amount: %q", f[0])
		}
		if len(f) == 2 && len(entries) == 1 && amountWord != "" {
			return nil, badSel("the amount is given twice")
		}
		if keyword {
			sel.All = true // the amount is forced to ALL
		} else {
			all, n, err := parseAmountWord(amt)
			if err != nil {
				return nil, err
			}
			if bulk && !all {
				return nil, badSel("the bulk selection %q needs the amount ALL", f[0])
			}
			sel.All, sel.Amount = all, n
		}
		out = append(out, sel)
	}
	return out, nil
}

// Held is one asset type found on the candidate inputs with its total.
type Held struct {
	Asset       chain.AssetID
	Fingerprint string
	Total       uint64
}

// HeldAssets lists the asset types of a total in ascending policy and name
// order with their fingerprints.
func HeldAssets(total []chain.AssetAmount) []Held {
	out := make([]Held, 0, len(total))
	for _, a := range total {
		out = append(out, Held{Asset: a.Asset, Fingerprint: Fingerprint(a.Asset), Total: a.Quantity})
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Asset.Policy[:], out[j].Asset.Policy[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(out[i].Asset.Name, out[j].Asset.Name) < 0
	})
	return out
}

// Duplicates lists the fingerprints named by more than one selection after
// the file references were resolved, in first-seen order.
func Duplicates(sels []Selection) []string {
	seen, dup := map[string]int{}, []string{}
	for _, s := range sels {
		if s.Fingerprint == "" {
			continue
		}
		seen[s.Fingerprint]++
		if seen[s.Fingerprint] == 2 {
			dup = append(dup, s.Fingerprint)
		}
	}
	return dup
}

// Plan is the outcome of resolving selections against the candidate inputs.
type Plan struct {
	// Send is the assets to send, sorted by policy and name, with their
	// quantities (ALL replaced by the total).
	Send []chain.AssetAmount
	// Warnings are advice, such as a FORCEADA that found no asset.
	Warnings []string
}

// Resolve matches the selections against the assets of the candidate inputs
// by fingerprint, expands bulk and keyword selections, merges an asset named
// twice (the amounts are added and ALL wins, when sum is true; otherwise a
// duplicate is refused, SPO-01sendAssets-PR-001) and checks the amounts
// against the totals. keep lists the policy ids an ALLASSETS or FORCEADA
// selection leaves on the source.
//
// A bulk entry that matches nothing is refused as an absent asset.
// ALLASSETS on inputs without assets is refused; FORCEADA instead yields an
// empty send.
//
// spec: SPO-01sendAssets-INV-001, SPO-01sendAssets-INV-002, SPO-01sendAssets-INV-003, SPO-01sendAssets-INV-004,
// spec: SPO-01sendAssets-INV-005, SPO-01sendAssets-PRE-002, SPO-01sendAssets-PRE-003, SPO-01sendAssets-PR-001,
// spec: SPO-01sendAssets-IF-013
func Resolve(sels []Selection, held []Held, keep [][28]byte, sum bool) (Plan, error) {
	type entry struct {
		h   Held
		all bool
		n   uint64
		in  string
	}
	var order []string
	byFP := map[string]*entry{}
	add := func(h Held, all bool, n uint64, in string, explicit bool) error {
		e, ok := byFP[h.Fingerprint]
		if !ok {
			byFP[h.Fingerprint] = &entry{h: h, all: all, n: n, in: in}
			order = append(order, h.Fingerprint)
			return nil
		}
		if !explicit {
			// A bulk selection adds an asset with ALL; ALL wins.
			e.all = true
			return nil
		}
		if !sum {
			return fmt.Errorf("%w: %s (%s)", ErrDuplicateAsset, in, h.Fingerprint)
		}
		if all || e.all {
			e.all = true
			return nil
		}
		if e.n > ^uint64(0)-n {
			return badSel("the amounts of %s add up beyond 64 bits", in)
		}
		e.n += n
		return nil
	}
	find := func(fp string) (Held, bool) {
		for _, h := range held {
			if h.Fingerprint == fp {
				return h, true
			}
		}
		return Held{}, false
	}
	kept := func(p [28]byte) bool {
		for _, k := range keep {
			if k == p {
				return true
			}
		}
		return false
	}
	var warnings []string
	// Explicit references are collected first and bulk selections expand
	// over them afterwards, as upstream does, so a bulk selection never
	// counts as a duplicate of an explicit one.
	ordered := make([]Selection, 0, len(sels))
	for _, s := range sels {
		if s.Kind != KindBulkHex && s.Kind != KindBulkText && s.Kind != KindAllAssets && s.Kind != KindForceAda {
			ordered = append(ordered, s)
		}
	}
	for _, s := range sels {
		if s.Kind == KindBulkHex || s.Kind == KindBulkText || s.Kind == KindAllAssets || s.Kind == KindForceAda {
			ordered = append(ordered, s)
		}
	}
	for _, s := range ordered {
		switch s.Kind {
		case KindFingerprint, KindHexID, KindNamed, KindFile:
			h, ok := find(s.Fingerprint)
			if !ok {
				return Plan{}, fmt.Errorf("%w: %s (%s)", ErrAssetAbsent, s.Input, s.Fingerprint)
			}
			if err := add(h, s.All, s.Amount, s.Input, true); err != nil {
				return Plan{}, err
			}
		case KindBulkHex, KindBulkText:
			matched := 0
			for _, h := range held {
				if h.Asset.Policy == s.Policy && len(h.Asset.Name) > 0 && bytes.HasPrefix(h.Asset.Name, s.Prefix) {
					matched++
					if err := add(h, true, 0, s.Input, false); err != nil {
						return Plan{}, err
					}
				}
			}
			if matched == 0 {
				return Plan{}, fmt.Errorf("%w: nothing matches the bulk selection %s", ErrAssetAbsent, s.Input)
			}
		case KindAllAssets, KindForceAda:
			matched := 0
			for _, h := range held {
				if kept(h.Asset.Policy) {
					continue
				}
				matched++
				if err := add(h, true, 0, s.Input, false); err != nil {
					return Plan{}, err
				}
			}
			if matched == 0 {
				if s.Kind == KindAllAssets {
					return Plan{}, fmt.Errorf("%w: %s", ErrNoAssets, s.Input)
				}
				warnings = append(warnings, "FORCEADA: no asset to send, the transaction sends lovelace only")
			}
		default:
			return Plan{}, badSel("unresolved selection %q", s.Input)
		}
	}
	var send []chain.AssetAmount
	for _, fp := range order {
		e := byFP[fp]
		n := e.n
		if e.all {
			n = e.h.Total
		}
		if n > e.h.Total {
			return Plan{}, fmt.Errorf("%w: %s asks %d, a maximum of %d is available", ErrAmountTooHigh, e.in, n, e.h.Total)
		}
		if n == 0 {
			continue
		}
		send = append(send, chain.AssetAmount{Asset: e.h.Asset, Quantity: n})
	}
	sort.Slice(send, func(i, j int) bool {
		if c := bytes.Compare(send[i].Asset.Policy[:], send[j].Asset.Policy[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(send[i].Asset.Name, send[j].Asset.Name) < 0
	})
	return Plan{Send: send, Warnings: warnings}, nil
}
