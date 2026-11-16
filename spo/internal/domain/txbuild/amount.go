package txbuild

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

type amountKind int

const (
	amountLovelaces amountKind = iota + 1
	amountAll
	amountAllFunds
	amountMin
)

// Amount is how much a payment sends. It is a closed type: Lovelaces(n),
// All, AllFunds or Min (spec 01_sendLovelaces, Domain mapping).
type Amount struct {
	kind amountKind
	n    chain.Lovelace
}

// Lovelaces sends exactly n lovelace (SPO-01sendLovelaces-OUT-005).
func Lovelaces(n chain.Lovelace) Amount { return Amount{kind: amountLovelaces, n: n} }

// All sends everything that is not needed to return the assets
// (SPO-01sendLovelaces-OUT-002, OUT-003).
func All() Amount { return Amount{kind: amountAll} }

// AllFunds sends all lovelace and every asset (SPO-01sendLovelaces-OUT-001).
func AllFunds() Amount { return Amount{kind: amountAllFunds} }

// Min sends the minimum output value (SPO-01sendLovelaces-OUT-004).
func Min() Amount { return Amount{kind: amountMin} }

// ErrBadAmount means the amount word is not a keyword or a plain number.
var ErrBadAmount = errors.New("the amount must be ALL, ALLFUNDS, MIN or a whole number of lovelace")

// ParseAmount reads the amount word. The word is upper-cased, so `all` is
// the keyword. Anything else must be ASCII digits only.
//
// Upstream substitutes the word into shell arithmetic as typed, so `010`
// is octal there. A zero-padded number is ambiguous, and the port refuses
// it instead of choosing a base (decision for the IF-002 quirk). Zero
// itself parses; the minimum-value check refuses it later.
//
// spec: SPO-01sendLovelaces-IF-002
func ParseAmount(word string) (Amount, error) {
	switch strings.ToUpper(word) {
	case "ALL":
		return All(), nil
	case "ALLFUNDS":
		return AllFunds(), nil
	case "MIN":
		return Min(), nil
	}
	if word == "" {
		return Amount{}, fmt.Errorf("%w: it is empty", ErrBadAmount)
	}
	for _, r := range word {
		if r < '0' || r > '9' {
			return Amount{}, fmt.Errorf("%w: %q", ErrBadAmount, word)
		}
	}
	if len(word) > 1 && word[0] == '0' {
		return Amount{}, fmt.Errorf("%w: %q has leading zeros", ErrBadAmount, word)
	}
	n, err := strconv.ParseUint(word, 10, 64)
	if err != nil {
		return Amount{}, fmt.Errorf("%w: %q does not fit in 64 bits", ErrBadAmount, word)
	}
	return Lovelaces(chain.Lovelace(n)), nil
}

func (a Amount) String() string {
	switch a.kind {
	case amountAll:
		return "ALL"
	case amountAllFunds:
		return "ALLFUNDS"
	case amountMin:
		return "MIN"
	case amountLovelaces:
		return strconv.FormatUint(uint64(a.n), 10)
	}
	return "invalid"
}

// Valid reports whether the amount was constructed.
func (a Amount) Valid() bool { return a.kind != 0 }
