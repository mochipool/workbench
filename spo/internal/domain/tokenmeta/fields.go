package tokenmeta

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The limits of the registry (CIP-26 and spec/upstream/scripts/12a). Lengths
// are counted in characters, not bytes.
const (
	MinName, MaxName            = 1, 50
	MinDescription              = 1 // upstream 12a requires a description; CIP-26 has no minimum
	MaxDescription              = 500
	MinTicker, MaxTicker        = 2, 9
	MaxURL                      = 250
	MaxDecimalsUpstream         = 255 // what 12a accepts (SPO-12a-PRE-005)
	MaxDecimals                 = 19  // CIP-26: "maximum": 19
	MaxLogoBytes                = 64 * 1024
	MaxLogoBase64               = 87400 // CIP-26 maxLength of the base64 text
	MaxSubjectHex               = 120
	MinSubjectHex               = 56
	pngMagic             string = "\x89PNG\r\n\x1a\n"
)

// ErrInvalidField is wrapped by every refusal of Fields.Validate; the message
// names the property and the limit.
var ErrInvalidField = errors.New("invalid token metadata field")

// Fields are the properties an operator supplies.
type Fields struct {
	Name, Description string
	// Ticker, URL and Decimals are optional; empty adds nothing.
	Ticker, URL string
	// Decimals is the text of a non-negative whole number, or empty.
	Decimals string
	// Logo is the PNG file's bytes, or nil.
	Logo []byte
}

func chars(s string) int { return utf8.RuneCountInString(s) }

func bad(prop Property, format string, a ...any) error {
	return fmt.Errorf("%w: %s %s", ErrInvalidField, prop, fmt.Sprintf(format, a...))
}

// Validate applies the registry's limits.
//
// Decision: upstream accepts any `https://` substring in the url and any
// decimals up to 255 (SPO-12a-PRE-004, SPO-12a-PRE-005); the registry
// requires a leading `https://` and at most 19 decimals (CIP-26), and a
// submission that breaks either is rejected by the registry, so this refuses
// it here.
//
// spec: SPO-12a-PRE-001, SPO-12a-PRE-002, SPO-12a-PRE-003, SPO-12a-PRE-004, SPO-12a-PRE-005, SPO-12a-PRE-006
func (f Fields) Validate() error {
	if n := chars(f.Name); n < MinName || n > MaxName {
		return bad(PropName, "must be %d to %d characters, it has %d", MinName, MaxName, n)
	}
	if n := chars(f.Description); n < MinDescription || n > MaxDescription {
		return bad(PropDescription, "must be %d to %d characters, it has %d", MinDescription, MaxDescription, n)
	}
	if f.Ticker != "" {
		if n := chars(f.Ticker); n < MinTicker || n > MaxTicker {
			return bad(PropTicker, "must be %d to %d characters, it has %d", MinTicker, MaxTicker, n)
		}
	}
	if f.URL != "" {
		if !strings.HasPrefix(f.URL, "https://") {
			return bad(PropURL, "must start with https://")
		}
		if n := chars(f.URL); n > MaxURL {
			return bad(PropURL, "must be at most %d characters, it has %d", MaxURL, n)
		}
	}
	if f.Decimals != "" {
		if _, err := ParseDecimals(f.Decimals); err != nil {
			return err
		}
	}
	if f.Logo != nil {
		if err := CheckLogo(f.Logo); err != nil {
			return err
		}
	}
	return nil
}

// ParseDecimals reads the decimals text: digits only, at most 255 as upstream
// accepts, and at most 19 as the registry does.
func ParseDecimals(s string) (uint64, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, bad(PropDecimals, "must be a whole number, not %q", s)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > MaxDecimalsUpstream {
		return 0, bad(PropDecimals, "must be at most %d", MaxDecimalsUpstream)
	}
	if n > MaxDecimals {
		return 0, bad(PropDecimals, "must be at most %d (CIP-26); upstream's check of %d lets a value the registry rejects through", MaxDecimals, MaxDecimalsUpstream)
	}
	return n, nil
}

// CheckLogo accepts a PNG of at most 64 KB. Upstream checks only that
// `file -b` says PNG (SPO-12a-PRE-006) and no size; the registry limit of
// CIP-26 is enforced as the port note asks.
func CheckLogo(png []byte) error {
	if !bytes.HasPrefix(png, []byte(pngMagic)) {
		return bad(PropLogo, "must be a PNG image")
	}
	if len(png) > MaxLogoBytes {
		return bad(PropLogo, "must be at most %d bytes, it has %d", MaxLogoBytes, len(png))
	}
	return nil
}

// CheckSubject checks a subject: 56 to 120 hex digits, policy id then asset
// name (SPO-12b-IN-001).
func CheckSubject(s string) error {
	if len(s) < MinSubjectHex || len(s) > MaxSubjectHex || strings.Trim(s, "0123456789abcdefABCDEF") != "" {
		return fmt.Errorf("a subject is %d to %d hex digits (the policy id and the hex asset name)", MinSubjectHex, MaxSubjectHex)
	}
	return nil
}
