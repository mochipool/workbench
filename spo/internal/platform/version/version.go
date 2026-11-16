// Package version orders tool versions the way upstream's versionCheck does.
package version

import "strings"

// Compare orders two version strings in GNU `sort -V` order for the forms
// tools print (dot-separated numbers, optionally with text suffixes).
// It returns -1, 0 or 1.
//
// spec: SPO-Cconf-INV-015, SPO-Chw-INV-001
func Compare(a, b string) int {
	as, bs := split(a), split(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		// A version that runs out of parts first sorts first: 1.20 < 1.20.0.
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		x, y := as[i], bs[i]
		if c := cmpPart(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// AtLeast reports whether have >= min. An empty have is never at least a
// non-empty min: an unreadable version fails the gate. Upstream lets an empty
// hardware-cli version pass (SPO-Chw-INV-001); that quirk is fixed here.
func AtLeast(have, min string) bool {
	if min == "" {
		return true
	}
	if have == "" {
		return false
	}
	return Compare(have, min) >= 0
}

// AtMost reports whether have <= max. An empty max means no upper bound.
func AtMost(have, max string) bool {
	if max == "" {
		return true
	}
	if have == "" {
		return false
	}
	return Compare(have, max) <= 0
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

func cmpPart(x, y string) int {
	xn, xr := leadingNumber(x)
	yn, yr := leadingNumber(y)
	if c := cmpNumeric(xn, yn); c != 0 {
		return c
	}
	return strings.Compare(xr, yr)
}

func leadingNumber(s string) (digits, rest string) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i], s[i:]
}

// cmpNumeric compares two digit strings of any length as numbers.
func cmpNumeric(x, y string) int {
	x = strings.TrimLeft(x, "0")
	y = strings.TrimLeft(y, "0")
	if len(x) != len(y) {
		if len(x) < len(y) {
			return -1
		}
		return 1
	}
	return strings.Compare(x, y)
}
