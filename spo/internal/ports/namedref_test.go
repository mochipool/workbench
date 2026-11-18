package ports

import (
	"errors"
	"strings"
	"testing"
)

// A name is a plain label: no path syntax, no shell or jq syntax, no control
// character (hazard H7). The text form of an identity is accepted as a name by
// NamedRef (it names the owner that lists it) and refused as a label name (the
// labels package tests that).
//
// spec: SPO-Xidentity-INV-027
func TestNamedRefRefusesHostileNames(t *testing.T) {
	for _, name := range []string{"", "../evil", "a/b", `a\b`, ".hidden", "a..b", "x;rm -rf ~", "$(id)", "a b", "pool\x00", "a\nb", "a\x1b[31m",
		"a[$(id)]", "-", strings.Repeat("a", 129), "trailing.", "é"} {
		if err := (NamedRef{Name: name, Kind: KesCounter}).Validate(); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("name %q: %v", name, err)
		}
	}
	for _, name := range []string{"pool1", "w.payment", "a_b-c", "0abc", strings.Repeat("a", 128)} {
		if err := (NamedRef{Name: name, Kind: KesCounter}).Validate(); err != nil {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if _, ok := IdentityName("key-hash:" + strings.Repeat("ab", 28)); !ok {
		t.Error("an identity name is not recognised")
	}
	if _, ok := IdentityName("key-hash:" + strings.Repeat("AB", 28)); ok {
		t.Error("an upper-case identity name was recognised")
	}
}
