package txparam

import (
	"errors"
	"strings"
	"testing"
)

// Limits on UTF-8 text count bytes, not characters: 32 two-byte characters
// are exactly 64 bytes, a 33rd is over.
//
// spec: SPO-Cconv-OUT-012
func TestLengthLimitsCountUTF8Bytes(t *testing.T) {
	if err := CheckMessages([]string{strings.Repeat("é", 32)}); err != nil {
		t.Errorf("64 bytes refused: %v", err)
	}
	if err := CheckMessages([]string{strings.Repeat("é", 33)}); !errors.Is(err, ErrBadMessage) {
		t.Errorf("66 bytes: %v", err)
	}
}
