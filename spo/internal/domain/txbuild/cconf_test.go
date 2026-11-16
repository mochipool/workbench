package txbuild

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// A transaction is valid for DefaultTTL slots after the tip, 100000 (a little
// over a day at one-second slots), upstream's defTTL. The other constants of
// the group are the address kinds `payment` and `stake`, which the port
// carries as ports.AddrBase/AddrEnterprise/AddrPointer and AddrReward, and the
// era `latest` for era-independent commands, which the native ledger has no
// need of.
//
// spec: SPO-Cconf-INV-009
func TestDefaultTTL(t *testing.T) {
	if DefaultTTL != 100000 {
		t.Errorf("DefaultTTL = %d, upstream's defTTL is 100000", DefaultTTL)
	}
	got, err := TTL(chain.Tip{Slot: 500}, DefaultTTL)
	if err != nil || got != 100500 {
		t.Errorf("TTL = %d, %v", got, err)
	}
}
