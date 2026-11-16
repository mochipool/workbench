package pool

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// A collection is expired when the tip has reached its TTL slot, as the signer
// holds a request expired.
// spec: SPO-Xparty-INV-015
func TestStateAtTipExpiresAtTheTTLSlot(t *testing.T) {
	c, err := OpenCollection(Collection{ID: 1, Type: GenericTransaction, TTL: 1000, Body: txbuild.TxBody{CBOR: []byte{1}, ID: chain.TxID{1}},
		Slots: []Slot{{Name: "a"}}})
	if err != nil {
		t.Fatal(err)
	}
	for tip, want := range map[uint64]CollectionState{999: CollectionOpenIncomplete, 1000: CollectionExpired, 1001: CollectionExpired, 1<<64 - 1: CollectionExpired} {
		if got := c.StateAtTip(tip); got != want {
			t.Errorf("tip %d: %s, want %s", tip, got, want)
		}
	}
}
