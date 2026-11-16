package chain

import (
	"encoding/hex"
	"testing"
)

// The vectors of CIP-14.
func TestAssetFingerprint(t *testing.T) {
	pol, _ := hex.DecodeString("7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373")
	var id AssetID
	copy(id.Policy[:], pol)
	if got := AssetFingerprint(id); got != "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3" {
		t.Errorf("empty name: %s", got)
	}
	id.Name = []byte("A")
	if got := AssetFingerprint(id); got == "" || got == "asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3" {
		t.Errorf("a name changes the fingerprint: %s", got)
	}
}
