package relaypeer_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaypeer"
)

// FuzzVerify: any statement and key bytes either verify into a relay identity
// that names the device given and re-verifies, or are refused; nothing panics.
func FuzzVerify(f *testing.F) {
	g := good()
	f.Add(g.Sign1, g.COSEKey)
	f.Add(wallet.BindingStatementAt(wallet.EnterpriseAddress(0), dev, now-60, now+3600).Sign1, g.COSEKey)
	f.Add([]byte{0x84}, []byte{0xa4})
	f.Fuzz(func(t *testing.T, s1, key []byte) {
		ev, err := relaypeer.Verify(s1, key, dev, now, pol, 0)
		if err != nil {
			return
		}
		if ev.Relay.Device != dev || party.CheckRelay(&ev.Relay, dev) != nil {
			t.Fatal("evidence for another device")
		}
		if err := relaypeer.Reverify(ev.Relay, dev); err != nil {
			t.Fatalf("verified evidence does not re-verify: %v", err)
		}
	})
}
