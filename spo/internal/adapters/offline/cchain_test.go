package offline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/genesisfile"
)

const byronJSON = `{"startTime":1506203091,"blockVersionData":{"slotDuration":"20000"},"protocolConsts":{"k":2160}}`
const shelleyJSON = `{"systemStart":"2017-09-23T21:44:51Z","slotLength":1,"epochLength":432000,"slotsPerKESPeriod":129600,"maxKESEvolutions":62,"networkMagic":764824073}`

// The Byron inputs come from the Byron genesis file (slot duration in
// milliseconds, k, start time); the Shelley slot length from the Shelley
// file; the epochs of the Byron era are a property of the network. The
// offline tip then follows the Byron derivations: a Byron epoch is 10*k
// slots, the Byron era ends at start + epochs*10k*slotDuration, and the
// epoch afterwards is E_b + elapsed/slotLength/epochLength (two truncating
// divisions). The tip slot is the same arithmetic.
//
// spec: SPO-Cchain-INV-003, SPO-Cchain-INV-004, SPO-Cchain-INV-005, SPO-Cchain-OUT-003, SPO-Cchain-INV-006
func TestOfflineEpochAndSlotFromTheGenesisFiles(t *testing.T) {
	dir := t.TempDir()
	bp, sp := filepath.Join(dir, "byron.json"), filepath.Join(dir, "shelley.json")
	if err := os.WriteFile(bp, []byte(byronJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, []byte(shelleyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	byron, err := genesisfile.ReadByron(bp, 208)
	if err != nil {
		t.Fatal(err)
	}
	if byron.K != 2160 || byron.SlotDuration != 20*time.Second || byron.Start.Unix() != 1506203091 || byron.ToShelleyEpochs != 208 {
		t.Fatalf("%+v", byron)
	}
	end := byron.Start.Unix() + 208*10*2160*20 // INV-004: the end of the Byron era
	if end != 1596059091 {
		t.Fatalf("byron end %d, mainnet's is 1596059091", end)
	}
	for _, c := range []struct {
		now         int64
		slot, epoch uint64
	}{
		{end, 208 * 21600, 208},                 // the first Shelley slot
		{end + 5, 208*21600 + 5, 208},           // inside the first Shelley epoch
		{end + 432000, 208*21600 + 432000, 209}, // one epoch later
		{end + 432000*3 + 17, 208*21600 + 432000*3 + 17, 211},
		{byron.Start.Unix() + 20*21600*3, 3 * 21600, 3}, // still Byron: epoch of 21600 slots
	} {
		tip := Tip{Clock: clock{time.Unix(c.now, 0)}, Genesis: genesisfile.Shelley{Path: sp}, Byron: &byron}
		got, err := tip.Tip(context.Background())
		if err != nil || got.Slot != c.slot || got.Epoch != c.epoch {
			t.Errorf("now %d: %+v %v, want slot %d epoch %d", c.now, got, err, c.slot, c.epoch)
		}
	}
}

// A missing Shelley or Byron genesis file is an error that names the file
// (upstream exits 1, the Shelley file checked first); the transfer file is
// not consulted.
//
// spec: SPO-Cchain-MODE-004, SPO-Cchain-MODE-008
func TestOfflineTipNeedsBothGenesisFiles(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.json")
	tip := Tip{Clock: clock{time.Unix(1700000000, 0)}, Genesis: genesisfile.Shelley{Path: missing}}
	if _, err := tip.Tip(context.Background()); err == nil {
		t.Error("a missing Shelley genesis file was accepted")
	}
	if _, err := genesisfile.ReadByron(missing, 208); err == nil {
		t.Error("a missing Byron genesis file was accepted")
	}
}
