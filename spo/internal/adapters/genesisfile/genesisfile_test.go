package genesisfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "g.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// spec: SPO-04d-IN-004, SPO-04d-PRE-006
func TestShelley(t *testing.T) {
	p := write(t, `{"epochLength":86400,"maxKESEvolutions":62,"networkMagic":2,"slotLength":1,"slotsPerKESPeriod":129600,"systemStart":"2022-10-25T00:00:00Z"}`)
	g, err := Shelley{p}.Genesis(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g.SlotLength != time.Second || g.SlotsPerKESPeriod != 129600 || g.MaxKESEvolutions != 62 || g.EpochLength != 86400 ||
		g.NetworkMagic != 2 || g.SystemStart.Unix() != 1666656000 {
		t.Errorf("%+v", g)
	}
	// Missing file and missing members are failures (upstream exits 1).
	if _, err := (Shelley{filepath.Join(t.TempDir(), "none.json")}).Genesis(context.Background()); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := (Shelley{write(t, `{"slotLength":1}`)}).Genesis(context.Background()); err == nil {
		t.Error("incomplete genesis accepted")
	}
}

func TestByron(t *testing.T) {
	p := write(t, `{"startTime":1666656000,"blockVersionData":{"slotDuration":"20000"},"protocolConsts":{"k":432,"protocolMagic":2}}`)
	b, err := ReadByron(p, 0)
	if err != nil || b.SlotDuration != 20*time.Second || b.K != 432 || b.Start.Unix() != 1666656000 {
		t.Fatalf("%+v %v", b, err)
	}
}
