package transferfile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The snapshot carries the two parameters the pool use cases need.
//
// spec: SPO-05a-IN-006, SPO-05a-MODE-001, SPO-07a-IN-003, SPO-Ptransfer-OUT-002
func TestPoolParametersFromTheSnapshot(t *testing.T) {
	withPool := strings.Replace(snapshot, `"stakeAddressDeposit":2000000`, `"stakeAddressDeposit":2000000,"stakePoolDeposit":500000000,"minPoolCost":170000000,"poolRetireMaxEpoch":18`, 1)
	f := write(t, withPool)
	p, err := f.ProtocolParameters(context.Background())
	if err != nil || p.MinPoolCost != 170_000_000 || p.PoolRetireMaxEpoch != 18 || p.StakePoolDeposit != 500_000_000 {
		t.Fatalf("%+v %v", p, err)
	}
	// Absent they are zero, and the use cases refuse rather than default.
	p, err = write(t, snapshot).ProtocolParameters(context.Background())
	if err != nil || p.MinPoolCost != 0 || p.PoolRetireMaxEpoch != 0 {
		t.Errorf("%+v %v", p, err)
	}
	if !strings.Contains(string(p.Raw), "stakeAddressDeposit") {
		t.Error("the raw document is kept")
	}
}

// Attach stores a file as upstream's `attach` does and keeps the rest of the
// document.
//
// spec: SPO-Ptransfer-OUT-017, SPO-Ptransfer-OUT-018, SPO-05c-PR-005, SPO-05c-PR-006, SPO-05c-PR-007, SPO-05d-PR-003
func TestAttachStoresAFileAndKeepsTheRest(t *testing.T) {
	f := write(t, snapshot)
	content := []byte("{\n  \"name\": \"n\"\n}\n")
	if err := f.Attach(context.Background(), "mypool.metadata.json", content); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(f.Path)
	var doc struct {
		Files   map[string]struct{ Date, Size, Base64 string } `json:"files"`
		History []struct{ Date, Action string }                `json:"history"`
		Address map[string]json.RawMessage                     `json:"address"`
		Token   json.RawMessage                                `json:"tokenMetaServer"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	e := doc.Files["mypool.metadata.json"]
	if e.Date != "Mon, 16 Nov 2026 10:00:00 +0100" || e.Size != "18" {
		t.Errorf("%+v", e)
	}
	if b, _ := base64.StdEncoding.DecodeString(e.Base64); string(b) != string(content) || strings.Contains(e.Base64, "\n") {
		t.Errorf("base64 %q", e.Base64)
	}
	if _, ok := doc.Files["x.json"]; !ok {
		t.Error("an earlier attachment was lost")
	}
	if len(doc.History) != 2 || doc.History[1].Action != "attached file 'mypool.metadata.json'" {
		t.Errorf("%+v", doc.History)
	}
	if len(doc.Address) != 2 || len(doc.Token) == 0 {
		t.Error("the snapshot changed")
	}
	// Attaching the same name again overwrites that entry.
	if err := f.Attach(context.Background(), "mypool.metadata.json", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(f.Path)
	_ = json.Unmarshal(raw, &doc)
	if doc.Files["mypool.metadata.json"].Size != "2" || len(doc.Files) != 2 {
		t.Errorf("%+v", doc.Files)
	}
	// A file that is not a usable transfer file is refused and not touched.
	bad := write(t, "not json")
	if err := bad.Attach(context.Background(), "a", []byte("b")); err == nil {
		t.Error("attached into garbage")
	}
	var _ ports.TransferAttacher = f
}
