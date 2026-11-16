package fsstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// spec: SPO-Pparam-PRE-005, SPO-Pparam-OUT-003
func TestMetadataFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	os.WriteFile(p, []byte(`{"1":1}`), 0o600)
	got, err := MetadataFiles{}.ReadMetadataFile(p)
	if err != nil || string(got) != `{"1":1}` {
		t.Fatalf("%q %v", got, err)
	}
	if after, _ := os.ReadFile(p); string(after) != `{"1":1}` {
		t.Error("the file was changed")
	}
	if _, err := (MetadataFiles{}).ReadMetadataFile(filepath.Join(dir, "none.json")); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	if _, err := (MetadataFiles{}).ReadMetadataFile(dir); err == nil {
		t.Error("a directory")
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, []byte(strings.Repeat("x", maxMetadataFile+1)), 0o600)
	if _, err := (MetadataFiles{}).ReadMetadataFile(big); err == nil {
		t.Error("an oversized file")
	}
}
