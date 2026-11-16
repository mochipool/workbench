package transferfile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func refOf(t *testing.T, hash string, ix uint32) chain.OutRef {
	t.Helper()
	id, err := chain.ParseTxID(hash)
	if err != nil {
		t.Fatal(err)
	}
	return chain.OutRef{TxID: id, Index: ix}
}

func snapshotFile(t *testing.T, doc string) *File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "offlineTransfer.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return &File{Path: p}
}

// A reference among the UTxOs the snapshot holds resolves with the address it
// is listed under; any other reference is Unknown, never None.
//
// spec: SPO-Xparty-PR-002
func TestResolveUtxosFromTheSnapshot(t *testing.T) {
	f := snapshotFile(t, snapshot)
	a, b := refOf(t, hashA, 1), refOf(t, hashB, 0)
	missing, wrongIndex := refOf(t, strings.Repeat("11", 32), 0), refOf(t, hashA, 7)
	got, err := f.ResolveUtxos(context.Background(), []chain.OutRef{a, b, missing, wrongIndex})
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := got[a].Get(); !ok || u.Address != addr || u.Lovelace != 20000000 || len(u.Assets) != 0 {
		t.Fatalf("%+v", got[a])
	}
	if u, ok := got[b].Get(); !ok || u.Lovelace != 5000000 || len(u.Assets) != 2 {
		t.Fatalf("%+v", got[b])
	}
	for _, r := range []chain.OutRef{missing, wrongIndex} {
		if !got[r].IsUnknown() || got[r].IsNone() {
			t.Fatalf("%s: %+v, want Unknown", r, got[r])
		}
	}
}

// Two addresses listing one reference is a snapshot that contradicts itself:
// Unknown. A file that is not a usable snapshot is an error.
//
// spec: SPO-Xparty-PR-002
func TestResolveUtxosContradictionAndBadFile(t *testing.T) {
	doc := strings.Replace(snapshot, `"stake_test1other": {"name": "s", "type": "stake", "rewardsJSON": []}`,
		`"addr_test1vqq": {"name": "x", "type": "payment", "utxoJSON": {"`+hashA+`#1": {"address": "addr_test1vqq", "value": {"lovelace": "1"}}}}`, 1)
	if doc == snapshot {
		t.Fatal("the snapshot text moved")
	}
	ref := refOf(t, hashA, 1)
	got, err := snapshotFile(t, doc).ResolveUtxos(context.Background(), []chain.OutRef{ref})
	if err != nil || !got[ref].IsUnknown() || !strings.Contains(got[ref].Why(), "two addresses") {
		t.Fatalf("%+v %v", got[ref], err)
	}
	if _, err := snapshotFile(t, "not json").ResolveUtxos(context.Background(), []chain.OutRef{ref}); err == nil {
		t.Fatal("a bad file resolved")
	}
}
