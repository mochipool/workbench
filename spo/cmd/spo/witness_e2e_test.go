package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A second owner's witness is signed with `pool witness sign`: the body is
// decoded and shown in full, the default answer is No (the file is then
// untouched), a yes rewrites the file in place with a witness the collection
// accepts, and `info` and `clear` report and discard the collection.
func TestPoolWitnessSignInfoAndClear(t *testing.T) {
	r := newPoolRig(t, "quartz-owner", "second")
	r.certAndDescriptor(t, "quartz-owner", "second:external")
	out := r.must(t, []string{"y"}, "pool", "register", "p", "quartz-owner.payment", "--allow-pending")
	name := regexp.MustCompile(`wrote\s+(p_second_\d+)\.witness`).FindStringSubmatch(out)[1]
	var raw []byte
	if err := storeOf(t, r.dir).View(context.Background(), func(rd ports.Reader) error {
		var err error
		raw, err = rd.Get(ports.Ref{Name: name, Kind: ports.PoolWitnessFile})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), name+".witness")
	os.WriteFile(file, raw, 0o600)

	out = r.mustG(t, nil, "pool", "witness", "info", "p")
	mustHave(t, out, "Witness collection", "valid until  slot", "OpenIncomplete", "signed     quartz-owner.staking", "open       second.staking")

	// Not signed without the key name.
	if _, err := exec2(t, r.dir, nil, "pool", "witness", "sign", file, "--shelley-genesis", r.genesis); err == nil {
		t.Fatal("signed without --key")
	}
	// Declined (an empty answer is No): the body was shown, the file is untouched.
	out, err := exec2(t, r.dir, []string{""}, "pool", "witness", "sign", file, "--key", "second", "--shelley-genesis", r.genesis)
	if err == nil || !strings.Contains(err.Error(), "did not approve") {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Transaction to sign", "certificate  pool-registration", "pledge       100.000000 ADA", "margin       1/20", "relay        dns relay.example.org:3001",
		"fee          ", "valid until  slot", `You are asked to sign this as "second.staking"`)
	if now, _ := os.ReadFile(file); !bytes.Equal(now, raw) {
		t.Fatal("a declined signing changed the file")
	}
	// A key that is not the one the witness was requested for.
	if out, err := exec2(t, r.dir, []string{"y"}, "pool", "witness", "sign", file, "--key", "quartz-owner", "--shelley-genesis", r.genesis); err == nil || !strings.Contains(err.Error(), "wrong signing key") {
		t.Fatalf("%v\n%s", err, out)
	}
	// Signed.
	out, err = exec2(t, r.dir, []string{"y"}, "pool", "witness", "sign", file, "--key", "second", "--shelley-genesis", r.genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Signed.", file)
	signed, _ := os.ReadFile(file)
	tf, err := pool.ParseTransferFile(signed)
	if err != nil || !tf.Signed() {
		t.Fatalf("the file is not signed: %v", err)
	}
	// Signed once.
	if out, err := exec2(t, r.dir, []string{"y"}, "pool", "witness", "sign", file, "--key", "second", "--shelley-genesis", r.genesis); err == nil || !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("%v\n%s", err, out)
	}
	// The collection accepts it.
	out = r.mustG(t, nil, "pool", "witness", "import", "p", file)
	mustHave(t, out, "Imported the witness of slot second.staking", "Collection is OpenComplete")

	// clear: No by default, then Yes.
	out = r.mustG(t, []string{""}, "pool", "witness", "clear", "p")
	mustHave(t, out, "Not cleared")
	out = r.mustG(t, nil, "pool", "witness", "info", "p")
	mustHave(t, out, "OpenComplete")
	out = r.mustG(t, []string{"y"}, "pool", "witness", "clear", "p")
	mustHave(t, out, "Cleared the witness collection")
	out = r.mustG(t, nil, "pool", "witness", "info", "p")
	mustHave(t, out, "No witness collection is open")
	out = r.mustG(t, nil, "pool", "witness", "clear", "p", "--yes")
	mustHave(t, out, "nothing to clear")
}

func TestPoolBLSGenerate(t *testing.T) {
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "pool", "bls", "generate", "p")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Generated the BLS keys of pool p")
	notLeaked(t, out, "SigningKey", "Signing")
	if _, err := withPass(t, dir, testPass, "pool", "bls", "generate", "p"); err == nil {
		t.Error("BLS keys were generated over existing ones")
	}
	// Refused on mainnet, with the reason, before anything is stored.
	main := copyWorkspace(t)
	os.WriteFile(filepath.Join(main, "spo.toml"), []byte("network = \"mainnet\"\nmode = \"offline\"\n"), 0o600)
	out, err = withPass(t, main, testPass, "pool", "bls", "generate", "p")
	if err == nil || !strings.Contains(err.Error(), "testnet tree") {
		t.Fatalf("%v\n%s", err, out)
	}
}
