package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// changing answers one way the first time it is asked and another way after,
// like a provider whose view moves between two reads.
type changing struct {
	src          chain.Source
	first, later chain.Reading[chain.PoolInfo]
	asked        int
}

func (c *changing) Source() chain.Source { return c.src }
func (c *changing) PoolInfo(context.Context, chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	c.asked++
	if c.asked == 1 {
		return c.first, nil
	}
	return c.later, nil
}

// The registration data is read once: Fetch reads and cross-checks, and every
// Run that is given the result reads nothing from the chain, so what is written
// is what the operator was shown even when the provider answers differently
// the second time.
//
// spec: ADR 0006 (pool import)
func TestImportReadsTheChainOnceAndWritesWhatWasConfirmed(t *testing.T) {
	pools, meta := recordedApex(t)
	first, _ := pools.info.Get()
	later := first
	later.RewardAddr = "stake_test1uqevilreplaced"
	later.Owners = []string{"stake_test1uqevilreplaced"}
	primary := &changing{src: "fake", first: chain.Value(first), later: chain.Value(later)}
	st := newMem()
	uc := pools.uc(meta, st)
	uc.Pools, uc.Cross = primary, secondPools{pools}
	pools.info = chain.Value(first)

	src := PoolInfoSource{PoolID: apexBech}
	f, err := uc.Fetch(context.Background(), src, false)
	if err != nil {
		t.Fatal(err)
	}
	dry, err := uc.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, DryRun: true, Fetched: f})
	if err != nil {
		t.Fatal(err)
	}
	res, err := uc.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, Fetched: f})
	if err != nil {
		t.Fatal(err)
	}
	if primary.asked != 1 || len(meta.asked) != 1 {
		t.Errorf("the chain was read %d times and the metadata fetched %d times, want once each", primary.asked, len(meta.asked))
	}
	if dry.Info.RewardAddr != first.RewardAddr || res.Info.RewardAddr != first.RewardAddr {
		t.Errorf("shown %q, written %q, confirmed %q", dry.Info.RewardAddr, res.Info.RewardAddr, first.RewardAddr)
	}
	if d := descriptor(t, st, "apex"); strings.Contains(string(st.files[ports.NamedRef{Name: "apex", Kind: ports.PoolDescriptor}]), "evilreplaced") || d == nil {
		t.Error("the descriptor holds the second answer")
	}
}

// The single source of the data written is recorded before the first write; a
// failing hook writes nothing; a dry run records nothing; an info file or two
// agreeing sources need no record.
//
// spec: ADR 0006 (single source is written to the audit log before the effect)
func TestImportRecordsTheSingleSourceBeforeWriting(t *testing.T) {
	pools, meta := recordedApex(t)
	src := PoolInfoSource{PoolID: apexBech}
	var reads []string
	st := newMem()
	uc := pools.uc(meta, st)
	uc.Cross = nil
	uc.OnSingle = func(_ context.Context, read, source string) error {
		if len(st.files) != 0 {
			t.Error("something was written before the record")
		}
		reads = append(reads, read+" ["+source+"]")
		return nil
	}
	f, err := uc.Fetch(context.Background(), src, true)
	if err != nil || !f.Single {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := uc.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, DryRun: true, Fetched: f}); err != nil || len(reads) != 0 {
		t.Fatalf("dry run: %v, records %v", err, reads)
	}
	if res, err := uc.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, Fetched: f}); err != nil || !res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
	if len(reads) != 1 || !strings.Contains(reads[0], "[fake]") || len(st.files) == 0 {
		t.Errorf("records %v, %d files", reads, len(st.files))
	}

	// A failing hook: nothing written.
	st2 := newMem()
	uc2 := pools.uc(meta, st2)
	uc2.Cross = nil
	uc2.OnSingle = func(context.Context, string, string) error { return errors.New("audit log full") }
	if _, err := uc2.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, SingleSource: true}); err == nil || err.Error() != "audit log full" || len(st2.files) != 0 {
		t.Fatalf("%v, %d files", err, len(st2.files))
	}
	// Missing hook with the acknowledgement: refused.
	uc3 := pools.uc(meta, newMem())
	uc3.Cross = nil
	if _, err := uc3.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, SingleSource: true}); !errors.Is(err, ports.ErrNoSingleSourceHook) {
		t.Fatalf("%v", err)
	}
	// Two agreeing sources: no record, no hook needed.
	uc4 := pools.uc(meta, newMem())
	if res, err := uc4.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: src, SingleSource: true}); err != nil || res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
}

// Fields both providers state are compared, an empty value on one side against
// a value on the other is a difference, and the metadata URL and hash and the
// VRF key hash are among them.
//
// spec: ADR 0006 (pool import cross-check)
func TestImportCrossCheckCoversMetadataVRFAndEmptyOwnersRelays(t *testing.T) {
	pools, meta := recordedApex(t)
	info, _ := pools.info.Get()
	if len(info.Owners) == 0 || len(info.Relays) == 0 {
		t.Fatal("the recorded pool has no owners or relays")
	}
	for name, mod := range map[string]func(*chain.PoolInfo){
		"metadata url":  func(i *chain.PoolInfo) { i.MetaURL = "https://elsewhere.example/p.json" },
		"metadata hash": func(i *chain.PoolInfo) { i.MetaHash = strings.Repeat("0", 64) },
		"vrf key hash":  func(i *chain.PoolInfo) { i.VRFKeyHash = strings.Repeat("1", 64) },
		"owners":        func(i *chain.PoolInfo) { i.Owners = nil },
		"relays":        func(i *chain.PoolInfo) { i.Relays = nil },
	} {
		o := info
		mod(&o)
		for _, single := range []bool{false, true} {
			uc := pools.uc(meta, newMem())
			uc.Cross = varying{"web", chain.Value(o)}
			_, err := uc.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: PoolInfoSource{PoolID: apexBech}, DryRun: true, SingleSource: single})
			if !errors.Is(err, ErrImportSourcesDisagree) || !strings.Contains(err.Error(), name) {
				t.Errorf("%s (single=%v): %v", name, single, err)
			}
		}
	}
}
