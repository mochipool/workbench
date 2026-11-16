package poolops

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// spec: SPO-05e-IF-001, SPO-05e-IF-002, SPO-05e-IN-001, SPO-05e-PRE-002, SPO-05e-INV-001
func TestPoolReferenceResolution(t *testing.T) {
	r := newPoolRig(t)
	r.mustGenerate()
	hexID := hex.EncodeToString(r.poolID[:])
	bech := r.poolID.Bech32()
	other := chain.PoolID{3}
	ok := []string{hexID, bech, "mypool", "mypool.pool", "mypool.json", "mypool.pool.json", "mypool.pool.id", "mypool.pool.id-bech", "./mypool", "MYPOOL" /* the id forms are case-insensitive, names are not */}
	for _, ref := range ok[:len(ok)-1] {
		id, err := resolvePool(readerOf(r), ref)
		if err != nil || id != r.poolID {
			t.Errorf("%q: %v %v", ref, id, err)
		}
	}
	if id, err := resolvePool(readerOf(r), "POOL1"+bech[5:]); err == nil && id != r.poolID {
		t.Errorf("upper-case bech32: %v", id)
	}
	if id, err := resolvePool(readerOf(r), hexUpper(hexID)); err != nil || id != r.poolID {
		t.Errorf("upper-case hex: %v %v", id, err)
	}
	// The order: the id file before the descriptor.
	r.write("mypool.pool.id-bech", []byte(other.Bech32()+"\n"))
	if id, _ := resolvePool(readerOf(r), "mypool"); id != other {
		t.Errorf("the id-bech file comes first: %v", id)
	}
	r.remove("mypool.pool.id-bech")
	r.write("mypool.pool.id", []byte(hex.EncodeToString(other[:])+"\n"))
	if id, _ := resolvePool(readerOf(r), "mypool"); id != other {
		t.Errorf("the id file comes second: %v", id)
	}
	// An invalid id file is refused; upstream goes on with an empty id (SPO-05e-INV-001).
	r.write("mypool.pool.id-bech", []byte("pool1notvalid\n"))
	if _, err := resolvePool(readerOf(r), "mypool"); !errors.Is(err, ErrBadPoolID) {
		t.Errorf("%v", err)
	}
	r.remove("mypool.pool.id-bech")
	r.write("mypool.pool.id", []byte("zz\n"))
	if _, err := resolvePool(readerOf(r), "mypool"); !errors.Is(err, ErrBadPoolID) {
		t.Errorf("%v", err)
	}
	// Nothing resolves.
	if _, err := resolvePool(readerOf(r), "nothing"); !errors.Is(err, ErrPoolUnresolved) {
		t.Errorf("%v", err)
	}
	if _, err := resolvePool(readerOf(r), "pool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"); !errors.Is(err, ErrBadPoolID) {
		t.Errorf("a bech32 id with a bad checksum: %v", err)
	}
}

func hexUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// spec: SPO-05e-EXT-001, SPO-05e-MODE-001, SPO-05e-MODE-002, SPO-05e-PRE-001
func TestCheckPoolOnChain(t *testing.T) {
	r := newPoolRig(t)
	r.mustGenerate()
	st := chain.PoolState{ID: r.poolID, Name: "My Pool", Ticker: "MYPL", Margin: "0.1"}
	cases := []struct {
		name   string
		read   chain.Reading[chain.PoolState]
		status PoolStatus
		reg    bool
	}{
		{"registered", chain.Value(st), StatusRegistered, true},
		{"retiring", chain.Value(chain.PoolState{ID: r.poolID, Status: chain.PoolRetiring, RetiringEpoch: 9}), StatusRetiring, true},
		{"retired", chain.Value(chain.PoolState{ID: r.poolID, Status: chain.PoolRetired}), StatusRetired, false},
		{"never registered", chain.None[chain.PoolState](), StatusNotRegistered, false},
		{"the provider did not say", chain.Unknown[chain.PoolState]("HTTP 502"), StatusUnknown, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			uc := CheckPoolOnChain{Store: r.store, Pools: &ppools{c: r.calls, src: "koios", r: c.read}}
			got, err := uc.Run(ctx, "mypool")
			if err != nil || got.Status != c.status || got.Registered() != c.reg || got.PoolID != r.poolID || got.Bech32 != r.poolID.Bech32() || got.Source != "koios" {
				t.Errorf("%+v %v", got, err)
			}
			if c.status == StatusUnknown && got.Why == "" {
				t.Error("an unknown answer says why")
			}
		})
	}
	uc := CheckPoolOnChain{Store: r.store, Pools: &ppools{c: r.calls, src: "koios", err: errors.New("down")}}
	if _, err := uc.Run(ctx, "mypool"); err == nil {
		t.Error("a failing provider is an error, never not registered")
	}
	if _, err := (CheckPoolOnChain{Store: r.store}).Run(ctx, "mypool"); !errors.Is(err, ErrNoChainReader) {
		t.Errorf("offline: %v", err)
	}
	if _, err := uc.Run(ctx, ""); err == nil {
		t.Error("empty argument")
	}
}
