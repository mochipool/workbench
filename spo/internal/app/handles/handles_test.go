package handles

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/handle"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var policy = func() [28]byte { p, _ := handle.Policy(handle.PolicyCurrent); return p }()

const (
	alice  = "addr_test1qp20v9uqgpuv9v2zv5rufqtwp930fg8e44e3cde8thg2u20tepjkemk4v508nmgce4dcs0s26lxqkq9ka0vk6ytthtqqe4gct5"
	bob    = "addr_test1qz56x54rn7ptkgtqajzkcy28e0u2c5gkugxgv0yepmmpujdrdk30n6fuqhwuk330f8sm7xq7jv6zrkewufvum2ms49sqv6zmx9"
	script = "addr_test1wscript"
)

type src struct{}

func (src) Source() chain.Source { return "test" }

type holders struct {
	src
	by    map[string][]chain.Address // key: asset name hex
	err   error
	calls []string
	pols  [][28]byte
}

func (h *holders) AssetHolders(_ context.Context, p [28]byte, n string) ([]chain.Address, error) {
	h.calls = append(h.calls, n)
	h.pols = append(h.pols, p)
	return h.by[n], h.err
}

type directory struct {
	src
	rec ports.HandleRecord
	err error
	got string
}

func (d *directory) ResolveHandle(_ context.Context, n string) (ports.HandleRecord, error) {
	d.got = n
	return d.rec, d.err
}

type datums struct {
	src
	rows []ports.InlineDatum
	err  error
}

func (d datums) AssetInlineDatums(context.Context, [28]byte, string) ([]ports.InlineDatum, error) {
	return d.rows, d.err
}

type utxos struct {
	src
	by    map[chain.Address][]chain.Utxo
	err   error
	calls int
}

func (u *utxos) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	u.calls++
	return u.by[a], u.err
}

type inspector struct{}

func (inspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	switch {
	case a == script:
		return ports.AddressInfo{Kind: ports.AddrEnterprise, PaymentIsScript: true}, errors.New("not a key address")
	case strings.HasPrefix(string(a), "addr_test1q"):
		return ports.AddressInfo{Kind: ports.AddrBase}, nil
	case strings.HasPrefix(string(a), "stake"):
		return ports.AddressInfo{Kind: ports.AddrReward}, nil
	}
	return ports.AddressInfo{}, errors.New("not an address")
}

type sync struct {
	src
	ok  bool
	err error
}

func (s sync) Synced(context.Context) (bool, error) { return s.ok, s.err }

func holding(nameHex string, n int) []chain.Utxo {
	name, _ := hex.DecodeString(nameHex)
	var out []chain.Utxo
	for i := 0; i < n; i++ {
		out = append(out, chain.Utxo{Index: uint32(i), Lovelace: 2_000_000,
			Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: policy, Name: name}, Quantity: 1}}})
	}
	return out
}

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

type rig struct {
	h *holders
	d *directory
	u *utxos
	r Resolver
}

func newRig() *rig {
	g := &rig{h: &holders{by: map[string][]chain.Address{}}, d: &directory{}, u: &utxos{by: map[chain.Address][]chain.Utxo{}}}
	g.r = Resolver{Policy: policy, Holders: g.h, Directory: g.d, Utxos: g.u, Addresses: inspector{}}
	return g
}

// A classic root handle: the asset name is the name's bytes, one holder, the
// holder's outputs carry the asset once. The text is lowercased first, the
// result is a value and the holder's outputs come with it for the caller to
// reuse.
//
// spec: SPO-Caddr-IF-001, SPO-Caddr-IF-002, SPO-Caddr-OUT-007, SPO-Caddr-EXT-002, SPO-Caddr-INV-003, SPO-Caddr-INV-004, SPO-Caddr-EXT-005, SPO-Caddr-INV-006, SPO-Caddr-INV-009, SPO-Caddr-MODE-001, SPO-Caddr-INV-002
func TestClassicRoot(t *testing.T) {
	g := newRig()
	g.h.by[hx("alice")] = []chain.Address{alice}
	g.u.by[alice] = holding(hx("alice"), 1)
	got, err := g.r.Resolve(context.Background(), "$AlIcE")
	if err != nil || got.Address != alice || got.Kind != RootClassic || got.VerifiedBy != "holder utxo" || len(got.Utxos) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if len(g.h.calls) != 1 || g.h.calls[0] != hx("alice") || g.h.pols[0] != policy {
		t.Errorf("lookups %v %x: the configured policy and the plain name hex are asked", g.h.calls, g.h.pols)
	}
}

// A CIP-68 root: the classic lookup finds nothing (or several), the second
// asks with the 000de140 label and needs exactly one holder. An asset of
// another policy at the holder does not count (policy trust).
//
// spec: SPO-Caddr-EXT-003, SPO-Caddr-INV-003, SPO-Caddr-PRE-006, SPO-Caddr-INV-009
func TestCIP68RootAndItsFailures(t *testing.T) {
	g := newRig()
	n := handle.LabelCIP68 + hx("alice")
	g.h.by[n] = []chain.Address{alice}
	g.u.by[alice] = holding(n, 1)
	got, err := g.r.Resolve(context.Background(), "$alice")
	if err != nil || got.Kind != RootCIP68 || got.AssetNameHex != n || len(g.h.calls) != 2 {
		t.Fatalf("%+v %v %v", got, err, g.h.calls)
	}

	// Several holders of the classic name: the CIP-68 lookup decides.
	g = newRig()
	g.h.by[hx("alice")] = []chain.Address{alice, bob}
	g.h.by[n] = []chain.Address{alice}
	g.u.by[alice] = holding(n, 1)
	if got, err := g.r.Resolve(context.Background(), "$alice"); err != nil || got.Kind != RootCIP68 {
		t.Fatalf("classic ambiguous, cip68 unique: %+v %v", got, err)
	}

	// Neither: not found. Several in both: reported as ambiguous, apart.
	g = newRig()
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no holder: %v", err)
	}
	g.h.by[hx("alice")] = []chain.Address{alice, bob}
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrAmbiguous) {
		t.Errorf("two holders: %v", err)
	}

	// The same asset name under another policy does not satisfy the holder check.
	g = newRig()
	g.h.by[hx("alice")] = []chain.Address{alice}
	other := holding(hx("alice"), 1)
	other[0].Assets[0].Asset.Policy[0] ^= 0xff
	g.u.by[alice] = other
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotHeld) {
		t.Errorf("an asset of another policy counted: %v", err)
	}
}

// A failed lookup does not fall back to the next one, and every precondition
// is an error value.
//
// spec: SPO-Caddr-PRE-002, SPO-Caddr-PRE-003, SPO-Caddr-PRE-004, SPO-Caddr-PRE-005, SPO-Caddr-PRE-007
func TestPreconditions(t *testing.T) {
	g := newRig()
	g.h.err = errors.New("koios down")
	if _, err := g.r.Resolve(context.Background(), "$alice"); err == nil || len(g.h.calls) != 1 {
		t.Errorf("a failed classic lookup: %v after %d calls (no fallback)", err, len(g.h.calls))
	}

	g = newRig()
	g.r.Offline = true
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrOffline) || len(g.h.calls) != 0 {
		t.Errorf("offline: %v", err)
	}
	g = newRig()
	g.r.Holders = nil
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNoChainProvider) {
		t.Errorf("no provider: %v", err)
	}
	for _, bad := range []string{"alice", "$", "$a b", "$" + strings.Repeat("a", 16), "$a@", "$@b", "$a@b@c", "$ä"} {
		g = newRig()
		if _, err := g.r.Resolve(context.Background(), bad); !errors.Is(err, handle.ErrFormat) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	g = newRig()
	g.r.Directory = nil
	if _, err := g.r.Resolve(context.Background(), "$sub@root"); !errors.Is(err, ErrNoDirectory) {
		t.Errorf("no directory: %v", err)
	}
	// A root handle needs no directory.
	g.h.by[hx("alice")] = []chain.Address{alice}
	g.u.by[alice] = holding(hx("alice"), 1)
	if _, err := g.r.Resolve(context.Background(), "$alice"); err != nil {
		t.Errorf("root without a directory: %v", err)
	}
}

// The holder must be a payment address, the provider must be synced when a
// sync gate is composed (online; light mode has none), and the holder's
// outputs must carry the asset exactly once.
//
// spec: SPO-Caddr-PRE-009, SPO-Caddr-PRE-010, SPO-Caddr-INV-006, SPO-Caddr-MODE-001
func TestHolderVerification(t *testing.T) {
	g := newRig()
	g.h.by[hx("alice")] = []chain.Address{"stake_test1uxx"}
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotPayment) || g.u.calls != 0 {
		t.Errorf("a reward address: %v (outputs read %d times)", err, g.u.calls)
	}
	g.h.by[hx("alice")] = []chain.Address{script}
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotPayment) {
		t.Errorf("a script address: %v", err)
	}

	g = newRig()
	g.h.by[hx("alice")] = []chain.Address{alice}
	g.u.by[alice] = holding(hx("alice"), 1)
	g.r.Sync = sync{ok: false}
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotSynced) || g.u.calls != 0 {
		t.Errorf("unsynced: %v (outputs read %d times)", err, g.u.calls)
	}
	g.r.Sync = sync{err: errors.New("down")}
	if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotSynced) {
		t.Errorf("sync error: %v", err)
	}
	g.r.Sync = sync{ok: true}
	if _, err := g.r.Resolve(context.Background(), "$alice"); err != nil {
		t.Errorf("synced: %v", err)
	}
	g.r.Sync = nil // light mode
	if _, err := g.r.Resolve(context.Background(), "$alice"); err != nil {
		t.Errorf("light mode: %v", err)
	}

	for _, n := range []int{0, 2} {
		g.u.by[alice] = holding(hx("alice"), n)
		if _, err := g.r.Resolve(context.Background(), "$alice"); !errors.Is(err, ErrNotHeld) {
			t.Errorf("%d outputs hold the asset: %v", n, err)
		}
	}
	g.u.err = errors.New("down")
	if _, err := g.r.Resolve(context.Background(), "$alice"); err == nil {
		t.Error("an output query failure was swallowed")
	}
}

// A CIP-68 sub-handle: the Handle API names the address and the asset name,
// which must be the label and the handle's own name; the chain confirms the
// holder.
//
// spec: SPO-Caddr-EXT-004, SPO-Caddr-INV-005, SPO-Caddr-PRE-008, SPO-Caddr-PRE-009, SPO-Caddr-INV-006, SPO-Caddr-MODE-001
func TestSubHandleOnChain(t *testing.T) {
	g := newRig()
	n := handle.LabelCIP68 + hx("sub@root")
	g.d.rec = ports.HandleRecord{AssetNameHex: n, Address: alice}
	g.u.by[alice] = holding(n, 1)
	got, err := g.r.Resolve(context.Background(), "$SUB@Root")
	if err != nil || got.Kind != SubCIP68 || got.Address != alice || g.d.got != "sub@root" || len(g.h.calls) != 0 {
		t.Fatalf("%+v %v asked %q", got, err, g.d.got)
	}
	// The directory's failures are the directory's errors, 404 and 202 included.
	for _, e := range []error{ports.ErrHandleNotFound, ports.ErrHandleDirectoryBehind, errors.New("500")} {
		g.d.err = e
		if _, err := g.r.Resolve(context.Background(), "$sub@root"); !errors.Is(err, e) {
			t.Errorf("%v: got %v", e, err)
		}
	}
	// Not a payment address, even before any holder check.
	g.d.err = nil
	g.d.rec.Address = "stake_test1uxx"
	g.u.calls = 0
	if _, err := g.r.Resolve(context.Background(), "$sub@root"); !errors.Is(err, ErrNotPayment) || g.u.calls != 0 {
		t.Errorf("%v", err)
	}
	// The directory names an address that does not hold the asset.
	g.d.rec.Address = bob
	if _, err := g.r.Resolve(context.Background(), "$sub@root"); !errors.Is(err, ErrNotHeld) {
		t.Errorf("a claim the chain does not support: %v", err)
	}
}

const (
	virtualName = "000000003030664068616c" // recorded: $00f@hal on preview
	virtualAddr = "addr_test1qz56x54rn7ptkgtqajzkcy28e0u2c5gkugxgv0yepmmpujdrdk30n6fuqhwuk330f8sm7xq7jv6zrkewufvum2ms49sqv6zmx9"
)

// A virtual sub-handle has no output of its own: the address the directory
// states must equal the address in the inline datum of the asset's output. A
// different address, no datum and several outputs are refusals. No sync gate
// applies.
//
// spec: SPO-Caddr-EXT-006, SPO-Caddr-PRE-011, SPO-Caddr-INV-007, SPO-Caddr-INV-008, SPO-Caddr-PRE-012, SPO-Caddr-PRE-010, SPO-Caddr-OUT-007
func TestVirtualSubHandle(t *testing.T) {
	addrBytes, _ := hex.DecodeString("00a9a352a39f82bb2160ec856c1147cbf8ac5116e20c863c990ef61e49a36da2f9e93c05ddcb462f49e1bf181e933421db2ee259cdab70a960")
	enc, _ := chain.Bech32Encode("addr_test", addrBytes)
	if enc != virtualAddr {
		t.Fatalf("the fixture address does not encode: %s", enc)
	}
	// The reader looks for the key text and then the `ada` key with the
	// 57-byte string header; the real datum is tested against Koios' record.
	datum := "52" + "7265736f6c7665645f616464726573736573" + "a1" + "436164615839" + hex.EncodeToString(addrBytes) + "ff"

	g := newRig()
	g.d.rec = ports.HandleRecord{AssetNameHex: virtualName, Address: virtualAddr}
	g.r.Datums = datums{rows: []ports.InlineDatum{{CBORHex: datum}}}
	g.r.Sync = sync{ok: false} // no gate for virtual handles
	got, err := g.r.Resolve(context.Background(), "$00f@hal")
	if err != nil || got.Kind != SubVirtual || got.Address != virtualAddr || got.VerifiedBy != "inline datum" || got.Utxos != nil || g.u.calls != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	// The directory lies about the address.
	g.d.rec.Address = alice
	if _, err := g.r.Resolve(context.Background(), "$00f@hal"); !errors.Is(err, ErrDatumMismatch) {
		t.Errorf("a different address: %v", err)
	}
	g.d.rec.Address = virtualAddr
	for name, rows := range map[string][]ports.InlineDatum{
		"no output":       nil,
		"two outputs":     {{CBORHex: datum}, {CBORHex: datum}},
		"no inline datum": {{}},
		"unreadable":      {{CBORHex: "d8799f00ff"}},
	} {
		g.r.Datums = datums{rows: rows}
		if _, err := g.r.Resolve(context.Background(), "$00f@hal"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	g.r.Datums = datums{err: errors.New("down")}
	if _, err := g.r.Resolve(context.Background(), "$00f@hal"); err == nil {
		t.Error("a datum query failure was swallowed")
	}
}

// Upstream returns the directory's address for a sub-handle whose asset name
// has neither label, with no verification at all (SPO-Caddr-SEC-001).
// Decision: fix. The port refuses it, and also refuses a label whose rest is
// not the handle's own name (the directory would be answering for another
// asset).
//
// spec: SPO-Caddr-SEC-001
func TestUnverifiableSubHandlesAreRefused(t *testing.T) {
	g := newRig()
	for _, name := range []string{"deadbeef" + hx("sub@root"), hx("sub@root"), handle.LabelCIP68 + hx("other@root"), handle.LabelVirtual + hx("other@root"), ""} {
		g.d.rec = ports.HandleRecord{AssetNameHex: name, Address: alice}
		g.u.by[alice] = holding(name, 1)
		if got, err := g.r.Resolve(context.Background(), "$sub@root"); !errors.Is(err, ErrUnverifiable) {
			t.Errorf("asset name %q: %+v %v", name, got, err)
		}
	}
}
