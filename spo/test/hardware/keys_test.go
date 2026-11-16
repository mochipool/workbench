package hardware_test

import (
	"context"
	"errors"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

func get(t *testing.T, w *world.World, name string, kind ports.Kind) []byte {
	t.Helper()
	var out []byte
	err := w.Store.View(context.Background(), func(r ports.Reader) error {
		var err error
		out, err = r.Get(ports.Ref{Name: name, Kind: kind})
		return err
	})
	if err != nil {
		t.Fatalf("%s %v: %v", name, kind, err)
	}
	return out
}

func has(w *world.World, name string, kind ports.Kind) bool {
	ok := false
	_ = w.Store.View(context.Background(), func(r ports.Reader) error { ok, _ = r.Exists(ports.Ref{Name: name, Kind: kind}); return nil })
	return ok
}

func description(t *testing.T, vkey []byte) string {
	t.Helper()
	e, err := pool.ParseEnvelope(vkey)
	if err != nil {
		t.Fatal(err)
	}
	return e.Description
}

// A payment account on a Ledger: the verification key and the hardware signing
// file are stored, no signing key is, and the verification key carries the
// hardware marker. A Trezor or no device is refused upfront with nothing stored.
//
// spec: SPO-02-EXT-003, SPO-02-OUT-002, SPO-02-IF-003, SPO-Pfiles-OUT-004, SPO-Pfiles-INV-001
func TestPaymentAccountOnLedger(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	uc := wallet.GeneratePaymentAccount{Store: w.Store, KeyGen: native.SoftwareKeys{}, Addresses: w.Ledger, NetworkID: w.Network, Hardware: w.Exporter()}
	res, err := uc.Run(context.Background(), wallet.GeneratePaymentRequest{Name: "pay", Holder: custody.HolderHardware, Account: 3, Index: 7})
	if err != nil {
		t.Fatal(err)
	}
	if got := description(t, get(t, w, "pay", ports.AddrVKey)); got != "Payment Hardware Verification Key" {
		t.Errorf("description %q", got)
	}
	if !has(w, "pay", ports.AddrHwsFile) || has(w, "pay", ports.AddrSKey) || !has(w, "pay", ports.AddrFile) {
		t.Error("expected .vkey, .hwsfile and .addr, and no .skey")
	}
	if res.Address == "" {
		t.Error("no address")
	}
	call := w.HW.Last("address", "key-gen")
	if got := strings.Join(call, " "); !strings.Contains(got, "--path 1852H/1815H/3H/0/7") {
		t.Errorf("path: %s", got)
	}
	// hwmulti: purpose 1854H.
	if _, err := uc.Run(context.Background(), wallet.GeneratePaymentRequest{Name: "multi", Holder: custody.HolderHardware, Multisig: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.HW.Last("address", "key-gen"), " "); !strings.Contains(got, "--path 1854H/1815H/0H/0/0") {
		t.Errorf("multisig path: %s", got)
	}
}

// With no hardware exporter wired the refusal is the one it has always been,
// before any effect; with a Trezor the pool cold key is refused by the profile.
//
// spec: SPO-02-EXT-003, SPO-04a-EXT-003, SPO-Chw-PRE-003
func TestGenerationRefusedUpfront(t *testing.T) {
	w := world.New(t)
	uc := wallet.GeneratePaymentAccount{Store: w.Store, KeyGen: native.SoftwareKeys{}, Addresses: w.Ledger, NetworkID: w.Network}
	_, err := uc.Run(context.Background(), wallet.GeneratePaymentRequest{Name: "pay", Holder: custody.HolderHardware})
	var un *custody.UnsupportedError
	if err == nil || !strings.Contains(err.Error(), "no signer is configured that can generate keys held by hardware") {
		t.Fatalf("no exporter: %v (%T)", err, err)
	}
	_ = un

	w2 := world.New(t)
	w2.UseHardware("Trezor", "2.7.2")
	cold := poolops.GenerateColdKeys{Store: w2.Store, KeyGen: native.SoftwareKeys{}, Hardware: w2.Exporter()}
	_, err = cold.Run(context.Background(), poolops.GenerateColdKeysRequest{Pool: "p", Holder: custody.HolderHardware})
	if !errors.As(err, &un) {
		t.Fatalf("a Trezor holds no pool cold key: %v", err)
	}
	if n := w2.HW.Prompts(); n != 0 {
		t.Errorf("the device was called %d times for a refused plan", n)
	}
	if has(w2, "p", ports.NodeVKey) {
		t.Error("a refusal stored a file")
	}
}

// A wallet on a Ledger: payment and stake keys on the device (03a hw), the base
// address from both; the hybrid type keeps the stake key in the vault.
//
// spec: SPO-03a-EXT-002, SPO-03a-EXT-004, SPO-03a-INV-001, SPO-03a-OUT-001, SPO-03a-IF-001, SPO-Pfiles-INV-001
func TestWalletOnLedgerAndHybrid(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	uc := wallet.GenerateWalletAccount{Store: w.Store, Payment: native.SoftwareKeys{}, Stake: native.SoftwareKeys{}, Addresses: w.Ledger,
		NetworkID: w.Network, Hardware: w.Exporter()}
	res, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: "hw", Holder: custody.HolderHardware, Account: 2, Index: 5})
	if err != nil {
		t.Fatal(err)
	}
	if res.PaymentAddress == "" || res.StakeAddress == "" {
		t.Fatalf("%+v", res)
	}
	if description(t, get(t, w, "hw.payment", ports.AddrVKey)) != "Payment Hardware Verification Key" ||
		description(t, get(t, w, "hw", ports.StakingVKey)) != "Stake Hardware Verification Key" {
		t.Error("hardware markers")
	}
	if !has(w, "hw.payment", ports.AddrHwsFile) || !has(w, "hw", ports.StakingHwsFile) || has(w, "hw", ports.StakingSKey) {
		t.Error("files")
	}
	calls := w.HW.Calls()
	var paths []string
	for _, c := range calls {
		if len(c) > 2 && c[0] == "address" && c[1] == "key-gen" {
			paths = append(paths, c[3])
		}
	}
	if strings.Join(paths, ",") != "1852H/1815H/2H/0/5,1852H/1815H/2H/2/0" {
		t.Errorf("paths %v", paths)
	}
	// Hybrid: hardware payment, stake key in the vault.
	if _, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: "hy", Holder: custody.HolderHardware, StakeHolder: custody.HolderVault, Multisig: true}); err != nil {
		t.Fatal(err)
	}
	if !has(w, "hy.payment", ports.AddrHwsFile) || !has(w, "hy", ports.StakingSKey) || has(w, "hy", ports.StakingHwsFile) {
		t.Error("hybrid files")
	}
	// A software payment key with a hardware stake key is not a type of 03a.
	if _, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: "bad", StakeHolder: custody.HolderHardware}); err == nil {
		t.Error("software payment with hardware stake was accepted")
	}
}

// A pool cold key on a Ledger: the counter is built from the verification key
// as for a software key; governance keys (DRep, committee) on a Ledger carry the
// hardware markers of their scripts.
//
// spec: SPO-04a-EXT-003, SPO-04a-EXT-004, SPO-04a-INV-002, SPO-04a-IF-003, SPO-21a-EXT-004, SPO-21a-INV-002, SPO-21a-OUT-004,
// spec: SPO-23a-INV-002, SPO-23a-OUT-003, SPO-23b-INV-002, SPO-23b-OUT-003
func TestColdAndGovernanceKeysOnLedger(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	ctx := context.Background()
	cold, err := poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}.
		Run(ctx, poolops.GenerateColdKeysRequest{Pool: "pool", Holder: custody.HolderHardware, Index: 4})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.HW.Last("node", "key-gen"), " "); !strings.Contains(got, "--path 1853H/1815H/0H/4H") {
		t.Errorf("path: %s", got)
	}
	if !has(w, "pool", ports.NodeHwsFile) || has(w, "pool", ports.NodeSKey) || !has(w, "pool", ports.NodeCounter) {
		t.Error("files")
	}
	ctr, err := pool.ParseIssueCounter(get(t, w, "pool", ports.NodeCounter))
	if err != nil || ctr.Next != 0 {
		t.Fatalf("counter %+v %v", ctr, err)
	}
	env, _ := pool.ParseEnvelope(cold.VKey)
	raw, _ := env.Key32()
	if string(ctr.ColdVKey[:]) != string(raw) {
		t.Error("the counter is not over the device's verification key")
	}

	soft := native.SoftwareKeys{}
	drep, err := governance.GenerateDRepKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}.
		Run(ctx, governance.GenerateKeysRequest{Name: "d", Holder: custody.HolderHardware, Source: governance.KeysRandom, Account: 1, Index: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.HW.Last("address", "key-gen"), " "); !strings.Contains(got, "--path 1852H/1815H/1H/3/2") {
		t.Errorf("drep path: %s", got)
	}
	if description(t, drep.VKey) != "Hardware Delegate Representative Verification Key" || !has(w, "d", ports.DRepHwsFile) || has(w, "d", ports.DRepSKey) || !has(w, "d", ports.DRepID) {
		t.Error("drep artefacts")
	}
	if _, err := (governance.GenerateCommitteeHotKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}).
		Run(ctx, governance.GenerateKeysRequest{Name: "h", Holder: custody.HolderHardware, Source: governance.KeysRandom}); err != nil {
		t.Fatal(err)
	}
	if !has(w, "h", ports.CCHotHwsFile) || !has(w, "h", ports.CCHotHash) {
		t.Error("hot key artefacts")
	}
	if _, err := (governance.GenerateCommitteeColdKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}).
		Run(ctx, governance.GenerateKeysRequest{Name: "c", Holder: custody.HolderHardware, Source: governance.KeysRandom}); err != nil {
		t.Fatal(err)
	}
	if !has(w, "c", ports.CCColdHwsFile) {
		t.Error("cold key artefacts")
	}
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) }

type genesis struct{}

func (genesis) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{SystemStart: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), SlotLength: time.Second, EpochLength: 432000,
		SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62, NetworkMagic: 2}, nil
}

type noCounter struct{}

func (noCounter) Source() chain.Source { return "fake chain" }
func (noCounter) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	return chain.None[uint64](), nil
}

// An operational certificate issued with a hardware cold key: the device signs,
// the counter is the stored one, and both counters advance only after success.
// With a Trezor (no cold key) nothing is asked of the device.
//
// spec: SPO-04d-EXT-004, SPO-04d-OUT-002, SPO-04d-PR-003, SPO-04a-EXT-003
func TestOpCertWithHardwareColdKey(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	if _, err := (poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}).
		Run(ctx, poolops.GenerateColdKeysRequest{Pool: "pool", Holder: custody.HolderHardware}); err != nil {
		t.Fatal(err)
	}
	if _, err := (poolops.GenerateKesKey{Store: w.Store, KeyGen: native.KeyGen{}}).Run(ctx, "pool"); err != nil {
		t.Fatal(err)
	}
	uc := poolops.IssueOperationalCertificate{Store: w.Store, Signers: w.Signers(), Tip: w.Chain, Genesis: genesis{}, Counters: noCounter{}, Clock: fixedClock{}, SingleSource: true, OnSingle: noopSingle} // upstream 04d takes the counter from one provider in light and online mode; the port needs that acknowledged (ADR 0006, N7)
	res, err := uc.Run(ctx, "pool", poolops.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w.HW.Count("node", "issue-op-cert") != 1 || res.Counter != 0 || len(res.OpCert) == 0 {
		t.Fatalf("%+v calls=%v", res, w.HW.Calls())
	}
	oc, err := pool.ParseOpCert(res.OpCert)
	if err != nil {
		t.Fatal(err)
	}
	ctr, _ := pool.ParseIssueCounter(get(t, w, "pool", ports.NodeCounter))
	if ctr.Next != 1 || string(oc.ColdVKey[:]) != string(ctr.ColdVKey[:]) {
		t.Errorf("counter after issue %+v", ctr)
	}
}

// A device that fails during the export ends the generation with an error and
// stores nothing, for every key kind that has an export: ERROR and DISCONNECT are
// the adapter's classification, the use case's part is that no file is left.
//
// spec: SPO-02-EXT-003, SPO-04a-PRE-005, SPO-03a-EXT-002, SPO-Chw-INV-002
func TestDeviceFailureDuringExportStoresNothing(t *testing.T) {
	ctx := context.Background()
	for _, action := range []string{"error", "disconnect", "rejected"} {
		w := world.New(t)
		w.UseHardware("Ledger", "8.0.8")
		w.HW.Lazy.Profile()
		w.HW.Set("action", action)
		_, err := poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}.
			Run(ctx, poolops.GenerateColdKeysRequest{Pool: "p", Holder: custody.HolderHardware})
		if err == nil {
			t.Fatalf("%s: no error", action)
		}
		_, err2 := wallet.GeneratePaymentAccount{Store: w.Store, KeyGen: native.SoftwareKeys{}, Addresses: w.Ledger, NetworkID: w.Network, Hardware: w.Exporter()}.
			Run(ctx, wallet.GeneratePaymentRequest{Name: "pay", Holder: custody.HolderHardware})
		if err2 == nil {
			t.Fatalf("%s: no error for the payment key", action)
		}
		for _, k := range []ports.Kind{ports.NodeVKey, ports.NodeHwsFile, ports.NodeCounter} {
			if has(w, "p", k) {
				t.Errorf("%s: %v left behind", action, k)
			}
		}
		if has(w, "pay", ports.AddrVKey) || has(w, "pay", ports.AddrHwsFile) || has(w, "pay", ports.AddrFile) {
			t.Errorf("%s: payment files left behind", action)
		}
	}
}

// The DRep and committee keys are held on a Ledger or a Keystone only; a Trezor
// is refused by the plan before the device is asked. The committee keys use the
// paths 1852H/1815H/<acc>H/4/<idx> (cold) and /5/<idx> (hot).
//
// spec: SPO-21a-PRE-011, SPO-23a-PRE-008, SPO-23b-PRE-007, SPO-23a-EXT-004, SPO-23b-EXT-004, SPO-Chw-PRE-003
func TestGovernanceKeysPathsAndVendors(t *testing.T) {
	ctx := context.Background()
	soft := native.SoftwareKeys{}
	for _, vendor := range []struct{ name, app string }{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		w := world.New(t)
		w.UseHardware(vendor.name, vendor.app)
		req := governance.GenerateKeysRequest{Name: "c", Holder: custody.HolderHardware, Source: governance.KeysRandom, Account: 2, Index: 3}
		if _, err := (governance.GenerateCommitteeColdKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}).Run(ctx, req); err != nil {
			t.Fatalf("%s: %v", vendor.name, err)
		}
		if got := strings.Join(w.HW.Last("address", "key-gen"), " "); !strings.Contains(got, "--path 1852H/1815H/2H/4/3") {
			t.Errorf("cold path: %s", got)
		}
		req.Name = "h"
		if _, err := (governance.GenerateCommitteeHotKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}).Run(ctx, req); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(w.HW.Last("address", "key-gen"), " "); !strings.Contains(got, "--path 1852H/1815H/2H/5/3") {
			t.Errorf("hot path: %s", got)
		}
	}
	w := world.New(t)
	w.UseHardware("Trezor", "2.7.2")
	req := governance.GenerateKeysRequest{Name: "x", Holder: custody.HolderHardware, Source: governance.KeysRandom}
	_, e1 := governance.GenerateDRepKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}.Run(ctx, req)
	_, e2 := governance.GenerateCommitteeColdKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}.Run(ctx, req)
	_, e3 := governance.GenerateCommitteeHotKeys{Store: w.Store, Keys: soft, Hardware: w.Exporter()}.Run(ctx, req)
	for i, err := range []error{e1, e2, e3} {
		var un *custody.UnsupportedError
		if !errors.As(err, &un) {
			t.Errorf("Trezor %d: %v", i, err)
		}
	}
	if w.HW.Count("address", "key-gen") != 0 {
		t.Error("a refused plan reached the device")
	}
}

// A policy key on a Ledger: at 1855H/1815H/0H, with the mint marker, and the
// policy id is the device's answer, which agrees with the id of the script. The
// device's answer is taken from the stored files.
//
// spec: SPO-10-EXT-002, SPO-10-EXT-005, SPO-10-OUT-004, SPO-10-INV-005
func TestPolicyOnLedgerAsksTheDeviceForTheId(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	uc := assets.GeneratePolicy{Store: w.Store, KeyGen: native.SoftwareKeys{}, Policies: w.Ledger, Tip: w.Chain, Hardware: w.Exporter(), PolicyIDer: w.HW.Lazy}
	res, err := uc.Run(ctx, assets.GeneratePolicyRequest{Name: "pol", Holder: custody.HolderHardware})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.HW.Last("address", "key-gen"), " "); !strings.Contains(got, "--path 1855H/1815H/0H") {
		t.Errorf("path: %s", got)
	}
	if description(t, get(t, w, "pol", ports.PolicyVKey)) != "Mint Hardware Verification Key" || !has(w, "pol", ports.PolicyHwsFile) || has(w, "pol", ports.PolicySKey) {
		t.Error("policy artefacts")
	}
	if w.HW.Count("transaction", "policyid") != 1 {
		t.Errorf("the device was not asked for the policy id: %v", w.HW.Calls())
	}
	if got := strings.TrimSpace(string(get(t, w, "pol", ports.PolicyID))); got != res.PolicyID {
		t.Errorf("stored id %s, result %s", got, res.PolicyID)
	}
}
