package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var errDevice = errors.New("fake device went away")

// fakeHW is a hardware exporter: it records what it was asked and answers a
// fixed key. fail makes the export fail.
type fakeHW struct {
	vendor custody.Vendor
	keys   []custody.KeyRef
	paths  []string
	fail   error
}

func (f *fakeHW) Profile() custody.Profile {
	return custody.HardwareProfile(f.vendor, "8.0.8", func(string, string) bool { return true })
}

func (f *fakeHW) ExportHardwareKey(_ context.Context, key custody.KeyRef, path string) (ports.HardwareKey, error) {
	f.keys = append(f.keys, key)
	f.paths = append(f.paths, path)
	if f.fail != nil {
		return ports.HardwareKey{}, f.fail
	}
	return ports.HardwareKey{
		VKey:        []byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"Payment Hardware Verification Key","cborHex":"` + genVKeyHex + `"}`),
		SigningFile: []byte(`{"type":"PaymentHWSigningFileShelley_ed25519","description":"Payment Hardware Signing File","path":["1852H"],"cborXPubKeyHex":"5840` + strings.Repeat("00", 64) + `"}`),
	}, nil
}

func hwDeps(out *bytes.Buffer, g *genFake, hw ports.HardwareKeyExporter) Deps {
	d := genDeps(out, g)
	wire := d.Wire
	d.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := wire(st, o)
		if hw != nil {
			env.Hardware = hw
		} else {
			env.Absent(CapHardware, "the release set of this binary has no cardano-hw-cli, so no hardware wallet can be used")
		}
		return env, err
	}
	return d
}

func TestHardwareFlagsMapToHolderAndPath(t *testing.T) {
	var out bytes.Buffer
	g, hw := &genFake{}, &fakeHW{vendor: custody.VendorLedger}
	dir := t.TempDir()
	if err := runGen(t, hwDeps(&out, g, hw), dir, "wallet", "new", "w", "--hardware", "--account", "3", "--index", "4", "--multisig"); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(hw.keys) != 1 || hw.keys[0].Holder != custody.HolderHardware || hw.keys[0].Role != custody.RolePayment || hw.keys[0].Owner != "w" {
		t.Fatalf("keys %+v", hw.keys)
	}
	if hw.paths[0] != "1854H/1815H/3H/0/4" {
		t.Errorf("path %s", hw.paths[0])
	}
	if g.calls != 0 {
		t.Errorf("a software key was generated %d times", g.calls)
	}

	hw2 := &fakeHW{vendor: custody.VendorLedger}
	if err := runGen(t, hwDeps(&out, g, hw2), dir, "pool", "keys", "generate", "p", "--hardware", "--index", "2"); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(hw2.keys) != 1 || hw2.keys[0].Role != custody.RolePoolCold || hw2.paths[0] != "1853H/1815H/0H/2H" {
		t.Errorf("%+v %v", hw2.keys, hw2.paths)
	}
	if !strings.Contains(out.String(), "on the hardware wallet") {
		t.Errorf("the output does not say where the key is:\n%s", out.String())
	}

	// A wallet with a stake key: hybrid keeps the stake key in the workspace.
	hw3 := &fakeHW{vendor: custody.VendorLedger}
	if err := runGen(t, hwDeps(&out, g, hw3), dir, "wallet", "new", "h", "--stake", "--hardware", "--hybrid"); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(hw3.keys) != 1 || g.calls != 1 {
		t.Errorf("hybrid: %d device keys, %d software keys", len(hw3.keys), g.calls)
	}
}

func TestHardwareOnlyFlagsNeedHardware(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"wallet", "new", "w", "--multisig"}, {"wallet", "new", "w", "--stake", "--hybrid"}, {"drep", "keys", "generate", "d", "--account", "1"}} {
		err := runGen(t, hwDeps(&out, &genFake{}, &fakeHW{}), t.TempDir(), args...)
		if err == nil {
			t.Errorf("%v: accepted", args)
		}
	}
	err := runGen(t, hwDeps(&out, &genFake{}, &fakeHW{}), t.TempDir(), "wallet", "new", "w", "--hardware", "--mnemonic")
	if err == nil || !strings.Contains(err.Error(), "no mnemonic") {
		t.Errorf("%v", err)
	}
}

// ADR 0008: the refusal lists the capability and why, before any prompt or
// opening of the workspace.
func TestHardwareNeedRefusedBeforeAnyPrompt(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, WorkspaceFile), []byte("sealed"), 0o600)
	var out bytes.Buffer
	opened := false
	g := &genFake{}
	d := hwDeps(&out, g, nil)
	d.Terminal = failTerm{t}
	d.Sealed = SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) {
		opened = true
		return nil, nil
	}}
	for _, args := range [][]string{{"pool", "keys", "generate", "p", "--hardware"}, {"wallet", "new", "w", "--hardware"}, {"drep", "keys", "generate", "d", "--hardware"}, {"policy", "new", "x", "--hardware"}} {
		root := NewRoot(d)
		root.SetArgs(append([]string{"-C", dir}, args...))
		err := root.ExecuteContext(context.Background())
		if err == nil || !strings.Contains(err.Error(), "hardware-wallet") || !strings.Contains(err.Error(), "no cardano-hw-cli") {
			t.Errorf("%v: %v", args, err)
		}
	}
	if opened || g.calls != 0 {
		t.Errorf("opened %v, generated %d", opened, g.calls)
	}
}

// A Trezor cannot hold a pool cold key: refused by the plan with no call to
// the device's key generation.
func TestTrezorColdKeyRefusedBeforeTheDevice(t *testing.T) {
	var out bytes.Buffer
	hw := &fakeHW{vendor: custody.VendorTrezor}
	err := runGen(t, hwDeps(&out, &genFake{}, hw), t.TempDir(), "pool", "keys", "generate", "p", "--hardware")
	if err == nil || len(hw.keys) != 0 {
		t.Fatalf("%v; device asked %d times", err, len(hw.keys))
	}
}

// The errors an adapter declares are mapped by Deps.MapError, and the ones of
// app and ports by the command tree.
func TestDeviceErrorsAreMapped(t *testing.T) {
	var out bytes.Buffer
	hw := &fakeHW{vendor: custody.VendorLedger, fail: errDevice}
	d := hwDeps(&out, &genFake{}, hw)
	d.MapError = func(err error) error {
		if errors.Is(err, errDevice) {
			return Explain(err, err.Error()+"\nreconnect the device and run again")
		}
		return err
	}
	err := runGen(t, d, t.TempDir(), "pool", "keys", "generate", "p", "--hardware")
	if err == nil || !errors.Is(err, errDevice) || !strings.Contains(err.Error(), "reconnect the device") {
		t.Errorf("%v", err)
	}

	for _, c := range []struct {
		err  error
		want string
	}{
		{&ports.ErrNotHardwareCanonical{}, "fault in spo"},
		{txflow.ErrNoCanonicalizer, "release set has no cardano-hw-cli"},
		{ports.ErrNoHardwareSigner, "release set has no cardano-hw-cli"},
		{txflow.ErrMixedHolders, "same device"},
		{governance.ErrUnrestrictedNeeded, "--allow-unrestricted"},
	} {
		got := explain(c.err)
		if !errors.Is(got, c.err) && !strings.Contains(got.Error(), c.want) {
			t.Errorf("%v", got)
		}
		if !strings.Contains(got.Error(), c.want) || !strings.Contains(got.Error(), "Nothing was signed") && c.want != "fault in spo" {
			t.Errorf("%v: %q missing in %q", c.err, c.want, got)
		}
	}
}

// Unrestricted mode is never implied: not by the flag, not by a skip, not by a
// missing terminal; only a yes to the question, and without the flag nothing
// is asked.
func TestUnrestrictedConsentIsNeverImplied(t *testing.T) {
	ask := func(flag bool, lines ...string) (bool, error, int) {
		term := &scriptTerm{t: t, lines: lines}
		var out bytes.Buffer
		a := newApp(Deps{Terminal: term, Out: &out, Err: &out})
		ok, err := a.unrestrictedConsent(context.Background(), flag)
		if flag && !strings.Contains(out.String(), "cannot check") {
			t.Errorf("the question does not say what the mode means:\n%s", out.String())
		}
		return ok, err, term.asked
	}
	if ok, err, n := ask(false); ok || err != nil || n != 0 {
		t.Errorf("no flag: %v %v asked %d", ok, err, n)
	}
	for _, ans := range []string{"", "n", "no", "maybe"} {
		if ok, err, _ := ask(true, ans); ok || !errors.Is(err, ErrUnrestrictedDeclined) {
			t.Errorf("answer %q: %v %v", ans, ok, err)
		}
	}
	if ok, err, _ := ask(true); ok || err == nil {
		t.Errorf("no terminal: %v %v", ok, err)
	}
	if ok, err, _ := ask(true, "y"); !ok || err != nil {
		t.Errorf("yes: %v %v", ok, err)
	}
}

func TestUnrestrictedFlagOnlyWhereTheRequestHasIt(t *testing.T) {
	root := NewRoot(Deps{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}})
	has := func(path ...string) bool {
		c, _, err := root.Find(path)
		if err != nil || c == nil {
			t.Fatalf("%v: %v", path, err)
		}
		return c.Flags().Lookup("allow-unrestricted") != nil
	}
	for _, p := range [][]string{{"drep", "register"}, {"drep", "retire"}, {"vote", "submit"}} {
		if !has(p...) {
			t.Errorf("%v has no --allow-unrestricted", p)
		}
	}
	for _, p := range [][]string{{"wallet", "send"}, {"stake", "register"}, {"wallet", "claim-rewards"}} {
		if c, _, err := root.Find(p); err == nil && c.Flags().Lookup("allow-unrestricted") != nil {
			t.Errorf("%v has --allow-unrestricted", p)
		}
	}
}

func TestTxViewIsShownInFull(t *testing.T) {
	var out bytes.Buffer
	a := newApp(Deps{Terminal: &scriptTerm{t: t, lines: []string{"n"}}, Out: &out, Err: &out})
	ttl := uint64(99)
	dep := uint64(2_000_000)
	v := party.TxView{Fee: 170000, TTL: &ttl,
		Outputs:      []party.ViewOutput{{Address: "addr_test1qexample", Lovelace: 5_000_000}},
		Certificates: []party.ViewCert{{Kind: party.CertStakeDeregistration, Credential: "key:abcd", Deposit: &dep}}}
	ok, err := terminalApprover{a}.ApproveSigning(context.Background(), "owner.staking", v)
	if ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	for _, want := range []string{"addr_test1qexample", "5.000000 ADA", "0.170000 ADA", "stake-deregistration", "key:abcd", "slot 99", "owner.staking"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("%q missing:\n%s", want, out.String())
		}
	}
	// No terminal: never signs unseen, and an empty answer is No.
	a2 := newApp(Deps{Terminal: &scriptTerm{t: t}, Out: &out, Err: &out})
	if ok, err := (terminalApprover{a2}).ApproveSigning(context.Background(), "x", v); ok || err == nil {
		t.Errorf("%v %v", ok, err)
	}
	a3 := newApp(Deps{Terminal: &scriptTerm{t: t, lines: []string{""}}, Out: &out, Err: &out})
	if ok, _ := (terminalApprover{a3}).ApproveSigning(context.Background(), "x", v); ok {
		t.Error("an empty answer signed")
	}
	a4 := newApp(Deps{Terminal: &scriptTerm{t: t, lines: []string{"Y"}}, Out: &out, Err: &out})
	if ok, _ := (terminalApprover{a4}).ApproveSigning(context.Background(), "x", v); !ok {
		t.Error("yes did not sign")
	}
}

func TestWitnessSignNeedsAKey(t *testing.T) {
	var out bytes.Buffer
	err := runGen(t, genDeps(&out, &genFake{}), t.TempDir(), "pool", "witness", "sign", "f.witness")
	if err == nil || !strings.Contains(err.Error(), "--key") {
		t.Errorf("%v", err)
	}
}

type fakeBLS struct{ calls int }

func (f *fakeBLS) GenerateBLS(context.Context) (ports.KeyPair, error) {
	f.calls++
	return ports.KeyPair{VKey: []byte(`{"type":"Bls","description":"","cborHex":"5860` + strings.Repeat("11", 96) + `"}`),
		SKey: secret.Take([]byte(`{"type":"BlsSk","description":"","cborHex":"5820` + strings.Repeat("22", 32) + `"}`))}, nil
}

func TestBLSGenerate(t *testing.T) {
	for _, c := range []struct {
		network string
		refused bool
	}{{"preview", false}, {"mainnet", true}} {
		dir := t.TempDir()
		var out bytes.Buffer
		bls := &fakeBLS{}
		d := genDeps(&out, &genFake{})
		wire := d.Wire
		d.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
			env, err := wire(st, o)
			env.BLSKeys = bls
			return env, err
		}
		d.Config = memConfig(map[string]WorkspaceConfig{dir: {Network: c.network, Mode: ModeOffline}})
		err := runGen(t, d, dir, "pool", "bls", "generate", "p")
		if c.refused {
			if err == nil || !strings.Contains(err.Error(), "testnet tree") || bls.calls != 0 {
				t.Errorf("%s: %v, %d calls", c.network, err, bls.calls)
			}
			continue
		}
		if err != nil || bls.calls != 1 {
			t.Fatalf("%s: %v\n%s", c.network, err, out.String())
		}
		if strings.Contains(out.String(), "BlsSk") || strings.Contains(out.String(), strings.Repeat("22", 32)) {
			t.Errorf("the signing key is shown:\n%s", out.String())
		}
		if err := runGen(t, d, dir, "pool", "bls", "generate", "p"); err == nil || !strings.Contains(err.Error(), "already exist") {
			t.Errorf("second generate: %v", err)
		}
	}
}
