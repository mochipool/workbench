package hardware_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/catalyst"
	"github.com/mochipool/workbench/spo/internal/app/poolkey"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

const publicPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func storeHas(t *testing.T, w *world.World, ref ports.Ref) bool {
	t.Helper()
	var ok bool
	if err := w.Store.View(context.Background(), func(r ports.Reader) error {
		var err error
		ok, err = r.Exists(ref)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return ok
}

// calidusWorld has a Calidus key in the vault and a pool cold key on the device.
func calidusWorld(t *testing.T, vendor, app string) *world.World {
	t.Helper()
	w := world.New(t)
	w.UseHardware(vendor, app)
	ctx := context.Background()
	m := secret.Take([]byte(publicPhrase))
	defer m.Destroy()
	if _, err := (poolkey.GenerateCalidusKey{Store: w.Store, Deriver: native.SoftwareKeys{}, Mnemonics: native.SoftwareKeys{}}).
		Run(ctx, poolkey.GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	return w
}

func coldOnDevice(t *testing.T, w *world.World) {
	t.Helper()
	if _, err := (poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}).
		Run(context.Background(), poolops.GenerateColdKeysRequest{Pool: "p", Place: custody.PlaceHardware}); err != nil {
		t.Fatal(err)
	}
}

// The Calidus registration signed by the pool cold key on a Ledger and on a
// Keystone (15 `genmeta` with a hardware cold key): the device is asked with the
// argument vector of the spec, the operator is shown the hash the device will
// display before anything is sent to it, and the stored registration verifies as
// a CIP-88 registration for the pool whose id is the hash of the device's key.
//
// spec: SPO-15-EXT-004, SPO-15-EXT-005, SPO-15-INV-002, SPO-15-INV-005, SPO-15-INV-006, SPO-15-OUT-003, SPO-15-PR-001
func TestCalidusRegistrationWithLedgerAndKeystoneColdKey(t *testing.T) {
	for _, dev := range [][2]string{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		ctx := context.Background()
		w := calidusWorld(t, dev[0], dev[1])
		coldOnDevice(t, w)
		var shown []poolkey.DeviceSigning
		uc := poolkey.GenerateCalidusRegistration{Store: w.Store, Signers: w.Signers(), Clock: fixedClock{},
			BeforeDevice: func(_ context.Context, d poolkey.DeviceSigning) error { shown = append(shown, d); return nil }}
		res, err := uc.Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "cal", Pool: "p", Nonce: 4242})
		if err != nil {
			t.Fatalf("%s: %v", dev[0], err)
		}
		if len(shown) != 1 || shown[0].PoolBech != res.PoolBech || shown[0].Nonce != 4242 || len(shown[0].DeviceHash) != 56 {
			t.Errorf("%s: the operator was shown %+v", dev[0], shown)
		}
		argv := w.HW.Last("message", "sign")
		if len(argv) == 0 || strings.Contains(strings.Join(argv, " "), "--hashed") {
			t.Fatalf("%s: argv %v", dev[0], argv)
		}
		back, err := cose.VerifyCip88(res.CBOR)
		if err != nil || back.Nonce != 4242 || back.PoolID != res.PoolID {
			t.Errorf("%s: %+v %v", dev[0], back, err)
		}
		if id, _ := cose.CalidusID(back.CalidusPub[:]); id != res.CalidusID {
			t.Errorf("%s: calidus id %s", dev[0], id)
		}
		if !storeHas(t, w, res.Ref) {
			t.Errorf("%s: the registration was not stored", dev[0])
		}
	}
}

// A misbehaving tool, a declined confirmation, a Trezor and a cold key of another
// pool are refused: nothing is stored, and the device is not asked when the plan or
// the operator says no.
//
// spec: SPO-15-EXT-005, SPO-15-PR-001, SPO-15-EXT-004, SPO-Chw-PRE-003
func TestCalidusRegistrationRefusals(t *testing.T) {
	ctx := context.Background()
	w := calidusWorld(t, "Ledger", "8.0.8")
	coldOnDevice(t, w)
	run := func(uc poolkey.GenerateCalidusRegistration) error {
		_, err := uc.Run(ctx, poolkey.CalidusRegistrationRequest{Calidus: "cal", Pool: "p", Nonce: 1})
		return err
	}
	base := poolkey.GenerateCalidusRegistration{Store: w.Store, Signers: w.Signers(), Clock: fixedClock{}}
	for _, m := range []string{"msgwrongpayload", "msgbadsig", "msgwrongkey", "msgaddr", "msgtruncated"} {
		w.HW.Set("misbehave", m)
		if err := run(base); err == nil {
			t.Errorf("%s accepted", m)
		}
	}
	w.HW.Set("misbehave", "")
	for _, a := range []string{"disconnect", "rejected", "error"} {
		w.HW.Set("action", a)
		if err := run(base); err == nil {
			t.Errorf("action %s accepted", a)
		}
	}
	w.HW.Set("action", "ok")
	if files, _ := filepath.Glob(filepath.Join(w.Dir, "*calidus-registration*")); len(files) != 0 {
		t.Errorf("a refused registration was stored: %v", files)
	}
	// Declined at the confirmation: the device is never asked to sign.
	before := w.HW.Count("message", "sign")
	declined := base
	declined.BeforeDevice = func(context.Context, poolkey.DeviceSigning) error { return errors.New("declined") }
	if err := run(declined); err == nil || w.HW.Count("message", "sign") != before {
		t.Errorf("declined: %v (%d calls)", err, w.HW.Count("message", "sign")-before)
	}
	// A Trezor: refused by the plan before the tool is called.
	hw := w.UseHardware("Trezor", "2.7.2")
	hw.Lazy.Profile()
	p := hw.Prompts()
	var ue *custody.UnsupportedError
	if err := run(poolkey.GenerateCalidusRegistration{Store: w.Store, Signers: w.Signers(), Clock: fixedClock{}}); !errors.As(err, &ue) || hw.Prompts() != p {
		t.Errorf("trezor: %v", err)
	}
	// A Calidus key cannot be made on a device, and no hardware key signs a text.
	if _, err := (poolkey.GenerateCalidusKey{Store: w.Store, Deriver: native.SoftwareKeys{}, Mnemonics: native.SoftwareKeys{}}).
		Run(ctx, poolkey.GenerateCalidusKeyRequest{Name: "hwcal", Place: custody.PlaceHardware}); !errors.Is(err, poolkey.ErrHardwareCalidusSuspended) {
		t.Errorf("hardware calidus: %v", err)
	}
	// A hardware signing file alone is no Calidus signing key (the flag that
	// used to say "on hardware" is gone: the directory decides).
	if err := w.Store.Update(ctx, func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: "hwonly", Kind: ports.CalidusHwsFile}, []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := (poolkey.SignWithCalidusKey{Store: w.Store, Signers: w.Signers()}).Run(ctx, "hwonly", []byte("x")); !errors.Is(err, poolkey.ErrMissingFile) {
		t.Errorf("hardware text signing: %v", err)
	}
}

// catalystWorld has a wallet `hw` on a Ledger (payment key 0/0, stake key 2/0).
func catalystWorld(t *testing.T) (*world.World, string) {
	t.Helper()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	acc := account(t, w, "hw", custody.PlaceHardware, 0)
	return w, string(acc.PaymentAddress)
}

// A voting key on a Ledger (09a `new hw`): only the verification key and the
// hardware signing file are stored, nothing a mnemonic or a signing key would be;
// a Keystone and a Trezor are refused before the device is contacted, and the QR
// code of a hardware voting key is refused.
//
// spec: SPO-09a-EXT-002, SPO-09a-OUT-004, SPO-09a-OUT-009, SPO-09a-PRE-008
func TestVotingKeyOnLedger(t *testing.T) {
	ctx := context.Background()
	w, _ := catalystWorld(t)
	res, err := (catalyst.GenerateVotingKey{Store: w.Store, Hardware: w.Exporter()}).Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "v", Place: custody.PlaceHardware, Account: 1, Index: 2})
	if err != nil {
		t.Fatal(err)
	}
	argv := w.HW.Last("address", "key-gen")
	if got := strings.Join(argv, " "); !strings.Contains(got, "--path 1694H/1815H/1H/0/2") {
		t.Errorf("argv %v", argv)
	}
	for _, k := range []ports.Kind{ports.VotingVKey, ports.VotingHwsFile} {
		if !storeHas(t, w, ports.Ref{Name: "v", Kind: k}) {
			t.Errorf("no %s", k)
		}
	}
	for _, k := range []ports.Kind{ports.VotingSKey, ports.VotingPKey, ports.VotingMnemonics} {
		if storeHas(t, w, ports.Ref{Name: "v", Kind: k}) {
			t.Errorf("a hardware voting key has a %s", k)
		}
	}
	if !strings.HasPrefix(res.PKey, "cvote_vk1") {
		t.Errorf("public key %q", res.PKey)
	}
	// The QR code of a hardware key is refused.
	_, err = (catalyst.ExportVotingKeyQR{Store: w.Store, Source: native.VotingKeyQR{Vault: w.Store}, Renderer: failingRenderer{}, Auditor: failingAuditor{}}).
		Run(ctx, catalyst.QRRequest{Name: "v", PIN: []byte("1234")})
	if !errors.Is(err, catalyst.ErrHardwareVotingKey) {
		t.Errorf("qr: %v", err)
	}
	// Other vendors, and no hardware signer at all.
	for _, v := range [][2]string{{"Keystone", "1.7.7"}, {"Trezor", "2.7.2"}} {
		hw := w.UseHardware(v[0], v[1])
		hw.Lazy.Profile()
		p := hw.Prompts()
		var ue *custody.UnsupportedError
		_, err := (catalyst.GenerateVotingKey{Store: w.Store, Hardware: w.Exporter()}).Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "o", Place: custody.PlaceHardware})
		if !errors.As(err, &ue) || hw.Prompts() != p || storeHas(t, w, ports.Ref{Name: "o", Kind: ports.VotingVKey}) {
			t.Errorf("%s: %v", v[0], err)
		}
	}
	var ue *custody.UnsupportedError
	if _, err := (catalyst.GenerateVotingKey{Store: w.Store}).Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "n", Place: custody.PlaceHardware}); !errors.As(err, &ue) {
		t.Errorf("no hardware signer: %v", err)
	}
	// A hardware key cannot take a mnemonic.
	m := secret.Take([]byte(publicPhrase))
	defer m.Destroy()
	w.UseHardware("Ledger", "8.0.8")
	if _, err := (catalyst.GenerateVotingKey{Store: w.Store, Hardware: w.Exporter()}).Run(ctx, catalyst.GenerateVotingKeyRequest{Name: "m", Place: custody.PlaceHardware, Mnemonic: m}); err == nil {
		t.Error("a mnemonic for a hardware key")
	}
}

type failingRenderer struct{}

func (failingRenderer) Terminal([]byte) (string, error) { return "", errors.New("must not be called") }

type failingAuditor struct{}

func (failingAuditor) Record(context.Context, ports.AuditEvent) error {
	return errors.New("must not be called")
}

func catalystRegistration(t *testing.T, w *world.World, rewards string) (catalyst.RegistrationGenerated, error) {
	t.Helper()
	uc := catalyst.GenerateRegistration{Store: w.Store, Signers: w.Signers(), Clock: sharedTick, Tip: w.Chain, NetworkID: w.Network}
	return uc.Run(context.Background(), catalyst.RegistrationRequest{
		Delegation: []catalyst.DelegationWord{{Ref: strings.Repeat("ab", 32), Weight: 2}}, Stake: "hw", Rewards: rewards, Nonce: 5150})
}

// A Catalyst registration signed by the stake key on a Ledger (09a `genmeta`
// with a hardware stake key): the signature verifies as a CIP-36 registration;
// when the rewards address is the payment address of the same wallet its signing
// file goes to the device too (SPO-09a-INV-004), and with another rewards address
// it does not. A misbehaving tool is refused, and a Keystone is refused before the
// device is asked.
//
// spec: SPO-09a-EXT-004, SPO-09a-INV-004, SPO-09a-INV-005, SPO-09a-OUT-006
func TestCatalystRegistrationWithLedgerStakeKey(t *testing.T) {
	w, payAddr := catalystWorld(t)
	other := account(t, w, "elsewhere", custody.PlaceVault, 0)
	res, err := catalystRegistration(t, w, "hw.payment")
	if err != nil {
		t.Fatal(err)
	}
	argv := w.HW.Last("vote", "registration-metadata")
	if len(flagValuesOf(argv, "--payment-address-signing-key-hwsfile")) != 1 || len(flagValuesOf(argv, "--stake-signing-key-hwsfile")) != 1 ||
		flagValuesOf(argv, "--payment-address")[0] != payAddr {
		t.Errorf("same wallet: argv %v", argv)
	}
	reg, err := cose.VerifyCip36(res.CBOR)
	if err != nil || reg.Nonce != 5150 || len(reg.Delegations) != 1 || reg.Delegations[0].Weight != 2 {
		t.Errorf("%+v %v", reg, err)
	}
	if _, err := catalystRegistration(t, w, string(other.PaymentAddress)); err != nil {
		t.Fatal(err)
	}
	if argv := w.HW.Last("vote", "registration-metadata"); len(flagValuesOf(argv, "--payment-address-signing-key-hwsfile")) != 0 {
		t.Errorf("another rewards address: argv %v", argv)
	}

	n := w.HW.Count("vote")
	files := 0
	count := func() int { f, _ := filepath.Glob(filepath.Join(w.Dir, "*vote-registration*")); return len(f) }
	files = count()
	for _, m := range []string{"votewrongkey", "votebadsig", "votewrongaddr", "votetruncated"} {
		w.HW.Set("misbehave", m)
		if _, err := catalystRegistration(t, w, "hw.payment"); err == nil {
			t.Errorf("%s accepted", m)
		}
	}
	w.HW.Set("misbehave", "")
	if count() != files || w.HW.Count("vote") != n+4 {
		t.Errorf("a refused registration was stored (%d files, %d calls)", count(), w.HW.Count("vote")-n)
	}

	hw := w.UseHardware("Keystone", "1.7.7")
	hw.Lazy.Profile()
	p := hw.Prompts()
	var ue *custody.UnsupportedError
	if _, err := catalystRegistration(t, w, "hw.payment"); !errors.As(err, &ue) || hw.Prompts() != p {
		t.Errorf("keystone: %v", err)
	}
	_ = os.Stat
	_ = chain.Lovelace(0)
}

func flagValuesOf(argv []string, flag string) []string {
	var out []string
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			out = append(out, argv[i+1])
		}
	}
	return out
}

// tickClock moves on by a second at every reading, so two registrations of one
// second's work do not share a file name.
type tickClock struct{ n int }

func (c *tickClock) Now() time.Time {
	c.n++
	return time.Date(2026, 1, 2, 0, 0, c.n, 0, time.UTC)
}

var sharedTick = &tickClock{}
