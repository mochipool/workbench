package hardware_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

// A reference carries a role and an identity and no holder: unplugging the
// device before the plan makes its keys unavailable, and the demand fails in
// the plan, before the device is asked anything and before the operator is.
//
// spec: SPO-Xidentity-IF-001, SPO-Xidentity-PRE-005
func TestUnpluggedDeviceFailsInThePlanBeforeAnyPrompt(t *testing.T) {
	w := world.New(t)
	hw := w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	account(t, w, "dst", custody.PlaceVault, 0)
	hw.Set("device", "nodevice") // unplugged before planning
	w.NewSession()               // the command that follows opens its own session
	before := hw.Prompts()
	_, err := sender(w).Run(context.Background(), wallet.SendRequest{Source: "hw.payment", Destination: "dst.payment", Amount: "5000000"})
	var ue *custody.UnsupportedError
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("the plan must refuse an unplugged device: %v", err)
	}
	if hw.Prompts() != before || len(w.Conf.Seen) != 0 || len(w.Chain.Submitted) != 0 {
		t.Errorf("a prompt or an effect came before the plan failed: prompts %d->%d, shown %d", before, hw.Prompts(), len(w.Conf.Seen))
	}
}

// A hardware file for another account than the one demanded is refused before
// the device is touched, and an answer is verified again: the
// stored hardware file of the demanded key identity holds another key's public
// key, and what the device signs is verified against the identity demanded, not
// against the file it was asked to use.
//
// spec: SPO-Xidentity-SEC-005
func TestAWrongAccountHardwareAnswerIsRefused(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	account(t, w, "dst", custody.PlaceVault, 0)
	// another account of the same device (account 1)
	if _, err := (wallet.GenerateWalletAccount{Store: w.Store, Payment: native.SoftwareKeys{}, Stake: native.SoftwareKeys{}, Addresses: w.Ledger,
		NetworkID: w.Network, Hardware: w.Exporter()}).Run(ctx, wallet.GenerateWalletRequest{Name: "other", Place: custody.PlaceHardware,
		Source: wallet.WalletKeysRandom, Account: 1}); err != nil {
		t.Fatal(err)
	}
	// the file stored for hw's payment key is the file of another account
	var otherFile []byte
	if err := w.Store.View(ctx, func(r ports.Reader) error {
		var err error
		otherFile, err = r.Get(ports.Ref{Name: "other.payment", Kind: ports.AddrHwsFile})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Store.Update(ctx, func(wr ports.Writer) error {
		return wr.Put(ports.Ref{Name: "hw.payment", Kind: ports.AddrHwsFile}, otherFile)
	}); err != nil {
		t.Fatal(err)
	}
	before := w.HW.Prompts()
	_, err := sender(w).Run(ctx, wallet.SendRequest{Source: "hw.payment", Destination: "dst.payment", Amount: "5000000"})
	if err == nil || !strings.Contains(err.Error(), hwcli.ErrWrongKey.Error()) {
		t.Fatalf("a wrong-account answer was accepted: %v", err)
	}
	if w.HW.Prompts() != before {
		t.Errorf("the device was asked something (%d calls) before the wrong file was refused", w.HW.Prompts()-before)
	}
	if len(w.Chain.Submitted) != 0 {
		t.Error("a transaction was submitted")
	}
}

// fakeParties resolves a party name to a fingerprint; it implements only ByName.
type fakeParties map[string]party.Fingerprint

func (f fakeParties) ByName(_ ports.Reader, name string) (party.Party, error) {
	if fp, ok := f[name]; ok {
		return party.Party{Name: name, Fingerprint: fp}, nil
	}
	return party.Party{}, ports.ErrNotFound
}
func (fakeParties) ByFingerprint(ports.Reader, party.Fingerprint) (party.Party, error) {
	return party.Party{}, ports.ErrNotFound
}
func (fakeParties) List(ports.Reader) ([]party.Party, error) { return nil, nil }
func (fakeParties) Put(ports.Writer, party.Party) error      { return nil }
func (fakeParties) SetScope(ports.Writer, string, party.Scope) (party.Party, error) {
	return party.Party{}, nil
}
func (fakeParties) Revoke(ports.Writer, string) (party.Party, error) { return party.Party{}, nil }
func (fakeParties) Rotate(ports.Writer, party.Fingerprint, party.Party, party.Party) error {
	return nil
}

const mixedDescriptor = `{
  "poolName": "mypool",
  "poolOwner": [
    {"ownerName": "hw", "ownerWitness": "local"},
    {"ownerName": "va", "ownerWitness": "local"},
    {"ownerName": "rem", "ownerWitness": "bobparty"}
  ],
  "poolRewards": "hw",
  "poolPledge": "100000000000",
  "poolCost": "340000000",
  "poolMargin": "0.10",
  "poolRelays": [
    {"relayType": "dns", "relayEntry": "relay.example.org", "relayPort": "3001"}
  ],
  "poolMetaName": "My Pool",
  "poolMetaDescription": "A pool for tests",
  "poolMetaTicker": "MYPL",
  "poolMetaHomepage": "https://example.org",
  "poolMetaUrl": "https://example.org/mypool.metadata.json",
  "poolExtendedMetaUrl": "",
  "---": "--- DO NOT EDIT OR DELETE BELOW THIS LINE ---"
}
`

// One pool registration with the cold key and the payer on the stand-in
// hardware wallet, one owner in the vault, one on the device and one owner
// whose witness a co-signer makes. The use case states demands (key identity,
// role, operation) and builds the plan from the signers connected now: it has
// no holder branch (the archtest in internal/archtest keeps it so). The vault
// answers the owner in the vault, the device slots are left for the operator's
// later run (AllowPending, as before), and the third slot is assigned to the
// co-signer by fingerprint and left open.
//
// spec: SPO-Xidentity-IF-001, SPO-Xidentity-INV-015, SPO-Xidentity-INV-016, SPO-05c-INV-005
func TestOneRegistrationRunsThroughTheSamePlanningForVaultDeviceAndRemote(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	w.Chain.Params.StakePoolDeposit, w.Chain.Params.MinPoolCost, w.Chain.Params.PoolRetireMaxEpoch = 500_000_000, 170_000_000, 18
	hwAcc := account(t, w, "hw", custody.PlaceHardware, 900_000_000)
	vaultAcc := account(t, w, "va", custody.PlaceVault, 0)
	remAcc := account(t, w, "rem", custody.PlaceVault, 0)
	// the remote owner's signing key is with the co-signer: only the verification key is here
	if err := w.Store.Update(ctx, func(wr ports.Writer) error { return wr.Delete(ports.Ref{Name: "rem", Kind: ports.StakingSKey}) }); err != nil {
		t.Fatal(err)
	}
	cold, err := (poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}, Hardware: w.Exporter()}).
		Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool", Place: custody.PlaceHardware})
	if err != nil {
		t.Fatal(err)
	}
	for name, vk := range map[string][]byte{"hw": hwAcc.StakeVKey, "va": vaultAcc.StakeVKey, "rem": remAcc.StakeVKey} {
		env, err := pool.ParseEnvelope(vk)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := env.Key32()
		dc, err := w.Ledger.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(txbuild.HashKey(raw)), Pool: cold.PoolID})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Store.Update(ctx, func(wr ports.Writer) error { return wr.Put(ports.Ref{Name: name, Kind: ports.DelegCert}, dc.Envelope) }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (poolops.GenerateVrfKeys{Store: w.Store, KeyGen: native.KeyGen{}}).Run(ctx, poolops.GenerateVrfKeysRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Dir, "mypool.pool.json"), []byte(mixedDescriptor), 0o600); err != nil {
		t.Fatal(err)
	}
	gen := poolops.GeneratePoolCertificate{Store: w.Store, Params: w.Chain, Certs: w.Ledger, Hasher: w.Ledger, Clock: fixedClock{}, NetworkID: w.Network}
	if _, err := gen.Run(ctx, poolops.GenerateRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	fp := party.Fingerprint{0xb0, 0xb1}
	uc := poolops.RegisterPool{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, Pipeline: w.Pipeline(),
		PoolCerts: w.Ledger, StakeCerts: w.Ledger, TxIDs: w.Ledger, Hasher: w.Ledger, Clock: fixedClock{},
		Pools: noPools{}, Sources: poolops.SingleSourceAcknowledged, OnSingle: noopSingle, AllowPending: true,
		Parties: fakeParties{"bobparty": fp}}
	res, err := uc.Run(ctx, poolops.RegisterRequest{Pool: "mypool", Payer: "hw.payment"})
	if err != nil {
		t.Fatal(err)
	}
	// With AllowPending a slot on a device is left for the operator's later run (as
	// before), the remote one for its co-signer, and the vault answers the owner
	// va in this run.
	if res.State != pool.CollectionOpenIncomplete || len(res.Missing) != 4 {
		t.Fatalf("%+v", res)
	}
	if n := w.HW.Count("transaction", "witness"); n != 0 {
		t.Errorf("the device witnessed %d times in a run that defers its slots: %v", n, w.HW.Calls())
	}
	var raw []byte
	if err := w.Store.View(ctx, func(r ports.Reader) error {
		var err error
		raw, err = r.Get(ports.Ref{Name: "mypool", Kind: ports.PoolDescriptor})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	d, err := pool.ParseDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	coll, err := d.Collection(w.Ledger.TransactionID)
	if err != nil || coll == nil || len(coll.Slots) != 5 {
		t.Fatalf("%v %v", coll, err)
	}
	filled := 0
	for _, s := range coll.Slots {
		if s.Filled() {
			filled++
		}
		// the stored slot names the key it needs and a party fingerprint; no holder
		if s.Name == "rem.staking" && (s.Filled() || s.PartyFingerprint != fp) {
			t.Errorf("the remote slot %+v", s)
		}
		if s.Name != "rem.staking" && s.Assigned() {
			t.Errorf("a local slot is assigned: %+v", s)
		}
	}
	if filled != 1 {
		t.Errorf("%d slots filled, want 1 (the vault owner)", filled)
	}
	if strings.Contains(string(raw), `"holder"`) || strings.Contains(string(raw), `"party"`) || !strings.Contains(string(raw), `"partyFingerprint"`) {
		t.Errorf("the stored slots carry a holder or a party name, or no fingerprint:\n%s", raw)
	}
}

// A payer with both a signing key and a hardware file is signed on the device
// (the hardware file wins, SPO-Pfiles-INV-002): the payment is witnessed by the
// device, not by the vault, and nothing is mixed.
//
// spec: SPO-Pfiles-INV-002, SPO-Xidentity-INV-016
func TestAPayerWithBothFilesIsSignedOnTheDevice(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	account(t, w, "dst", custody.PlaceVault, 0)
	// a signing key stored beside the hardware file (it need not be the key: the
	// directory goes by the files stored for the verification key)
	if err := w.Store.Update(ctx, func(wr ports.Writer) error {
		return wr.PutSecret(ports.Ref{Name: "hw.payment", Kind: ports.AddrSKey}, secret.Take([]byte("{}")))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sender(w).Run(ctx, wallet.SendRequest{Source: "hw.payment", Destination: "dst.payment", Amount: "5000000"}); err != nil {
		t.Fatal(err)
	}
	if n := w.HW.Count("transaction", "witness"); n != 1 {
		t.Errorf("the device witnessed %d times, want 1: %v", n, w.HW.Calls())
	}
}
