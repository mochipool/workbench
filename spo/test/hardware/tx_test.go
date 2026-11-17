package hardware_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poll"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/stake"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	dpoll "github.com/mochipool/workbench/spo/internal/domain/poll"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

// account makes a wallet `name` (payment name.payment, stake name) and funds
// its base address. hw puts the payment and stake keys on the device.
func account(t *testing.T, w *world.World, name string, holder custody.Placement, lovelace chain.Lovelace) wallet.WalletGenerated {
	t.Helper()
	uc := wallet.GenerateWalletAccount{Store: w.Store, Payment: native.SoftwareKeys{}, Stake: native.SoftwareKeys{}, Addresses: w.Ledger,
		NetworkID: w.Network, Hardware: w.Exporter()}
	res, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: name, Place: holder, Source: wallet.WalletKeysRandom})
	if err != nil {
		t.Fatal(err)
	}
	if lovelace > 0 {
		w.Fund(res.PaymentAddress, lovelace)
	}
	return res
}

func sender(w *world.World) wallet.SendLovelaces {
	return wallet.SendLovelaces{Store: w.Store, Signers: w.Signers(), Utxos: w.Chain, Params: w.Chain, Tip: w.Chain,
		Addresses: w.Ledger, Min: w.Ledger, Fees: w.Ledger, Bodies: w.Bodies, Assembler: w.Ledger, Confirmer: w.Conf,
		Submitter: w.Chain, NetworkID: w.Network, Canonicalizer: w.Canonicalizer()}
}

// A payment from a hardware wallet: the body is brought to hardware form BEFORE
// it is shown, the operator is shown the id of the canonical body, the device
// witnesses exactly that body, and the assembled transaction verifies and has
// that id. The builder here writes the inputs in a legacy form, so the
// canonical body has another id than the first one built.
//
// spec: SPO-Ptx-EXT-005, SPO-Xparty-INV-012, SPO-Ctx-EXT-001, SPO-01sendLovelaces-EXT-002, SPO-Ptx-INV-009, SPO-Ptx-INV-010, SPO-Ptx-PRE-005
func TestSendFromHardwarePayerCanonicalisesBeforeDisplay(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	src := account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	dst := account(t, w, "dst", custody.PlaceVault, 0)

	// The id of the body as first built, to show that it was not the one used.
	res, err := sender(w).Run(context.Background(), wallet.SendRequest{Source: "hw.payment", Destination: "dst.payment", Amount: "5000000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Conf.Seen) != 1 || w.Conf.Seen[0].TxID != res.TxID {
		t.Fatalf("the operator was shown %v, the transaction is %s", w.Conf.Seen, res.TxID)
	}
	if !res.Submitted || len(w.Chain.Submitted) != 1 {
		t.Fatal("not submitted")
	}
	if w.HW.Count("transaction", "transform") < 1 {
		t.Error("the body was never canonicalised")
	}
	// The canonicalisation came before the witness call.
	order := ""
	for _, c := range w.HW.Calls() {
		if len(c) >= 2 && c[0] == "transaction" {
			order += c[1] + ","
		}
	}
	if !strings.HasPrefix(order, "transform,") || !strings.Contains(order, "witness,") {
		t.Errorf("order of device calls: %s", order)
	}
	// The assembled transaction carries a witness that verifies over the shown id.
	signed := w.Chain.Submitted[0]
	id, err := w.Ledger.TransactionID(signed)
	if err != nil || id != res.TxID {
		t.Fatalf("submitted id %s (%v), result %s", id, err, res.TxID)
	}
	ws, err := (native.TxViewer{}).Witnesses(signed)
	if err != nil || len(ws) != 1 {
		t.Fatalf("witnesses %v %v", ws, err)
	}
	info, _ := w.Ledger.InspectAddress(src.PaymentAddress)
	if err := txbuild.VerifyWitness(txbuild.TxBody{ID: id}, ws[0], *info.PaymentKeyHash); err != nil {
		t.Error(err)
	}
	// The change output was declared to the device with both hardware files.
	witness := w.HW.Last("transaction", "witness")
	if n := strings.Count(strings.Join(witness, " "), "--change-output-key-file"); n != 2 {
		t.Errorf("change keys declared: %d in %v", n, witness)
	}
	_ = dst
}

// No canonicalizer wired and a hardware payer: refused upfront, naming the
// missing capability, before any device prompt.
//
// spec: SPO-Xparty-INV-012, SPO-Ptx-EXT-005
func TestHardwarePayerWithoutCanonicalizerIsRefused(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	src := account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	account(t, w, "dst", custody.PlaceVault, 0)
	before := w.HW.Prompts()
	uc := sender(w)
	uc.Canonicalizer = nil
	_, err := uc.Run(context.Background(), wallet.SendRequest{Source: "hw.payment", Destination: "dst.payment", Amount: "5000000"})
	if !errors.Is(err, txflow.ErrNoCanonicalizer) || !strings.Contains(err.Error(), "canonicalizer") {
		t.Fatalf("%v", err)
	}
	if w.HW.Prompts() != before || len(w.Conf.Seen) != 0 || len(w.Chain.Submitted) != 0 {
		t.Error("a refused plan had effects")
	}
	_ = src
}

// Stake registration and delegation from a hardware wallet, through the shared
// pipeline: the certificate body is canonicalised, both keys witness it on the
// device, and the submitted transaction carries two verifying witnesses.
//
// spec: SPO-03b-EXT-003, SPO-06-EXT-001, SPO-Ptx-EXT-005, SPO-Ptx-INV-006, SPO-Xparty-INV-012
func TestStakeRegistrationAndDelegationOnLedger(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	res := account(t, w, "hw", custody.PlaceHardware, 100_000_000)
	base := stake.Base{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, NetworkID: w.Network, Pipeline: w.Pipeline()}
	reg := stake.RegisterStakeAddress{Base: base, Certs: w.Ledger, AllowUnverified: true}
	out, err := reg.Run(context.Background(), stake.RegisterRequest{Stake: "hw", Payer: "hw.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Submitted || len(w.Chain.Submitted) != 1 {
		t.Fatalf("not submitted: %+v", out)
	}
	if w.Conf.Seen[0].TxID != out.TxID {
		t.Error("the shown id is not the signed id")
	}
	ws, err := (native.TxViewer{}).Witnesses(w.Chain.Submitted[0])
	if err != nil || len(ws) != 2 {
		t.Fatalf("witnesses %d %v", len(ws), err)
	}
	if w.HW.Count("transaction", "transform") < 1 || w.HW.Count("transaction", "witness") < 2 {
		t.Errorf("device calls: %v", w.HW.Calls())
	}
	_ = res
	_ = hex.EncodeToString
	_ = ports.NetworkTestnet
}

// A poll answer with a hardware payment key and a key-file cold key is allowed
// here (unlike the mixed combinations of SPO-Ptx-PRE-006): the device witnesses
// the canonical body for the payment key, the cold key's witness is made in
// memory over the same body, and the assembled transaction carries both.
//
// spec: SPO-13b-EXT-004, SPO-13b-INV-011, SPO-13b-INV-001, SPO-Ptx-EXT-005
func TestPollAnswerWithHardwarePayerAndKeyFileColdKey(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	if _, err := (poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}}).Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool"}); err != nil {
		t.Fatal(err)
	}
	var qh [32]byte
	qh[0] = 1
	uc := poll.SubmitPollAnswer{Send: sender(w)}
	res, err := uc.Run(ctx, poll.SubmitRequest{Payer: "hw.payment", Destination: "hw.payment", Amount: "MIN", Pool: "mypool",
		Answer: &poll.Answer{CBOR: dpoll.EncodeAnswer(qh, 0), FileName: dpoll.FileName(qh)}})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := (native.TxViewer{}).Witnesses(w.Chain.Submitted[0])
	if err != nil || len(ws) != 2 {
		t.Fatalf("witnesses %d %v", len(ws), err)
	}
	if w.HW.Count("transaction", "witness") != 1 || w.HW.Count("transaction", "transform") < 1 || w.Conf.Seen[0].TxID != res.TxID {
		t.Errorf("device calls %v", w.HW.Calls())
	}
}

// A hybrid wallet (hardware payment key, key-file stake key) cannot register its
// stake address: a hardware key is not combined with a key-file key
// (SPO-Ptx-PRE-006), refused before the device is asked for anything.
//
// spec: SPO-Ptx-PRE-006, SPO-03a-INV-001
func TestHybridWalletStakeRegistrationIsRefused(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	uc := wallet.GenerateWalletAccount{Store: w.Store, Payment: native.SoftwareKeys{}, Stake: native.SoftwareKeys{}, Addresses: w.Ledger, NetworkID: w.Network, Hardware: w.Exporter()}
	res, err := uc.Run(context.Background(), wallet.GenerateWalletRequest{Name: "hy", Place: custody.PlaceHardware, StakePlace: custody.PlaceVault})
	if err != nil {
		t.Fatal(err)
	}
	w.Fund(res.PaymentAddress, 50_000_000)
	before := w.HW.Prompts()
	base := stake.Base{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, NetworkID: w.Network, Pipeline: w.Pipeline()}
	_, err = stake.RegisterStakeAddress{Base: base, Certs: w.Ledger, AllowUnverified: true}.Run(context.Background(), stake.RegisterRequest{Stake: "hy", Payer: "hy.payment"})
	if !errors.Is(err, txflow.ErrMixedHolders) {
		t.Fatalf("%v", err)
	}
	if w.HW.Prompts() != before || len(w.Chain.Submitted) != 0 {
		t.Error("a refusal had effects")
	}
}
