package hardware_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

type noDRep struct{}

func (noDRep) Source() chain.Source { return "fake chain" }
func (noDRep) DRepState(context.Context, chain.DRepID) (chain.Reading[chain.DRepState], error) {
	return chain.None[chain.DRepState](), nil
}

func govBase(w *world.World) governance.Base {
	return governance.Base{Store: w.Store, Addresses: w.Ledger, Params: w.Chain, Tip: w.Chain, Utxos: w.Chain, NetworkID: w.Network, Pipeline: w.Pipeline()}
}

func drepKey(t *testing.T, w *world.World, name string, holder custody.Placement) governance.DRepKeysGenerated {
	t.Helper()
	res, err := governance.GenerateDRepKeys{Store: w.Store, Keys: native.SoftwareKeys{}, Hardware: w.Exporter()}.
		Run(context.Background(), governance.GenerateKeysRequest{Name: name, Place: holder, Source: governance.KeysRandom})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func registerDRep(w *world.World) governance.RegisterDRep {
	return governance.RegisterDRep{Base: govBase(w), Certs: w.Ledger, DReps: noDRep{}}
}

// A DRep registration with the payment and the DRep key both on a Ledger: the
// body is canonicalised, the device witnesses it with both keys, the submitted
// transaction verifies, and the device was not put in unrestricted mode.
//
// spec: SPO-21b-INV-006, SPO-21b-EXT-001, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func TestDRepRegistrationBothOnLedger(t *testing.T) {
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
	account(t, w, "hw", custody.PlaceHardware, 700_000_000)
	drepKey(t, w, "d", custody.PlaceHardware)
	res, err := registerDRep(w).Run(context.Background(), governance.RegisterDRepRequest{DRep: "d", Payer: "hw.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || w.Conf.Seen[0].TxID != res.TxID {
		t.Fatalf("submitted=%v shown=%v result=%s", res.Submitted, w.Conf.Seen[0].TxID, res.TxID)
	}
	ws, err := (native.TxViewer{}).Witnesses(w.Chain.Submitted[0])
	if err != nil || len(ws) != 2 {
		t.Fatalf("witnesses %d %v", len(ws), err)
	}
	if strings.Contains(strings.Join(w.HW.Last("transaction", "witness"), " "), "--allow-unrestricted-mode") {
		t.Error("unrestricted mode was used without being asked for")
	}
}

// A hardware payer with a key-file DRep needs the device's unrestricted mode.
// It is never implied: without the operator's consent the run is refused before
// any device prompt; with it the flag is passed and the demand includes it, so
// a Trezor refuses it upfront.
//
// spec: SPO-21b-PR-001, SPO-21b-SEC-003, SPO-21b-INV-006, SPO-21d-INV-004
func TestUnrestrictedModeIsNeverImplied(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	account(t, w, "hw", custody.PlaceHardware, 700_000_000)
	drepKey(t, w, "soft", custody.PlaceVault)

	before := w.HW.Prompts()
	_, err := registerDRep(w).Run(ctx, governance.RegisterDRepRequest{DRep: "soft", Payer: "hw.payment"})
	if !errors.Is(err, governance.ErrUnrestrictedNeeded) {
		t.Fatalf("without consent: %v", err)
	}
	if w.HW.Prompts() != before || len(w.Chain.Submitted) != 0 {
		t.Error("a refusal reached the device or the chain")
	}

	res, err := registerDRep(w).Run(ctx, governance.RegisterDRepRequest{DRep: "soft", Payer: "hw.payment", Unrestricted: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(w.HW.Last("transaction", "witness"), " "), "--allow-unrestricted-mode") {
		t.Error("the consent was not passed to the device")
	}
	if !strings.Contains(strings.Join(w.HW.Last("transaction", "transform"), " "), "--allow-unrestricted-mode") {
		t.Error("the consent was not passed to the canonicalisation")
	}
	if !res.Submitted {
		t.Error("not submitted")
	}

	// A Trezor has no unrestricted mode: refused upfront, naming the feature.
	w2 := world.New(t)
	w2.UseHardware("Trezor", "2.7.2")
	account(t, w2, "hw", custody.PlaceHardware, 700_000_000)
	drepKey(t, w2, "soft", custody.PlaceVault)
	p := w2.HW.Prompts()
	_, err = registerDRep(w2).Run(ctx, governance.RegisterDRepRequest{DRep: "soft", Payer: "hw.payment", Unrestricted: true})
	var un *custody.UnsupportedError
	if !errors.As(err, &un) || !strings.Contains(err.Error(), "unrestricted") {
		t.Fatalf("Trezor: %v", err)
	}
	if w2.HW.Prompts() != p {
		t.Error("a Trezor was prompted for a refused plan")
	}
}

// A vote with the DRep key and the payment key on a Ledger is witnessed on the
// device; on a Trezor or a Keystone the whole plan is refused upfront with one
// error that names the missing capability, and the tool is called for nothing
// but the version probe.
//
// spec: SPO-24b-EXT-001, SPO-24b-EXT-002, SPO-24b-PRE-008, SPO-Chw-PRE-003, SPO-Ptx-EXT-005
func TestVoteOnLedgerAndRefusedOnOtherVendors(t *testing.T) {
	ctx := context.Background()
	vote := func(w *world.World, drep governance.DRepKeysGenerated) governance.RegisterVoteRequest {
		var act dgov.ActionID
		act.TxID[0], act.Index = 7, 0
		vf, err := w.Ledger.BuildVoteFile(dgov.Vote{Voter: dgov.Voter{Role: dgov.RoleDRep, Cred: drep.Credential}, Action: act, Decision: dgov.Yes}, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Store.Update(ctx, func(wr ports.NamedWriter) error {
			return wr.Put(ports.NamedRef{Name: "d_1700000000", Kind: ports.VoteDRepFile}, vf.Envelope)
		}); err != nil {
			t.Fatal(err)
		}
		return governance.RegisterVoteRequest{Voter: "d", Payer: "hw.payment", Files: []string{"d_1700000000.drep.vote"}}
	}

	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	d := drepKey(t, w, "d", custody.PlaceHardware)
	res, err := (governance.RegisterVote{Base: govBase(w), Votes: w.Ledger}).Run(ctx, vote(w, d))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || w.HW.Count("transaction", "witness") < 1 {
		t.Fatalf("%+v", res)
	}

	for _, vendor := range []struct{ name, app string }{{"Trezor", "2.7.2"}, {"Keystone", "1.7.7"}} {
		w := world.New(t)
		w.UseHardware("Ledger", "8.0.8") // the keys are made on a Ledger,
		account(t, w, "hw", custody.PlaceHardware, 50_000_000)
		d := drepKey(t, w, "d", custody.PlaceHardware)
		hw := w.UseHardware(vendor.name, vendor.app) // and the vote is tried on another device
		hw.Lazy.Profile()                            // the version probe is the only call the vendor may see
		before := hw.Prompts()
		_, err := (governance.RegisterVote{Base: govBase(w), Votes: w.Ledger}).Run(ctx, vote(w, d))
		var un *custody.UnsupportedError
		if !errors.As(err, &un) || !strings.Contains(err.Error(), "vote") {
			t.Fatalf("%s: %v", vendor.name, err)
		}
		if hw.Prompts() != before || len(w.Chain.Submitted) != 0 || len(w.Conf.Seen) != 0 {
			t.Errorf("%s: a refused plan had effects: %v", vendor.name, hw.Calls())
		}
	}
}

// A vote file from a hardware payer and a key-file voter is refused (the mixed
// combination), and a governance action proposal with a hardware payer is
// refused, as the scripts do.
//
// spec: SPO-24b-PRE-009, SPO-Ptx-PRE-006, SPO-25b-PRE-002
func TestKeptHardwareRefusals(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	d := drepKey(t, w, "d", custody.PlaceVault)
	var act dgov.ActionID
	act.TxID[0] = 9
	vf, _ := w.Ledger.BuildVoteFile(dgov.Vote{Voter: dgov.Voter{Role: dgov.RoleDRep, Cred: d.Credential}, Action: act, Decision: dgov.No}, "")
	_ = w.Store.Update(ctx, func(wr ports.NamedWriter) error {
		return wr.Put(ports.NamedRef{Name: "d_1700000001", Kind: ports.VoteDRepFile}, vf.Envelope)
	})
	before := w.HW.Prompts()
	_, err := (governance.RegisterVote{Base: govBase(w), Votes: w.Ledger}).Run(ctx, governance.RegisterVoteRequest{Voter: "d", Payer: "hw.payment", Files: []string{"d_1700000001.drep.vote"}})
	if err == nil || !strings.Contains(err.Error(), "SPO-Ptx-PRE-006") {
		t.Fatalf("mixed vote: %v", err)
	}
	if w.HW.Prompts() != before {
		t.Error("the mixed refusal reached the device")
	}
}

// Several votes in one transaction on a device need its unrestricted mode: asked
// of the operator (the request field), never implied. Without it the run is
// refused before any device prompt; with it the flag reaches the canonicalisation
// and the witness.
//
// spec: SPO-24b-PR-001, SPO-24b-EXT-001, SPO-24b-EXT-002, SPO-Ptx-EXT-005
func TestSeveralVotesOnLedgerNeedConsent(t *testing.T) {
	ctx := context.Background()
	w := world.New(t)
	w.UseHardware("Ledger", "8.0.8")
	account(t, w, "hw", custody.PlaceHardware, 50_000_000)
	d := drepKey(t, w, "d", custody.PlaceHardware)
	var names []string
	for i := 0; i < 2; i++ {
		var act dgov.ActionID
		act.TxID[0], act.Index = byte(20+i), 0
		vf, err := w.Ledger.BuildVoteFile(dgov.Vote{Voter: dgov.Voter{Role: dgov.RoleDRep, Cred: d.Credential}, Action: act, Decision: dgov.Yes}, "")
		if err != nil {
			t.Fatal(err)
		}
		name := "d_17000000000" + string(rune('0'+i))
		if err := w.Store.Update(ctx, func(wr ports.NamedWriter) error {
			return wr.Put(ports.NamedRef{Name: name, Kind: ports.VoteDRepFile}, vf.Envelope)
		}); err != nil {
			t.Fatal(err)
		}
		names = append(names, name+".drep.vote")
	}
	uc := governance.RegisterVote{Base: govBase(w), Votes: w.Ledger}
	before := w.HW.Prompts()
	if _, err := uc.Run(ctx, governance.RegisterVoteRequest{Voter: "d", Payer: "hw.payment", Files: names}); !errors.Is(err, governance.ErrUnrestrictedNeeded) {
		t.Fatalf("without consent: %v", err)
	}
	if w.HW.Prompts() != before {
		t.Error("a refusal reached the device")
	}
	res, err := uc.Run(ctx, governance.RegisterVoteRequest{Voter: "d", Payer: "hw.payment", Files: names, Unrestricted: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || !strings.Contains(strings.Join(w.HW.Last("transaction", "witness"), " "), "--allow-unrestricted-mode") {
		t.Errorf("%+v %v", res, w.HW.Last("transaction", "witness"))
	}
}

type registeredDRep struct{ noDRep }

func (registeredDRep) DRepState(context.Context, chain.DRepID) (chain.Reading[chain.DRepState], error) {
	return chain.Value(chain.DRepState{Deposit: 500_000_000}), nil
}

// A DRep that is already registered gets an update certificate (SPO-21b-EXT-006),
// signed with the same two hardware witnesses as a registration (SPO-21b-INV-006),
// on a Ledger and on a Keystone; a Trezor has no DRep key to begin with.
//
// spec: SPO-21b-INV-006, SPO-21b-EXT-006, SPO-21b-INV-002
func TestDRepUpdateOnLedgerAndKeystone(t *testing.T) {
	for _, dev := range [][2]string{{"Ledger", "8.0.8"}, {"Keystone", "1.7.7"}} {
		w := world.New(t)
		w.UseHardware(dev[0], dev[1])
		w.Bodies = world.LegacyInputs{Ledger: w.Ledger}
		account(t, w, "hw", custody.PlaceHardware, 5_000_000)
		drepKey(t, w, "d", custody.PlaceHardware)
		uc := governance.RegisterDRep{Base: govBase(w), Certs: w.Ledger, DReps: registeredDRep{}}
		res, err := uc.Run(context.Background(), governance.RegisterDRepRequest{DRep: "d", Payer: "hw.payment", AllowAnchorClear: true})
		if err != nil {
			t.Fatalf("%s: %v", dev[0], err)
		}
		if !res.Submitted {
			t.Fatalf("%s: not submitted", dev[0])
		}
		sent := w.Chain.Submitted[0]
		if !strings.Contains(hex.EncodeToString(sent), "83128200") {
			t.Errorf("%s: no DRep update certificate in the transaction", dev[0])
		}
		if ws, err := (native.TxViewer{}).Witnesses(sent); err != nil || len(ws) != 2 {
			t.Errorf("%s: witnesses %d %v", dev[0], len(ws), err)
		}
		// One witness call per key, and the conversion was settled before the first:
		// the witnesses do not ask the tool to transform the body again.
		seenWitness := false
		for _, c := range w.HW.Calls() {
			switch {
			case len(c) > 1 && c[0] == "transaction" && c[1] == "witness":
				seenWitness = true
			case len(c) > 1 && c[0] == "transaction" && c[1] == "transform" && seenWitness:
				t.Errorf("%s: a transform after a witness", dev[0])
			}
		}
		if n := w.HW.Count("transaction", "witness"); n != 2 {
			t.Errorf("%s: %d witness calls", dev[0], n)
		}
	}
}
