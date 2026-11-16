package multiparty

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// The second review's findings, end to end, as a hostile but enrolled and
// authenticated coordinator would use them, and the fixes' numbers.

// A payment key's witness spends every UTxO whose payment credential is the
// key, at any address form. The signer resolves every input by reference and
// classifies it by the credential of its address, so an input at a base address
// that its own list never named, with the key's own stake credential or with
// anyone's, is its own, and the review's numbers count it.
// spec: SPO-Xparty-PR-002
func TestInputsAreOwnedByCredentialAtAnyAddressForm(t *testing.T) {
	f := newFixture(t, payAndStake)
	ownStake, foreignStake := f.bobHash, other28
	baseOwnStake, err := f.led.BuildAddress(0, f.payHash, &ownStake)
	if err != nil {
		t.Fatal(err)
	}
	baseForeignStake, err := f.led.BuildAddress(0, f.payHash, &foreignStake)
	if err != nil {
		t.Fatal(err)
	}
	a := chain.Utxo{TxID: chain.TxID{0xb1}, Lovelace: 1_000_000_000}
	b := chain.Utxo{TxID: chain.TxID{0xb2}, Lovelace: 300_000_000}
	stranger := chain.Utxo{TxID: chain.TxID{0xb3}, Lovelace: 7_000_000}
	f.utxos.put(baseOwnStake, a)
	f.utxos.put(baseForeignStake, b)
	f.utxos.put(f.testnetAddr(other28), stranger) // another key's
	// 50 + 1000 + 300 own, 7 not: 1357 in; 1329.8 to the attacker, 20 back to
	// bob's own address, 7 to the attacker's, fee 0.2.
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own, a, b, stranger},
		Outputs: []txbuild.Output{
			{Address: f.testnetAddr(other28), Lovelace: 1_336_800_000},
			{Address: f.payAddr, Lovelace: 20_000_000},
		}})
	f.accepted(f.send(f.signer(), f.request(body, custody.RolePayment, f.payHash), ports.ViaFile))
	fl := f.review().Flow
	if !fl.Checked || len(fl.OwnInputs) != 3 || fl.ForeignInputs != 1 {
		t.Fatalf("own inputs %d, foreign %d: %+v", len(fl.OwnInputs), fl.ForeignInputs, fl)
	}
	if fl.OwnInputLovelace != 1_350_000_000 || fl.OwnOutputLovelace != 20_000_000 || fl.ToOthersLovelace != 1_336_800_000 || fl.NetLovelace != 1_330_000_000 || fl.Fee != 200_000 {
		t.Fatalf("the numbers: in %d, own out %d, to others %d, net %d, fee %d", fl.OwnInputLovelace, fl.OwnOutputLovelace, fl.ToOthersLovelace, fl.NetLovelace, fl.Fee)
	}
	if fl.Outputs[0].Own || !fl.Outputs[1].Own {
		t.Fatalf("output marks %+v", fl.Outputs)
	}
}

// A payment-key request needs every input resolved: one the provider does not
// know, one it says is spent, a failing provider and a signer with no
// provider are each a silent refusal, and nothing is signed.
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-006
func TestPaymentRequestWithAnUnresolvableInputIsRefusedInSilence(t *testing.T) {
	f := newFixture(t, payAndStake)
	unknown := chain.Utxo{TxID: chain.TxID{0xcc}, Lovelace: 5_000_000} // the provider was never told of it
	spent := chain.Utxo{TxID: chain.TxID{0xcd}, Lovelace: 5_000_000}
	f.utxos.put(f.testnetAddr(other28), spent)
	f.utxos.spend(spent)
	for name, in := range map[string]chain.Utxo{"unknown": unknown, "spent": spent} {
		body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own, in},
			Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 54_800_000}}})
		req := f.request(body, custody.RolePayment, f.payHash)
		h := f.send(f.signer(), req, ports.ViaFile)
		t.Run(name, func(t *testing.T) { f.silentRefusal(h, party.RefuseCannotResolveInputs, req.TxBody) })
	}
	// The same body with its inputs resolved is accepted.
	f.utxos.put(f.testnetAddr(other28), unknown)
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own, unknown},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 54_800_000}}})
	f.accepted(f.send(f.signer(), f.request(body, custody.RolePayment, f.payHash), ports.ViaFile))
}

// A body that delegates to the in-scope pool, withdraws bob's rewards to an
// attacker and delegates his votes is refused for a coordinator scoped to the
// pool and not unscoped: the scope is per part. With both it is shown, and the
// withdrawal is counted in the net, with the note that a payment witness for
// his own input must come from elsewhere.
// spec: SPO-Xparty-INV-010, SPO-Xparty-PR-002
func TestScopeIsPerPartAndTheWithdrawalIsInTheNet(t *testing.T) {
	build := func(f *fixture) txbuild.TxBody {
		deleg, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(f.bobHash), Pool: f.poolID})
		if err != nil {
			t.Fatal(err)
		}
		vote, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertVoteDelegation, Stake: stake.KeyHash(f.bobHash), DRep: stake.DRep{Kind: stake.DRepNoConfidence}})
		if err != nil {
			t.Fatal(err)
		}
		return f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own},
			Outputs:      []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 549_800_000}},
			Certificates: []stake.Certificate{deleg, vote},
			Withdrawals:  []txbuild.Withdrawal{{Reward: f.rewards, Credential: stake.KeyHash(f.bobHash), Amount: 500_000_000}}})
	}
	// Scoped to the pool, stake role, not unscoped: the pool-less parts are out.
	f := newFixture(t, scoped(false, true, custody.RoleStake))
	req := f.request(build(f), custody.RoleStake, f.bobHash)
	f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseOutOfScope, req.TxBody)

	// Unscoped and for the pool: shown. 50 own input + 500 own withdrawal.
	f = newFixture(t, scoped(true, true, custody.RoleStake))
	f.accepted(f.send(f.signer(), f.request(build(f), custody.RoleStake, f.bobHash), ports.ViaFile))
	fl := f.review().Flow
	if !fl.Checked || fl.WithdrawalsOwn != 500_000_000 || fl.WithdrawalsOther != 0 || fl.OwnInputLovelace != 50_000_000 {
		t.Fatalf("terms: %+v", fl)
	}
	if fl.NetLovelace != 550_000_000 || fl.ToOthersLovelace != 549_800_000 || fl.OwnOutputLovelace != 0 {
		t.Fatalf("net %d, to others %d, own outputs %d", fl.NetLovelace, fl.ToOthersLovelace, fl.OwnOutputLovelace)
	}
	if !fl.PaymentWitnessElsewhere {
		t.Fatal("a stake-role request that spends the signer's own payment UTxO does not say that the payment witness is elsewhere")
	}
}

// A refund and a deposit on the signer's own credentials are in the net, and
// an output to the signer's payment key whose stake credential is someone
// else's is not the signer's.
// spec: SPO-Xparty-PR-002
func TestOutputToTheSignersKeyWithAForeignStakeCredentialIsNotOwn(t *testing.T) {
	f := newFixture(t, payAndStake)
	foreign := other28
	toForeignStake, err := f.led.BuildAddress(0, f.payHash, &foreign)
	if err != nil {
		t.Fatal(err)
	}
	ownStake := f.bobHash
	toOwnStake, err := f.led.BuildAddress(0, f.payHash, &ownStake)
	if err != nil {
		t.Fatal(err)
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own},
		Outputs: []txbuild.Output{{Address: toForeignStake, Lovelace: 30_000_000}, {Address: toOwnStake, Lovelace: 19_800_000}}})
	f.accepted(f.send(f.signer(), f.request(body, custody.RolePayment, f.payHash), ports.ViaFile))
	fl := f.review().Flow
	if len(fl.Outputs) != 2 || fl.Outputs[0].Own || fl.Outputs[0].Note == "" || !fl.Outputs[1].Own {
		t.Fatalf("output marks %+v", fl.Outputs)
	}
	// 50 in, only the 19.8 to his own stake credential comes back.
	if fl.NetLovelace != 30_200_000 || fl.ToOthersLovelace != 30_000_000 || fl.OwnOutputLovelace != 19_800_000 {
		t.Fatalf("net %d, to others %d, own %d", fl.NetLovelace, fl.ToOthersLovelace, fl.OwnOutputLovelace)
	}
}

// Rewards and refunds that leave with the transaction are not hidden by the
// inputs: a stake key's request with a refund of its own credential counts it.
// spec: SPO-Xparty-PR-002
func TestRefundOfAnOwnCredentialIsInTheNet(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	dereg, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertDeregistration, Stake: stake.KeyHash(f.bobHash), Deposit: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}},
		Outputs:      []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 11_800_000}},
		Certificates: []stake.Certificate{dereg}})
	f.accepted(f.send(f.signer(), f.request(body, custody.RoleStake, f.bobHash), ports.ViaFile))
	fl := f.review().Flow
	// The 10 ada input is not his (unresolved: not checked); the refund is his.
	if fl.Checked || fl.RefundsOwn != 2_000_000 || fl.Refunds != 2_000_000 {
		t.Fatalf("refund terms: %+v", fl)
	}
	// Once his provider answers, the input is resolved as another key's and the
	// refund shows as money that arrives to him and leaves to the outputs.
	f.utxos.put(f.testnetAddr(other28), chain.Utxo{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000})
	f.refuseAll()
	f.accepted(f.send(f.signer(), f.request(body, custody.RoleStake, f.bobHash), ports.ViaFile))
	fl = f.review().Flow
	if !fl.Checked || fl.NetLovelace != 2_000_000 || fl.RefundsOwn != 2_000_000 {
		t.Fatalf("net %d: %+v", fl.NetLovelace, fl)
	}
}

// refuseAll declines everything pending, so the next request is the only one.
func (f *fixture) refuseAll() {
	f.t.Helper()
	pend, _ := f.signer().Pending(ctx)
	for _, p := range pend {
		if _, err := f.signer().Refuse(ctx, p.ID); err != nil {
			f.t.Fatal(err)
		}
	}
	f.B.Outbox().Flush(ctx, partyrig.NewPipe(ports.ViaFile).Transport())
}

// The approval is claimed against what the signer sees then: an own UTxO that
// is spent, or whose value is not what was shown, between the review and the
// approval makes the approval stale, and nothing is signed.
// spec: SPO-Xparty-INV-025, SPO-Xparty-INV-016
func TestApproveRefusesAFlowThatChangedSinceTheReview(t *testing.T) {
	for name, change := range map[string]func(f *fixture){
		"the UTxO is spent": func(f *fixture) { f.utxos.spend(f.own) },
		"the UTxO is not as big": func(f *fixture) {
			f.utxos.put(f.payAddr, chain.Utxo{TxID: f.own.TxID, Index: f.own.Index, Lovelace: 1_000_000})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, payAndStake)
			body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own},
				Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 49_800_000}}})
			f.accepted(f.send(f.signer(), f.request(body, custody.RolePayment, f.payHash), ports.ViaFile))
			a, err := f.review().Approval()
			if err != nil {
				t.Fatal(err)
			}
			change(f)
			if _, err := f.signer().Approve(ctx, a); !errors.Is(err, multisig.ErrReviewStale) {
				t.Fatalf("Approve: %v", err)
			}
			if f.B.Gate.Count() != 0 {
				t.Fatal("the operator was asked to authenticate for a stale approval")
			}
			if items, _ := f.B.Outbox().Pending(ctx); len(items) != 0 {
				t.Fatalf("queued %+v", items)
			}
		})
	}
}

// Enrollment refuses a node key that another enrolled party already has.
// spec: SPO-Xparty-INV-018
func TestEnrollRefusesANodeKeyAnotherPartyHas(t *testing.T) {
	w := newWorld(t, &party.NodeKey{0xb0, 3})
	other := partyrig.NewWithNode(t, "twin", w.clock, w.chain.Chain, &party.NodeKey{0xb0, 3}) // the same node key as bob's
	doc, err := parties.ExportIdentity{Store: other.Store, Kit: other.Kit}.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	uc := parties.Enroll{Store: w.C.Store, Kit: w.C.Kit, Registry: w.C.Registry, Clock: w.clock}
	_, err = uc.Run(ctx, parties.EnrollRequest{Document: doc.Document, Name: "twin", Roles: []party.Role{party.RoleSigner}, Confirmation: doc.Fingerprint.String()[:19]})
	if !errors.Is(err, party.ErrNodeKeyInUse) {
		t.Fatalf("a second party with bob's node key: %v", err)
	}
	var ps []party.Party
	if err := w.C.Store.View(ctx, func(r ports.Reader) error {
		var err error
		ps, err = w.C.Registry.List(r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.Name == "twin" {
			t.Fatal("the twin was enrolled")
		}
	}
}

// The size limit counts the auxiliary data: a body whose metadata makes the
// transaction too big is refused by the coordinator before it seals, and a
// request a lying coordinator seals anyway is refused on receipt.
// spec: SPO-Xparty-INV-008
func TestOversizedAuxiliaryDataIsRefusedBothEnds(t *testing.T) {
	f := newFixture(t, payAndStake)
	var lines []string
	for range 247 {
		lines = append(lines, strings.Repeat("x", 64))
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own}, Message: lines,
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 49_800_000}}})
	req := f.request(body, custody.RolePayment, f.payHash)
	if len(req.TxBody) > party.DefaultMaxTxSize || len(req.AuxData) > party.DefaultMaxTxSize || len(req.TxBody)+len(req.AuxData) <= party.DefaultMaxTxSize {
		t.Fatalf("the fixture: body %d, aux %d: want each within and together over %d", len(req.TxBody), len(req.AuxData), party.DefaultMaxTxSize)
	}
	h := f.send(f.signer(), req, ports.ViaFile)
	if !h.Refused || !strings.Contains(h.Reason, "together exceed maxTxSize") {
		t.Fatalf("on receipt: %+v", h)
	}
	if pend, _ := f.signer().Pending(ctx); len(pend) != 0 {
		t.Fatal("it waits for a decision")
	}
	// The coordinator: a collection of this body is not sealed into a request.
	c := f.C.Coordinator()
	_, err := c.Open(ctx, multisig.OpenRequest{Name: "big", Body: body, TTL: 1500, Slots: []pool.Slot{{Name: "pay", Role: custody.RolePayment,
		KeyHash: f.payHash, Holder: custody.HolderRemote, Party: "bobparty"}}})
	if err == nil || !strings.Contains(err.Error(), "maxTxSize") {
		t.Fatalf("a collection with an oversized transaction: %v", err)
	}
}
