package multiparty

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// Fail closed: what the signer cannot tell is a script, and a request that
// came over a network is refused unless every input was resolved and read.

func headerAddr(t *testing.T, hdr byte, parts ...[]byte) chain.Address {
	t.Helper()
	b := []byte{hdr}
	for _, p := range parts {
		b = append(b, p...)
	}
	s, err := chain.Bech32Encode("addr_test", b)
	if err != nil {
		t.Fatal(err)
	}
	return chain.Address(s)
}

// stakeBody is a stake registration for bob's stake key that spends in.
func (f *fixture) stakeBody(in ...chain.Utxo) txbuild.TxBody {
	f.t.Helper()
	cert, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stake.KeyHash(f.bobHash), Deposit: 2_000_000})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.builtBody(txbuild.BodySpec{Inputs: in, Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 7_800_000}},
		Certificates: []stake.Certificate{cert}})
}

// Script inputs in the address forms other than enterprise are refused over
// the file transport for the stake and the payment key: a pointer address with
// a script payment credential (header 0x5), a script payment with a key stake
// (0x1) and a script with a script stake (0x3).
// spec: SPO-Xparty-PR-004, SPO-Xparty-PRE-006
func TestFileScriptInputInEveryAddressFormIsRefused(t *testing.T) {
	scr := bytes.Repeat([]byte{0x5c}, 28)
	forms := map[string]func(f *fixture) chain.Address{
		"script pointer 0x5": func(f *fixture) chain.Address { return headerAddr(t, 0x50, scr, []byte{1, 2, 3}) },
		"script payment, key stake 0x1": func(f *fixture) chain.Address {
			return headerAddr(t, 0x10, scr, f.bobHash[:])
		},
		"script payment, script stake 0x3": func(f *fixture) chain.Address { return headerAddr(t, 0x30, scr, scr) },
	}
	for name, mk := range forms {
		for _, role := range []custody.Role{custody.RoleStake, custody.RolePayment} {
			t.Run(name+"/"+string(role), func(t *testing.T) {
				f := newFixture(t, payAndStake)
				in := chain.Utxo{TxID: chain.TxID{0x5d}, Lovelace: 100_000_000}
				f.utxos.put(mk(f), in)
				var body txbuild.TxBody
				hash := f.bobHash
				if role == custody.RoleStake {
					body = f.stakeBody(in)
				} else {
					hash = f.payHash
					body = f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{in, f.own},
						Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 149_800_000}}})
				}
				req := f.request(body, role, hash)
				f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseScriptInput, req.TxBody)
			})
		}
	}
}

// A key payment credential with a script stake credential (header 0x2): the
// input is the signer's (its payment key spends it) and an output to the same
// address is NOT the signer's: its rewards belong to the script.
// spec: SPO-Xparty-PR-002
func TestKeyPaymentScriptStakeInputIsOwnOutputIsNot(t *testing.T) {
	f := newFixture(t, payAndStake)
	addr := headerAddr(t, 0x20, f.payHash[:], bytes.Repeat([]byte{0x5c}, 28))
	in := chain.Utxo{TxID: chain.TxID{0x2a}, Lovelace: 40_000_000}
	f.utxos.put(addr, in)
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{in}, Outputs: []txbuild.Output{{Address: addr, Lovelace: 39_800_000}}})
	f.accepted(f.send(f.signer(), f.request(body, custody.RolePayment, f.payHash), ports.ViaFile))
	fl := f.review().Flow
	if len(fl.OwnInputs) != 1 || fl.OwnInputs[0].Lovelace != 40_000_000 {
		t.Fatalf("the input is the signer's: %+v", fl)
	}
	if len(fl.Outputs) != 1 || fl.Outputs[0].Own || fl.Outputs[0].Note == "" || fl.ToOthersLovelace != 39_800_000 {
		t.Fatalf("the output to a script stake is not the signer's: %+v", fl.Outputs)
	}
}

// A signer with no address inspector refuses to work on any request, with a
// configuration error, rather than pass it unchecked.
// spec: SPO-Xparty-PR-004
func TestSignerWithoutAnAddressInspectorRefusesEveryRequest(t *testing.T) {
	f := newFixture(t, payAndStake)
	body := f.stakeBody(chain.Utxo{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000})
	f.B.Addresses = nil
	f.utxos.put(f.testnetAddr(other28), chain.Utxo{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000})
	env := seal(t, f.world, f.request(body, custody.RoleStake, f.bobHash))
	for _, via := range []ports.TransportKind{ports.ViaFile, ports.ViaNetwork} {
		if _, err := f.signer().Handle(context.Background(), partyrig.Received(env, via)); !errors.Is(err, multisig.ErrNoAddressInspector) {
			t.Fatalf("%v: err = %v, want ErrNoAddressInspector", via, err)
		}
	}
	if pend, _ := f.signer().Pending(ctx); len(pend) != 0 {
		t.Fatalf("a request was stored: %+v", pend)
	}
}

// A request over a network is refused, silently, for EVERY role unless the
// signer has its own chain view, every input resolves and every input address
// reads. The same body by file is shown with the not-checked warning.
// spec: SPO-Xparty-PRE-007, SPO-Xparty-PR-004
func TestNetworkRequestNeedsEveryInputResolvedAndRead(t *testing.T) {
	setup := func(t *testing.T) (*fixture, chain.Utxo) {
		f := newFixture(t, payAndStake)
		return f, chain.Utxo{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}
	}
	cases := []struct {
		name    string
		arrange func(f *fixture, in chain.Utxo)
	}{
		{"no resolver", func(f *fixture, in chain.Utxo) { f.B.Resolver = nil }},
		{"the input is unknown to the provider", func(f *fixture, in chain.Utxo) {}},
		{"the input is spent", func(f *fixture, in chain.Utxo) {
			f.utxos.put(f.testnetAddr(other28), in)
			f.utxos.spend(in)
		}},
		{"the provider fails", func(f *fixture, in chain.Utxo) { f.utxos.fail = context.DeadlineExceeded }},
		{"the input address cannot be read", func(f *fixture, in chain.Utxo) { f.utxos.put("not an address", in) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, in := setup(t)
			tc.arrange(f, in)
			body := f.stakeBody(in)
			for _, via := range []ports.TransportKind{ports.ViaNetwork, ports.ViaUnknown} {
				req := f.request(body, custody.RoleStake, f.bobHash)
				f.silentRefusal(f.send(f.signer(), req, via), party.RefuseCannotResolveInputs, req.TxBody)
			}
		})
	}
	t.Run("everything resolves", func(t *testing.T) {
		f, in := setup(t)
		f.utxos.put(f.testnetAddr(other28), in)
		f.accepted(f.send(f.signer(), f.request(f.stakeBody(in), custody.RoleStake, f.bobHash), ports.ViaNetwork))
	})
	t.Run("by file the same body is warned, not refused", func(t *testing.T) {
		f, in := setup(t)
		f.B.Resolver = nil
		f.accepted(f.send(f.signer(), f.request(f.stakeBody(in), custody.RoleStake, f.bobHash), ports.ViaFile))
		if fl := f.review().Flow; fl.Checked || fl.NotChecked != party.NotCheckedText {
			t.Fatalf("flow: %+v", fl)
		}
	})
}

// Over the file transport an input whose address cannot be read is a script
// for the signer, not a foreign input: refused, whatever the key role.
// spec: SPO-Xparty-PR-004
func TestFileInputAtAnUnreadableAddressIsRefusedAsAScript(t *testing.T) {
	f := newFixture(t, payAndStake)
	in := chain.Utxo{TxID: chain.TxID{0xab}, Lovelace: 10_000_000}
	f.utxos.put("not an address", in)
	req := f.request(f.stakeBody(in), custody.RoleStake, f.bobHash)
	f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseScriptInput, req.TxBody)
}

// The network rule is applied again at review, from the stored transport: a
// request accepted over a network while its inputs resolved cannot be
// reviewed once the signer's view stops resolving them.
// spec: SPO-Xparty-PRE-007
func TestNetworkRuleIsAppliedAgainAtReview(t *testing.T) {
	f := newFixture(t, payAndStake)
	in := chain.Utxo{TxID: chain.TxID{0xac}, Lovelace: 10_000_000}
	f.utxos.put(f.testnetAddr(other28), in)
	f.accepted(f.send(f.signer(), f.request(f.stakeBody(in), custody.RoleStake, f.bobHash), ports.ViaNetwork))
	f.B.Resolver = nil
	pend, _ := f.signer().Pending(ctx)
	if _, err := f.signer().ReviewRequest(ctx, pend[0].ID); !errors.Is(err, multisig.ErrCannotReview) {
		t.Fatalf("err = %v, want ErrCannotReview", err)
	}
}
