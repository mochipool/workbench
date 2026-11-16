package multiparty

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Third review: what a key witness can satisfy that the signer is never shown.

// scriptAddr is an enterprise address whose payment credential is a script.
func scriptAddr(t *testing.T) chain.Address {
	t.Helper()
	s, err := chain.Bech32Encode("addr_test", append([]byte{0x70}, bytes.Repeat([]byte{0x5c}, 28)...))
	if err != nil {
		t.Fatal(err)
	}
	return chain.Address(s)
}

// An input at a native-script address is refused for every key role: a key
// witness can satisfy a script that names the key, and the script is in the
// witness set, which the signer is never shown (N1).
// spec: SPO-Xparty-PR-004, SPO-Xparty-INV-006
func TestR3InputAtAScriptAddressIsRefusedForEveryRole(t *testing.T) {
	cases := []struct {
		name    string
		role    custody.Role
		hash    func(f *fixture) txbuild.KeyHash
		withOwn bool
	}{
		{"payment key, own input beside the script input", custody.RolePayment, func(f *fixture) txbuild.KeyHash { return f.payHash }, true},
		{"payment key, only a script input", custody.RolePayment, func(f *fixture) txbuild.KeyHash { return f.payHash }, false},
		{"stake key with a resolver", custody.RoleStake, func(f *fixture) txbuild.KeyHash { return f.bobHash }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, payAndStake)
			script := chain.Utxo{TxID: chain.TxID{0x5c}, Index: 0, Lovelace: 100_000_000}
			f.utxos.put(scriptAddr(t), script)
			ins := []chain.Utxo{script}
			if tc.withOwn {
				ins = append(ins, f.own)
			}
			spec := txbuild.BodySpec{Inputs: ins, Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 149_800_000}}}
			if tc.role == custody.RoleStake {
				cert, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stake.KeyHash(f.bobHash), Deposit: 2_000_000})
				if err != nil {
					t.Fatal(err)
				}
				spec.Certificates = []stake.Certificate{cert}
				spec.Outputs[0].Lovelace = 97_800_000
			}
			req := f.request(f.builtBody(spec), tc.role, tc.hash(f))
			f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseScriptInput, req.TxBody)
		})
	}
}

// A key that cannot spend from its own address and has no resolver is told,
// in the review, plainly, that the inputs were not checked and that a key
// witness satisfies native scripts that name the key (N1).
// spec: SPO-Xparty-PR-004
func TestR3ReviewWithoutAResolverStatesTheNativeScriptRisk(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	cert, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stake.KeyHash(f.bobHash), Deposit: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 7_800_000}}, Certificates: []stake.Certificate{cert}})
	f.B.Resolver = nil
	f.accepted(f.send(f.signer(), f.request(body, custody.RoleStake, f.bobHash), ports.ViaFile))
	fl := f.review().Flow
	if fl.Checked || !strings.Contains(fl.NotChecked, "native script") || !strings.Contains(fl.NotChecked, "inputs not checked") {
		t.Fatalf("the review does not say it plainly: %q", fl.NotChecked)
	}
}

// A withdrawal from a script reward account, a certificate on a script
// credential and a vote by a script voter are refused like a script input (N1).
// spec: SPO-Xparty-PR-004
func TestR3ScriptCredentialsInTheBodyAreRefused(t *testing.T) {
	scriptCred := bytes.Repeat([]byte{0x5c}, 28)
	scriptReward := cbBytes(append([]byte{0xf0}, scriptCred...)) // a testnet script reward account
	cases := map[string]func(f *fixture) []byte{
		"a withdrawal from a script reward account": func(f *fixture) []byte {
			return cat(cb(0, 5), cb(5, 1), scriptReward, cb(0, 3_000_000))
		},
		"a certificate on a script credential": func(f *fixture) []byte {
			return cat(cb(0, 4), cb(4, 1), cb(4, 2), cb(0, 1), cb(4, 2), cb(0, 1), cbBytes(scriptCred))
		},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, scoped(true, true, custody.RoleStake))
			f.utxos.put(f.testnetAddr(other28), chain.Utxo{TxID: chain.TxID{0x01, 0x01}})
			body := rawBody(1500, 1, [][]byte{f.plainOut(f.testnetAddr(other28), 9_800_000)}, extra(f))
			f.B.Resolver = nil // the refusal does not depend on resolving inputs
			req := f.requestRaw(body, nil, custody.RoleStake, f.bobHash)
			f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseScriptInput, body)
		})
	}
}

// A mint, reference inputs, collateral and a script data hash are refused for
// every role, the policy role included: remote signing signs no body whose
// scripts the signer cannot see being evaluated. The decision is that a mint
// is Undisplayable, not a part with its own scope rule (N1).
// spec: SPO-Xparty-PR-004, SPO-Xparty-PR-002
func TestR3MintAndScriptCompanionsAreRefusedForEveryRole(t *testing.T) {
	txin := cat(cb(4, 1), cb(4, 2), cbBytes(bytes.Repeat([]byte{9}, 32)), cb(0, 0))
	hash32 := cbBytes(bytes.Repeat([]byte{5}, 32))
	parts := map[string][]byte{
		"a mint":             cat(cb(0, 9), cb(5, 1), cbBytes(bytes.Repeat([]byte{7}, 28)), cb(5, 1), cbBytes([]byte("T")), cb(0, 1)),
		"reference inputs":   cat(cb(0, 18), txin),
		"collateral":         cat(cb(0, 13), txin),
		"a script data hash": cat(cb(0, 11), hash32),
	}
	for name, extra := range parts {
		for _, role := range []custody.Role{custody.RolePayment, custody.RoleStake, custody.RolePolicy} {
			t.Run(name+"/"+string(role), func(t *testing.T) {
				f := newFixture(t, scoped(true, true, custody.RolePayment, custody.RoleStake, custody.RolePolicy))
				body := rawBody(1500, 1, [][]byte{f.plainOut(f.testnetAddr(other28), 9_800_000)}, extra)
				req := f.requestRaw(body, nil, role, f.bobHash)
				f.sentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseUndisplayable, body)
			})
		}
	}
}

// Provider error text is not part of the review digest: an approval after a
// provider failed with another message the second time is not stale (item 7).
// spec: SPO-Xparty-INV-026
func TestR3ProviderErrorTextDoesNotMakeTheReviewStale(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	cert, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stake.KeyHash(f.bobHash), Deposit: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 7_800_000}}, Certificates: []stake.Certificate{cert}})
	f.B.Resolver = &utxoSet{fail: errors.New("dial tcp 10.0.0.1: i/o timeout after 3.002s")}
	f.accepted(f.send(f.signer(), f.request(body, custody.RoleStake, f.bobHash), ports.ViaFile))
	rv := f.review()
	if rv.Flow.NotCheckedDetail == "" || strings.Contains(rv.Flow.NotChecked, "10.0.0.1") {
		t.Fatalf("the error text is for display only: %+v", rv.Flow)
	}
	a, err := rv.Approval()
	if err != nil {
		t.Fatal(err)
	}
	f.B.Resolver = &utxoSet{fail: errors.New("dial tcp 10.0.0.1: i/o timeout after 3.007s")} // another message
	if _, err := f.signer().Approve(ctx, a); err != nil {
		t.Fatalf("a different error text made the review stale: %v", err)
	}
}

// With the inputs unchecked, a stake-role withdrawal of the signer's own
// rewards to someone else's output is visible as value leaving (N4).
// spec: SPO-Xparty-PR-003
func TestR3UncheckedReviewShowsOwnRewardsLeaving(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	rewardRaw := f.addrBytes(chain.Address(f.rewards))
	body := rawBody(1500, 1, [][]byte{f.plainOut(f.testnetAddr(other28), 19_800_000)}, cat(cb(0, 5), cb(5, 1), cbBytes(rewardRaw), cb(0, 20_000_000)))
	f.B.Resolver = nil
	f.accepted(f.send(f.signer(), f.requestRaw(body, nil, custody.RoleStake, f.bobHash), ports.ViaFile))
	fl := f.review().Flow
	if fl.Checked || !fl.NetExcludesInputs || fl.NetLovelace != 20_000_000 || fl.WithdrawalsOwn != 20_000_000 || fl.ToOthersLovelace != 19_800_000 {
		t.Fatalf("the withdrawal is not shown as leaving: %+v", fl)
	}
}

// A snapshot resolver is the signer's own only through the constructor that
// says so (item 8): a plain provider value cannot be assigned to the field.
// spec: SPO-Xparty-PR-005
func TestR3OwnResolverIsMadeOnlyByItsConstructors(t *testing.T) {
	var zero multisig.OwnResolver
	if zero.IsSet() {
		t.Fatal("the zero resolver is set")
	}
	u := &utxoSet{}
	var _ ports.UtxoResolver = u
	if !multisig.OwnProvider(u).IsSet() || !multisig.OwnSnapshot(u).IsSet() {
		t.Fatal("constructors make a set resolver")
	}
}
