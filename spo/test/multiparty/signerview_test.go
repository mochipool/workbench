package multiparty

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// The attacks on what a signer is shown and what it is asked: a coordinator
// that is enrolled, authenticated and hostile. Each is refused with its reason,
// and nothing is signed.

// utxoSet is the signer's own chain view, a ports.UtxoResolver over a map of
// references. A reference it was not told about is Unknown, as the snapshot's
// and Koios' are.
type utxoSet struct {
	byRef map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]
	fail  error
}

func (u *utxoSet) Source() chain.Source { return "the signer's own view" }

// put makes the UTxO unspent at the address.
func (u *utxoSet) put(addr chain.Address, ut chain.Utxo) {
	if u.byRef == nil {
		u.byRef = map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]{}
	}
	u.byRef[chain.OutRef{TxID: ut.TxID, Index: ut.Index}] = chain.Value(chain.ResolvedUtxo{Address: addr, Lovelace: ut.Lovelace, Assets: ut.Assets})
}

// spend makes the provider say the UTxO is spent.
func (u *utxoSet) spend(ut chain.Utxo) {
	u.byRef[chain.OutRef{TxID: ut.TxID, Index: ut.Index}] = chain.None[chain.ResolvedUtxo]()
}

func (u *utxoSet) ResolveUtxos(_ context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	if u.fail != nil {
		return nil, u.fail
	}
	out := map[chain.OutRef]chain.Reading[chain.ResolvedUtxo]{}
	for _, r := range refs {
		if v, ok := u.byRef[r]; ok {
			out[r] = v
		} else {
			out[r] = chain.Unknown[chain.ResolvedUtxo]("the rig's provider has no answer for " + r.String())
		}
	}
	return out, nil
}

// fixture is the world with a payment key on bob's machine, his own address
// with one UTxO of 50 ada, and a coordinator scoped as the test names.
type fixture struct {
	*world
	payHash txbuild.KeyHash
	payAddr chain.Address
	own     chain.Utxo // 50 ada at payAddr
	utxos   *utxoSet
	rewards chain.StakeAddress
}

var other28 = txbuild.KeyHash{0xdd}

func newFixture(t *testing.T, scope func(w *world) party.Scope) *fixture {
	t.Helper()
	w := newWorldOpt(t, worldOpt{wide: true, coordScope: scope})
	f := &fixture{world: w}
	f.payHash = w.B.AddKey(custody.RolePayment, "bobpay")
	var err error
	if f.payAddr, err = w.led.BuildAddress(0, f.payHash, nil); err != nil {
		t.Fatal(err)
	}
	if f.rewards, err = w.led.BuildStakeAddress(0, w.bobHash); err != nil {
		t.Fatal(err)
	}
	f.own = chain.Utxo{TxID: chain.TxID{0xb0}, Index: 0, Lovelace: 50_000_000}
	f.utxos = &utxoSet{}
	f.utxos.put(f.payAddr, f.own)
	// bob's credentials: the hashes of the payment and stake keys in his store.
	w.B.Owned = party.OwnedKeys{Payment: [][28]byte{f.payHash}, Stake: [][28]byte{w.bobHash}}
	w.B.Resolver = f.utxos
	w.B.Addresses = w.led
	w.B.AddKnownKey(custody.RoleStake, "bob", [28]byte(w.bobHash))
	return f
}

// scoped is the scope of the coordinator at bob's machine, as the test names
// it: the roles, whether it is unscoped, and whether it may speak of the pool.
func scoped(unscoped, forThePool bool, roles ...custody.Role) func(w *world) party.Scope {
	return func(w *world) party.Scope {
		sc := party.Scope{KeyRoles: roles, Unscoped: unscoped}
		if forThePool {
			sc.Pools = []string{w.bech}
		}
		return sc
	}
}

var payAndStake = scoped(true, true, custody.RolePayment, custody.RoleStake)

func (f *fixture) testnetAddr(hash txbuild.KeyHash) chain.Address {
	f.t.Helper()
	a, err := f.led.BuildAddress(0, hash, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

// request is a SigningRequest for body (a built transaction), for the key.
func (f *fixture) request(body txbuild.TxBody, role custody.Role, hash txbuild.KeyHash) party.SigningRequest {
	f.t.Helper()
	m := bodyMap(f.t, body)
	aux, err := native.TxViewer{}.AuxOf(body.CBOR)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.requestRaw(m, aux, role, hash)
}

// requestRaw is a request for body map bytes that need not come from a
// builder.
func (f *fixture) requestRaw(m, aux []byte, role custody.Role, hash txbuild.KeyHash) party.SigningRequest {
	f.t.Helper()
	view, err := native.TxViewer{}.View(m)
	var ttl uint64 = 1500
	if err == nil && view.TTL != nil {
		ttl = *view.TTL
	} else if t, ok := rawTTL(m); ok {
		ttl = t
	}
	var id party.CollectionID
	copy(id[:], fmt.Sprintf("coll-%d", time.Now().UnixNano()))
	return party.SigningRequest{Collection: id, Slot: 0, KeyRole: role, KeyHash: [28]byte(hash), Operation: string(custody.OpWitnessTx),
		TxBody: m, BodyHash: blake2b.Sum256(m), TTLSlot: ttl, NetworkMagic: partyrig.Magic, Purpose: "do the thing", AuxData: aux}
}

// rawTTL reads key 3 of a body map written by rawBody.
func rawTTL(m []byte) (uint64, bool) {
	i := bytes.Index(m, []byte{0x03, 0x19})
	if i < 0 || i+4 > len(m) {
		return 0, false
	}
	return uint64(m[i+2])<<8 | uint64(m[i+3]), true
}

// send seals req from the coordinator to bob and hands it to bob's signer.
func (f *fixture) send(s multisig.Signer, req party.SigningRequest, via ports.TransportKind) multisig.Handled {
	f.t.Helper()
	env := seal(f.t, f.world, req)
	rcv := partyrig.Received(env, via)
	h, err := s.Handle(ctx, rcv)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func seal(t *testing.T, w *world, body party.Body) []byte {
	t.Helper()
	return partyrig.Seal(t, w.C, w.B, body, 5*time.Minute) // inside the ttl slot's time (INV-009)
}

// signer is bob's signer role.
func (f *fixture) signer() multisig.Signer { return f.B.Signer() }

// builtBody is a transaction built by the native builder: the inputs, outputs
// and the rest as given, with a TTL.
func (f *fixture) builtBody(spec txbuild.BodySpec) txbuild.TxBody {
	f.t.Helper()
	if spec.TTL == 0 {
		spec.TTL = 1500
	}
	if spec.Fee == 0 {
		spec.Fee = 200_000
	}
	b, err := f.led.BuildBody(spec)
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

// silentRefusal asserts that the request was refused for reason, was kept
// to ourselves, left no body behind and signed nothing.
func (f *fixture) silentRefusal(h multisig.Handled, reason party.RefusalReason, body []byte) {
	f.t.Helper()
	f.refusal(h, reason, body)
	if items, _ := f.B.Outbox().Pending(ctx); len(items) != 0 {
		f.t.Fatalf("a refusal for %q was sent to the coordinator: %+v", reason, items)
	}
}

// sentRefusal is a refusal the coordinator is told about.
func (f *fixture) sentRefusal(h multisig.Handled, reason party.RefusalReason, body []byte) {
	f.t.Helper()
	f.refusal(h, reason, body)
	items, _ := f.B.Outbox().Pending(ctx)
	if len(items) != 1 || items[0].Type != string(party.TypeSigningRefusal) {
		f.t.Fatalf("the refusal for %q is not queued for the coordinator: %+v", reason, items)
	}
}

func (f *fixture) refusal(h multisig.Handled, reason party.RefusalReason, body []byte) {
	f.t.Helper()
	if h.Refused || h.Effect != "refused" || h.Reason != reason.String() {
		f.t.Fatalf("handled = %+v, want a refusal for %q", h, reason)
	}
	if !f.B.HasEvent("request-refused", reason.String()) {
		f.t.Errorf("no audit event for %q: %v", reason, f.B.Events())
	}
	if pend, _ := f.signer().Pending(ctx); len(pend) != 0 {
		f.t.Error("the refused request waits for a decision")
	}
	if n := f.B.Gate.Count(); n != 0 {
		f.t.Errorf("the gate was asked %d times: something was about to be signed", n)
	}
	// A refused request is kept without its body.
	raw := f.signerRecord()
	if len(body) > 0 && bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(body))) {
		f.t.Error("a refused request is stored with its body")
	}
}

// signerRecord is bob's inbox record, as stored.
func (f *fixture) signerRecord() []byte {
	f.t.Helper()
	var raw []byte
	if err := f.B.Store.View(ctx, func(r ports.Reader) error {
		var err error
		raw, err = r.Get(ports.Ref{Name: "state", Kind: ports.MultisigSigner})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// accepted asserts the request is stored, pending, for review.
func (f *fixture) accepted(h multisig.Handled) {
	f.t.Helper()
	if h.Refused || h.Effect != "stored" {
		f.t.Fatalf("handled = %+v, want it stored for review", h)
	}
	if pend, _ := f.signer().Pending(ctx); len(pend) != 1 {
		f.t.Fatalf("pending = %+v", pend)
	}
}

func (f *fixture) review() multisig.Review {
	f.t.Helper()
	pend, _ := f.signer().Pending(ctx)
	rv, err := f.signer().ReviewRequest(ctx, pend[0].ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return rv
}

// ---- H1: whose money leaves -------------------------------------------------------

// A payment-key request is refused when the signer has no UTxO reader of its
// own, or its lookup fails: it cannot see whose money would leave.
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-006
func TestAttackPaymentKeyRequestWithoutAUTxOReader(t *testing.T) {
	f := newFixture(t, payAndStake)
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 49_800_000}}})
	req := f.request(body, custody.RolePayment, f.payHash)

	f.B.Resolver = nil
	h := f.send(f.signer(), req, ports.ViaFile)
	f.silentRefusal(h, party.RefuseCannotResolveInputs, req.TxBody)

	// A reader that fails is the same: its answer is unknown, never "none".
	f.B.Resolver = &utxoSet{fail: context.DeadlineExceeded}
	req2 := f.request(body, custody.RolePayment, f.payHash)
	f.silentRefusal(f.send(f.signer(), req2, ports.ViaFile), party.RefuseCannotResolveInputs, req2.TxBody)
}

// A payment-key request that spends the signer's UTxO to an output that is not
// its own is accepted for review, and the review shows the outflow, the marks
// and the fee in numbers the signer worked out itself.
// spec: SPO-Xparty-PR-002
func TestPaymentKeyRequestShowsWhoseMoneyLeaves(t *testing.T) {
	f := newFixture(t, payAndStake)
	foreign := chain.Utxo{TxID: chain.TxID{0xf0}, Index: 3, Lovelace: 1_000_000_000}
	f.utxos.put(f.testnetAddr(other28), foreign) // someone else's: resolved, at another key's address
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own, foreign},
		Outputs: []txbuild.Output{
			{Address: f.testnetAddr(other28), Lovelace: 1_030_000_000}, // to someone else
			{Address: f.payAddr, Lovelace: 19_800_000},                 // change to bob
		}})
	f.accepted(f.send(f.signer(), f.request(body, custody.RolePayment, f.payHash), ports.ViaFile))
	rv := f.review()
	fl := rv.Flow
	if !fl.Checked || len(fl.OwnInputs) != 1 || fl.OwnInputs[0].Lovelace != 50_000_000 || fl.ForeignInputs != 1 {
		t.Fatalf("inputs: %+v", fl)
	}
	if len(fl.Outputs) != 2 || fl.Outputs[0].Own || !fl.Outputs[1].Own {
		t.Fatalf("output marks: %+v", fl.Outputs)
	}
	// 50 ada of his go in, 19.8 come back: 30.2 leave, the fee among it.
	if fl.NetLovelace != 30_200_000 || fl.Fee != 200_000 {
		t.Fatalf("net outflow %d, fee %d", fl.NetLovelace, fl.Fee)
	}
	if len(rv.View.Outputs) != 2 || rv.TotalOutput != 1_049_800_000 {
		t.Fatalf("view: %+v", rv.View.Outputs)
	}
	// It can be approved: the flow met the rule.
	if _, err := rv.Approval(); err != nil {
		t.Fatal(err)
	}
}

// A payment-key request in which none of the inputs is the signer's is
// refused: the key is not needed for this body.
// spec: SPO-Xparty-PR-002
func TestAttackPaymentKeyRequestWithNoInputOfTheSigner(t *testing.T) {
	f := newFixture(t, payAndStake)
	notMine := chain.Utxo{TxID: chain.TxID{0xee}, Index: 0, Lovelace: 5_000_000}
	f.utxos.put(f.testnetAddr(other28), notMine) // resolved, and not at an address of bob's key
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{notMine},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 4_800_000}}})
	req := f.request(body, custody.RolePayment, f.payHash)
	f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseNotASignerInput, req.TxBody)
}

// A key that cannot spend funds does not need its inputs resolved: the review
// says they were not checked.
// spec: SPO-Xparty-PR-002
func TestStakeKeyRequestStatesThatInputsWereNotChecked(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	cert, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertRegistration, Stake: stake.KeyHash(f.bobHash), Deposit: 2_000_000})
	if err != nil {
		t.Fatal(err)
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}},
		Outputs:      []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 7_800_000}},
		Certificates: []stake.Certificate{cert}})
	f.B.Resolver = nil
	f.accepted(f.send(f.signer(), f.request(body, custody.RoleStake, f.bobHash), ports.ViaFile))
	rv := f.review()
	if rv.Flow.Checked || rv.Flow.NotChecked != party.NotCheckedText || rv.Flow.Deposits != 2_000_000 {
		t.Fatalf("flow: %+v", rv.Flow)
	}
	// With a reader, the same kind of request resolves its inputs anyway.
}

// ---- H2: the coordinator's scope ---------------------------------------------------

func (f *fixture) delegationBody(pool chain.PoolID) txbuild.TxBody {
	f.t.Helper()
	cert, err := f.led.BuildCertificate(stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(f.bobHash), Pool: pool})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}},
		Outputs:      []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 9_800_000}},
		Certificates: []stake.Certificate{cert}})
}

// A body that delegates to pool B, from a coordinator scoped to pool A, is out
// of scope; one that delegates to pool A is not.
// spec: SPO-Xparty-INV-010, SPO-Xparty-INV-006
func TestAttackDelegationToAnotherPoolThanTheCoordinatorsScope(t *testing.T) {
	f := newFixture(t, scoped(false, true, custody.RoleStake))
	mine := f.request(f.delegationBody(f.poolID), custody.RoleStake, f.bobHash)
	f.accepted(f.send(f.signer(), mine, ports.ViaFile)) // pool A: fine
	if _, err := f.signer().Refuse(ctx, mustPending(t, f.signer())); err != nil {
		t.Fatal(err)
	}
	f.B.Gate.Calls = nil
	drained := partyrig.NewPipe(ports.ViaFile)
	f.B.Outbox().Flush(ctx, drained.Transport())
	drained.Take()

	attack := f.request(f.delegationBody(f.otherID), custody.RoleStake, f.bobHash) // pool B
	f.silentRefusal(f.send(f.signer(), attack, ports.ViaFile), party.RefuseOutOfScope, attack.TxBody)
}

func mustPending(t *testing.T, s multisig.Signer) party.MessageID {
	t.Helper()
	pend, err := s.Pending(ctx)
	if err != nil || len(pend) != 1 {
		t.Fatalf("pending = %+v, %v", pend, err)
	}
	return pend[0].ID
}

// A body that concerns no pool, a payment, from a coordinator that is not
// unscoped, is out of scope, with the right key and the right role.
// spec: SPO-Xparty-INV-010
func TestAttackPoolLessPaymentFromACoordinatorWithoutUnscoped(t *testing.T) {
	f := newFixture(t, scoped(false, true, custody.RolePayment, custody.RoleStake))
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 49_800_000}}})
	req := f.request(body, custody.RolePayment, f.payHash)
	f.silentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseOutOfScope, req.TxBody)
}

// A request for a key role the coordinator was not given is out of scope, and
// the answer is the same whether or not bob holds such a key: the coordinator
// learns nothing about his keys.
// spec: SPO-Xparty-INV-010, SPO-Xparty-INV-006
func TestAttackKeyRoleOutsideTheCoordinatorsKeyRoles(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{f.own},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 49_800_000}}})
	held := f.request(body, custody.RolePayment, f.payHash) // bob holds this key
	f.silentRefusal(f.send(f.signer(), held, ports.ViaFile), party.RefuseOutOfScope, held.TxBody)
	unheld := f.request(body, custody.RolePoolCold, txbuild.KeyHash{0x99}) // and not this one
	f.silentRefusal(f.send(f.signer(), unheld, ports.ViaFile), party.RefuseOutOfScope, unheld.TxBody)
}

func (f *fixture) auxOf(b txbuild.TxBody) []byte {
	f.t.Helper()
	aux, err := native.TxViewer{}.AuxOf(b.CBOR)
	if err != nil || aux == nil {
		f.t.Fatalf("no auxiliary data: %v", err)
	}
	return aux
}

// ---- M1: an unset transport kind is a network --------------------------------------

// A request for a pool cold key that arrives with no stated transport kind is
// refused as a network request; by file it is accepted.
// spec: SPO-Xparty-PRE-004, SPO-Xparty-PRE-006, SPO-Xparty-INV-024
func TestAttackColdKeyRequestWithAnUnsetTransportKind(t *testing.T) {
	f := newFixture(t, func(w *world) party.Scope {
		return party.Scope{KeyRoles: []custody.Role{custody.RolePoolCold}, Pools: []string{w.otherBech}}
	})
	cert, err := f.led.BuildPoolRetirement(poolRetirement(f.otherID))
	if err != nil {
		t.Fatal(err)
	}
	body := f.builtBody(txbuild.BodySpec{Inputs: []chain.Utxo{{TxID: chain.TxID{0xaa}, Lovelace: 10_000_000}},
		Outputs:      []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 9_800_000}},
		Certificates: []stake.Certificate{cert.Attachment(0)}})
	for _, via := range []ports.TransportKind{ports.ViaUnknown, ports.ViaNetwork} {
		req := f.request(body, custody.RolePoolCold, txbuild.KeyHash(f.otherID))
		f.sentRefusal(f.send(f.signer(), req, via), party.RefuseColdKeyOverNetwork, req.TxBody)
		f.B.Outbox().Flush(ctx, partyrig.NewPipe(ports.ViaFile).Transport()) // drain for the next round
	}
	f.accepted(f.send(f.signer(), f.request(body, custody.RolePoolCold, txbuild.KeyHash(f.otherID)), ports.ViaFile))
}

// ---- M3: what is not shown is not signed ------------------------------------------

func cb(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
	return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func cbBytes(b []byte) []byte { return cat(cb(2, uint64(len(b))), b) }

func cbText(s string) []byte { return cat(cb(3, uint64(len(s))), []byte(s)) }

func (f *fixture) addrBytes(a chain.Address) []byte {
	f.t.Helper()
	_, raw, err := chain.Bech32Decode(string(a))
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// rawBody is a body map written by hand: one input, the outputs given (each
// already CBOR), a fee, a ttl, and the extra key/value pairs.
func rawBody(ttl uint64, in byte, outputs [][]byte, extras ...[]byte) []byte {
	out := cb(5, uint64(4+len(extras)))
	out = cat(out, cb(0, 0), cb(4, 1), cb(4, 2), cbBytes(bytes.Repeat([]byte{in}, 32)), cb(0, 0))
	out = cat(out, cb(0, 1), cb(4, uint64(len(outputs))), cat(outputs...))
	out = cat(out, cb(0, 2), cb(0, 200_000), cb(0, 3), cb(0, ttl))
	return cat(append([][]byte{out}, extras...)...)
}

func (f *fixture) plainOut(a chain.Address, coin uint64) []byte {
	return cat(cb(4, 2), cbBytes(f.addrBytes(a)), cb(0, coin))
}

var rewardAcct = cbBytes(append([]byte{0xe0}, bytes.Repeat([]byte{0x77}, 28)...)) // a testnet reward account

// A body with a part a remote signer cannot be shown is refused, and the
// coordinator is told: a proposal, collateral, a script data hash, reference
// inputs, an inline datum, a datum hash, a script reference, a mint.
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-006
func TestAttackBodiesWithPartsThatCannotBeDisplayed(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	good := f.plainOut(f.testnetAddr(other28), 9_800_000)
	txin := cat(cb(4, 1), cb(4, 2), cbBytes(bytes.Repeat([]byte{9}, 32)), cb(0, 0))
	hash32 := cbBytes(bytes.Repeat([]byte{5}, 32))
	toAddr := cbBytes(f.addrBytes(f.testnetAddr(other28)))
	cases := map[string][]byte{
		"a proposal": rawBody(1500, 1, [][]byte{good}, cat(cb(0, 20), []byte{0xd9, 0x01, 0x02}, cb(4, 1),
			cb(4, 4), cb(0, 500_000_000_000), rewardAcct, cb(4, 1), cb(0, 6), cb(4, 2), cbText("https://x.example/a"), hash32)),
		"collateral":         rawBody(1500, 1, [][]byte{good}, cat(cb(0, 13), txin)),
		"total collateral":   rawBody(1500, 1, [][]byte{good}, cat(cb(0, 17), cb(0, 5_000_000))),
		"a script data hash": rawBody(1500, 1, [][]byte{good}, cat(cb(0, 11), hash32)),
		"reference inputs":   rawBody(1500, 1, [][]byte{good}, cat(cb(0, 18), txin)),
		"an inline datum":    rawBody(1500, 1, [][]byte{cat(cb(5, 3), cb(0, 0), toAddr, cb(0, 1), cb(0, 9_800_000), cb(0, 2), cb(4, 2), cb(0, 1), []byte{0xd8, 0x18}, cbBytes([]byte{0x01}))}),
		"a datum hash":       rawBody(1500, 1, [][]byte{cat(cb(4, 3), toAddr, cb(0, 9_800_000), hash32)}),
		"a script reference": rawBody(1500, 1, [][]byte{cat(cb(5, 3), cb(0, 0), toAddr, cb(0, 1), cb(0, 9_800_000), cb(0, 3), []byte{0xd8, 0x18}, cbBytes([]byte{0x01}))}),
		"a mint":             rawBody(1500, 1, [][]byte{good}, cat(cb(0, 9), cb(5, 1), cbBytes(bytes.Repeat([]byte{7}, 28)), cb(5, 1), cbBytes([]byte("T")), cb(0, 1))),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := f.requestRaw(body, nil, custody.RoleStake, f.bobHash)
			f.sentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseUndisplayable, body)
			f.B.Outbox().Flush(ctx, partyrig.NewPipe(ports.ViaFile).Transport())
		})
	}
	// Control: the same builder without the extra part is stored.
	f.accepted(f.send(f.signer(), f.requestRaw(rawBody(1500, 1, [][]byte{good}), nil, custody.RoleStake, f.bobHash), ports.ViaFile))
}

// A body that names auxiliary data comes with it, and the hash matches; the
// signer shows the metadata, CIP-20 messages as text.
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-020
func TestAuxiliaryDataIsCarriedCheckedAndShown(t *testing.T) {
	f := newFixture(t, payAndStake)
	spec := txbuild.BodySpec{Inputs: []chain.Utxo{f.own}, Message: []string{"rent for November"},
		Outputs: []txbuild.Output{{Address: f.testnetAddr(other28), Lovelace: 49_800_000}}}
	body := f.builtBody(spec)
	good := f.request(body, custody.RolePayment, f.payHash)
	if len(good.AuxData) == 0 {
		t.Fatal("the request does not carry the auxiliary data")
	}

	none := good
	none.AuxData = nil
	f.sentRefusal(f.send(f.signer(), none, ports.ViaFile), party.RefuseUndisplayable, none.TxBody)
	f.B.Outbox().Flush(ctx, partyrig.NewPipe(ports.ViaFile).Transport())

	spec.Message = []string{"send me everything"}
	liar := good
	liar.AuxData = f.auxOf(f.builtBody(spec))
	f.sentRefusal(f.send(f.signer(), liar, ports.ViaFile), party.RefuseUndisplayable, liar.TxBody)
	f.B.Outbox().Flush(ctx, partyrig.NewPipe(ports.ViaFile).Transport())

	f.accepted(f.send(f.signer(), good, ports.ViaFile))
	rv := f.review()
	if rv.Aux == nil || len(rv.Aux.Labels) != 1 || rv.Aux.Labels[0].Label != 674 || len(rv.Aux.Labels[0].Messages) != 1 || rv.Aux.Labels[0].Messages[0] != "rent for November" {
		t.Fatalf("the metadata is not shown: %+v", rv.Aux)
	}
}

// ---- L1: the body's own network -----------------------------------------------------

// A body with an address of another network, or a network id that is not the
// workspace's, is refused.
// spec: SPO-Xparty-PRE-006
func TestAttackBodyForAnotherNetwork(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	mainnet, err := f.led.BuildAddress(1, other28, nil)
	if err != nil {
		t.Fatal(err)
	}
	good := f.plainOut(f.testnetAddr(other28), 9_800_000)
	mainnetReward := cbBytes(append([]byte{0xe1}, bytes.Repeat([]byte{0x77}, 28)...))
	cases := map[string][]byte{
		"an output on mainnet":         rawBody(1500, 1, [][]byte{f.plainOut(mainnet, 9_800_000)}),
		"a withdrawal on mainnet":      rawBody(1500, 1, [][]byte{good}, cat(cb(0, 5), cb(5, 1), mainnetReward, cb(0, 1))),
		"a network id of mainnet":      rawBody(1500, 1, [][]byte{good}, cat(cb(0, 15), cb(0, 1))),
		"one output of two on mainnet": rawBody(1500, 1, [][]byte{good, f.plainOut(mainnet, 1_000_000)}),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := f.requestRaw(body, nil, custody.RoleStake, f.bobHash)
			f.sentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseWrongNetwork, body)
			f.B.Outbox().Flush(ctx, partyrig.NewPipe(ports.ViaFile).Transport())
		})
	}
	// The matching testnet network id is fine.
	f.accepted(f.send(f.signer(), f.requestRaw(rawBody(1500, 1, [][]byte{good}, cat(cb(0, 15), cb(0, 0))), nil, custody.RoleStake, f.bobHash), ports.ViaFile))
}

// ---- L2: a map or a set with a repeat ---------------------------------------------

// A withdrawal key twice is a body that does not decode, whatever the decoder
// that signs would have made of it.
// spec: SPO-Xparty-PR-002
func TestAttackDuplicateWithdrawalKey(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	good := f.plainOut(f.testnetAddr(other28), 9_800_000)
	body := rawBody(1500, 1, [][]byte{good}, cat(cb(0, 5), cb(5, 2), rewardAcct, cb(0, 1), rewardAcct, cb(0, 9_000_000)))
	req := f.requestRaw(body, nil, custody.RoleStake, f.bobHash)
	f.sentRefusal(f.send(f.signer(), req, ports.ViaFile), party.RefuseBodyDecode, body)
}

func poolRetirement(id chain.PoolID) pool.RetirementSpec {
	return pool.RetirementSpec{Pool: id, Epoch: 20}
}

// ---- M4: one enrolled party cannot exhaust a signer ------------------------------

// A second coordinator, enrolled at bob's with the same scope.
func (f *fixture) secondCoordinator() *partyrig.Workspace {
	f.t.Helper()
	c2 := partyrig.New(f.t, "coordinator2", f.clock, f.chain.Chain)
	scope := party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Unscoped: true}
	f.B.EnrollScoped(c2, "coord2", []party.Role{party.RoleCoordinator}, scope)
	c2.EnrollScoped(f.B, "bob", []party.Role{party.RoleSigner}, scope)
	return c2
}

// One coordinator with as many undecided requests as a signer takes is refused
// the next, and only that coordinator is: another still gets through. A
// decision frees a place.
// spec: SPO-Xparty-INV-022
func TestOneSendersQuotaDoesNotBlockAnother(t *testing.T) {
	f := newFixture(t, scoped(true, true, custody.RoleStake))
	c2 := f.secondCoordinator()
	body := rawBody(1500, 1, [][]byte{f.plainOut(f.testnetAddr(other28), 9_800_000)})
	req := func() party.SigningRequest { return f.requestRaw(body, nil, custody.RoleStake, f.bobHash) }
	for i := 0; i < party.MaxPendingPerSender; i++ {
		if h := f.send(f.signer(), req(), ports.ViaFile); h.Refused || h.Effect != "stored" {
			t.Fatalf("request %d: %+v", i, h)
		}
	}
	over := f.send(f.signer(), req(), ports.ViaFile)
	if !over.Refused || over.Reason != multisig.ErrQuota.Error() {
		t.Fatalf("over quota: %+v", over)
	}
	if over.Outward() != nil {
		t.Error("something goes back to the sender")
	}
	if pend, _ := f.signer().Pending(ctx); len(pend) != party.MaxPendingPerSender {
		t.Fatalf("%d pending", len(pend))
	}
	// The other coordinator is not affected.
	h, err := f.signer().Handle(ctx, ports.FileReceived(partyrig.Seal(t, c2, f.B, req(), 5*time.Minute)))
	if err != nil || h.Refused || h.Effect != "stored" {
		t.Fatalf("another coordinator: %+v, %v", h, err)
	}
	// Declining one frees a place for the first.
	pend, _ := f.signer().Pending(ctx)
	if _, err := f.signer().Refuse(ctx, pend[0].ID); err != nil {
		t.Fatal(err)
	}
	if h := f.send(f.signer(), req(), ports.ViaFile); h.Refused || h.Effect != "stored" {
		t.Fatalf("after a decision: %+v", h)
	}
	// The refusal was an authenticated sender's: a security event.
	if !f.B.HasEvent("envelope-refused", multisig.ErrQuota.Error()) {
		t.Errorf("no audit event: %v", f.B.Events())
	}
}

// ---- M5: garbage does not flush the audit log -------------------------------------

// Hundreds of envelopes that fail before the signature step leave every
// security event in place; they fill their own ring and counter.
// spec: SPO-Xparty-INV-023, SPO-Xparty-INV-006
func TestGarbageDoesNotEvictSecurityEvents(t *testing.T) {
	w, _, _ := requested(t)
	before := w.C.Events()
	if len(before) < 2 {
		t.Fatalf("only %d security events", len(before))
	}
	for i := 0; i < 400; i++ {
		junk := bytes.Repeat([]byte{byte(i), byte(i >> 8)}, 40)
		h, err := w.C.Coordinator().Handle(ctx, ports.FileReceived(junk))
		if err != nil || !h.Refused || h.HasSender {
			t.Fatalf("garbage %d: %+v, %v", i, h, err)
		}
	}
	after := w.C.Events()
	if len(after) != len(before) {
		t.Fatalf("security events %d, now %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("event %d changed: %+v, now %+v", i, before[i], after[i])
		}
	}
	ring, total := w.C.Noise()
	if total != 400 || len(ring) != 128 {
		t.Fatalf("noise: %d in the ring of %d", total, len(ring))
	}
}
