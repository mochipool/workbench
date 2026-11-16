package poolops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var ctx = context.Background()

func (r *prig) run(uc RegisterPool) (RegisterResult, error) {
	return uc.Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay"})
}

// ready generates the certificate; every registration test starts from it.
func ready(t *testing.T) *prig {
	t.Helper()
	r := newPoolRig(t)
	r.mustGenerate()
	return r
}

func registered(status chain.PoolStatus) chain.Reading[chain.PoolState] {
	return chain.Value(chain.PoolState{Status: status})
}

// spec: SPO-05c-IF-001, SPO-05c-IF-002, SPO-05c-IN-001, SPO-05c-IN-003, SPO-05c-INV-004, SPO-05c-INV-005, SPO-05c-INV-007, SPO-05c-INV-009,
// spec: SPO-05c-EXT-004, SPO-05c-EXT-006, SPO-05c-EXT-007, SPO-05c-OUT-001, SPO-05c-OUT-005, SPO-05c-OUT-006, SPO-05c-MODE-006,
// spec: SPO-05c-PR-001, SPO-05c-PR-003, SPO-05c-INV-002, SPO-Pfiles-OUT-019
func TestFirstRegistrationAllLocal(t *testing.T) {
	r := ready(t)
	spec0 := mustSpec(t, r) // the certificate file is consumed by the registration
	res, err := r.run(r.register(false, func(uc *RegisterPool) {
		uc.Pools = &ppools{c: r.calls, src: "koios", r: chain.None[chain.PoolState]()}
		uc.Sources = SingleSourceAcknowledged
		uc.OnSingle = noopHook
	}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != pool.PoolRegistration || res.State != pool.CollectionSubmitted || !res.Submitted || res.Deposit != 500_000_000 || !res.SingleSource {
		t.Fatalf("%+v", res)
	}
	// The fee is estimated for 2 + owners witnesses, not for the inputs.
	if r.calls.count("fee witnesses=4") == 0 || r.calls.count("fee witnesses=3") != 0 || r.calls.count("fee witnesses=2") != 0 {
		t.Errorf("witness counts: %v", r.calls.l)
	}
	// Two confirmations, the first before any witness, the second before the submission.
	if r.calls.count("confirm body") != 1 || r.calls.count("confirm submit") != 1 {
		t.Errorf("%v", r.calls.l)
	}
	if got := r.conf.got[0]; got.Kind != "pool registration" || got.Stage != "body" || got.Deposit != 500_000_000 || got.Pledge != 100_000_000_000 || got.Pool != r.poolID.Bech32() ||
		len(got.Attachments) != 3 || !strings.Contains(got.Attachments[0], "pool registration") || !strings.Contains(got.Attachments[1], "delegation") {
		t.Errorf("%+v", got)
	}
	// One transaction: the pool certificate, then the owners' delegation certificates in descriptor order.
	if len(r.sub.sent) != 1 {
		t.Fatalf("%d submissions", len(r.sub.sent))
	}
	hexTx := fmt.Sprintf("%x", r.sub.sent[0])
	pc, _ := r.led.BuildPoolRegistration(*spec0)
	dc, _ := r.led.BuildCertificate(delegSpec(r, "alice"))
	dc2, _ := r.led.BuildCertificate(delegSpec(r, "bob"))
	want := fmt.Sprintf("%x%x%x", pc.CBOR, dc.CBOR, dc2.CBOR)
	if !strings.Contains(hexTx, want) {
		t.Errorf("the certificates are not attached in order")
	}
	// Four witnesses (cold, payer, both owners): the fee was estimated for 4. The balance carries the deposit.
	var total chain.Lovelace = 1_500_000_000
	if len(res.Outputs) != 1 || res.Outputs[0].Lovelace != total-res.Fee-500_000_000 {
		t.Errorf("change %+v fee %d", res.Outputs, res.Fee)
	}
	// The record: epoch, time, no collection, and the certificate consumed.
	d := r.descriptor()
	if d.Text("regEpoch") != "7" || d.Text("regSubmitted") != "Mon, 16 Nov 2026 12:00:00 +0000" || d.Has("regWitness") {
		t.Errorf("%s", d.Render())
	}
	if r.exists("mypool.pool.cert") {
		t.Error("the certificate is deleted after the submission")
	}
	if r.exists("mypool_mypool.node_1.witness") {
		t.Error("no transfer file when every slot is local")
	}
	if !contains(res.Decisions, "SPO-05c-OUT-006") {
		t.Error("the deletion decision is recorded")
	}
}

func t0(r *prig) *testing.T { return r.t }

func mustSpec(t *testing.T, r *prig) *pool.RegistrationSpec {
	raw := []byte(r.read("mypool.pool.cert"))
	c, err := r.led.DecodePoolCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c.Registration
}

func delegSpec(r *prig, owner string) stake.Spec {
	return stake.Spec{Kind: stake.CertPoolDelegation, Stake: stake.KeyHash(r.hashOf(owner + ".staking.vkey")), Pool: r.poolID}
}

func delegToOther(r *prig) stake.Spec {
	s := delegSpec(r, "bob")
	s.Pool = chain.PoolID{9}
	return s
}

func contains(ss []string, id string) bool {
	for _, s := range ss {
		if strings.Contains(s, id) {
			return true
		}
	}
	return false
}

// spec: SPO-05c-MODE-001, SPO-05c-MODE-002, SPO-05c-INV-009, SPO-05c-INV-002
func TestReRegistrationPaysNoDeposit(t *testing.T) {
	for _, st := range []chain.PoolStatus{chain.PoolRegistered, chain.PoolRetiring} {
		r := ready(t)
		res, err := r.run(r.register(false, func(uc *RegisterPool) {
			uc.Pools = &ppools{c: r.calls, src: "node", r: registered(st)}
			uc.CrossCheck = &ppools{c: r.calls, src: "koios", r: registered(st)}
		}))
		if err != nil {
			t.Fatal(err)
		}
		if res.Type != pool.PoolReRegistration || res.Deposit != 0 || len(res.Sources) != 2 || res.SingleSource {
			t.Errorf("%s: %+v", st, res)
		}
		if res.Outputs[0].Lovelace != 1_500_000_000-res.Fee {
			t.Errorf("a re-registration returns inputs - fee: %d", res.Outputs[0].Lovelace)
		}
	}
	// A pool that was retired registers again with the deposit.
	r := ready(t)
	res, err := r.run(r.register(false, func(uc *RegisterPool) {
		uc.Pools = &ppools{c: r.calls, src: "node", r: registered(chain.PoolRetired)}
		uc.CrossCheck = &ppools{c: r.calls, src: "koios", r: registered(chain.PoolRetired)}
	}))
	if err != nil || res.Type != pool.PoolRegistration || res.Deposit != 500_000_000 {
		t.Errorf("retired: %+v %v", res, err)
	}
}

// spec: SPO-05c-MODE-001, SPO-05c-MODE-002, SPO-05c-MODE-003, SPO-05c-PRE-004, SPO-05c-INV-002, SPO-05c-IN-002, SPO-07b-OUT-004
func TestRegistrationTypeDecisionAtTheUseCase(t *testing.T) {
	two := func(r *prig, a, b chain.Reading[chain.PoolState]) func(*RegisterPool) {
		return func(uc *RegisterPool) {
			uc.Pools = &ppools{c: r.calls, src: "node", r: a}
			uc.CrossCheck = &ppools{c: r.calls, src: "koios", r: b}
		}
	}
	cases := []struct {
		name string
		do   func(r *prig) func(*RegisterPool)
		req  pool.RegistrationType
		want error
	}{
		{"unknown is never not registered", func(r *prig) func(*RegisterPool) {
			return func(uc *RegisterPool) {
				uc.Pools = &ppools{c: r.calls, src: "koios", r: chain.Unknown[chain.PoolState]("HTTP 500")}
			}
		}, "", errUnknown},
		{"one source without acknowledgement", func(r *prig) func(*RegisterPool) {
			return func(uc *RegisterPool) { uc.Pools = &ppools{c: r.calls, src: "koios", r: chain.None[chain.PoolState]()} }
		}, "", ErrSingleSource},
		{"two sources that disagree", func(r *prig) func(*RegisterPool) {
			return two(r, chain.None[chain.PoolState](), registered(chain.PoolRegistered))
		}, "", ErrSourcesDisagree},
		{"retired before, no type", func(r *prig) func(*RegisterPool) {
			r.edit("deregSubmitted", "then")
			return two(r, chain.None[chain.PoolState](), chain.None[chain.PoolState]())
		}, "", pool.ErrChooseType},
		{"a provider that fails", func(r *prig) func(*RegisterPool) {
			return func(uc *RegisterPool) {
				uc.Pools = &ppools{c: r.calls, src: "koios", err: errors.New("connection refused")}
			}
		}, "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ready(t)
			opt := c.do(r)
			before := r.snapshot()
			_, err := r.register(false, opt).Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay", Type: c.req})
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			r.nothingChanged(before, "a refusal")
			if r.calls.count("utxos") != 0 || r.calls.count("confirm") != 0 {
				t.Errorf("the type is decided before the pipeline: %v", r.calls.l)
			}
		})
	}
	t.Run("a forced type does not consult the chain", func(t *testing.T) {
		r := ready(t)
		r.edit("deregSubmitted", "then")
		res, err := r.register(false, func(uc *RegisterPool) {
			uc.Pools = &ppools{c: r.calls, src: "koios", err: errors.New("must not be called")}
		}).Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay", Type: pool.PoolReRegistration})
		if err != nil || res.Type != pool.PoolReRegistration || r.calls.count("pool-state") != 0 {
			t.Errorf("%+v %v %v", res, err, r.calls.l)
		}
	})
	t.Run("unknown goes on from the descriptor when allowed, and says so", func(t *testing.T) {
		r := ready(t)
		r.edit("regSubmitted", "queued before")
		res, err := r.run(r.register(false, func(uc *RegisterPool) {
			uc.Pools = &ppools{c: r.calls, src: "koios", r: chain.Unknown[chain.PoolState]("HTTP 500")}
			uc.AllowUnverified = true
		}))
		if err != nil || res.Type != pool.PoolReRegistration || !hasPrefixAny(res.Unchecked, "the registration type comes from the descriptor") {
			t.Errorf("%+v %v", res, err)
		}
	})
	t.Run("offline: the descriptor decides", func(t *testing.T) {
		for _, queued := range []bool{false, true} {
			r := ready(t)
			if queued {
				r.edit("regSubmitted", "x (only offline, no proof)")
			}
			res, err := r.run(r.register(true))
			want := pool.PoolRegistration
			if queued {
				want = pool.PoolReRegistration
			}
			if err != nil || res.Type != want || r.calls.count("pool-state") != 0 {
				t.Errorf("queued=%v: %+v %v", queued, res, err)
			}
		}
	})
}

func hasPrefixAny(ss []string, prefix string) bool {
	for _, s := range ss {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// spec: SPO-05c-MODE-008, SPO-05c-OUT-005, SPO-05c-OUT-006, SPO-05c-PR-005, SPO-05c-PR-006, SPO-Ptransfer-OUT-010
func TestOfflineRegistrationQueuesTheTransaction(t *testing.T) {
	r := ready(t)
	r.edit("regProtectionKey", "key-in-the-descriptor")
	var attached []string
	res, err := r.run(r.register(true, func(uc *RegisterPool) { uc.Attach = attachRec{&attached} }))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Queued || res.Submitted || len(r.queue.got) != 1 || r.calls.count("submit") != 0 {
		t.Fatalf("%+v", res)
	}
	q := r.queue.got[0]
	if q.Type != "PoolRegistration" || q.FromName != "pay" || q.ToName != "pay" || q.FromAddr != q.ToAddr ||
		q.Description != "signed pool registration transaction for 'MYPL', payment via 'pay'" {
		t.Errorf("%+v", q)
	}
	want := []ports.QueuedField{{Key: "poolMetaTicker", Value: "MYPL"}, {Key: "regProtectionKey", Value: "key-in-the-descriptor"},
		{Key: "poolMetaUrl", Value: "https://example.org/mypool.metadata.json"}, {Key: "poolMetaHash", Value: r.descriptor().Text("poolMetaHash")}}
	if fmt.Sprint(q.Extra) != fmt.Sprint(want) {
		t.Errorf("%v", q.Extra)
	}
	d := r.descriptor()
	if d.Text("regSubmitted") != "Mon, 16 Nov 2026 12:00:00 +0000 (only offline, no proof)" || d.Text("regEpoch") != "7" || r.exists("mypool.pool.cert") {
		t.Errorf("%s", d.Render())
	}
	if len(attached) != 1 || attached[0] != "mypool.metadata.json" {
		t.Errorf("attached %v", attached)
	}
}

type attachRec struct{ got *[]string }

func (a attachRec) Attach(_ context.Context, name string, _ []byte) error {
	*a.got = append(*a.got, name)
	return nil
}

// spec: SPO-05c-PR-001, SPO-05c-OUT-001
func TestDeclinedBodyStoresNothing(t *testing.T) {
	r := ready(t)
	r.conf.answer = []bool{false}
	before := r.snapshot()
	_, err := r.run(r.register(false))
	if !errors.Is(err, txflow.ErrDeclined) {
		t.Fatalf("%v", err)
	}
	r.nothingChanged(before, "a declined confirmation")
	if r.calls.count("submit") != 0 || r.calls.count("enqueue") != 0 {
		t.Error("sent")
	}
}

// spec: SPO-05c-PR-003, SPO-05c-PR-004, SPO-Ptx-PR-004
func TestFinalConfirmationIsNeverSkipped(t *testing.T) {
	r := ready(t)
	r.conf.answer = []bool{false}
	_, err := r.run(r.register(false, func(uc *RegisterPool) { uc.Pipeline.Approval = txflow.ApprovalSkip }))
	// The first confirmation is skipped by the policy, the second is asked and declined.
	if !errors.Is(err, txflow.ErrDeclined) || r.calls.count("confirm body") != 0 || r.calls.count("confirm submit") != 1 || r.calls.count("submit") != 0 {
		t.Fatalf("%v %v", err, r.calls.l)
	}
	// The collection stays, complete; the certificate stays.
	c := r.collection()
	if c == nil || len(c.Missing()) != 0 || !r.exists("mypool.pool.cert") {
		t.Fatal("the collection and the certificate stay")
	}
	// Declining with DiscardOnDecline removes the collection.
	r2 := ready(t)
	r2.conf.answer = []bool{true, false}
	res, err := r2.run(r2.register(false, func(uc *RegisterPool) { uc.DiscardOnDecline = true }))
	if !errors.Is(err, txflow.ErrDeclined) || res.State != pool.CollectionDiscarded || r2.collection() != nil || !r2.exists("mypool.pool.cert") {
		t.Errorf("%v %+v", err, res)
	}
	// Run again: a new collection is made, and approved.
	r2.conf.answer = []bool{true}
	if res, err := r2.run(r2.register(false)); err != nil || !res.Submitted {
		t.Errorf("%v %+v", err, res)
	}
}

// spec: SPO-05c-INV-005, SPO-05c-OUT-003, SPO-05c-PRE-010, SPO-05c-OUT-002, SPO-Pfiles-OUT-023, SPO-Xparty-INV-013, SPO-Xparty-PRE-003
func TestAnOwnerWhoSignsElsewhereLeavesAnOpenSlot(t *testing.T) {
	// Without AllowPending a holder with no signer is refused up front.
	r := ready(t)
	r.setOwnerWitness("external")
	before := r.snapshot()
	_, err := r.run(r.register(false))
	var ue *custody.UnsupportedError
	if !errors.As(err, &ue) || len(ue.Problems) != 1 || !strings.Contains(ue.Problems[0].Slot.Label, "bob") {
		t.Fatalf("%v", err)
	}
	r.nothingChanged(before, "the refusal")
	if r.calls.count("utxos") != 0 || r.calls.count("fee") != 0 {
		t.Errorf("the plan refuses before any read: %v", r.calls.l)
	}

	// With AllowPending the collection opens incomplete and nothing is sent.
	res, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != pool.CollectionOpenIncomplete || res.Submitted || len(res.Missing) != 1 || res.Missing[0] != "bob.staking" ||
		len(res.TransferFiles) != 1 || res.TransferFiles[0] != fmt.Sprintf("mypool_bob_%d", res.CollectionID) {
		t.Fatalf("%+v", res)
	}
	if r.calls.count("submit") != 0 || r.calls.count("confirm submit") != 0 || !r.exists("mypool.pool.cert") {
		t.Errorf("%v", r.calls.l)
	}
	c := r.collection()
	if c == nil || c.State(1000) != pool.CollectionOpenIncomplete || c.ID != uint64(r.clock.t.Unix()) || c.Type != pool.PoolRegistration || c.TTL != 1000+100000 || c.PayName != "pay" {
		t.Fatalf("%+v", c)
	}
	// Slots: cold, payer, owners, in that order; the local ones filled, the remote one empty and assigned.
	var names []string
	for _, s := range c.Slots {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "mypool.node,pay,alice.staking,bob.staking" {
		t.Errorf("%v", names)
	}
	roles := []custody.Role{custody.RolePoolCold, custody.RolePayment, custody.RoleStake, custody.RoleStake}
	for i, s := range c.Slots {
		if s.Role != roles[i] || (s.Name == "bob.staking") == s.Filled() {
			t.Errorf("slot %+v", s)
		}
	}
	if bob := c.Slots[3]; bob.Holder != custody.HolderRemote || bob.Party != "external" || bob.KeyHash != r.hashOf("bob.staking.vkey") {
		t.Errorf("%+v", bob)
	}
	// The transfer file is the upstream request: the whole body, the slot's verification key, no witness yet.
	tf := r.transferFile(res.TransferFiles[0])
	if tf.SigningName != "bob.staking" || tf.ID != c.ID || tf.TTL != c.TTL || tf.Type != pool.PoolRegistration || tf.PoolFile != "mypool" || tf.PoolMetaTicker != "MYPL" ||
		tf.Signed() || tf.DateCreated != "Mon, 16 Nov 2026 12:00:00 +0000" || tf.Matches(*c) != nil || !bytes.Contains(tf.SigningVKey, []byte("StakeVerificationKeyShelley_ed25519")) {
		t.Errorf("%+v", tf)
	}
	// Running again resumes: no new collection, no second file, still incomplete.
	prev := r.snapshot()
	again, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
	if err != nil || again.State != pool.CollectionOpenIncomplete || again.CollectionID != res.CollectionID || len(again.TransferFiles) != 0 {
		t.Errorf("%+v %v", again, err)
	}
	if strings.Count(r.snapshot(), "witness=") != strings.Count(prev, "witness=") {
		t.Error("a resumed run wrote another transfer file")
	}
}

// spec: SPO-05d-INV-006, SPO-05d-SEC-003, SPO-05d-OUT-003, SPO-05d-INV-004, SPO-Xparty-PRE-005, SPO-Xparty-IF-007, SPO-05c-INV-003, SPO-05c-EXT-007
func TestImportedWitnessCompletesTheCollectionAndAssemblesTheSameTransaction(t *testing.T) {
	// The reference: every owner signs locally.
	ref := ready(t)
	refRes, err := ref.run(ref.register(false))
	if err != nil {
		t.Fatal(err)
	}

	r := ready(t)
	r.setOwnerWitness("external")
	pending, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
	if err != nil {
		t.Fatal(err)
	}
	file := pending.TransferFiles[0]
	tf := r.signWitness(r.transferFile(file), "bob", "StakeVerificationKeyShelley_ed25519")
	imp, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()})
	if err != nil {
		t.Fatal(err)
	}
	if imp.State != pool.CollectionOpenComplete || len(imp.Missing) != 0 || imp.Slot != "bob.staking" || !imp.Unauthenticated {
		t.Errorf("%+v", imp)
	}
	if r.exists(file + ".witness") {
		t.Error("the transfer file goes once its witness is stored")
	}
	if c := r.collection(); c == nil || !c.Slots[3].Filled() || !c.Slots[3].Unauthenticated || c.Version != 5 {
		t.Errorf("%+v", c)
	}
	// Re-running assembles and submits the stored body with the stored witnesses.
	res, err := r.run(r.register(false))
	if err != nil || !res.Submitted || res.State != pool.CollectionSubmitted {
		t.Fatalf("%+v %v", res, err)
	}
	if !bytes.Equal(r.sub.sent[0], ref.sub.sent[0]) {
		t.Errorf("the assembled transaction differs from the all-local one\n  imported:  %x\n  all local: %x", r.sub.sent[0], ref.sub.sent[0])
	}
	if res.TxID != refRes.TxID {
		t.Error("tx id")
	}
	// A resumed run does not rebuild: the UTxOs were read once, in the first run.
	if r.calls.count("utxos") != 1 {
		t.Errorf("%d UTxO reads: the body is built once", r.calls.count("utxos"))
	}
	if r.exists("mypool.pool.cert") || r.descriptor().Has("regWitness") || !r.descriptor().Has("regSubmitted") {
		t.Error("submission record")
	}
}

// spec: SPO-05d-INV-006, SPO-05d-SEC-003, SPO-05d-PRE-007, SPO-05d-PRE-008, SPO-05d-PRE-009, SPO-05d-PRE-010, SPO-05d-PRE-011, SPO-05d-PR-002,
// spec: SPO-Xparty-PRE-005, SPO-Xparty-INV-015
func TestImportRefusals(t *testing.T) {
	setup := func(t *testing.T) (*prig, pool.TransferFile) {
		r := ready(t)
		r.setOwnerWitness("external")
		res, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
		if err != nil {
			t.Fatal(err)
		}
		return r, r.transferFile(res.TransferFiles[0])
	}
	cases := []struct {
		name string
		do   func(r *prig, tf pool.TransferFile) pool.TransferFile
		want error
	}{
		{"a witness of the wrong key (here the payer's)", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			return r.signWitness(tf, "pay", "PaymentVerificationKeyShelley_ed25519")
		}, txbuild.ErrWitnessKey},
		{"a witness of the reward account's key", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			return r.signWitness(tf, "alice", "StakeVerificationKeyShelley_ed25519")
		}, txbuild.ErrWitnessKey},
		{"a corrupt signature", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
			w, _ := pool.ParseWitnessEnvelope(tf.SignedWitness)
			w.Signature[0] ^= 1
			tf.SignedWitness = pool.WitnessEnvelope(w)
			return tf
		}, txbuild.ErrWitnessSignature},
		{"not signed yet", func(r *prig, tf pool.TransferFile) pool.TransferFile { return tf }, ErrNotSigned},
		{"another collection's id", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
			tf.ID++
			return tf
		}, pool.ErrCollectionMismatch},
		{"another ticker", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
			tf.PoolMetaTicker = "OTHR"
			return tf
		}, pool.ErrCollectionMismatch},
		{"a slot the collection does not have", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
			tf.SigningName = "carol.staking"
			return tf
		}, pool.ErrUnknownSlot},
		{"a signature over another body", func(r *prig, tf pool.TransferFile) pool.TransferFile {
			// The right key, a signature that is not over this body.
			tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
			w, _ := pool.ParseWitnessEnvelope(tf.SignedWitness)
			w.Signature = [64]byte{}
			tf.SignedWitness = pool.WitnessEnvelope(w)
			return tf
		}, txbuild.ErrWitnessSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, tf := setup(t)
			tf = c.do(r, tf)
			before := r.snapshot()
			_, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()})
			if !isErr(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			r.nothingChanged(before, "a refused import")
		})
	}
	t.Run("an expired collection accepts no witness", func(t *testing.T) {
		r, tf := setup(t)
		tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
		r.chain.tip.Slot = 1000 + 100000 + 1
		before := r.snapshot()
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); !errors.Is(err, pool.ErrCollectionNotOpen) {
			t.Errorf("%v", err)
		}
		r.nothingChanged(before, "a refused import")
		// Upstream quirk decision (SPO-05d-INV-003): upstream treats the
		// window as open while ttl >= tip. The body's TTL is the ledger's
		// invalid-hereafter bound, which is exclusive: once the tip has
		// reached it, no later block can include the transaction. Fixed: the
		// collection is expired at the TTL slot itself.
		r.chain.tip.Slot = 1000 + 100000
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); !errors.Is(err, pool.ErrCollectionNotOpen) {
			t.Errorf("at the TTL: %v", err)
		}
		// One slot earlier it is still open.
		r.chain.tip.Slot = 1000 + 100000 - 1
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); err != nil {
			t.Errorf("one slot before the TTL: %v", err)
		}
	})
	t.Run("no collection", func(t *testing.T) {
		r := ready(t)
		tf := pool.TransferFile{ID: 1, TTL: 2, Type: pool.PoolRegistration, SigningName: "bob.staking", SigningVKey: []byte(`{}`), TxBody: []byte(`{}`), SignedWitness: []byte(`{"x":1}`)}
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); !errors.Is(err, ErrNoCollection) {
			t.Errorf("%v", err)
		}
	})
	t.Run("a file that is not JSON", func(t *testing.T) {
		r := ready(t)
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: []byte("nope")}); err == nil {
			t.Error("accepted")
		}
	})
	t.Run("a filled slot needs a confirmed overwrite", func(t *testing.T) {
		r, tf := setup(t)
		tf = r.signWitness(tf, "bob", "StakeVerificationKeyShelley_ed25519")
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); err != nil {
			t.Fatal(err)
		}
		before := r.snapshot()
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); !errors.Is(err, pool.ErrSlotFilled) {
			t.Errorf("%v", err)
		}
		r.nothingChanged(before, "a refused import")
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render(), Overwrite: true}); err != nil {
			t.Errorf("overwrite: %v", err)
		}
	})
}

// spec: SPO-05c-PRE-003, SPO-05c-INV-003, SPO-05c-INV-008, SPO-05c-INV-001
func TestResumedCollection(t *testing.T) {
	setup := func(t *testing.T) *prig {
		r := ready(t)
		r.setOwnerWitness("external")
		if _, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true })); err != nil {
			t.Fatal(err)
		}
		return r
	}
	t.Run("a type or a message is refused while a collection is open", func(t *testing.T) {
		r := setup(t)
		before := r.snapshot()
		for _, req := range []RegisterRequest{{Pool: "mypool", Payer: "pay", Type: pool.PoolRegistration}, {Pool: "mypool", Payer: "pay", Message: []string{"hi"}}} {
			if _, err := r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }).Run(ctx, req); !errors.Is(err, ErrCollectionOpen) {
				t.Errorf("%v", err)
			}
		}
		r.nothingChanged(before, "a refusal")
	})
	t.Run("an expired collection is refused and stays until discarded", func(t *testing.T) {
		r := setup(t)
		r.chain.tip.Slot = 1000 + 100000 + 1
		before := r.snapshot()
		if _, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true })); !errors.Is(err, ErrCollectionExpired) {
			t.Errorf("%v", err)
		}
		r.nothingChanged(before, "a refusal")
	})
	t.Run("a different payer is refused", func(t *testing.T) {
		r := setup(t)
		r.putKey("pay2.vkey", "pay2.skey", "PaymentVerificationKeyShelley_ed25519", "PaymentSigningKeyShelley_ed25519", "")
		addr, _ := r.led.BuildAddress(0, r.hashOf("pay2.vkey"), nil)
		r.write("pay2.addr", []byte(addr+"\n"))
		before := r.snapshot()
		if _, err := r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }).Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay2"}); !errors.Is(err, ErrPayerDiffers) {
			t.Errorf("%v", err)
		}
		r.nothingChanged(before, "a refusal")
	})
	t.Run("the stored transaction is used, whatever the descriptor says now", func(t *testing.T) {
		r := setup(t)
		c := r.collection()
		r.edit("poolPledge", "1")
		r.mustGenerate() // regenerating the certificate does not change the stored body
		if c2 := r.collection(); c2 == nil || c2.Body.ID != c.Body.ID {
			t.Fatal("the collection changed")
		}
		tf := r.signWitness(r.transferFile(fmt.Sprintf("mypool_bob_%d", c.ID)), "bob", "StakeVerificationKeyShelley_ed25519")
		if _, err := r.importer().Run(ctx, ImportRequest{Pool: "mypool", File: tf.Render()}); err != nil {
			t.Fatal(err)
		}
		res, err := r.run(r.register(false))
		if err != nil || res.TxID != chain.TxID(c.Body.ID) {
			t.Errorf("%v %+v", err, res)
		}
	})
}

// spec: SPO-05c-PRE-002, SPO-05c-PRE-001, SPO-05c-PRE-005, SPO-05c-PRE-006, SPO-05c-IN-001, SPO-05c-INV-006, SPO-05c-IN-004, SPO-05c-PRE-007, SPO-05c-PRE-008, SPO-05c-MODE-005
func TestRegistrationRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name string
		do   func(r *prig)
		want error
	}{
		{"no descriptor", func(r *prig) { r.remove("mypool.pool.json") }, ErrNoDescriptor},
		{"the certificate was not generated, or is used up", func(r *prig) { r.remove("mypool.pool.cert") }, ErrMissingFile},
		{"a required field is missing", func(r *prig) { r.edit("poolMetaHash", nil) }, pool.ErrMissingField},
		{"no cold verification key", func(r *prig) { r.remove("mypool.node.vkey") }, ErrMissingFile},
		{"neither a cold signing key nor a hardware file", func(r *prig) { r.remove("mypool.node.skey") }, ErrNoColdSigner},
		{"no payment address", func(r *prig) { r.remove("pay.addr") }, ErrMissingFile},
		{"no payment signing key", func(r *prig) { r.remove("pay.skey") }, ErrNoSigningKey},
		{"an owner's delegation certificate is missing", func(r *prig) { r.remove("bob.deleg.cert") }, ErrMissingFile},
		{"an owner's delegation certificate targets another pool", func(r *prig) {
			c, _ := r.led.BuildCertificate(delegToOther(r))
			r.write("bob.deleg.cert", c.Envelope)
		}, ErrDelegationOtherPool},
		{"an owner has no signing key and signs locally", func(r *prig) { r.remove("bob.staking.skey") }, ErrNoSigningKey},
		{"a hardware owner has no signer here", func(r *prig) { r.remove("bob.staking.skey"); r.write("bob.staking.hwsfile", []byte("hw")) }, nil},
		{"the certificate is for another pool", func(r *prig) {
			spec := *mustSpec(t0(r), r)
			spec.Operator = chain.PoolID{7}
			c, _ := r.led.BuildPoolRegistration(spec)
			r.write("mypool.pool.cert", c.Envelope)
		}, ErrCertificateMismatch},
		{"the pool has no deposit parameter", func(r *prig) { r.chain.params.StakePoolDeposit = 0 }, ErrNoPoolDeposit},
		{"the protocol is too old", func(r *prig) { r.chain.params.ProtocolMajor = 8 }, ErrProtocolTooOld},
		{"no funds", func(r *prig) { r.chain.utxos = nil }, txbuild.ErrNoFunds},
		{"not enough for the deposit", func(r *prig) { r.chain.utxos = r.chain.utxos[:1]; r.chain.utxos[0].Lovelace = 400_000_000 }, txbuild.ErrInsufficient},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ready(t)
			c.do(r)
			before := r.snapshot()
			_, err := r.run(r.register(false))
			if err == nil || (c.want != nil && !errors.Is(err, c.want) && !strings.Contains(fmt.Sprint(err), "cannot")) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			r.nothingChanged(before, "a refusal")
			if r.calls.count("submit") != 0 || r.calls.count("enqueue") != 0 {
				t.Error("sent")
			}
		})
	}
}

// spec: SPO-05c-INV-006
func TestHardwareWalletInvolvedAttachesOnlyTheRegistrationCertificate(t *testing.T) {
	// An owner key whose description says Hardware: the delegation certificates are left out.
	r := ready(t)
	r.putKey("bob.staking.vkey", "bob.staking.skey", "StakeVerificationKeyShelley_ed25519", "StakeSigningKeyShelley_ed25519", "Hardware Stake Verification Key")
	res, err := r.run(r.register(true))
	// The vault signs here (a test fixture), so only the attachments are checked.
	if err != nil {
		t.Fatal(err)
	}
	if len(r.conf.got[0].Attachments) != 1 || !strings.Contains(r.conf.got[0].Attachments[0], "pool registration") {
		t.Errorf("%v", r.conf.got[0].Attachments)
	}
	if c := res; !c.Queued {
		t.Error("queued")
	}
}

// spec: SPO-05c-EXT-001, SPO-05c-SEC-002, SPO-05c-MODE-004, SPO-Ptransfer-PRE-006
func TestTickerProtectionIsOptInAndSendsOnlyTheTicker(t *testing.T) {
	// Off by default: nothing is asked, and the result says the lookup is off.
	r := ready(t)
	r.edit("regProtectionKey", "private-key")
	res, err := r.run(r.register(false))
	if err != nil || !hasPrefixAny(res.Unchecked, "the ticker-protection lookup is off") {
		t.Errorf("%+v %v", res, err)
	}
	// On: the checker is handed the ticker, and nothing else exists to hand it.
	for name, c := range map[string]struct {
		v    ports.TickerVerdict
		err  error
		want error
	}{
		"allowed":     {v: ports.TickerAllowed},
		"protected":   {v: ports.TickerProtected, want: ErrTickerProtected},
		"unreachable": {err: errors.New("offline")},
		"no answer":   {v: ports.TickerUnchecked},
	} {
		t.Run(name, func(t *testing.T) {
			r := ready(t)
			ck := &tickerRec{v: c.v, err: c.err}
			before := r.snapshot()
			res, err := r.run(r.register(false, func(uc *RegisterPool) { uc.Tickers = ck }))
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("%v", err)
				}
				r.nothingChanged(before, "a refusal")
			} else if err != nil {
				t.Fatalf("%v", err)
			}
			if len(ck.got) != 1 || ck.got[0] != "MYPL" {
				t.Errorf("asked %v", ck.got)
			}
			if c.err != nil || c.v == ports.TickerUnchecked {
				if !hasPrefixAny(res.Unchecked, "the ticker was not checked") {
					t.Errorf("a failed lookup lets the run go on and says so: %v", res.Unchecked)
				}
			}
		})
	}
}

type tickerRec struct {
	got []string
	v   ports.TickerVerdict
	err error
}

func (t *tickerRec) CheckTicker(_ context.Context, ticker string) (ports.TickerVerdict, error) {
	t.got = append(t.got, ticker)
	return t.v, t.err
}

type fetchFake struct {
	doc []byte
	err error
	url string
}

func (f *fetchFake) Fetch(_ context.Context, url string) ([]byte, error) {
	f.url = url
	return f.doc, f.err
}

// spec: SPO-05c-EXT-002, SPO-05c-SEC-005
func TestPublishedMetadataMustMatchTheHash(t *testing.T) {
	r := ready(t)
	good := []byte(r.read("mypool.metadata.json"))
	cases := map[string]struct {
		f    *fetchFake
		want error
	}{
		"the published file is the one hashed": {f: &fetchFake{doc: good}},
		"another file":                         {f: &fetchFake{doc: bytes.Replace(good, []byte("A pool"), []byte("a pool"), 1)}, want: ErrMetadataMismatch},
		"not JSON":                             {f: &fetchFake{doc: []byte("<html>404</html>")}, want: errAny},
		"over the size limit":                  {f: &fetchFake{doc: bytes.Repeat([]byte(" "), 513)}, want: ErrMetadataMismatch},
		"unreachable":                          {f: &fetchFake{err: errors.New("no route")}, want: errAny},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := ready(t)
			before := r.snapshot()
			_, err := r.run(r.register(false, func(uc *RegisterPool) { uc.Metadata = c.f }))
			switch {
			case c.want == nil && err != nil:
				t.Fatalf("%v", err)
			case c.want == errAny && err == nil, c.want != nil && c.want != errAny && !errors.Is(err, c.want):
				t.Fatalf("%v", err)
			}
			if c.f.url != "https://example.org/mypool.metadata.json" {
				t.Errorf("fetched %q", c.f.url)
			}
			if c.want != nil {
				r.nothingChanged(before, "a refusal")
			}
		})
	}
}

var errAny = errors.New("any error")

// spec: SPO-05c-IF-003, SPO-05c-IF-004
func TestBadMessageRefusesBeforeAnythingIsRead(t *testing.T) {
	r := ready(t)
	r.calls.l = nil
	before := r.snapshot()
	_, err := r.register(false).Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay", Message: []string{strings.Repeat("x", 65)}})
	if !errors.Is(err, txbuild.ErrBadMessage) {
		t.Fatalf("%v", err)
	}
	r.nothingChanged(before, "a refusal")
	if len(r.calls.l) != 0 {
		t.Errorf("the chain was read: %v", r.calls.l)
	}
	// A message is carried by the transaction and recorded in its metadata.
	res, err := r.register(false).Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay", Message: []string{"registering"}})
	if err != nil || !res.Submitted || len(r.conf.got[0].Message) != 1 {
		t.Errorf("%+v %v", res, err)
	}
}

// spec: SPO-05c-PRE-011, SPO-05c-INV-020, SPO-05c-OUT-001, SPO-Ptx-PRE-007
func TestATransactionOverTheSizeLimitIsRefusedBeforeAnythingIsStored(t *testing.T) {
	r := ready(t)
	r.chain.params.MaxTxSize = 600
	before := r.snapshot()
	_, err := r.run(r.register(false))
	if err == nil || !strings.Contains(err.Error(), "above the maximum") {
		t.Fatalf("%v", err)
	}
	r.nothingChanged(before, "a refusal")
	if r.calls.count("confirm") != 0 || r.calls.count("submit") != 0 {
		t.Errorf("%v", r.calls.l)
	}
}

// Every slot goes through the same flow, the payer and the cold key too: a
// payer whose key is on a device is a pending slot with its own transfer file.
//
// spec: SPO-05c-INV-010, SPO-05c-OUT-003, SPO-Xparty-INV-013, SPO-05c-EXT-005, SPO-05c-EXT-008
func TestPayerAndColdKeySlotsCanBePendingToo(t *testing.T) {
	r := ready(t)
	r.remove("pay.skey")
	r.write("pay.hwsfile", []byte("hw"))
	res, err := r.run(r.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != pool.CollectionOpenIncomplete || len(res.Missing) != 1 || res.Missing[0] != "pay" || len(res.TransferFiles) != 1 {
		t.Fatalf("%+v", res)
	}
	c := r.collection()
	if c.Slots[1].Holder != custody.HolderHardware || c.Slots[1].Role != custody.RolePayment || c.Slots[0].Filled() == false {
		t.Errorf("%+v", c.Slots)
	}
	if tf := r.transferFile(res.TransferFiles[0]); tf.SigningName != "pay" || !strings.Contains(string(tf.SigningVKey), "PaymentVerificationKeyShelley_ed25519") {
		t.Errorf("%+v", tf)
	}
	// The cold key too: only a hardware or remote holder is pending, and a missing key is refused.
	r2 := ready(t)
	r2.remove("mypool.node.skey")
	r2.write("mypool.node.hwsfile", []byte("hw"))
	res, err = r2.run(r2.register(false, func(uc *RegisterPool) { uc.AllowPending = true }))
	if err != nil || len(res.Missing) != 1 || res.Missing[0] != "mypool.node" || !strings.Contains(string(r2.transferFile(res.TransferFiles[0]).SigningVKey), "StakePoolVerificationKey") {
		t.Errorf("%+v %v", res, err)
	}
	if !contains(r2.conf.got[0].Attachments, "pool registration") || r2.conf.got[0].Pool != r2.poolID.Bech32() {
		t.Error("the summary names the pool")
	}
}

// spec: SPO-05c-INV-011, SPO-05c-INV-012, SPO-05c-INV-013, SPO-05c-INV-014, SPO-05c-INV-015, SPO-05c-INV-016, SPO-05c-INV-018, SPO-05c-INV-019,
// spec: SPO-05c-INV-021, SPO-05c-INV-022, SPO-05c-MODE-007, SPO-05c-MODE-009, SPO-05c-IN-002, SPO-05c-IN-005, SPO-05c-SEC-003, SPO-05c-INV-008
func TestStageMapOfTheRegistration(t *testing.T) {
	// Stage 2: the validity end is tip + defTTL; stage 3 and 4: every UTxO of the
	// payer is spent and its assets go back in the change; stage 7: the change
	// is inputs - fee - deposit.
	r := ready(t)
	r.chain.utxos[1].Assets = []chain.AssetAmount{{Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("t")}, Quantity: 4}}
	res, err := r.run(r.register(false, func(uc *RegisterPool) { uc.DefTTL = 5000 }))
	if err != nil {
		t.Fatal(err)
	}
	if res.TTL != 6000 || res.Inputs != 2 || len(res.Outputs) != 1 || len(res.Outputs[0].Assets) != 1 || res.Outputs[0].Lovelace != 1_500_000_000-500_000_000-res.Fee {
		t.Errorf("%+v", res)
	}
	// The collection stores the unsigned transaction and its witnesses in the descriptor (SPO-05c-SEC-003):
	// whoever holds the descriptor can assemble before the TTL ends, so it is never printed or logged.
	r2 := ready(t)
	r2.setOwnerWitness("external")
	if _, err := r2.run(r2.register(false, func(uc *RegisterPool) { uc.AllowPending = true })); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r2.read("mypool.pool.json"), `"regWitness"`) {
		t.Error("the collection is stored")
	}
	// A light submitter and an online one are the same route here: a failed submission is an error, the
	// certificate and the collection stay (SPO-05c-MODE-006, SPO-05c-MODE-007).
	r3 := ready(t)
	r3.sub.err = errors.New("node rejected the transaction")
	_, err = r3.run(r3.register(false))
	if err == nil || !strings.Contains(err.Error(), "rejected") || !r3.exists("mypool.pool.cert") || r3.collection() == nil || r3.descriptor().Has("regSubmitted") {
		t.Errorf("%v", err)
	}
}

// The second source's refusal to answer names both sources and the answer of
// the first; the single source is accepted only when acknowledged.
//
// spec: SPO-05c-MODE-001, SPO-05c-MODE-002
func TestRegistrationTypeSecondSourceDownOrDisagreeing(t *testing.T) {
	r := ready(t)
	_, err := r.run(r.register(false, func(uc *RegisterPool) {
		uc.Pools = &ppools{c: r.calls, src: "koios", r: registered(chain.PoolRegistered)}
		uc.CrossCheck = &ppools{c: r.calls, src: "blockfrost", r: chain.Unknown[chain.PoolState]("HTTP 503")}
	}))
	if !errors.Is(err, ErrSingleSource) || !strings.Contains(err.Error(), "koios says registered, but blockfrost did not answer: HTTP 503") {
		t.Fatalf("%v", err)
	}
	r = ready(t)
	_, err = r.run(r.register(false, func(uc *RegisterPool) {
		uc.Pools = &ppools{c: r.calls, src: "koios", r: registered(chain.PoolRegistered)}
		uc.CrossCheck = &ppools{c: r.calls, src: "blockfrost", r: chain.None[chain.PoolState]()}
	}))
	if !errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), "koios says registered, blockfrost says not registered") {
		t.Fatalf("%v", err)
	}
}

// A retiring pool that both sources state as retiring is agreement; the
// status the web provider does not state is not a disagreement; a real
// difference names the field.
//
// spec: SPO-05c-MODE-001 (ADR 0006, F1)
func TestRegistrationTypeRetiringPoolAcrossSources(t *testing.T) {
	ret := chain.Value(chain.PoolState{Status: chain.PoolRetiring, RetiringEpoch: 9})
	for _, c := range []struct {
		name  string
		other chain.Reading[chain.PoolState]
		diff  string
	}{
		{"both retiring", ret, ""},
		{"unstated", chain.Value(chain.PoolState{Status: chain.PoolStatusUnstated}), ""},
		{"status differs", registered(chain.PoolRegistered), "differ on the pool's status"},
	} {
		r := ready(t)
		_, err := r.run(r.register(true, func(uc *RegisterPool) {
			uc.Pools = &ppools{c: r.calls, src: "node", r: ret}
			uc.CrossCheck = &ppools{c: r.calls, src: "koios", r: c.other}
		}))
		if c.diff == "" && errors.Is(err, ErrSourcesDisagree) {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.diff != "" && (!errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), c.diff)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
