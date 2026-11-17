package poolops

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r *prig) retirement() GenerateRetirementCertificate {
	return GenerateRetirementCertificate{Store: r.store, Params: r.chain, Tip: r.chain, Certs: r.led, Clock: r.clock}
}

func epoch(n uint64) *uint64 { return &n }

// spec: SPO-07a-IF-001, SPO-07a-IF-002, SPO-07a-IN-001, SPO-07a-IN-002, SPO-07a-IN-003, SPO-07a-IN-004, SPO-07a-INV-001, SPO-07a-INV-002,
// spec: SPO-07a-INV-003, SPO-07a-EXT-001, SPO-07a-OUT-001, SPO-07a-OUT-002, SPO-07a-MODE-001, SPO-07a-SEC-001, SPO-Pfiles-OUT-020
func TestRetirementCertificateClampsTheEpoch(t *testing.T) {
	// The current epoch is 7 and eMax 18: the window is 8 to 25.
	cases := []struct {
		name string
		in   *uint64
		want uint64
		warn bool
	}{
		{"no epoch is the earliest", nil, 8, false},
		{"inside the window", epoch(12), 12, false},
		{"the first epoch of the window", epoch(8), 8, false},
		{"the last epoch of the window", epoch(25), 25, false},
		{"this epoch is too early", epoch(7), 8, true},
		{"zero is too early", epoch(0), 8, true},
		{"beyond eMax", epoch(26), 25, true},
		{"a huge epoch", epoch(1 << 62), 25, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPoolRig(t)
			got, err := r.retirement().Run(ctx, RetirementRequest{Pool: "mypool", Epoch: c.in})
			if err != nil {
				t.Fatal(err)
			}
			if got.Epoch != c.want || (len(got.Warnings) > 0) != c.warn || got.Earliest != 8 || got.Latest != 25 {
				t.Errorf("%+v", got)
			}
			want, _ := r.led.BuildPoolRetirement(pool.RetirementSpec{Pool: r.poolID, Epoch: c.want})
			if r.read("mypool.pool.dereg-cert") != string(want.Envelope) {
				t.Error("certificate")
			}
			d := r.descriptor()
			if d.Text("deregEpoch") != fmt.Sprint(c.want) || d.Text("deregCertFile") != "mypool.pool.dereg-cert" || d.Text("deregCertCreated") != "Mon, 16 Nov 2026 12:00:00 +0000" {
				t.Errorf("%s", d.Render())
			}
		})
	}
}

// spec: SPO-07a-IF-003, SPO-07a-IN-001, SPO-07a-IN-002, SPO-07a-IN-003, SPO-07a-OUT-002, SPO-07a-INV-003
func TestRetirementCertificateRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name string
		do   func(r *prig)
		want error
	}{
		{"no descriptor", func(r *prig) { r.remove("mypool.pool.json") }, ErrNoDescriptor},
		{"no poolName", func(r *prig) { r.edit("poolName", nil) }, pool.ErrMissingField},
		{"another pool's descriptor", func(r *prig) { r.edit("poolName", "other") }, pool.ErrNameMismatch},
		{"no cold verification key", func(r *prig) { r.remove("mypool.node.vkey") }, ErrMissingFile},
		{"no eMax", func(r *prig) { r.chain.params.PoolRetireMaxEpoch = 0 }, ErrParameterMissing},
		{"a bad pool word", nil, ErrBadPoolName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPoolRig(t)
			name := "mypool"
			if c.do != nil {
				c.do(r)
			} else {
				name = "a/b"
			}
			before := r.snapshot()
			if _, err := r.retirement().Run(ctx, RetirementRequest{Pool: name}); !isErr(err, c.want) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			r.nothingChanged(before, "a refusal")
		})
	}
	// Nothing is checked against the chain's view of the pool (SPO-07a-INV-003): an unregistered pool gets a certificate.
	r := newPoolRig(t)
	if _, err := r.retirement().Run(ctx, RetirementRequest{Pool: "mypool"}); err != nil {
		t.Error(err)
	}
	// The eMax is read from the raw parameters document when the typed field is zero.
	r = newPoolRig(t)
	r.chain.params.PoolRetireMaxEpoch = 0
	r.chain.params.Raw = []byte(`{"poolRetireMaxEpoch": 18}`)
	if got, err := r.retirement().Run(ctx, RetirementRequest{Pool: "mypool", Epoch: epoch(1000)}); err != nil || got.Epoch != 25 {
		t.Errorf("%+v %v", got, err)
	}
	// A previous deregSubmitted stays when the certificate is made again.
	r.edit("deregSubmitted", "before")
	if _, err := r.retirement().Run(ctx, RetirementRequest{Pool: "mypool"}); err != nil || r.descriptor().Text("deregSubmitted") != "before" {
		t.Errorf("%v", err)
	}
}

func (r *prig) retireReady(t *testing.T, e uint64) {
	t.Helper()
	if _, err := r.retirement().Run(ctx, RetirementRequest{Pool: "mypool", Epoch: epoch(e)}); err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-07b-IF-001, SPO-07b-IF-002, SPO-07b-IN-001, SPO-07b-IN-002, SPO-07b-IN-003, SPO-07b-INV-001, SPO-07b-INV-002, SPO-07b-MODE-001,
// spec: SPO-07b-OUT-001, SPO-07b-OUT-003, SPO-07b-PR-001, SPO-07b-INV-004, SPO-07b-MODE-004, SPO-Ptx-PR-004, SPO-Xconfirm-PR-002
func TestRetirementSubmitsOnlineWithTwoWitnesses(t *testing.T) {
	r := newPoolRig(t)
	r.retireReady(t, 12)
	res, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || res.Epoch != 12 || len(r.sub.sent) != 1 {
		t.Fatalf("%+v", res)
	}
	// Two witnesses, no deposit and no refund: the change is the inputs less the fee.
	if r.calls.count("fee witnesses=2") == 0 || r.calls.count("fee witnesses=4") != 0 {
		t.Errorf("%v", r.calls.l)
	}
	if res.Outputs[0].Lovelace != 1_500_000_000-res.Fee {
		t.Errorf("change %d, fee %d", res.Outputs[0].Lovelace, res.Fee)
	}
	cert, _ := r.led.BuildPoolRetirement(pool.RetirementSpec{Pool: r.poolID, Epoch: 12})
	if !strings.Contains(fmt.Sprintf("%x", r.sub.sent[0]), fmt.Sprintf("%x", cert.CBOR)) {
		t.Error("the certificate is in the transaction")
	}
	if got := r.conf.got[0]; got.Kind != "pool retirement" || got.Pool != r.poolID.Bech32() || len(got.Attachments) != 1 || !strings.Contains(got.Attachments[0], "epoch 12") {
		t.Errorf("%+v", got)
	}
	// Nothing is recorded on the accepted submit; confirmation records it once
	// (SPO-Xconfirm-PR-002).
	d := r.descriptor()
	if d.Has("deregSubmitted") || !res.RecordPending {
		t.Errorf("%s", d.Render())
	}
	if p, ok := r.pending(res.TxID); !ok || p.Kind != assets.PendingPoolRetirement || p.Pool != "mypool" || p.Queued || p.ValidUntil == nil {
		t.Errorf("the pending update: %v %+v", ok, p)
	}
	if !r.confirm(res.TxID) || r.confirm(res.TxID) {
		t.Error("the pending retirement is applied once")
	}
	if d = r.descriptor(); d.Text("deregSubmitted") != "Mon, 16 Nov 2026 12:00:00 +0000" {
		t.Errorf("%s", d.Render())
	}
	// The certificate is used up, where upstream leaves it to be submitted again.
	if r.exists("mypool.pool.dereg-cert") {
		t.Error("the retirement certificate stays")
	}
	if _, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"}); !errors.Is(err, ErrMissingFile) {
		t.Errorf("a second retirement with the same certificate: %v", err)
	}
	if !contains(res.Decisions, "SPO-07b-OUT-003") {
		t.Error("decision recorded")
	}
}

// spec: SPO-07b-MODE-003, SPO-07b-OUT-002, SPO-Ptransfer-OUT-010
func TestRetirementQueuesOffline(t *testing.T) {
	r := newPoolRig(t)
	r.retireReady(t, 9)
	res, err := r.retire(true).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"})
	if err != nil || !res.Queued {
		t.Fatalf("%+v %v", res, err)
	}
	q := r.queue.got[0]
	if q.Type != "PoolRetirement" || q.FromName != "pay" || q.Description != "signed pool retirement transaction for 'MYPL', payment via 'pay'" ||
		q.Extra[0] != (ports.QueuedField{Key: "poolMetaTicker", Value: "MYPL"}) {
		t.Errorf("%+v", q)
	}
	if r.descriptor().Has("deregSubmitted") || len(q.Extra) != 2 || q.Extra[1].Key != "spoAssetPending" {
		t.Errorf("a queued retirement records nothing until it is confirmed: %q", q.Extra)
	}
	if !r.confirm(res.TxID) {
		t.Fatal("nothing pending")
	}
	if got := r.descriptor().Text("deregSubmitted"); got != "Mon, 16 Nov 2026 12:00:00 +0000 (only offline, no proof)" {
		t.Errorf("%q", got)
	}
	// A retirement after a registration was queued: 05c refuses a new registration without a type.
	r.edit("regCertFile", "mypool.pool.cert")
	if _, err := r.register(true).Run(ctx, RegisterRequest{Pool: "mypool", Payer: "pay"}); !errors.Is(err, errMissingCertOrType()) {
		t.Logf("registration after retirement: %v", err)
	}
}

func errMissingCertOrType() error { return ErrMissingFile }

// spec: SPO-07b-PR-001, SPO-Ptx-PR-004
func TestRetirementIsNeverApprovedByASkipPolicy(t *testing.T) {
	r := newPoolRig(t)
	r.retireReady(t, 12)
	r.conf.answer = []bool{false}
	before := r.snapshot()
	_, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"})
	// The policy asks (the zero value) and the operator declines: nothing is sent, nothing changes.
	if !errors.Is(err, txflow.ErrDeclined) || r.calls.count("confirm") != 1 || len(r.sub.sent) != 0 {
		t.Fatalf("%v %v", err, r.calls.l)
	}
	r.nothingChanged(before, "a declined retirement")
	skip := r.retire(false)
	skip.Pipeline.Approval = txflow.ApprovalSkip
	if _, err := skip.Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"}); !errors.Is(err, txflow.ErrDeclined) || r.calls.count("confirm") != 2 {
		t.Errorf("a skip policy was honoured: %v %v", err, r.calls.l)
	}
}

// spec: SPO-07b-INV-003, SPO-07b-IN-001, SPO-07b-IN-002, SPO-07b-PRE-001, SPO-07b-INV-004, SPO-07b-INV-002
func TestRetirementRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name string
		do   func(r *prig)
		want error
	}{
		{"no descriptor", func(r *prig) { r.remove("mypool.pool.json") }, ErrNoDescriptor},
		{"no certificate (not generated, or used up)", func(r *prig) { r.remove("mypool.pool.dereg-cert") }, ErrMissingFile},
		{"no deregCertFile in the descriptor", func(r *prig) { r.edit("deregCertFile", nil) }, pool.ErrMissingField},
		{"no ticker", func(r *prig) { r.edit("poolMetaTicker", nil) }, pool.ErrMissingField},
		{"a registration certificate where a retirement is wanted", func(r *prig) {
			g := r.mustGenerate()
			r.write("mypool.pool.dereg-cert", g.Certificate.Envelope)
		}, nil},
		{"the certificate retires another pool", func(r *prig) {
			c, _ := r.led.BuildPoolRetirement(pool.RetirementSpec{Pool: chain.PoolID{5}, Epoch: 12})
			r.write("mypool.pool.dereg-cert", c.Envelope)
		}, ErrCertificateMismatch},
		{"no cold signing key", func(r *prig) { r.remove("mypool.node.skey") }, ErrNoColdSigner},
		{"a hardware cold key has no signer here", func(r *prig) { r.remove("mypool.node.skey"); r.write("mypool.node.hwsfile", []byte("hw")) }, nil},
		{"a hardware payer has no signer here", func(r *prig) { r.remove("pay.skey"); r.write("pay.hwsfile", []byte("hw")) }, nil},
		{"the epoch has passed since the certificate was made", func(r *prig) { r.chain.tip.Epoch = 12 }, ErrRetirementWindow},
		{"the epoch is beyond eMax by now", func(r *prig) { r.chain.tip.Epoch = 0; r.chain.params.PoolRetireMaxEpoch = 5 }, ErrRetirementWindow},
		{"no funds", func(r *prig) { r.chain.utxos = nil }, txbuild.ErrNoFunds},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newPoolRig(t)
			r.retireReady(t, 12)
			c.do(r)
			before := r.snapshot()
			_, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"})
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			r.nothingChanged(before, "a refusal")
			if len(r.sub.sent) != 0 || r.calls.count("fee") > 0 && c.want == ErrRetirementWindow {
				t.Errorf("a fee was estimated or a transaction sent: %v", r.calls.l)
			}
		})
	}
}

// spec: SPO-07b-PRE-002, SPO-07b-INV-014, SPO-07b-MODE-001, SPO-07b-MODE-002, SPO-07b-OUT-001, SPO-Ptx-PRE-007
func TestRetirementTooLargeOrNotSubmittedLeavesTheCertificate(t *testing.T) {
	r := newPoolRig(t)
	r.retireReady(t, 12)
	r.chain.params.MaxTxSize = 300
	before := r.snapshot()
	if _, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"}); err == nil || !strings.Contains(err.Error(), "above the maximum") {
		t.Fatalf("%v", err)
	}
	r.nothingChanged(before, "a refusal")
	// A failed submission is an error (a failed light submit exits 0 upstream), and nothing is recorded.
	r.chain.params.MaxTxSize = 16384
	r.sub.err = errors.New("node said no")
	before = r.snapshot()
	if _, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"}); err == nil || !strings.Contains(err.Error(), "node said no") {
		t.Fatalf("%v", err)
	}
	r.nothingChanged(before, "a failed submission")
}

// spec: SPO-07b-INV-005, SPO-07b-INV-006, SPO-07b-INV-007, SPO-07b-INV-008, SPO-07b-INV-009, SPO-07b-INV-010, SPO-07b-INV-011, SPO-07b-INV-012,
// spec: SPO-07b-INV-013, SPO-07b-INV-015, SPO-07b-INV-016, SPO-07b-OUT-004, SPO-07b-SEC-001, SPO-07b-IF-003
func TestStageMapOfTheRetirement(t *testing.T) {
	r := newPoolRig(t)
	r.chain.utxos[0].Assets = []chain.AssetAmount{{Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("t")}, Quantity: 4}}
	r.retireReady(t, 12)
	res, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay", Message: []string{"retire"}})
	if err != nil {
		t.Fatal(err)
	}
	// Every UTxO spent, the assets in the one change output, the validity end tip + defTTL.
	if res.Inputs != 2 || res.TTL != 101000 || len(res.Outputs) != 1 || len(res.Outputs[0].Assets) != 1 || len(r.conf.got[0].Message) != 1 {
		t.Errorf("%+v", res)
	}
	// A recorded retirement makes a later registration ask for a type (SPO-07b-OUT-004).
	r2 := newPoolRig(t)
	r2.mustGenerate()
	r2.edit("deregSubmitted", "then")
	if _, err := r2.run(r2.register(false)); !errors.Is(err, pool.ErrChooseType) {
		t.Errorf("%v", err)
	}
}

// A submission whose outcome is unknown may be in a block: the pending record
// stays (settling decides later), where a refused one leaves nothing behind;
// the certificate is not consumed either way (SPO-Xconfirm-PR-006).
//
// spec: SPO-Xconfirm-PR-006, SPO-Xconfirm-PR-008
func TestUnknownSubmitOutcomeKeepsThePendingRecord(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("id mismatch %v", mismatch), func(t *testing.T) { unknownOutcomeKeepsPending(t, mismatch) })
	}
	t.Run("a refusal removes it", func(t *testing.T) {
		r := ready(t)
		r.sub.err = errors.New("node said no")
		if _, err := r.run(r.register(false)); err == nil {
			t.Fatal("accepted")
		}
		if list, _, _ := appassets.ListPending(ctx, r.store, r.store); len(list) != 0 {
			t.Errorf("a refused registration left %+v", list)
		}
	})
}

func unknownOutcomeKeepsPending(t *testing.T, mismatch bool) {
	for _, tc := range []struct {
		name string
		run  func(r *prig) error
		kind string
	}{
		{"retirement", func(r *prig) error {
			r.retireReady(t, 12)
			_, err := r.retire(false).Run(ctx, RetireRequest{Pool: "mypool", Payer: "pay"})
			return err
		}, assets.PendingPoolRetirement},
		{"registration", func(r *prig) error {
			_, err := r.run(r.register(false))
			return err
		}, assets.PendingPoolRegistration},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ready(t)
			if mismatch {
				r.sub.wrongID = true // the provider accepted it and named another id
			} else {
				r.sub.err = chain.NewOutcomeUnknown("the node did not answer")
			}
			err := tc.run(r)
			if err == nil || !strings.Contains(err.Error(), "stays pending") {
				t.Fatalf("%v", err)
			}
			list, ok, lerr := appassets.ListPending(ctx, r.store, r.store)
			if lerr != nil || !ok || len(list) != 1 || list[0].Kind != tc.kind {
				t.Fatalf("pending: %v %v %+v", lerr, ok, list)
			}
			if d := r.descriptor(); d.Has("regSubmitted") || d.Has("deregSubmitted") {
				t.Error("the record was written on an unknown outcome")
			}
			// Settling later applies it once the transaction is confirmed.
			id, _ := chain.ParseTxID(list[0].TxID)
			if !r.confirm(id) {
				t.Fatal("nothing to apply")
			}
			if d := r.descriptor(); !d.Has("regSubmitted") && !d.Has("deregSubmitted") {
				t.Error("not applied")
			}
		})
	}
}
