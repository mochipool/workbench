package poll_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/poll"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dpoll "github.com/mochipool/workbench/spo/internal/domain/poll"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/world"
)

// recFees records the witness count of every fee estimate.
type recFees struct {
	native.Ledger
	counts []uint
}

func (f *recFees) EstimateFee(p chain.ProtocolParameters, b txbuild.TxBody, n uint) (chain.Lovelace, error) {
	f.counts = append(f.counts, n)
	return f.Ledger.EstimateFee(p, b, n)
}

type submitRig struct {
	fees   *recFees
	w      *world.World
	uc     poll.SubmitPollAnswer
	pay    wallet.PaymentAccountGenerated
	pool   poolops.ColdKeysGenerated
	answer poll.Answer
}

func newSubmitRig(t *testing.T) *submitRig {
	t.Helper()
	w := world.New(t)
	ctx := context.Background()
	pay, err := wallet.GeneratePaymentAccount{Store: w.Store, KeyGen: native.SoftwareKeys{}, Addresses: w.Ledger, NetworkID: w.Network}.
		Run(ctx, wallet.GeneratePaymentRequest{Name: "pay"})
	if err != nil {
		t.Fatal(err)
	}
	w.Fund(pay.Address, 50_000_000)
	cold, err := poolops.GenerateColdKeys{Store: w.Store, KeyGen: native.SoftwareKeys{}}.Run(ctx, poolops.GenerateColdKeysRequest{Pool: "mypool"})
	if err != nil {
		t.Fatal(err)
	}
	var qh [32]byte
	qh[0] = 0xab
	ans := poll.Answer{QuestionHash: qh, Index: 1, CBOR: dpoll.EncodeAnswer(qh, 1), FileName: dpoll.FileName(qh)}
	fees := &recFees{Ledger: w.Ledger}
	send := wallet.SendLovelaces{Store: w.Store, Signers: w.Signers(), Utxos: w.Chain, Params: w.Chain, Tip: w.Chain, Addresses: w.Ledger,
		Min: w.Ledger, Fees: fees, Bodies: w.Bodies, Assembler: w.Ledger, Confirmer: w.Conf, Submitter: w.Chain, NetworkID: w.Network}
	return &submitRig{fees: fees, w: w, uc: poll.SubmitPollAnswer{Send: send}, pay: pay, pool: cold, answer: ans}
}

// The answer transaction: a payment of MIN back to the paying address that
// carries the 13a answer, lists the pool's cold key hash in the body's required
// signers (key 14), pays the fee of two witnesses, and is witnessed by both the
// payment key and the cold key. The pool id shown is the cold key hash.
//
// spec: SPO-13b-IF-001, SPO-13b-IF-002, SPO-13b-IN-001, SPO-13b-IN-002, SPO-13b-EXT-001, SPO-13b-EXT-002, SPO-13b-EXT-003,
// spec: SPO-13b-INV-001, SPO-13b-INV-002, SPO-13b-INV-003, SPO-13b-INV-008, SPO-13b-INV-009, SPO-13b-INV-010, SPO-13b-INV-011,
// spec: SPO-13b-INV-004, SPO-13b-INV-005, SPO-13b-INV-006, SPO-13b-INV-007, SPO-13b-INV-012, SPO-13b-INV-013, SPO-13b-INV-014, SPO-13b-MODE-001, SPO-13b-SEC-002, SPO-13b-SEC-003
func TestAnswerIsSignedByThePayerAndThePoolColdKey(t *testing.T) {
	r := newSubmitRig(t)
	res, err := r.uc.Run(context.Background(), poll.SubmitRequest{Payer: "pay", Destination: "pay", Amount: "MIN", Pool: "mypool.node.skey", Answer: &r.answer})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || len(r.w.Chain.Submitted) != 1 || r.w.Conf.Seen[0].TxID != res.TxID {
		t.Fatalf("%+v", res)
	}
	// Stages 2 to 5: the TTL is slot + 100000 and every UTxO of the payer is spent.
	if res.TTL != 101000 || res.Inputs != 1 {
		t.Errorf("ttl %d, inputs %d", res.TTL, res.Inputs)
	}
	signed := r.w.Chain.Submitted[0]
	cold, _ := hashOf(r.pool.VKey)
	if !bytes.Contains(signed, append([]byte{0x0e, 0xd9, 0x01, 0x02, 0x81, 0x58, 0x1c}, cold[:]...)) {
		t.Error("the body does not list the cold key hash as a required signer (key 14)")
	}
	if id := chain.PoolID(cold); id != res.PoolID {
		t.Errorf("pool id %x, cold key hash %x", res.PoolID, cold)
	}
	// Two witnesses, one per key.
	ws, err := (native.TxViewer{}).Witnesses(signed)
	if err != nil || len(ws) != 2 {
		t.Fatalf("witnesses %d %v", len(ws), err)
	}
	payHash := hashOfKey(t, r.w.Ledger, r.pay.Address)
	got := map[txbuild.KeyHash]bool{}
	for _, w := range ws {
		got[txbuild.HashKey(w.VKey[:])] = true
		if err := txbuild.VerifyWitness(txbuild.TxBody{ID: res.TxID}, w, txbuild.HashKey(w.VKey[:])); err != nil {
			t.Error(err)
		}
	}
	if !got[payHash] || !got[cold] {
		t.Errorf("witnesses are not the payment and the cold key: %v", got)
	}
	// The fee is estimated for two witnesses on every call, never one.
	if len(r.fees.counts) == 0 {
		t.Fatal("no fee was estimated")
	}
	for _, n := range r.fees.counts {
		if n != 2 {
			t.Errorf("fee estimated for %d witnesses: %v", n, r.fees.counts)
		}
	}
	// The answer is the metadata (label 94).
	if !bytes.Contains(signed, r.answer.CBOR[1:]) {
		t.Error("the answer metadata is not in the transaction")
	}
}

// The three forms of the pool name are one pool; a message is not an answer; no
// metadata at all refuses before the chain is asked; a missing cold key and a
// hardware cold key are refused.
//
// spec: SPO-13b-IF-001, SPO-13b-IF-002, SPO-13b-IF-003, SPO-13b-IN-001, SPO-13b-PRE-001
func TestAnswerRefusals(t *testing.T) {
	ctx := context.Background()
	for in, want := range map[string]string{"mypool": "mypool", "mypool.node": "mypool", "mypool.node.skey": "mypool", "d/mypool.node.skey": "d/mypool", "mypool.skey": "mypool"} {
		if got := poll.PoolStem(in); got != want {
			t.Errorf("PoolStem(%q) = %q", in, got)
		}
	}
	r := newSubmitRig(t)
	base := poll.SubmitRequest{Payer: "pay", Destination: "pay", Amount: "MIN", Pool: "mypool"}

	// Fewer than four words.
	for _, bad := range []poll.SubmitRequest{{Destination: "pay", Amount: "MIN", Pool: "mypool", Answer: &r.answer}, {Payer: "pay", Destination: "pay", Amount: "MIN", Answer: &r.answer}} {
		if _, err := r.uc.Run(ctx, bad); err == nil {
			t.Error("a request with a word missing was accepted")
		}
	}
	// No metadata file: nothing is read, nothing is queried.
	noFile := base
	noFile.Extras = &txparam.Extras{Messages: []string{"hello"}}
	for name, req := range map[string]poll.SubmitRequest{"none": base, "a message does not count": noFile} {
		if _, err := r.uc.Run(ctx, req); !errors.Is(err, poll.ErrNoAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No cold key.
	missing := base
	missing.Pool, missing.Answer = "nopool", &r.answer
	if _, err := r.uc.Run(ctx, missing); !errors.Is(err, poll.ErrNoColdKey) {
		t.Errorf("no cold key: %v", err)
	}
	// A hardware cold key is not supported (only the key-file form).
	if err := r.w.Store.Update(ctx, func(w ports.NamedWriter) error {
		return w.Put(ports.NamedRef{Name: "hwpool", Kind: ports.NodeHwsFile}, []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	hw := base
	hw.Pool, hw.Answer = "hwpool.node", &r.answer
	if _, err := r.uc.Run(ctx, hw); !errors.Is(err, poll.ErrHardwareColdKey) {
		t.Errorf("hardware cold key: %v", err)
	}
	if len(r.w.Chain.Submitted) != 0 || len(r.w.Conf.Seen) != 0 {
		t.Error("a refusal reached the confirmation or the chain")
	}
}

func hashOf(vkeyEnvelope []byte) (txbuild.KeyHash, error) {
	var env struct {
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(vkeyEnvelope, &env); err != nil {
		return txbuild.KeyHash{}, err
	}
	raw, err := hex.DecodeString(env.CborHex[4:])
	return txbuild.HashKey(raw), err
}

func hashOfKey(t *testing.T, l native.Ledger, a chain.Address) txbuild.KeyHash {
	t.Helper()
	info, err := l.InspectAddress(a)
	if err != nil || info.PaymentKeyHash == nil {
		t.Fatal(err)
	}
	return *info.PaymentKeyHash
}
