package poolops

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrRetirementWindow: the retirement epoch of the certificate is not after
// the current epoch or is beyond eMax. Upstream submits anyway and the ledger
// rejects it after the fee was paid (SPO-07b-INV-003); the port refuses first.
var ErrRetirementWindow = errors.New("the retirement epoch of the certificate is outside the window the ledger accepts")

// GenerateRetirementCertificate makes the certificate that retires a pool at
// an epoch (upstream 07a_genStakepoolRetireCert). The epoch is clamped into
// the window current+1 .. current+eMax, and the result says so.
type GenerateRetirementCertificate struct {
	Store  ports.Store
	Params ports.ProtocolParametersReader
	Tip    ports.TipReader
	Certs  ports.PoolCertificateBuilder
	Clock  ports.Clock
}

// RetirementRequest names the pool and optionally the epoch. A nil epoch is
// the earliest. The epoch is a number here: upstream hands the text to a bash
// arithmetic evaluation, which a crafted word can abuse (SPO-07a-SEC-001).
type RetirementRequest struct {
	Pool  string
	Epoch *uint64
}

// RetirementCertificate is the result.
type RetirementCertificate struct {
	Certificate pool.Certificate
	Epoch       uint64
	Earliest    uint64
	Latest      uint64
	Warnings    []string
}

// Run generates the certificate.
//
// spec: SPO-07a-IF-001, SPO-07a-IF-002, SPO-07a-IF-003, SPO-07a-IN-001, SPO-07a-IN-002, SPO-07a-IN-003, SPO-07a-IN-004,
// spec: SPO-07a-INV-001, SPO-07a-INV-002, SPO-07a-INV-003, SPO-07a-EXT-001, SPO-07a-OUT-001, SPO-07a-OUT-002,
// spec: SPO-07a-MODE-001, SPO-07a-SEC-001, SPO-Pfiles-OUT-020
func (uc GenerateRetirementCertificate) Run(ctx context.Context, req RetirementRequest) (RetirementCertificate, error) {
	name, err := poolName(req.Pool)
	if err != nil {
		return RetirementCertificate{}, err
	}
	var d *pool.Descriptor
	var nodeEnv []byte
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if d, err = readDescriptor(r, name); err != nil {
			return err
		}
		if err = d.Require(pool.FieldName); err != nil {
			return err
		}
		if err = d.CheckName(name); err != nil {
			return err
		}
		nodeEnv, err = get(r, ports.Ref{Name: name, Kind: ports.NodeVKey})
		return err
	}); err != nil {
		return RetirementCertificate{}, err
	}
	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return RetirementCertificate{}, fmt.Errorf("protocol parameters: %w", err)
	}
	eMax, err := retireMaxEpoch(params)
	if err != nil {
		return RetirementCertificate{}, err
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return RetirementCertificate{}, fmt.Errorf("current epoch: %w", err)
	}
	id, err := poolIDOf(nodeEnv)
	if err != nil {
		return RetirementCertificate{}, fmt.Errorf("%s.node.vkey: %w", name, err)
	}
	out := RetirementCertificate{Earliest: tip.Epoch + 1, Latest: tip.Epoch + eMax}
	out.Epoch = out.Earliest
	if req.Epoch != nil {
		out.Epoch = *req.Epoch
		switch {
		case out.Epoch < out.Earliest:
			out.Epoch = out.Earliest
		case out.Epoch > out.Latest:
			out.Epoch = out.Latest
		}
		if out.Epoch != *req.Epoch {
			out.Warnings = append(out.Warnings, fmt.Sprintf("the epoch %d is outside %d to %d and was set to %d", *req.Epoch, out.Earliest, out.Latest, out.Epoch))
		}
	}
	if out.Certificate, err = uc.Certs.BuildPoolRetirement(pool.RetirementSpec{Pool: id, Epoch: out.Epoch}); err != nil {
		return RetirementCertificate{}, err
	}
	d.RecordRetirementCert(rfc5322(uc.Clock.Now()), name+".pool.dereg-cert", out.Epoch)
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(ports.Ref{Name: name, Kind: ports.PoolDeregCert}, out.Certificate.Envelope); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: name, Kind: ports.PoolDescriptor}, d.Render())
	}); err != nil {
		return RetirementCertificate{}, err
	}
	return out, nil
}

// RetirePool submits the retirement certificate (upstream 07b_deregStakepoolCert):
// one transaction with the certificate, signed by the payer and the pool cold
// key, paid for by the payer; no deposit moves in it. One workflow: whether
// the cold key is in the vault or on a device is the signer's business; a
// holder without a signer refuses up front.
type RetirePool struct {
	Store     ports.Store
	Addresses ports.AddressInspector
	Params    ports.ProtocolParametersReader
	Tip       ports.TipReader
	Utxos     ports.UtxoReader
	Pipeline  txflow.Pipeline
	PoolCerts ports.PoolCertificateDecoder
	Clock     ports.Clock
	NetworkID uint8
	DefTTL    uint64
	Selection txbuild.SelectionStrategy
}

// RetireRequest names the pool and the paying address.
type RetireRequest struct {
	Pool    string
	Payer   string
	Message []string
}

// RetireResult is what happened.
type RetireResult struct {
	txflow.Result
	Epoch     uint64
	Decisions []string
}

// retireWitnesses is the fixed witness count: the payer and the cold key
// (SPO-07b-INV-001).
const retireWitnesses uint = 2

// Run retires the pool.
//
// spec: SPO-07b-IF-001, SPO-07b-IF-002, SPO-07b-IN-001, SPO-07b-IN-002, SPO-07b-IN-003, SPO-07b-INV-001, SPO-07b-INV-002,
// spec: SPO-07b-INV-003, SPO-07b-INV-004, SPO-07b-PRE-001, SPO-07b-PR-001, SPO-07b-OUT-001, SPO-07b-OUT-002, SPO-07b-OUT-003, SPO-07b-OUT-004,
// spec: SPO-07b-MODE-001, SPO-07b-MODE-002, SPO-07b-MODE-003, SPO-07b-MODE-004
func (uc RetirePool) Run(ctx context.Context, req RetireRequest) (RetireResult, error) {
	if err := uc.Pipeline.Check(); err != nil {
		return RetireResult{}, err
	}
	if req.Pool == "" || req.Payer == "" {
		return RetireResult{}, errors.New("a retirement needs a pool and a paying address")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return RetireResult{}, err
	}
	name, err := poolName(req.Pool)
	if err != nil {
		return RetireResult{}, err
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return RetireResult{}, fmt.Errorf("payer: %w", err)
	}
	var (
		d      *pool.Descriptor
		cert   pool.Certificate
		id     chain.PoolID
		pay    payer
		holder custody.Holder
	)
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if d, err = readDescriptor(r, name); err != nil {
			return err
		}
		if err = d.Require(pool.FieldName, pool.FieldDeregFile, pool.FieldMetaTicker); err != nil {
			return err
		}
		if d.Text(pool.FieldDeregFile) != name+".pool.dereg-cert" {
			return fmt.Errorf("%w: deregCertFile is %q", ErrCertificateMismatch, d.Text(pool.FieldDeregFile))
		}
		raw, err := get(r, ports.Ref{Name: name, Kind: ports.PoolDeregCert})
		if err != nil {
			return fmt.Errorf("%w (not generated, or already submitted)", err)
		}
		if cert, err = uc.PoolCerts.DecodePoolCertificate(raw); err != nil {
			return fmt.Errorf("%s.pool.dereg-cert: %w", name, err)
		}
		nodeEnv, err := get(r, ports.Ref{Name: name, Kind: ports.NodeVKey})
		if err != nil {
			return err
		}
		if id, err = poolIDOf(nodeEnv); err != nil {
			return fmt.Errorf("%s.node.vkey: %w", name, err)
		}
		if cert.Retirement == nil || cert.Retirement.Pool != id {
			return fmt.Errorf("%w: it is not a retirement of %s", ErrCertificateMismatch, id.Bech32())
		}
		if holder, err = holderOf(r, ports.Ref{Name: name, Kind: ports.NodeSKey}, ports.Ref{Name: name, Kind: ports.NodeHwsFile}); err != nil {
			return fmt.Errorf("%w: %v", ErrNoColdSigner, err)
		}
		pay, err = readPayer(r, uc.Addresses, uc.NetworkID, pn)
		return err
	}); err != nil {
		return RetireResult{}, err
	}
	att := cert.Attachment(0)
	slots := []txflow.Slot{
		{Label: "payment", Key: custody.KeyRef{Role: custody.RolePayment, Holder: pay.holder, Owner: pay.name}, Hash: pay.hash},
		{Label: "pool cold key", Key: custody.KeyRef{Role: custody.RolePoolCold, Holder: holder, Owner: name}, Hash: txbuild.KeyHash(id)},
	}
	// Refuse a holder no signer serves before any chain read (SPO-07b-INV-004).
	if _, err := uc.Pipeline.Prepare(txbuild.Draft{Certificates: []stk.Certificate{att}, Message: req.Message}, slots, retireWitnesses); err != nil {
		return RetireResult{}, err
	}
	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return RetireResult{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if params.ProtocolMajor < 9 {
		return RetireResult{}, ErrProtocolTooOld
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return RetireResult{}, fmt.Errorf("current slot: %w", err)
	}
	// The epoch is revalidated now, before a fee is spent (SPO-07b-INV-003).
	eMax, err := retireMaxEpoch(params)
	if err != nil {
		return RetireResult{}, err
	}
	if e := cert.Retirement.Epoch; e <= tip.Epoch || e > tip.Epoch+eMax {
		return RetireResult{}, fmt.Errorf("%w: epoch %d, the current epoch is %d and the last allowed is %d (generate the certificate again)",
			ErrRetirementWindow, e, tip.Epoch, tip.Epoch+eMax)
	}
	ttl, err := txbuild.TTL(tip, uc.DefTTL)
	if err != nil {
		return RetireResult{}, err
	}
	utxos, err := uc.Utxos.Utxos(ctx, pay.addr)
	if err != nil {
		return RetireResult{}, fmt.Errorf("the UTxOs of %s: %w", pay.name, err)
	}
	strategy := uc.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	inputs, err := strategy.Select(utxos)
	if err != nil {
		return RetireResult{}, fmt.Errorf("%s: %w", pay.name, err)
	}
	draft, err := txbuild.NewCertificateDraft(pay.addr, inputs, []stk.Certificate{att}, req.Message)
	if err != nil {
		return RetireResult{}, err
	}
	// Retirement is never approved by a skip policy (SPO-Ptx-PR-004,
	// SPO-07b-PR-001).
	pl := uc.Pipeline
	pl.Approval = txflow.ApprovalAsk
	prep, err := pl.Prepare(draft, slots, retireWitnesses)
	if err != nil {
		return RetireResult{}, err
	}
	ticker := d.Text(pool.FieldMetaTicker)
	sum := ports.TxSummary{Kind: "pool retirement", Stage: "submit", Pool: id.Bech32(), Source: pay.name, SourceAddr: pay.addr, Account: name,
		Attachments: draft.AttachmentLines()}
	res, err := pl.Execute(ctx, txflow.Input{Draft: draft, Params: params, TTL: ttl, Prepared: prep, Witnesses: retireWitnesses, Summary: sum,
		Queued: ports.QueuedTx{Type: "PoolRetirement", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
			Description: fmt.Sprintf("signed pool retirement transaction for '%s', payment via '%s'", ticker, pay.name),
			Extra:       []ports.QueuedField{{Key: "poolMetaTicker", Value: ticker}}}})
	if err != nil {
		return RetireResult{}, err
	}
	stamp := rfc5322(uc.Clock.Now())
	if res.Queued {
		stamp += " (only offline, no proof)"
	}
	// The record and the consumption of the certificate are one transaction
	// (SPO-07b-OUT-003: upstream leaves the certificate reusable).
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		raw, err := w.Get(ports.Ref{Name: name, Kind: ports.PoolDescriptor})
		if err != nil {
			return err
		}
		d, err := pool.ParseDescriptor(raw)
		if err != nil {
			return err
		}
		d.RecordRetirement(stamp)
		if err := w.Put(ports.Ref{Name: name, Kind: ports.PoolDescriptor}, d.Render()); err != nil {
			return err
		}
		return w.Delete(ports.Ref{Name: name, Kind: ports.PoolDeregCert})
	}); err != nil {
		return RetireResult{Result: res}, fmt.Errorf("the transaction was sent (%s), but the retirement record could not be stored: %w", res.TxID, err)
	}
	return RetireResult{Result: res, Epoch: cert.Retirement.Epoch, Decisions: []string{
		"the retirement certificate is deleted with the record of the submission, where upstream leaves it reusable (SPO-07b-OUT-003)",
		"the retirement epoch is checked against the current epoch and eMax before a fee is spent (SPO-07b-INV-003)",
	}}, nil
}
