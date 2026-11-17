package poolops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
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
	// Files and Encrypter are needed only by a request with Extras that name
	// metadata files or ask for message encryption.
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
}

// RetireRequest names the pool and the paying address.
type RetireRequest struct {
	Pool    string
	Payer   string
	Message []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase is the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// RetireResult is what happened.
type RetireResult struct {
	txflow.Result
	Epoch uint64
	// RecordPending is true when the retirement record waits for the
	// transaction to be confirmed.
	RecordPending bool
	Decisions     []string
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
	// spec: SPO-Pparam-IF-010, SPO-Pparam-IF-016
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: uc.Files, Encrypter: uc.Encrypter}, req.Extras, req.Message, req.Passphrase)
	if err != nil {
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
	// Refuse a holder no signer serves before any chain read (SPO-07b-INV-004),
	// and a hardware key mixed with a key-file key: "only a hardware cold key can
	// be registered with a hardware payer" (SPO-07b-INV-004, SPO-Ptx-PRE-006).
	retireOpts := txflow.PrepareOptions{RefuseMixed: true}
	if _, err := uc.Pipeline.PrepareWith(txbuild.Draft{Certificates: []stk.Certificate{att}, Message: req.Message}, slots, retireWitnesses, retireOpts); err != nil {
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
	if req.Extras != nil {
		if draft, err = meta.Attach(draft); err != nil {
			return RetireResult{}, err
		}
	}
	// Retirement is never approved by a skip policy (SPO-Ptx-PR-004,
	// SPO-07b-PR-001).
	pl := uc.Pipeline
	pl.Approval = txflow.ApprovalAsk
	prep, err := pl.PrepareWith(draft, slots, retireWitnesses, retireOpts)
	if err != nil {
		return RetireResult{}, err
	}
	ticker := d.Text(pool.FieldMetaTicker)
	sum := ports.TxSummary{Kind: "pool retirement", Stage: "submit", Pool: id.Bech32(), Source: pay.name, SourceAddr: pay.addr, Account: name,
		Attachments: draft.AttachmentLines()}
	// The retirement record (deregSubmitted) waits until the transaction is
	// confirmed: Stage keeps it as a pending record under the transaction's id
	// before the transaction leaves, and `spo tx settle` or the wait of this
	// command applies it (hazard H9, SPO-Xconfirm-PR-002).
	var pref ports.Ref
	stage := func(ctx context.Context, id chain.TxID, validUntil uint64, queued bool) ([]ports.QueuedField, error) {
		stamp := rfc5322(uc.Clock.Now())
		if queued {
			stamp += " (only offline, no proof)"
		}
		pend := assets.Pending{Kind: assets.PendingPoolRetirement, TxID: id.String(), ValidUntil: &validUntil, Queued: queued,
			Date: uc.Clock.Now().Format(time.RFC3339Nano), Pool: name, Epoch: strconv.FormatUint(cert.Retirement.Epoch, 10), Stamp: stamp}
		pb, err := pend.Marshal()
		if err != nil {
			return nil, err
		}
		pref = ports.Ref{Name: pend.TxID, Kind: ports.PendingUpdate}
		if err := uc.Store.Update(ctx, func(w ports.Writer) error { return w.Put(pref, pb) }); err != nil {
			return nil, fmt.Errorf("keep the retirement record until the transaction is confirmed: %w", err)
		}
		if !queued {
			return nil, nil
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, pb); err != nil {
			return nil, err
		}
		return []ports.QueuedField{{Key: transfer.KeyAssetPending, Value: compact.String()}}, nil
	}
	res, err := pl.Execute(ctx, txflow.Input{Stage: stage, Draft: draft, Params: params, TTL: ttl, Prepared: prep, Witnesses: retireWitnesses, Summary: sum, HardwareChangeKeys: hwChangeKeys(slots[0].Key),
		Queued: ports.QueuedTx{Type: "PoolRetirement", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
			Description: fmt.Sprintf("signed pool retirement transaction for '%s', payment via '%s'", ticker, pay.name),
			Extra:       []ports.QueuedField{{Key: "poolMetaTicker", Value: ticker}}}})
	if err != nil {
		switch {
		case pref.Name == "":
		case pl.Queue == nil && errors.Is(err, chain.ErrSubmitOutcomeUnknown):
			// The transaction may be in a block: the pending record stays.
			err = fmt.Errorf("%w\nThe retirement record of pool %s stays pending under transaction %s: spo tx settle applies it once the transaction is confirmed, and drops it when it has expired", err, name, pref.Name)
		default:
			_ = uc.Store.Update(ctx, func(w ports.Writer) error { return w.Delete(pref) })
		}
		return RetireResult{}, err
	}
	// The consumption of the certificate follows the pending record (SPO-07b-OUT-003:
	// upstream leaves the certificate reusable).
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		return w.Delete(ports.Ref{Name: name, Kind: ports.PoolDeregCert})
	}); err != nil {
		return RetireResult{Result: res}, fmt.Errorf("the transaction was sent (%s), but the retirement certificate could not be consumed: %w", res.TxID, err)
	}
	return RetireResult{Result: res, Epoch: cert.Retirement.Epoch, RecordPending: true, Decisions: []string{
		"deregSubmitted is written when the transaction is confirmed, not when it is sent (SPO-Xconfirm-PR-002, port note)",
		"the retirement certificate is deleted when the transaction is sent, where upstream leaves it reusable (SPO-07b-OUT-003)",
		"the retirement epoch is checked against the current epoch and eMax before a fee is spent (SPO-07b-INV-003)",
	}}, nil
}

// hwChangeKeys declares a hardware payment key to the device as the owner of the
// change output (SPO-Ptx-INV-009); nil for any other key.
func hwChangeKeys(pay custody.KeyRef) []custody.KeyRef {
	if pay.Holder != custody.HolderHardware {
		return nil
	}
	return []custody.KeyRef{pay}
}
