package wallet

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// SendAssets sends native assets, with the lovelace they need, from a payment
// address to a destination (upstream 01_sendAssets). It has the same ports as
// SendLovelaces and the same pipeline (txflow); what is its own is the
// selection of assets and the layout of the two outputs.
type SendAssets struct {
	Store     ports.NamedStore
	Signers   ports.SignerDirectory
	Utxos     ports.UtxoReader
	Params    ports.ProtocolParametersReader
	Tip       ports.TipReader
	Addresses ports.AddressInspector
	Min       ports.MinOutputCalculator
	Fees      ports.FeeEstimator
	Bodies    ports.TxBodyBuilder
	Assembler ports.TxAssembler
	Confirmer ports.Confirmer

	// Exactly one of Submitter and Queue is set.
	Submitter ports.TxSubmitter
	Queue     ports.TxQueue

	NetworkID uint8
	Approval  ApprovalPolicy
	DefTTL    uint64
	Selection txbuild.SelectionStrategy
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
	// Canonicalizer brings the body to hardware form when the paying key is held
	// by a hardware wallet; nil refuses a hardware plan.
	Canonicalizer ports.HardwareCanonicalizer
	// Handles resolves an ADA Handle destination; nil refuses handles.
	Handles HandleResolver
}

// SendAssetsRequest is one send. Selections come from assets.ParseSelections;
// Extras from txparam.Parse with txparam.ForSendAssets (its Lovelaces is the
// lovelace to send along with the assets, raised to the destination's
// minimum).
type SendAssetsRequest struct {
	Source      string
	Destination string
	Selections  []assets.Selection
	// SumDuplicates is the answer to "do you want to sum the amount up?"
	// (SPO-01sendAssets-PR-001). False refuses an asset named twice.
	SumDuplicates bool
	// Message holds plain CIP-20 lines beside those of Extras.
	Message    []string
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// SendAssetsResult is what happened. Nothing in it is secret.
type SendAssetsResult struct {
	SendResult
	// Sent is the assets sent, in ledger order.
	Sent []chain.AssetAmount
	// Warnings is advice, such as a FORCEADA that found no asset.
	Warnings []string
}

// Run performs the send.
//
// spec: SPO-01sendAssets-IF-001, SPO-01sendAssets-IF-002, SPO-01sendAssets-IF-005, SPO-01sendAssets-IF-006,
// spec: SPO-01sendAssets-IN-001, SPO-01sendAssets-INV-006, SPO-01sendAssets-INV-007, SPO-01sendAssets-INV-008,
// spec: SPO-01sendAssets-INV-009, SPO-01sendAssets-INV-010, SPO-01sendAssets-INV-011, SPO-01sendAssets-INV-012,
// spec: SPO-01sendAssets-INV-013, SPO-01sendAssets-INV-014, SPO-01sendAssets-INV-015, SPO-01sendAssets-INV-016,
// spec: SPO-01sendAssets-INV-017, SPO-01sendAssets-EXT-001, SPO-01sendAssets-EXT-002, SPO-01sendAssets-PRE-004,
// spec: SPO-01sendAssets-OUT-002, SPO-01sendAssets-PR-002
func (uc SendAssets) Run(ctx context.Context, req SendAssetsRequest) (SendAssetsResult, error) {
	pipe := txflow.Pipeline{Signers: uc.Signers, Min: uc.Min, Fees: uc.Fees, Bodies: uc.Bodies, Assembler: uc.Assembler,
		Confirmer: uc.Confirmer, Submitter: uc.Submitter, Queue: uc.Queue, Approval: txflow.ApprovalPolicy(uc.Approval),
		Canonicalizer: uc.Canonicalizer}
	if err := pipe.Check(); err != nil {
		return SendAssetsResult{}, err
	}
	if req.Source == "" || req.Destination == "" || len(req.Selections) == 0 {
		return SendAssetsResult{}, errors.New("an asset send needs a source, a destination and an asset selection")
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return SendAssetsResult{}, err
	}
	var lovelaces chain.Lovelace
	var keep [][28]byte
	if req.Extras != nil {
		lovelaces, keep = req.Extras.Lovelaces, req.Extras.KeepPolicies
	}
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: uc.Files, Encrypter: uc.Encrypter}, req.Extras, req.Message, req.Passphrase)
	if err != nil {
		return SendAssetsResult{}, err
	}

	srcName, err := normalizeName(req.Source)
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("source: %w", err)
	}
	var src, dst resolved
	var payKey custody.KeyRef
	sels := append([]assets.Selection(nil), req.Selections...)
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		// The source files are checked first, then the destination, both
		// before the asset selection is resolved (SPO-01sendAssets-IF-002).
		addr, ok, err := readAddress(r, srcName)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s.addr", ErrNoSourceAddress, srcName)
		}
		src = resolved{name: srcName, addr: addr}
		var held bool
		if payKey, held, err = keyring.ResolveHeld(r, custody.RolePayment, srcName); err != nil {
			return err
		}
		if !held {
			return fmt.Errorf("%w: %s", ErrNoSigningKey, srcName)
		}
		if dst, err = (SendLovelaces{Addresses: uc.Addresses, Handles: uc.Handles}).resolveDestination(r, req.Destination); err != nil {
			return err
		}
		for i, s := range sels {
			if s.Kind != assets.KindFile {
				continue
			}
			if sels[i], err = resolveAssetFile(r, s); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return SendAssetsResult{}, err
	}
	// An ADA Handle destination is resolved and verified here, outside the store
	// view, and shown as the handle and its address (ADR 0006).
	if dst, err = resolveHandle(ctx, uc.Handles, dst); err != nil {
		return SendAssetsResult{}, err
	}
	if dups := assets.Duplicates(sels); len(dups) > 0 && !req.SumDuplicates {
		return SendAssetsResult{}, fmt.Errorf("%w: %s", assets.ErrDuplicateAsset, strings.Join(dups, ", "))
	}

	srcInfo, err := uc.Addresses.InspectAddress(src.addr)
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("source address: %w", err)
	}
	if !srcInfo.Kind.IsPayment() || srcInfo.PaymentKeyHash == nil {
		return SendAssetsResult{}, fmt.Errorf("%w: %s", ErrSourceNotKey, src.name)
	}
	if srcInfo.NetworkID != uc.NetworkID {
		return SendAssetsResult{}, fmt.Errorf("%w: the source %s", ErrNetworkMismatch, src.name)
	}
	dstInfo, err := uc.Addresses.InspectAddress(dst.addr)
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("destination address: %w", err)
	}
	if !dstInfo.Kind.IsPayment() {
		return SendAssetsResult{}, fmt.Errorf("%w: %s is a %s address", ErrBadDestination, dst.name, dstInfo.Kind)
	}
	if dstInfo.NetworkID != uc.NetworkID {
		return SendAssetsResult{}, fmt.Errorf("%w: the destination %s", ErrNetworkMismatch, dst.name)
	}

	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("current slot: %w", err)
	}
	ttl, err := txbuild.TTL(tip, uc.DefTTL)
	if err != nil {
		return SendAssetsResult{}, err
	}
	utxos, err := uc.Utxos.Utxos(ctx, src.addr)
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("the UTxOs of %s: %w", src.name, err)
	}
	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if params.ProtocolMajor < 7 {
		return SendAssetsResult{}, ErrProtocolTooOld
	}

	// Every availability check uses only the candidates left after the
	// filters (SPO-01sendAssets-INV-009).
	strategy := uc.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	inputs, err := strategy.Select(txflow.FilterCandidates(req.Extras, utxos))
	if err != nil {
		return SendAssetsResult{}, fmt.Errorf("%s: %w", src.name, err)
	}
	total, err := txbuild.TotalOf(inputs)
	if err != nil {
		return SendAssetsResult{}, err
	}
	plan, err := assets.Resolve(sels, assets.HeldAssets(total.Assets), keep, req.SumDuplicates)
	if err != nil {
		return SendAssetsResult{}, err
	}
	if len(plan.Send) == 0 && !hasForceAda(sels) {
		return SendAssetsResult{}, txbuild.ErrNothingToSend
	}
	draft, err := txbuild.NewSendAssetsDraft(src.addr, dst.addr, lovelaces, plan.Send, inputs, nil)
	if err != nil {
		return SendAssetsResult{}, err
	}
	if draft, err = meta.Attach(draft); err != nil {
		return SendAssetsResult{}, err
	}

	prep, err := pipe.Prepare(draft, []txflow.Slot{{Label: "payment",
		Key:  payKey,
		Hash: *srcInfo.PaymentKeyHash}}, txbuild.SendWitnesses)
	if err != nil {
		return SendAssetsResult{}, err
	}
	res, err := pipe.Execute(ctx, txflow.Input{Draft: draft, Params: params, TTL: ttl, Prepared: prep, Witnesses: txbuild.SendWitnesses,
		HardwareChangeKeys: hardwareChangeKeys(ctx, uc.Store, src.name, payKey),
		Summary: ports.TxSummary{Kind: "asset payment", Source: src.name, SourceAddr: src.addr, Destination: dst.name, DestAddr: dst.addr,
			Amount: fmt.Sprintf("%d asset type(s)", len(plan.Send))},
		Queued: ports.QueuedTx{Type: "Transaction", FromName: src.name, FromAddr: src.addr, ToName: dst.name, ToAddr: dst.addr,
			Description: fmt.Sprintf("generated and signed utxo-token-transaction from '%s' to '%s'", src.name, dst.name)}})
	if err != nil {
		return SendAssetsResult{}, wrapPipeline(err)
	}
	out := SendAssetsResult{SendResult: SendResult{TxID: res.TxID, Fee: res.Fee, TTL: res.TTL, Outputs: res.Outputs, Inputs: res.Inputs,
		Size: res.Size, SignedTx: res.SignedTx, Submitted: res.Submitted, Queued: res.Queued, ApprovalSkipped: res.ApprovalSkipped,
		Destination: dst.name, Handle: dst.handle, Encrypted: meta.Encryption != ""}, Sent: plan.Send, Warnings: plan.Warnings}
	for _, f := range meta.Files {
		out.MetadataFiles = append(out.MetadataFiles, f.Name)
	}
	return out, nil
}

func hasForceAda(sels []assets.Selection) bool {
	for _, s := range sels {
		if s.Kind == assets.KindForceAda {
			return true
		}
	}
	return false
}

// resolveAssetFile reads the asset record a selection names and fills in the
// fingerprint of its asset.
//
// spec: SPO-01sendAssets-IF-014, SPO-Pfiles-OUT-033
func resolveAssetFile(r ports.NamedReader, s assets.Selection) (assets.Selection, error) {
	name := s.File
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = assets.RecordName(name[:i], name[i+1:])
	}
	ref := ports.NamedRef{Name: name, Kind: ports.AssetFile}
	if err := ref.Validate(); err != nil {
		return s, fmt.Errorf("%w: the asset %q is not a fingerprint, a policy id with a name, or the name of an asset file", assets.ErrBadSelection, s.Input)
	}
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return s, fmt.Errorf("%w: the asset %q could not be resolved from an asset file, a fingerprint or a policy id and name", assets.ErrBadSelection, s.Input)
	}
	if err != nil {
		return s, err
	}
	rec, err := assets.ParseRecord(b)
	if err != nil {
		return s, fmt.Errorf("%s.asset: %w", name, err)
	}
	id, err := rec.Fields().AssetOf()
	if err != nil {
		return s, fmt.Errorf("%s.asset: %w", name, err)
	}
	s.Fingerprint = assets.Fingerprint(id)
	return s, nil
}

// wrapPipeline gives the pipeline's refusals the names this package's callers
// test for, as SendLovelaces' own copy of the stages does.
func wrapPipeline(err error) error {
	switch {
	case errors.Is(err, txflow.ErrDeclined):
		return fmt.Errorf("%w", ErrDeclined)
	case errors.Is(err, txflow.ErrNoConfirmer):
		return fmt.Errorf("%w", ErrNoConfirmer)
	case errors.Is(err, txflow.ErrNoSigner):
		return fmt.Errorf("%w: %v", ErrNoSigner, err)
	}
	return err
}
