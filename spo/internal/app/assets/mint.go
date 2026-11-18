package assets

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of mint and burn.
var (
	// ErrPolicyFiles: a policy file is missing (SPO-11a-IN-001).
	ErrPolicyFiles = errors.New("the policy is incomplete")
	// ErrPolicyExpired: the policy's time lock is not after the current slot
	// (SPO-11a-PRE-003). Upstream exits 2.
	ErrPolicyExpired = errors.New("the policy has expired")
	// ErrPolicyMismatch: the policy id file or the policy key does not belong
	// to the script.
	ErrPolicyMismatch = errors.New("the policy id or key does not match the policy script")
	// ErrNoPayer: the paying address is missing or cannot sign with a key
	// (SPO-11a-IN-002).
	ErrNoPayer = errors.New("the paying address is missing, or has no key the port can sign with")
	// ErrNetworkMismatch: the paying address belongs to another network.
	ErrNetworkMismatch = errors.New("the address belongs to a different network")
	// ErrProtocolTooOld: protocol versions before 7 are not implemented.
	ErrProtocolTooOld = errors.New("the protocol version is older than 7: the older minimum output rule is not implemented")
)

// Base holds the ports of mint and burn: both read a policy and a paying
// address, build a body with a mint field and two witnesses, and update the
// asset record. Exactly one of Submitter and Queue is set.
type Base struct {
	Store     ports.NamedStore
	Signers   ports.SignerDirectory
	Utxos     ports.UtxoReader
	Params    ports.ProtocolParametersReader
	Tip       ports.TipReader
	Addresses ports.AddressInspector
	Policies  ports.PolicyIDCalculator
	Min       ports.MinOutputCalculator
	Fees      ports.FeeEstimator
	Bodies    ports.TxBodyBuilder
	Assembler ports.TxAssembler
	Confirmer ports.Confirmer
	Submitter ports.TxSubmitter
	Queue     ports.TxQueue
	Clock     ports.Clock

	NetworkID uint8
	Approval  txflow.ApprovalPolicy
	DefTTL    uint64
	Selection txbuild.SelectionStrategy
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
	// Canonicalizer brings the body to hardware form when the policy or paying
	// key is held by a hardware wallet; nil refuses a hardware plan.
	Canonicalizer ports.HardwareCanonicalizer
}

// MintAsset mints a positive amount of one asset under a policy and credits
// it to the paying address (upstream 11a_mintAsset).
type MintAsset struct{ Base }

// BurnAsset burns an amount of one asset held on the paying address under the
// policy that minted it (upstream 11b_burnAsset).
type BurnAsset struct{ Base }

// Request is a mint or a burn. Asset is `<policy>.<asset>` (a trailing
// `.asset` is dropped); Amount the positive amount; Payer the paying
// address name. Extras come from txparam.Parse with txparam.ForMint.
type Request struct {
	Asset      string
	Amount     string
	Payer      string
	Message    []string
	Extras     *txparam.Extras
	Passphrase *ports.Secret
}

// Result is what happened. Nothing in it is secret.
type Result struct {
	txflow.Result
	PolicyID string
	// Record is the store name of the asset record. The update is pending
	// (RecordPending) from the moment the transaction is sent or queued, and is
	// applied when the transaction is confirmed (see Settle); nothing in the
	// record changes before.
	Record        string
	RecordPending bool
	// Expiry is the policy's expiry slot; Limited is false for an unlimited policy.
	Expiry  uint64
	Limited bool
}

// Run mints.
//
// spec: SPO-11a-IF-001, SPO-11a-IF-002, SPO-11a-IF-003, SPO-11a-IF-004, SPO-11a-PRE-001, SPO-11a-PRE-002
func (uc MintAsset) Run(ctx context.Context, req Request) (Result, error) {
	return uc.run(ctx, req, false)
}

// Run burns.
//
// spec: SPO-11b-IF-001, SPO-11b-IF-002, SPO-11b-IF-003, SPO-11b-IF-004
func (uc BurnAsset) Run(ctx context.Context, req Request) (Result, error) {
	return uc.run(ctx, req, true)
}

type payerInfo struct {
	name string
	addr chain.Address
	key  custody.KeyRef
	hash txbuild.KeyHash
}

func (b Base) run(ctx context.Context, req Request, burn bool) (Result, error) {
	pipe := txflow.Pipeline{Signers: b.Signers, Min: b.Min, Fees: b.Fees, Bodies: b.Bodies, Assembler: b.Assembler,
		Confirmer: b.Confirmer, Submitter: b.Submitter, Queue: b.Queue, Approval: b.Approval,
		Canonicalizer: b.Canonicalizer}
	if err := pipe.Check(); err != nil {
		return Result{}, err
	}
	if b.Store == nil || b.Policies == nil || b.Clock == nil {
		return Result{}, fmt.Errorf("%w: a store, a policy id calculator and a clock are needed", ErrMisconfigured)
	}
	verb, past := "mint", "minted"
	if burn {
		verb, past = "burn", "burned"
	}

	// Stage 1: the words are checked before any file or network access.
	ref, err := assets.ParseRef(req.Asset)
	if err != nil {
		return Result{}, err
	}
	name, err := assets.ParseName(ref.Asset)
	if err != nil {
		return Result{}, err
	}
	amount, err := assets.ParseMintAmount(req.Amount)
	if err != nil {
		return Result{}, err
	}
	policyName, err := PolicyName(ref.Policy)
	if err != nil {
		return Result{}, err
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return Result{}, err
	}
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: b.Files, Encrypter: b.Encrypter}, req.Extras, req.Message, req.Passphrase)
	if err != nil {
		return Result{}, err
	}
	payerName := strings.TrimSuffix(strings.TrimPrefix(req.Payer, "./"), ".addr")
	if payerName == "" || strings.ContainsAny(payerName, "/\\") {
		return Result{}, fmt.Errorf("%w: %q", ErrNoPayer, req.Payer)
	}

	var script []byte
	var idHex string
	var polHash txbuild.KeyHash
	var polKey custody.KeyRef
	var payer payerInfo
	if err := b.Store.View(ctx, func(r ports.NamedReader) error {
		// spec: SPO-11a-IN-001, SPO-11a-IN-002, SPO-11b-IN-001
		get := func(k ports.Kind) ([]byte, error) {
			v, err := r.Get(ports.NamedRef{Name: policyName, Kind: k})
			if errors.Is(err, ports.ErrNotFound) {
				return nil, fmt.Errorf("%w: %s.%s is missing; create the policy first", ErrPolicyFiles, policyName, k)
			}
			return v, err
		}
		id, err := get(ports.PolicyID)
		if err != nil {
			return err
		}
		idHex = strings.TrimSpace(string(id))
		if script, err = get(ports.PolicyScript); err != nil {
			return err
		}
		// The signing plan decides whether the signer connected for the key can
		// sign a mint (the policy row of custody.HardwareTable).
		var held bool
		if polKey, held, err = keyring.ResolveHeld(r, custody.RolePolicy, policyName); err != nil {
			return err
		}
		if !held {
			return fmt.Errorf("%w: %s.policy.skey is missing", ErrPolicyFiles, policyName)
		}
		vk, err := get(ports.PolicyVKey)
		if err != nil {
			return err
		}
		env, err := pool.ParseEnvelope(vk)
		if err != nil {
			return err
		}
		raw, err := env.Key32()
		if err != nil {
			return err
		}
		polHash = txbuild.HashKey(raw)

		ab, err := r.Get(ports.NamedRef{Name: payerName, Kind: ports.AddrFile})
		if err != nil {
			if errors.Is(err, ports.ErrNotFound) {
				return fmt.Errorf("%w: %s.addr", ErrNoPayer, payerName)
			}
			return err
		}
		line, _, _ := strings.Cut(string(ab), "\n")
		payer = payerInfo{name: payerName, addr: chain.Address(strings.TrimSpace(line))}
		pk, held, err := keyring.ResolveHeld(r, custody.RolePayment, payerName)
		if err != nil {
			return err
		}
		if !held {
			return fmt.Errorf("%w: %s has no .skey or .hwsfile", ErrNoPayer, payerName)
		}
		payer.key = pk
		return nil
	}); err != nil {
		return Result{}, err
	}

	// The policy id is read from its file upstream and never recomputed; a
	// file that does not match the script would mint under an id nobody can
	// spend with, so the port compares them.
	want, err := b.Policies.PolicyID(script)
	if err != nil {
		return Result{}, fmt.Errorf("the policy script: %w", err)
	}
	if !strings.EqualFold(hex.EncodeToString(want[:]), idHex) {
		return Result{}, fmt.Errorf("%w: %s.policy.id says %s, the script hashes to %x", ErrPolicyMismatch, policyName, idHex, want[:])
	}
	if !strings.Contains(string(script), hex.EncodeToString(polHash[:])) {
		return Result{}, fmt.Errorf("%w: %s.policy.vkey is not the key the script requires", ErrPolicyMismatch, policyName)
	}

	info, err := b.Addresses.InspectAddress(payer.addr)
	if err != nil {
		return Result{}, fmt.Errorf("paying address: %w", err)
	}
	if !info.Kind.IsPayment() || info.PaymentKeyHash == nil {
		return Result{}, fmt.Errorf("%w: %s", ErrNoPayer, payerName)
	}
	if info.NetworkID != b.NetworkID {
		return Result{}, fmt.Errorf("%w: %s", ErrNetworkMismatch, payerName)
	}
	payer.hash = *info.PaymentKeyHash

	// Stage 2: the validity window. The TTL is the policy's `before` slot, or
	// the tip plus defTTL; a TTL that is not after the tip is a refusal before
	// any UTxO query.
	//
	// spec: SPO-11a-INV-001, SPO-11a-PRE-003, SPO-11a-INV-007, SPO-11b-INV-005
	tip, err := b.Tip.Tip(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("current slot: %w", err)
	}
	expiry, limited := assets.Expiry(script)
	ttl := expiry
	if !limited {
		if ttl, err = txbuild.TTL(tip, b.DefTTL); err != nil {
			return Result{}, err
		}
	}
	if ttl <= tip.Slot {
		return Result{}, fmt.Errorf("%w: it was valid before slot %d, the current slot is %d", ErrPolicyExpired, ttl, tip.Slot)
	}

	utxos, err := b.Utxos.Utxos(ctx, payer.addr)
	if err != nil {
		return Result{}, fmt.Errorf("the UTxOs of %s: %w", payer.name, err)
	}
	params, err := b.Params.ProtocolParameters(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if params.ProtocolMajor < 7 {
		return Result{}, ErrProtocolTooOld
	}
	strategy := b.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	inputs, err := strategy.Select(txflow.FilterCandidates(req.Extras, utxos))
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", payer.name, err)
	}

	var asset chain.AssetID
	copy(asset.Policy[:], want[:])
	asset.Name = name.Bytes
	signed := amount
	if burn {
		// spec: SPO-11b-PRE-002, SPO-11b-INV-001
		total, err := txbuild.TotalOf(inputs)
		if err != nil {
			return Result{}, err
		}
		var held uint64
		for _, a := range total.Assets {
			if a.Asset.Policy == asset.Policy && string(a.Asset.Name) == string(asset.Name) {
				held = a.Quantity
			}
		}
		if held < uint64(amount) {
			return Result{}, fmt.Errorf("%w: you can only burn %d, %d were asked", txbuild.ErrBurnExceedsHolding, held, amount)
		}
		signed = -amount
	}
	draft, err := txbuild.NewMintDraft(payer.addr, inputs, []txbuild.MintEntry{{Asset: asset, Quantity: signed}}, [][]byte{script}, nil)
	if err != nil {
		return Result{}, err
	}
	if draft, err = meta.Attach(draft); err != nil {
		return Result{}, err
	}

	// The policy witness first, then the payment witness (SPO-11a-EXT-003); two
	// signatures, the fee's witness count (SPO-11a-INV-003).
	prep, err := pipe.Prepare(draft, []txflow.Slot{
		{Label: "policy", Key: polKey, Hash: polHash},
		{Label: "payment", Key: payer.key, Hash: payer.hash},
	}, txbuild.MintWitnesses)
	if err != nil {
		return Result{}, err
	}

	record := assets.RecordName(policyName, ref.Asset)
	in := txflow.Input{Draft: draft, Params: params, TTL: ttl, Prepared: prep, Witnesses: txbuild.MintWitnesses,
		Summary: ports.TxSummary{Kind: "asset " + verb, Source: payer.name, SourceAddr: payer.addr, Destination: payer.name, DestAddr: payer.addr,
			Amount: fmt.Sprintf("%s %s.%s", req.Amount, policyName, ref.Asset)},
		Queued: ports.QueuedTx{Type: map[bool]string{false: "Asset-Minting", true: "Asset-Burning"}[burn],
			FromName: payer.name, FromAddr: payer.addr, ToName: payer.name, ToAddr: payer.addr,
			Description: fmt.Sprintf("%s %s '%s' on '%s'", past, req.Amount, ref.Asset, payer.name)}}

	built, err := pipe.BuildCtx(ctx, in)
	if err != nil {
		return Result{}, err
	}
	skipped, err := pipe.Confirm(ctx, in, built)
	if err != nil {
		return Result{}, err
	}
	bal := built.Balanced
	sws, err := prep.Sign(ctx, bal.Body)
	if err != nil {
		return Result{}, err
	}
	var ws []txbuild.Witness
	for _, sw := range sws {
		if err := txbuild.VerifyWitness(bal.Body, sw.Witness, sw.Slot.Hash); err != nil {
			return Result{}, fmt.Errorf("witness for the %s key of %s: %w", sw.Slot.Key.Role, sw.Slot.Key.Identity, err)
		}
		ws = append(ws, sw.Witness)
	}

	// Hazard H9: upstream updates the record when the transaction is queued or
	// sent, before anything is known of the chain. The port keeps the update
	// as a pending record under the transaction's id, written before the
	// transaction leaves (a crash after the submit cannot lose it), and applies
	// it when the transaction is confirmed (spo tx settle, or the wait of this
	// command). A transaction that is refused leaves no pending record; one
	// whose outcome is unknown keeps it, because it may be in a block.
	action := fmt.Sprintf("%s %d", verb, amount)
	if b.Queue != nil {
		action += " (only Offline proof)"
	}
	ttlv := ttl
	now := b.Clock.Now()
	p := assets.Pending{Kind: assets.PendingAsset, TxID: bal.Body.ID.String(), ValidUntil: &ttlv, Queued: b.Queue != nil,
		Date: now.Format(time.RFC3339Nano), Record: record, Policy: hex.EncodeToString(asset.Policy[:]),
		NameHex: hex.EncodeToString(asset.Name), HexTyped: name.HexTyped, Delta: fmt.Sprint(signed),
		ValidBefore: assets.ValidBefore(expiry, limited), Action: action}
	pb, err := p.Marshal()
	if err != nil {
		return Result{}, err
	}
	pending := ports.NamedRef{Name: bal.Body.ID.String(), Kind: ports.PendingUpdate}
	if err := b.Store.Update(ctx, func(w ports.NamedWriter) error { return w.Put(pending, pb) }); err != nil {
		return Result{}, fmt.Errorf("keep the asset record update until the transaction is confirmed: %w", err)
	}
	if b.Queue != nil {
		// The update also travels with the queue entry, so the machine that
		// submits it can report the outcome back across the air gap.
		var compact bytes.Buffer
		if err := json.Compact(&compact, pb); err != nil {
			return Result{}, err
		}
		in.Queued.Extra = append(in.Queued.Extra, ports.QueuedField{Key: transfer.KeyAssetPending, Value: compact.String()})
	}
	spec := bal.Spec
	res, err := pipe.Deliver(ctx, in, bal.Body, &spec, ws, skipped)
	if err != nil {
		if b.Queue == nil && errors.Is(err, chain.ErrSubmitOutcomeUnknown) {
			return Result{}, fmt.Errorf("%w\nThe update of the asset record %s stays pending under transaction %s: spo tx settle applies it once the transaction is confirmed, and drops it when it has expired", err, record, bal.Body.ID)
		}
		_ = b.Store.Update(ctx, func(w ports.NamedWriter) error { return w.Delete(pending) })
		return Result{}, err
	}
	return Result{Result: res, PolicyID: idHex, Record: record, Expiry: expiry, Limited: limited, RecordPending: true}, nil
}
