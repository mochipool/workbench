// Package wallet holds the use cases of payment accounts: sending
// lovelace, and later assets and rewards. They share the transaction
// pipeline of the txbuild kernel (spec/upstream/patterns/Ptx.md).
package wallet

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of SendLovelaces. Every failure is a returned error: where
// upstream exits 0 after a failed query, a failed submission or a refused
// minimum value (hazard H3), the port returns an error.
var (
	// ErrNoSourceAddress: the paying address file does not exist.
	ErrNoSourceAddress = errors.New("the source has no address file (.addr)")
	// ErrNoSigningKey: neither a signing key (.skey) nor a hardware
	// signing file (.hwsfile) exists for the source.
	ErrNoSigningKey = errors.New("the source has no signing key (.skey) or hardware signing file (.hwsfile)")
	// ErrBadDestination: the destination is not a stored address, a
	// payment address or an ADA Handle.
	ErrBadDestination = errors.New("the destination is not a stored address name, a payment address or an ADA Handle")
	// ErrAdaHandleUnsupported: no handle resolver is wired (SendLovelaces.Handles).
	ErrAdaHandleUnsupported = errors.New("ADA Handle destinations are not supported yet; give the address or the name of a stored address")
	// ErrNetworkMismatch: an address belongs to another network.
	ErrNetworkMismatch = errors.New("the address belongs to a different network")
	// ErrSourceNotKey: the paying address cannot be spent with a key witness.
	ErrSourceNotKey = errors.New("the source address does not use a payment key (a script or Byron address cannot be signed with a key file)")
	// ErrProtocolTooOld: the minimum output rule of protocol versions
	// before 7 is not implemented.
	ErrProtocolTooOld = errors.New("the protocol version is older than 7: the older minimum output rule is not implemented")
	// ErrNoSigner: the signer for the paying key cannot witness transactions.
	ErrNoSigner = errors.New("the signer for the paying key cannot witness transactions")
	// ErrNoConfirmer: confirmation is required and no Confirmer is wired.
	ErrNoConfirmer = errors.New("the transaction needs confirmation and no confirmer is configured; set the approval policy explicitly to skip it")
	// ErrDeclined: the operator did not approve. Nothing was signed,
	// submitted or queued. Upstream ends with exit 0 here; the caller of
	// the use case decides what a decline means to its own caller.
	ErrDeclined = errors.New("the transaction was not approved")
	// ErrMisconfigured: the composition is wrong (a programming error).
	ErrMisconfigured = errors.New("send lovelaces is not wired correctly")
)

// ApprovalPolicy says how the final confirmation is obtained. Skipping it
// is explicit and recorded in the result; it is never the default of a
// non-interactive caller (SPO-Ptx-SEC-003).
type ApprovalPolicy int

const (
	// ApprovalAsk asks the Confirmer. It is the zero value.
	ApprovalAsk ApprovalPolicy = iota
	// ApprovalSkip proceeds without asking: the audited replacement of
	// upstream's ENV_SKIP_PROMPT=YES.
	ApprovalSkip
)

// SendLovelaces builds, signs and sends a payment from one paying address
// to a destination (upstream 01_sendLovelaces). There is one workflow: the
// composition decides whether the signed transaction is submitted or
// queued for an online machine, and which signer holds the paying key.
type SendLovelaces struct {
	Store     ports.Store
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

	// Exactly one of Submitter and Queue is set: online and light
	// compositions submit, the offline composition queues.
	Submitter ports.TxSubmitter
	Queue     ports.TxQueue

	// NetworkID is the network the addresses must belong to
	// (ports.NetworkTestnet or ports.NetworkMainnet).
	NetworkID uint8
	Approval  ApprovalPolicy
	// DefTTL is the number of slots of validity; zero means the default.
	DefTTL uint64
	// Selection chooses the inputs; empty means SelectAll.
	Selection txbuild.SelectionStrategy
	// Files and Encrypter are needed only by a request with Extras that name
	// metadata files or ask for message encryption.
	Files     ports.MetadataFileReader
	Encrypter ports.MessageEncrypter
	// Canonicalizer brings the body to the form a hardware wallet accepts. It is
	// needed exactly when the paying key is held by a hardware wallet; nil with
	// a hardware payer refuses upfront (txflow.ErrNoCanonicalizer). Handles
	// resolves an ADA Handle destination (Caddr/resolveAdahandle); nil keeps the
	// refusal of ErrAdaHandleUnsupported.
	Canonicalizer ports.HardwareCanonicalizer
	Handles       HandleResolver
}

// SendRequest is one payment. Source and Destination are as the operator
// typed them.
type SendRequest struct {
	Source      string
	Destination string
	Amount      string // ALL, ALLFUNDS, MIN or lovelace
	// Message holds CIP-20 lines (the pieces of `msg:`), at most 64 bytes each.
	Message []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForSendLovelaces): further messages, encryption, metadata
	// files and the UTxO filters. Optional.
	Extras *txparam.Extras
	// Passphrase is the `pass:` passphrase of Extras, for `enc:basic`; nil
	// means the default. The caller owns it and destroys it.
	Passphrase *ports.Secret
	// CoSign adds a second signature to the payment (13b's pool cold key): its
	// witness is made and verified like the payment's and counted in the fee.
	// Optional.
	CoSign *CoSigner
	// ExtraFiles are metadata files the caller already holds in memory (13b's
	// poll answer from 13a); they follow the files of Extras.
	ExtraFiles []txbuild.MetadataFile
}

// CoSigner is a second signature of a payment.
type CoSigner struct {
	Label string
	Key   custody.KeyRef
	// Hash is the key hash the witness must prove.
	Hash txbuild.KeyHash
	// RequiredSigner lists Hash in the body's required signers (body key 14,
	// `--required-signer-hash`).
	RequiredSigner bool
}

// SendResult is what happened. Nothing in it is secret.
type SendResult struct {
	TxID      chain.TxID
	Fee       chain.Lovelace
	TTL       uint64
	Outputs   []txbuild.Output
	Inputs    int
	Size      int // size of the signed transaction in bytes
	SignedTx  []byte
	Submitted bool // sent to the chain
	Queued    bool // appended to the offline queue
	// ApprovalSkipped is true when the confirmation was skipped by policy.
	ApprovalSkipped bool
	Destination     string // the name or address the money was sent to; for an ADA Handle, the handle
	// Handle is set when the destination was an ADA Handle: the handle and the
	// address it resolved to, both (ADR 0006). The same two are in the
	// confirmation summary (Destination and DestAddr) and the queue entry.
	Handle *HandleDestination
	// MetadataFiles names the user metadata files attached.
	MetadataFiles []string
	// Encrypted is true when the message lines are CIP-83 encrypted.
	Encrypted bool
}

var (
	handleRoot = regexp.MustCompile(`^\$[a-z0-9_.-]{1,15}$`)
	handleSub  = regexp.MustCompile(`^\$[a-z0-9_.-]{1,15}@[a-z0-9_.-]{1,15}$`)
)

// normalizeName applies SPO-Pfiles-IN-001: a leading `./` and the `.addr`
// extension are dropped. A directory part cannot name an artefact in the
// store (a name is a plain label, hazard H7) and is refused.
//
// spec: SPO-Pfiles-IN-001
func normalizeName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("%w: %q", ErrBadDestination, s)
	}
	return s, nil
}

// resolved is an address with the name it is known by.
type resolved struct {
	name string
	addr chain.Address
	// pendingHandle is an ADA Handle destination not yet resolved; handle is
	// the verified resolution (the name is then the handle).
	pendingHandle string
	handle        *HandleDestination
}

func readAddress(r ports.Reader, name string) (chain.Address, bool, error) {
	ref := ports.Ref{Name: name, Kind: ports.AddrFile}
	if err := ref.Validate(); err != nil {
		return "", false, nil // not a stored name
	}
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	// SPO-Pfiles-OUT-001: the first line is the address.
	line, _, _ := strings.Cut(string(b), "\n")
	return chain.Address(strings.TrimSpace(line)), true, nil
}

// Run performs the payment.
func (uc SendLovelaces) Run(ctx context.Context, req SendRequest) (SendResult, error) {
	if (uc.Submitter == nil) == (uc.Queue == nil) {
		return SendResult{}, fmt.Errorf("%w: exactly one of Submitter and Queue must be set", ErrMisconfigured)
	}

	// Stage 1: prepare. The amount and the message are checked before any
	// file or network access.
	//
	// spec: SPO-01sendLovelaces-IF-001, SPO-01sendLovelaces-IF-002, SPO-Ptx-IF-002
	if req.Source == "" || req.Destination == "" || req.Amount == "" {
		return SendResult{}, errors.New("a payment needs a source, a destination and an amount")
	}
	amount, err := txbuild.ParseAmount(req.Amount)
	if err != nil {
		return SendResult{}, err
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return SendResult{}, err
	}
	// The extra parameters are resolved before any file or network access:
	// the metadata files are read, the message is encrypted.
	//
	// spec: SPO-01sendLovelaces-IF-003, SPO-Pparam-IF-010, SPO-Pparam-IF-016
	meta, err := txflow.ResolveExtras(txflow.ExtrasPorts{Files: uc.Files, Encrypter: uc.Encrypter}, req.Extras, req.Message, req.Passphrase)
	if err != nil {
		return SendResult{}, err
	}

	meta.Files = append(meta.Files, req.ExtraFiles...)

	srcName, err := normalizeName(req.Source)
	if err != nil {
		return SendResult{}, fmt.Errorf("source: %w", err)
	}
	var src, dst resolved
	var holder custody.Holder
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		// spec: SPO-Ptx-IN-001, SPO-Ptx-IN-002, SPO-01sendLovelaces-IN-001, SPO-Pfiles-INV-002
		addr, ok, err := readAddress(r, srcName)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: %s.addr", ErrNoSourceAddress, srcName)
		}
		src = resolved{name: srcName, addr: addr}
		skey, err := r.Exists(ports.Ref{Name: srcName, Kind: ports.AddrSKey})
		if err != nil {
			return err
		}
		hws, err := r.Exists(ports.Ref{Name: srcName, Kind: ports.AddrHwsFile})
		if err != nil {
			return err
		}
		switch {
		case hws: // the hardware file wins when both exist (SPO-Pfiles-INV-002)
			holder = custody.HolderHardware
		case skey:
			holder = custody.HolderVault
		default:
			return fmt.Errorf("%w: %s", ErrNoSigningKey, srcName)
		}
		dst, err = uc.resolveDestination(r, req.Destination)
		return err
	}); err != nil {
		return SendResult{}, err
	}
	// An ADA Handle is resolved outside the store view (it asks the network) and
	// shown as the handle and the address it resolved to.
	if dst, err = resolveHandle(ctx, uc.Handles, dst); err != nil {
		return SendResult{}, err
	}

	// spec: SPO-01sendLovelaces-IF-008, SPO-Caddr-PRE-001
	srcInfo, err := uc.Addresses.InspectAddress(src.addr)
	if err != nil {
		return SendResult{}, fmt.Errorf("source address: %w", err)
	}
	if !srcInfo.Kind.IsPayment() || srcInfo.PaymentKeyHash == nil {
		return SendResult{}, fmt.Errorf("%w: %s", ErrSourceNotKey, src.name)
	}
	if srcInfo.NetworkID != uc.NetworkID {
		return SendResult{}, fmt.Errorf("%w: the source %s", ErrNetworkMismatch, src.name)
	}
	dstInfo, err := uc.Addresses.InspectAddress(dst.addr)
	if err != nil {
		return SendResult{}, fmt.Errorf("destination address: %w", err)
	}
	if !dstInfo.Kind.IsPayment() {
		return SendResult{}, fmt.Errorf("%w: %s is a %s address", ErrBadDestination, dst.name, dstInfo.Kind)
	}
	if dstInfo.NetworkID != uc.NetworkID {
		return SendResult{}, fmt.Errorf("%w: the destination %s", ErrNetworkMismatch, dst.name)
	}

	// Stages 2, 3, 5: clock, inputs, parameters. A failing query is an
	// error, not an exit 0 (hazard H3).
	//
	// spec: SPO-Ptx-MODE-001, SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-004, SPO-Ptx-MODE-006,
	// spec: SPO-01sendLovelaces-PRE-001
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return SendResult{}, fmt.Errorf("current slot: %w", err)
	}
	ttl, err := txbuild.TTL(tip, uc.DefTTL)
	if err != nil {
		return SendResult{}, err
	}
	utxos, err := uc.Utxos.Utxos(ctx, src.addr)
	if err != nil {
		return SendResult{}, fmt.Errorf("the UTxOs of %s: %w", src.name, err)
	}
	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return SendResult{}, fmt.Errorf("protocol parameters: %w", err)
	}
	if params.ProtocolMajor < 7 {
		return SendResult{}, ErrProtocolTooOld
	}

	// Stage 3 and 4: every UTxO is spent; totals and assets follow from
	// the draft.
	strategy := uc.Selection
	if strategy == "" {
		strategy = txbuild.SelectAll
	}
	// The filters of the extra parameters narrow the candidates in every
	// work mode; the strategy then chooses among them (hazard H4).
	//
	// spec: SPO-01sendLovelaces-MODE-002, SPO-Pparam-IF-019, SPO-Pparam-IF-020, SPO-Pparam-IF-022
	inputs, err := strategy.Select(txflow.FilterCandidates(req.Extras, utxos))
	if err != nil {
		return SendResult{}, fmt.Errorf("%s: %w", src.name, err)
	}
	draft, err := txbuild.NewDraft(src.addr, dst.addr, amount, inputs, nil)
	if err != nil {
		return SendResult{}, err
	}
	if draft, err = meta.Attach(draft); err != nil {
		return SendResult{}, err
	}
	if req.CoSign != nil && req.CoSign.RequiredSigner {
		draft.RequiredSigners = []txbuild.KeyHash{req.CoSign.Hash}
	}

	// The signing plan is made from the draft's features before the body is
	// finalised, shown or confirmed (ADR 0008).
	feats, err := draft.Features()
	if err != nil {
		return SendResult{}, err
	}
	keyRef := custody.KeyRef{Role: custody.RolePayment, Holder: holder, Owner: src.name}
	slots := []custody.Slot{{
		Label:  "payment",
		Key:    keyRef,
		Demand: custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx, Features: feats},
	}}
	// witnessHash is the key hash each planned witness must prove.
	witnessHash := map[custody.KeyRef]txbuild.KeyHash{keyRef: *srcInfo.PaymentKeyHash}
	nWit := txbuild.SendWitnesses
	if req.CoSign != nil {
		// A second signature, whose key hash 13b lists in the body's required
		// signers: the fee counts its witness (SPO-13b-INV-001).
		slots = append(slots, custody.Slot{Label: req.CoSign.Label, Key: req.CoSign.Key,
			Demand: custody.Demand{Role: req.CoSign.Key.Role, Operation: custody.OpWitnessTx, Features: feats}})
		witnessHash[req.CoSign.Key] = req.CoSign.Hash
		nWit++
	}
	plan, err := ports.PlanSignatures(uc.Signers, slots)
	if err != nil {
		return SendResult{}, err
	}
	witnessers := map[custody.KeyRef]ports.TxWitnesser{}
	hardware := false
	for _, sl := range plan.Slots() {
		signer, err := uc.Signers.SignerFor(sl.Key)
		if err != nil {
			return SendResult{}, err
		}
		wt, ok := signer.(ports.TxWitnesser)
		if !ok {
			return SendResult{}, ErrNoSigner
		}
		witnessers[sl.Key] = wt
		hardware = hardware || sl.Key.Holder == custody.HolderHardware
	}
	if hardware && uc.Canonicalizer == nil {
		return SendResult{}, txflow.ErrNoCanonicalizer
	}
	if uint(len(plan.Slots())) != nWit {
		return SendResult{}, fmt.Errorf("%w: the plan has %d signatures, the fee is estimated for %d", ErrMisconfigured, len(plan.Slots()), nWit)
	}

	// Stages 6 to 8: fee, balance, the one body. Nothing below changes it.
	//
	// spec: SPO-Ptx-INV-010
	//
	// A hardware wallet accepts one body form. Every body of the fee loop is
	// brought to it, before the body is shown, confirmed or signed: the fee is
	// estimated for it and its id is the id displayed and witnessed
	// (SPO-Xparty-INV-012, SPO-Ctx-EXT-001, SPO-Ptx-EXT-005).
	build := uc.Bodies.BuildBody
	if hardware {
		build = txflow.CanonicalBodies(ctx, uc.Canonicalizer, build, ports.HardwareTxOptions{})
	}
	bal, err := draft.Balance(ttl, txbuild.Ledger{
		MinOutput: func(o txbuild.Output) (chain.Lovelace, error) { return uc.Min.MinOutput(params, o) },
		Fee: func(b txbuild.TxBody) (chain.Lovelace, error) {
			return uc.Fees.EstimateFee(params, b, nWit)
		},
		Build: build,
	})
	if err != nil {
		return SendResult{}, err
	}

	// Stage 10, first look: refuse an oversize transaction before the
	// operator is asked.
	est, err := uc.Fees.EstimateSize(bal.Body, nWit)
	if err != nil {
		return SendResult{}, err
	}
	if err := txbuild.CheckSize(est, params.MaxTxSize); err != nil {
		return SendResult{}, err
	}

	// Stage 11: confirm.
	route := "submit"
	if uc.Queue != nil {
		route = "queue"
	}
	skipped := false
	switch uc.Approval {
	case ApprovalSkip:
		skipped = true
	case ApprovalAsk:
		if uc.Confirmer == nil {
			return SendResult{}, ErrNoConfirmer
		}
		yes, err := uc.Confirmer.Confirm(ctx, ports.TxSummary{
			Kind: "payment", Source: src.name, SourceAddr: src.addr, Destination: dst.name, DestAddr: dst.addr,
			Amount: amount.String(), Inputs: len(bal.Spec.Inputs), Outputs: bal.Spec.Outputs, Fee: bal.Spec.Fee,
			TTL: bal.Spec.TTL, Message: bal.Spec.Message, Size: est, TxID: bal.Body.ID, Route: route,
		})
		if err != nil {
			return SendResult{}, fmt.Errorf("confirmation: %w", err)
		}
		if !yes {
			return SendResult{}, ErrDeclined
		}
	default:
		return SendResult{}, fmt.Errorf("%w: unknown approval policy %d", ErrMisconfigured, uc.Approval)
	}

	// Stage 9: witnesses from the planned signers, each checked against
	// the body and the key the address names before anything is assembled.
	var witnesses []txbuild.Witness
	for _, slot := range plan.Slots() {
		var w txbuild.Witness
		var err error
		witnesser := witnessers[slot.Key]
		if hw, isHW := witnesser.(ports.HardwareWitnesser); isHW && slot.Key.Holder == custody.HolderHardware {
			// The change keys let the device recognise the change output when the
			// body has two outputs (SPO-01sendLovelaces-EXT-002).
			var change []custody.KeyRef
			if len(bal.Spec.Outputs) == 2 {
				change = hardwareChangeKeys(ctx, uc.Store, slot.Key)
			}
			w, err = hw.WitnessWith(ctx, slot.Key, bal.Body, ports.HardwareTxOptions{ChangeKeys: change})
		} else {
			w, err = witnesser.Witness(ctx, slot.Key, bal.Body)
		}
		if err != nil {
			return SendResult{}, fmt.Errorf("witness for the %s key of %s: %w", slot.Key.Role, slot.Key.Owner, err)
		}
		if err := txbuild.VerifyWitness(bal.Body, w, witnessHash[slot.Key]); err != nil {
			return SendResult{}, fmt.Errorf("witness for the %s key of %s: %w", slot.Key.Role, slot.Key.Owner, err)
		}
		witnesses = append(witnesses, w)
	}
	signed, err := uc.Assembler.Assemble(bal.Body, witnesses)
	if err != nil {
		return SendResult{}, err
	}
	if signed.ID != bal.Body.ID {
		return SendResult{}, errors.New("the assembled transaction has a different id from the confirmed body")
	}
	if err := txbuild.CheckSize(len(signed.CBOR), params.MaxTxSize); err != nil {
		return SendResult{}, err
	}

	// Stage 12: submit or queue exactly what was confirmed.
	res := SendResult{TxID: signed.ID, Fee: bal.Spec.Fee, TTL: bal.Spec.TTL, Outputs: bal.Spec.Outputs,
		Inputs: len(bal.Spec.Inputs), Size: len(signed.CBOR), SignedTx: signed.CBOR, ApprovalSkipped: skipped,
		Destination: dst.name, Handle: dst.handle, Encrypted: meta.Encryption != ""}
	for _, f := range meta.Files {
		res.MetadataFiles = append(res.MetadataFiles, f.Name)
	}
	if uc.Queue != nil {
		toName := dst.name
		if err := uc.Queue.Enqueue(ctx, ports.QueuedTx{Type: "Transaction", FromName: src.name, FromAddr: src.addr,
			ToName: toName, ToAddr: dst.addr, Tx: signed,
			Description: fmt.Sprintf("signed utxo-transaction from '%s' to '%s'", src.name, toName)}); err != nil {
			return SendResult{}, fmt.Errorf("queue the transaction: %w", err)
		}
		res.Queued = true
		return res, nil
	}
	id, err := uc.Submitter.Submit(ctx, signed.CBOR)
	if err != nil {
		return SendResult{}, fmt.Errorf("submit: %w", err)
	}
	if id != signed.ID {
		return SendResult{}, &chain.IDMismatchError{Answered: id, Local: signed.ID}
	}
	res.Submitted = true
	return res, nil
}

// resolveDestination tries the three forms in order and the first match
// wins: a stored address name, a literal payment address, an ADA Handle.
//
// spec: SPO-01sendLovelaces-IF-004, SPO-01sendLovelaces-IF-005, SPO-01sendLovelaces-IF-006,
// spec: SPO-01sendLovelaces-IF-007, SPO-Pfiles-IN-002
func (uc SendLovelaces) resolveDestination(r ports.Reader, word string) (resolved, error) {
	if name, err := normalizeName(word); err == nil {
		addr, ok, err := readAddress(r, name)
		if err != nil {
			return resolved{}, err
		}
		if ok {
			return resolved{name: name, addr: addr}, nil
		}
	}
	lit := strings.TrimSpace(word)
	if info, err := uc.Addresses.InspectAddress(chain.Address(lit)); err == nil {
		if !info.Kind.IsPayment() {
			return resolved{}, fmt.Errorf("%w: %s is a %s address, not a payment address", ErrBadDestination, lit, info.Kind)
		}
		// A literal is kept in memory and never routed through a file
		// (SPO-01sendLovelaces-SEC-001); the queue entry names it by its
		// address.
		return resolved{name: lit, addr: chain.Address(lit)}, nil
	}
	if h := strings.ToLower(lit); handleRoot.MatchString(h) || handleSub.MatchString(h) {
		if uc.Handles == nil {
			return resolved{}, fmt.Errorf("%w: %s", ErrAdaHandleUnsupported, h)
		}
		return resolved{name: h, pendingHandle: h}, nil
	}
	return resolved{}, fmt.Errorf("%w: %q", ErrBadDestination, word)
}
