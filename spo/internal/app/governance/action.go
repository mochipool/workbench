package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the action use cases.
var (
	// ErrReturnNotRegistered: the deposit-return stake address is not registered.
	ErrReturnNotRegistered = errors.New("the deposit-return stake address is not registered on chain: register it first")
	// ErrNeedsKeyCredential: an action whose deposit-return or receiving credential is a script.
	ErrNeedsKeyCredential = errors.New("the credential is a script hash: only key credentials are supported")
	// ErrActionFile: an action file the transaction cannot carry.
	ErrActionFile = errors.New("invalid action file")
	// ErrHardwarePayer: a hardware wallet cannot pay for a governance action proposal.
	ErrHardwarePayer = errors.New("a hardware wallet cannot pay for or sign a governance action proposal")
)

// ProposalTTL is the validity of a proposal transaction: tip + 25000 slots,
// the constant of upstream's 25b that replaces defTTL (SPO-25b-INV-003).
const ProposalTTL uint64 = 25000

// stakeCredential reads a stake address (bech32): the network and the credential.
func stakeCredential(a string) (governance.Credential, uint8, error) {
	hrp, data, err := chain.Bech32Decode(a)
	if err != nil {
		return governance.Credential{}, 0, fmt.Errorf("%q is not a bech32 stake address: %w", a, err)
	}
	if (hrp != "stake" && hrp != "stake_test") || len(data) != 29 || data[0]>>4 < 0xe {
		return governance.Credential{}, 0, fmt.Errorf("%q is not a stake address", a)
	}
	c := governance.Credential{Script: data[0]>>4 == 0xf}
	copy(c.Hash[:], data[1:])
	return c, data[0] & 0xf, nil
}

// ---- 25a --------------------------------------------------------------------------------

// GenerateAction makes a governance action file (upstream 25a): one of the
// seven kinds, with the deposit-return stake address, the anchor and the
// previous action id of its purpose. The deposit is always the chain's current
// `govActionDeposit` (SPO-25a-INV-003).
//
// An action that needs the guardrails script gets its file with the script hash
// from the constitution: the script is a witness of the transaction that
// proposes it (RegisterAction).
type GenerateAction struct {
	Store   ports.Store
	Actions ports.ActionFileBuilder
	Params  ports.ProtocolParametersReader
	Epoch   ports.EpochReader
	// Constitution and LastEnacted are the chain readers of the guardrails
	// script hash and of the previous-action ids. Each is required only by the
	// kinds that need it: LastEnacted by the kinds with a previous-action
	// purpose, Constitution by treasury withdrawals and parameter changes, and
	// Epoch by the committee update. An info action needs no chain reader at
	// all (the parameters may come from a snapshot).
	Constitution ports.ConstitutionReader
	LastEnacted  ports.LastEnactedReader
	Clock        ports.Clock
	Anchors      AnchorSource
	// Verifier checks the CIP-100/108 anchor document. Optional by policy: when
	// the anchor document was fetched and no verifier is wired, the run is
	// refused unless AnchorUnverifiedAcknowledged (SPO-25a-EXT-003).
	Verifier                     ports.AnchorVerifier
	AnchorUnverifiedAcknowledged bool
	// NetworkID: the network the stake addresses must belong to.
	NetworkID uint8
}

// GenerateActionRequest names the deposit-return account as typed (a stake
// account name with `.staking.addr`, or a literal `stake...` address) and the
// action. Which fields apply depends on Kind; the others must be empty.
type GenerateActionRequest struct {
	Return string
	Kind   governance.ActionKind
	// URL and Hash are the anchor words; URL is required.
	URL, Hash string
	// TreasuryWithdrawals: Amount and the receiving stake address (default: the return address).
	Amount lovelace
	Addr   string
	// HardForkInitiation.
	Version governance.Version
	// UpdateCommittee: the threshold as written, `add-hash`, `add-script`,
	// `rem-hash`, `rem-script` as 56-digit hashes and the term end epoch (0: the
	// current epoch plus committeeMaxTermLength).
	Threshold           string
	AddKeys, AddScripts []string
	RemKeys, RemScripts []string
	Epoch               uint64
	// NewConstitution: the document URL and hash.
	ConstitutionURL, ConstitutionHash string
	// ParameterChange: the parameters, name and value as typed.
	Params []governance.ParamChange
	// AllowCostModelLengthChange lets a cost model have another number of values
	// than the current one in the provider's parameters.
	AllowCostModelLengthChange bool
}

type lovelace = chain.Lovelace

// ActionGenerated is the result.
type ActionGenerated struct {
	Ref    ports.Ref
	Action governance.Action
	// Decisions records what shaped the file: a replaced hash, an unverified anchor.
	Decisions []string
	// NeedsGuardrails: the kind needs the guardrails script when it is proposed.
	NeedsGuardrails bool
	// ParamDiffs lists every parameter of a ParameterChange with its new value
	// and, when the parameters document of the source gives it, the old one.
	ParamDiffs []governance.ParamDiff
}

// Run validates, builds and stores the action file.
//
// spec: SPO-25a-IF-001, SPO-25a-IF-002, SPO-25a-IF-003, SPO-25a-IF-004, SPO-25a-IF-005, SPO-25a-IF-006, SPO-25a-IF-007, SPO-25a-IF-009, SPO-25a-IF-010,
// spec: SPO-25a-IF-012, SPO-25a-IF-013, SPO-25a-IF-014, SPO-25a-IF-015, SPO-25a-IF-016, SPO-25a-IF-018, SPO-25a-IF-019, SPO-25a-IF-020,
// spec: SPO-25a-IN-001, SPO-25a-IN-002, SPO-25a-PRE-002, SPO-25a-PRE-003, SPO-25a-PRE-004, SPO-25a-PRE-005, SPO-25a-PRE-006, SPO-25a-PRE-007,
// spec: SPO-25a-PRE-008, SPO-25a-PRE-009, SPO-25a-PRE-010, SPO-25a-PRE-011, SPO-25a-PRE-012, SPO-25a-PRE-013, SPO-25a-PRE-014, SPO-25a-PRE-015,
// spec: SPO-25a-PRE-016, SPO-25a-PRE-017, SPO-25a-PRE-018, SPO-25a-PRE-019, SPO-25a-EXT-001, SPO-25a-EXT-002, SPO-25a-EXT-003, SPO-25a-EXT-004,
// spec: SPO-25a-EXT-005, SPO-25a-EXT-006, SPO-25a-EXT-007, SPO-25a-EXT-008, SPO-25a-EXT-009, SPO-25a-EXT-010, SPO-25a-EXT-011, SPO-25a-EXT-012,
// spec: SPO-25a-INV-001, SPO-25a-INV-002, SPO-25a-INV-003, SPO-25a-INV-004, SPO-25a-OUT-001, SPO-25a-OUT-002, SPO-25a-OUT-003, SPO-25a-OUT-004,
// spec: SPO-25a-OUT-006, SPO-25a-MODE-001, SPO-25a-MODE-004, SPO-25a-MODE-005, SPO-25a-SEC-001, SPO-Pfiles-OUT-030
func (uc GenerateAction) Run(ctx context.Context, req GenerateActionRequest) (ActionGenerated, error) {
	var res ActionGenerated
	if req.Return == "" || !req.Kind.Valid() {
		return res, fmt.Errorf("an action needs a deposit-return stake account and one of the seven kinds: %w", governance.ErrActionKind)
	}
	if uc.Params == nil || uc.Clock == nil {
		return res, fmt.Errorf("%w: the parameter reader and a clock are needed", ErrMisconfigured)
	}
	// The readers the kind needs are checked before anything is read or written.
	if _, ok := governance.PurposeOf(req.Kind); ok && uc.LastEnacted == nil {
		return res, fmt.Errorf("the last enacted action of a %s: %w", req.Kind, ErrNoChainReader)
	}
	if (req.Kind == governance.TreasuryWithdrawals || req.Kind == governance.ParameterChange) && uc.Constitution == nil {
		return res, fmt.Errorf("the constitution's guardrails script of a %s: %w", req.Kind, ErrNoChainReader)
	}
	if req.Kind == governance.UpdateCommittee && uc.Epoch == nil {
		return res, fmt.Errorf("the current epoch of the committee terms: %w", ErrNoChainReader)
	}
	// The deposit-return address (SPO-25a-IF-003).
	var addr, prefix string
	if rest, ok := strings.CutPrefix(strings.ToLower(req.Return), "stake"); ok && (strings.HasPrefix(rest, "1") || strings.HasPrefix(rest, "_test1")) {
		addr, prefix = strings.ToLower(req.Return), strings.ToLower(string(req.Kind))
	} else {
		nm := strings.TrimSuffix(strings.TrimSuffix(trimDir(req.Return), ".addr"), ".staking")
		if _, err := name(nm); err != nil {
			return res, fmt.Errorf("deposit-return account: %w", err)
		}
		if err := uc.Store.View(ctx, func(r ports.Reader) error {
			b, err := get(r, ports.Ref{Name: nm, Kind: ports.StakingAddr})
			addr = firstLine(b)
			return err
		}); err != nil {
			return res, fmt.Errorf("the deposit-return account %q is neither a stake address nor a stored stake account: %w", req.Return, err)
		}
		prefix = nm + "_" + strings.ToLower(string(req.Kind))
	}
	retKey, net, err := stakeCredential(addr)
	if err != nil {
		return res, fmt.Errorf("deposit return: %w", err)
	}
	if net != uc.NetworkID {
		return res, fmt.Errorf("%w: the deposit-return address", ErrNetworkMismatch)
	}

	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return res, fmt.Errorf("protocol parameters: %w", err)
	}
	if err := governance.CheckProposable(req.Kind, params.ProtocolMajor); err != nil {
		return res, err
	}
	if params.GovActionDeposit == 0 {
		return res, errors.New("the protocol parameters carry no govActionDeposit")
	}

	// The anchor.
	if req.URL == "" {
		return res, fmt.Errorf("an action needs an anchor: %w", governance.ErrAnchorPair)
	}
	anchor, err := uc.Anchors.Resolve(ctx, req.URL, req.Hash)
	if err != nil {
		return res, err
	}
	if anchor.GivenHashDiffered {
		res.Decisions = append(res.Decisions, "the given anchor hash differed from the document's and was replaced")
	}
	if anchor.Fetched {
		if _, dec, err := verifyAnchor(ctx, uc.Verifier, uc.AnchorUnverifiedAcknowledged, ports.AnchorCIP108, anchor.Doc); err != nil {
			return res, err
		} else if dec != "" {
			res.Decisions = append(res.Decisions, dec)
		}
	}

	a := governance.Action{Kind: req.Kind, Deposit: params.GovActionDeposit, Return: chain.StakeAddress(addr), ReturnKey: retKey, Anchor: anchor.Anchor}
	if err := uc.kindFields(ctx, &a, req, params, &res); err != nil {
		return res, err
	}
	// The previous action of the purpose (SPO-25a-INV-004).
	if p, ok := governance.PurposeOf(req.Kind); ok {
		rd, err := uc.LastEnacted.LastEnacted(ctx, p)
		if err != nil {
			return res, fmt.Errorf("the last enacted %s action from %s: %w", p, uc.LastEnacted.Source(), err)
		}
		switch {
		case rd.IsUnknown():
			return res, fmt.Errorf("%w: the last enacted %s action: %s", ErrUnverified, p, rd.Why())
		case !rd.IsNone():
			id, _ := rd.Get()
			a.Prev = &id
		}
	}
	// The guardrails script hash for the kinds that must carry it.
	if req.Kind == governance.TreasuryWithdrawals || req.Kind == governance.ParameterChange {
		res.NeedsGuardrails = true
		cr, err := uc.Constitution.Constitution(ctx)
		if err != nil {
			return res, fmt.Errorf("the constitution from %s: %w", uc.Constitution.Source(), err)
		}
		if cr.IsUnknown() {
			return res, fmt.Errorf("%w: the constitution: %s", ErrUnverified, cr.Why())
		}
		if c, ok := cr.Get(); ok {
			a.Guardrails = c.Script
		}
	}
	if err := a.Validate(); err != nil {
		return res, err
	}
	af, err := uc.Actions.BuildActionFile(a)
	if err != nil {
		return res, err
	}
	// The file name: the first free second (SPO-25a-OUT-006 overwrites within one second).
	t := uc.Clock.Now()
	err = uc.Store.Update(ctx, func(w ports.Writer) error {
		for i := 0; i < 600; i++ {
			ref := ports.Ref{Name: prefix + "_" + t.Add(time.Duration(i)*time.Second).Format("060102150405"), Kind: ports.GovActionFile}
			ok, err := w.Exists(ref)
			if err != nil {
				return err
			}
			if !ok {
				res.Ref = ref
				return w.Put(ref, af.Envelope)
			}
		}
		return errors.New("no free action file name")
	})
	if err != nil {
		return ActionGenerated{}, err
	}
	res.Action = a
	return res, nil
}

// kindFields fills and checks the fields of the kind.
func (uc GenerateAction) kindFields(ctx context.Context, a *governance.Action, req GenerateActionRequest, params chain.ProtocolParameters, res *ActionGenerated) error {
	switch req.Kind {
	case governance.InfoAction, governance.NoConfidenceAction:
	case governance.TreasuryWithdrawals:
		if req.Amount == 0 {
			return fmt.Errorf("%w: a treasury withdrawal needs a non-zero amount", governance.ErrActionField)
		}
		recv := string(a.Return)
		if req.Addr != "" {
			recv = strings.TrimSpace(req.Addr)
		}
		key, net, err := stakeCredential(recv)
		if err != nil {
			return fmt.Errorf("receiving address: %w", err)
		}
		if net != uc.NetworkID {
			return fmt.Errorf("%w: the receiving address", ErrNetworkMismatch)
		}
		a.Withdrawals = []governance.Withdrawal{{Account: chain.StakeAddress(recv), Key: key, Amount: req.Amount}}
	case governance.HardForkInitiation:
		cur := governance.Version{Major: params.ProtocolMajor, Minor: params.ProtocolMinor}
		if req.Version == (governance.Version{}) {
			return fmt.Errorf("%w: a hard fork needs the target version", governance.ErrActionField)
		}
		if err := governance.CheckVersionStep(cur, req.Version); err != nil {
			return err
		}
		a.Version = req.Version
	case governance.NewConstitution:
		if req.ConstitutionURL == "" {
			return fmt.Errorf("%w: a new constitution needs its URL", governance.ErrActionField)
		}
		// The document is fetched and hashed as the anchor is, without the JSON check.
		url, err := governance.ParseAnchorURL(req.ConstitutionURL)
		if err != nil {
			return err
		}
		var h [32]byte
		if uc.Anchors.Fetcher != nil {
			doc, err := uc.Anchors.Fetcher.Fetch(ctx, governance.FetchURL(url, uc.Anchors.IPFSGateway))
			if err != nil {
				return fmt.Errorf("%w: %s: %v", ErrAnchorFetch, url, err)
			}
			h = governance.HashDocument(doc)
			if req.ConstitutionHash != "" {
				if given, gerr := governance.ParseHash32(req.ConstitutionHash); gerr != nil {
					return gerr
				} else if given != h {
					res.Decisions = append(res.Decisions, "the given constitution hash differed from the document's and was replaced")
				}
			}
		} else {
			if req.ConstitutionHash == "" {
				return fmt.Errorf("%w: the constitution document cannot be fetched here: give its hash", ErrAnchorNotChecked)
			}
			if h, err = governance.ParseHash32(req.ConstitutionHash); err != nil {
				return err
			}
		}
		a.Constitution = governance.Anchor{URL: url, Hash: h}
	case governance.UpdateCommittee:
		th, err := governance.ParseThreshold(req.Threshold)
		if err != nil {
			return err
		}
		a.Threshold = th
		epoch, err := uc.committeeEpoch(ctx, req, params)
		if err != nil {
			return err
		}
		add := func(hs []string, script bool) error {
			for _, h := range hs {
				b, err := governance.ParseHash28(h)
				if err != nil {
					return err
				}
				a.Add = append(a.Add, governance.CommitteeAdd{Cold: governance.Credential{Script: script, Hash: b}, Epoch: epoch})
			}
			return nil
		}
		rem := func(hs []string, script bool) error {
			for _, h := range hs {
				b, err := governance.ParseHash28(h)
				if err != nil {
					return err
				}
				a.Remove = append(a.Remove, governance.Credential{Script: script, Hash: b})
			}
			return nil
		}
		for _, f := range []func() error{
			func() error { return add(req.AddKeys, false) }, func() error { return add(req.AddScripts, true) },
			func() error { return rem(req.RemKeys, false) }, func() error { return rem(req.RemScripts, true) },
		} {
			if err := f(); err != nil {
				return err
			}
		}
	case governance.ParameterChange:
		// The set in canonical form (SPO-25a-IF-021 to SPO-25a-IF-023).
		set, err := governance.CheckParams(req.Params)
		if err != nil {
			return err
		}
		a.Params = set
		if !req.AllowCostModelLengthChange {
			if err := governance.CheckCostModelLengths(set, params.Raw); err != nil {
				return err
			}
		} else if note := costModelNote(set, params.Raw); note != "" {
			res.Decisions = append(res.Decisions, note)
		}
		res.ParamDiffs = governance.DescribeParams(set, params.Raw)
	}
	return nil
}

// committeeEpoch is the term end of the added members: `epoch:` when given
// (after the current epoch, at most committeeMaxTermLength beyond it), else the
// current epoch plus committeeMaxTermLength.
func (uc GenerateAction) committeeEpoch(ctx context.Context, req GenerateActionRequest, params chain.ProtocolParameters) (uint64, error) {
	cur, err := uc.Epoch.Epoch(ctx)
	if err != nil {
		return 0, fmt.Errorf("the current epoch: %w", err)
	}
	var doc struct {
		Max *uint64 `json:"committeeMaxTermLength"`
	}
	if len(params.Raw) > 0 {
		_ = json.Unmarshal(params.Raw, &doc)
	}
	if doc.Max == nil {
		return 0, errors.New("the protocol parameters carry no committeeMaxTermLength")
	}
	if req.Epoch != 0 {
		if err := governance.CheckTermEpoch(req.Epoch, cur, *doc.Max); err != nil {
			return 0, err
		}
		return req.Epoch, nil
	}
	return cur + *doc.Max, nil
}

// ---- 25b --------------------------------------------------------------------------------

// RegisterAction puts one or more governance action files on chain (upstream
// 25b): the proposal procedures and their deposits, paid from a payment
// address; the change is inputs - fee - the deposits. One witness: the payment
// key. The validity is tip + 25000 slots.
//
// A TreasuryWithdrawals or ParameterChange proposal must carry the
// constitution's guardrails Plutus script when the constitution names one: the
// script is a witness with a `proposing` redeemer, the payer sets aside a
// collateral UTxO, and the fee covers the script's execution units. This build
// runs no Plutus: Evaluator is a provider that does, and the command refuses
// before any prompt when none is wired (see guardrails.go). Upstream decides the
// variant from the last file only (SPO-25b-INV-006); here any such action
// takes this path.
type RegisterAction struct {
	Base
	Actions ports.ActionFileBuilder
	// Rewards checks that the deposit-return address is registered
	// (SPO-25b-PRE-007); nil or Unknown goes on only with AllowUnverified
	// (offline), and the check is listed in Result.Unchecked.
	Rewards         ports.RewardAccountReader
	AllowUnverified bool
	// Constitution reads the constitution's guardrails script hash and
	// Evaluator the execution units of the script: both are needed exactly when
	// a file is a treasury withdrawal or a parameter change. The script file is
	// read through Base.Files.
	Constitution ports.ConstitutionReader
	Evaluator    ports.TxEvaluator
}

// RegisterActionRequest names the paying address and the action files by name
// (`x_<ts>.action` with or without the extension).
type RegisterActionRequest struct {
	Payer   string
	Files   []string
	Message []string
	// Extras are the parsed extra parameters (txparam.Parse with
	// txparam.ForCertificate); Passphrase is the `pass:` of Extras. Optional.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
	// GuardrailsScript is the path of the constitution's guardrails script
	// (upstream's `guardrailsScriptFile`, SPO-25b-IN-004); empty means
	// DefaultGuardrailsScriptFile. It is read only when a proposal needs it.
	GuardrailsScript string
	// AllowCostModelLengthChange lets a parameter change give a cost model another
	// number of values than the current one.
	AllowCostModelLengthChange bool
}

// ActionRegistered is the result: the transaction and the ids the actions will have.
type ActionRegistered struct {
	Result
	// IDs are the action ids in file order: the transaction id and the index of
	// each proposal (SPO-25b-OUT-002), in the hex and CIP-129 forms.
	IDs []ActionIDs
	// Guardrails is set when the transaction carried the guardrails script.
	Guardrails *GuardrailReport
}

// ActionIDs are the two spellings of an action id.
type ActionIDs struct{ Hex, CIP129 string }

// Run registers the actions.
//
// spec: SPO-25b-IF-001, SPO-25b-IF-002, SPO-25b-IF-003, SPO-25b-IF-004, SPO-25b-IF-005, SPO-25b-IF-006, SPO-25b-IN-001, SPO-25b-IN-002, SPO-25b-IN-003,
// spec: SPO-25b-IN-004, SPO-25b-IN-005, SPO-25b-INV-005, SPO-25b-INV-007, SPO-25b-INV-008, SPO-25b-EXT-001, SPO-25b-EXT-002, SPO-25b-EXT-003, SPO-25b-EXT-004, SPO-25b-EXT-005,
// spec: SPO-25b-PRE-012, SPO-25b-PRE-013, SPO-25b-PRE-014, SPO-25b-INV-013, SPO-25b-INV-015, SPO-25b-INV-016, SPO-25b-INV-017, SPO-25b-SEC-001, SPO-25b-PRE-002, SPO-25b-PRE-003, SPO-25b-PRE-004, SPO-25b-PRE-005, SPO-25b-PRE-006, SPO-25b-PRE-007, SPO-25b-PRE-008,
// spec: SPO-25b-PRE-009, SPO-25b-PRE-010, SPO-25b-PRE-015, SPO-25b-INV-001, SPO-25b-INV-003, SPO-25b-INV-004, SPO-25b-INV-006, SPO-25b-EXT-006,
// spec: SPO-25b-EXT-007, SPO-25b-EXT-008, SPO-25b-EXT-009, SPO-25b-INV-009, SPO-25b-PR-001, SPO-25b-OUT-001, SPO-25b-OUT-002, SPO-25b-OUT-006
func (uc RegisterAction) Run(ctx context.Context, req RegisterActionRequest) (ActionRegistered, error) {
	var out ActionRegistered
	if req.Payer == "" {
		return out, errors.New("an action registration needs a paying address")
	}
	if len(req.Files) == 0 {
		return out, fmt.Errorf("%w: no action file given", ErrActionFile)
	}
	if err := txbuild.ValidateMessage(req.Message); err != nil {
		return out, err
	}
	pn, err := payerName(req.Payer)
	if err != nil {
		return out, fmt.Errorf("payer: %w", err)
	}
	var pay payer
	var props []txbuild.ProposalAttachment
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		var err error
		if pay, err = uc.readPayer(r, pn); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, f := range req.Files {
			nm := strings.TrimSuffix(trimDir(f), ".action")
			if nm == "" || strings.ContainsAny(nm, "/\\") {
				return fmt.Errorf("%w: %q", ErrActionFile, f)
			}
			if seen[nm] {
				return fmt.Errorf("%w: %s is given twice", ErrActionFile, f)
			}
			seen[nm] = true
			raw, err := get(r, ports.Ref{Name: nm, Kind: ports.GovActionFile})
			if err != nil {
				return err
			}
			af, err := uc.Actions.DecodeActionFile(raw)
			if err != nil {
				return fmt.Errorf("%s: %w: %v", f, ErrActionFile, err)
			}
			if af.Action.Deposit == 0 {
				return fmt.Errorf("%s: %w: the action has no deposit", f, ErrActionFile)
			}
			if af.Action.ReturnKey.Script {
				return fmt.Errorf("%s: deposit return: %w", f, ErrNeedsKeyCredential)
			}
			for _, w := range af.Action.Withdrawals {
				if w.Key.Script {
					return fmt.Errorf("%s: treasury withdrawal receiver: %w", f, ErrNeedsKeyCredential)
				}
			}
			props = append(props, txbuild.ProposalAttachment{Action: af.Action, CBOR: af.CBOR})
		}
		return nil
	}); err != nil {
		return out, err
	}
	// The deposit is paid by a key-file payer (the signer the directory
	// connects for the key decides, not a flag).
	if hwkeys.OnDevice(uc.Pipeline.Signers, pay.key) {
		return out, ErrHardwarePayer
	}
	run := txRun{payer: pay, props: props, message: req.Message, extras: req.Extras, pass: req.Passphrase, ttl: ProposalTTL}
	if err := uc.early(run); err != nil {
		return out, err
	}
	params, err := uc.params(ctx)
	if err != nil {
		return out, err
	}
	var lengthNotes []string
	for i, p := range props {
		if p.Action.Kind != governance.ParameterChange {
			continue
		}
		if !req.AllowCostModelLengthChange {
			if err := governance.CheckCostModelLengths(p.Action.Params, params.Raw); err != nil {
				return out, fmt.Errorf("proposal %d: %w", i+1, err)
			}
		} else if note := costModelNote(p.Action.Params, params.Raw); note != "" {
			lengthNotes = append(lengthNotes, fmt.Sprintf("proposal %d: %s", i+1, note))
		}
	}
	// The guardrails variant: the constitution, the script and the order of the
	// proposals are checked before anything else is read.
	run.plutus, err = uc.guardrails(ctx, props, params, req.GuardrailsScript)
	if err != nil {
		return out, err
	}
	if run.plutus != nil {
		if err := uc.early(run); err != nil {
			return out, err
		}
	}

	// The deposit-return stake address must be registered (online and light).
	unchecked := append([]string(nil), lengthNotes...)
	var sources []chain.Source
	seenRet := map[chain.StakeAddress]bool{}
	for _, p := range props {
		ra := p.Action.Return
		if seenRet[ra] {
			continue
		}
		seenRet[ra] = true
		switch {
		case uc.Rewards == nil:
			if !uc.AllowUnverified {
				return out, fmt.Errorf("the deposit-return address registration: %w", ErrNoChainReader)
			}
			unchecked = append(unchecked, "the registration of "+string(ra)+" was not checked: no chain reader in this mode")
		default:
			rd, err := uc.Rewards.RewardAccount(ctx, ra)
			if err != nil {
				return out, fmt.Errorf("the stake address state from %s: %w", uc.Rewards.Source(), err)
			}
			switch {
			case rd.IsUnknown():
				if !uc.AllowUnverified {
					return out, fmt.Errorf("%w: the stake address state from %s: %s", ErrUnverified, uc.Rewards.Source(), rd.Why())
				}
				unchecked = append(unchecked, "the registration of "+string(ra)+" was not checked: "+rd.Why())
			case rd.IsNone():
				return out, fmt.Errorf("%w: %s", ErrReturnNotRegistered, ra)
			default:
				sources = append(sources, uc.Rewards.Source())
			}
		}
	}

	run.params = params
	run.summary = ports.TxSummary{Kind: "governance action proposal", Sources: sources, Unchecked: unchecked}
	run.queued = ports.QueuedTx{Type: "Transaction", FromName: pay.name, FromAddr: pay.addr, ToName: pay.name, ToAddr: pay.addr,
		Description: fmt.Sprintf("signed utxo-transaction from '%s' to '%s'", pay.name, pay.name)}
	res, sum, err := uc.execute(ctx, run)
	if err != nil {
		return out, err
	}
	out.Result = Result{Result: res, Summary: sum, Sources: sources, Unchecked: unchecked}
	if run.plutus != nil {
		rep := *run.plutus.report
		out.Guardrails = &rep
		// What the operator was told about the evaluation is part of the result
		// too: a run that skipped the confirmation prints it from here.
		out.Result.Sources = append(append([]chain.Source(nil), sources...), rep.Evaluator)
		out.Result.Unchecked = append(append([]string(nil), unchecked...), rep.Notes()...)
	}
	for i := range props {
		id := governance.ActionID{TxID: res.TxID, Index: uint32(i)}
		c, err := id.CIP129()
		if err != nil {
			return out, err
		}
		out.IDs = append(out.IDs, ActionIDs{Hex: id.Hex(), CIP129: c})
	}
	return out, nil
}

// costModelNote is the line a summary carries when a cost model update was let
// through with --allow-cost-model-length-change and the current model could not
// be read as an array, so its length was not compared: empty when it was.
func costModelNote(changes []governance.ParamChange, raw json.RawMessage) string {
	un := governance.CostModelUnchecked(changes, raw)
	if len(un) == 0 {
		return ""
	}
	return "cost model length not checked: the current " + strings.Join(un, ", ") + " model cannot be read from the protocol parameters as an array of values"
}
