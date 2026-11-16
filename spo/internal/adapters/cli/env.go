package cli

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Cap names one capability of an Env. The names are what `spo capabilities`
// prints and what a refusal lists, so a command's error and the listing
// cannot disagree.
type Cap string

// The capabilities of an Env.
const (
	CapSigners Cap = "signers"
	CapKesKeys Cap = "kes-keygen"
	CapVrfKeys Cap = "vrf-keygen"

	CapColdKeys    Cap = "cold-keygen"
	CapPaymentKeys Cap = "payment-keygen"
	CapStakeKeys   Cap = "stake-keygen"
	CapMnemonics   Cap = "mnemonic-generation"
	CapDeriver     Cap = "wallet-derivation"
	CapAddressMake Cap = "address-building"
	CapClock       Cap = "clock"
	CapGenesis     Cap = "genesis"
	CapAddress     Cap = "address-inspection"
	CapMinOut      Cap = "min-output"
	CapFees        Cap = "fee-estimation"
	CapBodies      Cap = "tx-body"
	CapAssemble    Cap = "tx-assembly"
	CapCerts       Cap = "certificate-building"
	CapCertDecode  Cap = "certificate-decoding"

	CapTip         Cap = "tip"
	CapSync        Cap = "sync-check"
	CapOpCertCount Cap = "opcert-counter"
	CapParams      Cap = "protocol-parameters"
	CapUtxos       Cap = "utxo"
	CapRewards     Cap = "reward-account"
	CapPools       Cap = "pool-state"
	CapDReps       Cap = "drep-state"
	CapCrossCheck  Cap = "reward-account-crosscheck"
	CapSubmit      Cap = "tx-submit"
	CapQueue       Cap = "tx-queue"
)

// Env is everything a command may use, resolved once when the command
// starts (ADR 0008). Every field is typed by the narrow port the command
// needs. A chain field is nil when the configured mode or provider cannot
// supply it; a command states its needs with Require before it prompts or
// changes anything, and never nil-checks a field itself.
type Env struct {
	Signers ports.SignerDirectory
	// SignerKinds are the signers Signers can return, for display. Each has
	// passed ports.CheckSigner.
	SignerKinds []ports.Signer
	KesKeys     ports.KesKeyGenerator
	VrfKeys     ports.VrfKeyGenerator
	ColdKeys    ports.ColdKeyGenerator
	PaymentKeys ports.PaymentKeyGenerator
	StakeKeys   ports.StakeKeyGenerator
	Mnemonics   ports.MnemonicGenerator
	// WalletDeriver derives a wallet account from a mnemonic.
	WalletDeriver ports.WalletDeriver
	// Addresses builds addresses from key hashes.
	Addresses ports.AddressBuilder
	Clock     ports.Clock
	Genesis   ports.GenesisReader
	// NetworkID is ports.NetworkMainnet or ports.NetworkTestnet.
	NetworkID uint8

	AddressInspector    ports.AddressInspector
	MinOutputCalculator ports.MinOutputCalculator
	FeeEstimator        ports.FeeEstimator
	TxBodyBuilder       ports.TxBodyBuilder
	TxAssembler         ports.TxAssembler
	// Certs builds certificates; CertDecoder reads certificate files back.
	Certs       ports.CertificateBuilder
	CertDecoder ports.CertificateDecoder

	Tip            ports.TipReader
	Sync           ports.SyncChecker
	OpCertCounters ports.OpCertCounterReader
	Params         ports.ProtocolParametersReader
	Utxos          ports.UtxoReader
	Rewards        ports.RewardAccountReader
	// Pools and DReps read the registration of a pool and of a DRep.
	Pools ports.PoolStateReader
	DReps ports.DRepStateReader
	// CrossCheck is a second reward-account source, independent of Rewards.
	// Reads of the "harmful if false" class (ADR 0006) need it, or the
	// operator's explicit --single-source.
	CrossCheck ports.RewardAccountReader
	Submitter  ports.TxSubmitter
	Queue      ports.TxQueue

	// AllowUnverified is true only when the chain is not consulted.
	AllowUnverified bool

	// Mode is the effective mode ("" when the workspace has none).
	Mode string
	// Endpoints names the endpoint of a provider, by its Source name.
	Endpoints map[string]string

	why map[Cap]string
}

// Absent records why a capability is not there. The first reason wins, so a
// wiring that knows the precise cause is not overwritten by a caller's
// generic one. It is a no-op for a capability that is present.
func (e *Env) Absent(c Cap, reason string) {
	if e.has(c) {
		return
	}
	if e.why == nil {
		e.why = map[Cap]string{}
	}
	if _, ok := e.why[c]; !ok {
		e.why[c] = reason
	}
}

// Reason returns why a capability is absent, or "" when it is present.
func (e *Env) Reason(c Cap) string {
	if e.has(c) {
		return ""
	}
	if r, ok := e.why[c]; ok {
		return r
	}
	if e.Mode == "" {
		return "no mode is configured for this workspace (no " + configFile + "); pass --offline or create the workspace with: spo init"
	}
	return fmt.Sprintf("%s mode cannot supply it", e.Mode)
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface, reflect.Chan:
		return rv.IsNil()
	}
	return false
}

func (e *Env) has(c Cap) bool {
	var v any
	switch c {
	case CapSigners:
		v = e.Signers
	case CapKesKeys:
		v = e.KesKeys
	case CapVrfKeys:
		v = e.VrfKeys
	case CapColdKeys:
		v = e.ColdKeys
	case CapPaymentKeys:
		v = e.PaymentKeys
	case CapStakeKeys:
		v = e.StakeKeys
	case CapMnemonics:
		v = e.Mnemonics
	case CapDeriver:
		v = e.WalletDeriver
	case CapAddressMake:
		v = e.Addresses
	case CapClock:
		v = e.Clock
	case CapGenesis:
		v = e.Genesis
	case CapAddress:
		v = e.AddressInspector
	case CapMinOut:
		v = e.MinOutputCalculator
	case CapFees:
		v = e.FeeEstimator
	case CapBodies:
		v = e.TxBodyBuilder
	case CapAssemble:
		v = e.TxAssembler
	case CapCerts:
		v = e.Certs
	case CapCertDecode:
		v = e.CertDecoder
	case CapTip:
		v = e.Tip
	case CapSync:
		v = e.Sync
	case CapOpCertCount:
		v = e.OpCertCounters
	case CapParams:
		v = e.Params
	case CapUtxos:
		v = e.Utxos
	case CapRewards:
		v = e.Rewards
	case CapPools:
		v = e.Pools
	case CapDReps:
		v = e.DReps
	case CapCrossCheck:
		v = e.CrossCheck
	case CapSubmit:
		v = e.Submitter
	case CapQueue:
		v = e.Queue
	}
	return !isNil(v)
}

// Has reports whether a capability is present.
func (e *Env) Has(c Cap) bool { return e.has(c) }

// Source names the provider behind a chain capability, or "" when the
// capability is absent or has no provider name (a local one).
func (e *Env) Source(c Cap) string {
	var v any
	switch c {
	case CapTip:
		v = e.Tip
	case CapSync:
		v = e.Sync
	case CapOpCertCount:
		v = e.OpCertCounters
	case CapParams:
		v = e.Params
	case CapUtxos:
		v = e.Utxos
	case CapRewards:
		v = e.Rewards
	case CapPools:
		v = e.Pools
	case CapDReps:
		v = e.DReps
	case CapCrossCheck:
		v = e.CrossCheck
	case CapSubmit:
		v = e.Submitter
	case CapQueue:
		v = e.Queue
	}
	if isNil(v) {
		return ""
	}
	if s, ok := v.(ports.ChainSource); ok {
		return string(s.Source())
	}
	return ""
}

// Need is one requirement of a command: a Cap, or OneOf several.
type Need interface {
	missing(e *Env) string // "" when met
}

func (c Cap) missing(e *Env) string {
	if e.has(c) {
		return ""
	}
	return string(c) + ": " + e.Reason(c)
}

type oneOf []Cap

// OneOf is met when any of the capabilities is present.
func OneOf(caps ...Cap) Need { return oneOf(caps) }

func (o oneOf) missing(e *Env) string {
	var names, reasons []string
	for _, c := range o {
		if e.has(c) {
			return ""
		}
		names = append(names, string(c))
		reasons = append(reasons, e.Reason(c))
	}
	return "one of " + strings.Join(names, ", ") + ": " + strings.Join(reasons, "; ")
}

// Require checks every need and returns ONE error listing everything
// missing and why, or nil. A command calls it first, before it prompts for
// a secret or changes anything.
func (e *Env) Require(needs ...Need) error {
	var miss []string
	for _, n := range needs {
		if m := n.missing(e); m != "" {
			miss = append(miss, m)
		}
	}
	if len(miss) == 0 {
		return nil
	}
	return fmt.Errorf("this command cannot run here; it needs:\n  - %s", strings.Join(miss, "\n  - "))
}

// WireOptions is what the composition root builds an Env from.
type WireOptions struct {
	// Workspace is the workspace directory.
	Workspace string
	// Config is spo.toml; HaveConfig is false when the workspace has none
	// (a command that was given --offline can still run).
	Config     WorkspaceConfig
	HaveConfig bool
	// Mode is the effective mode: the configured one, or ModeOffline when
	// Offline is set, or "" when there is no configuration.
	Mode string
	// Offline is true when --offline overrode the workspace's mode.
	Offline bool
	Preset  NetworkPreset
	Genesis GenesisOverrides
	// Token is the provider API token from the store, or nil. The wiring
	// does not own it.
	Token *secret.Buffer
	// TransferFile is the offline transfer file to read and queue to.
	// Whether it exists is for the wiring to find out.
	TransferFile string
}

// GenesisOverrides are the genesis files and the Byron epoch count in
// effect: the flags, else the bundled files and the network's preset.
type GenesisOverrides struct {
	Shelley     string
	Byron       string
	ByronEpochs uint64
}
