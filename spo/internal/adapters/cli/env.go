package cli

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/handles"
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

	CapPoolCerts      Cap = "pool-certificate-building"
	CapPoolCertDecode Cap = "pool-certificate-decoding"
	CapMetaHash       Cap = "metadata-hash"
	CapTxID           Cap = "tx-id"
	CapAttach         Cap = "transfer-attach"
	CapMetaFetch      Cap = "metadata-fetch"
	CapTickers        Cap = "ticker-protection"

	CapTip         Cap = "tip"
	CapSync        Cap = "sync-check"
	CapOpCertCount Cap = "opcert-counter"
	CapParams      Cap = "protocol-parameters"
	CapUtxos       Cap = "utxo"
	CapRewards     Cap = "reward-account"
	CapPools       Cap = "pool-state"
	CapDReps       Cap = "drep-state"
	CapCrossCheck  Cap = "reward-account-crosscheck"
	// CapPoolCross is a second, independent source of the pool registration
	// state (ADR 0006); CapCrossCheck is the one of the reward account and
	// CapDRepCross the one of the DRep state.
	CapPoolCross Cap = "pool-state-crosscheck"
	// CapOpCertCross is a second, independent source of the operational
	// certificate counter (the node and an indexer, say).
	CapOpCertCross Cap = "opcert-counter-crosscheck"
	CapSubmit      Cap = "tx-submit"
	CapQueue       Cap = "tx-queue"

	CapBundle   Cap = "transfer-file"
	CapEras     Cap = "era"
	CapFileSink Cap = "extract-sink"
	CapTxView   Cap = "tx-view"

	// Extra parameters and native assets (spec/upstream Pparam, 10 to 11b).
	CapMetaFiles  Cap = "metadata-file"
	CapMsgEncrypt Cap = "message-encryption"
	CapPolicyID   Cap = "policy-id"
	// CapKeyCrypto is upstream's gpg envelope for signing keys. It is needed
	// only to read or write upstream's encrypted keys.
	CapKeyCrypto Cap = "key-encryption"
	// CapVKeyDerive derives the verification key of a signing key, so an
	// import can check the stored pair belongs together.
	CapVKeyDerive Cap = "verification-key-derivation"

	// Governance (spec/upstream 21a to 25b).
	CapDRepKeys     Cap = "drep-keygen"
	CapComColdKeys  Cap = "committee-cold-keygen"
	CapComHotKeys   Cap = "committee-hot-keygen"
	CapGovDeriver   Cap = "governance-derivation"
	CapVoteFiles    Cap = "vote-file"
	CapActionFiles  Cap = "action-file"
	CapAnchorFetch  Cap = "anchor-fetch"
	CapAnchorVerify Cap = "anchor-verification"
	CapCommittee    Cap = "committee-state"
	CapGovActions   Cap = "governance-actions"
	CapConstitution Cap = "constitution"
	CapLastEnacted  Cap = "last-enacted-action"
	CapStakeDist    Cap = "stake-distribution"
	CapEpoch        Cap = "epoch"
	// CapVotingSummary is the provider's own tally of a proposal (light mode,
	// SPO-24c-MODE-005); CapDRepCross a second, independent DRep-state source
	// for the reads that need corroboration (the deposit a DRep refund rests on).
	CapVotingSummary Cap = "voting-summary"
	CapDRepCross     Cap = "drep-state-crosscheck"

	// The Calidus pool key (CIP-151, upstream 15) and Catalyst (CIP-36, 09a).
	// CapSignatures is a signer that can sign CIP-8 messages, CIP-36 and
	// CIP-88 registrations (ADR 0008); CapCalidusRead is a provider that reads
	// the Calidus keys registered on chain.
	CapCalidusKeys Cap = "calidus-keygen"
	CapVotingKeys  Cap = "voting-keygen"
	CapSignatures  Cap = "registration-signing"
	CapCalidusRead Cap = "calidus-registrations"
	// CapVotingQR makes the QR code of a voting key (09a `qrcode`): a vault that
	// builds the PIN-encrypted payload and a renderer.
	CapVotingQR Cap = "voting-key-qr"

	// CapHardware is a hardware wallet: the release set has cardano-hw-cli.
	// Whether a device is connected, and which one, is found only when a
	// command's plan needs it. CapAdaHandle resolves ADA Handles (a chain
	// provider and the Handle API); CapPollQuestion reads an SPO poll's
	// question; CapBLSKeys generates the pool BLS key pair.
	CapHardware     Cap = "hardware-wallet"
	CapAdaHandle    Cap = "ada-handle"
	CapPollQuestion Cap = "poll-question"
	CapBLSKeys      Cap = "bls-keygen"
	// CapParty is the multi-party stack: the party identity, the registry,
	// the envelope kit and the transports (spec/extensions/Xparty.md).
	CapParty Cap = "multi-party-signing"

	// The token registry (CIP-26, upstream 12a and 12b) and the import of a
	// pool from the chain (0x). CapTokenRegistry reads a registry server and
	// exists only where a server is reachable; CapRegistrySigning is a signer
	// that signs registry entries with a policy key; CapLogoFiles reads the
	// logo a record names. CapPoolInfo and CapPoolUpdates read a pool's
	// registration and latest update; CapVKeyEnvelope and CapVrfVKey derive the
	// verification key envelope of an imported signing key.
	CapTokenRegistry   Cap = "token-registry"
	CapRegistrySigning Cap = "registry-signing"
	CapLogoFiles       Cap = "logo-file"
	CapPoolInfo        Cap = "pool-info"
	CapPoolUpdates     Cap = "pool-updates"
	CapVKeyEnvelope    Cap = "verification-key-envelope"
	CapVrfVKey         Cap = "vrf-verification-key"
	// CapTxEvaluator is a provider that evaluates the Plutus scripts of a
	// transaction and reports their execution units (the guardrails script of
	// a treasury withdrawal or parameter change). This build runs no Plutus
	// itself.
	CapTxEvaluator Cap = "plutus-script-evaluation"
)

// GovernanceChainCaps are the governance capabilities that read the chain.
var GovernanceChainCaps = []Cap{CapCommittee, CapGovActions, CapConstitution, CapLastEnacted, CapStakeDist, CapEpoch, CapVotingSummary, CapDRepCross, CapTxEvaluator}

// GovernanceLocalCaps are the governance capabilities that need no chain.
var GovernanceLocalCaps = []Cap{CapDRepKeys, CapComColdKeys, CapComHotKeys, CapGovDeriver, CapVoteFiles, CapActionFiles, CapAnchorFetch, CapAnchorVerify}

// HandleResolver resolves an ADA Handle (app/handles.Resolver satisfies it).
type HandleResolver interface {
	Resolve(ctx context.Context, text string) (handles.Resolved, error)
}

// FileSinkFactory opens a sink that writes files into one directory and
// nowhere else (ports.FileSink). The composition root supplies it, so this
// package imports no file adapter.
type FileSinkFactory func(dir string) (ports.FileSink, error)

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
	// PoolCerts builds and PoolCertDecoder reads the pool certificates;
	// MetadataHasher hashes the pool metadata; TxIDs gives the id of a body.
	PoolCerts       ports.PoolCertificateBuilder
	PoolCertDecoder ports.PoolCertificateDecoder
	MetadataHasher  ports.PoolMetadataHasher
	TxIDs           ports.TxIDCalculator
	// Attach stores files in the offline transfer file (offline only).
	Attach ports.TransferAttacher
	// Metadata downloads the published pool metadata (light and online
	// only). Tickers is the opt-in ticker-protection lookup: it is built in
	// no mode (hazard H6).
	Metadata ports.MetadataFetcher
	Tickers  ports.TickerProtectionChecker

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
	// PoolCross is the second source of the pool registration state, as
	// CrossCheck is of the reward account and DRepCross of the DRep state.
	PoolCross ports.PoolStateReader
	// OpCertCross is the second source of the operational certificate counter
	// (OpCertCounters is the answering one). The two may mean different
	// numbers (chain.CompareOpCertCounters says when they agree).
	OpCertCross ports.OpCertCounterReader
	Submitter   ports.TxSubmitter
	Queue       ports.TxQueue

	// Bundle is the air-gap transfer file at WireOptions.TransferFile, read
	// and changed through the narrow bundle ports. It is present in every
	// mode (`offline new` creates the file); whether the file exists is for
	// the use case to find out.
	Bundle ports.BundleStore
	// Eras reads the era of the transfer file (offline); nil in light mode,
	// where the era comes from the light-mode parameters document.
	Eras ports.EraReader
	// Sinks opens the directory `offline extract` writes into.
	Sinks FileSinkFactory
	// TxViewer decodes a queued transaction for display.
	TxViewer ports.TxViewer

	// MetadataFiles reads the user metadata files (.json, .cbor) of the extra
	// parameters; MsgEncrypter does the CIP-83 `basic` encryption of the
	// message lines; PolicyIDs gives the id of a native script. All are local.
	MetadataFiles ports.MetadataFileReader
	MsgEncrypter  ports.MessageEncrypter
	PolicyIDs     ports.PolicyIDCalculator
	// KeyEncryptor and KeyDecryptor make and open upstream's gpg-encrypted
	// signing key envelopes. They are nil where gpg is not available.
	KeyEncryptor ports.KeyEncryptor
	KeyDecryptor ports.KeyDecryptor
	// VKeyDeriver derives a verification key from a signing key (local).
	VKeyDeriver ports.VerificationKeyDeriver

	// The governance ports (21a to 25b). Key generators, the deriver and the
	// vote and action file builders are local. AnchorFetcher downloads anchor
	// documents (not in offline mode); AnchorVerifier checks them as
	// CIP-100/108/119 and is absent in every mode until an adapter exists:
	// a command that would verify refuses without its policy flag.
	DRepKeys       ports.DRepKeyGenerator
	ComColdKeys    ports.CommitteeColdKeyGenerator
	ComHotKeys     ports.CommitteeHotKeyGenerator
	GovDeriver     ports.GovernanceDeriver
	VoteFiles      ports.VoteFileBuilder
	ActionFiles    ports.ActionFileBuilder
	AnchorFetcher  ports.MetadataFetcher
	AnchorVerifier ports.AnchorVerifier
	// The governance chain readers; each is nil until an adapter of the
	// mode implements the port.
	Committee    ports.CommitteeStateReader
	GovActions   ports.GovActionReader
	Constitution ports.ConstitutionReader
	LastEnacted  ports.LastEnactedReader
	StakeDists   ports.StakeDistributionReader
	Epochs       ports.EpochReader
	// Summaries is the provider's voting summary and committee threshold, the
	// light-mode source of a tally; DRepCross is a second DRep-state source,
	// independent of DReps. Neither exists in every mode.
	Summaries ports.VotingSummaryReader
	DRepCross ports.DRepStateReader

	// CalidusKeys and VotingKeys derive the Calidus and the Catalyst voting
	// key from a mnemonic (local). SignatureSigner is a signer of the vault
	// that also signs messages, CIP-36 and CIP-88 registrations (ports.CheckSigner
	// and ports.CheckSignatureSigner passed); Signers hands it out for a
	// vault-held key. CalidusReader reads the registered Calidus keys.
	CalidusKeys     ports.CalidusKeyDeriver
	VotingKeys      ports.VotingKeyDeriver
	SignatureSigner ports.Signer
	CalidusReader   ports.CalidusKeyReader
	// VotingQR builds the payload of a voting key's QR code from the vault;
	// QRCodes draws it (CapVotingQR needs both).
	VotingQR ports.VotingKeyQRSource
	QRCodes  ports.QRCodeRenderer

	// Hardware exports the keys of a hardware wallet, Canonicalizer brings a
	// transaction body to the form a device accepts and PolicyIDer asks the
	// device for a policy id. They are one lazily opened session: nothing
	// touches a device until a command's plan needs it. All three are nil when
	// the release set has no cardano-hw-cli.
	Hardware      ports.HardwareKeyExporter
	Canonicalizer ports.HardwareCanonicalizer
	PolicyIDer    ports.HardwarePolicyIDer
	// Handles resolves an ADA Handle to the address that holds it, verified
	// against the chain; nil where no provider can (the offline mode keeps a
	// resolver that refuses, so the refusal says why).
	Handles HandleResolver
	// Polls reads the question of an SPO poll (light mode).
	Polls ports.PollQuestionReader
	// BLSKeys generates the pool BLS key pair (local).
	BLSKeys ports.BLSKeyGenerator

	// Party is the multi-party stack (party identities, envelopes, the file
	// and tailcat transports). OwnUtxos is the signer's OWN chain provider as
	// a resolver of inputs by reference: set only in light mode, where it is
	// the provider the operator configured; the offline transfer file is
	// never put here, because a transfer file may have been written by
	// another party (ADR 0005, obligation 3). SnapshotResolver reads an
	// offline snapshot at a path the operator names with --own-snapshot.
	Party            *PartyKit
	OwnUtxos         ports.UtxoResolver
	SnapshotResolver func(path string) ports.UtxoResolver

	// Registry reads a token-registry server (light mode, a server configured
	// or the network's public one). RegistrySigner is the vault signer that also
	// signs registry entries; Signers hands it out for a vault-held policy key,
	// and a hardware key has none. Logos reads the logo file a record names.
	Registry       ports.TokenRegistryReader
	RegistrySigner ports.Signer
	Logos          ports.LogoFileReader
	// PoolInfos and PoolUpdates read the registration of a pool and its latest
	// update (light mode); VKeyEnvelopes and VrfVKeys derive the verification
	// key envelopes of the signing keys of an imported pool (local).
	PoolInfos   ports.PoolInfoReader
	PoolUpdates ports.PoolUpdateReader
	// PoolInfoCross is the optional second, independent reader of a pool's
	// registration, against which the pool import corroborates (ADR 0006).
	PoolInfoCross ports.PoolInfoReader
	VKeyEnvelopes ports.VKeyEnvelopeDeriver
	VrfVKeys      ports.VrfVKeyDeriver
	// TxEvaluator evaluates the Plutus scripts of a transaction (light mode,
	// where the provider does; nil elsewhere).
	TxEvaluator ports.TxEvaluator

	// AllowUnverified is true only when the chain is not consulted.
	AllowUnverified bool

	// Mode is the effective mode ("" when the workspace has none).
	Mode string
	// Endpoints names the endpoint of a provider, by its Source name.
	Endpoints map[string]string
	// SameHostOK is [provider] same_host_ok: the operator states that two
	// sources of a cross-check that share a host are independent all the same.
	// It weakens the check, and is why CheckIndependentSources skips the host
	// comparison.
	SameHostOK bool
	// sharedHost lists the cross-checks whose two sources are on one host and
	// that same_host_ok let through (set by CheckIndependentSources).
	sharedHost []string

	why map[Cap]string
	// closers release what the wiring opened lazily (a node connection). A
	// command's Env is closed when the command ends.
	closers []func()
}

// OnClose registers a function Close calls: the wiring uses it for a
// connection that is opened only when a read needs it.
func (e *Env) OnClose(f func()) { e.closers = append(e.closers, f) }

// Close runs the functions registered with OnClose, last first, once. It is
// safe on a nil Env.
func (e *Env) Close() {
	if e == nil {
		return
	}
	cl := e.closers
	e.closers = nil
	for i := len(cl) - 1; i >= 0; i-- {
		cl[i]()
	}
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
	case CapPoolCerts:
		v = e.PoolCerts
	case CapPoolCertDecode:
		v = e.PoolCertDecoder
	case CapMetaHash:
		v = e.MetadataHasher
	case CapTxID:
		v = e.TxIDs
	case CapAttach:
		v = e.Attach
	case CapMetaFetch:
		v = e.Metadata
	case CapTickers:
		v = e.Tickers
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
	case CapPoolCross:
		v = e.PoolCross
	case CapOpCertCross:
		v = e.OpCertCross
	case CapSubmit:
		v = e.Submitter
	case CapQueue:
		v = e.Queue
	case CapBundle:
		v = e.Bundle
	case CapEras:
		v = e.Eras
	case CapFileSink:
		v = e.Sinks
	case CapTxView:
		v = e.TxViewer
	case CapMetaFiles:
		v = e.MetadataFiles
	case CapMsgEncrypt:
		v = e.MsgEncrypter
	case CapPolicyID:
		v = e.PolicyIDs
	case CapVKeyDerive:
		v = e.VKeyDeriver
	case CapKeyCrypto:
		if e.KeyEncryptor != nil && e.KeyDecryptor != nil {
			v = e.KeyEncryptor
		}
	case CapDRepKeys:
		v = e.DRepKeys
	case CapComColdKeys:
		v = e.ComColdKeys
	case CapComHotKeys:
		v = e.ComHotKeys
	case CapGovDeriver:
		v = e.GovDeriver
	case CapVoteFiles:
		v = e.VoteFiles
	case CapActionFiles:
		v = e.ActionFiles
	case CapAnchorFetch:
		v = e.AnchorFetcher
	case CapAnchorVerify:
		v = e.AnchorVerifier
	case CapCommittee:
		v = e.Committee
	case CapGovActions:
		v = e.GovActions
	case CapConstitution:
		v = e.Constitution
	case CapLastEnacted:
		v = e.LastEnacted
	case CapStakeDist:
		v = e.StakeDists
	case CapEpoch:
		v = e.Epochs
	case CapVotingSummary:
		v = e.Summaries
	case CapDRepCross:
		v = e.DRepCross
	case CapCalidusKeys:
		v = e.CalidusKeys
	case CapVotingKeys:
		v = e.VotingKeys
	case CapSignatures:
		v = e.SignatureSigner
	case CapCalidusRead:
		v = e.CalidusReader
	case CapVotingQR:
		if e.QRCodes == nil {
			return false
		}
		v = e.VotingQR
	case CapHardware:
		v = e.Hardware
	case CapAdaHandle:
		// Offline the resolver exists only to refuse with its reason.
		if e.Mode != ModeOffline {
			v = e.Handles
		}
	case CapPollQuestion:
		v = e.Polls
	case CapBLSKeys:
		v = e.BLSKeys
	case CapParty:
		v = e.Party
	case CapTokenRegistry:
		v = e.Registry
	case CapRegistrySigning:
		v = e.RegistrySigner
	case CapLogoFiles:
		v = e.Logos
	case CapPoolInfo:
		v = e.PoolInfos
	case CapPoolUpdates:
		v = e.PoolUpdates
	case CapVKeyEnvelope:
		v = e.VKeyEnvelopes
	case CapVrfVKey:
		v = e.VrfVKeys
	case CapTxEvaluator:
		v = e.TxEvaluator
	}
	return !isNil(v)
}

// Has reports whether a capability is present.
func (e *Env) Has(c Cap) bool { return e.has(c) }

// Source names the provider behind a chain capability, or "" when the
// capability is absent or has no provider name (a local one).
func (e *Env) Source(c Cap) string {
	if c == CapTokenRegistry { // named by its host, not by a chain source
		if isNil(e.Registry) {
			return ""
		}
		return e.Registry.Registry()
	}
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
	case CapPoolCross:
		v = e.PoolCross
	case CapOpCertCross:
		v = e.OpCertCross
	case CapSubmit:
		v = e.Submitter
	case CapQueue:
		v = e.Queue
	case CapCommittee:
		v = e.Committee
	case CapGovActions:
		v = e.GovActions
	case CapConstitution:
		v = e.Constitution
	case CapLastEnacted:
		v = e.LastEnacted
	case CapStakeDist:
		v = e.StakeDists
	case CapEpoch:
		v = e.Epochs
	case CapVotingSummary:
		v = e.Summaries
	case CapDRepCross:
		v = e.DRepCross
	case CapCalidusRead:
		v = e.CalidusReader
	case CapPollQuestion:
		v = e.Polls
	case CapPoolInfo:
		v = e.PoolInfos
	case CapPoolUpdates:
		v = e.PoolUpdates
	case CapTxEvaluator:
		v = e.TxEvaluator
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
	// Ctx is the context of the command: what a lazily opened adapter (the
	// hardware wallet) uses where a call has none of its own.
	Ctx     context.Context
	Preset  NetworkPreset
	Genesis GenesisOverrides
	// Token is the provider API token from the store, or nil. The wiring
	// does not own it.
	Token *secret.Buffer
	// Tokens are the stored tokens of the other configured providers, by
	// provider kind ("blockfrost": the project id). Nil entries are absent.
	Tokens map[string]*secret.Buffer
	// TransferFile is the offline transfer file to read and queue to.
	// Whether it exists is for the wiring to find out.
	TransferFile string
	// Toolchain and Tools are the external tools of the release set, for the
	// few capabilities that run one (gpg for upstream's encrypted keys). Tools
	// is empty when the binary runs without a toolchain manifest.
	Toolchain ports.Toolchain
	Tools     []ports.ToolName
}

// GenesisOverrides are the genesis files and the Byron epoch count in
// effect: the flags, else the bundled files and the network's preset.
type GenesisOverrides struct {
	Shelley     string
	Byron       string
	ByronEpochs uint64
}
