package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
)

// Governance artefacts (SPO-Pfiles-OUT-024 to OUT-030). The Name of a
// reference is the operator's name: the DRep for the `drep.*` kinds, the
// committee member for the `cc-*` kinds (a hot key's certificate is named after the
// hot key, a resignation after the cold key), `<voter>_<yymmddHHMMSS>` for a vote
// file and `<stake>_<yymmddHHMMSS>` (or `<stake>_<actionType>_...`) for an
// action file. A pool voter's key is the pool's NodeVKey.
const (
	DRepSKey      Kind = "drep.skey"
	DRepHwsFile   Kind = "drep.hwsfile"
	DRepID        Kind = "drep.id"
	DRepMnemonics Kind = "drep.mnemonics"
	DRepRegCert   Kind = "drep-reg.cert"
	DRepRetCert   Kind = "drep-ret.cert"

	CCColdVKey      Kind = "cc-cold.vkey"
	CCColdSKey      Kind = "cc-cold.skey"
	CCColdHwsFile   Kind = "cc-cold.hwsfile"
	CCColdHash      Kind = "cc-cold.hash"
	CCColdMnemonics Kind = "cc-cold.mnemonics"
	CCHotVKey       Kind = "cc-hot.vkey"
	CCHotSKey       Kind = "cc-hot.skey"
	CCHotHwsFile    Kind = "cc-hot.hwsfile"
	CCHotHash       Kind = "cc-hot.hash"
	CCHotMnemonics  Kind = "cc-hot.mnemonics"
	CCHotCert       Kind = "cc-hot.cert"
	CCColdRetCert   Kind = "cc-cold-ret.cert"

	VoteDRepFile  Kind = "drep.vote"
	VoteCCHotFile Kind = "cc-hot.vote"
	VotePoolFile  Kind = "pool.vote"
	GovActionFile Kind = "action"
)

func init() {
	for k, info := range map[Kind]kindInfo{
		DRepSKey: {secret: true}, DRepHwsFile: {}, DRepID: {}, DRepMnemonics: {secret: true}, DRepRegCert: {}, DRepRetCert: {},
		CCColdVKey: {}, CCColdSKey: {secret: true}, CCColdHwsFile: {}, CCColdHash: {}, CCColdMnemonics: {secret: true},
		CCHotVKey: {}, CCHotSKey: {secret: true}, CCHotHwsFile: {}, CCHotHash: {}, CCHotMnemonics: {secret: true},
		CCHotCert: {}, CCColdRetCert: {},
		VoteDRepFile: {}, VoteCCHotFile: {}, VotePoolFile: {}, GovActionFile: {},
	} {
		kinds[k] = info
	}
}

// VoteFileKind is the kind of the vote file of a voter role.
func VoteFileKind(r governance.Role) Kind {
	switch r {
	case governance.RoleDRep:
		return VoteDRepFile
	case governance.RoleCommitteeHot:
		return VoteCCHotFile
	}
	return VotePoolFile
}

// ---- key generation -------------------------------------------------------------

// DRepKeyGenerator makes random DRep key pairs (cardano-cli
// `governance drep key-gen`).
type DRepKeyGenerator interface {
	GenerateDRep(ctx context.Context) (KeyPair, error)
}

// CommitteeColdKeyGenerator and CommitteeHotKeyGenerator make the key pairs of
// a committee member (`governance committee key-gen-cold`, `key-gen-hot`).
type CommitteeColdKeyGenerator interface {
	GenerateCommitteeCold(ctx context.Context) (KeyPair, error)
}

// CommitteeHotKeyGenerator makes committee hot key pairs.
type CommitteeHotKeyGenerator interface {
	GenerateCommitteeHot(ctx context.Context) (KeyPair, error)
}

// GovernanceDeriver derives the governance keys of a mnemonic along the
// CIP-1852 paths 1852H/1815H/<account>H/<role>/<index> with role 3 (DRep),
// 4 (committee cold) and 5 (committee hot) (SPO-21a-INV-002, SPO-23a-INV-002,
// SPO-23b-INV-002). The signing keys are extended (BIP32) keys, the
// verification keys the plain ones. The mnemonic is the normalised phrase
// (see WalletDeriver); a bad phrase gives ErrInvalidMnemonic.
type GovernanceDeriver interface {
	DeriveDRep(ctx context.Context, mnemonic *Secret, account, index uint32) (KeyPair, error)
	DeriveCommitteeCold(ctx context.Context, mnemonic *Secret, account, index uint32) (KeyPair, error)
	DeriveCommitteeHot(ctx context.Context, mnemonic *Secret, account, index uint32) (KeyPair, error)
}

// ---- vote and action files ---------------------------------------------------------

// VoteFile is a vote as a file: the decoded vote, the voting-procedure CBOR
// that a transaction body carries, and the text envelope as stored, with the
// description (the action title upstream injects, SPO-24a-OUT-001).
type VoteFile struct {
	Vote governance.Vote
	CBOR []byte
	// Envelope is the file 24a stores: description injected, jq's two-space
	// indent. CLIEnvelope is the file cardano-cli itself writes (empty
	// description, four-space indent): the bytes the oracle compares.
	Envelope    []byte
	CLIEnvelope []byte
	Description string
}

// VoteFileBuilder makes and reads vote files exactly as `cardano-cli governance
// vote create` writes them, plus the injected description. A file that holds
// more than one vote, or an unknown voter type, is an error: upstream examines
// only the first entry (SPO-24b-IF-005).
type VoteFileBuilder interface {
	BuildVoteFile(v governance.Vote, description string) (VoteFile, error)
	DecodeVoteFile(envelope []byte) (VoteFile, error)
}

// ActionFile is a governance action as a file: the proposal CBOR a body carries
// and the envelope as stored.
type ActionFile struct {
	Action   governance.Action
	CBOR     []byte
	Envelope []byte
}

// ErrParameterChangeUnsupported: the parameter-update proposal is not built
// by the action-file adapter yet. An ActionFileBuilder that cannot build a
// ParameterChange must return an error that wraps this one, so that the use
// cases and the CLI can tell it from any other failure with errors.Is and
// without matching text.
//
// TODO(native): adapters/native/govaction.go returns its own
// native.ErrParameterChangeUnsupported, which the layers above cannot import.
// Until native returns (or wraps) this sentinel, the composition root maps the
// native error to this one (cmd/spo/env.go). Once native wraps it the mapping
// can go.
var ErrParameterChangeUnsupported = errors.New("a ParameterChange action file is not built by this adapter yet")

// ActionFileBuilder makes and reads `.action` files as `cardano-cli governance
// action create-*` writes them. An action that needs the guardrails script
// (treasury withdrawal and parameter change under a constitution that has one)
// still gets its file: the script is evaluated at transaction time. A
// parameter change is not built by this adapter yet (ErrParameterChangeUnsupported).
type ActionFileBuilder interface {
	BuildActionFile(a governance.Action) (ActionFile, error)
	DecodeActionFile(envelope []byte) (ActionFile, error)
}

// ---- chain readers -------------------------------------------------------------------

// CommitteeStateReader reads a committee member's state by its cold or hot
// hash. None means the hash is no member's: Unknown means the provider did not
// say. A false answer is harmful for a resignation (ADR 0006).
type CommitteeStateReader interface {
	ChainSource
	// CommitteeMember finds the member whose cold credential is cold.
	CommitteeMember(ctx context.Context, cold governance.Credential) (chain.Reading[governance.CommitteeMember], error)
	// CommitteeMemberByHot finds the member whose authorised hot credential is hot.
	CommitteeMemberByHot(ctx context.Context, hot governance.Credential) (chain.Reading[governance.CommitteeMember], error)
}

// GovActionReader reads the open governance actions (`query gov-state`
// proposals): their type, anchor, expiry, deposit return and the votes cast.
type GovActionReader interface {
	ChainSource
	// GovActions lists the open proposals. An action id filters; a nil id lists all.
	GovActions(ctx context.Context, id *governance.ActionID) (chain.Reading[[]governance.ActionState], error)
}

// ConstitutionReader reads the constitution of the chain: its anchor and the
// guardrails script hash (None when there is none).
type ConstitutionReader interface {
	ChainSource
	Constitution(ctx context.Context) (chain.Reading[governance.Constitution], error)
}

// LastEnactedReader reads the id of the last enacted action of each purpose
// (`prevActionIDs`). None for a purpose means the chain has no previous
// action of it; Unknown means the provider did not say.
type LastEnactedReader interface {
	ChainSource
	LastEnacted(ctx context.Context, p governance.Purpose) (chain.Reading[governance.ActionID], error)
}

// StakeDistributionReader reads what the tally of 24c needs: the stake of the
// active DReps, the always-no-confidence power, the pool stake with the
// default DRep of each pool's reward account, and the committee.
type StakeDistributionReader interface {
	ChainSource
	DRepDistribution(ctx context.Context) (chain.Reading[governance.DRepDistribution], error)
	PoolDistribution(ctx context.Context) (chain.Reading[[]governance.PoolStake], error)
	CommitteeComposition(ctx context.Context) (chain.Reading[governance.CommitteeComposition], error)
}

// VotingSummaryReader reads the voting tally a provider computed for one
// proposal: the DRep, pool and committee yes percentages and the vote powers
// behind them, as Koios's proposal voting summary states them. Light mode has
// no node to derive a tally from, so it reads this (SPO-24c-MODE-005); a
// provider that implements StakeDistributionReader needs no summary.
type VotingSummaryReader interface {
	ChainSource
	// VotingSummary reads the summary of one proposal. A summary that is
	// missing, empty or not interpretable is Unknown, never a zero tally.
	VotingSummary(ctx context.Context, id governance.ActionID) (chain.Reading[governance.VotingSummary], error)
	// CommitteeThreshold reads the fraction the committee must reach. Unknown
	// when the provider does not state it, including in the no-confidence state
	// (an absent number is not a positive statement of no confidence).
	CommitteeThreshold(ctx context.Context) (chain.Reading[chain.Rational], error)
}

// EpochReader gives the current epoch of the work mode (SPO-Cchain-OUT-001).
type EpochReader interface {
	ChainSource
	Epoch(ctx context.Context) (uint64, error)
}

// ---- anchor documents ----------------------------------------------------------------

// AnchorDocKind is which CIP the anchor document follows.
type AnchorDocKind string

// Anchor document kinds.
const (
	AnchorCIP100 AnchorDocKind = "CIP-100" // governance metadata (vote, DRep, action)
	AnchorCIP108 AnchorDocKind = "CIP-108" // governance action
	AnchorCIP119 AnchorDocKind = "CIP-119" // DRep
)

// AnchorVerdict is what the check of a document says. It is a projection for
// the operator: no tally and no transaction depends on it.
type AnchorVerdict struct {
	StructureOK bool
	Message     string
	Authors     []AnchorAuthor
	Title       string // body.title, set only when the document verified
}

// AnchorAuthor is one author signature of a CIP-100 document.
type AnchorAuthor struct {
	Name  string
	Valid bool
}

// AnchorVerifier checks a CIP-100/108/119 anchor document (structure and
// author signatures). No Go library does that: cardano-signer stays the
// adapter (`verify --cip100`). No adapter that shells out is written here, so
// a use case that upstream gates on it takes the verifier as an optional
// dependency and refuses without one unless the operator acknowledges the
// unverified anchor (governance.AnchorUnverifiedAcknowledged).
type AnchorVerifier interface {
	VerifyAnchor(ctx context.Context, kind AnchorDocKind, doc []byte) (AnchorVerdict, error)
}
