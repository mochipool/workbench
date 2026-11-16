package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Artefact families of Pfiles that no other file of this package declares:
// BLS keys, minting policies and assets, Catalyst voting keys, Calidus keys.
// The Name of a reference is the operator's name for the owner; for the
// asset record it is `<policy>.<assetname>`, and for a token-registry
// submission file the subject (policy id and hex name).
const (
	// spec: SPO-Pfiles-OUT-016
	BLSVKey Kind = "bls.vkey"
	BLSSKey Kind = "bls.skey"

	// spec: SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032, SPO-Pfiles-OUT-033, SPO-Pfiles-OUT-034
	PolicyVKey        Kind = "policy.vkey"
	PolicySKey        Kind = "policy.skey"
	PolicyHwsFile     Kind = "policy.hwsfile"
	PolicyScript      Kind = "policy.script"
	PolicyID          Kind = "policy.id"
	AssetFile         Kind = "asset"
	TokenRegistration Kind = "token-registration.json"

	// spec: SPO-Pfiles-OUT-035
	VotingVKey          Kind = "voting.vkey"
	VotingSKey          Kind = "voting.skey"
	VotingHwsFile       Kind = "voting.hwsfile"
	VotingPKey          Kind = "voting.pkey"
	VotingMnemonics     Kind = "voting.mnemonics"
	CatalystQRCode      Kind = "catalyst-qrcode.png"
	VoteRegistration    Kind = "vote-registration.cbor"
	CalidusVKey         Kind = "calidus.vkey"
	CalidusSKey         Kind = "calidus.skey"
	CalidusHwsFile      Kind = "calidus.hwsfile"
	CalidusMnemonics    Kind = "calidus.mnemonics"
	CalidusID           Kind = "calidus.id"
	CalidusRegistration Kind = "calidus-registration.json"

	// UpstreamEncryptedSKey is a signing key kept in upstream's gpg-wrapped
	// form (SPO-Ckey-OUT-001) because no password was given at import. The
	// Name is the stem of the original file (`<pool>.node`, `<wallet>.payment`,
	// `<pool>.kes-003`). It is opaque: no signer reads it. Secret, because the
	// ciphertext protects a signing key only as well as its password does.
	UpstreamEncryptedSKey Kind = "upstream-encrypted.skey"
)

func init() {
	for k, info := range map[Kind]kindInfo{
		BLSVKey: {}, BLSSKey: {secret: true},
		PolicyVKey: {}, PolicySKey: {secret: true}, PolicyHwsFile: {}, PolicyScript: {}, PolicyID: {}, AssetFile: {}, TokenRegistration: {},
		VotingVKey: {}, VotingSKey: {secret: true}, VotingHwsFile: {}, VotingPKey: {}, VotingMnemonics: {secret: true},
		CatalystQRCode: {secret: true}, VoteRegistration: {},
		CalidusVKey: {}, CalidusSKey: {secret: true}, CalidusHwsFile: {}, CalidusMnemonics: {secret: true}, CalidusID: {},
		CalidusRegistration:   {},
		UpstreamEncryptedSKey: {secret: true},
	} {
		kinds[k] = info
	}
}

// SigningKeyRole describes a signing-key kind: the kind of the verification
// key that belongs to it ("" when it has none in the catalogue) and the role
// part of the file stem, used to name an upstream-encrypted record.
type SigningKeyRole struct {
	VKey Kind
	Role string // ".node", ".kes-%03d" for numbered kinds, "" for a plain wallet key
}

// SigningKeyKinds lists every kind whose content is a signing key envelope,
// plain or in upstream's encrypted form (SPO-Pfiles-SEC-001).
func SigningKeyKinds() map[Kind]SigningKeyRole {
	return map[Kind]SigningKeyRole{
		NodeSKey: {NodeVKey, ".node"}, VrfSKey: {VrfVKey, ".vrf"}, KesSKey: {KesVKey, ".kes-%03d"},
		AddrSKey: {AddrVKey, ""}, StakingSKey: {StakingVKey, ".staking"},
		PoolItnSKey: {PoolItnVKey, ".itn"}, DRepSKey: {DRepVKey, ".drep"},
		CCColdSKey: {CCColdVKey, ".cc-cold"}, CCHotSKey: {CCHotVKey, ".cc-hot"},
		BLSSKey: {BLSVKey, ".bls"}, PolicySKey: {PolicyVKey, ".policy"},
		VotingSKey: {VotingVKey, ".voting"}, CalidusSKey: {CalidusVKey, ".calidus"},
	}
}

// IsSigningKey reports whether k is a signing-key kind.
func (k Kind) IsSigningKey() bool { _, ok := SigningKeyKinds()[k]; return ok }

// HardwareFileKinds lists the kinds that are hardware signing files
// (SPO-Pfiles-OUT-004): sensitive, not secret.
func HardwareFileKinds() []Kind {
	return []Kind{NodeHwsFile, AddrHwsFile, StakingHwsFile, DRepHwsFile, CCColdHwsFile, CCHotHwsFile, PolicyHwsFile, VotingHwsFile, CalidusHwsFile}
}

// Errors of the workspace ports.
var (
	// ErrWrongPassphrase means gpg refused the passphrase. It is the only
	// outcome that names the passphrase; the caller never retries by itself.
	ErrWrongPassphrase = errors.New("the passphrase does not open this key")
	// ErrMalformedCiphertext means the encrypted data is not an OpenPGP
	// symmetric message. Retrying with another passphrase cannot help.
	ErrMalformedCiphertext = errors.New("the encrypted key is not a valid gpg message")
	// ErrBadPlaintext means gpg decrypted the message but the result is not
	// the hex text of a cborHex.
	ErrBadPlaintext = errors.New("the decrypted key is not hex text")
	// ErrBadPassphraseText means a passphrase cannot be handed to gpg
	// through a pipe (empty, or it contains a line break).
	ErrBadPassphraseText = errors.New("the passphrase is empty or contains a line break")
	// ErrKeyTypeUnsupported means a verification key cannot be derived for
	// this kind of signing key; the consistency check is skipped.
	ErrKeyTypeUnsupported = errors.New("verification key derivation is not supported for this key type")
)

// KeyDecryptor opens upstream's encrypted key form (SPO-Ckey-EXT-002).
type KeyDecryptor interface {
	// Decrypt takes the ASCII hex text of the envelope's encrHex member
	// (the adapter decodes it) and returns the cborHex text, without its
	// trailing newline, in guarded memory. A wrong passphrase gives
	// ErrWrongPassphrase after one attempt: there is no retry.
	Decrypt(ctx context.Context, encrHex []byte, passphrase *Secret) (*Secret, error)
}

// KeyEncryptor makes upstream's encrypted key form (SPO-Ckey-EXT-001).
type KeyEncryptor interface {
	// Encrypt returns the lower-case hex text of the gpg symmetric message
	// over cborHex plus a newline, for the envelope's encrHex member.
	Encrypt(ctx context.Context, plaintextCborHex *Secret, passphrase *Secret) (encrHex []byte, err error)
}

// VerificationKeyDeriver derives the verification key of a signing key, so
// an import can check that the stored `.vkey` belongs to the `.skey`.
// The native adapter is expected to implement it (ed25519 seed to public
// key; extended keys carry the public key).
type VerificationKeyDeriver interface {
	// DeriveVerificationKey takes the signing key envelope and returns the
	// 32-byte raw verification key. A key type it cannot handle (KES, VRF,
	// BLS) gives ErrKeyTypeUnsupported.
	DeriveVerificationKey(ctx context.Context, skeyEnvelope *Secret) ([]byte, error)
}

// SourceEntry is one recognised artefact of a directory.
type SourceEntry struct {
	Ref Ref
}

// SourceUnknown is a file that is no artefact of the catalogue.
type SourceUnknown struct {
	File   string // base name as it is in the directory
	Reason string
}

// SourceListing is what a lister found.
type SourceListing struct {
	Entries []SourceEntry
	Unknown []SourceUnknown
}

// SourceLister enumerates the artefacts of a store by the naming rules of
// Pfiles. The upstream-layout adapter implements it from its name mapping;
// the sealed store implements it from its records.
type SourceLister interface {
	List(ctx context.Context) (SourceListing, error)
}

// AuditEvent is the record of a dangerous workspace operation. It holds
// counts and names the operator gave, never secret material.
type AuditEvent struct {
	Operation     string // "export-workspace", "unprotect-key"
	Owners        []string
	PlaintextKeys int  // signing keys and mnemonics written in clear
	ProtectedKeys int  // signing keys written in upstream's encrypted form
	Protected     bool // a password was used
	Acknowledged  bool // the operator acknowledged plaintext export

	// The fields below describe a read that rested on one chain source because
	// the operator gave --single-source (Operation "single-source-read").
	Command      string // the command, "spo stake deregister"
	Read         string // what was read, "reward balance and stake deposit"
	Source       string // the one provider the read rested on
	SingleSource bool   // --single-source was given and was needed
}

// WorkspaceAuditor records AuditEvents. The use case records before it
// writes a secret and stops when the record cannot be made.
type WorkspaceAuditor interface {
	Record(ctx context.Context, e AuditEvent) error
}

// IsWorkspaceKind reports whether a kind is part of an upstream workspace
// (Pfiles). This program's own records (party identities, tailcat keys,
// multi-party state, provider tokens) are not, and neither import nor export
// touches them.
func IsWorkspaceKind(k Kind) bool {
	switch k {
	case PartyKeys, PartyIdentity, PartyRecords, PartyReplay, TailcatNodeKey, TailcatPSK, TailcatAddr,
		MultisigCoordinator, MultisigSigner, MultisigOutbox, MultisigEvents, MultisigCollection, MultisigSubmitted, ProviderToken,
		WorkspaceAuditLog:
		return false
	}
	return k.Known()
}

// TakeSecret moves b into guarded memory and wipes b (secret.TryTake), so
// use cases, which may not import the platform layer, can build secrets.
func TakeSecret(b []byte) (*Secret, error) { return secret.TryTake(b) }

// FillSecret returns a guarded buffer of n bytes that fn writes into
// directly (secret.Fill).
func FillSecret(n int, fn func(b []byte) error) (*Secret, error) { return secret.Fill(n, fn) }
