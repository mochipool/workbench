package ports

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Kind names a type of artefact. The catalogue is spec/upstream/patterns/Pfiles.md;
// kinds are added here as use cases need them.
type Kind string

// Pool artefacts (SPO-Pfiles-OUT-010 to OUT-015).
const (
	NodeVKey       Kind = "node.vkey"
	NodeSKey       Kind = "node.skey"
	NodeCounter    Kind = "node.counter"
	NodeHwsFile    Kind = "node.hwsfile" // hardware signing file of the cold key; not secret (SPO-Pfiles-OUT-010)
	VrfVKey        Kind = "vrf.vkey"
	VrfSKey        Kind = "vrf.skey"
	KesVKey        Kind = "kes.vkey"         // numbered
	KesSKey        Kind = "kes.skey"         // numbered
	KesCounter     Kind = "kes.counter"      // newest generated KES key number
	KesCounterNext Kind = "kes.counter-next" // number the next KES key must have
	OpCert         Kind = "node.opcert"      // numbered
	KesExpire      Kind = "kes-expire.json"
)

// Workspace-level records, not owned by a pool or wallet.
const (
	// ProviderToken is the API token of a chain provider; the Ref name is
	// the provider ("koios"). Secret (ADR 0004, concern N3).
	ProviderToken Kind = "provider.token"
)

// Wallet artefacts (SPO-Pfiles-OUT-001, OUT-002, OUT-004). The Name of a
// reference is the operator's name for the address as upstream's scripts
// take it: `w` for a key-only address made by `02` (files `w.addr`,
// `w.vkey`, `w.skey`), `w.payment` for the payment account of a wallet made
// by `03a` (`w.payment.addr`, ...). The stake account of such a wallet is
// `w` with the Staking kinds (`w.staking.addr`, ...). A dot in a name is
// allowed by Ref.Validate, so no separate kinds are needed for `.payment.`.
const (
	AddrFile       Kind = "addr"         // <name>.addr: one bech32 address, not secret
	AddrVKey       Kind = "addr.vkey"    // <name>.vkey
	AddrSKey       Kind = "addr.skey"    // <name>.skey: a payment signing key, secret
	AddrHwsFile    Kind = "addr.hwsfile" // <name>.hwsfile: hardware signing file, not secret
	StakingAddr    Kind = "staking.addr" // <name>.staking.addr
	StakingVKey    Kind = "staking.vkey" // <name>.staking.vkey
	StakingSKey    Kind = "staking.skey" // <name>.staking.skey: secret
	StakingHwsFile Kind = "staking.hwsfile"
	// StakingCert is the stake registration certificate 03b writes
	// (<name>.staking.cert). 03a refuses to run when it exists
	// (SPO-03a-PRE-001); the kind is for that check.
	StakingCert Kind = "staking.cert"
	// DelegCert is the stake delegation certificate 05b writes
	// (<name>.deleg.cert), SPO-Pfiles-OUT-007.
	DelegCert Kind = "deleg.cert"
	// VoteDelegCert is the vote delegation certificate 22a writes
	// (<name>.vote-deleg.cert), SPO-Pfiles-OUT-008.
	VoteDelegCert Kind = "vote-deleg.cert"
	// StakingDeregCert is the deregistration certificate 08a writes
	// (<name>.staking.dereg-cert), SPO-Pfiles-OUT-009.
	StakingDeregCert Kind = "staking.dereg-cert"
	// DRepVKey is a DRep verification key (<name>.drep.vkey), read by 22a.
	DRepVKey Kind = "drep.vkey"
	// PaymentMnemonics is <name>.payment.mnemonics: the 24 words of a
	// mnemonic-derived wallet, one line. Secret in clear (SPO-Pfiles-OUT-005).
	PaymentMnemonics Kind = "payment.mnemonics"
)

type kindInfo struct {
	secret   bool
	numbered bool
}

var kinds = map[Kind]kindInfo{
	NodeVKey: {}, NodeSKey: {secret: true}, NodeCounter: {}, NodeHwsFile: {},
	VrfVKey: {}, VrfSKey: {secret: true},
	KesVKey: {numbered: true}, KesSKey: {secret: true, numbered: true},
	KesCounter: {}, KesCounterNext: {},
	OpCert: {numbered: true}, KesExpire: {},
	ProviderToken: {secret: true},
	AddrFile:      {}, AddrVKey: {}, AddrSKey: {secret: true}, AddrHwsFile: {},
	StakingAddr: {}, StakingVKey: {}, StakingSKey: {secret: true}, StakingHwsFile: {},
	StakingCert: {}, PaymentMnemonics: {secret: true},
	DelegCert: {}, VoteDelegCert: {}, StakingDeregCert: {}, DRepVKey: {},
	PartyKeys: {secret: true}, PartyIdentity: {}, PartyRecords: {}, PartyReplay: {},
	TailcatNodeKey: {secret: true}, TailcatPSK: {secret: true}, TailcatAddr: {secret: true},
}

// Known reports whether k is in the catalogue.
func (k Kind) Known() bool { _, ok := kinds[k]; return ok }

// Secret reports whether artefacts of this kind hold secret material
// (SPO-Pfiles-SEC-001). Secret artefacts are written with PutSecret and read
// only through Vault.
func (k Kind) Secret() bool { return kinds[k].secret }

// Numbered reports whether artefacts of this kind carry a sequence number.
func (k Kind) Numbered() bool { return kinds[k].numbered }

// Ref identifies one artefact: the operator's name for its owner (a pool, a
// wallet), the kind, and a sequence number for numbered kinds.
type Ref struct {
	Name string
	Kind Kind
	Num  int
}

func (r Ref) String() string {
	if r.Kind.Numbered() {
		return fmt.Sprintf("%s/%s#%d", r.Name, r.Kind, r.Num)
	}
	return fmt.Sprintf("%s/%s", r.Name, r.Kind)
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)*$`)

// Validate checks a reference before it reaches any adapter. A name is a
// plain label: no path separators, no leading dot, no shell or jq syntax
// (hazard H7).
func (r Ref) Validate() error {
	if !r.Kind.Known() {
		return fmt.Errorf("%w: unknown artefact kind %q", ErrInvalidRef, r.Kind)
	}
	if len(r.Name) > 128 || !nameRE.MatchString(r.Name) {
		return fmt.Errorf("%w: name %q must be letters, digits, '-', '_' and single dots", ErrInvalidRef, r.Name)
	}
	if r.Num < 0 || (!r.Kind.Numbered() && r.Num != 0) {
		return fmt.Errorf("%w: bad sequence number %d for %s", ErrInvalidRef, r.Num, r.Kind)
	}
	return nil
}

// Errors of the Store and Vault ports.
var (
	ErrNotFound   = errors.New("artefact not found")
	ErrInvalidRef = errors.New("invalid artefact reference")
	ErrSecretKind = errors.New("secret artefacts are read through the vault and written with PutSecret")
	ErrConflict   = errors.New("the workspace changed during the operation")
)

// Reader reads artefacts inside a View or Update.
type Reader interface {
	// Get returns a non-secret artefact, or ErrNotFound.
	Get(ref Ref) ([]byte, error)
	// Exists reports whether an artefact of any kind is present.
	Exists(ref Ref) (bool, error)
}

// Writer changes artefacts inside an Update. Nothing is visible to others
// until Update returns nil.
type Writer interface {
	Reader
	Put(ref Ref, data []byte) error
	// PutSecret stores secret material. The buffer stays owned by the caller.
	PutSecret(ref Ref, s *secret.Buffer) error
	Delete(ref Ref) error
}

// Store persists artefacts. An Update commits all of its writes or none
// (hazard H10; upstream leaves orphans, SPO-04c-PRE-004).
type Store interface {
	View(ctx context.Context, fn func(Reader) error) error
	Update(ctx context.Context, fn func(Writer) error) error
}

// ReadStore is a Store that can only be read. A directory that is only the
// source of an import is opened as one, so no write method exists to be misused
// (SPO-Xcustody-INV-001).
type ReadStore interface {
	View(ctx context.Context, fn func(Reader) error) error
}

// Vault releases secret material to the adapters that sign or export. Use
// cases never call it: they pass references to a Signer.
type Vault interface {
	// Open returns the secret in guarded memory. The caller destroys it.
	Open(ctx context.Context, ref Ref) (*secret.Buffer, error)
}

// Multi-party records (spec/extensions/Xparty.md). Names are the operator's
// local label: "local" for the workspace's own identity, the coordinator's
// party name for an address received in an Invite.
const (
	// PartyKeys is the local identity's private keys: 64 bytes, the Ed25519
	// seed then the X25519 scalar (SPO-Xparty-INV-001). Secret.
	PartyKeys Kind = "party.keys"
	// PartyIdentity is the local signed public identity document
	// (SPO-Xparty-INV-003). Not secret; it contains no address (IF-001).
	PartyIdentity Kind = "party.identity"
	// PartyRecords holds every enrolled party record, one blob, so a
	// registry change commits atomically and needs no listing (Store has no
	// List). Sensitive (SPO-Xparty-OUT-001).
	PartyRecords Kind = "party.records"
	// PartyReplay is the replay log (SPO-Xparty-INV-007): message ids with
	// their expiry, in one blob written in the transaction of the effect.
	PartyReplay Kind = "party.replay"
	// TailcatNodeKey is the persistent tailcat node private key (32 bytes),
	// TailcatPSK the pre-shared key (32 bytes) and TailcatAddr the tailcat
	// address text. All Secret (SPO-Xparty-SEC-001).
	TailcatNodeKey Kind = "tailcat.nodekey"
	TailcatPSK     Kind = "tailcat.psk"
	TailcatAddr    Kind = "tailcat.addr"
)
