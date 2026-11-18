package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Deps is what the composition root hands to the command tree. Everything
// that touches a file format, a database or the network is a function here:
// this package imports no other adapter.
type Deps struct {
	Version   string
	Release   string
	Toolchain ports.Toolchain
	Tools     []ports.ToolName
	Out       io.Writer
	Err       io.Writer

	// Terminal prompts the operator. Nil means stdin (fd 0), prompting on Err.
	Terminal Terminal

	Config ConfigOps
	// Factors is the FIDO2 factor source (ADR 0011). Nil where the binary cannot
	// reach one: a command that needs a factor then fails before any prompt.
	Factors ports.FactorSource
	// NodeAddressWarning returns the warning to print for a node address that
	// is plain TCP to a non-loopback host, "" otherwise. Nil: no warning.
	NodeAddressWarning func(address string) string
	Sealed             SealedOps

	// OpenUpstream opens a directory in the upstream scripts' file layout as
	// a WORKSPACE, with signing keys unsealed (--upstream-layout). The release
	// binary leaves it nil and has no such flag: it must be unable to write a
	// signing key in clear (SPO-Xcustody-INV-001). Only a build with the
	// `plainlayout` tag, and tests, set it, with spo/test/plainstore.
	OpenUpstream func(dir string) (ports.Store, error)

	// OpenUpstreamSource opens an upstream-layout directory to be read as the
	// source of a workspace import. The source is read only by type.
	OpenUpstreamSource func(dir string) (UpstreamSource, error)

	// OpenExportDir opens the destination of `workspace export`: a store that
	// accepts non-secret files and signing keys in upstream's encrypted form,
	// and refuses every other secret.
	OpenExportDir func(dir string) (ports.NamedStore, error)

	// WorkspaceAuditor makes the recorder of dangerous workspace operations
	// (export) over a store; reason is the operator's, kept with each event.
	// dir is the workspace directory: a store with no place for the log keeps
	// it in a file there.
	WorkspaceAuditor func(dir string, store ports.NamedStore, reason string) ports.WorkspaceAuditor

	// HotSealer and HotDeriver are the age sealer and the KES and VRF
	// verification-key deriver of `node export` (ADR 0011 decision 2). Nil: the
	// command is unavailable. Neither can write a file.
	HotSealer  ports.HotSealer
	HotDeriver ports.HotVKeyDeriver

	// Wire builds the Env a command runs in, from the open store (nil to
	// only inspect what the configuration yields) and the options. It
	// constructs; it does not touch the network. Adding a command never
	// needs a change here.
	Wire func(store ports.Store, o WireOptions) (*Env, error)

	// MapError turns the typed errors an adapter declares (this package
	// imports none) into what the operator should do next, with Explain. It
	// returns an error it does not know unchanged. Nil maps nothing.
	MapError func(error) error

	// Genesis returns the genesis files the release set bundles for a
	// network, or ok=false when the binary has no manifest or no entry.
	Genesis func(network string) (shelley, byron string, ok bool)

	// Sleep and Now drive the pauses and the timeout of --wait; nil is the
	// real clock. A test passes a fake so no test sleeps.
	Sleep func(ctx context.Context, d time.Duration) error
	Now   func() time.Time
}

// UpstreamSource is an upstream-layout directory opened for an import.
type UpstreamSource interface {
	ports.NamedReadStore
	ports.NamedVault
	ports.SourceLister
	ports.SourceTree
}

// WorkspaceConfig mirrors spo.toml (see adapters/config).
type WorkspaceConfig struct {
	Network string
	Mode    string
	Koios   *KoiosConfig // nil: no Koios provider configured
	// Blockfrost is the optional [blockfrost] section: a second provider kind.
	Blockfrost *BlockfrostConfig
	// Node is the optional [node] section: a node socket (node-to-client).
	Node *NodeConfig
	// Order is [provider] order, the operator's order of preference among the
	// configured providers (empty: the default order koios, blockfrost).
	Order []string
	// SameHostOK is [provider] same_host_ok (see Env.SameHostOK).
	SameHostOK bool
	// Hardware is the optional [hardware] section; nil keeps every default.
	Hardware *HardwareConfig
	// Handles is the optional [handles] section; nil keeps the network's API.
	Handles *HandlesConfig
	// Party and Tailcat are the optional [party] and [tailcat] sections.
	Party   *PartyConfig
	Tailcat *TailcatConfig
	// Registry is the optional [registry] section: the token-registry server.
	Registry *RegistryConfig
}

// NodeConfig is the [node] section: Address is a socket path, unix:PATH or
// tcp://host:port; TimeoutSeconds bounds each operation (0: the default).
type NodeConfig struct {
	Address        string
	TimeoutSeconds int
}

// RegistryConfig is the [registry] section: URL is the root of a CIP-26
// token-registry server.
type RegistryConfig struct{ URL string }

// PartyConfig is the [party] section: the file transport's directories.
type PartyConfig struct{ Inbox, Outbox string }

// TailcatConfig is the [tailcat] section. Zero values keep the defaults.
type TailcatConfig struct {
	Port       int
	DERPMapURL string
}

// HardwareConfig is the [hardware] section. Zero values keep the defaults.
type HardwareConfig struct {
	// WaitSeconds bounds the wait for the device to answer (default 60).
	WaitSeconds int
	// MinLedger, MinTrezor and MinKeystone override the minimum app or
	// firmware version of that vendor (dotted numbers).
	MinLedger, MinTrezor, MinKeystone string
}

// HandlesConfig is the [handles] section: URL overrides the ADA Handle API
// root of the network.
type HandlesConfig struct{ URL string }

// BlockfrostConfig is the [blockfrost] section. URL empty means the network's
// public endpoint; TokenRecord names the Secret record of the project id (empty:
// "blockfrost").
type BlockfrostConfig struct{ URL, TokenRecord string }

// KoiosConfig is the [koios] section. URL empty means the network's public
// endpoint.
type KoiosConfig struct{ URL string }

// Modes of operation.
const (
	ModeOnline  = "online"
	ModeLight   = "light"
	ModeOffline = "offline"
)

// NetworkPreset is the per-network data of the upstream presets.
type NetworkPreset struct {
	Name                 string
	Magic                string
	AddressPrefix        string
	ByronToShelleyEpochs uint64
	KoiosURL             string
	LightParametersURL   string
	// HandleURL is the ADA Handle API root, "" where the network has none.
	HandleURL string
}

// ConfigOps reads and writes spo.toml. Load's error satisfies
// errors.Is(err, os.ErrNotExist) when the file is absent.
type ConfigOps struct {
	Load     func(dir string) (WorkspaceConfig, error)
	Create   func(dir string, c WorkspaceConfig) error
	Save     func(dir string, c WorkspaceConfig) error
	Preset   func(network string) (NetworkPreset, bool)
	Networks func() []string
}

// Sentinel errors the composition root maps the sealed store's errors to.
// The command tree turns each into one sentence that says what happened and
// what to do (see explain).
var (
	// ErrWrongPassphrase: no key slot opens with the given passphrase.
	ErrWrongPassphrase = errors.New("wrong passphrase")
	// ErrWrongRecoveryKey: no key slot opens with the given recovery key.
	ErrWrongRecoveryKey = errors.New("wrong recovery key")
	// ErrBadRecoveryKey: the text is not a recovery key.
	ErrBadRecoveryKey = errors.New("that is not a recovery key")
	// ErrRolledBack: the workspace file is older than the recorded head.
	ErrRolledBack = errors.New("workspace older than its recorded state")
	// ErrHeadMismatch: the head file belongs to another workspace.
	ErrHeadMismatch = errors.New("head file does not belong to this workspace")
	// ErrLocked: the workspace is open elsewhere or being replaced.
	ErrLocked = errors.New("workspace is locked")
	// ErrOtherWorkspace: the backup is of a different workspace.
	ErrOtherWorkspace = errors.New("backup of another workspace")
	// ErrOlderBackup: the backup is older than, or diverged from, the workspace.
	ErrOlderBackup = errors.New("backup older than the workspace")
)

// OpenOptions are the choices of opening a sealed workspace.
type OpenOptions struct {
	// AcceptRollback opens a workspace older than its recorded head and
	// records the file's own state as the new head.
	AcceptRollback bool
}

// RestoreOptions are the choices of a restore.
type RestoreOptions struct {
	Overwrite           bool
	AllowOlder          bool
	AllowOtherWorkspace bool
	// AllowWeakerPolicy and CurrentRecovery: a backup whose unlock policy is
	// weaker than the workspace's replaces it only when both are given.
	AllowWeakerPolicy bool
	CurrentRecovery   *FactorOpen
}

// Head is the end of a workspace's audit chain.
type Head struct {
	Seq uint64
	MAC []byte
}

// VerifyReport is what a verification found besides pass or fail.
type VerifyReport struct {
	Head    Head
	Notices []string
}

// SealedOps are the operations on the sealed workspace file.
type SealedOps struct {
	// Init creates the file and returns the recovery key text, shown once.
	Init func(path string, passphrase *secret.Buffer) (recovery *secret.Buffer, err error)
	Open func(path string, passphrase *secret.Buffer, o OpenOptions) (SealedStore, error)
	// OpenRecovery unlocks with the printed recovery key (grouped text).
	OpenRecovery func(path string, recovery *secret.Buffer, o OpenOptions) (SealedStore, error)
	// VerifyFile verifies a workspace or backup file read-only.
	VerifyFile func(path string, passphrase *secret.Buffer) (VerifyReport, error)
	// VerifyFileDeep is VerifyFile that also decrypts every record (store
	// verify --deep). Nil where it is not available.
	VerifyFileDeep func(path string, passphrase *secret.Buffer) (VerifyReport, error)
	Restore        func(backup, dest string, passphrase *secret.Buffer, o RestoreOptions) error
	// RestoreFactors restores a backup of a workspace that unlocks through FIDO2
	// factors, verifying it through them. Nil where it is not available.
	RestoreFactors func(backup, dest string, in FactorOpen, o RestoreOptions) error
	// Migrate converts a workspace file of the old format (records keyed by name)
	// to the current one (ADR 0010 decision 4). Nil where it is not available.
	Migrate func(path string, passphrase *secret.Buffer, o MigrateOptions) (MigrateReport, error)
	// Describe reads the policy and the slots of the file without any key. Nil
	// where it is not available (the command then asks for a passphrase).
	Describe func(path string) (WorkspaceInfo, error)
	// OpenFactors unlocks through a fido2-hmac or composite slot.
	OpenFactors func(path string, in FactorOpen, o OpenOptions) (SealedStore, error)
	// VerifyFileFactors verifies a workspace or backup file read-only, unlocking
	// through its FIDO2 slots (a hardware workspace has no passphrase). deep also
	// decrypts every record.
	VerifyFileFactors func(path string, in FactorOpen, deep bool) (VerifyReport, error)
}

// WorkspaceInfo is the policy and the slot table of a workspace file.
type WorkspaceInfo struct {
	Policy string // standard, hardware or strict
	Slots  []Slot
	// ID, Records and AuditRows are what the file shows without a key: its
	// workspace id and the number of records and audit rows it holds.
	ID        []byte
	Records   int
	AuditRows int
}

// FactorOpen is what a command can present of the factors a slot asks for. A
// nil callback means the command cannot present that factor. Passphrase and
// Recovery return text as typed (the recovery key as printed).
type FactorOpen struct {
	Source     ports.FactorSource
	Device     string
	PIN        func(ctx context.Context) (*secret.Buffer, error)
	Passphrase func(ctx context.Context) (*secret.Buffer, error)
	Recovery   func(ctx context.Context) (*secret.Buffer, error)
	Notify     func(msg string)
}

// RotateRequest is the table a rotation writes. Policy standard: Passphrase is
// the new passphrase and the table is that passphrase and a recovery key.
// hardware: Daily is the authenticator of the fido2-hmac slot and Recovery the
// second authenticator of the recovery composite. strict: Daily only.
type RotateRequest struct {
	// YesRemove are the slot ids (hex) the operator confirmed removing; the store
	// re-checks them against the table inside its transaction (strict rotations).
	YesRemove  []string
	Policy     string
	Passphrase *secret.Buffer
	// ColdPassphrase presents the sub-key passphrase of the new table (standard);
	// under hardware and strict the new daily authenticator (Daily) presents it.
	ColdPassphrase func(ctx context.Context, create bool) (*secret.Buffer, error)
	Daily          FactorOpen
	Recovery       FactorOpen
	// CurrentRecovery presents the workspace's current recovery credential: the
	// recovery key (Recovery returns the printed text) and, under hardware, the
	// recovery composite's second authenticator (Source, Device, PIN). ADR 0011
	// decision 6: the recovery path changes only in a rotation that presents it.
	// A strict workspace has none.
	CurrentRecovery FactorOpen
	// KeepCopy is the path of an explicit copy of the file made before the
	// rotation; it still opens with the old credentials (workspace rotate
	// --keep-copy). Empty makes no copy.
	KeepCopy string
	// LeaveUnreachable names the cold-role records (kind/label) the rotation may
	// leave under their old cold factor (--leave-unreachable); without it a record
	// that cannot be re-established refuses the rotation.
	LeaveUnreachable []string
}

// RemoveSlotRequest is `workspace slot remove`: the slot, what presents the
// factors of the slots that stay (Daily: the daily authenticator and, as
// Passphrase, the passphrase of a passphrase slot), and the current recovery
// credential.
type RemoveSlotRequest struct {
	ID              []byte
	Daily           FactorOpen
	CurrentRecovery FactorOpen
	KeepCopy        string
}

// RecoveryAdmin is the optional interface of a SealedStore that checks the
// current recovery key before the recovery path changes (a rekey).
type RecoveryAdmin interface {
	// PresentRecovery checks the recovery key (as printed) against the workspace.
	PresentRecovery(ctx context.Context, in FactorOpen) error
	// ChangePassphraseKeepRecovery changes the passphrase and keeps the recovery
	// key presented (no new recovery key is made).
	ChangePassphraseKeepRecovery(ctx context.Context, newPassphrase, recoveryText *secret.Buffer) error
}

// FactorReauth is the optional interface of a SealedStore that can ask for a
// fresh presentation of a factor of the slot it unlocked through (the approval
// gate of a factor session).
type FactorReauth interface {
	Reauthenticate(ctx context.Context, in FactorOpen) error
}

// SlotAdmin is the optional interface of a SealedStore that can change its slot
// table (ADR 0011).
type SlotAdmin interface {
	Policy(ctx context.Context) (string, error)
	// AddFIDO2Slot enrols the authenticator named by in and adds a fido2-hmac slot.
	AddFIDO2Slot(ctx context.Context, in FactorOpen) (id []byte, err error)
	// Rotate writes the table of req and returns the new recovery key (nil under
	// strict) and the path of the explicit copy when req.KeepCopy asked for one.
	Rotate(ctx context.Context, req RotateRequest) (recovery *secret.Buffer, backup string, err error)
	// RemoveSlot removes a slot by a rotation that re-creates the others, and
	// returns the new recovery key when a recovery slot or composite stays.
	RemoveSlot(ctx context.Context, req RemoveSlotRequest) (recovery *secret.Buffer, backup string, err error)
}

// MigrateOptions are the operator's choices for `workspace migrate`.
type MigrateOptions struct {
	// Quarantine names the pools to proceed with although their descriptor does
	// not resolve to keys or their records collide.
	Quarantine []string
	// Cold presents the sub-key factor the migration seals cold-role keys under.
	Cold ColdOpen
}

// MigrateReport says what a migration did.
type MigrateReport struct {
	Backup string
	// Backup3 is the copy made before the conversion to store format 3, when the
	// migration ran both steps; Format3Only says the workspace was already in
	// format 2 and Backup is that copy.
	Backup3     string
	Format3Only bool
	Records     int
	Merged      int
	Added       int
	Owners      int
	Rewritten   []string
	Quarantined []string
	Unassigned  []string
	// ColdNoWrap is the number of cold-role records the migration sealed with no
	// recovery wrap.
	ColdNoWrap int
}

// Slot describes a key slot. Nothing in it is secret.
type Slot struct {
	Legacy  bool
	Factors []string
	// Touch is parallel to Factors: for a FIDO2 factor the stored result of the
	// enrolment touch probe as a phrase ("touch not enforced"), else "".
	Touch  []string
	ID     []byte
	Kind   string // "passphrase" or "recovery"
	Detail string // key-derivation parameters of a passphrase slot
}

// SealedStore is an unlocked sealed workspace.
type SealedStore interface {
	// The sealed workspace is the anchor-level store (ADR 0010): the commands
	// reach it by name through labels.Named, and the signers reach its keys
	// through ports.Vault and the key index.
	ports.Store
	ports.Vault
	VerifyDetailed(ctx context.Context) (VerifyReport, error)
	BackupWithHead(ctx context.Context, dest string) (Head, error)
	Slots(ctx context.Context) ([]Slot, error)
	// ChangePassphraseRekey replaces the passphrase and the master key and
	// returns the NEW recovery key; every earlier recovery key is revoked.
	ChangePassphraseRekey(ctx context.Context, newPassphrase *secret.Buffer) (*secret.Buffer, error)
	// RekeyKeepPassphrase replaces the master key, keeping the given current
	// passphrase, and returns the NEW recovery key; earlier ones are revoked.
	RekeyKeepPassphrase(ctx context.Context, current *secret.Buffer) (*secret.Buffer, error)
	// Notices are non-fatal messages from opening.
	Notices() []string
	Head() Head
	Close() error
}

// signerProfile renders a profile for display: role and operations.
func signerProfile(s ports.Signer) (name string, lines []string) {
	p := s.Profile()
	for _, role := range custody.Roles() {
		ops := p.Operations(role)
		if len(ops) == 0 {
			continue
		}
		var names []string
		for _, op := range ops {
			names = append(names, string(op))
		}
		lines = append(lines, string(role)+" -> "+strings.Join(names, ", "))
	}
	return p.Name(), lines
}
