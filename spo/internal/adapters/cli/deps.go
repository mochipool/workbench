package cli

import (
	"context"
	"errors"
	"io"
	"strings"

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
	Sealed SealedOps

	// OpenUpstream opens a directory in the upstream scripts' file layout,
	// where signing keys are not sealed (--upstream-layout).
	OpenUpstream func(dir string) (ports.Store, error)

	// Wire builds the Env a command runs in, from the open store (nil to
	// only inspect what the configuration yields) and the options. It
	// constructs; it does not touch the network. Adding a command never
	// needs a change here.
	Wire func(store ports.Store, o WireOptions) (*Env, error)

	// Genesis returns the genesis files the release set bundles for a
	// network, or ok=false when the binary has no manifest or no entry.
	Genesis func(network string) (shelley, byron string, ok bool)
}

// WorkspaceConfig mirrors spo.toml (see adapters/config).
type WorkspaceConfig struct {
	Network string
	Mode    string
	Koios   *KoiosConfig // nil: no Koios provider configured
}

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
}

// Slot describes a key slot. Nothing in it is secret.
type Slot struct {
	ID     []byte
	Kind   string // "passphrase" or "recovery"
	Detail string // key-derivation parameters of a passphrase slot
}

// SealedStore is an unlocked sealed workspace.
type SealedStore interface {
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
