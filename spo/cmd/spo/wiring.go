package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/adapters/storeaudit"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// newDeps wires the adapters to the command tree. term may be nil (stdin).
func newDeps(out, errw io.Writer, term cli.Terminal) cli.Deps {
	return cli.Deps{
		Version: version, Release: "none", Out: out, Err: errw, Terminal: term,
		Toolchain: noToolchain{},
		Config: cli.ConfigOps{
			Load:     loadConfig,
			Create:   func(dir string, c cli.WorkspaceConfig) error { return config.Create(dir, toConfig(c)) },
			Save:     func(dir string, c cli.WorkspaceConfig) error { return config.Save(dir, toConfig(c)) },
			Preset:   presetFor,
			Networks: config.Networks,
		},
		Sealed: cli.SealedOps{
			Init: func(path string, pass *secret.Buffer) (*secret.Buffer, error) {
				k, err := sqlitestore.Init(path, pass)
				return k, mapStoreErr(err)
			},
			Open: func(path string, pass *secret.Buffer, o cli.OpenOptions) (cli.SealedStore, error) {
				s, err := sqlitestore.OpenWithOptions(path, pass, sqlitestore.OpenOptions{AcceptRollback: o.AcceptRollback})
				if err != nil {
					return nil, mapStoreErr(err)
				}
				return sealedStore{s}, nil
			},
			OpenRecovery: func(path string, rec *secret.Buffer, o cli.OpenOptions) (cli.SealedStore, error) {
				s, err := sqlitestore.OpenWithRecoveryOptions(path, rec, sqlitestore.OpenOptions{AcceptRollback: o.AcceptRollback})
				if err != nil {
					return nil, mapRecoveryErr(err)
				}
				return sealedStore{s}, nil
			},
			VerifyFile: func(path string, pass *secret.Buffer) (cli.VerifyReport, error) {
				r, err := sqlitestore.VerifyFileDetailed(path, pass)
				return cli.VerifyReport{Head: toHead(r.Head), Notices: r.Notices}, mapStoreErr(err)
			},
			VerifyFileDeep: func(path string, pass *secret.Buffer) (cli.VerifyReport, error) {
				r, err := sqlitestore.VerifyFilePayloads(path, pass)
				return cli.VerifyReport{Head: toHead(r.Head), Notices: r.Notices}, mapStoreErr(err)
			},
			Restore: func(backup, dest string, pass *secret.Buffer, o cli.RestoreOptions) error {
				return mapStoreErr(sqlitestore.RestoreWithOptions(backup, dest, pass, sqlitestore.RestoreOptions{
					Overwrite: o.Overwrite, AllowOlder: o.AllowOlder, AllowOtherWorkspace: o.AllowOtherWorkspace}))
			},
		},
		OpenUpstream: func(dir string) (ports.Store, error) { return fsstore.Open(dir) },
		OpenUpstreamSource: func(dir string) (cli.UpstreamSource, error) {
			s, err := fsstore.Open(dir)
			if err != nil {
				return nil, err
			}
			return readOnlySource{s}, nil
		},
		WorkspaceAuditor: func(dir string, store ports.Store, reason string) ports.WorkspaceAuditor {
			if _, plain := store.(*fsstore.Store); plain {
				store = auditFile{dir: dir}
			}
			return &storeaudit.Auditor{Store: store, Reason: reason}
		},
		RefOfFile: fsstore.RefOf,
		Wire:      func(store ports.Store, o cli.WireOptions) (*cli.Env, error) { return wireTo(errw, store, o) },
		MapError:  mapError,
	}
}

func toHead(h sqlitestore.Head) cli.Head { return cli.Head{Seq: h.Seq, MAC: h.MAC} }

// mapStoreErr maps the sealed store's sentinel errors to the command tree's,
// which turns each into advice. Anything else passes through.
func mapStoreErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sqlitestore.ErrWrongCredential):
		return cli.ErrWrongPassphrase
	case errors.Is(err, sqlitestore.ErrRolledBack):
		return cli.ErrRolledBack
	case errors.Is(err, sqlitestore.ErrHeadMismatch):
		return cli.ErrHeadMismatch
	case errors.Is(err, sqlitestore.ErrLocked):
		return cli.ErrLocked
	case errors.Is(err, sqlitestore.ErrOtherWorkspace):
		return cli.ErrOtherWorkspace
	case errors.Is(err, sqlitestore.ErrOlderBackup):
		return cli.ErrOlderBackup
	case errors.Is(err, sqlitestore.ErrOutcomeUnknown):
		return fmt.Errorf("%w (%v)", cli.ErrOutcomeUnknown, err)
	}
	return err
}

func mapRecoveryErr(err error) error {
	switch {
	case errors.Is(err, sqlitestore.ErrWrongCredential):
		return cli.ErrWrongRecoveryKey
	case errors.Is(err, seal.ErrRecoveryFormat):
		return cli.ErrBadRecoveryKey
	}
	return mapStoreErr(err)
}

func loadConfig(dir string) (cli.WorkspaceConfig, error) {
	c, err := config.Load(dir)
	if err != nil {
		return cli.WorkspaceConfig{}, err
	}
	out := cli.WorkspaceConfig{Network: c.Network, Mode: c.Mode}
	if c.Koios != nil {
		out.Koios = &cli.KoiosConfig{URL: c.Koios.URL}
	}
	if h := c.Hardware; h != nil {
		out.Hardware = &cli.HardwareConfig{WaitSeconds: h.WaitSeconds, MinLedger: h.MinLedger, MinTrezor: h.MinTrezor, MinKeystone: h.MinKeystone}
	}
	if c.Handles != nil {
		out.Handles = &cli.HandlesConfig{URL: c.Handles.URL}
	}
	if c.Registry != nil {
		out.Registry = &cli.RegistryConfig{URL: c.Registry.URL}
	}
	if c.Party != nil {
		out.Party = &cli.PartyConfig{Inbox: c.Party.Inbox, Outbox: c.Party.Outbox}
	}
	if c.Tailcat != nil {
		out.Tailcat = &cli.TailcatConfig{Port: c.Tailcat.Port, DERPMapURL: c.Tailcat.DERPMapURL}
	}
	return out, nil
}

func toConfig(c cli.WorkspaceConfig) config.Config {
	out := config.Config{Network: c.Network, Mode: c.Mode}
	if c.Koios != nil {
		out.Koios = &config.Koios{URL: c.Koios.URL}
	}
	if h := c.Hardware; h != nil {
		out.Hardware = &config.Hardware{WaitSeconds: h.WaitSeconds, MinLedger: h.MinLedger, MinTrezor: h.MinTrezor, MinKeystone: h.MinKeystone}
	}
	if c.Handles != nil {
		out.Handles = &config.Handles{URL: c.Handles.URL}
	}
	if c.Registry != nil {
		out.Registry = &config.Registry{URL: c.Registry.URL}
	}
	if c.Party != nil {
		out.Party = &config.Party{Inbox: c.Party.Inbox, Outbox: c.Party.Outbox}
	}
	if c.Tailcat != nil {
		out.Tailcat = &config.Tailcat{Port: c.Tailcat.Port, DERPMapURL: c.Tailcat.DERPMapURL}
	}
	return out
}

func presetFor(network string) (cli.NetworkPreset, bool) {
	p, ok := config.PresetFor(network)
	return cli.NetworkPreset(p), ok
}

// auditFile keeps the workspace audit log of an upstream-layout directory in
// one file next to the keys, because that layout has no record for it. The
// store holds only that record; the file holds names the operator gave, counts
// and a reason, never key material. It is not part of the upstream layout, so
// an import lists it as an unknown file.
type auditFile struct{ dir string }

// AuditFileName is the audit log of an upstream-layout directory.
const AuditFileName = ".spo-workspace-audit.json"

// legacyAuditFileName is the name before the file became a dotfile; it is read
// when the new one is absent and removed when the log is next written.
const legacyAuditFileName = "spo-workspace-audit.json"

func (a auditFile) path() string { return filepath.Join(a.dir, AuditFileName) }

func (a auditFile) View(_ context.Context, fn func(ports.Reader) error) error {
	return fn(auditTx{a})
}

func (a auditFile) Update(_ context.Context, fn func(ports.Writer) error) error {
	return fn(auditTx{a})
}

type auditTx struct{ a auditFile }

var errAuditOnly = errors.New("this record store holds the audit log only")

func (t auditTx) Get(ref ports.Ref) ([]byte, error) {
	if ref != storeaudit.Ref {
		return nil, errAuditOnly
	}
	b, err := os.ReadFile(t.a.path())
	if errors.Is(err, os.ErrNotExist) {
		b, err = os.ReadFile(filepath.Join(t.a.dir, legacyAuditFileName))
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	return b, err
}

func (t auditTx) Exists(ref ports.Ref) (bool, error) {
	_, err := t.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (t auditTx) Put(ref ports.Ref, data []byte) error {
	if ref != storeaudit.Ref {
		return errAuditOnly
	}
	tmp, err := os.CreateTemp(t.a.dir, ".audit-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), t.a.path()); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(t.a.dir, legacyAuditFileName))
	return nil
}

func (t auditTx) PutSecret(ports.Ref, *secret.Buffer) error { return errAuditOnly }
func (t auditTx) Delete(ports.Ref) error                    { return errAuditOnly }

// readOnlySource is an upstream-layout directory that an import only reads:
// every write is refused, so a mistake in the import cannot change the source.
type readOnlySource struct{ s *fsstore.Store }

var errReadOnlySource = errors.New("the import source is read-only")

func (r readOnlySource) View(ctx context.Context, fn func(ports.Reader) error) error {
	return r.s.View(ctx, fn)
}
func (r readOnlySource) Update(context.Context, func(ports.Writer) error) error {
	return errReadOnlySource
}
func (r readOnlySource) Open(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
	return r.s.Open(ctx, ref)
}
func (r readOnlySource) List(ctx context.Context) (ports.SourceListing, error) { return r.s.List(ctx) }

// sealedStore adapts *sqlitestore.Store to cli.SealedStore.
type sealedStore struct{ s *sqlitestore.Store }

func (w sealedStore) View(ctx context.Context, fn func(ports.Reader) error) error {
	return w.s.View(ctx, fn)
}
func (w sealedStore) Update(ctx context.Context, fn func(ports.Writer) error) error {
	return mapStoreErr(w.s.Update(ctx, fn))
}
func (w sealedStore) Open(ctx context.Context, ref ports.Ref) (*secret.Buffer, error) {
	return w.s.Open(ctx, ref)
}
func (w sealedStore) VerifyDetailed(ctx context.Context) (cli.VerifyReport, error) {
	r, err := w.s.VerifyDetailed(ctx)
	return cli.VerifyReport{Head: toHead(r.Head), Notices: r.Notices}, err
}
func (w sealedStore) BackupWithHead(ctx context.Context, dest string) (cli.Head, error) {
	h, err := w.s.BackupWithHead(ctx, dest)
	return toHead(h), err
}
func (w sealedStore) ChangePassphraseRekey(ctx context.Context, p *secret.Buffer) (*secret.Buffer, error) {
	key, err := w.s.ChangePassphraseRekey(ctx, p)
	return key, mapStoreErr(err)
}
func (w sealedStore) RekeyKeepPassphrase(ctx context.Context, p *secret.Buffer) (*secret.Buffer, error) {
	key, err := w.s.Rekey(ctx, []sqlitestore.Credential{sqlitestore.PassphraseCredential(p)})
	return key, mapStoreErr(err)
}

// List enumerates the artefacts of the sealed workspace (ports.SourceLister),
// for the workspace export.
func (w sealedStore) List(ctx context.Context) (ports.SourceListing, error) { return w.s.List(ctx) }
func (w sealedStore) Notices() []string                                     { return w.s.Notices() }
func (w sealedStore) Head() cli.Head {
	seq, mac := w.s.Head()
	return cli.Head{Seq: seq, MAC: mac}
}
func (w sealedStore) Close() error { return w.s.Close() }

// Cleanup finishes a rekey (sqlitestore.Store.Cleanup); the commands reach it
// through an optional interface.
func (w sealedStore) Cleanup(ctx context.Context) error { return w.s.Cleanup(ctx) }
func (w sealedStore) Slots(ctx context.Context) ([]cli.Slot, error) {
	in, err := w.s.Slots(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]cli.Slot, 0, len(in))
	for _, x := range in {
		d := ""
		if x.Kind == "passphrase" {
			d = fmt.Sprintf("argon2id %d MiB, %d passes, %d lanes", x.KDF.MemoryKiB/1024, x.KDF.Passes, x.KDF.Lanes)
		}
		out = append(out, cli.Slot{ID: x.ID, Kind: x.Kind, Detail: d})
	}
	return out, nil
}
