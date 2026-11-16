package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
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
		Wire:         wire,
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
	return out, nil
}

func toConfig(c cli.WorkspaceConfig) config.Config {
	out := config.Config{Network: c.Network, Mode: c.Mode}
	if c.Koios != nil {
		out.Koios = &config.Koios{URL: c.Koios.URL}
	}
	return out
}

func presetFor(network string) (cli.NetworkPreset, bool) {
	p, ok := config.PresetFor(network)
	return cli.NetworkPreset(p), ok
}

// sealedStore adapts *sqlitestore.Store to cli.SealedStore.
type sealedStore struct{ s *sqlitestore.Store }

func (w sealedStore) View(ctx context.Context, fn func(ports.Reader) error) error {
	return w.s.View(ctx, fn)
}
func (w sealedStore) Update(ctx context.Context, fn func(ports.Writer) error) error {
	return w.s.Update(ctx, fn)
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
	return w.s.ChangePassphraseRekey(ctx, p)
}
func (w sealedStore) RekeyKeepPassphrase(ctx context.Context, p *secret.Buffer) (*secret.Buffer, error) {
	return w.s.Rekey(ctx, []sqlitestore.Credential{sqlitestore.PassphraseCredential(p)})
}
func (w sealedStore) Notices() []string { return w.s.Notices() }
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
