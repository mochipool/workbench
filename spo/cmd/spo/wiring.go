package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/exportdir"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c"
	"github.com/mochipool/workbench/spo/internal/adapters/nodeage"
	objdir "github.com/mochipool/workbench/spo/internal/adapters/objstore/dir"
	objs3 "github.com/mochipool/workbench/spo/internal/adapters/objstore/s3"
	"github.com/mochipool/workbench/spo/internal/adapters/scratchdir"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/adapters/storeaudit"
	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/app/backupsink"
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
		NodeAddressWarning: func(addr string) string {
			if n2c.IsPlainTCP(addr) {
				return n2c.WarnPlainTCP
			}
			return ""
		},
		OpenSink:    openSink,
		OpenScratch: func(dir string) (ports.Scratch, error) { return scratchdir.Open(dir) },
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
			Describe: describe,
			InspectHead: func(path string) ([]byte, cli.Head, error) {
				id, h, err := sqlitestore.InspectHead(path)
				return id, toHead(h), mapStoreErr(err)
			},
			InspectFacts: func(path string) (cli.BackupFacts, error) {
				f, err := sqlitestore.InspectBackupFacts(path)
				return cli.BackupFacts{WorkspaceID: f.WorkspaceID, Head: toHead(f.Head), SlotTable: f.SlotTable}, mapStoreErr(err)
			},
			OpenFactors:       openFactors,
			VerifyFileFactors: verifyFileFactors,
			Migrate: func(path string, pass *secret.Buffer, o cli.MigrateOptions) (cli.MigrateReport, error) {
				s, err := sqlitestore.OpenLegacy(path, pass)
				if errors.Is(err, sqlitestore.ErrFormat2) {
					// Not format 1: a format 2 workspace needs only the second step.
					s2, err := sqlitestore.OpenFormat2(path, pass)
					if err != nil {
						return cli.MigrateReport{}, mapStoreErr(err)
					}
					defer s2.Close()
					s2.SetColdSource(coldSource(o.Cold))
					r, err := s2.Migrate3(context.Background(), "")
					if err != nil {
						return cli.MigrateReport{}, mapStoreErr(err)
					}
					return cli.MigrateReport{Backup: r.Backup, Format3Only: true, ColdNoWrap: r.ColdNoWrap}, nil
				}
				if err != nil {
					return cli.MigrateReport{}, mapStoreErr(err)
				}
				defer s.Close()
				s.SetColdSource(coldSource(o.Cold))
				r, err := s.Migrate(context.Background(), sqlitestore.MigrateOptions{Quarantine: o.Quarantine})
				if err != nil {
					return cli.MigrateReport{}, mapStoreErr(err)
				}
				return cli.MigrateReport{Backup: r.Backup, Backup3: r.Backup3, Records: r.Records, Merged: r.Merged, Added: r.Added, Owners: r.Owners,
					Rewritten: r.Rewritten, Quarantined: r.Quarantined, Unassigned: r.Unassigned, ColdNoWrap: r.ColdNoWrap}, nil
			},
			Restore: func(backup, dest string, pass *secret.Buffer, o cli.RestoreOptions) error {
				so, done := restoreOptionsReporting(o)
				err := mapStoreErr(sqlitestore.RestoreWithOptions(backup, dest, pass, so))
				done()
				return err
			},
			RestoreFactors: func(backup, dest string, in cli.FactorOpen, o cli.RestoreOptions) error {
				so, done := restoreOptionsReporting(o)
				err := mapStoreErr(sqlitestore.RestoreWithFactors(backup, dest, factorInputs(in), so))
				done()
				return err
			},
		},
		// A plain-directory workspace is wired only by a build with the
		// plainlayout tag (wiring_plain.go) and by tests; nil here.
		OpenUpstream: openPlain,
		OpenUpstreamSource: func(dir string) (cli.UpstreamSource, error) {
			return upstreamdir.Open(dir)
		},
		HotSealer:     nodeage.Sealer{},
		HotDeriver:    native.HotKeyDeriver{},
		OpenExportDir: func(dir string) (ports.NamedStore, error) { return exportdir.Open(dir) },
		WorkspaceAuditor: func(dir string, store ports.NamedStore, reason string) ports.WorkspaceAuditor {
			if plainAudit != nil {
				store = plainAudit(dir, store)
			}
			return &storeaudit.Auditor{Store: store, Reason: reason}
		},
		Wire:     func(store ports.Store, o cli.WireOptions) (*cli.Env, error) { return wireTo(errw, store, o) },
		MapError: mapError,
	}
}

func toHead(h sqlitestore.Head) cli.Head { return cli.Head{Seq: h.Seq, MAC: h.MAC} }

// credentialRefusal is the store's refusal for a destination whose credential was
// not presented, kept whole (message and chain) and also matching
// cli.ErrCountersNeedCredential.
type credentialRefusal struct{ err error }

func (e *credentialRefusal) Error() string        { return e.err.Error() }
func (e *credentialRefusal) Unwrap() error        { return e.err }
func (e *credentialRefusal) Is(target error) bool { return target == cli.ErrCountersNeedCredential }

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
	case errors.Is(err, sqlitestore.ErrCountersNeedCredential):
		return &credentialRefusal{err}
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
	if c.Blockfrost != nil {
		out.Blockfrost = &cli.BlockfrostConfig{URL: c.Blockfrost.URL, TokenRecord: c.Blockfrost.TokenRecord}
	}
	if c.Node != nil {
		out.Node = &cli.NodeConfig{Address: c.Node.Address, TimeoutSeconds: c.Node.TimeoutSeconds}
	}
	out.Order = c.Order
	out.SameHostOK = c.SameHostOK
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
	if c.Blockfrost != nil {
		out.Blockfrost = &config.Blockfrost{URL: c.Blockfrost.URL, TokenRecord: c.Blockfrost.TokenRecord}
	}
	if c.Node != nil {
		out.Node = &config.Node{Address: c.Node.Address, TimeoutSeconds: c.Node.TimeoutSeconds}
	}
	out.Order = c.Order
	out.SameHostOK = c.SameHostOK
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

// openPlain opens a plain upstream-layout directory as a workspace. It is nil
// in the release binary: the writable plain store is not part of it
// (SPO-Xcustody-INV-001). wiring_plain.go sets it under the plainlayout tag,
// and tests set it for the length of a test.
var openPlain func(dir string) (ports.Store, error)

// plainAudit gives a plain directory a place for its audit log (it has no
// record store); it returns any other store unchanged. Nil in the release.
var plainAudit func(dir string, store ports.NamedStore) ports.NamedStore

// sealedStore adapts *sqlitestore.Store to cli.SealedStore.
type sealedStore struct{ s *sqlitestore.Store }

// DailyCredentialIDs lists the credential ids of the daily slots (the checkpoint
// key may not be one).
func (w sealedStore) DailyCredentialIDs(ctx context.Context) ([][]byte, error) {
	ids, err := w.s.DailyCredentialIDs(ctx)
	return ids, mapStoreErr(err)
}

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
		if x.Legacy {
			d += " legacy (rekey to bind policy): sealed before store format 3, it binds no policy and no recovery key"
		}
		if len(x.Factors) > 1 || x.Kind == "fido2-hmac" || x.Kind == "composite" {
			var fs []string
			for _, f := range x.Factors {
				fs = append(fs, f.Kind)
			}
			d = strings.Join(fs, " + ")
		}
		out = append(out, cli.Slot{ID: x.ID, Kind: x.Kind, Detail: d})
	}
	return out, nil
}

// restoreOptions maps the command tree's restore choices to the store's.
func restoreOptions(o cli.RestoreOptions) sqlitestore.RestoreOptions {
	out := sqlitestore.RestoreOptions{AcceptLowerCounters: o.AcceptLowerCounters, ExpectedSHA256: o.ExpectedSHA256, Overwrite: o.Overwrite, AllowOlder: o.AllowOlder, AllowOtherWorkspace: o.AllowOtherWorkspace, AllowWeakerPolicy: o.AllowWeakerPolicy}
	if o.CurrentRecovery != nil {
		in := factorInputs(*o.CurrentRecovery)
		out.CurrentRecovery = &in
	}
	return out
}

// restoreOptionsReporting is restoreOptions with the store's report of the
// counter rule; done copies it into the command's report once the restore is over.
func restoreOptionsReporting(o cli.RestoreOptions) (sqlitestore.RestoreOptions, func()) {
	so := restoreOptions(o)
	var rep sqlitestore.RestoreReport
	so.Report = &rep
	return so, func() {
		if o.Report == nil {
			return
		}
		o.Report.LowerAccepted = rep.LowerAccepted
		o.Report.HeadAhead = rep.HeadAhead
		for _, c := range rep.Carried {
			o.Report.Carried = append(o.Report.Carried, cli.CarriedCounter{Pool: c.Pool, Kind: c.Kind, Live: c.Live, Backup: c.Backup})
		}
	}
}

// openSink builds a backup sink from its URL: s3://bucket/prefix or
// dir:/absolute/path. The S3 adapter is constructed only for an s3:// URL, and
// construction makes no network call.
func openSink(ctx context.Context, url string) (backupsink.Sink, error) {
	switch {
	case strings.HasPrefix(url, "dir:"):
		d, err := objdir.Open(strings.TrimPrefix(url, "dir:"))
		if err != nil {
			return backupsink.Sink{}, err
		}
		return backupsink.Sink{Kind: ports.SinkDir, Writer: d, Reader: d, Lister: d, Ranger: d, Probe: d}, nil
	case strings.HasPrefix(url, "s3://"):
		bucket, prefix, _ := strings.Cut(strings.TrimPrefix(url, "s3://"), "/")
		s, err := objs3.New(ctx, bucket, prefix)
		if err != nil {
			return backupsink.Sink{}, err
		}
		return backupsink.Sink{Kind: ports.SinkS3, Writer: s, Reader: s, Lister: s, Ranger: s, Probe: s}, nil
	}
	return backupsink.Sink{}, errors.New("a sink is s3://bucket/prefix or dir:/absolute/path")
}
