package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/workspace"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// gpgNeed is the sentence a refusal for the missing gpg tool carries.
const gpgNote = "gpg is needed only for upstream's encrypted signing keys"

// plaintextWord is what the operator types to confirm that signing keys are
// written unprotected.
const plaintextWord = "plaintext"

func (a *app) workspaceCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "workspace",
		Short: "Move an upstream-layout directory into the sealed workspace, and back out",
		Long: `The sealed workspace holds every key protected. An existing directory in the
upstream scripts' file layout (what gitmachtl/scripts wrote) is brought in with
import; export writes the files out again for the upstream scripts, which is a
dangerous operation and is recorded in the workspace's audit log.`,
	}
	c.AddCommand(a.workspaceImportCommand(), a.workspaceExportCommand())
	return c
}

func (a *app) keyCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "Upstream-layout signing key files: encrypt or decrypt one in place",
		Long: `The encrypted form of a signing key file is upstream's: a gpg symmetric
envelope with the password hashed as upstream's prompt does. These commands work
on a plain upstream-layout directory (--upstream-layout) only: a key in the
sealed workspace is always protected.`,
	}
	c.AddCommand(a.keyProtectCommand(false), a.keyProtectCommand(true))
	return c
}

// ---- reports ----

// statusText is one word per status.
func statusText(s workspace.Status) string { return string(s) }

func artefactName(r ports.Ref) string {
	if r.Kind.Numbered() {
		return fmt.Sprintf("%s.%s#%d", r.Name, r.Kind, r.Num)
	}
	return r.Name + "." + string(r.Kind)
}

// printWorkspaceReport writes the report as a table: owner, artefact, status,
// reason. It holds names, kinds and the use case's reasons, no key material.
func printWorkspaceReport(w io.Writer, rep *workspace.Report, protection func(ports.Ref) string) {
	fmt.Fprintf(w, "%-20s %-40s %-8s %s\n", "OWNER", "ARTEFACT", "STATUS", "REASON")
	for _, o := range rep.Owners {
		if len(o.Artefacts) == 0 {
			fmt.Fprintf(w, "%-20s %-40s %-8s %s\n", shownAny(o.Owner), "-", "failed", shownAny(o.Reason))
		}
		for _, ar := range o.Artefacts {
			why := ar.Reason
			if why == "" {
				why = ar.Note
			} else if ar.Note != "" {
				why += "; " + ar.Note
			}
			if protection != nil && ar.Status == workspace.StatusDone {
				if p := protection(ar.Ref); p != "" {
					if why != "" {
						why += "; "
					}
					why += p
				}
			}
			fmt.Fprintf(w, "%-20s %-40s %-8s %s\n", shownAny(o.Owner), artefactName(ar.Ref), statusText(ar.Status), shownAny(why))
		}
	}
	for _, u := range rep.Unknown {
		fmt.Fprintf(w, "%-20s %-40s %-8s %s\n", "-", shownAny(u.File), "ignored", shownAny(u.Reason))
	}
	for _, x := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", shownAny(x))
	}
}

// ---- import ----

func (a *app) workspaceImportCommand() *cobra.Command {
	var (
		owners        []string
		passFD        int
		keepEncrypted bool
		overwrite     bool
	)
	cmd := &cobra.Command{
		Use:   "import <dir> [--owner NAME]... [--password-fd N] [--keep-encrypted] [--overwrite]",
		Short: "Bring the pools and wallets of an upstream-layout directory into the sealed workspace",
		Long: `Read <dir> (never changed) and store what it holds in the sealed workspace,
checking each signing key against its verification key and each address against
its keys. An owner is imported whole or not at all: one failed artefact leaves
the owner out. Names that are not pools or wallets of the catalogue are listed
and ignored.

A key that upstream encrypted needs its password: --password-fd N reads it from a
descriptor, else it is asked for without echo when such a key is met. --keep-encrypted
imports it in upstream's encrypted form without decrypting. An existing artefact
is kept and its owner refused unless --overwrite.

The result is a table of owner, artefact, status and reason; it never shows key
material. The exit status is not zero when any owner failed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("workspace import writes into a sealed workspace; it does not apply with --upstream-layout")
			}
			if a.d.OpenUpstreamSource == nil {
				return errors.New("the upstream layout is not available in this build")
			}
			spec := envSpec{needs: []Need{CapVKeyDerive, CapAddress}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				src, err := a.d.OpenUpstreamSource(args[0])
				if err != nil {
					return err
				}
				if sameDir(args[0], a.workspace) {
					return fmt.Errorf("%s is the workspace itself", args[0])
				}
				pw, err := a.importPassword(ctx, src, env, passFD, keepEncrypted)
				if err != nil {
					return err
				}
				defer pw.Destroy()
				uc := workspace.ImportWorkspace{Source: src, SourceVault: src, Lister: src, Dest: s.Store,
					Decryptor: env.KeyDecryptor, Deriver: env.VKeyDeriver, Addresses: env.AddressInspector}
				rep, err := uc.Run(ctx, workspace.ImportOptions{Owners: owners, Password: pw, KeepEncrypted: keepEncrypted, Overwrite: overwrite})
				if rep != nil {
					printWorkspaceReport(a.d.Out, rep, nil)
					fmt.Fprintf(a.d.Out, "\n%d owner(s) of %d imported, %d artefact(s) written.\n", len(rep.Owners)-rep.Failed(), len(rep.Owners), rep.Done())
				}
				if err != nil {
					return err
				}
				if n := rep.Failed(); n > 0 {
					return fmt.Errorf("%d owner(s) were not imported; nothing of them was written", n)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&owners, "owner", nil, "import only this pool or wallet (repeatable; default: all)")
	cmd.Flags().IntVar(&passFD, "password-fd", -1, "read the password of upstream's encrypted keys from this inherited file descriptor (trailing newline stripped); there is no password flag or variable")
	cmd.Flags().BoolVar(&keepEncrypted, "keep-encrypted", false, "import upstream-encrypted keys in their encrypted form instead of decrypting them (no password, no gpg)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace artefacts that already exist in the workspace (default: refuse the owner)")
	return cmd
}

// importPassword returns the password of the encrypted keys, or nil when the
// source holds none that needs it. A descriptor is read when given; otherwise
// the source is looked at, and the password is asked for without echo only if an
// encrypted key is met and the import is to decrypt it. gpg is required before
// the password is asked for.
func (a *app) importPassword(ctx context.Context, src UpstreamSource, env *Env, fd int, keep bool) (*ports.Secret, error) {
	if keep && fd < 0 {
		return nil, nil
	}
	if fd >= 0 {
		if err := env.Require(CapKeyCrypto); err != nil {
			return nil, withGPGNote(err)
		}
		if a.passFD == fd {
			return nil, errors.New("--password-fd and --passphrase-fd name the same descriptor")
		}
		return readFDSecret(fd, "the password of the encrypted keys")
	}
	n, err := encryptedKeys(ctx, src)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if err := env.Require(CapKeyCrypto); err != nil {
		return nil, withGPGNote(fmt.Errorf("the directory holds %d key(s) that upstream encrypted: %w", n, err))
	}
	p, err := a.term.ReadSecret(ctx, "Password of the upstream-encrypted keys: ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, errors.New("the directory holds keys that upstream encrypted and there is no terminal to ask for their password on; give it on a file descriptor with --password-fd N, or pass --keep-encrypted")
	}
	return p, err
}

func withGPGNote(err error) error {
	return &explained{msg: err.Error() + "\n" + gpgNote + "; without it, pass --keep-encrypted to import such a key undecrypted", err: err}
}

// encryptedKeys counts the signing keys of the source that are in upstream's
// encrypted form.
func encryptedKeys(ctx context.Context, src UpstreamSource) (int, error) {
	l, err := src.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range l.Entries {
		if !e.Ref.Kind.IsSigningKey() {
			continue
		}
		buf, err := src.Open(ctx, e.Ref)
		if err != nil {
			continue // the import reports it
		}
		_ = buf.Use(func(b []byte) error {
			if info, cerr := keyfile.Classify(b); cerr == nil && info.Form == keyfile.FormEncrypted {
				n++
			}
			return nil
		})
		buf.Destroy()
	}
	return n, nil
}

// ---- export ----

func (a *app) workspaceExportCommand() *cobra.Command {
	var (
		owners    []string
		passFD    int
		plaintext bool
		overwrite bool
		yes       bool
		reason    string
	)
	cmd := &cobra.Command{
		Use:   "export <dir> [--owner NAME]... (--password-fd N | --plaintext) [--overwrite] [--reason TEXT] [--yes]",
		Short: "Write pools and wallets out of the sealed workspace in the upstream file layout",
		Long: `Write the files the upstream scripts expect into <dir>, which must be new or
empty (--overwrite writes into a directory that is not). You must say how the
signing keys leave:

  --password-fd N   encrypt each signing key in upstream's gpg form with the
                    password read from that descriptor (needs gpg)
  --plaintext       write them in CLEAR, as upstream stores them. You must type
                    the word "` + plaintextWord + `" to confirm (--yes types it for you)

Mnemonics have no protected form and are written only with --plaintext.

The export is recorded in the workspace's audit log, with --reason, BEFORE any
key is written, and is not made when the record cannot be. The directory holds
every secret you export: put it on storage you control and remove it afterwards.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("workspace export reads the sealed workspace; it does not apply with --upstream-layout")
			}
			protected := passFD >= 0
			switch {
			case protected && plaintext:
				return errors.New("choose one: --password-fd N protects the signing keys, --plaintext writes them in clear")
			case !protected && !plaintext:
				return errors.New("say how the signing keys leave the workspace: --password-fd N (encrypt them in upstream's form) or --plaintext (write them in clear)")
			}
			if a.passFD == passFD && protected {
				return errors.New("--password-fd and --passphrase-fd name the same descriptor")
			}
			if a.d.OpenUpstream == nil || a.d.WorkspaceAuditor == nil {
				return errors.New("the upstream layout is not available in this build")
			}
			needs := []Need{}
			if protected {
				needs = append(needs, CapKeyCrypto)
			}
			return a.withEnv(cmd, envSpec{needs: needs}, func(ctx context.Context, s *session, env *Env, _ WireOptions) (err error) {
				if s.Sealed == nil {
					return errors.New("workspace export reads the sealed workspace")
				}
				lister, ok := any(s.Sealed).(ports.SourceLister)
				if !ok {
					return errors.New("this build's sealed workspace cannot list its artefacts")
				}
				if sameDir(args[0], a.workspace) {
					return fmt.Errorf("%s is the workspace directory: export into another directory", args[0])
				}
				if plaintext {
					ok, err := a.confirmPlaintext(ctx, args[0], yes)
					if err != nil {
						return err
					}
					if !ok {
						return errors.New("the export was declined: nothing was written")
					}
				}
				var pw *ports.Secret
				if protected {
					pw, err = readFDSecret(passFD, "the export password")
					if err != nil {
						return err
					}
					defer pw.Destroy()
				}
				created, err := prepareExportDir(args[0], overwrite)
				if err != nil {
					return err
				}
				dest, err := a.d.OpenUpstream(args[0])
				if err != nil {
					return err
				}
				uc := workspace.ExportWorkspace{Source: s.Store, SourceVault: s.Sealed, Lister: lister, Dest: dest,
					Encryptor: env.KeyEncryptor, Decryptor: env.KeyDecryptor, Auditor: a.d.WorkspaceAuditor(a.workspace, s.Store, reason)}
				rep, err := uc.Run(ctx, workspace.ExportOptions{Owners: owners, Password: pw, PlaintextAcknowledged: plaintext, Overwrite: overwrite})
				if rep != nil {
					printWorkspaceReport(a.d.Out, rep, exportProtection(protected))
					fmt.Fprintf(a.d.Out, "\n%d owner(s) of %d exported to %s, %d artefact(s) written.\n", len(rep.Owners)-rep.Failed(), len(rep.Owners), args[0], rep.Done())
					if rep.Done() > 0 {
						if plaintext {
							fmt.Fprintf(a.d.Out, "The signing keys in %s are in CLEAR. Remove the directory when you are done.\n", args[0])
						} else {
							fmt.Fprintf(a.d.Out, "The signing keys in %s are encrypted in upstream's form with the password you gave.\n", args[0])
						}
					}
				}
				if created && (rep == nil || rep.Done() == 0) {
					_ = os.Remove(args[0]) // only an empty directory goes
				}
				if err != nil {
					return err
				}
				if n := rep.Failed(); n > 0 {
					return fmt.Errorf("%d owner(s) were not exported", n)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&owners, "owner", nil, "export only this pool or wallet (repeatable; default: all)")
	cmd.Flags().IntVar(&passFD, "password-fd", -1, "encrypt the signing keys with the password read from this inherited file descriptor (trailing newline stripped); there is no password flag or variable")
	cmd.Flags().BoolVar(&plaintext, "plaintext", false, "write the signing keys in clear, as upstream stores them (asks you to type \""+plaintextWord+"\")")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "write into a directory that is not empty, replacing files of the same name")
	cmd.Flags().BoolVar(&yes, "yes", false, "type \""+plaintextWord+"\" for --plaintext")
	cmd.Flags().StringVar(&reason, "reason", "", "why the keys are exported; recorded in the audit log (not secret: no key material)")
	cmd.MarkFlagsMutuallyExclusive("password-fd", "plaintext")
	cmd.MarkFlagsOneRequired("password-fd", "plaintext")
	return cmd
}

// exportProtection says how an exported artefact is protected, for the table.
func exportProtection(protected bool) func(ports.Ref) string {
	return func(r ports.Ref) string {
		switch {
		case r.Kind == ports.UpstreamEncryptedSKey:
			return "encrypted"
		case r.Kind.IsSigningKey() && protected:
			return "encrypted"
		case r.Kind.Secret():
			return "PLAINTEXT"
		}
		return ""
	}
}

// confirmPlaintext asks the operator to type the word, or accepts --yes.
func (a *app) confirmPlaintext(ctx context.Context, dir string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	fmt.Fprintf(a.d.Err, "Signing keys and mnemonics will be written to %s in CLEAR, unprotected.\n", dir)
	ans, err := a.term.ReadLine(ctx, "Type "+plaintextWord+" to go on: ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on; pass --yes to confirm the plaintext export")
	}
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(ans) == plaintextWord, nil
}

// prepareExportDir makes sure the destination is a new or empty directory (or
// any directory with --overwrite) and creates it when absent. It reports
// whether it created it.
func prepareExportDir(dir string, overwrite bool) (created bool, err error) {
	st, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return false, err
		}
		return true, nil
	case err != nil:
		return false, err
	case !st.IsDir():
		return false, fmt.Errorf("%s exists and is not a directory", dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	if len(ents) > 0 && !overwrite {
		names := make([]string, 0, 3)
		for _, e := range ents {
			if len(names) < 3 {
				names = append(names, filepath.Base(e.Name()))
			}
		}
		sort.Strings(names)
		return false, fmt.Errorf("%s is not empty (it holds %s ...): export into a new directory, or pass --overwrite", dir, strings.Join(names, ", "))
	}
	return false, nil
}

// ---- key protect, unprotect ----

func (a *app) keyProtectCommand(unprotect bool) *cobra.Command {
	var (
		passFD int
		yes    bool
		reason string
	)
	use, short := "protect", "Encrypt a plain signing key file in place, in upstream's form"
	if unprotect {
		use, short = "unprotect", "Decrypt an upstream-encrypted signing key file in place, back to clear text"
	}
	cmd := &cobra.Command{
		Use:   use + " <file> [--password-fd N]" + map[bool]string{true: " [--reason TEXT] [--yes]"}[unprotect],
		Short: short,
		Long: `<file> is the upstream name of a signing key in the directory (for example
mypool.node.skey or mywallet.skey). Needs --upstream-layout: in the sealed
workspace every key is protected already. The password must be strong in upstream's
sense (10 characters, lower case, upper case, a digit and a special character).
It is read from --password-fd N, else asked for without echo. gpg is needed.` + map[bool]string{true: `

Unprotect writes the key in CLEAR and is recorded in the audit log, with
--reason. You must type "` + plaintextWord + `" to confirm; --yes types it for you.`}[unprotect],
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !a.upstream {
				// The use case's typed refusal, with the way out.
				var err error
				if unprotect {
					err = workspace.UnprotectKey{Sealed: true}.Run(cmd.Context(), ports.Ref{}, nil, false)
				} else {
					err = workspace.ProtectKey{Sealed: true}.Run(cmd.Context(), ports.Ref{}, nil)
				}
				return &explained{msg: err.Error() + "; to " + use + " a key of a plain upstream-layout directory, pass --upstream-layout", err: err}
			}
			if a.d.RefOfFile == nil {
				return errors.New("the upstream layout is not available in this build")
			}
			ref, ok := a.d.RefOfFile(filepath.Base(args[0]))
			if !ok || !ref.Kind.IsSigningKey() {
				return fmt.Errorf("%s is not the name of a signing key file in the upstream layout", args[0])
			}
			if unprotect && a.d.WorkspaceAuditor == nil {
				return errors.New("the upstream layout is not available in this build")
			}
			spec := envSpec{needs: []Need{CapKeyCrypto}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				vault, ok := s.Store.(ports.Vault)
				if !ok {
					return errors.New("the store cannot release signing keys")
				}
				if unprotect {
					okc, err := a.confirmPlaintext(ctx, args[0], yes)
					if err != nil {
						return err
					}
					if !okc {
						return errors.New("declined: the key file was not changed")
					}
				}
				pw, err := a.keyPassword(ctx, passFD, !unprotect)
				if err != nil {
					return err
				}
				defer pw.Destroy()
				if unprotect {
					err = workspace.UnprotectKey{Store: s.Store, Vault: vault, Decryptor: env.KeyDecryptor,
						Auditor: a.d.WorkspaceAuditor(a.workspace, s.Store, reason)}.Run(ctx, ref, pw, true)
				} else {
					err = workspace.ProtectKey{Store: s.Store, Vault: vault, Encryptor: env.KeyEncryptor, Decryptor: env.KeyDecryptor}.Run(ctx, ref, pw)
				}
				if err != nil {
					return err
				}
				if unprotect {
					fmt.Fprintf(a.d.Out, "%s is now in CLEAR.\n", args[0])
				} else {
					fmt.Fprintf(a.d.Out, "%s is now encrypted in upstream's form.\n", args[0])
				}
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&passFD, "password-fd", -1, "read the password from this inherited file descriptor (trailing newline stripped); there is no password flag or variable")
	if unprotect {
		cmd.Flags().BoolVar(&yes, "yes", false, "type \""+plaintextWord+"\" for you")
		cmd.Flags().StringVar(&reason, "reason", "", "why the key is written in clear; recorded in the audit log")
	}
	return cmd
}

// keyPassword reads a password from the descriptor, else without echo (twice
// when it is a new one).
func (a *app) keyPassword(ctx context.Context, fd int, confirm bool) (*ports.Secret, error) {
	if fd >= 0 {
		if a.passFD == fd {
			return nil, errors.New("--password-fd and --passphrase-fd name the same descriptor")
		}
		return readFDSecret(fd, "the password")
	}
	p, err := a.term.ReadSecret(ctx, "Password: ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, errors.New("no terminal to ask for the password on; give it on a file descriptor with --password-fd N")
	}
	if err != nil {
		return nil, err
	}
	if confirm {
		again, err := a.term.ReadSecret(ctx, "Repeat the password: ")
		if err != nil {
			p.Destroy()
			return nil, err
		}
		same := equalSecrets(p, again)
		again.Destroy()
		if !same {
			p.Destroy()
			return nil, errors.New("the two entries differ; nothing was changed")
		}
	}
	return p, nil
}
