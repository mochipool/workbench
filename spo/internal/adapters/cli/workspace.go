package cli

import (
	"context"
	"crypto/rand"
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
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/secretfd"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// gpgNeed is the sentence a refusal for the missing gpg tool carries.
const gpgNote = "gpg is needed only for upstream's encrypted signing keys"

func (a *app) workspaceCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "workspace",
		Short: "Bring an upstream-layout directory into the sealed workspace, and write one out, encrypted",
		Long: `The sealed workspace holds every key protected, and this program never writes a
signing key or any other secret unprotected. An existing directory in the
upstream scripts' file layout (what gitmachtl/scripts wrote) is brought in with
import, which only reads it. Export writes the files out again for the upstream
scripts with every signing key encrypted in upstream's gpg form; it is recorded
in the workspace's audit log.`,
	}
	c.AddCommand(a.workspaceImportCommand(), a.workspaceExportCommand(), a.workspaceMigrateCommand(), a.workspaceSlotCommand(), a.workspacePolicyCommand(), a.workspaceRotateCommand())
	return c
}

// workspaceMigrateCommand is `workspace migrate`: it converts a workspace of the
// old format (records keyed by the operator's names) to the current one, where
// every record is keyed by the anchor identity of its owner and a name is a label
// (ADR 0010 decision 4).
//
// spec: SPO-Xidentity-IF-005
func (a *app) workspaceMigrateCommand() *cobra.Command {
	var quarantine []string
	var removeCopies bool
	cmd := &cobra.Command{
		Use:   "migrate [--quarantine POOL]...",
		Short: "Convert a workspace of the old format (records keyed by name) to the current one",
		Long: `A workspace made by an earlier version keys every record by the name of its
owner. This version keys records by the identity of their owner and keeps a name
as a label. migrate converts the file in place, in one transaction: every record
is sealed again under the same master key, the owners and their anchors are found
from the keys the workspace holds (a pool by its cold key, a wallet by its payment
key, else its stake key), each pool descriptor's owners and reward account are
rewritten from names to key hashes, and the witness slots of an open registration
get the fingerprint of their party.

It first makes a copy of the file beside it (<file>.pre-migrate-v1) and says where.
A workspace of store format 2 (identity-keyed records, no slot kinds or policy) is
converted to format 3 in one transaction after a copy named <file>.pre-migrate-v2:
the policy becomes standard and the passphrase and recovery slots are unchanged.
It refuses, with a list and without changing anything, when a name in a descriptor
resolves to no key or its registration data disagrees with the keys, when one key
would belong to two owners, or when two records that become one differ.
--quarantine POOL lets the migration go on for a pool whose own problems those
are, and leaves that pool unusable until you fix it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("migrate works on a sealed workspace; it does not apply with --upstream-layout")
			}
			if a.d.Sealed.Migrate == nil {
				return errors.New("workspace migrate is not available in this build")
			}
			ctx := cmd.Context()
			if !exists(a.workspaceFile()) {
				return fmt.Errorf("no workspace in %s (%s not found)", a.workspace, WorkspaceFile)
			}
			pass, err := a.readPassphrase(ctx)
			if err != nil {
				return err
			}
			defer pass.Destroy()
			rep, err := a.d.Sealed.Migrate(a.workspaceFile(), pass, MigrateOptions{Quarantine: quarantine, Cold: a.coldOpen()})
			if err != nil {
				return err
			}
			w := a.d.Out
			defer warnColdNoWrap(a.d.Err, rep) // runs last: the warning is the end of the output
			defer a.migrateCopies(ctx, w, rep, pass, removeCopies)
			if rep.Format3Only {
				fmt.Fprintf(w, "Migrated %s from store format 2 to format 3: the workspace now has the policy standard, and its passphrase and recovery slots are unchanged.\n", a.workspaceFile())
				fmt.Fprintf(w, "The old file is kept as %s\n", rep.Backup)
				return nil
			}
			if rep.Backup3 != "" {
				defer fmt.Fprintf(w, "The copy made before the conversion to store format 3 is %s\n", rep.Backup3)
			}
			fmt.Fprintf(w, "Migrated %s to the current format: %d record(s) converted, %d merged, %d added, %d owner(s).\n", a.workspaceFile(), rep.Records, rep.Merged, rep.Added, rep.Owners)
			fmt.Fprintf(w, "The old file is kept as %s\n", rep.Backup)
			for _, p := range rep.Rewritten {
				fmt.Fprintf(w, "  descriptor of pool %s: owners and reward account now name key hashes\n", p)
			}
			for _, l := range rep.Unassigned {
				fmt.Fprintf(w, "  unassigned: %s\n", l)
			}
			for _, l := range rep.Quarantined {
				fmt.Fprintf(w, "  quarantined: %s\n", l)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&quarantine, "quarantine", nil, "go on for this pool although its descriptor or records are unresolved; it is left unusable (repeatable)")
	cmd.Flags().BoolVar(&removeCopies, "remove-copies", false, "delete the .pre-migrate copies once the migrated workspace verifies and opens (best effort on modern storage)")
	return cmd
}

// warnColdNoWrap ends a migration that sealed cold-role keys with no recovery
// path: the migrated slots bind no recovery key, so the recovery key cannot open
// those keys until a rekey binds one and adds their wraps.
func warnColdNoWrap(w io.Writer, rep MigrateReport) {
	if rep.ColdNoWrap == 0 {
		return
	}
	fmt.Fprintf(w, "\nWARNING: %d cold key record(s) have NO recovery path. The migrated workspace binds no recovery key, so if the cold-key passphrase is lost these keys are lost. Run `spo store passphrase change` now (or `spo store recovery-key new`): it binds the recovery key and adds the recovery wrap to every cold key, and asks for the cold-key passphrase once. `spo store slots` and `spo store verify` report how many cold records still lack the wrap.\n", rep.ColdNoWrap)
}

// migrateCopies says what the copies made before the migration hold and, with
// removeCopies, deletes them after the migrated file verifies and opens. A
// failed check keeps them. Deletion is an unlink: the bytes may stay on a
// journaling or copy-on-write file system and on an SSD, and no overwrite is
// attempted.
func (a *app) migrateCopies(ctx context.Context, w io.Writer, rep MigrateReport, pass *secret.Buffer, remove bool) {
	var copies []string
	for _, c := range []string{rep.Backup, rep.Backup3} {
		if c != "" {
			copies = append(copies, c)
		}
	}
	if len(copies) == 0 {
		return
	}
	fmt.Fprintf(w, "WARNING: the copies of the old file (%s) are in the older format: a pool cold key or committee cold key in them is sealed under the master key alone, without the cold-key passphrase. Anyone with a copy and the workspace passphrase can read it.\n", strings.Join(copies, ", "))
	if !remove {
		fmt.Fprintln(w, "Delete them once you have checked the migrated workspace, or run the migration with --remove-copies. Deleting is best effort on modern storage (the bytes may stay on disk).")
		return
	}
	if _, err := a.d.Sealed.VerifyFile(a.workspaceFile(), pass); err != nil {
		fmt.Fprintf(w, "The copies were NOT removed: the migrated workspace did not verify: %v\n", err)
		return
	}
	st, err := a.d.Sealed.Open(a.workspaceFile(), pass, OpenOptions{})
	if err != nil {
		fmt.Fprintf(w, "The copies were NOT removed: the migrated workspace did not open: %v\n", err)
		return
	}
	defer st.Close()
	// The copies may hold the only readable form of a cold key that has no recovery
	// wrap: they are removed only after the cold key has been read again, with the
	// factor typed afresh (not the one the migration used), and decrypts.
	if cc, ok := st.(ColdWrapCounter); ok {
		if _, without, cerr := cc.ColdWithoutWrap(ctx); cerr != nil || without > 0 {
			if cerr != nil {
				fmt.Fprintf(w, "The copies were NOT removed: the cold records could not be counted: %v\n", cerr)
				return
			}
			if a.coldFD >= 0 {
				fmt.Fprintf(w, "The copies were NOT removed: %d cold key record(s) have no recovery wrap, so the copies may be the only other readable form; --remove-copies then needs the cold-key passphrase typed again at the terminal, and --cold-passphrase-fd gives it only once. Remove the copies by hand when you have checked the keys.\n", without)
				return
			}
			cf, okf := st.(ColdFactors)
			cv, okv := st.(ColdVerifier)
			if !okf || !okv {
				fmt.Fprintln(w, "The copies were NOT removed: this build cannot read the cold keys again to check them.")
				return
			}
			fresh := func(ctx context.Context, _ bool) (*secret.Buffer, error) {
				return a.askColdPassphrase(ctx, false, "Cold-key passphrase, typed again to confirm the cold key still opens before its copy is removed", "")
			}
			cf.SetColdSource(ColdOpen{Passphrase: fresh})
			if _, verr := cv.VerifyColdPayloads(ctx); verr != nil {
				fmt.Fprintf(w, "The copies were NOT removed: a cold key did not open with the factor typed again: %v\n", verr)
				return
			}
		}
	}
	for _, c := range copies {
		if err := os.Remove(c); err != nil {
			fmt.Fprintf(w, "could not remove %s: %v\n", c, err)
			continue
		}
		fmt.Fprintf(w, "Removed %s (unlinked; deletion is best effort on modern storage, the bytes may remain on disk).\n", c)
	}
}

func (a *app) keyCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "Signing keys kept in upstream's encrypted form",
		Long: `An older workspace may hold a key still in upstream's password-encrypted form
(an import made before --keep-encrypted was removed; a new import creates none).
Such a key cannot sign and is never written out. convert turns it into an
ordinary sealed key; for a key of a cold role it needs the cold sub-key factor.`,
	}
	c.AddCommand(a.keyConvertCommand())
	return c
}

// ---- reports ----

// statusText is one word per status.
func statusText(s workspace.Status) string { return string(s) }

func artefactName(r ports.NamedRef) string {
	if r.Kind.Numbered() {
		return fmt.Sprintf("%s.%s#%d", r.Name, r.Kind, r.Num)
	}
	return r.Name + "." + string(r.Kind)
}

// printWorkspaceReport writes the report as a table: owner, artefact, status,
// reason. It holds names, kinds and the use case's reasons, no key material.
func printWorkspaceReport(w io.Writer, rep *workspace.Report, protection func(ports.NamedRef) string) {
	if rep.Extended {
		printSelectiveReport(w, rep)
		return
	}
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

// printSelectiveReport is the table of a selective import: the folder and the
// stored name of each owner, the owners found and not selected, and every
// descriptor rewrite (SPO-Xmulti-OUT-009). Names, folders and values come from
// the sources and go through shown (SPO-Xmulti-SEC-004).
func printSelectiveReport(w io.Writer, rep *workspace.Report) {
	fmt.Fprintf(w, "%-16s %-6s %-30s %-16s %-34s %-8s %s\n", "OWNER", "KIND", "FOLDER", "STORED AS", "ARTEFACT", "STATUS", "REASON")
	for _, o := range rep.Owners {
		if len(o.Artefacts) == 0 {
			fmt.Fprintf(w, "%-16s %-6s %-30s %-16s %-34s %-8s %s\n", shown(o.Owner), o.Kind, shown(o.Dir), shown(o.Final), "-", "failed", shown(o.Reason))
		}
		for _, ar := range o.Artefacts {
			why := ar.Reason
			if why == "" {
				why = ar.Note
			} else if ar.Note != "" {
				why += "; " + ar.Note
			}
			fmt.Fprintf(w, "%-16s %-6s %-30s %-16s %-34s %-8s %s\n", shown(o.Owner), o.Kind, shown(o.Dir), shown(o.Final), artefactName(ar.Ref), statusText(ar.Status), shown(why))
		}
	}
	for _, f := range rep.Found {
		fmt.Fprintf(w, "%-16s %-6s %-30s %-16s %-34s %-8s %s\n", shown(f.Name), f.Kind, shown(f.Dir), "-", "-", "found", "not selected")
	}
	n := 0
	for _, o := range rep.Owners {
		n += len(o.Rewrites)
	}
	if n > 0 {
		fmt.Fprintln(w, "\ndescriptor rewrites (pool, field, old -> new):")
		for _, o := range rep.Owners {
			for _, r := range o.Rewrites {
				fmt.Fprintf(w, "  %s: %s: %s -> %s\n", shown(r.Pool), shown(r.Field), quotedText(r.Old), quotedText(r.New))
			}
		}
	}
	for _, u := range rep.Unknown {
		fmt.Fprintf(w, "%-16s %-6s %-30s %-16s %-34s %-8s %s\n", "-", "-", "-", "-", shown(u.File), "ignored", shown(u.Reason))
	}
	for _, x := range rep.Warnings {
		fmt.Fprintf(w, "warning: %s\n", shown(x))
	}
}

// ---- import ---- (the command is in workspace_import.go)

// importPassword returns the password of the encrypted keys, or nil when the
// source holds none that needs it. A descriptor is read when given; otherwise
// the source is looked at, and the password is asked for without echo only if an
// encrypted key is met and the import is to decrypt it. gpg is required before
// the password is asked for.
func (a *app) importPassword(ctx context.Context, count func() (int, error), env *Env, fd int, keep bool) (*ports.Secret, error) {
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
	n, err := count()
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
		return nil, errors.New("the directory holds keys that upstream encrypted and there is no terminal to ask for their password on; give it on a file descriptor with --password-fd N, or pass --defer-encrypted (that leaves the key file, and its owner, out of the import)")
	}
	return p, err
}

func withGPGNote(err error) error {
	return &explained{msg: err.Error() + "\n" + gpgNote + "; without it, pass --defer-encrypted to leave such a key file in the source", err: err}
}

// ---- export ----

func (a *app) workspaceExportCommand() *cobra.Command {
	var (
		owners    []string
		passFD    int
		generate  bool
		outFD     int
		overwrite bool
		reason    string
	)
	cmd := &cobra.Command{
		Use:   "export <dir> (--password-fd N | --generate-password [--password-out-fd N]) [--owner NAME]... [--overwrite] [--reason TEXT]",
		Short: "Write pools and wallets out of the sealed workspace in the upstream file layout, keys encrypted",
		Long: `Write the files the upstream scripts expect into <dir>, which must be new or
empty (--overwrite writes into a directory that is not). Every signing key is
encrypted in upstream's gpg form (needs gpg: AES-256, iterated-and-salted S2K
with SHA-512 and the largest count, integrity-protected) with the password read
from --password-fd, which must be strong in upstream's sense and at least 20
characters long, or with a password this command generates (--generate-password:
160 random bits as base32 groups), shown once on the terminal (standard output
must be one) or written to a pipe on --password-out-fd N, before any file is
written (a regular file, a terminal and descriptors 0, 1, 2 are refused: a
secret is never written to a file). A signing key is never written
in clear: there is no option for it.

The password's protection is gpg's S2K, which is not memory-hard, so an export is
weaker against offline guessing than the sealed workspace. Treat the directory as
a transport form: move it, use it, delete it and the password.

Mnemonics and the Catalyst QR code have no encrypted form and are not written;
nor are keys kept in upstream's encrypted form (convert them first with
spo key convert).

The export is recorded in the workspace's audit log, with --reason, BEFORE any
key is written, and is not made when the record cannot be. The directory holds
what you export: put it on storage you control and remove it afterwards.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("workspace export reads the sealed workspace; it does not apply with --upstream-layout")
			}
			if !generate && cmd.Flags().Changed("password-out-fd") {
				return errors.New("--password-out-fd goes with --generate-password")
			}
			if generate {
				if cmd.Flags().Changed("password-out-fd") {
					if outFD < 0 {
						return errors.New("--password-out-fd needs a file descriptor number")
					}
					if outFD == a.passFD {
						return errors.New("--password-out-fd and --passphrase-fd name the same descriptor")
					}
					// Before any key is read or file written: a descriptor that
					// is not a pipe or a socket would lose or leak the password.
					if err := secretfd.Check("password-out-fd", outFD); err != nil {
						return err
					}
				} else if !stdoutIsTerminal(a.d.Out) {
					return errors.New("a generated password is shown once, on a terminal, and standard output is not one: pass --password-out-fd N to receive it on a descriptor")
				}
			} else if a.passFD == passFD {
				return errors.New("--password-fd and --passphrase-fd name the same descriptor")
			}
			if a.d.OpenExportDir == nil || a.d.WorkspaceAuditor == nil {
				return errors.New("workspace export is not available in this build")
			}
			return a.withEnv(cmd, envSpec{needs: []Need{CapKeyCrypto}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) (err error) {
				if s.Sealed == nil {
					return errors.New("workspace export reads the sealed workspace")
				}
				lister, ok := any(s.Store).(ports.SourceLister)
				if !ok {
					return errors.New("this build's sealed workspace cannot list its artefacts")
				}
				if sameDir(args[0], a.workspace) {
					return fmt.Errorf("%s is the workspace directory: export into another directory", args[0])
				}
				var pw *secret.Buffer
				if generate {
					raw, gerr := keyfile.GenerateExportPassword(rand.Reader)
					if gerr != nil {
						return gerr
					}
					if pw, err = secret.TryTake(raw); err != nil {
						return err
					}
				} else if pw, err = readFDSecret(passFD, "the export password"); err != nil {
					return err
				}
				defer pw.Destroy()
				// A generated password goes to its descriptor BEFORE any file is
				// written: when the write fails nothing exists yet, and when it
				// succeeds and the export then fails, the only loss is a
				// password that opens nothing. A password cannot be lost while
				// encrypted files remain.
				if generate && cmd.Flags().Changed("password-out-fd") {
					if derr := a.deliverExportPassword(pw, outFD, true); derr != nil {
						return derr
					}
				}
				created, err := prepareExportDir(args[0], overwrite)
				if err != nil {
					return err
				}
				dest, err := a.d.OpenExportDir(args[0])
				if err != nil {
					return err
				}
				uc := workspace.ExportWorkspace{Source: s.Store, SourceVault: s.Store.(ports.NamedVault), Lister: lister, Dest: dest,
					Encryptor: env.KeyEncryptor, Decryptor: env.KeyDecryptor, Auditor: a.d.WorkspaceAuditor(a.workspace, s.Store, reason)}
				rep, err := uc.Run(ctx, workspace.ExportOptions{Owners: owners, Password: pw, Overwrite: overwrite})
				if rep != nil {
					printWorkspaceReport(a.d.Out, rep, exportProtection)
					fmt.Fprintf(a.d.Out, "\n%d owner(s) of %d exported to %s, %d artefact(s) written.\n", len(rep.Owners)-rep.Failed(), len(rep.Owners), args[0], rep.Done())
					if rep.Done() > 0 {
						fmt.Fprintf(a.d.Out, "The signing keys in %s are encrypted in upstream's form with the %s password.\n", args[0], map[bool]string{true: "generated", false: "given"}[generate])
						fmt.Fprint(a.d.Out, "gpg's key derivation is not memory-hard: this is a transport form, weaker against offline guessing than the sealed workspace. Delete the directory and the password after use.\n")
						if generate && !cmd.Flags().Changed("password-out-fd") {
							if derr := a.deliverExportPassword(pw, outFD, false); derr != nil {
								return derr
							}
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
	cmd.Flags().BoolVar(&generate, "generate-password", false, "encrypt with a password generated here (160 random bits, base32 groups), shown once on the terminal or written to --password-out-fd; exclusive with --password-fd")
	cmd.Flags().IntVar(&outFD, "password-out-fd", -1, "with --generate-password: write the generated password to this inherited pipe or socket (never a file) instead of showing it")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "write into a directory that is not empty, replacing files of the same name")
	cmd.Flags().StringVar(&reason, "reason", "", "why the keys are exported; recorded in the audit log (not secret: no key material)")
	cmd.MarkFlagsMutuallyExclusive("password-fd", "generate-password")
	cmd.MarkFlagsOneRequired("password-fd", "generate-password")
	return cmd
}

// deliverExportPassword gives the operator the generated export password,
// once: written to the descriptor they opened, or shown on the terminal.
func (a *app) deliverExportPassword(pw *secret.Buffer, fd int, toFD bool) error {
	if toFD {
		if err := pw.Use(func(b []byte) error { return secretfd.Write("password-out-fd", fd, b) }); err != nil {
			return err
		}
		if err := secretfd.Write("password-out-fd", fd, []byte("\n")); err != nil {
			return err
		}
		fmt.Fprintf(a.d.Out, "The generated password was written to file descriptor %d, before any file was written.\n", fd)
		return nil
	}
	fmt.Fprint(a.d.Out, "\nThe export password (shown once; it is not stored anywhere):\n\n  ")
	pw.WriteTo(a.d.Out)
	fmt.Fprint(a.d.Out, "\n\n")
	return nil
}

// exportProtection says how an exported artefact is protected, for the table.
func exportProtection(r ports.NamedRef) string {
	if r.Kind.IsSigningKey() {
		return "encrypted"
	}
	return ""
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

// ---- key convert ----

func (a *app) keyConvertCommand() *cobra.Command {
	var passFD int
	cmd := &cobra.Command{
		Use:   "convert <key> [--password-fd N]",
		Short: "Turn a key kept in upstream's encrypted form into a sealed signing key",
		Long: `<key> names a key that an older import stored in upstream's encrypted form: the key file name, with or without .skey (mypool.node,
mywallet.payment.skey). The upstream password is read from --password-fd N, else
asked for without echo. gpg is needed.

The key is decrypted in protected memory only, checked against the verification
key in the workspace (import the .vkey file too; a key with no verification key
here is refused), then stored sealed, and the kept record removed, in one
transaction. The key is never written in clear. A KES or VRF key is checked in its
exact form (the Sum6 root key, or the public half of the seed) against the
verification key of its number; BLS keys cannot be checked and are not converted:
import them again with --password-fd.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("key convert works on the sealed workspace; it does not apply with --upstream-layout")
			}
			return a.withEnv(cmd, envSpec{needs: []Need{CapKeyCrypto, CapVKeyDerive}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				vault, ok := any(s.Store).(ports.NamedVault)
				if !ok || s.Sealed == nil {
					return errors.New("key convert works on the sealed workspace")
				}
				pw, err := a.keyPassword(ctx, passFD)
				if err != nil {
					return err
				}
				defer pw.Destroy()
				ref, err := workspace.ConvertKey{Store: s.Store, Vault: vault, Decryptor: env.KeyDecryptor, Deriver: env.VKeyDeriver}.Run(ctx, args[0], pw)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "%s is now a sealed signing key (%s); the kept encrypted record was removed.\n", args[0], artefactName(ref))
				return nil
			})
		},
	}
	cmd.Flags().IntVar(&passFD, "password-fd", -1, "read the upstream password from this inherited file descriptor (trailing newline stripped); there is no password flag or variable")
	return cmd
}

// keyPassword reads a password from the descriptor, else without echo.
func (a *app) keyPassword(ctx context.Context, fd int) (*ports.Secret, error) {
	if fd >= 0 {
		if a.passFD == fd {
			return nil, errors.New("--password-fd and --passphrase-fd name the same descriptor")
		}
		return readFDSecret(fd, "the password")
	}
	p, err := a.term.ReadSecret(ctx, "Password of the upstream-encrypted key: ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, errors.New("no terminal to ask for the password on; give it on a file descriptor with --password-fd N")
	}
	return p, err
}
