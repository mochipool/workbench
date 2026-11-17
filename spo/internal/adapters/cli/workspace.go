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
	c.AddCommand(a.workspaceImportCommand(), a.workspaceExportCommand())
	return c
}

func (a *app) keyCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "key",
		Short: "Signing keys kept in upstream's encrypted form",
		Long: `A workspace import with --keep-encrypted stores a key still in upstream's
password-encrypted form. Such a key cannot sign and is never written out. convert
turns it into an ordinary sealed key.`,
	}
	c.AddCommand(a.keyConvertCommand())
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
		return nil, errors.New("the directory holds keys that upstream encrypted and there is no terminal to ask for their password on; give it on a file descriptor with --password-fd N, or pass --keep-encrypted")
	}
	return p, err
}

func withGPGNote(err error) error {
	return &explained{msg: err.Error() + "\n" + gpgNote + "; without it, pass --keep-encrypted to import such a key undecrypted", err: err}
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
				lister, ok := any(s.Sealed).(ports.SourceLister)
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
				uc := workspace.ExportWorkspace{Source: s.Store, SourceVault: s.Sealed, Lister: lister, Dest: dest,
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
func exportProtection(r ports.Ref) string {
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
		Long: `<key> names a key that an import with --keep-encrypted stored in upstream's
encrypted form: the key file name, with or without .skey (mypool.node,
mywallet.payment.skey). The upstream password is read from --password-fd N, else
asked for without echo. gpg is needed.

The key is decrypted in protected memory only, checked against the verification
key in the workspace (import the .vkey file too; a key with no verification key
here is refused), then stored sealed, and the kept record removed, in one
transaction. The key is never written in clear. KES, VRF and BLS keys cannot be
checked this way and are not converted: import them again with --password-fd.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("key convert works on the sealed workspace; it does not apply with --upstream-layout")
			}
			return a.withEnv(cmd, envSpec{needs: []Need{CapKeyCrypto, CapVKeyDerive}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				vault, ok := any(s.Sealed).(ports.Vault)
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
