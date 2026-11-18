package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/nodekeys"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

func (a *app) nodeCommand() *cobra.Command {
	c := &cobra.Command{Use: "node", Short: "Deliver the hot node keys to a block producer"}
	c.AddCommand(a.nodeExport())
	return c
}

// maxRecipientFile bounds the recipient file: one public key and some comments.
const maxRecipientFile = 8 << 10

func (a *app) nodeExport() *cobra.Command {
	var (
		recipientFile string
		out           string
		kesNum        int
		reason        string
		noTPM         bool
	)
	cmd := &cobra.Command{
		Use:   "export <pool> --recipient FILE --out DIR [--kes N] [--no-tpm-identity] [--reason TEXT]",
		Short: "Seal a pool's KES key, VRF key and operational certificate to a block producer (age ciphertext only)",
		Long: `Reads the pool's KES signing key, VRF signing key and operational certificate
from the workspace and writes three age ciphertext files into --out (new or
empty): kes.skey.age, vrf.skey.age and node.cert.age, sealed to the age X25519
public key in --recipient FILE. No plaintext leaves this command. The block
producer's start-up helper, spo-node-keys, decrypts them on the producer into a
ramfs directory (see docs/how-to/slots-policy-and-rotation.md).

Before anything is sealed: the role history of the KES and of the VRF key must
contain their hot role and must not contain a cold role, and a missing history is
refused; the certificate must name this KES key; the verification key derived
from each signing key must be the stored one. --kes N names the KES key (default:
the newest one that has a certificate).

The producer's age identity should be held only as a TPM-bound systemd
credential; this command cannot see the producer's host. --no-tpm-identity
records that you know it is not. The delivery is recorded in the workspace's
audit log (recipient identifier, KES number, file names) before any file is
written.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("node export reads the sealed workspace; it does not apply with --upstream-layout")
			}
			if a.d.HotSealer == nil || a.d.HotDeriver == nil || a.d.WorkspaceAuditor == nil {
				return errors.New("node export is not available in this build")
			}
			if recipientFile == "" || out == "" {
				return errors.New("node export needs --recipient FILE (the producer's age public key) and --out DIR")
			}
			// Refusals that need no workspace come before any prompt.
			recipient, err := readRecipient(a, recipientFile)
			if err != nil {
				return err
			}
			if _, err := a.d.HotSealer.CheckRecipient(recipient); err != nil {
				return err
			}
			if sameDir(out, a.workspace) {
				return fmt.Errorf("%s is the workspace directory: write the delivery into another directory", out)
			}
			if err := checkNewOrEmptyDir(out); err != nil {
				return err
			}
			req := nodekeys.Request{Pool: args[0], Recipient: recipient, NoTPMIdentity: noTPM}
			if cmd.Flags().Changed("kes") {
				req.KES = &kesNum
			}
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				if s.Sealed == nil {
					return errors.New("node export reads the sealed workspace")
				}
				vault, ok := s.Store.(ports.NamedVault)
				if !ok {
					return errors.New("this build's workspace cannot release a signing key to be sealed")
				}
				idx := labels.NewIndex(s.Anchored)
				uc := nodekeys.Export{
					Store: s.Store, Vault: vault, Derive: a.d.HotDeriver, Sealer: a.d.HotSealer,
					History: func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
						return ports.RoleHistoryOf(ctx, idx, id)
					},
					Homes:   func(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) { return idx.Homes(ctx, id) },
					Auditor: a.d.WorkspaceAuditor(a.workspace, s.Store, reason),
				}
				res, err := uc.Run(ctx, req)
				if err != nil {
					return err
				}
				if err := writeCiphertexts(ctx, out, res); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Sealed the hot keys of %s (KES key %d) to recipient %s: %d file(s) in %s.\n", args[0], res.KESNumber, res.RecipientID, len(res.Files), out)
				for _, f := range res.Files {
					fmt.Fprintf(a.d.Out, "  %s\n", f.Name)
				}
				if noTPM {
					fmt.Fprintln(a.d.Out, "Recorded: the producer's identity is not held in a TPM-bound credential. Anyone who can read that host's disk can decrypt these files.")
				} else {
					fmt.Fprintln(a.d.Out, "The producer's identity should be a TPM-bound systemd credential; this command cannot check the host. Pass --no-tpm-identity to record that it is not.")
				}
				fmt.Fprintln(a.d.Out, "Copy the files to the producer and run spo-node-keys there. The KES key evolves with each period: rotate it and deliver again before the certificate expires.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&recipientFile, "recipient", "", "file with the block producer's age X25519 public key (age1...)")
	cmd.Flags().StringVar(&out, "out", "", "directory for the three ciphertext files (new or empty)")
	cmd.Flags().IntVar(&kesNum, "kes", 0, "number of the KES key (default: the newest one that has a certificate)")
	cmd.Flags().BoolVar(&noTPM, "no-tpm-identity", false, "record that the producer's identity is not held in a TPM-bound credential")
	cmd.Flags().StringVar(&reason, "reason", "", "the reason, recorded in the audit log")
	return cmd
}

func readRecipient(a *app, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("the recipient file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRecipientFile+1))
	if err != nil || len(b) > maxRecipientFile {
		return "", errors.New("the recipient file is unreadable or larger than a public key file can be")
	}
	return a.d.HotSealer.ParseRecipientFile(b)
}

// writeCiphertexts writes the files under temporary names into a new or empty
// directory (each created exclusively, mode 0600, synced), records the delivery
// in the audit log, and only then renames them into place. A failed write or
// record removes what was made; the audit row is never written without the files
// (a crash between the record and the renames leaves a row and the temporary
// files).
func writeCiphertexts(ctx context.Context, dir string, res *nodekeys.Result) (err error) {
	created := false
	if _, serr := os.Lstat(dir); os.IsNotExist(serr) {
		created = true
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var temps []string
	defer func() {
		if err != nil {
			for _, p := range temps {
				os.Remove(p)
			}
			if created {
				os.Remove(dir)
			}
		}
	}()
	for _, f := range res.Files {
		p := filepath.Join(dir, "."+f.Name+".tmp")
		fh, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		temps = append(temps, p)
		_, werr := fh.Write(f.Ciphertext)
		if werr == nil {
			werr = fh.Sync()
		}
		if cerr := fh.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	if err := res.Record(ctx); err != nil {
		return err
	}
	for i, f := range res.Files {
		if err := os.Rename(temps[i], filepath.Join(dir, f.Name)); err != nil {
			return err
		}
	}
	return nil
}

// checkNewOrEmptyDir: the directory does not exist, or is an empty directory.
func checkNewOrEmptyDir(dir string) error {
	st, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return fmt.Errorf("%s is not empty: write the delivery into a new directory", dir)
	}
	return nil
}
