package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/registry"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// metaFields are the keys of the asset record the operator edits and the
// registry entry is built from (SPO-12a-OUT-001).
var metaFields = []string{"metaName", "metaDescription", "metaDecimals", "metaTicker", "metaUrl", "metaLogoPNG"}

// plainText makes text of a third party fit on one terminal line: everything
// textsafe escapes (controls of C0 and C1, bidirectional and invisible
// characters, newlines) is written as \u{hex}, and a long text is cut. The registry's answer is not ours.
func plainText(s string, max int) string {
	rs := []rune(s)
	cut := len(rs) > max
	if cut {
		rs = rs[:max]
	}
	out := textsafe.Text(string(rs))
	if cut {
		out += "..."
	}
	return out
}

func (a *app) assetMetaCommand() *cobra.Command {
	c := &cobra.Command{Use: "meta", Short: "Token-registry metadata of an asset: generate the signed entry, check it against the registry"}
	c.AddCommand(a.assetMetaGenerateCommand(), a.assetMetaCheckCommand())
	return c
}

// ---- generate -------------------------------------------------------------------------

func (a *app) assetMetaGenerateCommand() *cobra.Command {
	var (
		out  string
		sets []string
	)
	cmd := &cobra.Command{
		Use:   "generate <policy.asset> [--set FIELD=VALUE]... [--out FILE]",
		Short: "Create or sign the token-registry entry (CIP-26) of an asset",
		Long: `Build the token-registry entry of the asset <policy>.<asset>, sign it with the
policy key held in the workspace and store it as <subject>.json (upstream
12a_genAssetMeta, with the external token-metadata-creator replaced by a native
signer).

The first run only creates the asset record and says which fields to fill in:
metaName, metaDescription, metaDecimals, metaTicker, metaUrl and metaLogoPNG
(the path of a PNG of at most 64 KB, relative to the workspace directory unless
absolute). Fill them with --set FIELD=VALUE (repeatable; the record is created
first when it does not exist), then run the command again: the second run signs
and stores the entry, one sequence number above the record's. Show the record
with: spo asset show <policy.asset>.

--out FILE writes the signed entry, which is public data, to FILE for the pull
request to the token registry. The file must not exist. A hardware policy key is
refused: no device signs registry entries. The entry is built and signed before
anything is written, so a refusal leaves the record as it was.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kv, err := parseMetaSets(sets)
			if err != nil {
				return err
			}
			if out != "" {
				if _, err := os.Lstat(out); err == nil {
					return fmt.Errorf("%s already exists; the entry is not written over a file", out)
				}
			}
			spec := envSpec{needs: []Need{CapSigners, CapRegistrySigning, CapClock, CapLogoFiles}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				uc := registry.GenerateTokenMetadata{Store: s.Store, Signers: env.Signers, Clock: env.Clock, Logos: env.Logos}
				w := a.d.Out
				req := registry.GenerateRequest{Asset: args[0]}
				var res registry.Generated
				var err error
				if len(kv) > 0 {
					// The fields go in before anything is signed: the record is
					// created first when there is none.
					rec, rerr := assetRecordRef(args[0])
					if rerr != nil {
						return rerr
					}
					var have bool
					if err := s.Store.View(ctx, func(r ports.NamedReader) (e error) { have, e = r.Exists(rec); return }); err != nil {
						return err
					}
					if !have {
						if res, err = uc.Run(ctx, req); err != nil {
							return err
						}
						fmt.Fprintf(w, "Created the asset record %s (subject %s).\n", res.Record, res.Subject)
					}
					if err := setMetaFields(ctx, s.Store, rec, kv); err != nil {
						return err
					}
					fmt.Fprintf(w, "Set %s in %s.\n", metaKeys(kv), rec)
				}
				if res, err = uc.Run(ctx, req); err != nil {
					return err
				}
				if res.Created {
					fmt.Fprintf(w, "Created the asset record %s (subject %s).\n", res.Record, res.Subject)
					fmt.Fprintf(w, "Fill in the fields of the registry entry and run the command again to sign it:\n  %s\n", strings.Join(metaFields, ", "))
					fmt.Fprintf(w, "For example: spo asset meta generate %s --set metaName=NAME --set metaDescription=TEXT --set metaTicker=TICK --set metaDecimals=0\n", args[0])
					fmt.Fprintf(w, "Show the record with: spo asset show %s\n", args[0])
					if out != "" {
						fmt.Fprintln(w, "There is no entry yet, so nothing was written to "+out+".")
					}
					return nil
				}
				a.printGenerated(res)
				if out != "" {
					if err := writePublic(out, res.Entry.JSON()); err != nil {
						return fmt.Errorf("the entry is stored in the workspace but was not written to %s: %w", out, err)
					}
					fmt.Fprintf(w, "Wrote the signed entry to %s. It is public: submit it to the token registry in a pull request.\n", out)
				} else {
					fmt.Fprintln(w, "Write it out with --out FILE (running again signs a new sequence number).")
				}
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&sets, "set", nil, "set a field of the asset record before signing: "+strings.Join(metaFields, ", ")+" (repeatable)")
	cmd.Flags().StringVar(&out, "out", "", "write the signed public entry to this new file (for the registry pull request)")
	return cmd
}

func (a *app) printGenerated(res registry.Generated) {
	w := a.d.Out
	fmt.Fprintf(w, "Signed the registry entry of %s.\n", res.Record.Name)
	fmt.Fprintf(w, "  subject      %s\n  sequence     %d\n  entry        %s in the workspace (public data)\n", res.Subject, res.Sequence, res.File)
	var props []string
	for _, p := range tokenmeta.Properties() {
		if _, ok := res.Entry.Props[p]; ok {
			props = append(props, string(p))
		}
	}
	fmt.Fprintf(w, "  properties   %s\n", strings.Join(props, ", "))
}

// recordRef is the asset record of the argument.
func assetRecordRef(arg string) (ports.NamedRef, error) {
	ref, err := assets.ParseRef(arg)
	if err != nil {
		return ports.NamedRef{}, err
	}
	return ports.NamedRef{Name: assets.RecordName(ref.Policy, ref.Asset), Kind: ports.AssetFile}, nil
}

func parseMetaSets(sets []string) (map[string]string, error) {
	kv := map[string]string{}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, fmt.Errorf("--set %q is not FIELD=VALUE", s)
		}
		known := false
		for _, f := range metaFields {
			known = known || f == k
		}
		if !known {
			return nil, fmt.Errorf("--set %s: not a field of the registry entry; choose one of %s", k, strings.Join(metaFields, ", "))
		}
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("--set %s: a value is one line", k)
		}
		if _, dup := kv[k]; dup {
			return nil, fmt.Errorf("--set %s is given twice", k)
		}
		kv[k] = v
	}
	return kv, nil
}

func metaKeys(kv map[string]string) string {
	var ks []string
	for _, f := range metaFields {
		if _, ok := kv[f]; ok {
			ks = append(ks, f)
		}
	}
	return strings.Join(ks, ", ")
}

// setMetaFields changes the meta fields of the record in one transaction. The
// values are the operator's own words; the use case validates them when it
// builds the entry.
func setMetaFields(ctx context.Context, st ports.NamedStore, rec ports.NamedRef, kv map[string]string) error {
	return st.Update(ctx, func(w ports.NamedWriter) error {
		b, err := w.Get(rec)
		if err != nil {
			return err
		}
		r, err := assets.ParseRecord(b)
		if err != nil {
			return fmt.Errorf("%s: %w", rec, err)
		}
		for _, f := range metaFields {
			if v, ok := kv[f]; ok {
				r.Set(f, v)
			}
		}
		return w.Put(rec, r.Marshal())
	})
}

// writePublic writes public data to a new file, readable by everyone.
func writePublic(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// ---- check ----------------------------------------------------------------------------

func (a *app) assetMetaCheckCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "check <policy.asset|subject>",
		Short: "Compare the asset record with what the token registry serves",
		Long: `Ask the token-registry server for the entry of an asset and compare it with the
asset record (upstream 12b_checkAssetMetaServer). The argument is <policy>.<asset>
(a stored record) or a subject of 56 to 120 hex digits (nothing local to compare).

The output says where the submission stands: published (the registry serves the
record's sequence number), behind (it serves an older one: the pull request is
not merged yet), ahead, or not compared; then whether the entry's signatures
verify and its policy matches the subject, and each property side by side with
the record's value. "Not found" is a normal result and exits 0; an entry that does
not verify, or a registry that cannot be reached, is an error. Nothing is written.

Needs the token-registry capability: light mode with a registry server (mainnet
has the public one; for a test network set url in the [registry] section of
spo.toml). Offline there is none.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{needs: []Need{CapTokenRegistry}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := registry.CheckTokenMetadata{Store: s.Store, Registry: env.Registry, Logos: env.Logos}.
					Run(ctx, registry.CheckRequest{Argument: args[0]})
				if err != nil {
					if errors.Is(err, ports.ErrRegistryAnswer) {
						return fmt.Errorf("%w (the answer is not trusted and is not shown)", err)
					}
					return err
				}
				return a.printChecked(res)
			})
		},
	}
}

func (a *app) printChecked(res registry.Checked) error {
	w := a.d.Out
	fmt.Fprintf(w, "Registry  %s\nSubject   %s\n", plainText(res.Registry, 80), res.Subject)
	if res.HasRecord {
		fmt.Fprintf(w, "Record    %s (sequence %d)\n", res.Record, res.RecordSequence)
	}
	if !res.Found {
		fmt.Fprintln(w, "Status    not found: the registry has no entry for this subject.")
		if res.HasRecord && res.RecordSequence > 0 {
			fmt.Fprintln(w, "          The entry in the workspace is not published yet.")
		}
		return nil
	}
	fmt.Fprintf(w, "Status    %s (registry sequence %d)\n", res.Status, res.RegistrySequence)
	v := res.Verification
	switch {
	case v.OK:
		fmt.Fprintln(w, "Verify    OK: every property is signed and the policy matches the subject")
	default:
		fmt.Fprintln(w, "Verify    FAILED")
		for _, p := range v.Properties {
			if p.Valid == 0 || p.Invalid > 0 {
				fmt.Fprintf(w, "          %s: %d valid, %d invalid signature(s)\n", p.Property, p.Valid, p.Invalid)
			}
		}
		if v.PolicyError != "" {
			fmt.Fprintf(w, "          policy: %s\n", plainText(v.PolicyError, 120))
		} else if v.PolicyChecked && !v.PolicyIDMatches {
			fmt.Fprintln(w, "          policy: does not hash to the subject's policy id")
		}
	}
	for _, p := range res.Properties {
		reg := "(none)"
		if p.Present {
			reg = a.valueText(p.Property, p.Value)
		}
		line := fmt.Sprintf("  %-12s registry %s", p.Property, reg)
		switch {
		case !res.HasRecord:
		case !p.Compared:
			line += " | record not compared"
		case p.Match:
			line += " | record matches"
		default:
			local := p.Local
			if p.Property == tokenmeta.PropLogo {
				local = "file " + local
			}
			line += " | record differs: " + plainText(local, 60)
		}
		fmt.Fprintln(w, line)
	}
	if res.Logo != nil && !res.LogoIsPNG {
		fmt.Fprintln(w, "Warning   the registry's logo is not a PNG within the size limit; it is not shown")
	}
	if !v.OK {
		return errors.New("the registry's entry does not verify")
	}
	return nil
}

func (a *app) valueText(p tokenmeta.Property, v tokenmeta.Value) string {
	if p == tokenmeta.PropLogo {
		return fmt.Sprintf("%d bytes", len(v.Bytes()))
	}
	return plainText(v.String(), 80)
}
