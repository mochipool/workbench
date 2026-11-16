package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/workspace"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// maxKeyFile bounds a signing key file: an envelope is a few hundred bytes.
const maxKeyFile = 16 << 10

// maxInfoFile bounds a pool info file.
const maxInfoFile = 1 << 20

// readKeyFile reads a signing key file into guarded memory. The path is the
// operator's: a leading ~ is the home directory (SPO-0x-PR-003); a symbolic
// link, a device and a pipe are refused, and so is a file of more than a key's
// size. A file that others can read is read all the same and the operator is
// told (stderr), because upstream's keys are 0400 and a looser mode is worth
// knowing about. The content is never printed, and the buffer is the caller's
// to destroy.
func (a *app) readKeyFile(path, what string) (*secret.Buffer, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("the %s key file %s cannot be opened: %v (a symbolic link is refused: name the file itself)", what, path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("the %s key file %s is not a regular file", what, path)
	}
	if st.Size() == 0 || st.Size() > maxKeyFile {
		return nil, fmt.Errorf("the %s key file %s is empty or larger than a key may be (%d bytes)", what, path, maxKeyFile)
	}
	if st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(a.d.Err, "Warning: the %s key file %s is readable by others (mode %04o); restrict it after the import\n", what, path, st.Mode().Perm())
	}
	buf, err := secret.TryRead(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("the %s key file %s cannot be read: %w", what, path, err)
	}
	if buf.Len() > maxKeyFile {
		buf.Destroy()
		return nil, fmt.Errorf("the %s key file %s is larger than a key may be (%d bytes)", what, path, maxKeyFile)
	}
	return buf, nil
}

// accountFlag is one --account: NAME:PAYMENT_SKEY[:STAKE_SKEY].
type accountFlag struct{ name, payment, stake string }

func parseAccountFlags(vals []string) ([]accountFlag, error) {
	var out []accountFlag
	for _, v := range vals {
		parts := strings.Split(v, ":")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
			return nil, fmt.Errorf("--account %q is not NAME:PAYMENT_SKEY or NAME:PAYMENT_SKEY:STAKE_SKEY", v)
		}
		af := accountFlag{name: parts[0], payment: parts[1]}
		if len(parts) == 3 {
			af.stake = parts[2]
		}
		out = append(out, af)
	}
	return out, nil
}

func (a *app) poolImportCommand() *cobra.Command {
	var (
		coldFile, vrfFile string
		accountVals       []string
		dry, cont, accept bool
		f                 chainFlags
	)
	cmd := &cobra.Command{
		Use:   "import <name> <pool-id|info.json> [--cold FILE] [--vrf FILE] [--account NAME:PAYMENT_SKEY:STAKE_SKEY]... [--dry-run] [--continue] [--accept-metadata-mismatch] [--transfer-file PATH]",
		Short: "Bring a pool that was set up elsewhere into the workspace, from the chain or an info file",
		Long: `Import the pool <name> from its registration data and the key files you hold
(upstream 0x_importHelper). The second argument is a pool id (56 hex digits or
pool1...), read from the chain provider (light mode: the pool's registration,
its latest update and the metadata it publishes), or the path of an info file
made by pool export-info on an online machine (any mode, no network).

The result is the pool descriptor, and for each key you give: --cold FILE the
cold signing key (its verification key and the counter file, one above the
chain's), --vrf FILE the VRF signing key, and for each --account
NAME:PAYMENT_SKEY[:STAKE_SKEY] the payment and stake keys of an owner or rewards
account with their addresses and certificates (a payment key alone imports just
that key). A key must belong to the pool: the cold key hashes to the pool id and
the VRF key to its registered hash. The key files are read in place into
protected memory and sealed in the workspace; they are never printed or
changed. A key that upstream encrypted is refused: decrypt it first. Everything
is written in one commit, so a refusal leaves nothing behind.

Without --cold, --vrf and --account, and with a terminal, the paths are asked
for (blank skips or ends). When no account is the pool's rewards account you are
asked whether to add one (default Yes). If the published metadata does not hash
to the registered hash, both hashes are shown and you are asked whether to go on
(default No); --accept-metadata-mismatch answers yes. --dry-run checks and
prints what would be imported and writes nothing. --continue goes on when
other artefacts of the pool exist (the descriptor itself is never replaced).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := workspace.PoolImportName(args[0])
			if err != nil {
				return err
			}
			accs, err := parseAccountFlags(accountVals)
			if err != nil {
				return err
			}
			src, isFile, err := a.poolSource(args[1])
			if err != nil {
				return err
			}
			needs := []Need{CapVKeyEnvelope, CapVrfVKey, CapAddressMake, CapCerts}
			if !isFile {
				needs = append(needs, CapPoolInfo, CapPoolUpdates, CapMetaFetch, CapMetaHash)
			}
			for _, ac := range accs {
				if ac.stake != "" {
					needs = append(needs, CapParams)
					break
				}
			}
			spec := envSpec{flags: &f, needs: needs}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				imp := &poolImport{a: a, env: env, name: name, arg: args[1], isFile: isFile, dry: dry, accept: accept,
					uc: workspace.ImportPoolFromChain{
						PoolInfoAcquirer: workspace.PoolInfoAcquirer{Pools: env.PoolInfos, Updates: env.PoolUpdates, Metadata: env.Metadata, Hasher: env.MetadataHasher},
						Store:            s.Store, VKeys: env.VKeyEnvelopes, VRF: env.VrfVKeys, Addresses: env.Addresses, Certs: env.Certs,
						Params: env.Params, NetworkID: env.NetworkID,
					},
					req: workspace.ImportPoolRequest{Name: name, Source: src, ContinueExisting: cont}}
				defer imp.destroy()
				return imp.run(ctx, coldFile, vrfFile, accs)
			})
		},
	}
	cmd.Flags().StringVar(&coldFile, "cold", "", "the pool's cold signing key file (node.skey)")
	cmd.Flags().StringVar(&vrfFile, "vrf", "", "the pool's VRF signing key file (vrf.skey)")
	cmd.Flags().StringArrayVar(&accountVals, "account", nil, "an owner or rewards account's keys: NAME:PAYMENT_SKEY or NAME:PAYMENT_SKEY:STAKE_SKEY, files (repeatable)")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "check everything and print what would be imported; write nothing")
	cmd.Flags().BoolVar(&cont, "continue", false, "go on when other artefacts of the pool already exist (adds to them; the descriptor is never replaced)")
	cmd.Flags().BoolVar(&accept, "accept-metadata-mismatch", false, "take published metadata that does not hash to the registered hash (default: show both hashes and ask, default No)")
	addChainFlags(cmd, &f, true)
	return cmd
}

// poolSource reads the second argument: an existing regular file is an info
// file (SPO-0x-IF-003), anything else a pool id for the use case to judge.
func (a *app) poolSource(arg string) (workspace.PoolInfoSource, bool, error) {
	st, err := os.Stat(arg)
	if err != nil || !st.Mode().IsRegular() {
		return workspace.PoolInfoSource{PoolID: arg}, false, nil
	}
	if st.Size() > maxInfoFile {
		return workspace.PoolInfoSource{}, false, fmt.Errorf("%s is larger than a pool info file may be (%d bytes)", arg, maxInfoFile)
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return workspace.PoolInfoSource{}, false, err
	}
	if len(b) == 0 {
		return workspace.PoolInfoSource{}, false, fmt.Errorf("%s is empty", arg)
	}
	return workspace.PoolInfoSource{InfoFile: b}, true, nil
}

// poolImport is one run of the import command.
type poolImport struct {
	a      *app
	env    *Env
	uc     workspace.ImportPoolFromChain
	name   string
	arg    string
	isFile bool
	dry    bool
	accept bool
	req    workspace.ImportPoolRequest
	keys   []*secret.Buffer
	// noTerm is set when a question found no terminal to ask on.
	noTerm bool
}

func (p *poolImport) destroy() {
	for _, k := range p.keys {
		k.Destroy()
	}
}

func (p *poolImport) read(path, what string) (*secret.Buffer, error) {
	b, err := p.a.readKeyFile(path, what)
	if err != nil {
		return nil, err
	}
	p.keys = append(p.keys, b)
	return b, nil
}

func (p *poolImport) run(ctx context.Context, coldFile, vrfFile string, accs []accountFlag) error {
	var err error
	if coldFile != "" {
		if p.req.Cold, err = p.read(coldFile, "cold"); err != nil {
			return err
		}
	}
	if vrfFile != "" {
		if p.req.VRF, err = p.read(vrfFile, "VRF"); err != nil {
			return err
		}
	}
	for _, ac := range accs {
		k := workspace.AccountKeys{Name: ac.name}
		if k.Payment, err = p.read(ac.payment, "payment"); err != nil {
			return err
		}
		if ac.stake != "" {
			if k.Stake, err = p.read(ac.stake, "stake"); err != nil {
				return err
			}
		}
		p.req.Accounts = append(p.req.Accounts, k)
	}
	if coldFile == "" && vrfFile == "" && len(accs) == 0 {
		if err := p.askKeys(ctx); err != nil {
			return err
		}
	}

	check := p.req
	check.DryRun = true
	res, err := p.once(ctx, &check)
	for err == nil && res.RewardsMissing && !p.noTerm {
		more, aerr := p.askRewards(ctx)
		if aerr != nil {
			return aerr
		}
		if !more {
			break
		}
		check.Accounts = p.req.Accounts
		res, err = p.once(ctx, &check)
	}
	if err != nil {
		return err
	}
	if p.dry {
		p.printPlan(res)
		return nil
	}
	final := p.req
	final.Source.AcceptMetadataMismatch = check.Source.AcceptMetadataMismatch
	if res, err = p.once(ctx, &final); err != nil {
		return err
	}
	p.printImported(res)
	return nil
}

// once runs the use case. A published metadata document that does not hash to
// the registered hash is put to the operator: both hashes are shown and the
// default is No (the metadata text goes into the descriptor, SPO-0x-SEC-003).
func (p *poolImport) once(ctx context.Context, req *workspace.ImportPoolRequest) (workspace.PoolImported, error) {
	req.Source.AcceptMetadataMismatch = req.Source.AcceptMetadataMismatch || p.accept
	res, err := p.uc.Run(ctx, *req)
	if !errors.Is(err, workspace.ErrMetadataHash) || req.Source.AcceptMetadataMismatch || p.isFile {
		return res, err
	}
	registered, published, why := p.hashes(ctx)
	w := p.a.d.Out
	fmt.Fprintln(w, "The metadata the pool publishes does not match the hash it registered:")
	if why != "" {
		fmt.Fprintf(w, "  (the hashes could not be shown: %s)\n", plainText(why, 200))
		return res, err
	}
	fmt.Fprintf(w, "  registered hash  %s\n  published hash   %s\n", registered, published)
	yes, aerr := p.ask(ctx, "Import the pool with the published metadata anyway?")
	if aerr != nil {
		return res, fmt.Errorf("%w (pass --accept-metadata-mismatch to go on)", err)
	}
	if !yes {
		return res, fmt.Errorf("%w: declined, nothing was imported", workspace.ErrMetadataHash)
	}
	req.Source.AcceptMetadataMismatch = true
	return p.uc.Run(ctx, *req)
}

// hashes reads again what the acquirer compared: the registered hash and the
// hash of the published document.
func (p *poolImport) hashes(ctx context.Context) (registered, published, why string) {
	word, err := stake.ParsePoolWord(p.arg)
	if err != nil || !word.IsID {
		return "", "", "the argument is not a pool id"
	}
	rd, err := p.env.PoolInfos.PoolInfo(ctx, word.Pool)
	if err != nil {
		return "", "", err.Error()
	}
	info, ok := rd.Get()
	if !ok {
		return "", "", "the provider did not answer again"
	}
	raw, err := p.env.Metadata.Fetch(ctx, info.MetaURL)
	if err != nil {
		return "", "", err.Error()
	}
	h, err := p.env.MetadataHasher.MetadataHash(raw)
	if err != nil {
		return "", "", err.Error()
	}
	return strings.ToLower(info.MetaHash), hex.EncodeToString(h[:]), ""
}

// ask asks a yes/no question, default No. A missing terminal is an error and
// remembered, so no further question is attempted.
func (p *poolImport) ask(ctx context.Context, q string) (bool, error) {
	ans, err := p.a.term.ReadLine(ctx, q+" [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		p.noTerm = true
		return false, err
	}
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// line asks for one line; ok is false when there is no terminal.
func (p *poolImport) line(ctx context.Context, q string) (string, bool, error) {
	ans, err := p.a.term.ReadLine(ctx, q)
	if errors.Is(err, ErrNoTerminal) {
		p.noTerm = true
		return "", false, nil
	}
	return strings.TrimSpace(ans), err == nil, err
}

// askKey asks for the path of a key until one reads or the answer is blank
// (SPO-0x-PR-003, SPO-0x-PR-004: a failed attempt asks again).
func (p *poolImport) askKey(ctx context.Context, q, what string) (*secret.Buffer, error) {
	for {
		path, ok, err := p.line(ctx, q)
		if err != nil || !ok || path == "" {
			return nil, err
		}
		b, rerr := p.read(path, what)
		if rerr == nil {
			return b, nil
		}
		fmt.Fprintf(p.a.d.Err, "%v\n", rerr)
	}
}

// askKeys is the interactive import of the keys: the cold key, the VRF key and
// the accounts (SPO-0x-PR-003 to SPO-0x-PR-006). It has no readline pre-fill, so
// each prompt says what a blank answer does.
func (p *poolImport) askKeys(ctx context.Context) error {
	var err error
	if p.req.Cold, err = p.askKey(ctx, "Path of the pool's cold signing key, node.skey (blank to skip): ", "cold"); err != nil || p.noTerm {
		if p.noTerm {
			fmt.Fprintln(p.a.d.Out, "No terminal to ask for key files on: importing without keys. Pass --cold, --vrf and --account to import them.")
		}
		return err
	}
	if p.req.VRF, err = p.askKey(ctx, "Path of the pool's VRF signing key, vrf.skey (blank to skip): ", "VRF"); err != nil {
		return err
	}
	return p.askAccounts(ctx, "owner")
}

// askAccounts asks for accounts until the name is blank (SPO-0x-PR-005).
func (p *poolImport) askAccounts(ctx context.Context, example string) error {
	for {
		name, ok, err := p.line(ctx, fmt.Sprintf("Name of an owner or rewards account, such as %s (blank to end): ", example))
		if err != nil || !ok || name == "" {
			return err
		}
		pay, err := p.askKey(ctx, "Path of "+name+"'s payment.skey (blank to give the account up): ", "payment")
		if err != nil {
			return err
		}
		if pay == nil {
			continue
		}
		if !p.env.Has(CapParams) {
			fmt.Fprintf(p.a.d.Out, "Only the payment key of %s is imported: its stake key needs protocol-parameters (%s).\n", name, p.env.Reason(CapParams))
			p.req.Accounts = append(p.req.Accounts, workspace.AccountKeys{Name: name, Payment: pay})
			continue
		}
		stk, err := p.askKey(ctx, "Path of "+name+"'s stake.skey (blank to import the payment key only): ", "stake")
		if err != nil {
			return err
		}
		p.req.Accounts = append(p.req.Accounts, workspace.AccountKeys{Name: name, Payment: pay, Stake: stk})
	}
}

// askRewards is the question of SPO-0x-PR-007, default Yes: no account is the
// pool's rewards account, so go back and add one?
func (p *poolImport) askRewards(ctx context.Context) (bool, error) {
	ans, err := p.a.term.ReadLine(ctx, "Currently there is no rewards account included, do you wanna go back and add a payment/staking keypair for the rewards account? [Y/n] ")
	if errors.Is(err, ErrNoTerminal) {
		p.noTerm = true
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "", "y", "yes":
	default:
		return false, nil
	}
	before := len(p.req.Accounts)
	if err := p.askAccounts(ctx, "owner_andor_rewards"); err != nil {
		return false, err
	}
	return len(p.req.Accounts) > before, nil
}

func (p *poolImport) printDescriptor(res workspace.PoolImported) {
	w := p.a.d.Out
	fmt.Fprintf(w, "Descriptor %s:\n", p.name)
	for _, l := range strings.Split(strings.TrimRight(string(res.Descriptor), "\n"), "\n") {
		fmt.Fprintf(w, "  %s\n", plainText(l, 200))
	}
}

func (p *poolImport) printAccounts(res workspace.PoolImported) {
	w := p.a.d.Out
	for _, ac := range res.Accounts {
		role := "neither an owner nor the rewards account of the pool (kept, not in the descriptor)"
		switch {
		case ac.Owner && ac.Reward:
			role = "an owner and the rewards account"
		case ac.Owner:
			role = "an owner"
		case ac.Reward:
			role = "the rewards account"
		}
		switch {
		case !ac.Complete:
			fmt.Fprintf(w, "  account %s: payment key only\n", ac.Name)
		default:
			deleg := "no delegation certificate (no cold key)"
			if ac.Delegation {
				deleg = "delegation certificate"
			}
			fmt.Fprintf(w, "  account %s: %s; stake address %s; registration certificate, %s\n", ac.Name, role, ac.StakeAddress, deleg)
		}
	}
	if res.RewardsMissing {
		fmt.Fprintln(w, "Notice: no imported account is the pool's rewards account, so the descriptor has none. Set it with: spo pool descriptor set")
	}
}

func (p *poolImport) printPlan(res workspace.PoolImported) {
	w := p.a.d.Out
	fmt.Fprintf(w, "Dry run: nothing was written. Importing pool %s as %s would:\n", res.Info.IDBech, p.name)
	fmt.Fprintf(w, "  write the descriptor of %s\n", p.name)
	if p.req.Cold != nil {
		fmt.Fprintf(w, "  seal the cold key and write its verification key and the counter file (next number %d)\n", res.CounterNext)
	}
	if p.req.VRF != nil {
		fmt.Fprintln(w, "  seal the VRF key and write its verification key")
	}
	p.printAccounts(res)
	p.printDescriptor(res)
}

func (p *poolImport) printImported(res workspace.PoolImported) {
	w := p.a.d.Out
	fmt.Fprintf(w, "Imported pool %s as %s: %d artefact(s) written.\n", res.Info.IDBech, p.name, len(res.Written))
	for _, r := range res.Written {
		fmt.Fprintf(w, "  %s\n", r)
	}
	if p.req.Cold != nil {
		fmt.Fprintf(w, "  the operational certificate counter file holds %d (the chain's plus one)\n", res.CounterNext)
	}
	p.printAccounts(res)
	p.printDescriptor(res)
	fmt.Fprintf(w, "Next: spo pool kes generate %s, then spo pool opcert issue %s.\n", p.name, p.name)
}

// ---- export-info --------------------------------------------------------------------

func (a *app) poolExportInfoCommand() *cobra.Command {
	var (
		attach bool
		f      chainFlags
	)
	cmd := &cobra.Command{
		Use:   "export-info <pool-id> <file> [--attach] [--transfer-file PATH]",
		Short: "Write a pool's public registration data to a file, for an offline import",
		Long: `Read the registration of a pool from the chain provider (its registration, its
latest update and the metadata it publishes, checked against the registered
hash) and write it to <file> as one JSON document, so an offline machine, which
cannot query the chain, can import from it: spo pool import NAME <file>
(upstream 0x_importHelper with a third argument). The file holds public chain
data only. It must not exist.

--attach also adds the file to the offline transfer file (upstream asks; the
default is No). Needs the pool-info, pool-updates, metadata-fetch and
extract-sink capabilities (light mode), and transfer-attach for --attach, which
no mode has together with a chain reader today: the command then lists what is
missing.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			word, err := stake.ParsePoolWord(args[0])
			if err != nil || !word.IsID {
				return workspace.ErrBadPoolID
			}
			dir, base := filepath.Split(args[1])
			if base == "" || base == "." || base == ".." {
				return fmt.Errorf("%q is not a file name", args[1])
			}
			if dir == "" {
				dir = "."
			}
			needs := []Need{CapPoolInfo, CapPoolUpdates, CapMetaFetch, CapMetaHash, CapFileSink}
			if attach {
				needs = append(needs, CapAttach)
			}
			spec := envSpec{flags: &f, needs: needs}
			return a.withEnv(cmd, spec, func(ctx context.Context, _ *session, env *Env, _ WireOptions) error {
				sink, err := env.Sinks(dir)
				if err != nil {
					return err
				}
				uc := workspace.ExportPoolInfo{
					PoolInfoAcquirer: workspace.PoolInfoAcquirer{Pools: env.PoolInfos, Updates: env.PoolUpdates, Metadata: env.Metadata, Hasher: env.MetadataHasher},
					Sink:             sink,
				}
				if attach {
					uc.Attacher = env.Attach
				}
				res, err := uc.Run(ctx, workspace.ExportRequest{Source: workspace.PoolInfoSource{PoolID: args[0]}, File: base, Attach: attach})
				if err != nil {
					if errors.Is(err, workspace.ErrMetadataHash) {
						return fmt.Errorf("%w; nothing was written (the info file would carry metadata the pool did not register)", err)
					}
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Wrote the registration data of pool %s to %s (public data).\n", res.Info.IDBech, filepath.Join(dir, res.File))
				if res.Attached {
					fmt.Fprintf(w, "Attached it to the transfer file.\n")
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&attach, "attach", false, "also add the file to the offline transfer file")
	addChainFlags(cmd, &f, true)
	return cmd
}
