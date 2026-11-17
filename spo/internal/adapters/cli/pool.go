package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	yesRegisterWhy = "--yes is not accepted: a pool registration moves the pool deposit and sets the pledge, and it is asked twice, " +
		"before the witnesses are collected and again before the transaction goes out; no policy skips either question " +
		"(SPO-Ptx-PR-004, SPO-05c-PR-003). Answer at the terminal"
	yesRetireWhy = "--yes is not accepted: a pool retirement is never approved by a skip policy (SPO-Ptx-PR-004, SPO-07b-PR-001). Answer at the terminal"
)

// maxWitnessFile bounds a witness transfer file read from disk.
const maxWitnessFile = 1 << 20

// poolPipeline is the transaction tail of the pool commands: the approval is
// always asked, and the summary is the pool summary.
func (a *app) poolPipeline(s *session, env *Env) txflow.Pipeline {
	p := a.pipeline(s, env, false)
	p.Confirmer = poolConfirmer{a: a, store: s.Store, ids: env.TxIDs}
	return p
}

// poolFlags are the policy flags of the pool transaction commands.
type poolFlags struct {
	chain           chainFlags
	messages        []string
	extra           extraFlags
	yes             bool
	allowUnverified bool
	singleSource    bool
	allowPending    bool
	typ             string
}

// hint adds to a refusal the flag that would let the operator go on, and
// what it gives up.
func (f *poolFlags) hint(err error) error {
	if err == nil {
		return nil
	}
	var h string
	switch {
	case errors.Is(err, txflow.ErrDeclined), errors.Is(err, poolops.ErrDeclined):
		return fmt.Errorf("%w: nothing was signed, submitted or queued", err)
	case errors.Is(err, poolops.ErrNoDescriptor):
		h = "create it with: spo pool descriptor new <pool> ..."
	case errors.Is(err, poolops.ErrSingleSource) && !f.singleSource:
		h = "pass --single-source to go on with one source: a false answer from one provider decides wrongly between registration and re-registration; the summary will say so"
	case !f.allowUnverified && (errors.Is(err, poolops.ErrNoChainReader) || errors.Is(err, poolops.ErrUnverified) || strings.Contains(err.Error(), "the pool state is unknown")):
		h = "pass --allow-unverified to go on without that check: the type then comes from the descriptor, and a wrong type only makes the ledger reject the transaction; the summary lists every check that was skipped"
	case errors.Is(err, pool.ErrChooseType):
		h = "pass --type REG (first registration, pays the deposit) or --type REREG (re-registration, an update)"
	case errors.Is(err, poolops.ErrMetadataMismatch):
		h = "publish the metadata at poolMetaUrl (show it with: spo pool metadata show <pool>) or generate the certificate again"
	default:
		return err
	}
	return &explained{msg: err.Error() + "\n" + h, err: err}
}

func parseRegType(s string) (pool.RegistrationType, error) {
	switch strings.ToUpper(s) {
	case "":
		return "", nil
	case "REG", "POOLREGISTRATION":
		return pool.PoolRegistration, nil
	case "REREG", "POOLREREGISTRATION":
		return pool.PoolReRegistration, nil
	}
	return "", fmt.Errorf("--type %q is not REG or REREG", s)
}

func (a *app) readProtectionKey(fd int) (string, error) {
	if fd < 0 {
		return "", nil
	}
	if a.passphraseFDSet() && fd == a.passFD {
		return "", errors.New("--protection-key-fd and --passphrase-fd name the same descriptor")
	}
	b, err := readFDSecret(fd, "the registration protection key")
	if err != nil {
		return "", err
	}
	defer b.Destroy()
	var key string
	if err := b.Use(func(p []byte) error { key = string(p); return nil }); err != nil {
		return "", err
	}
	return key, nil
}

// ---- cert generate --------------------------------------------------------------

func (a *app) poolCertCommand() *cobra.Command {
	cert := &cobra.Command{Use: "cert", Short: "The pool registration certificate"}
	var (
		chainf             chainFlags
		raiseCost, accTick bool
		protectionFD       int
	)
	gen := &cobra.Command{
		Use:   "generate <pool> [--raise-cost] [--accept-ticker] [--protection-key-fd N]",
		Short: "Make the pool metadata, the pool id files and the registration certificate from the descriptor",
		Long: `Check <pool>.pool.json, then write the published metadata, the pool id files
and the registration certificate in one step: a refusal writes nothing. The
descriptor must not hold CHANGE-ME placeholders.

Two answers upstream asks at a prompt are flags here, both off by default:
--raise-cost raises poolCost to the protocol minimum when it is below it, and
--accept-ticker accepts the ticker with its disallowed characters replaced.

--protection-key-fd reads the registration protection key from an inherited
descriptor (never argv or the environment). It is recorded in the descriptor
for the offline entry and is never sent anywhere and never printed.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &chainf, config: true, needs: []Need{CapParams, CapClock, CapPoolCerts, CapMetaHash}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				if d, err := readDescriptorOf(ctx, s.Store, name); err == nil {
					if ph := placeholderFields(d); len(ph) > 0 {
						return fmt.Errorf("the descriptor still holds %s placeholders in: %s; set them with `spo pool descriptor set %s KEY=VALUE`", placeholder, strings.Join(ph, ", "), name)
					}
				}
				key, err := a.readProtectionKey(protectionFD)
				if err != nil {
					return err
				}
				res, err := poolops.GeneratePoolCertificate{
					Store: s.Store, Params: env.Params, Certs: env.PoolCerts, Hasher: env.MetadataHasher, Clock: env.Clock,
					NetworkID: env.NetworkID, Choices: pool.Choices{RaiseCost: raiseCost, AcceptTicker: accTick},
				}.Run(ctx, poolops.GenerateRequest{Pool: name, ProtectionKey: key})
				if err != nil {
					var cb *pool.CostBelowMinimumError
					var tc *pool.TickerCorrectionError
					switch {
					case errors.As(err, &cb):
						return &explained{msg: err.Error() + "\npass --raise-cost to raise poolCost to the minimum, or change it: spo pool descriptor set " + name + " poolCost=" + fmt.Sprint(uint64(cb.Min)), err: err}
					case errors.As(err, &tc):
						return &explained{msg: err.Error() + "\npass --accept-ticker to use " + tc.To + " instead of " + tc.From + ", or change it: spo pool descriptor set " + name + " poolMetaTicker=...", err: err}
					case errors.Is(err, poolops.ErrNoDescriptor):
						return &explained{msg: err.Error() + "\ncreate it with: spo pool descriptor new " + name + " ...", err: err}
					}
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Generated the registration certificate of pool %s.\n", name)
				fmt.Fprintf(w, "Pool id (hex)    %s\nPool id (bech32) %s\nMetadata hash    %s\n", res.PoolIDHex, res.PoolIDBech, res.MetaHash)
				for _, c := range res.Corrections {
					fmt.Fprintf(w, "Corrected        %s\n", shown(fmt.Sprint(c.Field)))
				}
				for _, m := range res.Warnings {
					fmt.Fprintf(w, "Warning          %s\n", shown(fmt.Sprint(m)))
				}
				fmt.Fprintf(w, "Stored %s.pool.cert, %s.metadata.json and the pool id files; the descriptor was updated.\n", name, name)
				fmt.Fprintf(w, "Publish the metadata at the poolMetaUrl before registering: spo pool metadata show %s\n", name)
				return nil
			})
		},
	}
	gen.Flags().BoolVar(&raiseCost, "raise-cost", false, "raise poolCost to the protocol's minimum pool cost when it is below it")
	gen.Flags().BoolVar(&accTick, "accept-ticker", false, "accept the ticker with disallowed characters replaced by _")
	gen.Flags().IntVar(&protectionFD, "protection-key-fd", -1, "read the registration protection key from this inherited file descriptor")
	addChainFlags(gen, &chainf, true)
	cert.AddCommand(gen)
	return cert
}

// poolMetadataCommand prints the public metadata documents a pool publishes.
func (a *app) poolMetadataCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "metadata", Short: "The pool metadata to publish"}
	var extended bool
	show := &cobra.Command{
		Use:   "show <pool> [--extended]",
		Short: "Print <pool>.metadata.json (or the extended metadata) for publishing at poolMetaUrl",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				kind := ports.PoolMetadata
				if extended {
					kind = ports.PoolExtendedMetadata
				}
				return s.Store.View(ctx, func(r ports.Reader) error {
					b, err := r.Get(ports.Ref{Name: name, Kind: kind})
					if errors.Is(err, ports.ErrNotFound) {
						return fmt.Errorf("pool %s has no %s: run `spo pool cert generate %s`", name, kind, name)
					}
					if err != nil {
						return err
					}
					_, err = a.d.Out.Write(b)
					return err
				})
			})
		},
	}
	show.Flags().BoolVar(&extended, "extended", false, "the extended metadata instead")
	cmd.AddCommand(show)
	return cmd
}

// ---- register ---------------------------------------------------------------------

func (a *app) poolRegisterCommand() *cobra.Command {
	var f poolFlags
	cmd := &cobra.Command{
		Use:   "register <pool> <payer> [--type REG|REREG] [--allow-unverified] [--single-source] [--allow-pending] [--message TEXT]...",
		Short: "Register or update a pool: one transaction, signed by the cold key, the payer and every owner",
		Long: `Build the registration transaction (the pool certificate and the owners'
delegation certificates), collect one witness per signer, and send or queue it.
<payer> names the stored address that pays the fee and, for a first registration,
the pool deposit. Whoever holds a key signs it: this workspace signs for the keys
it holds; an owner whose descriptor entry says "external" signs elsewhere.

You are asked twice, and --yes does not exist for this command: before the body
is built and the witnesses collected (nothing is stored when you decline), and
again before the transaction goes out. The summary shows the pool id, pledge,
cost, margin, reward account, owners, relays, metadata URL and hash, the deposit,
the fee, the TTL, the registration type and who holds each signature.

The type is decided from the chain when it can say, else from the descriptor
(offline); --type forces it. A chain check that cannot be made refuses unless
--allow-unverified; a registration state that rests on one source refuses unless
--single-source.

--allow-pending leaves slots whose signer is not in this workspace empty: the
witness collection stays open, a witness transfer file is written for each open
slot, and the command exits 0 saying how many signatures it waits for. Import
each signed file with: spo pool witness import <pool> <file>, then run this
command again. A stored collection is final: --type and --message are refused
while it is open.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.yes {
				return errors.New(yesRegisterWhy)
			}
			typ, err := parseRegType(f.typ)
			if err != nil {
				return err
			}
			needs := stakeTxNeeds(CapPoolCertDecode, CapCertDecode, CapTxID, CapMetaHash, CapClock)
			spec := envSpec{flags: &f.chain, config: true, needs: needs, extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				uc := poolops.RegisterPool{
					Store: s.Store, Addresses: env.AddressInspector, Params: env.Params, Tip: env.Tip, Utxos: env.Utxos,
					Pipeline: a.poolPipeline(s, env), PoolCerts: env.PoolCertDecoder, StakeCerts: env.CertDecoder,
					TxIDs: env.TxIDs, Hasher: env.MetadataHasher, Clock: env.Clock,
					Pools: env.Pools, Metadata: env.Metadata, Attach: env.Attach, Files: env.MetadataFiles, Encrypter: env.MsgEncrypter,
					// Tickers stays nil in every mode: the lookup is not built (hazard H6).
					NetworkID: env.NetworkID, AllowUnverified: f.allowUnverified, AllowPending: f.allowPending,
				}
				uc.CrossCheck = env.PoolCross
				if f.singleSource {
					uc.Sources = poolops.SingleSourceAcknowledged
				}
				uc.OnSingle = a.singleSourceHook(s, "spo pool register")
				res, err := uc.Run(ctx, poolops.RegisterRequest{Pool: args[0], Payer: args[1], Type: typ, Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				return a.reportRegister(ctx, s, env, wo, args, res, f.allowPending)
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.typ, "type", "", "force the registration type: REG (first registration, pays the deposit) or REREG (re-registration)")
	fl.StringArrayVar(&f.messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	f.extra.add(cmd, &f.messages, extraCert)
	fl.BoolVar(&f.yes, "yes", false, "not accepted: this command is always asked")
	fl.BoolVar(&f.allowUnverified, "allow-unverified", false, "go on when the chain could not say whether the pool is registered: the type then comes from the descriptor. A wrong type only makes the ledger reject the transaction. The summary lists every check that was skipped")
	fl.BoolVar(&f.singleSource, "single-source", false, "accept a registration state that rests on ONE chain source. A false answer decides wrongly between registration and re-registration. The summary says so")
	fl.BoolVar(&f.allowPending, "allow-pending", false, "leave the slots of signers that are not in this workspace open, write their witness transfer files and exit 0 while waiting")
	addSubmitFlags(cmd, &f.chain, true)
	return cmd
}

func (a *app) reportRegister(ctx context.Context, s *session, env *Env, wo WireOptions, args []string, res poolops.RegisterResult, allowPending bool) error {
	w := a.d.Out
	name, _ := poolArg(args[0])
	if len(res.Missing) > 0 {
		var slots []slotInfo
		if d, err := readDescriptorOf(ctx, s.Store, name); err == nil {
			_ = s.Store.View(ctx, func(r ports.Reader) error {
				coll, _ := d.Collection(env.TxIDs.TransactionID)
				pn, _ := payerWord(args[1])
				for _, sl := range poolSlots(r, d, name, pn, false, coll) {
					for _, m := range res.Missing {
						if m == sl.name {
							slots = append(slots, sl)
						}
					}
				}
				return nil
			})
		}
		fmt.Fprintf(w, "\nWitness collection %d (%s) is open: waiting for %d signature(s).\n", res.CollectionID, res.Type, len(res.Missing))
		for _, sl := range slots {
			fmt.Fprintf(w, "  open slot  %-28s %-10s %s\n", sl.name, sl.role, sl.holder)
		}
		if len(slots) == 0 {
			for _, m := range res.Missing {
				fmt.Fprintf(w, "  open slot  %s\n", m)
			}
		}
		for _, tf := range res.TransferFiles {
			fmt.Fprintf(w, "  wrote      %s.witness\n", tf)
		}
		fmt.Fprintf(w, "Have each open slot signed, import the signed file with: spo pool witness import %s <file>, then run this command again.\n", name)
		if !allowPending {
			return fmt.Errorf("%d signature(s) are still missing, so the transaction cannot be assembled yet (pass --allow-pending to treat waiting as success)", len(res.Missing))
		}
		return nil
	}
	switch {
	case res.Submitted:
		fmt.Fprintf(w, "Submitted transaction %s through %s.\n", res.TxID, env.Source(CapSubmit))
	case res.Queued:
		fmt.Fprintf(w, "Queued transaction %s in %s. Submit it from an online machine.\n", res.TxID, wo.TransferFile)
	}
	fmt.Fprintf(w, "Recorded the %s of pool %s in its descriptor; %s.pool.cert is consumed.\n", res.Type, name, name)
	return nil
}

func payerWord(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "./"), ".addr")
	if s == "" || strings.ContainsAny(s, "/\\") {
		return "", fmt.Errorf("invalid payer %q", s)
	}
	return s, nil
}

// ---- witness ---------------------------------------------------------------------

func (a *app) poolWitnessCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "witness", Short: "Witnesses of an open registration: import, status, info, sign, clear"}

	var (
		overwrite bool
		chainf    chainFlags
	)
	imp := &cobra.Command{
		Use:   "import <pool> <file> [--overwrite]",
		Short: "Take a signed witness transfer file into the open collection",
		Long: `Verify the signed witness in <file> (the signature over the stored body hash and
the key hash of the slot) and store it in the pool's open collection. The file
carries no authenticated sender, and the output says so. A slot that already holds
a witness is replaced only with --overwrite.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &chainf, config: true, needs: []Need{CapGenesis, CapTip, CapTxID}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				st, err := os.Stat(args[1])
				if err != nil {
					return err
				}
				if !st.Mode().IsRegular() || st.Size() > maxWitnessFile {
					return fmt.Errorf("%s is not a regular file of at most %d bytes", args[1], maxWitnessFile)
				}
				b, err := os.ReadFile(args[1])
				if err != nil {
					return err
				}
				res, err := poolops.ImportWitness{Store: s.Store, Tip: env.Tip, TxIDs: env.TxIDs}.Run(ctx, poolops.ImportRequest{Pool: args[0], File: b, Overwrite: overwrite})
				if err != nil {
					if errors.Is(err, pool.ErrSlotFilled) {
						return &explained{msg: err.Error() + "\npass --overwrite to replace it", err: err}
					}
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Imported the witness of slot %s: it verifies against the stored body and the slot's key.\n", res.Slot)
				if res.Unauthenticated {
					fmt.Fprintln(w, "The file came with no authenticated sender; only the signature and the key hash were checked.")
				}
				fmt.Fprintf(w, "Collection is %s.\n", res.State)
				for _, m := range res.Missing {
					fmt.Fprintf(w, "  still open  %s\n", m)
				}
				if len(res.Missing) == 0 {
					name, _ := poolArg(args[0])
					fmt.Fprintf(w, "Every slot is signed: run `spo pool register %s <payer>` to send the transaction.\n", name)
				}
				return nil
			})
		},
	}
	imp.Flags().BoolVar(&overwrite, "overwrite", false, "replace a witness the slot already holds")
	addChainFlags(imp, &chainf, false)

	var sf chainFlags
	status := &cobra.Command{
		Use:   "status <pool>",
		Short: "Show the open witness collection: state, expiry and which slots are signed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &sf, config: true, needs: []Need{CapTxID}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				name, err := poolArg(args[0])
				if err != nil {
					return err
				}
				d, err := readDescriptorOf(ctx, s.Store, name)
				if err != nil {
					return err
				}
				coll, err := d.Collection(env.TxIDs.TransactionID)
				if err != nil {
					return err
				}
				w := a.d.Out
				var slot uint64
				var tipWhy string
				if env.Tip != nil {
					if t, err := env.Tip.Tip(ctx); err != nil {
						tipWhy = err.Error()
					} else {
						slot = t.Slot
					}
				} else {
					tipWhy = env.Reason(CapTip)
				}
				life := pool.LifecycleOf(d, coll, slot)
				fmt.Fprintf(w, "Pool %s: %s\n", name, life)
				if coll == nil {
					fmt.Fprintln(w, "No witness collection is open.")
					return nil
				}
				fmt.Fprintf(w, "  collection   %d (%s)\n", coll.ID, coll.Type)
				fmt.Fprintf(w, "  body hash    %s\n", coll.Body.ID)
				fmt.Fprintf(w, "  paid by      %s\n", coll.PayName)
				fmt.Fprintf(w, "  valid until  slot %d\n", coll.TTL)
				if tipWhy != "" {
					fmt.Fprintf(w, "  current slot unknown (%s): expiry cannot be judged\n", tipWhy)
				} else {
					st := coll.State(slot)
					fmt.Fprintf(w, "  state        %s at slot %d", st, slot)
					if st == pool.CollectionExpired {
						fmt.Fprintf(w, " (expired %d slots ago: discard it and register again)", slot-coll.TTL)
					} else if coll.TTL >= slot {
						fmt.Fprintf(w, " (%d slots left)", coll.TTL-slot)
					}
					fmt.Fprintln(w)
				}
				var slots []slotInfo
				_ = s.Store.View(ctx, func(r ports.Reader) error {
					slots = poolSlots(r, d, name, coll.PayName, false, coll)
					return nil
				})
				missing := 0
				for _, sl := range slots {
					if sl.signed != nil && !*sl.signed {
						missing++
					}
				}
				fmt.Fprintf(w, "  signatures   %d of %d signed, %d missing\n", len(slots)-missing, len(slots), missing)
				printSlots(w, slots)
				return nil
			})
		},
	}
	addChainFlags(status, &sf, false)
	cmd.AddCommand(imp, status, a.witnessSignCommand(), a.witnessInfoCommand(), a.witnessClearCommand())
	return cmd
}

// ---- status -----------------------------------------------------------------------

func (a *app) poolStatusCommand() *cobra.Command {
	var f chainFlags
	cmd := &cobra.Command{
		Use:   "status <pool|pool-id>",
		Short: "Is the pool registered on the chain? (the facts, with their source)",
		Long: `Read the registration of a pool from the chain provider (light mode) or the
transfer file, when it holds pool state. <pool> is the name of a stored pool or a
pool id. An answer the provider did not give is "unknown", never "not registered",
and fails the command.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f, config: true, needs: []Need{CapPools}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := poolops.CheckPoolOnChain{Store: s.Store, Pools: env.Pools}.Run(ctx, args[0])
				if err != nil {
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Pool %s\n  pool id      %x\n  status       %s [%s]\n", res.Bech32, res.PoolID[:], res.Status, res.Source)
				if res.Status == poolops.StatusUnknown {
					fmt.Fprintf(w, "  why          %s\n", shown(res.Why))
					return fmt.Errorf("the registration state is unknown: %s", shown(res.Why))
				}
				if res.Status == poolops.StatusNotRegistered {
					return nil
				}
				st := res.State
				line := func(k, v string) {
					if v != "" {
						fmt.Fprintf(w, "  %-12s %s [%s]\n", k, shown(v), shown(string(res.Source)))
					}
				}
				line("name", st.Name)
				line("ticker", st.Ticker)
				if st.RetiringEpoch > 0 {
					line("retires at", fmt.Sprintf("epoch %d", st.RetiringEpoch))
				}
				line("pledge", readingText(st.Pledge, "not reported", lovelaceText))
				line("cost", readingText(st.Cost, "not reported", lovelaceText))
				line("margin", st.Margin)
				line("reward addr", st.RewardAddress)
				line("metadata", st.MetaURL)
				line("meta hash", st.MetaHash)
				return nil
			})
		},
	}
	addChainFlags(cmd, &f, true)
	return cmd
}

// ---- retirement -------------------------------------------------------------------

func (a *app) poolRetireCertCommand() *cobra.Command {
	var (
		f     chainFlags
		epoch uint64
	)
	cmd := &cobra.Command{
		Use:   "retire-cert <pool> [--epoch N]",
		Short: "Make the retirement certificate of a pool (no transaction)",
		Long: `Make the certificate that retires the pool at an epoch and store it. Without
--epoch the earliest epoch is used: the next one. An epoch outside the window the
ledger accepts (the next epoch up to the current one plus the protocol's maximum)
is set to the nearest edge, and the output says so. Nothing is sent: spo pool
retire does that.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &f, config: true, needs: []Need{CapParams, CapGenesis, CapTip, CapPoolCerts, CapClock}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				req := poolops.RetirementRequest{Pool: args[0]}
				if cmd.Flags().Changed("epoch") {
					req.Epoch = &epoch
				}
				res, err := poolops.GenerateRetirementCertificate{Store: s.Store, Params: env.Params, Tip: env.Tip, Certs: env.PoolCerts, Clock: env.Clock}.Run(ctx, req)
				if err != nil {
					return err
				}
				w := a.d.Out
				name, _ := poolArg(args[0])
				fmt.Fprintf(w, "Stored %s.pool.dereg-cert: the pool retires at epoch %d (allowed %d to %d).\n", name, res.Epoch, res.Earliest, res.Latest)
				for _, m := range res.Warnings {
					fmt.Fprintf(w, "Warning: %s\n", shown(fmt.Sprint(m)))
				}
				return nil
			})
		},
	}
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "retire at this epoch (default: the next one)")
	addChainFlags(cmd, &f, true)
	return cmd
}

func (a *app) poolRetireCommand() *cobra.Command {
	var f poolFlags
	cmd := &cobra.Command{
		Use:   "retire <pool> <payer> [--message TEXT]...",
		Short: "Send the retirement certificate: one transaction, signed by the payer and the pool cold key",
		Long: `Send the stored retirement certificate. <payer> names the stored address that
pays the fee; no deposit moves in this transaction. The summary is shown and you
are asked before anything is signed; the default answer is No and --yes does not
exist for this command. The epoch is checked against the current epoch and the
protocol's maximum before a fee is spent.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.yes {
				return errors.New(yesRetireWhy)
			}
			needs := stakeTxNeeds(CapPoolCertDecode, CapClock)
			spec := envSpec{flags: &f.chain, config: true, needs: needs, extras: &f.extra}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, wo WireOptions) error {
				res, err := poolops.RetirePool{
					Store: s.Store, Addresses: env.AddressInspector, Params: env.Params, Tip: env.Tip, Utxos: env.Utxos,
					Pipeline: a.poolPipeline(s, env), PoolCerts: env.PoolCertDecoder, Clock: env.Clock, NetworkID: env.NetworkID,
					Files: env.MetadataFiles, Encrypter: env.MsgEncrypter,
				}.Run(ctx, poolops.RetireRequest{Pool: args[0], Payer: args[1], Message: f.messages, Extras: f.extra.ex, Passphrase: f.extra.pass})
				if err != nil {
					return f.hint(err)
				}
				w := a.d.Out
				switch {
				case res.Submitted:
					fmt.Fprintf(w, "Submitted transaction %s through %s.\n", res.TxID, env.Source(CapSubmit))
				case res.Queued:
					fmt.Fprintf(w, "Queued transaction %s in %s. Submit it from an online machine.\n", res.TxID, wo.TransferFile)
				}
				fmt.Fprintf(w, "The pool retires at epoch %d.\n", res.Epoch)
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&f.messages, "message", nil, "CIP-20 message line, at most 64 bytes (repeatable)")
	f.extra.add(cmd, &f.messages, extraCert)
	cmd.Flags().BoolVar(&f.yes, "yes", false, "not accepted: this command is always asked")
	addSubmitFlags(cmd, &f.chain, true)
	return cmd
}
