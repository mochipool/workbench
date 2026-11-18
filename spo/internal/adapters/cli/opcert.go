package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/query"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (a *app) kesCommand() *cobra.Command {
	kesCmd := &cobra.Command{Use: "kes", Short: "KES key rotation"}
	kesCmd.AddCommand(&cobra.Command{
		Use:   "generate <pool>",
		Short: "Generate the KES key pair for the next operational certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{needs: []Need{CapKesKeys}}, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				res, err := poolops.GenerateKesKey{Store: s.Store, KeyGen: env.KesKeys}.Run(ctx, args[0])
				if err != nil {
					return err
				}
				// The verification key is public. The signing key is never shown.
				fmt.Fprintf(a.d.Out, "Generated KES key %03d for pool %s.\n%s\n", res.Number, res.Pool, res.VKey)
				return nil
			})
		},
	})
	return kesCmd
}

func (a *app) opcertCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "opcert", Short: "Operational certificates"}

	var (
		counter uint64
		flags   chainFlags
		single  bool
	)
	issue := &cobra.Command{
		Use:   "issue <pool>",
		Short: "Issue the operational certificate for the waiting KES key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &flags, needs: []Need{CapSigners, CapClock, CapGenesis, CapTip, CapOpCertCount}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				var iopts poolops.IssueOptions
				if cmd.Flags().Changed("counter") {
					iopts.CounterOverride = &counter
				}
				res, err := poolops.IssueOperationalCertificate{
					Store: s.Store, Signers: env.Signers, Tip: env.Tip, Genesis: env.Genesis,
					Counters: env.OpCertCounters, Cross: env.OpCertCross, SingleSource: single, OnSingle: a.singleSourceHook(s, "spo pool opcert issue"),
					Clock: env.Clock, AllowUnverified: env.AllowUnverified,
				}.Run(ctx, args[0], iopts)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Issued operational certificate %s.node-%03d.opcert with counter %d for KES period %d.\n",
					res.Pool, res.KesNumber, res.Counter, res.KesPeriod)
				fmt.Fprintf(a.d.Out, "KES key %03d expires in period %d, about %s.\n",
					res.KesNumber, res.Expiry.ExpireKESPeriod, res.Expiry.ExpireKESDate.Local().Format(pool.ExpireDateLayout))
				if res.Verified {
					fmt.Fprintf(a.d.Out, "The counter was checked against the chain (%s).\n", shown(string(res.Source)))
					if res.SingleSource {
						printSingleSourceWarning(a.d.Out, "the operational certificate counter", string(res.Source))
					}
				} else {
					fmt.Fprintln(a.d.Out, "The counter was not checked against the chain (offline). Check it on an online machine before use.")
				}
				return nil
			})
		},
	}
	issue.Flags().Uint64Var(&counter, "counter", 0, "issue with this counter instead of the stored one (also creates a missing counter file)")
	issue.Flags().BoolVar(&single, "single-source", false, opcertSingleSourceHelp)
	addChainFlags(issue, &flags, false)
	cmd.AddCommand(issue)

	var value uint64
	newCounter := &cobra.Command{
		Use:   "new-counter <pool>",
		Short: "Create the issue counter of a pool that has none",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.withEnv(cmd, envSpec{}, func(ctx context.Context, s *session, _ *Env, _ WireOptions) error {
				if err := (poolops.CreateIssueCounter{Store: s.Store}).Run(ctx, args[0], value); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Created the issue counter of pool %s at %d.\n", args[0], value)
				return nil
			})
		},
	}
	newCounter.Flags().Uint64Var(&value, "value", 0, "the next issue number")
	cmd.AddCommand(newCounter)
	cmd.AddCommand(a.opcertCheckCommand(), a.opcertCounterCommand())
	return cmd
}

// ErrOpCertCheck is returned when the check's verdict is FALSE or UNKNOWN.
// Upstream (04e) exits 0 for a FALSE verdict; here a verdict that is not OK
// is a failure, so a script cannot read it as success.
var ErrOpCertCheck = errors.New("the operational certificate check did not pass")

func (a *app) opcertCheckCommand() *cobra.Command {
	var (
		flags   chainFlags
		single  bool
		next    bool
		file    string
		number  int
		haveNum bool
	)
	cmd := &cobra.Command{
		Use:   "check [<pool>] [--next] [--opcert-file FILE] [--number N]",
		Short: "Check an operational certificate against the chain",
		Long: `Check the counter and the KES period of an operational certificate: the newest
stored one of <pool> (or --number N of it), or the file given with --opcert-file.
Without --next the counter in the certificate must equal the counter of the
pool's last block on the chain (0 and no block yet is fine); with --next it
must be that counter plus one, which is what a certificate about to be installed
needs.

The verdict is OK, FALSE (with the reasons) or UNKNOWN (with why the chain's
answer is not known: no connection, a pool the provider does not know, offline
mode). EXIT STATUS: 0 for OK; non-zero for FALSE and for UNKNOWN. This differs
from upstream 04e, which exits 0 after a FALSE verdict; a script must not read
a FALSE or UNKNOWN verdict as success.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && file == "" {
				return errors.New("name the pool, or give the certificate with --opcert-file")
			}
			haveNum = cmd.Flags().Changed("number")
			if haveNum && file != "" {
				return errors.New("--number selects a stored certificate; it does not apply with --opcert-file")
			}
			spec := envSpec{flags: &flags, needs: []Need{CapTip, CapGenesis, CapOpCertCount}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				req := query.OpCertCheck{Check: query.CheckCurrent}
				if next {
					req.Check = query.CheckNext
				}
				if len(args) == 1 {
					req.Pool = args[0]
				}
				if haveNum {
					req.Number = &number
				}
				if file != "" {
					b, err := readSmallFile(file, 64<<10)
					if err != nil {
						return err
					}
					req.OpCert = b
				}
				v, err := query.CheckOpCert{Store: s.Store, Tip: env.Tip, Genesis: env.Genesis, Counters: env.OpCertCounters, Cross: env.OpCertCross, SingleSource: single, OnSingle: a.singleSourceHook(s, "spo pool opcert check"), Sync: env.Sync}.Run(ctx, req)
				if err != nil {
					return err
				}
				printOpCertVerdict(a.d.Out, v, req.Check)
				if v.Single {
					printSingleSourceWarning(a.d.Out, "the operational certificate counter", string(v.Source))
				}
				if v.Status != query.StatusOK {
					return fmt.Errorf("%w: %s", ErrOpCertCheck, verdictWord(v.Status))
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&next, "next", false, "check that the counter is the chain's plus one (a certificate about to be installed)")
	cmd.Flags().StringVar(&file, "opcert-file", "", "check this certificate file instead of a stored one")
	cmd.Flags().BoolVar(&single, "single-source", false, opcertSingleSourceHelp)
	cmd.Flags().IntVar(&number, "number", 0, "check the stored certificate with this number (default: the newest)")
	addChainFlags(cmd, &flags, false)
	cmd.MarkFlagsMutuallyExclusive("number", "opcert-file")
	return cmd
}

func verdictWord(s query.Status) string {
	switch s {
	case query.StatusOK:
		return "OK"
	case query.StatusFalse:
		return "FALSE"
	}
	return "UNKNOWN"
}

func counterOnChain(r chain.Reading[uint64]) string {
	return readingText(r, "none: the pool has made no block yet", func(n uint64) string { return fmt.Sprint(n) })
}

func printOpCertVerdict(w io.Writer, v query.OpCertVerdict, c query.CounterCheck) {
	fmt.Fprintf(w, "Operational certificate check (%s)\n", c)
	fmt.Fprintf(w, "  pool            %s (%x)\n", v.PoolID.Bech32(), v.PoolID[:])
	if v.Number != nil {
		fmt.Fprintf(w, "  certificate     stored, number %d\n", *v.Number)
	} else {
		fmt.Fprintln(w, "  certificate     from the file")
	}
	fmt.Fprintf(w, "  counter in file %d\n", v.OnDisk)
	fmt.Fprintf(w, "  counter on chain %s  [%s]\n", counterOnChain(v.OnChain), shown(string(v.Source)))
	if v.NextRequired != nil {
		fmt.Fprintf(w, "  next required   %d\n", *v.NextRequired)
	}
	fmt.Fprintf(w, "  KES period      now %d, certificate valid %d to %d (%s)\n", v.Window.CurrentPeriod, v.Window.StartPeriod, v.Window.ExpirePeriod, verdictWord(v.KES))
	fmt.Fprintf(w, "  counter check   %s\n", verdictWord(v.Counter))
	fmt.Fprintf(w, "VERDICT: %s\n", verdictWord(v.Status))
	for _, r := range v.Reasons {
		fmt.Fprintf(w, "  - %s\n", shown(fmt.Sprint(r)))
	}
	if v.Status == query.StatusUnknown {
		why := "the counter on the chain is not known"
		if v.OnChain.Why() != "" {
			why += ": " + v.OnChain.Why()
		}
		fmt.Fprintf(w, "  - %s\n", shown(why))
	}
}

// opcertSingleSourceHelp is the help of --single-source on the opcert commands.
const opcertSingleSourceHelp = "go on when a second provider is not configured (issue requires this) or does not answer; the counter then rests on ONE source and the acknowledgement is recorded in the audit log. A disagreement between two sources, including one that differs by one, is never overridden"

func (a *app) opcertCounterCommand() *cobra.Command {
	var flags chainFlags
	var single bool
	cmd := &cobra.Command{
		Use:   "counter <pool|pool-id>",
		Short: "Show the operational certificate counter of a pool on the chain",
		Long: `Show the counter of the pool's last block on the chain, and the number the next
certificate must carry. <pool> is a stored pool name or a pool id (bech32 or
hex). Exit status is non-zero when the chain's answer is not known.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec := envSpec{flags: &flags, needs: []Need{CapOpCertCount}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				r, err := query.QueryOpCertCounter{Store: s.Store, Counters: env.OpCertCounters, Pools: env.Pools, Cross: env.OpCertCross, SingleSource: single, OnSingle: a.singleSourceHook(s, "spo pool opcert counter")}.Run(ctx, args[0])
				if err != nil {
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Pool %s (%x)\n", r.Bech32, r.PoolID[:])
				if r.Ticker != "" || r.Name != "" {
					fmt.Fprintf(w, "  registered as   %s (%s)\n", shown(r.Ticker), shown(r.Name))
				}
				fmt.Fprintf(w, "  counter on chain %s  [%s]\n", counterOnChain(r.Counter), shown(string(r.Source)))
				if r.Next != nil {
					fmt.Fprintf(w, "  next required   %d\n", *r.Next)
				}
				if r.Single {
					printSingleSourceWarning(w, "the operational certificate counter", string(r.Source))
				}
				if r.Counter.IsUnknown() {
					return fmt.Errorf("the counter is not known: %s", r.Counter.Why())
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&single, "single-source", false, opcertSingleSourceHelp)
	addChainFlags(cmd, &flags, false)
	return cmd
}

// providerTokenKind is the artefact kind of provider API tokens: a secret
// kind, named by provider.
var providerTokenKind = ports.ProviderToken

func tokenRef(provider string) ports.NamedRef {
	return ports.NamedRef{Name: provider, Kind: providerTokenKind}
}

// loadToken returns the stored API token of a provider, or nil when none is
// stored. The caller destroys it.
func (a *app) loadToken(cmd *cobra.Command, s *session, provider string) (*secret.Buffer, error) {
	if !providerTokenKind.Known() {
		return nil, nil
	}
	vault, ok := s.Store.(ports.NamedVault)
	if !ok {
		return nil, nil
	}
	var has bool
	if err := s.Store.View(cmd.Context(), func(r ports.NamedReader) error {
		var err error
		has, err = r.Exists(tokenRef(provider))
		return err
	}); err != nil || !has {
		return nil, err
	}
	return vault.Open(cmd.Context(), tokenRef(provider))
}
