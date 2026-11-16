package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/poolops"
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
					Counters: env.OpCertCounters, Clock: env.Clock, AllowUnverified: env.AllowUnverified,
				}.Run(ctx, args[0], iopts)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Issued operational certificate %s.node-%03d.opcert with counter %d for KES period %d.\n",
					res.Pool, res.KesNumber, res.Counter, res.KesPeriod)
				fmt.Fprintf(a.d.Out, "KES key %03d expires in period %d, about %s.\n",
					res.KesNumber, res.Expiry.ExpireKESPeriod, res.Expiry.ExpireKESDate.Local().Format(pool.ExpireDateLayout))
				if res.Verified {
					fmt.Fprintf(a.d.Out, "The counter was checked against the chain (%s).\n", env.OpCertCounters.Source())
				} else {
					fmt.Fprintln(a.d.Out, "The counter was not checked against the chain (offline). Check it on an online machine before use.")
				}
				return nil
			})
		},
	}
	issue.Flags().Uint64Var(&counter, "counter", 0, "issue with this counter instead of the stored one (also creates a missing counter file)")
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
	return cmd
}

// providerTokenKind is the artefact kind of provider API tokens: a secret
// kind, named by provider.
var providerTokenKind = ports.ProviderToken

func tokenRef(provider string) ports.Ref { return ports.Ref{Name: provider, Kind: providerTokenKind} }

// loadToken returns the stored API token of a provider, or nil when none is
// stored. The caller destroys it.
func (a *app) loadToken(cmd *cobra.Command, s *session, provider string) (*secret.Buffer, error) {
	if !providerTokenKind.Known() {
		return nil, nil
	}
	vault, ok := s.Store.(ports.Vault)
	if !ok {
		return nil, nil
	}
	var has bool
	if err := s.Store.View(cmd.Context(), func(r ports.Reader) error {
		var err error
		has, err = r.Exists(tokenRef(provider))
		return err
	}); err != nil || !has {
		return nil, err
	}
	return vault.Open(cmd.Context(), tokenRef(provider))
}
