// Command spo is the composition root: it wires adapters to use cases and
// does nothing else.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/genesisfile"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/offline"
	"github.com/mochipool/workbench/spo/internal/adapters/systemclock"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// version is set at build time with -ldflags.
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	// Before anything can hold a key: no core dumps, not ptrace-able (E4).
	if err := secret.HardenProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "spo: cannot harden the process:", err)
		return 1
	}
	defer secret.Purge()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	deps := cli.Deps{Version: version, Release: "none", Out: os.Stdout, Err: os.Stderr, Toolchain: noToolchain{}}
	manifest, err := toolchain.Load(os.Getenv(toolchain.EnvVar))
	switch {
	case err == nil:
		tc := toolchain.New(manifest, execx.OS{})
		deps.Toolchain, deps.Tools, deps.Release = tc, tc.Names(), tc.Release()
	case errors.Is(err, toolchain.ErrNoManifest):
		deps.Toolchain = noToolchain{err: err}
	default:
		fmt.Fprintln(os.Stderr, "spo:", err)
		return 1
	}

	deps.KeyGen = native.KeyGen{}
	deps.OfflineOpCert = offlineOpCert
	deps.OpenStore = func(dir string, upstreamLayout bool) (ports.Store, error) {
		if !upstreamLayout {
			return nil, errors.New("the sealed store is not built yet; pass --upstream-layout to work on a directory in the upstream file layout (keys unsealed)")
		}
		return fsstore.Open(dir)
	}

	if err := cli.NewRoot(deps).ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "spo:", err)
		return 1
	}
	return 0
}

// noToolchain refuses every tool when the binary runs without a manifest.
type noToolchain struct{ err error }

func (n noToolchain) Tool(context.Context, ports.ToolName) (ports.Tool, error) {
	if n.err != nil {
		return ports.Tool{}, n.err
	}
	return ports.Tool{}, toolchain.ErrNoManifest
}

// offlineOpCert wires operational certificate issue for a machine that does
// not consult the chain.
func offlineOpCert(store ports.Store, o cli.OfflineOptions) (cli.OpCertWiring, error) {
	vault, ok := store.(ports.Vault)
	if !ok {
		return cli.OpCertWiring{}, errors.New("the store cannot release signing keys to a signer")
	}
	signers := native.Signers{Vault: vault}
	for _, h := range []custody.Holder{custody.HolderVault} {
		s, err := signers.SignerFor(custody.KeyRef{Role: custody.RolePoolCold, Holder: h})
		if err != nil {
			return cli.OpCertWiring{}, err
		}
		if err := ports.CheckSigner(s); err != nil {
			return cli.OpCertWiring{}, err
		}
	}
	clock := systemclock.Clock{}
	genesis := genesisfile.Shelley{Path: o.ShelleyGenesis}
	tip := offline.Tip{Clock: clock, Genesis: genesis}
	if o.ByronEpochs > 0 {
		byron, err := genesisfile.ReadByron(o.ByronGenesis, o.ByronEpochs)
		if err != nil {
			return cli.OpCertWiring{}, err
		}
		tip.Byron = &byron
	}
	return cli.OpCertWiring{Signers: signers, Tip: tip, Genesis: genesis, Counters: offline.Counters{}, Clock: clock}, nil
}
