// Command spo-relay is the relay mailbox of ADR 0013 and ADR 0014: it holds
// sealed envelopes for the devices its tunnel admits, and can open none of them.
// This main only gives internal/app/relayhost the adapters (the configuration
// and key files, the two stores, the tailcat listener) and the signals; the
// logic and its tests are there. See docs/how-to/run-a-relay.md.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat/stream"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// deps are the production adapters, with the operator log on log.
func deps(log io.Writer) relayhost.Deps {
	return relayhost.Deps{
		LoadConfig: relayconfig.Load,
		LoadKey:    relayconfig.LoadKey,
		CreateKey:  func(p string) (*relayconf.Key, error) { return relayconfig.CreateKey(p, rand.Reader) },
		PublicKey: func(k *relayconf.Key) (party.NodeKey, error) {
			return stream.PublicKey(stream.KeyBytes(k.Node))
		},
		// the directory stores; OpenLease is left nil: the single-host lease, since
		// each directory's own lock keeps one writer
		OpenMailbox: func(spec relayhost.StoreSpec, env relayhost.StoreEnv) (relayport.MailboxStore, []string, error) {
			if spec.Kind != relayhost.StoreDirectory {
				return nil, nil, errors.New("this build opens directory stores only")
			}
			s, notes, err := mailboxstore.Open(spec.Dir, env.Clock)
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		OpenRegistry: func(spec relayhost.StoreSpec, cfg relayregistry.Config, env relayhost.StoreEnv) (relayport.Registry, []string, error) {
			if spec.Kind != relayhost.StoreDirectory {
				return nil, nil, errors.New("this build opens directory stores only")
			}
			s, notes, err := bindingstore.Open(spec.Dir, cfg, env.Clock)
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		Listen: func(ctx context.Context, spec relayhost.TunnelSpec) (relayhost.Tunnel, error) {
			l, err := stream.Listen(ctx, listenerConfig(spec))
			if err != nil {
				return nil, err
			}
			return l, nil
		},
		Rand: rand.Reader,
		Log:  log,
	}
}

// listenerConfig is the tailcat listener of a relay's tunnel spec: its keys,
// devices, port and DERP map, its stuck-teardown hook and its log (the
// adapter's lines go to the operator log through spec.Logf, which keeps them
// one line each and drops the tunnel library's chatter).
func listenerConfig(spec relayhost.TunnelSpec) stream.ListenerConfig {
	return stream.ListenerConfig{
		NodeKey: stream.SecretReader(spec.NodeKey), PSK: stream.SecretReader(spec.PSK),
		Allowed: spec.Allowed, Port: spec.Port, DERPMapURL: spec.DERPMapURL,
		Pin: regionPin(spec.Region), RegionID: spec.RegionID,
		OnTeardownStuck: spec.OnTeardownStuck, Logf: spec.Logf,
	}
}

// regionPin is the configured full region as the listener's type. It has no
// InsecureForTests: the listener's raw Region (the test rig's) is never set here.
func regionPin(r *relayconf.DERPRegion) *stream.RegionPin {
	if r == nil {
		return nil
	}
	p := &stream.RegionPin{ID: r.ID, Code: r.Code}
	for _, n := range r.Nodes {
		p.Nodes = append(p.Nodes, stream.RegionNode{Name: n.Name, HostName: n.HostName, CertName: n.CertName,
			IPv4: n.IPv4, IPv6: n.IPv6, STUNPort: int(n.STUNPort), DERPPort: int(n.DERPPort)})
	}
	return p
}

// signals turns SIGHUP into SignalReload and SIGINT and SIGTERM into SignalStop.
func signals(raw <-chan os.Signal) <-chan relayhost.Signal {
	sig := make(chan relayhost.Signal)
	go func() {
		for s := range raw {
			if s == syscall.SIGHUP {
				sig <- relayhost.SignalReload
			} else {
				sig <- relayhost.SignalStop
			}
		}
	}()
	return sig
}

func main() {
	raw := make(chan os.Signal, 4)
	signal.Notify(raw, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	os.Exit(relayhost.Main(os.Args[1:], os.Stdout, os.Stderr, signals(raw), deps(os.Stderr)))
}
