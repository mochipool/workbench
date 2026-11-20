// Command spo-relay is the relay mailbox of ADR 0013 and ADR 0014: it holds
// sealed envelopes for the devices its tunnel admits, and can open none of them.
// This main only gives internal/app/relayhost the adapters (the configuration
// and key files, the two stores, the tailcat listener) and the signals; the
// logic and its tests are there. See docs/how-to/run-a-relay.md.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/adapters/relaydir"
	"github.com/mochipool/workbench/spo/internal/adapters/relaystore"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat/stream"
	"github.com/mochipool/workbench/spo/internal/adapters/webidentity"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/platform/stsweb"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// deps are the production adapters, with the operator log on log.
func deps(log io.Writer) relayhost.Deps { return depsWith(log, storeOptions{}) }

// depsWith are the production adapters with a test's store options.
func depsWith(log io.Writer, o storeOptions) relayhost.Deps {
	return relayhost.Deps{
		// the object store ([store] kind = "s3"): web identity, both buckets, the
		// lease, the object mailbox and registry (store.go)
		OpenObjectStore: o.openObjectStore,
		LoadConfig:      relayconfig.Load,
		LoadKey:         relayconfig.LoadKey,
		CreateKey:       func(p string) (*relayconf.Key, error) { return relayconfig.CreateKey(p, rand.Reader) },
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

// storeTool is the command line of the store tools (ADR 0015 work package 9,
// internal/adapters/relaystore): the clients are built from [store] as
// openObjectStore builds them, the node key from the key file, and a
// confirmation is read from the terminal, never from standard input.
func storeTool() relaystore.CLI {
	open := func(path string) (relaystore.Deps, func(), error) {
		var none relaystore.Deps
		cfg, err := relayconfig.Load(path)
		if err != nil {
			return none, nil, err
		}
		c := cfg.Object
		if cfg.StoreKind() != relayconf.StoreS3 || c == nil {
			return none, nil, errors.New("the configuration's [store] is not kind = \"s3\": the store commands are for an object store")
		}
		k, err := relayconfig.LoadKey(cfg.KeyFile)
		if err != nil {
			return none, nil, fmt.Errorf("the key file: %w", err)
		}
		pub, err := stream.PublicKey(stream.KeyBytes(k.Node))
		k.Destroy()
		if err != nil {
			return none, nil, fmt.Errorf("the key file: %w", err)
		}
		endpoint := c.Endpoint
		if endpoint == "" {
			if endpoint, err = stsweb.RegionEndpoint("s3", c.Region); err != nil {
				return none, nil, err
			}
		}
		prov, err := webidentity.New(webidentity.Config{Region: c.Region, RoleARN: c.RoleARN, TokenFile: c.TokenFile,
			Endpoint: c.STSEndpoint, AllowLoopbackHTTP: c.LoopbackHTTP && c.STSEndpoint != ""})
		if err != nil {
			return none, nil, err
		}
		var cs [2]*s3client.Client
		for i, b := range []string{c.RegistryBucket, c.WorkingBucket} {
			if cs[i], err = s3client.New(s3client.Config{Endpoint: endpoint, Region: c.Region, Bucket: b, PathStyle: c.PathStyle,
				Credentials: prov, AllowLoopbackHTTP: c.LoopbackHTTP}); err != nil {
				return none, nil, fmt.Errorf("the bucket %s: %w", b, err)
			}
		}
		mode := s3client.Compliance
		if c.LockMode == relayconf.LockGovernance {
			mode = s3client.Governance
		}
		return relaystore.Deps{Registry: cs[0], Working: cs[1], NodeKey: pub, Mode: mode, Clock: toolClock{},
			RequestTimeout: c.RequestTimeout, Core: cfg.Registry}, func() { cs[0].Close(); cs[1].Close() }, nil
	}
	return relaystore.CLI{Open: open, Stdout: os.Stdout, Stderr: os.Stderr,
		OpenDir: func(m, r string) (relaystore.DirSource, func() error, error) {
			s, err := relaydir.Open(m, r)
			if err != nil {
				return nil, nil, err
			}
			return s, s.Close, nil
		},
		Confirm: func(q string) (bool, error) {
			tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return false, fmt.Errorf("there is no terminal to confirm on (%v)", err)
			}
			defer tty.Close()
			fmt.Fprintf(tty, "%s [y/N] ", q)
			line, _ := bufio.NewReader(io.LimitReader(tty, 64)).ReadString('\n')
			a := strings.ToLower(strings.TrimSpace(line))
			return a == "y" || a == "yes", nil
		},
	}
}

// toolClock is time.Now, whose readings carry the monotonic part the lease needs.
type toolClock struct{}

func (toolClock) Now() time.Time { return time.Now() }

func main() {
	if len(os.Args) > 1 && relaystore.IsCommand(os.Args[1]) {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		code := relaystore.Main(ctx, os.Args[1:], storeTool())
		stop()
		os.Exit(code)
	}
	raw := make(chan os.Signal, 4)
	signal.Notify(raw, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	os.Exit(relayhost.Main(os.Args[1:], os.Stdout, os.Stderr, signals(raw), deps(os.Stderr)))
}
