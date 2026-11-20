package relayhost

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"

	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

// Signal is what the process was told by its operator: the binary maps SIGINT
// and SIGTERM to SignalStop and SIGHUP to SignalReload.
type Signal int

// The signals.
const (
	SignalStop Signal = iota + 1
	SignalReload
)

// The exit statuses (SPO-Xmailbox-OUT-101).
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
	// ExitStuck: the teardown did not finish; the tunnel engine may still be up.
	ExitStuck = 3
	// ExitAuthority: the relay is no longer the writer of its store (its lease
	// was lost, or a conditional write met another writer's change). The teardown
	// finished and the lease was not released. A restart is the remedy, and the
	// new process waits for the lease; the status tells a supervisor and an
	// alert this cause from a configuration fault (1) and from a stuck tunnel
	// (3), which wins when both happen.
	ExitAuthority = 4
)

// authorityMsg is what serve says when the authority is lost.
const authorityMsg = "spo-relay: the relay is no longer the writer of its store (its lease was lost, or another writer changed it); it stopped serving and exits without releasing the lease, so that its supervisor can start it again"

const usage = `usage:
  spo-relay serve --config FILE [--print-address]
  spo-relay check-config --config FILE
  spo-relay init-key --config FILE

serve         run the relay until SIGINT or SIGTERM; SIGHUP reloads the [[device]] list
check-config  check the configuration (and the key file, when there is one) without starting
init-key      create the relay's key file (node key and pre-shared key) and print its node key

The relay holds sealed envelopes it cannot open and no party secret. Its tunnel
admits only the device node keys of the [[device]] tables.
`

// Main is the command line of spo-relay (SPO-Xmailbox-IF-023): it returns the
// exit status. signals is read by serve only.
func Main(args []string, stdout, stderr io.Writer, signals <-chan Signal, d Deps) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	fl := flag.NewFlagSet("spo-relay "+cmd, flag.ContinueOnError)
	fl.SetOutput(stderr)
	conf := fl.String("config", "", "the relay's configuration file")
	var printAddr *bool
	switch cmd {
	case "serve":
		printAddr = fl.Bool("print-address", false, "print the relay's address (a secret: it holds the pre-shared key) on standard output")
	case "check-config", "init-key":
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "spo-relay: unknown command %q\n%s", cmd, usage)
		return ExitUsage
	}
	if err := fl.Parse(rest); err != nil {
		return ExitUsage
	}
	if *conf == "" || fl.NArg() != 0 {
		fmt.Fprintf(stderr, "spo-relay %s: --config FILE is required and nothing else is taken\n%s", cmd, usage)
		return ExitUsage
	}
	if d.LoadConfig == nil || d.LoadKey == nil || d.CreateKey == nil || d.PublicKey == nil {
		fmt.Fprintln(stderr, "spo-relay: this build is missing an adapter")
		return ExitFail
	}
	cfg, err := d.LoadConfig(*conf)
	if err == nil {
		_, err = Prepare(cfg)
	}
	if err != nil {
		fmt.Fprintf(stderr, "spo-relay: %v\n", err)
		return ExitFail
	}
	switch cmd {
	case "check-config":
		return checkConfig(cfg, stdout, stderr, d)
	case "init-key":
		k, err := d.CreateKey(cfg.KeyFile)
		if err != nil {
			fmt.Fprintf(stderr, "spo-relay: %v\n", err)
			return ExitFail
		}
		defer k.Destroy()
		pub, err := d.PublicKey(k)
		if err != nil {
			fmt.Fprintf(stderr, "spo-relay: %v\n", err)
			return ExitFail
		}
		fmt.Fprintf(stdout, "created the relay key %s\nrelay node key %s\n", cfg.KeyFile, hex.EncodeToString(pub[:]))
		fmt.Fprintln(stdout, "Give the node key to every device that uses this relay; they pin it. The address is printed by: spo-relay serve --print-address")
		return ExitOK
	}
	return serve(*conf, cfg, *printAddr, stdout, stderr, signals, d)
}

func summary(w io.Writer, cfg *relayconf.Config) {
	fmt.Fprintf(w, "admission %s", cfg.Admission)
	if cfg.Admission == relayconf.AdmitAllowList {
		fmt.Fprintf(w, " (%d wallet key(s))", len(cfg.Wallets))
	}
	fmt.Fprintf(w, "; tunnel restricted to %d device node key(s); at most %d bound devices; retention %d s\n",
		len(cfg.Devices), cfg.Registry.MaxBoundDevices, cfg.RetentionSeconds)
	switch {
	case cfg.DERPRegion != nil:
		fmt.Fprintf(w, "DERP region pinned in full: region %d, %d node(s); the address is the same at every start with this key\n", cfg.DERPRegion.ID, len(cfg.DERPRegion.Nodes))
	case cfg.DERPRegionID != 0:
		fmt.Fprintf(w, "DERP region %d of the map: the address follows the map's description of that region\n", cfg.DERPRegionID)
	default:
		fmt.Fprintln(w, "DERP region not pinned: the address may change at a restart ([derp_region] pins it)")
	}
}

func checkConfig(cfg *relayconf.Config, stdout, stderr io.Writer, d Deps) int {
	fmt.Fprint(stdout, "the configuration is valid: ")
	summary(stdout, cfg)
	k, err := d.LoadKey(cfg.KeyFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(stdout, "there is no key file at %s yet: create it with spo-relay init-key\n", cfg.KeyFile)
		return ExitOK
	case err != nil:
		fmt.Fprintf(stderr, "spo-relay: the key file: %v\n", err)
		return ExitFail
	}
	defer k.Destroy()
	pub, err := d.PublicKey(k)
	if err != nil {
		fmt.Fprintf(stderr, "spo-relay: the key file: %v\n", err)
		return ExitFail
	}
	fmt.Fprintf(stdout, "relay node key %s\n", hex.EncodeToString(pub[:]))
	return ExitOK
}

func serve(path string, cfg *relayconf.Config, printAddr bool, stdout, stderr io.Writer, signals <-chan Signal, d Deps) int {
	k, err := d.LoadKey(cfg.KeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "spo-relay: there is no key file at %s: create it once with spo-relay init-key --config %s\n", cfg.KeyFile, path)
		return ExitFail
	}
	if err != nil {
		fmt.Fprintf(stderr, "spo-relay: the key file: %v\n", err)
		return ExitFail
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// the signals are watched during the start too: the lease may be held by
	// another process for a while, and SIGTERM must end the wait as a planned
	// stop (SPO-Xmailbox-OUT-132); a reload has nothing to reload yet
	stopped := false
	quit, watched := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watched)
		for {
			select {
			case <-quit:
				return
			case s := <-signals:
				if s == SignalStop {
					stopped = true
					cancel()
					return
				}
				fmt.Fprintln(stderr, "spo-relay: reload ignored: the relay is still starting")
			}
		}
	}()
	r, err := Start(ctx, cfg, k, d)
	close(quit)
	<-watched
	k.Destroy()
	// a stop during the start that made the start fail is a planned stop; one
	// that came as the start finished stops it below at once (ctx has ended),
	// and a stuck teardown or a lost authority keep their own status
	if stopped && err != nil && !errors.Is(err, ErrTeardownStuck) && !errors.Is(err, ErrAuthorityLost) {
		fmt.Fprintln(stdout, "spo-relay: stopped before serving")
		return ExitOK
	}
	switch {
	case errors.Is(err, ErrTeardownStuck):
		fmt.Fprintf(stderr, "spo-relay: %v\nspo-relay: tunnel did not stop: the tunnel engine may still be up and registered; this process exits now so that its supervisor can restart it\n", err)
		return ExitStuck
	case errors.Is(err, ErrAuthorityLost):
		fmt.Fprintf(stderr, "spo-relay: %v\n%s\n", err, authorityMsg)
		return ExitAuthority
	case err != nil:
		fmt.Fprintf(stderr, "spo-relay: %v\n", err)
		return ExitFail
	}
	pub := r.NodeKey()
	fmt.Fprintf(stdout, "spo-relay: serving\nrelay node key %s\n", hex.EncodeToString(pub[:]))
	summary(stdout, cfg)
	if printAddr {
		addr, err := r.Address()
		if err != nil {
			fmt.Fprintf(stderr, "spo-relay: no address: %v\n", err)
		} else {
			fmt.Fprintf(stdout, "address %s\n", addr)
			fmt.Fprintln(stderr, "spo-relay: the address holds the relay's pre-shared key: give it only to the devices that may use this relay, as a secret, and do not keep it in a log")
		}
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	for {
		select {
		case err := <-done:
			switch {
			case errors.Is(err, ErrTeardownStuck):
				fmt.Fprintln(stderr, "spo-relay: tunnel did not stop: the tunnel engine may still be up and registered; this process exits now so that its supervisor can restart it")
				return ExitStuck
			case errors.Is(err, ErrAuthorityLost):
				fmt.Fprintln(stderr, authorityMsg)
				return ExitAuthority
			case err != nil:
				fmt.Fprintf(stderr, "spo-relay: %v\n", err)
				return ExitFail
			}
			fmt.Fprintln(stdout, "spo-relay: stopped")
			return ExitOK
		case s := <-signals:
			switch s {
			case SignalStop:
				cancel()
			case SignalReload:
				next, err := d.LoadConfig(path)
				var changed bool
				if err == nil {
					changed, err = r.Reload(next)
				}
				switch {
				case err != nil:
					fmt.Fprintf(stderr, "spo-relay: reload refused, the device list in force stays: %v\n", err)
				case changed:
					fmt.Fprintf(stdout, "spo-relay: reloaded: the tunnel now admits %d device node key(s)\n", len(next.Devices))
				default:
					fmt.Fprintln(stdout, "spo-relay: reloaded: the device list is unchanged")
				}
			}
		}
	}
}
