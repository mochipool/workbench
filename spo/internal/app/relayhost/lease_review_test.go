package relayhost_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// failedStart runs Start with d changed by mod, expects it to fail, and returns
// the lease's release count and the log.
func failedStart(t *testing.T, mod func(h *host, d *relayhost.Deps)) (int32, string) {
	t.Helper()
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	_, tl := withStandLease(h)
	cfg := h.config(h.text([]*fakenet.Node{a.node}))
	key, err := relayconfig.CreateKey(cfg.KeyFile, seeded{})
	if err != nil {
		t.Fatal(err)
	}
	d := h.deps()
	mod(h, &d)
	if _, err := relayhost.Start(context.Background(), cfg, key, d); err == nil {
		t.Fatal("Start succeeded")
	}
	return tl.releases.Load(), h.logText()
}

// M4. A failed start releases the lease only when nothing it sent may still
// land: a registry that holds an operation storage has not confirmed, a store
// whose open failed (its writes' outcomes cannot be known), or statistics that
// cannot be read leave the lease to lapse; a failure before any store was
// opened, or after a load whose writes were all answered, releases it.
//
// spec: SPO-Xmailbox-IF-034, SPO-Xmailbox-OUT-129
func TestAFailedStartLetsTheLeaseLapseWhenRequestsMayLand(t *testing.T) {
	noTunnel := func(h *host, d *relayhost.Deps) {
		d.Listen = func(context.Context, relayhost.TunnelSpec) (relayhost.Tunnel, error) {
			return nil, errors.New("injected: no tunnel")
		}
	}
	t.Run("unconfirmed", func(t *testing.T) {
		n, log := failedStart(t, func(h *host, d *relayhost.Deps) {
			h.wrapRegistry = func(r relayport.Registry) relayport.Registry { return statsLie{r} }
			*d = h.deps()
			noTunnel(h, d)
		})
		if n != 0 || !strings.Contains(log, "start_failed lease=lapses reason=unconfirmed") {
			t.Fatalf("released %d times:\n%s", n, log)
		}
	})
	t.Run("the registry did not open", func(t *testing.T) {
		n, log := failedStart(t, func(h *host, d *relayhost.Deps) {
			d.OpenRegistry = func(relayhost.StoreSpec, relayregistry.Config, relayhost.StoreEnv) (relayport.Registry, []string, error) {
				return nil, nil, fmt.Errorf("injected: %w", relayport.ErrOutcomeUnknown)
			}
		})
		if n != 0 || !strings.Contains(log, "start_failed lease=lapses reason=load") {
			t.Fatalf("released %d times:\n%s", n, log)
		}
	})
	t.Run("the statistics cannot be read", func(t *testing.T) {
		n, log := failedStart(t, func(h *host, d *relayhost.Deps) {
			h.wrapRegistry = func(r relayport.Registry) relayport.Registry { return statsFail{r} }
			*d = h.deps()
			noTunnel(h, d)
		})
		if n != 0 || !strings.Contains(log, "start_failed lease=lapses reason=registry") {
			t.Fatalf("released %d times:\n%s", n, log)
		}
	})
	t.Run("every write answered", func(t *testing.T) {
		n, log := failedStart(t, noTunnel)
		if n != 1 || strings.Contains(log, "lease=lapses") {
			t.Fatalf("released %d times:\n%s", n, log)
		}
	})
}

// statsFail cannot read its statistics.
type statsFail struct{ relayport.Registry }

func (s statsFail) Stats(ctx context.Context) (relayregistry.Stats, error) {
	return relayregistry.Stats{}, errors.New("injected: no statistics")
}

// ratesUnknown answers SaveRates with an unknown outcome, as objregistry does
// for a put whose answer was lost and whose read-back did not show it
// (relayport.ErrOutcomeUnknown).
type ratesUnknown struct{ relayport.Registry }

func (r ratesUnknown) SaveRates(context.Context) error {
	return fmt.Errorf("%w: put registry/rates: injected", relayport.ErrOutcomeUnknown)
}

// M4. A rate save of unknown outcome at a planned stop leaves the lease to
// lapse: the server counts it unanswered.
//
// spec: SPO-Xmailbox-OUT-129, SPO-Xmailbox-IF-035
func TestARateSaveOfUnknownOutcomeAtTheStopLapses(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	_, tl := withStandLease(h)
	h.wrapRegistry = func(r relayport.Registry) relayport.Registry { return ratesUnknown{r} }
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	if err := end(); err != nil {
		t.Fatalf("a planned stop: %v", err)
	}
	if n := tl.releases.Load(); n != 0 || !strings.Contains(h.logText(), "stopped lease=lapses reason=unanswered") {
		t.Fatalf("released %d times:\n%s", n, h.logText())
	}
}
