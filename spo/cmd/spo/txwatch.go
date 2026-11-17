package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/koios"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Transaction status (spec/extensions/Xconfirm.md). Each configured provider
// becomes one ports.TxWatcher. Its status reader and its tip are guarded the
// same way on EVERY call, not once per command as the cross-check readers are:
// a wait lasts minutes, and a provider that falls behind in the middle of it
// must not start saying "not seen" (SPO-Xconfirm-INV-001). The guard for a web
// provider is the freshness of its tip against this machine's clock; for the
// node it is its own sync check.

const noTxStatusOffline = "offline mode has no chain provider to ask: a queued transaction is submitted later by spo offline execute on an online machine, where --wait applies"

// guardedStatus asks check before every read; a reason makes the reading
// Unknown, so a stale or unsynced provider is never heard as "not seen".
type guardedStatus struct {
	inner ports.TxStatusReader
	check func(ctx context.Context) string
}

func (g guardedStatus) Source() chain.Source { return g.inner.Source() }

func (g guardedStatus) TxStatus(ctx context.Context, q ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	if why := g.check(ctx); why != "" {
		if ctx.Err() != nil {
			return chain.Reading[chain.TxStatus]{}, ctx.Err()
		}
		return chain.Unknown[chain.TxStatus](why), nil
	}
	return g.inner.TxStatus(ctx, q)
}

// guardedTip is a provider's tip that fails when the guard does: only a tip of
// a fresh, synced provider can decide that a transaction has expired.
type guardedTip struct {
	inner ports.TipReader
	check func(ctx context.Context) string
}

func (g guardedTip) Source() chain.Source { return g.inner.Source() }

func (g guardedTip) Tip(ctx context.Context) (chain.Tip, error) {
	if why := g.check(ctx); why != "" {
		return chain.Tip{}, fmt.Errorf("the tip of %s cannot be used: %s", g.inner.Source(), why)
	}
	return g.inner.Tip(ctx)
}

// webGuard is the per-call freshness check of a web provider.
func webGuard(src ports.TipTimeReader, now func() time.Time) func(context.Context) string {
	return func(ctx context.Context) string {
		return (&freshness{src: src, now: now, max: maxWebTipAge}).stale(ctx)
	}
}

// nodeGuard is the per-call sync check of the node.
func nodeGuard(s ports.SyncChecker) func(context.Context) string {
	return func(ctx context.Context) string {
		ok, err := s.Synced(ctx)
		switch {
		case err != nil:
			return fmt.Sprintf("the sync state of %s cannot be read (%v)", s.Source(), err)
		case !ok:
			return fmt.Sprintf("%s is not synced", s.Source())
		}
		return ""
	}
}

// wireTxWatchers gives the Env one watcher per configured provider the mode
// allows: every web provider that has a section (online mode: those named in
// [provider] order, as for every read), and the node when it is configured
// (online mode, or named in the order). Offline mode has none.
func wireTxWatchers(env *cli.Env, o cli.WireOptions, errw io.Writer) error {
	cfg := toConfig(o.Config)
	var ws []ports.TxWatcher
	for _, kind := range cfg.Providers() {
		if o.Mode == cli.ModeOnline && config.IsWebKind(kind) && !contains(o.Config.Order, kind) {
			continue
		}
		switch kind {
		case config.KindKoios:
			url := o.Config.Koios.URL
			if url == "" {
				url = o.Preset.KoiosURL
			}
			k, err := koios.New(koios.Config{BaseURL: url, Network: o.Config.Network, Token: o.Token})
			if err != nil {
				return err
			}
			g := webGuard(k, time.Now)
			ws = append(ws, ports.TxWatcher{Status: guardedStatus{k, g}, Tip: guardedTip{k, g}})
		case config.KindBlockfrost:
			bf, err := newBlockfrost(o, cfg)
			if err != nil {
				return err
			}
			g := webGuard(bf, time.Now)
			ws = append(ws, ports.TxWatcher{Status: guardedStatus{bf, g}, Tip: guardedTip{bf, g}})
		case config.KindNode:
			if o.Config.Node == nil {
				continue
			}
			n, err := newNode(env, o, errw)
			if err != nil {
				return err
			}
			g := nodeGuard(n)
			ws = append(ws, ports.TxWatcher{Status: guardedStatus{n, g}, Tip: guardedTip{nodeTip{n}, g}})
		}
	}
	if len(ws) == 0 {
		env.Absent(cli.CapTxStatus, "no chain provider is configured that can say where a transaction is: spo provider set koios")
		return nil
	}
	env.TxWatchers = ws
	return nil
}
