package main

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/platform/endpoint"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// announcing prints the host a fetch is about to contact, once per host per
// command, before the request. The fetches of anchor documents and pool
// metadata go to the URL a chain record names, in every mode that has them,
// online mode included: that host is not one the operator configured.
type announcing struct {
	inner ports.MetadataFetcher
	w     io.Writer
	what  string

	mu   sync.Mutex
	seen map[string]bool
}

func (a *announcing) Fetch(ctx context.Context, url string) ([]byte, error) {
	h, _ := endpoint.Host(url)
	a.mu.Lock()
	first := !a.seen[h]
	if a.seen == nil {
		a.seen = map[string]bool{}
	}
	a.seen[h] = true
	a.mu.Unlock()
	if first && a.w != nil {
		if h == "" {
			h = url
		}
		fmt.Fprintf(a.w, "Fetching %s from %s, a host named on chain (not one you configured).\n", a.what, textsafe.Quote(h))
	}
	return a.inner.Fetch(ctx, url)
}

// announceFetches wraps the two fetchers that contact hosts named on chain.
func announceFetches(env *cli.Env, w io.Writer) {
	if env.AnchorFetcher != nil {
		env.AnchorFetcher = &announcing{inner: env.AnchorFetcher, w: w, what: "an anchor document"}
	}
	if env.Metadata != nil {
		env.Metadata = &announcing{inner: env.Metadata, w: w, what: "pool metadata"}
	}
}
