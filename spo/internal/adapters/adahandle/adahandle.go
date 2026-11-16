// Package adahandle is the client of the ADA Handle API (`GET /handles/<name>`,
// SPO-Caddr-EXT-004). It implements ports.HandleDirectory. The API is a third
// party and sends no authorization; what it says is a claim that the handles
// use case verifies against the chain.
package adahandle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	timeout = 30 * time.Second // SPO-Caddr-EXT-004
	maxBody = 1 << 20
)

// Config builds a Client.
type Config struct {
	// BaseURL is the Handle API root, for example https://preview.api.handle.me.
	// It must be https unless the host is loopback.
	BaseURL string
	// Network names the network for Source().
	Network    string
	HTTPClient *http.Client
}

// Client implements ports.HandleDirectory.
type Client struct {
	base   *url.URL
	source chain.Source
	hc     *http.Client
}

var _ ports.HandleDirectory = (*Client)(nil)

// New validates the configuration.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("adahandle: %q is not a plain API root", cfg.BaseURL)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))) {
		return nil, fmt.Errorf("adahandle: %q must be https", cfg.BaseURL)
	}
	hc := &http.Client{Timeout: timeout}
	if cfg.HTTPClient != nil {
		c := *cfg.HTTPClient
		hc = &c
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: u, source: chain.Source(strings.TrimSpace("handle-api " + cfg.Network)), hc: hc}, nil
}

// Source implements ports.ChainSource.
func (c *Client) Source() chain.Source { return c.source }

// ResolveHandle implements ports.HandleDirectory. name is the handle without
// its `$`. Status 200 continues; 202 is ErrHandleDirectoryBehind; 404 is
// ErrHandleNotFound; any other status is an error carrying the API's
// `message` and the status (SPO-Caddr-PRE-008). Of the API's body
// only `hex` and `resolved_addresses.ada` are read (SPO-Caddr-INV-005); an
// absent address is an error, not the text `null`.
func (c *Client) ResolveHandle(ctx context.Context, name string) (ports.HandleRecord, error) {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/handles/" + name
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ports.HandleRecord{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	var resp *http.Response
	for i := 0; i < 2; i++ { // one retry of a transport failure
		if resp, err = c.hc.Do(req); err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return ports.HandleRecord{}, fmt.Errorf("handle API: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return ports.HandleRecord{}, fmt.Errorf("handle API: %w", err)
	}
	switch resp.StatusCode {
	case 200:
	case 202:
		return ports.HandleRecord{}, ports.ErrHandleDirectoryBehind
	case 404:
		return ports.HandleRecord{}, ports.ErrHandleNotFound
	default:
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &e)
		if len(e.Message) > 120 {
			e.Message = e.Message[:120]
		}
		return ports.HandleRecord{}, fmt.Errorf("handle API answered %d: %s", resp.StatusCode, e.Message)
	}
	var rec struct {
		Hex      string `json:"hex"`
		Resolved struct {
			Ada string `json:"ada"`
		} `json:"resolved_addresses"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return ports.HandleRecord{}, fmt.Errorf("handle API: not JSON: %w", err)
	}
	if rec.Hex == "" || rec.Resolved.Ada == "" {
		return ports.HandleRecord{}, errors.New("handle API: the answer has no hex or resolved_addresses.ada")
	}
	return ports.HandleRecord{AssetNameHex: rec.Hex, Address: rec.Resolved.Ada}, nil
}
