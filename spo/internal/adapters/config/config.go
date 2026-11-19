// Package config reads and writes the workspace configuration, spo.toml: the
// non-secret settings of a workspace. Secrets (the passphrase, tokens) are
// never in it; they are records in the sealed store.
//
// The schema is strict. An unknown key, section or value is an error that
// names it, so a misspelt setting cannot silently fall back to a default.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/tomlsubset"
)

// FileName is the configuration file in a workspace directory.
const FileName = "spo.toml"

// Modes of operation (spec: SPO-Cconf-MODE-001).
const (
	ModeOnline  = "online"
	ModeLight   = "light"
	ModeOffline = "offline"
)

// Koios configures the Koios chain provider (ADR 0006). The section's
// presence is the operator's choice of Koios for this workspace; URL is an
// optional override of the network's public endpoint.
type Koios struct {
	URL string
}

// Blockfrost configures a Blockfrost-compatible chain provider (ADR 0006): the
// service itself or a self-hosted Dingo. The section's presence is the
// operator's choice. URL is an optional override of the public endpoint of the
// network. TokenRecord names the Secret record that holds the project id (the
// project id itself is never in spo.toml); empty means the record named after
// the provider, "blockfrost".
type Blockfrost struct {
	URL         string
	TokenRecord string
}

// Node configures the node-to-client provider (ADR 0006): a cardano-node's
// UNIX socket, or that socket forwarded over TCP. The section's presence is the
// operator's choice.
type Node struct {
	// Address is a socket path, "unix:PATH" or "tcp://host:port". Required.
	Address string
	// TimeoutSeconds bounds each operation against the node (1 to
	// MaxNodeTimeoutSeconds); zero keeps the adapter's default.
	TimeoutSeconds int
}

// MaxNodeTimeoutSeconds is the longest per-operation wait spo.toml may ask for.
const MaxNodeTimeoutSeconds = 600

// Provider kinds. Each has a section of the same name (the node's kind, "node",
// is the section [node] and the adapter n2c).
const (
	KindNode       = "node"
	KindKoios      = "koios"
	KindBlockfrost = "blockfrost"
)

// kinds are the provider kinds in their default order of preference. A node
// the operator configured is asked first: it is the operator's own.
var kinds = []string{KindNode, KindKoios, KindBlockfrost}

// IsWebKind reports whether the kind is a third-party HTTP provider, which
// learns the addresses it is asked about (the node does not).
func IsWebKind(kind string) bool { return kind == KindKoios || kind == KindBlockfrost }

// Hardware tunes the hardware wallet signer ([hardware]). Every zero value
// keeps the adapter's default.
type Hardware struct {
	// WaitSeconds bounds the wait for a device to answer (1 to 3600; default 60).
	WaitSeconds int
	// MinLedger, MinTrezor and MinKeystone override the minimum app or
	// firmware version of a vendor: dotted decimal numbers such as "8.0.8".
	MinLedger, MinTrezor, MinKeystone string
}

// Handles overrides the ADA Handle API root of the network ([handles]).
type Handles struct {
	URL string
}

// Registry names the token-registry server ([registry]): the root a subject is
// appended to (CIP-26). Without it mainnet uses the public server and the test
// networks have none.
type Registry struct {
	URL string
}

// Party sets where the multi-party file transport keeps its directories
// ([party]). A relative path is relative to the workspace directory. The
// inbox must be a local directory that only the operator can write to, and
// never a synced folder (ADR 0005, obligation 5).
type Party struct {
	Inbox, Outbox string
	// RelayLoginMax is relay_login_max as written ("12h"; "" is the default),
	// checked by ParseRelayLoginMax when the file is read.
	RelayLoginMax string
}

// DefaultRelayLoginMax is the login limit of a relay session when
// relay_login_max is not set (ADR 0014 decision 9).
const DefaultRelayLoginMax = 12 * time.Hour

// ParseRelayLoginMax reads relay_login_max: Go's duration form, from 1 minute
// to 168 hours; "" is DefaultRelayLoginMax (SPO-Xmailbox-PRE-066).
func ParseRelayLoginMax(s string) (time.Duration, error) {
	if s == "" {
		return DefaultRelayLoginMax, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < time.Minute || d > 168*time.Hour {
		return 0, fmt.Errorf("[party] relay_login_max must be a duration from 1m to 168h (such as \"12h\" or \"90m\"), not %q", s)
	}
	return d, nil
}

// Tailcat tunes the tailcat transport ([tailcat]). The node key, the
// pre-shared key and the coordinator's address are Secret records of the
// sealed store, never settings.
type Tailcat struct {
	// Port is the one TCP port a coordinator serves and a signer dials; zero
	// keeps the adapter's default, 7345 (adapters/tailcat.DefaultPort).
	Port int
	// DERPMapURL overrides where tailcat fetches its relay map from (https
	// only, or a loopback host).
	DERPMapURL string
}

// Config is the content of spo.toml.
type Config struct {
	Network string
	Mode    string
	// Koios is nil when no Koios provider is configured.
	Koios *Koios
	// Blockfrost is nil when no Blockfrost provider is configured.
	Blockfrost *Blockfrost
	// Node is nil when no node provider is configured.
	Node *Node
	// Order is the operator's order of preference among the configured
	// providers ([provider] order). The first answers reads; the next one
	// that is a different provider is the second source of the reads that
	// need corroboration. Empty means the default order. Use Providers for
	// the effective list.
	Order []string
	// SameHostOK is [provider] same_host_ok = true: the operator states that
	// two providers that share a host are independent all the same (for
	// example two operators behind one reverse proxy). It switches off the
	// refusal of a cross-check whose two sources share a host, and so weakens
	// the check; the default is false.
	SameHostOK bool
	// Hardware and Handles are nil when the file has no such section.
	Hardware *Hardware
	Handles  *Handles
	// Party and Tailcat are nil when the file has no such section.
	Party   *Party
	Tailcat *Tailcat
	// Registry is nil when the file has no [registry] section.
	Registry *Registry
}

var versionText = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)

// MaxWaitSeconds is the longest wait for a device that spo.toml may ask for.
const MaxWaitSeconds = 3600

func (h *Hardware) validate() error {
	if h.WaitSeconds < 0 || h.WaitSeconds > MaxWaitSeconds {
		return fmt.Errorf("[hardware] wait_seconds must be 1 to %d", MaxWaitSeconds)
	}
	for k, v := range map[string]string{"min_ledger": h.MinLedger, "min_trezor": h.MinTrezor, "min_keystone": h.MinKeystone} {
		if v != "" && !versionText.MatchString(v) {
			return fmt.Errorf("[hardware] %s %q is not a version such as 8.0.8", k, v)
		}
	}
	return nil
}

// HandleURL is the ADA Handle API root in effect: the override, else the
// preset's ("" where the network has none).
func (c Config) HandleURL() string {
	if c.Handles != nil && c.Handles.URL != "" {
		return c.Handles.URL
	}
	p, _ := PresetFor(c.Network)
	return p.HandleURL
}

// Path returns the configuration file of a workspace directory.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// KoiosURL is the Koios endpoint in effect: the override, else the preset's.
func (c Config) KoiosURL() string {
	if c.Koios == nil {
		return ""
	}
	if c.Koios.URL != "" {
		return c.Koios.URL
	}
	p, _ := PresetFor(c.Network)
	return p.KoiosURL
}

// Configured reports whether the provider kind has a section.
func (c Config) Configured(kind string) bool {
	switch kind {
	case KindKoios:
		return c.Koios != nil
	case KindBlockfrost:
		return c.Blockfrost != nil
	case KindNode:
		return c.Node != nil
	}
	return false
}

// Providers is the configured provider kinds in the order of preference: the
// kinds named by [provider] order first, then the others in the default order.
func (c Config) Providers() []string {
	var out []string
	seen := map[string]bool{}
	for _, k := range append(append([]string(nil), c.Order...), kinds...) {
		if !seen[k] && c.Configured(k) {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// TokenRecord is the name of the Secret record that holds the provider's
// token: the configured name, else the provider kind.
func (c Config) TokenRecord(kind string) string {
	if kind == KindBlockfrost && c.Blockfrost != nil && c.Blockfrost.TokenRecord != "" {
		return c.Blockfrost.TokenRecord
	}
	return kind
}

// BlockfrostURL is the Blockfrost endpoint in effect: the override, else the
// public one of the network ("" where there is none or no section).
func (c Config) BlockfrostURL() string {
	if c.Blockfrost == nil {
		return ""
	}
	if c.Blockfrost.URL != "" {
		return c.Blockfrost.URL
	}
	switch c.Network {
	case "mainnet", "preprod", "preview":
		return "https://cardano-" + c.Network + ".blockfrost.io/api/v0"
	}
	return ""
}

var recordName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

func (c Config) validateProviders() error {
	seen := map[string]bool{}
	for _, k := range c.Order {
		switch {
		case !c.Configured(k) && (k == KindKoios || k == KindBlockfrost || k == KindNode):
			return fmt.Errorf("[provider] order names %s, which has no [%s] section", k, k)
		case k != KindKoios && k != KindBlockfrost && k != KindNode:
			return fmt.Errorf("[provider] order names %q, which is not one of %s", k, strings.Join(kinds, ", "))
		case seen[k]:
			return fmt.Errorf("[provider] order names %s twice: a second source must be a different provider", k)
		}
		seen[k] = true
	}
	for _, u := range []struct{ name, v string }{
		{"[koios] url", c.koiosOverride()}, {"[blockfrost] url", c.blockfrostOverride()},
	} {
		if hasActiveChar(u.v) {
			return fmt.Errorf("%s has a control or bidirectional character", u.name)
		}
	}
	if b := c.Blockfrost; b != nil && b.TokenRecord != "" && !recordName.MatchString(b.TokenRecord) {
		return fmt.Errorf("[blockfrost] token_record %q is not a record name (lower-case letters, digits, '-' and '_')", b.TokenRecord)
	}
	if n := c.Node; n != nil {
		if strings.TrimSpace(n.Address) == "" {
			return errors.New("[node] needs an address: a socket path, unix:PATH or tcp://host:port")
		}
		if hasActiveChar(n.Address) {
			return errors.New("[node] address has a control or bidirectional character")
		}
		if n.TimeoutSeconds < 0 || n.TimeoutSeconds > MaxNodeTimeoutSeconds {
			return fmt.Errorf("[node] timeout_seconds must be 1 to %d", MaxNodeTimeoutSeconds)
		}
	}
	return nil
}

// Validate checks a configuration.
func (c Config) Validate() error {
	if _, ok := PresetFor(c.Network); !ok {
		return fmt.Errorf("network %q is not one of %s", c.Network, strings.Join(Networks(), ", "))
	}
	switch c.Mode {
	case ModeOnline, ModeLight, ModeOffline:
	default:
		return fmt.Errorf("mode %q is not one of online, light, offline", c.Mode)
	}
	if c.Mode == ModeLight && c.Koios == nil && c.Blockfrost == nil && c.Node == nil {
		return errors.New("mode light needs a [koios] or [blockfrost] section: light mode asks a third-party provider, and the workspace must name it (run: spo provider set koios)")
	}
	if err := c.validateProviders(); err != nil {
		return err
	}
	if c.Hardware != nil {
		if err := c.Hardware.validate(); err != nil {
			return err
		}
	}
	if t := c.Tailcat; t != nil && (t.Port < 0 || t.Port > 65535) {
		return errors.New("[tailcat] port must be 1 to 65535")
	}
	return nil
}

// Parse reads configuration text.
func Parse(data []byte) (Config, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return Config{}, err
	}
	var c Config
	var haveNetwork, haveMode bool
	for _, sec := range doc.sections {
		switch sec.name {
		case "":
			for _, e := range sec.entries {
				switch e.key {
				case "network":
					if c.Network, err = e.val.str(e.key); err != nil {
						return Config{}, err
					}
					haveNetwork = true
				case "mode":
					if c.Mode, err = e.val.str(e.key); err != nil {
						return Config{}, err
					}
					haveMode = true
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q", e.val.line, e.key)
				}
			}
		case "koios":
			c.Koios = &Koios{}
			for _, e := range sec.entries {
				switch e.key {
				case "url":
					if c.Koios.URL, err = e.val.str("koios.url"); err != nil {
						return Config{}, err
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [koios]", e.val.line, e.key)
				}
			}
		case "blockfrost":
			c.Blockfrost = &Blockfrost{}
			for _, e := range sec.entries {
				switch e.key {
				case "url":
					if c.Blockfrost.URL, err = e.val.str("blockfrost.url"); err != nil {
						return Config{}, err
					}
				case "token_record":
					if c.Blockfrost.TokenRecord, err = e.val.str("blockfrost.token_record"); err != nil {
						return Config{}, err
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [blockfrost]", e.val.line, e.key)
				}
			}
		case "node":
			c.Node = &Node{}
			for _, e := range sec.entries {
				switch e.key {
				case "address":
					if c.Node.Address, err = e.val.str("node.address"); err != nil {
						return Config{}, err
					}
				case "timeout_seconds":
					if e.val.kind != kindInt {
						return Config{}, fmt.Errorf("line %d: key \"node.timeout_seconds\" must be a whole number", e.val.line)
					}
					if e.val.i < 1 || e.val.i > MaxNodeTimeoutSeconds {
						return Config{}, fmt.Errorf("line %d: [node] timeout_seconds must be 1 to %d", e.val.line, MaxNodeTimeoutSeconds)
					}
					c.Node.TimeoutSeconds = int(e.val.i)
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [node]", e.val.line, e.key)
				}
			}
		case "provider":
			for _, e := range sec.entries {
				switch e.key {
				case "order":
					text, err := e.val.str("provider.order")
					if err != nil {
						return Config{}, err
					}
					c.Order = nil
					for _, k := range strings.Split(text, ",") {
						c.Order = append(c.Order, strings.TrimSpace(k))
					}
				case "same_host_ok":
					if e.val.kind != kindBool {
						return Config{}, fmt.Errorf("line %d: key \"provider.same_host_ok\" must be true or false", e.val.line)
					}
					c.SameHostOK = e.val.b
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [provider]", e.val.line, e.key)
				}
			}
		case "hardware":
			c.Hardware = &Hardware{}
			for _, e := range sec.entries {
				switch e.key {
				case "wait_seconds":
					if e.val.kind != kindInt {
						return Config{}, fmt.Errorf("line %d: key \"hardware.wait_seconds\" must be a whole number", e.val.line)
					}
					if e.val.i < 1 || e.val.i > MaxWaitSeconds {
						return Config{}, fmt.Errorf("line %d: [hardware] wait_seconds must be 1 to %d", e.val.line, MaxWaitSeconds)
					}
					c.Hardware.WaitSeconds = int(e.val.i)
				case "min_ledger":
					if c.Hardware.MinLedger, err = e.val.str("hardware.min_ledger"); err != nil {
						return Config{}, err
					}
				case "min_trezor":
					if c.Hardware.MinTrezor, err = e.val.str("hardware.min_trezor"); err != nil {
						return Config{}, err
					}
				case "min_keystone":
					if c.Hardware.MinKeystone, err = e.val.str("hardware.min_keystone"); err != nil {
						return Config{}, err
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [hardware]", e.val.line, e.key)
				}
			}
		case "handles":
			c.Handles = &Handles{}
			for _, e := range sec.entries {
				switch e.key {
				case "url":
					if c.Handles.URL, err = e.val.str("handles.url"); err != nil {
						return Config{}, err
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [handles]", e.val.line, e.key)
				}
			}
		case "registry":
			c.Registry = &Registry{}
			for _, e := range sec.entries {
				switch e.key {
				case "url":
					if c.Registry.URL, err = e.val.str("registry.url"); err != nil {
						return Config{}, err
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [registry]", e.val.line, e.key)
				}
			}
		case "party":
			c.Party = &Party{}
			for _, e := range sec.entries {
				switch e.key {
				case "inbox":
					if c.Party.Inbox, err = e.val.str("party.inbox"); err != nil {
						return Config{}, err
					}
				case "outbox":
					if c.Party.Outbox, err = e.val.str("party.outbox"); err != nil {
						return Config{}, err
					}
				case "relay_login_max":
					if c.Party.RelayLoginMax, err = e.val.str("party.relay_login_max"); err != nil {
						return Config{}, err
					}
					if _, err := ParseRelayLoginMax(c.Party.RelayLoginMax); err != nil || c.Party.RelayLoginMax == "" {
						return Config{}, fmt.Errorf("line %d: [party] relay_login_max must be a duration from 1m to 168h (such as \"12h\" or \"90m\")", e.val.line)
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [party]", e.val.line, e.key)
				}
			}
		case "tailcat":
			c.Tailcat = &Tailcat{}
			for _, e := range sec.entries {
				switch e.key {
				case "port":
					if e.val.kind != kindInt {
						return Config{}, fmt.Errorf("line %d: key \"tailcat.port\" must be a whole number", e.val.line)
					}
					if e.val.i < 1 || e.val.i > 65535 {
						return Config{}, fmt.Errorf("line %d: [tailcat] port must be 1 to 65535", e.val.line)
					}
					c.Tailcat.Port = int(e.val.i)
				case "derp_map_url":
					if c.Tailcat.DERPMapURL, err = e.val.str("tailcat.derp_map_url"); err != nil {
						return Config{}, err
					}
				default:
					return Config{}, fmt.Errorf("line %d: unknown key %q in [tailcat]", e.val.line, e.key)
				}
			}
		default:
			return Config{}, fmt.Errorf("line %d: unknown section [%s]", sec.line, sec.name)
		}
	}
	if !haveNetwork {
		return Config{}, errors.New("missing key \"network\"")
	}
	if !haveMode {
		return Config{}, errors.New("missing key \"mode\"")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (v value) str(key string) (string, error) {
	if v.kind != kindString {
		return "", fmt.Errorf("line %d: key %q must be a string", v.line, key)
	}
	return v.s, nil
}

// Marshal renders a configuration.
func Marshal(c Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	var q quoter
	b.WriteString("# spo workspace configuration. No secrets belong here.\n")
	fmt.Fprintf(&b, "network = %s\nmode = %s\n", q.quote("network", c.Network), q.quote("mode", c.Mode))
	if c.Koios != nil {
		b.WriteString("\n[koios]\n")
		if c.Koios.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", q.quote("[koios] url", c.Koios.URL))
		}
	}
	if c.Blockfrost != nil {
		b.WriteString("\n[blockfrost]\n")
		if c.Blockfrost.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", q.quote("[blockfrost] url", c.Blockfrost.URL))
		}
		if c.Blockfrost.TokenRecord != "" {
			fmt.Fprintf(&b, "token_record = %s\n", q.quote("[blockfrost] token_record", c.Blockfrost.TokenRecord))
		}
	}
	if n := c.Node; n != nil {
		b.WriteString("\n[node]\n")
		fmt.Fprintf(&b, "address = %s\n", q.quote("[node] address", n.Address))
		if n.TimeoutSeconds > 0 {
			fmt.Fprintf(&b, "timeout_seconds = %d\n", n.TimeoutSeconds)
		}
	}
	if len(c.Order) > 0 || c.SameHostOK {
		b.WriteString("\n[provider]\n")
		if len(c.Order) > 0 {
			fmt.Fprintf(&b, "order = %s\n", q.quote("[provider] order", strings.Join(c.Order, ",")))
		}
		if c.SameHostOK {
			b.WriteString("same_host_ok = true\n")
		}
	}
	if h := c.Hardware; h != nil {
		b.WriteString("\n[hardware]\n")
		if h.WaitSeconds > 0 {
			fmt.Fprintf(&b, "wait_seconds = %d\n", h.WaitSeconds)
		}
		for _, kv := range [][2]string{{"min_ledger", h.MinLedger}, {"min_trezor", h.MinTrezor}, {"min_keystone", h.MinKeystone}} {
			if kv[1] != "" {
				fmt.Fprintf(&b, "%s = %s\n", kv[0], q.quote("[hardware] "+kv[0], kv[1]))
			}
		}
	}
	if p := c.Party; p != nil {
		b.WriteString("\n[party]\n")
		if p.Inbox != "" {
			fmt.Fprintf(&b, "inbox = %s\n", q.quote("[party] inbox", p.Inbox))
		}
		if p.Outbox != "" {
			fmt.Fprintf(&b, "outbox = %s\n", q.quote("[party] outbox", p.Outbox))
		}
		if p.RelayLoginMax != "" {
			fmt.Fprintf(&b, "relay_login_max = %s\n", q.quote("[party] relay_login_max", p.RelayLoginMax))
		}
	}
	if t := c.Tailcat; t != nil {
		b.WriteString("\n[tailcat]\n")
		if t.Port > 0 {
			fmt.Fprintf(&b, "port = %d\n", t.Port)
		}
		if t.DERPMapURL != "" {
			fmt.Fprintf(&b, "derp_map_url = %s\n", q.quote("[tailcat] derp_map_url", t.DERPMapURL))
		}
	}
	if c.Registry != nil {
		b.WriteString("\n[registry]\n")
		if c.Registry.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", q.quote("[registry] url", c.Registry.URL))
		}
	}
	if c.Handles != nil {
		b.WriteString("\n[handles]\n")
		if c.Handles.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", q.quote("[handles] url", c.Handles.URL))
		}
	}
	if q.err != nil {
		return nil, fmt.Errorf("the configuration cannot be saved: %w", q.err)
	}
	return []byte(b.String()), nil
}

// Load reads the configuration of a workspace directory. A missing file
// returns an error satisfying errors.Is(err, os.ErrNotExist). Errors name the
// file.
func Load(dir string) (Config, error) {
	data, err := os.ReadFile(Path(dir))
	if err != nil {
		return Config{}, err
	}
	c, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", Path(dir), err)
	}
	return c, nil
}

// Create writes a new configuration file (mode 0600) and refuses to replace
// an existing one.
func Create(dir string, c Config) error {
	data, err := Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(Path(dir), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(Path(dir))
		return err
	}
	return f.Close()
}

// Save replaces the configuration file atomically (write beside, rename).
func Save(dir string, c Config) error {
	data, err := Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, FileName+".tmp-*") // mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), Path(dir))
}

func (c Config) koiosOverride() string {
	if c.Koios == nil {
		return ""
	}
	return c.Koios.URL
}

func (c Config) blockfrostOverride() string {
	if c.Blockfrost == nil {
		return ""
	}
	return c.Blockfrost.URL
}

// hasActiveChar is true for a string with a character a terminal acts on or
// that changes what a reader sees. The set is tomlsubset.ActiveRune, the one the
// file's parser and writer use.
func hasActiveChar(s string) bool { return tomlsubset.HasActive(s) }
