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
	if c.Mode == ModeLight && c.Koios == nil {
		return errors.New("mode light needs a [koios] section: light mode asks a third-party provider, and the workspace must name it (run: spo provider set koios)")
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
	b.WriteString("# spo workspace configuration. No secrets belong here.\n")
	fmt.Fprintf(&b, "network = %s\nmode = %s\n", quote(c.Network), quote(c.Mode))
	if c.Koios != nil {
		b.WriteString("\n[koios]\n")
		if c.Koios.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", quote(c.Koios.URL))
		}
	}
	if h := c.Hardware; h != nil {
		b.WriteString("\n[hardware]\n")
		if h.WaitSeconds > 0 {
			fmt.Fprintf(&b, "wait_seconds = %d\n", h.WaitSeconds)
		}
		for _, kv := range [][2]string{{"min_ledger", h.MinLedger}, {"min_trezor", h.MinTrezor}, {"min_keystone", h.MinKeystone}} {
			if kv[1] != "" {
				fmt.Fprintf(&b, "%s = %s\n", kv[0], quote(kv[1]))
			}
		}
	}
	if p := c.Party; p != nil {
		b.WriteString("\n[party]\n")
		if p.Inbox != "" {
			fmt.Fprintf(&b, "inbox = %s\n", quote(p.Inbox))
		}
		if p.Outbox != "" {
			fmt.Fprintf(&b, "outbox = %s\n", quote(p.Outbox))
		}
	}
	if t := c.Tailcat; t != nil {
		b.WriteString("\n[tailcat]\n")
		if t.Port > 0 {
			fmt.Fprintf(&b, "port = %d\n", t.Port)
		}
		if t.DERPMapURL != "" {
			fmt.Fprintf(&b, "derp_map_url = %s\n", quote(t.DERPMapURL))
		}
	}
	if c.Registry != nil {
		b.WriteString("\n[registry]\n")
		if c.Registry.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", quote(c.Registry.URL))
		}
	}
	if c.Handles != nil {
		b.WriteString("\n[handles]\n")
		if c.Handles.URL != "" {
			fmt.Fprintf(&b, "url = %s\n", quote(c.Handles.URL))
		}
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
