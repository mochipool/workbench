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

// Config is the content of spo.toml.
type Config struct {
	Network string
	Mode    string
	// Koios is nil when no Koios provider is configured.
	Koios *Koios
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
