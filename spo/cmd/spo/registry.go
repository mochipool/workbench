package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/tokenregistry"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
)

// registryURL is the token-registry server in effect: spo.toml's [registry]
// url, else the public server of mainnet. The test networks have none: the
// upstream testnet host no longer resolves (adapters/tokenregistry), so the
// operator names a server of their own.
func registryURL(o cli.WireOptions) string {
	if o.Config.Registry != nil && o.Config.Registry.URL != "" {
		return o.Config.Registry.URL
	}
	if o.Config.Network == "mainnet" {
		return tokenregistry.MainnetURL
	}
	return ""
}

// wireRegistry sets the token-registry reader of light mode, or records why
// there is none. Offline mode makes no request and sets none.
func wireRegistry(env *cli.Env, o cli.WireOptions) {
	url := registryURL(o)
	if url == "" {
		env.Absent(cli.CapTokenRegistry, fmt.Sprintf("the %s network has no working token-registry server (the upstream testnet host no longer resolves): set url in the [registry] section of spo.toml", o.Config.Network))
		return
	}
	c, err := tokenregistry.New(tokenregistry.Config{BaseURL: url})
	if err != nil {
		env.Absent(cli.CapTokenRegistry, "the [registry] url in spo.toml is unusable: "+err.Error())
		return
	}
	env.Registry = c
	env.Endpoints[c.Registry()] = url
}

// logoFiles reads the PNG a record's metaLogoPNG names. A relative path is
// relative to the workspace directory, which is where upstream's scripts run.
// It reads at most one byte more than a logo may have; the use case judges the
// size and the type.
type logoFiles struct{ dir string }

func (l logoFiles) ReadLogoFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		path = filepath.Join(l.dir, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, tokenmeta.MaxLogoBytes+1))
}
