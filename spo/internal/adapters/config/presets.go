package config

import "sort"

// Preset is the per-network data the workspace needs. The values are those
// of the upstream scripts' network presets (spec/upstream/common/Cconf.md);
// a value here changes only with the spec.
type Preset struct {
	// Name is the key in spo.toml: "mainnet", "preprod" or "preview".
	Name string
	// Magic is the network id as upstream exports it in
	// CARDANO_NODE_NETWORK_ID, and as the light-mode parameters file states
	// it: "mainnet" or the decimal testnet magic (SPO-Cconf-INV-011).
	Magic string
	// AddressPrefix is the bech32 human-readable part of payment addresses
	// (CIP-19; not stated in Cconf, which only passes --mainnet or
	// --testnet-magic to cardano-cli).
	AddressPrefix string
	// ByronToShelleyEpochs is the number of Byron epochs before the hard fork
	// (SPO-Cconf-INV-004 alias table).
	ByronToShelleyEpochs uint64
	// KoiosURL is the public Koios API root (SPO-Cconf-INV-006, endpoint
	// table, before slash normalisation: stored without a trailing slash).
	KoiosURL string
	// LightParametersURL is the light-mode protocol parameters file
	// (SPO-Cconf-INV-006).
	LightParametersURL string
}

// spec: SPO-Cconf-INV-004, SPO-Cconf-INV-006, SPO-Cconf-INV-011
var presets = map[string]Preset{
	"mainnet": {
		Name: "mainnet", Magic: "mainnet", AddressPrefix: "addr", ByronToShelleyEpochs: 208,
		KoiosURL:           "https://api.koios.rest/api/v1",
		LightParametersURL: "https://uptime.live/data/cardano/parms/mainnet-parameters.json",
	},
	"preprod": {
		Name: "preprod", Magic: "1", AddressPrefix: "addr_test", ByronToShelleyEpochs: 4,
		KoiosURL:           "https://preprod.koios.rest/api/v1",
		LightParametersURL: "https://uptime.live/data/cardano/parms/preprod-parameters.json",
	},
	"preview": {
		Name: "preview", Magic: "2", AddressPrefix: "addr_test", ByronToShelleyEpochs: 0,
		KoiosURL:           "https://preview.koios.rest/api/v1",
		LightParametersURL: "https://uptime.live/data/cardano/parms/preview-parameters.json",
	},
}

// PresetFor returns the preset of a network name.
func PresetFor(network string) (Preset, bool) {
	p, ok := presets[network]
	return p, ok
}

// Networks lists the supported network names, sorted.
func Networks() []string {
	out := make([]string, 0, len(presets))
	for n := range presets {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
