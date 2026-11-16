# spo.toml

`spo.toml` holds the non-secret settings of an `spo` workspace. It lives beside `workspace.spo`, with mode `0600`. `spo init` writes it; `spo provider set koios` and `spo mode set` edit it. Hand edits are allowed.

Secrets are never in this file: the passphrase and the provider API token are not settings. The token is a record in the sealed store.

## Syntax

A subset of TOML, parsed by `spo` itself:

* `key = value` lines and `[section]` headers (one level, plain names);
* values: basic strings in double quotes (escapes `\"`, `\\`, `\n`, `\t`), decimal integers, `true`, `false`;
* `#` comments, on their own line or after a value.

Arrays, inline tables, dotted keys, single-quoted strings, floats and dates are errors.

## Schema

The schema is strict. An unknown key or section, a duplicate key, or a value of the wrong type is an error that names it and the line. A missing `network` or `mode` is an error.

```toml
network = "preview"     # required: mainnet, preprod or preview
mode = "light"          # required: online, light or offline

[koios]                 # optional; present = Koios is the chosen chain provider
url = "https://preview.koios.rest/api/v1"   # optional endpoint override
```

| Key | Type | Meaning |
| --- | --- | --- |
| `network` | string | `mainnet`, `preprod` or `preview`. Selects the preset below and the bundled genesis files. |
| `mode` | string | `online` (node socket; not built yet), `light` (Koios) or `offline` (clock; no chain check). |
| `[koios]` | section | The operator's choice of Koios as chain provider. Required when `mode = "light"`. Ignored in `offline` mode. |
| `[koios] url` | string | Koios API root. When absent, the network's public endpoint. `https` is required except for a loopback host. |

There is no default provider. `[koios]` is written only after the operator confirms the privacy statement, at `init --mode light` or `provider set koios`.

## Network presets

From the upstream presets ([Cconf](../../spec/upstream/common/Cconf.md): SPO-Cconf-INV-004, INV-006, INV-011).

| Network | Network id | Address prefix | Byron epochs | Koios URL | Light-mode parameters |
| --- | --- | --- | --- | --- | --- |
| `mainnet` | `mainnet` | `addr` | 208 | `https://api.koios.rest/api/v1` | `https://uptime.live/data/cardano/parms/mainnet-parameters.json` |
| `preprod` | `1` | `addr_test` | 4 | `https://preprod.koios.rest/api/v1` | `https://uptime.live/data/cardano/parms/preprod-parameters.json` |
| `preview` | `2` | `addr_test` | 0 | `https://preview.koios.rest/api/v1` | `https://uptime.live/data/cardano/parms/preview-parameters.json` |

The address prefix is CIP-19, not part of Cconf. The light-mode parameters URL is in the table but no command uses it yet.

## Genesis files

Not in `spo.toml`. The packaged binary reads them from its release-set manifest (`networks.<name>.shelleyGenesis` and `byronGenesis`, the files the upstream scripts use). `--shelley-genesis` and `--byron-genesis` on `pool opcert issue` override them.
