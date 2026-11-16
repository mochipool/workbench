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

[hardware]              # optional; every key optional
wait_seconds = 60       # wait for a hardware wallet to answer, 1 to 3600
min_ledger = "8.0.8"    # minimum Cardano app version per vendor
min_trezor = "2.7.2"
min_keystone = "1.7.7"

[handles]               # optional
url = "https://preview.api.handle.me"       # ADA Handle API root override

[registry]              # optional
url = "https://tokens.cardano.org/metadata"  # token-registry server root

[party]                 # optional; multi-party signing, file transport
inbox = "party/inbox"   # default; relative to the workspace directory
outbox = "party/outbox" # default

[tailcat]               # optional; multi-party signing, tailcat transport
port = 7345             # the one TCP port a coordinator serves and a signer dials
derp_map_url = "https://controlplane.tailscale.com/derpmap/default"   # relay map override
```

| Key | Type | Meaning |
| --- | --- | --- |
| `network` | string | `mainnet`, `preprod` or `preview`. Selects the preset below and the bundled genesis files. |
| `mode` | string | `online` (node socket; not built yet), `light` (Koios) or `offline` (clock; no chain check). |
| `[koios]` | section | The operator's choice of Koios as chain provider. Required when `mode = "light"`. Ignored in `offline` mode. |
| `[koios] url` | string | Koios API root. When absent, the network's public endpoint. `https` is required except for a loopback host. |

| `[hardware]` | section | Tuning of the hardware wallet signer. A bare section keeps every default. Not read when the binary has no `cardano-hw-cli`. |
| `[hardware] wait_seconds` | integer | How long a command waits for the device to answer before failing with "no hardware wallet answered" (1 to 3600; default 60). |
| `[hardware] min_ledger`, `min_trezor`, `min_keystone` | string | Minimum app (Ledger) or firmware version of that vendor, dotted numbers such as `8.0.8`. Defaults are upstream's (`8.0.8`, `2.7.2`, `1.7.7`). Lowering one is the operator's decision and the device's profile is judged against it. |
| `[handles]` | section | ADA Handle API settings. |
| `[handles] url` | string | Handle API root. When absent, the network's (`mainnet` `https://api.handle.me`, `preprod` `https://preprod.api.handle.me`, `preview` `https://preview.api.handle.me`). `https` is required except for a loopback host. An unusable value makes capability `ada-handle` absent with the reason; other commands are unaffected. |
| `[registry]` | section | The token-registry server (CIP-26) that `asset meta check` asks. |
| `[registry] url` | string | The server root; a subject is appended to it (`GET <url>/<subject>`). When absent, mainnet uses the public server `https://tokens.cardano.org/metadata`; **preprod and preview have none**, because the testnet host of upstream's preset (`metadata.cardano-testnet.iohkdev.io`) no longer resolves. On a test network, capability `token-registry` is absent, with that reason, until a `url` is set. `https` is required except for a loopback host; a URL with credentials, a query or a fragment is unusable and makes the capability absent with the reason. Read in light mode only: offline there is no registry. `asset meta generate` needs no registry. |
| `[party]` | section | Where the file transport keeps its directories. |
| `[party] inbox` | string | The inbox directory, relative to the workspace directory unless absolute. Default `party/inbox`. It must be a local directory only the operator can write to (not a link, not group- or other-writable, not a network or FUSE file system) and **never a synced folder**. `spo party inbox import` refuses it otherwise. |
| `[party] outbox` | string | Where `party request export` and the invitations of `party serve` write by default. Default `party/outbox`. |
| `[tailcat]` | section | The tailcat transport. |
| `[tailcat] port` | integer | The TCP port a coordinator serves and a signer dials, 1 to 65535. Default 7345. |
| `[tailcat] derp_map_url` | string | Where tailcat fetches its relay (DERP) map from. Default: tailcat's own. |

The tailcat node key, the pre-shared key and the coordinator's address are **sealed records**, never settings: a key such as `psk`, `node_key`, `address` or `auth_key` is an unknown key and an error. There is no tailcat auth key anywhere: the pre-shared key is part of the address, which a coordinator gives only inside an invitation sealed to one signer.

There is no default provider. `[koios]` is written only after the operator confirms the privacy statement, at `init --mode light` or `provider set koios`.

## Network presets

From the upstream presets ([Cconf](../../spec/upstream/common/Cconf.md): SPO-Cconf-INV-004, INV-006, INV-011).

| Network | Network id | Address prefix | Byron epochs | Koios URL | Light-mode parameters | Handle API |
| --- | --- | --- | --- | --- | --- | --- |
| `mainnet` | `mainnet` | `addr` | 208 | `https://api.koios.rest/api/v1` | `https://uptime.live/data/cardano/parms/mainnet-parameters.json` | `https://api.handle.me` |
| `preprod` | `1` | `addr_test` | 4 | `https://preprod.koios.rest/api/v1` | `https://uptime.live/data/cardano/parms/preprod-parameters.json` | `https://preprod.api.handle.me` |
| `preview` | `2` | `addr_test` | 0 | `https://preview.koios.rest/api/v1` | `https://uptime.live/data/cardano/parms/preview-parameters.json` | `https://preview.api.handle.me` |

The address prefix is CIP-19, not part of Cconf. The light-mode parameters URL is in the table but no command uses it yet.

## Genesis files

Not in `spo.toml`. The packaged binary reads them from its release-set manifest (`networks.<name>.shelleyGenesis` and `byronGenesis`, the files the upstream scripts use). `--shelley-genesis` and `--byron-genesis` on `pool opcert issue` override them.
