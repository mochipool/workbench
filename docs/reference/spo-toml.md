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
relay_login_max = "12h" # default; the longest relay login (spo party relay login, the TUI's session)

[tailcat]               # optional; multi-party signing, tailcat transport
port = 7345             # the one TCP port a coordinator serves and a signer dials
derp_map_url = "https://controlplane.tailscale.com/derpmap/default"   # relay map override

[vault]                 # optional; a Vault Transit unlock factor (workspace slot add-backend)
address = "https://vault.example:8200"
namespace = "ops"       # optional (Vault Enterprise, HCP Vault)
mount = "transit"       # default
key = "spo-unlock"      # an aes256-gcm96, aes128-gcm96 or chacha20-poly1305 key, not derived
ca_file = "/etc/spo/vault-ca.pem"   # optional; default: the system roots
auth = "token"          # token (VAULT_TOKEN, else token_file) or jwt
token_file = "/home/op/.vault-token" # default: $HOME/.vault-token
jwt_mount = "jwt"       # auth = "jwt" only
jwt_role = "spo"
jwt_file = "/run/user/1000/vault.jwt"
timeout_seconds = 30    # 1 to 600
allow_loopback_http = false  # default; true allows http:// to a loopback IP only

[kms]                   # optional; an AWS KMS unlock factor
key_arn = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
# KMS and STS: the public endpoints of the key's region, with the system roots.
# The private_* keys are for private (VPC) endpoints only:
# private_endpoint = "https://vpce-0abc.kms.eu-west-1.vpce.amazonaws.com"
# private_ca_file = "/etc/spo/kms-ca.pem"       # the CA of private_endpoint only
# private_sts_endpoint = "https://vpce-0def.sts.eu-west-1.vpce.amazonaws.com"
# private_sts_ca_file = "/etc/spo/sts-ca.pem"   # the CA of private_sts_endpoint only
role_arn = "arn:aws:iam::111122223333:role/spo-unlock"  # with web_identity_token_file
web_identity_token_file = "/run/user/1000/aws.jwt"
role_session_name = "spo-unlock"  # default
timeout_seconds = 30
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
| `[party] relay_login_max` | string | How long a relay login lasts at most (`spo party relay login`, and the relay session of `spo tui`): a duration such as `"12h"` or `"90m"`, from `1m` to `168h`. Default 12 hours, counted from the login on the monotonic clock and on the wall clock, whichever reaches it first (time the machine was suspended counts). At the limit the login logs out by itself, even while a foreground command of the TUI waits at a prompt; there is no idle logout. Anything else refuses the file. |
| `[tailcat]` | section | The tailcat transport. |
| `[tailcat] port` | integer | The TCP port a coordinator serves and a signer dials, 1 to 65535. Default 7345. |
| `[tailcat] derp_map_url` | string | Where tailcat fetches its relay (DERP) map from. Default: tailcat's own. |
| `[vault]` | section | A Vault Transit key used as an unlock factor ([how-to](../how-to/unlock-with-vault-or-kms.md)). `address`, `namespace`, `mount` and `key` are read by `workspace slot add-backend --backend vault`, which stores them in the slot. They stay the authority: the slot's copy is a claim, and every unlock, verify and restore refuses a slot whose backend differs from these before any credential is read or any call is made (SPO-Xunlock-PRE-045). |
| `[vault] address` | string | `https://host[:port]`. No path, query or credentials. |
| `[vault] allow_loopback_http`, `[kms] allow_loopback_http` | boolean | `true` allows plain `http` to a loopback IP address (`127.0.0.1`, `[::1]`) for that section's endpoints: a local agent or a test server. Default `false`: TLS always. A slot cannot turn it on. |
| `[vault] namespace`, `mount`, `key` | string | The namespace (optional), the Transit mount (default `transit`) and the key name. The key must be of a type that takes associated data and must not be a derived key; the client reads its configuration and refuses otherwise. |
| `[vault] ca_file` | string | A PEM file of the CA certificates that sign the server's certificate. Default: the system roots. |
| `[vault] auth` | string | `token` (default): the token in `VAULT_TOKEN`, else in `token_file` (default `$HOME/.vault-token`, where `vault login` keeps it). `jwt`: a JWT login at `auth/<jwt_mount>/login` with `jwt_role` and the JWT in `jwt_file`. Token and JWT files must be regular files (no symbolic link, no pipe) owned by you and readable by you only. The token is looked up first; a token with TTL 0 or the `root` policy is refused. |
| `[vault] timeout_seconds` | integer | The deadline of each call, connection included, 1 to 600. Default 30. |
| `[kms]` | section | An AWS KMS symmetric key used as an unlock factor. `key_arn` and the endpoint (the public one of its region, or `private_endpoint`) are read by `workspace slot add-backend --backend kms`, which stores them in the slot; as with `[vault]`, they stay the authority at every unlock. |
| `[kms] key_arn` | string | A key ARN (`arn:aws:kms:<region>:<account>:key/<id>`). An alias or a bare key id is refused: every answer's key id is compared with this ARN. The KMS and STS endpoints are the public ones of its partition and region, with the system roots. |
| `[kms] private_endpoint`, `private_ca_file` | string | For a private (VPC) KMS endpoint only: its URL, and the PEM file of its CA (used for this endpoint only). `private_ca_file` without `private_endpoint` is refused. |
| `[kms] private_sts_endpoint`, `private_sts_ca_file` | string | For a private (VPC) STS endpoint only: where the web identity token is sent instead of the public STS endpoint, and its CA (for this endpoint only). `private_sts_ca_file` without `private_sts_endpoint` is refused. |
| `[kms] role_arn`, `web_identity_token_file`, `role_session_name` | string | A web identity exchanged at STS `AssumeRoleWithWebIdentity` for 15-minute credentials. Default: `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_SESSION_NAME` (default `spo-unlock`). The token file follows the rules of the Vault token file. Without a web identity, the environment must hold temporary credentials: an `ASIA` key id with `AWS_SESSION_TOKEN`; any other key id is refused. |
| `[kms] timeout_seconds` | integer | As for `[vault]`. |

No Vault token, JWT, AWS access key, secret key or session token is ever a setting: `[vault]` and `[kms]` have no key for one, and such a key is an unknown key and an error.

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
