# spo-relay configuration and command line

The relay mailbox of [ADR 0013](../explanation/adr/0013-tailnet-relay-and-mailbox.md) and [ADR 0014](../explanation/adr/0014-wallet-key-identity-for-the-relay.md) is its own binary, `spo-relay`. It holds sealed envelopes for the devices its tunnel admits and can open none of them; it holds no party secret. The rules below are specified in [Xmailbox](../../spec/extensions/Xmailbox.md), "The relay configuration, the relay binary and several relays" (SPO-Xmailbox-IF-022, IF-023, PRE-060 to PRE-064, OUT-100 to OUT-103, SEC-077 to SEC-079), and the DERP region pin in "The DERP region pin" (IF-030, OUT-122, OUT-123, PRE-068, PRE-069, SEC-085). How to run one: [Run a relay](../how-to/run-a-relay.md), and [on Kubernetes](../how-to/run-a-relay-on-kubernetes.md).

## Commands

| Command | What it does | Exit status |
| --- | --- | --- |
| `spo-relay init-key --config FILE` | Creates the key file named by `key_file` (mode 0600, refused if it exists) and prints the relay node key. | 0, or 1 |
| `spo-relay check-config --config FILE` | Checks the file (the DERP region pin included) and, when it exists, the key file, without opening a store or the tunnel. Prints a summary, which says how the DERP region is pinned, and the relay node key when there is one. | 0, or 1 |
| `spo-relay serve --config FILE [--print-address]` | Runs the relay until SIGINT or SIGTERM. SIGHUP reloads the `[[device]]` list. Prints the relay node key; with `--print-address` also the address (a secret: it holds the pre-shared key). | 0 after a clean stop; 1 for a configuration, key, store or tunnel failure (a pinned DERP region that is not in the map or does not answer included); 2 for a usage error; 3 when the teardown is stuck ("tunnel did not stop") |

Status 3 means the tunnel engine may still be up and registered at the DERP relay. The process exits so that its supervisor can restart it; nothing in the process can recover it.

A reload applies a new device list only. A file that differs in anything else is refused with a message, and the list in force stays; everything else takes a restart. Removing a device rebuilds the tunnel with the same identity and address and resets that device's live connections.

The operator log goes to standard error: one line per event, with public keys (node keys, device fingerprints, wallet key hashes) and fixed reason classes, never an envelope byte, a statement byte or the address.

## The file

A small subset of TOML: tables and `[[array]]` tables with bare names, `key = value` with a quoted string, an unsigned decimal integer or `true`/`false`, and `#` comments. Every other construct, every unknown table or key, a key outside a table, a key twice and a table twice is refused. No control character but tab, no bidirectional control. At most 1 MiB, lines at most 4 KiB, at most 4096 `[[device]]` and `[[wallet]]` tables together and at most 8 `[[derp_node]]` tables. The file must be a regular file of the user that runs the relay (or of root) that its group and others cannot write.

```toml
[relay]
admission    = "open"                       # required: "open" or "allow-list"
key_file     = "/var/lib/spo-relay/key/relay.key"
mailbox_dir  = "/var/lib/spo-relay/state/mailbox"
registry_dir = "/var/lib/spo-relay/state/registry"
# port = 7346
# derp_map_url = "https://derp.example/derpmap.json"
# retention_seconds = 604800
# sweep_seconds = 300

# The DERP region, pinned in full (recommended; see "The DERP region" below)
# [derp_region]
# region_id = 900
# [[derp_node]]
# name      = "own-1"
# host_name = "derp.example.org"

[[device]]
label    = "alice laptop"
node_key = "0123...cdef"                    # 64 lower-case hex digits

# [[wallet]]                                # admission = "allow-list" only
# label = "alice"
# key   = "a1b2...c3d4"                     # 56 lower-case hex digits

# [registry]
# max_bound_devices = 1024

# [quota]
# global_bytes = 4294967296

# [limits]
# connections = 64
```

### `[relay]` (required)

| Key | Value | Default |
| --- | --- | --- |
| `admission` | `"open"`: any device with a valid binding may log in. `"allow-list"`: only the wallet keys of the `[[wallet]]` tables (others are told `not_allowed`). Required; `open` with a `[[wallet]]` table is refused, and so is `allow-list` without one. | none |
| `key_file` | Absolute, clean path of the relay's key file. Its directory must belong to the user or root and not be writable by its group or others. | none |
| `mailbox_dir`, `registry_dir` | Absolute, clean paths of the two stores. Distinct from each other and from `key_file`, none inside another. An existing one must be a directory of the user with no group or other permission bit; the parent of a missing one must belong to the user or root and not be writable by others (the store creates it with mode 0700). | none |
| `port` | The TCP port served inside the tunnel, 1 to 65535. Devices use the same (`spo party relay add --port`). | 7346 |
| `derp_map_url` | An `https://` address of the DERP map, at most 512 bytes. Refused with `[derp_region]`, which fetches no map. | tailcat's default |
| `derp_region_id` | A region of the DERP map, 1 to 65535. Fixes which region is used, but the address embeds the map's description of that region and changes when the map does. Refused with `[derp_region]`. | none |
| `retention_seconds` | How long an entry is kept, 1 to 2592000 (30 days). One number for the session (announced at login) and the sweeper. | 604800 (7 days) |
| `sweep_seconds` | The interval of the retention and registry sweep, 60 to 86400. | 300 |
| `unsafe_open_tunnel` | `true` is refused by this build: tailcat v0.7.0 registers any client that knows the relay's public key and region, permanently, at a cost that grows as the square of their number. The tunnel admits only the `[[device]]` node keys. | `false` |

### The DERP region: `[derp_region]` and `[[derp_node]]`

The relay's address holds the relay's public keys, its pre-shared key and a full description of one DERP region: the host names, addresses and ports of its nodes. It holds no region id. So the address stays the same only while that description does.

* **Full region (recommended, required for any relay whose process may restart or move).** A `[derp_region]` table and 1 to 8 `[[derp_node]]` tables. No DERP map is fetched. The address is byte-equal at every start with the same key file and the same tables. Changing any node field below changes the address; `region_id`, `region_code` and a node's `name` are not in the address.
* **`derp_region_id` (in `[relay]`).** The map is fetched at each start and the region taken from it. The region is fixed, the address is not: it follows the map. The relay logs `derp_region=map` at start to say so.
* **Neither.** The tunnel library picks the nearest region at every start, as before. The address may change at a restart, and the relay logs `derp_region=unpinned` once at start. No mode refuses this yet; the object-store mode of ADR 0015 will require the full region.

`[derp_region]`: `region_id` (1 to 65535, required) and `region_code` (optional, 1 to 32 of `a` to `z`, `0` to `9` and `-`).

`[[derp_node]]`:

| Key | Value | Default |
| --- | --- | --- |
| `name` | 1 to 64 of letters, digits, `.`, `_` and `-`; unique in the region. Required. | none |
| `host_name` | A lower-case DNS name or an IP address. Dialled, and sent as the TLS server name. Required. | none |
| `cert_name` | The name the certificate must carry, or `"sha256-raw:"` and the 64 lower-case hex digits of the SHA-256 of the certificate (for a self-signed one). | `host_name` |
| `ipv4`, `ipv6` | An address of that family, or `"none"` to skip the family; not both `"none"`. | DNS lookup of `host_name` |
| `stun_port`, `derp_port` | 1 to 65535. | 3478, 443 |

TLS to DERP is always verified, by the system's roots or by the certificate hash; no key turns it off. At start the relay connects to the pinned region as a DERP client: verified TLS to one of its nodes, by that node's `cert_name` rule, and the DERP handshake. A STUN answer is not enough. A wrong `cert_name` or hash, a DERP port that is down (even with STUN up), a region that does not answer, a `derp_region_id` the map lacks, or a map's node that a `[[derp_node]]` table could not describe stops the start with status 1 and a message; `--print-address` then prints nothing, and the relay never falls back to another region.

Only the full `[derp_region]` form pins the DERP server. With `derp_region_id` the map's operator chooses the nodes, their host names and their certificate names; the relay checks each node with the rules above, nothing more.

The operator of the DERP server you name sees which node keys connect and when, and the size and timing of the traffic. It can learn whether a node key is on the relay's list (by a forged "meow" ping in that key's name), can tie a listed node key to a disco key of its own until the relay's tunnel is next rebuilt (breaking that device's direct path), and can drop or delay packets. It cannot read or change what the tunnel carries, which WireGuard encrypts with the pre-shared key. Choose a DERP server whose operator you trust with that.

The relay refuses to start when the environment sets a variable whose name starts with `TS_DEBUG_` (for example `TS_DEBUG_ADDR`, which makes the tunnel library print the address and its pre-shared key, or `TS_DEBUG_USE_DERP_HTTP`, which turns TLS to DERP off). Unset it.

### `[[device]]` (at least one)

The tunnel's allow-list: a device whose node key is not listed cannot reach the session at all. Each has a `label` (1 to 64 bytes, unique, not only spaces) and a `node_key` (the device's tailcat node key, 64 lower-case hex digits, not zero, unique). A device shows its node key with `spo party show`.

### `[[wallet]]` (admission `allow-list` only)

A `label` (as above) and a `key`: the wallet key hash, 56 lower-case hex digits, unique.

### `[registry]`

| Key | Range | Default |
| --- | --- | --- |
| `max_bound_devices` | 1 to 4096. One number for the registry and the open quota; the global quota must cover this many queues. | 1024 |
| `max_devices_per_key` | 1 to 8 | 8 |
| `max_binding_days` | 1 to 180. The longest binding the relay accepts; one policy for the registry and the session. | 180 |
| `skew_seconds` | 0 to 300 | 300 |
| `new_bindings_per_hour`, `new_binding_burst` | 1 to 60, 1 to 10 | 60, 10 |
| `revokes_per_hour`, `revoke_burst` | 1 to 60, 1 to 10 (revokes that invalidate nothing) | 60, 10 |
| `idle_drop_days` | 1 to 30 | 30 |
| `max_tombstones` | 2 to 65536 | 16 times `max_bound_devices` |

### `[quota]`

`mailbox_entries` (default 256), `mailbox_bytes` (4 MiB), `pair_entries` (64), `pair_bytes` (2 MiB), `sender_bytes` (64 MiB), `global_bytes` (4 GiB), `stranger_entries` (16), `stranger_bytes` (1 MiB). Each is set and no looser than the ADR 0013 table. The global quota must be at least `mailbox_bytes` times `max_bound_devices` (4096 devices need 16 GiB at 4 MiB), and the stranger allowance must sit strictly inside the queue: fewer entries, and at least one envelope of 1 MiB beyond it.

### `[limits]`

The session's limits; each may only tighten the protocol table, and is refused at load above it: `max_envelope_bytes` (1 MiB), `items_per_fetch` (16), `fetch_wait_seconds` (0 to 20; 0 turns long-poll off), `connections` (64), `conns_per_node_key` (2), `new_conns_per_minute` (6), `conns_per_device` (2), `conns_per_wallet_key` (16), `unauth_conns` (16), `revokes_per_conn` (8), `puts_per_minute` (120), `puts_in_flight` (2).

## The key file

Three lines, 156 bytes: `spo-relay-key-v1`, `node` and the node private key in 64 lower-case hex digits, `psk` and the pre-shared key in 64 lower-case hex digits. It is used only if it is a regular file of the user that runs the relay with no group or other permission bit (0600 or 0400), exactly in that form, with neither key zero. It is not a party secret, and the relay links no store encryption, so the file system protects it; back it up with the configuration (ADR 0013, "State and backup"). A new key file is a new relay node key and a new address, which every device must be told.
