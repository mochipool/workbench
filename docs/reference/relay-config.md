# spo-relay configuration and command line

The relay mailbox of [ADR 0013](../explanation/adr/0013-tailnet-relay-and-mailbox.md) and [ADR 0014](../explanation/adr/0014-wallet-key-identity-for-the-relay.md) is its own binary, `spo-relay`. It holds sealed envelopes for the devices its tunnel admits and can open none of them; it holds no party secret. The rules below are specified in [Xmailbox](../../spec/extensions/Xmailbox.md), "The relay configuration, the relay binary and several relays" (SPO-Xmailbox-IF-022, IF-023, PRE-060 to PRE-064, OUT-100 to OUT-103, SEC-077 to SEC-079), the DERP region pin in "The DERP region pin" (IF-030, OUT-122, OUT-123, PRE-068, PRE-069, SEC-085), and the object store in [Xobjstore](../../spec/extensions/Xobjstore.md), "The relay binary on the object store" (IF-301 to INV-301). How to run one: [Run a relay](../how-to/run-a-relay.md), and [on Kubernetes](../how-to/run-a-relay-on-kubernetes.md).

## Commands

| Command | What it does | Exit status |
| --- | --- | --- |
| `spo-relay init-key --config FILE` | Creates the key file named by `key_file` (mode 0600, refused if it exists) and prints the relay node key. | 0, or 1 |
| `spo-relay check-config --config FILE` | Checks the file (the DERP region pin and the `[store]` table included) and, when it exists, the key file, without opening a store, contacting STS or starting the tunnel. Prints a summary: how the DERP region is pinned, the store (kind, buckets, endpoint, Object Lock mode, where the web identity is exchanged), `configuration hash <16 hex>`, and with a key file the relay node key and, for an object store, `store prefix relays/<node key>/`. | 0, or 1 |
| `spo-relay serve --config FILE [--print-address]` | Runs the relay until SIGINT or SIGTERM. SIGHUP reloads the `[[device]]` list. Prints the relay node key; with `--print-address` also the address (a secret: it holds the pre-shared key). | 0 after a clean stop (also a SIGTERM during the start); 1 for a configuration, key, store or tunnel failure (a pinned DERP region that is not in the map or does not answer, a store that fails its self-test or was never initialised, a refused web identity included); 2 for a usage error; 3 when the teardown is stuck ("tunnel did not stop"); 4 when the relay is no longer the writer of its store (its lease was lost or taken, or a conditional write met another writer's change) |

Status 3 means the tunnel engine may still be up and registered at the DERP relay. The process exits so that its supervisor can restart it; nothing in the process can recover it. Status 4 means the relay stopped serving and did not release its lease; a restart waits for the lease. When both happen, 3 wins. A panic on the main path or in the serving loop is reported as one line (`internal error`, its type, never its value) and exits 1 without releasing the lease; a panic on another goroutine (a session, the lease keeper) still ends the process with Go's own status 2, the usage status.

A planned stop whose close of the stores ends after the lease does logs `stopped lease=lapses reason=late` instead of `stopped`: there is nothing left to release, and the next process waits out the lease.

The first line of the operator log at a start is `start config=<16 hex> store=<directory|s3>`, and for an object store also `registry_bucket=<name> working_bucket=<name> prefix=relays/<node key>/`. The hash is the first 8 bytes of the Blake2b-256 of the configuration file, the same that `check-config` prints.

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
| `mailbox_dir`, `registry_dir` | Absolute, clean paths of the two stores of a directory relay. Distinct from each other and from `key_file`, none inside another. An existing one must be a directory of the user with no group or other permission bit; the parent of a missing one must belong to the user or root and not be writable by others (the store creates it with mode 0700). Refused with `[store] kind = "s3"`. | none |
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
* **Neither.** The tunnel library picks the nearest region at every start, as before. The address may change at a restart, and the relay logs `derp_region=unpinned` once at start. The object store (`[store] kind = "s3"`) refuses this and `derp_region_id`: it requires the full region.

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

### `[store]`

Where the relay keeps its queues, bindings and tombstones ([ADR 0015](../explanation/adr/0015-stateless-relay.md); [Xobjstore](../../spec/extensions/Xobjstore.md), "The relay binary on the object store"). Without the table, or with `kind = "directory"` and no other key, the store is the two directories of `[relay]`, as before.

With `kind = "s3"` the store is two buckets of an S3-compatible object store, and the relay's objects are under `relays/<node key>/` in each (the prefix follows from the key file; `check-config` prints it). The relay then needs no volume. A complete example (the names are placeholders):

```toml
[relay]
admission = "open"
key_file  = "/etc/spo-relay/key/relay.key"

[store]
kind                    = "s3"
region                  = "eu-west-1"
registry_bucket         = "example-spo-relay-registry"
working_bucket          = "example-spo-relay-working"
role_arn                = "arn:aws:iam::111122223333:role/example-spo-relay-a"
web_identity_token_file = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
# object_lock_mode        = "compliance"
# request_timeout_seconds = 10
# endpoint                = "https://minio.example.internal:9000"   # an allow-listed compatible product only
# path_style              = true
# sts_endpoint            = "https://sts.eu-west-1.amazonaws.com"   # a private STS endpoint only

[derp_region]                                 # required with kind = "s3"
region_id = 900
[[derp_node]]
name      = "own-1"
host_name = "derp.example.org"

[[device]]
label    = "alice laptop"
node_key = "0123...cdef"
```

| Key | Value | Default |
| --- | --- | --- |
| `kind` | `"directory"` or `"s3"`. Required in the table. | directory, without the table |
| `region` | The store's region name (`eu-west-1`): the signature's scope and the public S3 and STS endpoints. Required. | none |
| `registry_bucket` | The bucket with versioning on and Object Lock enabled, no default retention: the marker, the bindings, the tombstones. Required. | none |
| `working_bucket` | The bucket whose versioning was never enabled: the marker, the lease, the rate state, the mailbox. Required; not the same bucket. | none |
| `endpoint` | `https://host[:port]` of an allow-listed S3-compatible product (ADR 0015 decision 2: AWS S3; MinIO after its self-test). Nothing but scheme and host. | `https://s3.<region>.amazonaws.com` |
| `path_style` | `true` puts the bucket in the path (MinIO); needed for a bucket name with a dot. | `false` |
| `object_lock_mode` | `"compliance"` or `"governance"`, for tombstones and the marker. Governance lets an account administrator delete tombstones and needs `test_deployment = true`. | `"compliance"` |
| `test_deployment` | `true` only with governance or with `unsafe_loopback_http_for_tests`, and required by both. | `false` |
| `role_arn` | The IAM role of this relay identity (`arn:aws:iam::<account>:role/<name>`, or `arn:aws-cn:` or `arn:aws-us-gov:`). Required. Without `sts_endpoint` the role must be in the region's partition (a `cn-` region: `aws-cn`; a `us-gov-` region: `aws-us-gov`; other regions: `aws`), since the region's STS assumes no role of another partition; an isolated region (`-iso`) needs `sts_endpoint`. With `sts_endpoint` (a private or non-AWS STS) the pair is not checked. The partition rules are from memory of AWS's region names. | none |
| `web_identity_token_file` | Absolute path of the projected service-account token (IRSA: the file `AWS_WEB_IDENTITY_TOKEN_FILE` names). Required. Read again at every exchange; not read by `check-config`. | none |
| `sts_endpoint` | `https://host[:port]` of a private STS endpoint. | the public STS endpoint of `region` |
| `request_timeout_seconds` | 1 to 10: the bound of one store request (the lease needs at most half its 20 s term). | 10 |
| `unsafe_loopback_http_for_tests` | `true` allows plain http to a loopback IP address for `endpoint` and `sts_endpoint`. For the in-process test rig only; refused unless `endpoint` is `http://127.x.x.x:port` (or `[::1]`), and needs `test_deployment = true`. | `false` |

Rules with `kind = "s3"`: `mailbox_dir` and `registry_dir` are refused; the full `[derp_region]` is required and `derp_region_id` is refused; the mailbox must fit what the relay lists at a start: `max_bound_devices` × `mailbox_entries` + 320 held keys at most 524 288 (at most 2046 bound devices at the default 256 entries a queue; the message gives the arithmetic). A change of any `[store]` key is a restart, never a reload.

**Credentials.** Only a web identity: there is no key for an access key or a secret. At each exchange the relay reads the token file (kubelet rotates it), sends `AssumeRoleWithWebIdentity` to STS over TLS with the role and the session name `spo-relay`, and asks for 15-minute credentials. The store client renews them from about five minutes before they expire (the expiry it is given is moved earlier by up to two minutes at random), without stopping requests (below). Credentials living more than 12 hours, without a session token, or from a key id that is not temporary are refused. Neither the token nor the credentials reach a log, an error or a file.

The token file is read when it is a regular file (or kubelet's link to `..data/<name>` in the same directory), of root or of the relay's user, not writable by its group or others, in a directory of root or the relay's user that others cannot write unless it is root's with the sticky bit (kubelet's volume directory), at most 16 KiB. Its path is resolved first: a link above it, such as `/var/run -> /run` on Debian and Alpine images, is followed, and every directory and link on the way must be root's or the relay user's, with the same rule for who may write it.

The store client keeps a set of credentials until five minutes before it expires; from then on it refreshes in the background and keeps using the set while it outlives the request by a minute, so an STS outage does not stop the relay until then. A failed refresh is tried again after 1 s, doubling to 30 s.

**At a start** the relay checks each bucket: the working bucket reports versioning never enabled; the registry bucket reports versioning on and Object Lock enabled, and refuses a simple delete under `registry/tombstones/`; in each, a conditional create over an existing object answers 412, a wrong `If-Match` answers 412, two writes give two ETags, and an object is read and listed at once. It removes what it wrote. A store that holds neither the identity's lease record nor its marker was never initialised: the start is refused and names `spo-relay init-store`, which is run once for a new relay and never for one that had a store. Then it waits for the lease, loads the queues and the registry while renewing it, and starts the tunnel. The role's permissions are in ADR 0015 decision 3.

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

Three lines, 156 bytes: `spo-relay-key-v1`, `node` and the node private key in 64 lower-case hex digits, `psk` and the pre-shared key in 64 lower-case hex digits. It is used only if it is a regular file of the user that runs the relay with no group or other permission bit (0600 or 0400), exactly in that form, with neither key zero. A file of root is accepted only as the Secret volume of a cluster, mounted directly (ADR 0015 decision 6, source 1): reached through kubelet's link `<name> -> ..data/<name>` into the timestamped directory beside it and no other link, mode 0400 or 0440, the group read bit only when the file's group is the relay's effective group (set the pod's `runAsGroup` to its `fsGroup`: kubelet adds `fsGroup` as a supplementary group, which does not count), in a directory of root or the relay's user that others cannot write unless it is root's with the sticky bit. A plain file of root, on a host or anywhere else, is refused: give the key to the relay's user (`chown`, mode 0400). A Secret mounted with `subPath` is not supported (it is a plain file of root, with no link): mount the whole volume. Every directory on the key's path, and every link on the way (a `/var/run -> /run` above it is fine), must be root's or the relay user's and closed to others (or root's with the sticky bit). It is not a party secret, and the relay links no store encryption, so the file system protects it; back it up with the configuration (ADR 0013, "State and backup"). A new key file is a new relay node key and a new address, which every device must be told.
