+++
id = "12b"
kind = "script"
title = "Check what the token registry serves for an asset"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["native-assets", "chain-access"]
use_cases = ["CheckAssetRegistry"]
depends_on = ["Cconf","Pfiles"]

upstream_path = "cardano/mainnet/12b_checkAssetMetaServer.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "d01cf06a7823be3ac7bd7ced774d08f40292e12446db828670dabd9c25db5f2d"
upstream_lines = 118
uses_common = [
  "checkError",
  "trimString",
]
cli_commands = []
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "tokenMetaServer",
]
env_vars = []
+++

# 12b_checkAssetMetaServer: Check what the token registry serves

Looks up the token-registry entry of one asset on the registry server (`tokenMetaServer`) and displays the fields the registry holds, each with its sequence number, so the operator can confirm that a submission made with [12a](./12a_genAssetMeta.md) was published. It is read-only. The asset is named either by its record file or directly by its subject.

## Interface

- **SPO-12b-IF-001** Takes exactly one argument; any other count prints usage to stderr and exits 1. The argument is either `<policy>.<asset>` (a trailing `.asset` is dropped; policy and asset name split at the first and last dot as in SPO-11a-IF-002), or a subject given directly as 56 to 120 hex digits (policy id plus hex asset name). (src: L23-L35, L56-L57)
- **SPO-12b-IF-002** The argument is first tried as an asset record: when `<policy>.<asset>.asset` exists it is used and the argument is not interpreted as a subject. Otherwise a value of only hex digits with length 56 to 120 is lower-cased and used as the subject. Neither form exits 1. (src: L25, L40-L60)

## Inputs

- **SPO-12b-IN-001** From an asset record the subject is the record's `subject` value. It must be hex digits only with length 56 to 120, else the script exits 1 and tells the operator to run 12a first. The record is displayed. (src: L44-L54)
- **SPO-12b-IN-002** Reads the `tokenMetaServer` setting (the network's registry URL, trailing slash removed, see SPO-Cconf-IN-005 and SPO-Cconf-INV-007) and the work mode. (src: L21, L63-L64)

## Behaviour

1. **Refuse offline mode.**
   - **SPO-12b-PRE-001** In `offline` work mode the script exits 1 ("you have to be in online mode") before looking at its arguments. `light` mode is allowed and behaves like `online`: it does not use Koios, only the registry. (src: L20-L21)
2. **Resolve the subject** as SPO-12b-IF-002 and SPO-12b-IN-001. (src: L39-L60)
3. **Query the registry.**
   - **SPO-12b-EXT-001** Sends an HTTP GET to `<tokenMetaServer>/<subject>`, following redirects, with a 20 second timeout and without checking the HTTP status. (src: L64)
   - **SPO-12b-PRE-002** An empty or blank body exits 1 ("no data found on the registry"). A body that is not valid JSON, including the plain-text answer of a 404, exits 1 and shows the body. (src: L67, L72-L77)
4. **Show the entry.**
   - **SPO-12b-OUT-001** Displays, for each of `name`, `description`, `ticker`, `url`, `decimals`, the entry's `value` and, when present, its `sequenceNumber`. Absent properties show empty. Display only. (src: L80-L103)
   - **SPO-12b-OUT-002** When the entry has a `logo`, the base64 value is decoded to `<tempDir>/tmp.png` (replaced on every run) and the byte size and `sequenceNumber` are shown. The file is not validated as a PNG. (src: L105-L113)
   - **SPO-12b-INV-001** Success ends with exit 0, including when some properties are missing. The script does not verify the entry's signature, compare it with the local record, or check that its sequence number matches the record's. (src: L63-L115)

## Work modes

- **SPO-12b-MODE-001** Online and light behave the same; offline is refused (SPO-12b-PRE-001). Registry endpoints differ per network (SPO-Cconf-IN-005): the preset for PreProd, Preview and the other test networks is the legacy testnet registry. (src: L20-L21, L63)

## Prompts

No prompts.

## Outputs

- **SPO-12b-OUT-003** Writes only `<tempDir>/tmp.png` (SPO-12b-OUT-002); nothing in the workspace changes. (src: L107-L108)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<tempDir>/tmp.png` | decoded registry logo | default | created or replaced, only when the entry has a logo |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Offline mode | 1 | SPO-12b-PRE-001 |
| Wrong argument count | 1 | SPO-12b-IF-001 |
| Neither a record nor a valid subject | 1 | SPO-12b-IF-002 |
| Record has no valid subject | 1 | SPO-12b-IN-001 |
| Empty registry answer | 1 | SPO-12b-PRE-002 |
| Invalid JSON answer | 1 | SPO-12b-PRE-002 |

## Security

- **SPO-12b-SEC-001** Handles no secrets. It discloses to the registry operator, and any network observer when the URL is plain HTTP, that the operator is interested in the subject; and it writes decoded remote content (the logo) to a predictable temp path without validating it. (src: L64, L107-L108)

## Domain mapping

Use case `CheckAssetRegistry(subject | policy.asset)`, read-only, on the `AssetRecord` projection.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(AssetRecord)` | Subject lookup |
| `Directory` | `tokenMetadata(subject)` | Fetch the registry entry |
| `UI` | `show(view)` | Display |

## Port notes

* Verify the HTTP status instead of inferring failure from the body, and distinguish "not found" from "unreachable".
* Compare the registry's `sequenceNumber` with the record's and report "published", "behind" or "not found".
* Verify the entry signature against the policy script when the library allows.
* Write the logo to a private temporary file and validate its type.

## Open questions

* None blocking. The exact shape of a registry answer (`<field>.value`, `<field>.sequenceNumber`, signatures) is the registry's contract and is only partially read here.
