+++
id = "12a"
kind = "script"
title = "Generate and sign token-registry metadata"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["native-assets", "key-custody"]
use_cases = ["GenerateAssetMetadata"]
depends_on = ["Cconf","Ckey","Cconv","Pfiles","Cchain"]

upstream_path = "cardano/mainnet/12a_genAssetMeta.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "b98296469ace20768f9be32288745fcc2165736871c3a53af48011bc23f2dbf9"
upstream_lines = 297
uses_common = [
  "checkError",
  "convert_assetNameASCII2HEX",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "file_lock",
  "file_unlock",
  "get_currentTTL",
  "majorError",
  "read_skeyFILE",
]
cli_commands = []
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 12a_genAssetMeta: Generate and sign token-registry metadata

Prepares the token-registry submission file for an asset created by [11a](./11a_mintAsset.md). It is a two-phase editor around the external tool `token-metadata-creator`. The first run creates the asset record `<policy>.<asset>.asset` (if absent) and stops so the operator can fill in the `meta*` fields. Later runs validate those fields, drive the tool to build a draft, sign it with the policy key, finalise and validate it, bump the record's `sequenceNumber`, and place `<subject>.json` next to the record. The operator then submits the file to the Cardano Token Registry as a pull request. The script never touches the chain and never uses a node or Koios. [12b](./12b_checkAssetMetaServer.md) checks whether the registry serves the result.

## Interface

- **SPO-12a-IF-001** Takes exactly one argument, `<policy>.<asset>` (a trailing `.asset` is dropped). Any other argument count prints usage to stderr and exits 1. The policy name is the directory part plus the text before the first dot and the asset name is the text after the last dot, as in SPO-11a-IF-002. (src: L27-L39)
- **SPO-12a-IF-002** The asset name rules are those of SPO-11a-IF-003: ASCII alphanumerics (converted to hex) or `{<hex>}`; anything else, or a name longer than 32 bytes, exits 1. (src: L53-L61)

## Inputs

- **SPO-12a-IN-001** The path of `token-metadata-creator` is the `cardanometa` setting (default `./token-metadata-creator`). When that path is not an existing command the script falls back to `<scriptDir>/token-metadata-creator`, else prints where to get it and exits 1. (src: L21-L25)
- **SPO-12a-IN-002** Requires `<policy>.policy.id` and `<policy>.policy.script` (exit 1 each), `<policy>.policy.skey` (exit 1), and refuses a hardware policy: when `<policy>.policy.hwsfile` exists it exits 1 ("signing with hardware wallet policies is not supported"), checked before the `.skey` check. The policy id is read verbatim from the id file. (src: L46-L50)
- **SPO-12a-IN-003** Reads the asset record `<policy>.<asset>.asset` (SPO-Pfiles-OUT-033). The record's file name uses the asset name as typed, so a `{hex}` name keeps its braces. (src: L43, L137)
- **SPO-12a-IN-004** The policy's `before` slot (or `unlimited`) is read from the script as in SPO-11a-INV-001 and written to the record. The script also computes the transaction TTL with `get_currentTTL` when the policy is unlimited, but the value is never used. (src: L69-L72)
  > **Upstream quirk:** that call needs chain access (node socket, Koios or genesis files) for no effect; a failure ends only the command substitution, so it never stops the script.

## Behaviour

1. **First run: create the record and stop.**
   - **SPO-12a-OUT-001** When `<policy>.<asset>.asset` does not exist the script creates it with these values: `metaName` (the readable asset name, cut to 50 characters), empty `metaDescription`, `metaDecimals`, `metaTicker`, `metaUrl`, `metaLogoPNG`, the marker keys `---` and `===`, `minted: "0"`, `name`, `hexname` (the hex name only for `{hex}` input, else empty), `bechName`, `policyID`, `policyValidBeforeSlot`, `subject` (policy id plus hex name), `sequenceNumber: "0"`, `lastUpdate` and `lastAction: "created Asset-File"`. It prints the record, tells the operator to edit and rerun, and exits 0 without any validation or signing. The new file is **not** locked. (src: L76-L111)
2. **Normalise the record.**
   - **SPO-12a-OUT-002** When the record exists it is read, merged over a skeleton in which the existing keys win, and written back (unlocked, written, locked `0400`) before validation. The skeleton supplies missing keys: `metaName` (the hex asset name), empty `metaDescription`, `metaDecimals: "0"`, empty `metaTicker`, `metaUrl`, `metaLogoPNG`, `minted: "0"`, `name`, empty `hexname`, `bechName`, `policyID`, `policyValidBeforeSlot`, `subject`, `sequenceNumber: "0"`, a fresh `lastUpdate` and `lastAction: "update Asset-File"`. Existing `lastUpdate`, `lastAction`, `policyValidBeforeSlot` and the rest are therefore kept, not refreshed. (src: L113-L148)
   > **Upstream quirk:** a record created by 11a (no `metaDecimals`) gains `metaDecimals: "0"` here and so registers 0 decimals, whereas a record created by 12a itself carries an empty `metaDecimals` and registers none. The record is locked before validation can fail, so the operator has to unlock it to fix an error.
   - **SPO-12a-INV-001** The subject used for everything that follows is the record's `subject` value, not a recomputed one. The new sequence number is the record's `sequenceNumber` plus one, in shell arithmetic. (src: L154-L156)
3. **Validate the fields** (each failure prints the reason and exits 1; characters are counted, not bytes).
   - **SPO-12a-PRE-001** `metaName` must be 1 to 50 characters. (src: L164-L168)
   - **SPO-12a-PRE-002** `metaDescription` must be 1 to 500 characters. (src: L173-L176)
   - **SPO-12a-PRE-003** `metaTicker` is optional; when non-empty it must be 2 to 9 characters. (src: L186-L193)
   - **SPO-12a-PRE-004** `metaUrl` is optional; when non-empty it must contain `https://` (the pattern is not anchored, so the text may precede it) and be at most 250 characters. (src: L197-L203)
   > **Upstream quirk:** `metaUrl` is accepted when `https://` occurs anywhere in the string. The registry requires a leading `https://`; a port anchors the check.
   - **SPO-12a-PRE-005** `metaDecimals` is optional; empty adds nothing. A value of digits only must be at most 255. Any other non-empty value is refused. (src: L207-L216)
   - **SPO-12a-PRE-006** `metaLogoPNG` is optional; when non-empty the file must exist (exit 1) and `file -b` must report PNG (exit 1). No size limit is checked here. (src: L220-L227)
4. **Build, sign, finalise, validate with the external tool.**
   - **SPO-12a-EXT-001** Runs `token-metadata-creator entry <subject> --init --name <metaName> --description <metaDescription> --policy <policy>.policy.script`, then `--ticker`, `--url`, `--decimals`, `--logo` for each optional field that passed. A non-zero exit ends the script with that code. The tool's stdout is the draft file name. (src: L160-L181, L186-L236)
   - **SPO-12a-EXT-002** In the draft the `sequenceNumber` line is rewritten to the new sequence number with `sed`. (src: L238-L242)
   - **SPO-12a-EXT-003** The draft is signed with `token-metadata-creator entry <subject> -a <policy key>`, where the policy signing key is read into memory with `read_skeyFILE` (an encrypted key asks for its password, see `Ckey`; failure exits 1) and handed over through an anonymous pipe, then unset. A tool failure ends the script with its code. (src: L246-L255)
   - **SPO-12a-EXT-004** The draft is finalised with `token-metadata-creator entry <subject> --finalize` (stdout is the final file name) and checked with `token-metadata-creator validate <file>`; each failure ends the script with the tool's code. (src: L259-L270)
5. **Record and place the result.**
   - **SPO-12a-OUT-003** The record gets `sequenceNumber` set to the new value, `lastUpdate` set to now, and `lastAction` `created Token-Registry-JSON`; the file is unlocked, written and locked. This happens after validation succeeds and before the file is moved. (src: L272-L276)
   - **SPO-12a-OUT-004** When the record lives in a directory other than `.`, the final JSON is moved into that directory, replacing a file of the same name; otherwise it stays in the working directory. The result is `<dir>/<subject>.json`. The script tells the operator to submit it as a pull request to the Cardano Foundation token registry. (src: L279-L292)
   - **SPO-12a-INV-002** `sequenceNumber` increases by exactly one on every successful run, and is the number embedded in the submission, so the registry accepts an update only when the record is kept (SPO-12a-OUT-003). (src: L154-L156, L238-L242, L272-L276)

## Work modes

Mode-independent: no chain query is needed (the unused TTL of SPO-12a-IN-004 aside).

## Prompts

No prompts, except the password for an encrypted policy key (SPO-12a-EXT-003).

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<policy>.<asset>.asset` | record, SPO-12a-OUT-001 / SPO-12a-OUT-002 / SPO-12a-OUT-003 | default after creation, `0400` after later runs | created, then replaced |
| `<subject>.json` (in the record's directory) | signed token-registry submission | default | created, replaced if present |
| intermediate draft | `token-metadata-creator` draft | default | consumed by the tool |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Tool not found | 1 | SPO-12a-IN-001 |
| Wrong argument count | 1 | SPO-12a-IF-001 |
| Bad or long asset name | 1 | SPO-12a-IF-002 |
| Policy id, script or key missing; hardware policy | 1 | SPO-12a-IN-002 |
| Invalid `meta*` field | 1 | SPO-12a-PRE-001 .. SPO-12a-PRE-006 |
| `token-metadata-creator` fails | tool's code | SPO-12a-EXT-001, SPO-12a-EXT-003, SPO-12a-EXT-004 |
| Key read failure | 1 | SPO-12a-EXT-003 |
| First run (record created, edit it) | 0 | SPO-12a-OUT-001 |

## Security

- **SPO-12a-SEC-001** The policy signing key is read and used in memory; no secret is printed. The submission proves control of the policy key and is public once submitted. (src: L246-L255)
- **SPO-12a-SEC-002** A registry entry is signed per asset under the policy key, and a later entry with a higher sequence number replaces it: whoever holds the policy key controls the displayed name, ticker, logo and decimals. (src: L250, L261)

## Domain mapping

Use case `GenerateAssetMetadata(policy, assetName)` on aggregate `AssetRecord` (metadata fields, sequence number) with the `MintingPolicy`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get/put(AssetRecord)`, `put(RegistryEntry)`, `lock` | Record and submission file |
| `Ledger` | `assetFingerprint`, `policyId` | `bechName`, `subject` |
| `Signer` | `signMessage(payload, policyKey)` | Sign the registry entry *(new: registry-entry signing, CIP-26)* |
| `Vault` | `unseal(policyKeyRef)` | In-memory key |
| `Directory` | `registryEntryBuilder` *(new)* | Draft/finalise/validate (upstream: external tool) |
| `UI` | `askPassword` | Encrypted policy key |

## Port notes

* The CIP-26 entry (subject, policy script, name, description, optional ticker, url, logo, decimals, each with sequence number and a signature over the entry) can be built natively; the external binary is only an adapter.
* Split "create record" from "publish metadata" into two use cases instead of the stop-and-rerun protocol, and take the fields as input rather than editing a file.
* Anchor the URL check, count bytes or characters consistently with the registry rules, and enforce the 64 KB logo limit of the registry.
* Hardware policies cannot be signed here (SPO-12a-IN-002); a remote signer or a device-signed message would remove that gap.
* Do not lock the record before validation (SPO-12a-OUT-002).

## Open questions

* Exact stdout of each `token-metadata-creator` subcommand (the draft and final file names) comes from the tool, not the script; confirm against the pinned release.
* The 64 KB logo limit and the registry's ticker and decimals rules are the registry's, not enforced here.
