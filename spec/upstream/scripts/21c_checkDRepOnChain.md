+++
id = "21c"
kind = "script"
title = "Check a DRep on chain"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "chain-access", "air-gap-transfer"]
use_cases = ["CheckDRepOnChain"]
depends_on = ["Cconf", "Cchain", "Clight", "Cconv", "Coffline", "Cui", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/21c_checkDRepOnChain.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "8aefdfd18f02e9684170062d11df673507d0702db77a5c25c143d074b9c8d58e"
upstream_lines = 285
uses_common = [
  "checkError",
  "convertToADA",
  "convert_actionBech2CIP129",
  "convert_actionCIP1292Bech",
  "exists",
  "get_currentEpoch",
  "get_currentSync",
  "majorError",
  "queryLight_drepInfo",
  "readOfflineFile",
  "showProcessAnimation",
  "stopProcessAnimation",
  "versionCheck",
]
cli_commands = [
  "governance drep id",
  "query drep-state",
]
hwcli_commands = []
signer_commands = [
  "verify",
]
http_endpoints = []
env_vars = []
+++

# 21c_checkDRepOnChain: Check a DRep on chain

Read-only lookup of a DRep by name, by file or by any of the id spellings. It resolves the input to a DRep id, shows the id in both the legacy (CIP-105) and CIP-129 forms, reads the DRep's state (registered, deposit, expiry epoch, anchor, delegated stake, credential type) and, in online and light mode, downloads the anchor document and checks its hash and CIP-100 signatures. It writes no artefact and builds no transaction.

The script is the one place in the governance scripts that accepts script-credential DRep ids.

## Interface

- **SPO-21c-IF-001** Takes exactly one argument; any other count prints usage on stderr and exits 1. (src: L19-L26)
- **SPO-21c-IF-002** The argument is a DRep name (a trailing `.id`, then a trailing `.drep`, are dropped), a 56-hex-digit credential hash, a legacy `drep1...` id (56 characters), a CIP-129 `drep1...` id (58 characters), a legacy `drep_script1...` id (63 characters), or the base name of a `.drep.vkey` file. The argument is lower-cased for the id forms; the file-name forms keep the original case. (src: L19-L21, L74-L129)
- **SPO-21c-PRE-001** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0. (src: L28-L33)

## Inputs

- **SPO-21c-IN-001** Resolution order, first match wins. (1) A file `<name>.drep.id` exists: its content is read as a bech32 id and then handled by rules 3 to 5 below, after being validated with the bech32 tool; an invalid bech32 exits 1. (2) 56 hex digits: converted with `bech32 drep` to a legacy `drep1...` id (always a key hash, since a hex hash carries no credential type). (3) `drep1...` of length 56: validated by the bech32 tool (exit 1 when invalid) and used as legacy id. (4) `drep1...` of length 58: validated and used as CIP-129 id. (5) `drep_script1...` of length 63: validated and used as legacy script id. (6) A file `<name>.drep.vkey`: the id is `cardano-cli latest governance drep id --drep-verification-key-file <name>.drep.vkey --out-file /dev/stdout`. (7) Otherwise exit 1. (src: L61-L129)
- **SPO-21c-INV-001** The id forms are displayed by converting between them with Cconv (SPO-Cconv-OUT-019 legacy to CIP-129, SPO-Cconv-OUT-020 CIP-129 to legacy, using the header bytes `22` key and `23` script, see its table). The script assumes that cardano-cli prints the legacy form for rule 6; a CIP-129 output would be converted a second time (see the quirk in Cconv). (src: L81-L82, L92-L93, L103-L104, L114-L115, L124-L125)
- **SPO-21c-INV-002** The credential hash used for the node query is the last 56 hex digits of the bech32 payload of the id, so a CIP-129 id contributes its hash without the header byte. It is also displayed. (src: L133-L135)
- **SPO-21c-IN-002** In offline mode reads `drep."<id>".drepStateJSON` from the transfer file, with `<id>` the resolved id exactly as held in the variable: a legacy id for rules 1 to 3, 5 and 6, but the CIP-129 string for rule 4. The transfer file is keyed by the legacy id read from `<name>.id` (SPO-Ptransfer-OUT-007), so a CIP-129 argument never finds its entry in offline mode. (src: L154-L156)

## Behaviour

1. **cardano-signer gate.**
   - **SPO-21c-PRE-002** In online and light mode, before resolving anything, requires a working `cardano-signer` of at least the minimum version (configured path, else `<scriptDir>/cardano-signer`); a missing, failing or old tool exits 1. The check happens even when no anchor will be verified. Offline mode skips it. (src: L39-L55)
2. **Resolve the id** as in SPO-21c-IN-001.
3. **Query the state.**
   - **SPO-21c-EXT-001** Online: requires the node to report synced (exit 1 otherwise), then runs `cardano-cli <era> query drep-state --drep-key-hash <hash> --drep-script-hash <hash> --include-stake` with the same hash for both options, so a key DRep and a script DRep with that hash both match, and keeps element 0 of the result (`[]` when absent). A failed query prints the error and exits **0** (status of the `echo` in `echo ...; exit $?`, L144). (src: L140-L146)
     > **Upstream quirk:** a failed DRep-state query looks like success to a caller. A port exits non-zero.
   - **SPO-21c-EXT-002** Light: calls `queryLight_drepInfo <id>` with the resolved id (SPO-Clight-IN-002 converts 56- and 63-character ids to CIP-129 for Koios) and keeps element 0. A failure exits **0** as in SPO-21c-EXT-001 (L150). (src: L148-L152)
   - **SPO-21c-PRE-003** Offline: an id missing from the transfer file prints "include it first online" and exits 0. (src: L154-L156)
4. **Report the state.**
   - **SPO-21c-OUT-001** The report shows, read from the state: entry count, deposit, anchor URL and anchor hash (`-` when absent), expiry epoch, delegated stake and the credential type (the key name of element 0: `keyHash` or `scriptHash`). Current epoch comes from the work mode (SPO-Cchain-OUT-001). (src: L161-L169, L189-L193)
   - **SPO-21c-PRE-004** An empty state (the DRep is not registered) is reported and the script exits **1**. This is the only outcome with a non-zero exit after a successful lookup; scripts or workflows that read the exit code as "registered or not" can rely on it. (src: L172-L174)
   - **SPO-21c-INV-003** A registered DRep whose expiry epoch is below the current epoch is reported as registered but expired (inactive) and the script continues and exits 0; otherwise it is reported as registered. (src: L176-L187)
5. **Verify the anchor (online and light only).**
   - **SPO-21c-EXT-003** When the DRep has an anchor URL, downloads it with `curl -sL -m 30 --max-filesize 10485760` (10 MiB cap, redirects followed), up to 5 attempts with a 1 second pause after a transport failure; `ipfs://<path>` is fetched from `https://ipfs.io/ipfs/<path>`. (src: L197-L219)
   - **SPO-21c-EXT-004** On HTTP 200 and valid JSON, hashes the file with `b2sum -l 256` and compares it with the registered anchor hash. On a match runs `cardano-signer verify --cip100 --data-file <file> --json-extended` and lists each author signature as valid or not. A 404, another status, a non-JSON body, a hash mismatch, a size above the cap and a failed download are each reported and **never change the exit code**. (src: L228-L282)
   - **SPO-21c-OUT-002** The temporary file `<tempDir>/DRepAnchorURLContent.tmp` is removed after a 200 response (valid JSON or not) and left behind after a 404, another status or a failed download. (src: L204, L234, L258, L263-L277)

## Work modes

- **SPO-21c-MODE-001** Online needs the synced node; light needs Koios; offline needs a transfer file made by `01_workOffline add-drep` and skips the anchor verification. Unlike 21b and 21d the offline mode is supported. (src: L138-L159, L197)

## Prompts

No prompts.

## Outputs

No files are written (except the temporary anchor file of SPO-21c-OUT-002). The result is the report and the exit code: 0 for registered (also expired), 1 for not registered or any error, 0 for offline-not-in-file and pre-Conway.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Wrong argument count | 1 | SPO-21c-IF-001 |
| Pre-Conway era (configured) | 0 | SPO-21c-PRE-001 |
| cardano-signer missing, old or failing (online, light) | 1 | SPO-21c-PRE-002 |
| Invalid bech32, unresolvable input | 1 | SPO-21c-IN-001 |
| Node not synced (online) | 1 | SPO-21c-EXT-001 |
| Query failed | **0** (status of the `echo`) | SPO-21c-EXT-001, SPO-21c-EXT-002 |
| Offline: id not in the transfer file | 0 | SPO-21c-PRE-003 |
| DRep not registered | 1 | SPO-21c-PRE-004 |

## Security

- **SPO-21c-SEC-001** The anchor URL comes from chain data chosen by the DRep and is fetched from the operator's machine with redirects followed; the 10 MiB cap limits the size, nothing limits the destination. (src: L197-L219)

## Domain mapping

Use case `CheckDRepOnChain(drepRef)` on aggregate `DRep` (read side).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `convertGovernanceId(id, form)` | CIP-105 and CIP-129 forms, hash extraction |
| `Ledger` | `deriveId(DRep verification key)` *(new)* | Rule 6 (shared with 21a) |
| `ChainQuery` | `drepState(drepId \| hash)`, `tip()`, `syncStatus()` | State and epoch |
| `Directory` | `fetchUrl(anchorUrl)` | Anchor download |
| `Ledger` | `anchorHash(bytes)` *(new)* | BLAKE2b-256 comparison |
| `Signer` | `verifyCip100(document)` *(new)* | `cardano-signer verify --cip100` author signatures |
| `Store` | `get(DRepId)` | `.drep.id` file |
| `Toolchain` | `locate`/`version(cardano-signer)` | Gate |

## Port notes

* Report registered, expired and not registered as distinct results instead of using exit code 1 for "not registered".
* Accept a CIP-129 id offline by normalising to one canonical form before the snapshot lookup.
* Accept a hex hash together with an explicit credential type, so script DReps can be checked from a hash.
* Require `cardano-signer` only when an anchor is actually verified.
* The vkey rule hard-codes the era `latest` instead of the configured era; a native derivation removes the difference.

## Open questions

* Whether the pinned cardano-cli prints the CIP-105 or CIP-129 form for `governance drep id`. This decides whether rule 6 shows the right "legacy" and "CIP129" lines. A real run settles it.
* Whether `query drep-state` accepts the same hash for `--drep-key-hash` and `--drep-script-hash` in one call and returns both matches; the script depends on it.
