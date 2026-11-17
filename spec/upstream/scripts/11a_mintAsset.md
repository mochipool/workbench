+++
id = "11a"
kind = "script"
title = "Mint native tokens under a policy"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["native-assets", "transaction-construction"]
use_cases = ["MintAsset"]
depends_on = ["Ptx","Pparam","Pfiles","Ptransfer","Cutxo","Cconv","Ckey","Chw","Cui"]

upstream_path = "cardano/mainnet/11a_mintAsset.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "52a8afd982a4cc49a198169efe6a0508e9380472b0d27e793e43722f1a408792"
upstream_lines = 738
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_assetNameASCII2HEX",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "file_lock",
  "file_unlock",
  "filterFor_UTXO",
  "generate_UTXO",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
  "readOfflineFile",
  "read_skeyFILE",
  "showOfflineFileInfo",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
  "submitLight",
  "trimString",
]
cli_commands = [
  "query protocol-parameters",
  "query utxo",
  "transaction assemble",
  "transaction build-raw",
  "transaction calculate-min-fee",
  "transaction submit",
  "transaction txid",
  "transaction witness",
]
hwcli_commands = [
  "transaction witness",
]
signer_commands = []
http_endpoints = [
  "tokenMetaServer",
]
env_vars = [
  "ENV_SKIP_PROMPT",
]
+++

# 11a_mintAsset: Mint native tokens under a policy

Mints a positive amount of one native asset under a policy created by [10](./10_genPolicy.md) and credits it to the paying address. It follows the shared transaction pipeline ([Ptx](../patterns/Ptx.md)) with one extra input (the policy: script, id and signing key) and two witnesses (the policy key and the payment key). It also keeps a running record of the asset in `<policy>.<asset>.asset`, which [12a](./12a_genAssetMeta.md) later turns into token-registry metadata. Its mirror image is [11b](./11b_burnAsset.md).

Follows the Ptx pipeline (SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-010) with the variations below. Shared behaviour is not repeated: the UTxO gathering and totals (SPO-Ptx-MODE-002 .. SPO-Ptx-INV-004), the dummy body and fee (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005, SPO-Ptx-INV-006, witness count 2), minimum output value (SPO-Ptx-EXT-003, SPO-Ptx-PRE-002), the final body (SPO-Ptx-EXT-004), the signing mechanics (SPO-Ptx-EXT-005, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-SEC-001), the size check (SPO-Ptx-PRE-007), the confirmation (SPO-Ptx-PR-002, SPO-Ptx-PR-003) and submission or queueing (SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010).

## Interface

- **SPO-11a-IF-001** Takes at least three positional words: the asset reference `<policy>.<asset>` (a trailing `.asset` is dropped), the amount, and the paying address name (extension `.addr` optional, see SPO-Pfiles-IN-001). Fewer words print usage to stderr and exit 1. (src: L20-L26, L27-L53)
- **SPO-11a-IF-002** The asset reference splits at dots: the policy name is the directory part plus the text before the **first** dot; the asset name is the text after the **last** dot. With more than one dot the text between is dropped silently, and with no dot the asset name equals the policy name. (src: L23-L25)
  > **Upstream quirk:** a reference such as `mypolicy` (no dot) mints an asset named `mypolicy` under policy `mypolicy`. A port requires exactly one dot.
- **SPO-11a-IF-003** The asset name is one of: ASCII alphanumerics only, which are converted to hex; or `{<hex>}` with an even number of hex digits (one or more pairs, case-insensitive, stored lower-case), used as the raw name. Anything else is refused with exit 1. (src: L57-L62)
- **SPO-11a-PRE-001** Exits 1 when the hex form of the asset name is longer than 64 hex digits (more than 32 bytes). (src: L66)
- **SPO-11a-PRE-002** Exits 1 when the amount is less than 1, evaluated as a shell integer; a word that is not a number evaluates as 0 and is refused. (src: L67)
  > **Upstream quirk:** an amount above the signed 64-bit range overflows the shell comparison, and amounts are not otherwise bounded. The ledger limits a single mint to a signed 64-bit integer; a port refuses larger values.
- **SPO-11a-IF-004** All words from the fourth on are extra parameters per `Pparam` (SPO-Pparam-IF-001). Accepted: metadata files `.json` / `.cbor` (SPO-Pparam-IF-014, SPO-Pparam-IF-015), a UTxO list (SPO-Pparam-IF-019), `msg:` (SPO-Pparam-IF-008), `enc:` (only `basic`; others silently send plain text, SPO-Pparam-INV-001) and `pass:`. `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and `keeppolicy:` are not known here, so they are treated as file words and refused with exit 1 (SPO-Pparam-IF-005). (src: L81-L140)
- **SPO-11a-OUT-001** A message file is written as in SPO-Pparam-OUT-002 (`<tempDir>/<payment name>.transactionMessage.json`) and appended after the user metadata files. (src: L143-L171)

## Inputs

- **SPO-11a-IN-001** Requires `<policy>.policy.id` and `<policy>.policy.script` (exit 1 each when missing) and `<policy>.policy.skey` or `<policy>.policy.hwsfile` (exit 2 when both are missing), created by [10](./10_genPolicy.md). The policy id is read verbatim from the id file; it is not recomputed from the script. (src: L70-L73)
- **SPO-11a-IN-002** Requires `<pay>.addr` (exit 1 when missing) and `<pay>.skey` or `<pay>.hwsfile` (exit 1 when both are missing). The paying address is also the destination of the minted tokens: the destination name equals the payer name. (src: L21-L22, L75-L77, L196-L197)
- **SPO-11a-IN-003** The paying address is validated as an address (SPO-Caddr-*; failure ends the script with that code). (src: L199)
- **SPO-11a-IN-004** Reads `ENV_SKIP_PROMPT`, the work mode, `queryTokenRegistry` and the token registry endpoint (display only), `cropTxOutput` and `transactionExplorer`, as in SPO-Ptx-IN-003. (src: L358, L438, L537, L551)

## Behaviour

1. **Establish the validity window.**
   - **SPO-11a-INV-001** The policy's expiry is the `slot` of the first `before` entry of the script's top-level `scripts` array, or `unlimited` when the script has none (a plain `sig` script, or an unreadable script). (src: L186-L187)
   - **SPO-11a-PRE-003** The transaction TTL (`--invalid-hereafter`) is the policy's expiry slot when it has one, else `current slot + defTTL` (SPO-Ptx-INV-001). When the TTL is not greater than the current slot the script exits 2 ("policy expired") before any UTxO query. (src: L183, L188, L194)
2. **Gather inputs.** As SPO-Ptx-MODE-002 .. SPO-Ptx-MODE-004 with the UTxO list filter only; zero UTxOs exit 1 (SPO-Ptx-PRE-001). (src: L208-L239)
3. **Add the minted amount to the totals.**
   - **SPO-11a-INV-002** The asset totals start with the minted asset at the minted amount, then the amounts of the same asset on the inputs are added. Every asset with a total above zero, including the minted one, is returned to the paying address in the single change output together with the lovelaces. (src: L247-L254, L299-L302, L366, L175)
4. **Build, sign, submit.**
   - **SPO-11a-EXT-001** Both the dummy and the final body are built with `--mint "<amount> <policyid>[.<hexname>]"` (the dot is omitted for an empty name), `--minting-script-file <policy>.policy.script` and `--invalid-hereafter <ttl>`, plus the metadata files. (src: L400, L435)
   - **SPO-11a-INV-003** The fee estimate uses witness count 2: one for the policy key, one for the payment key. (src: L404)
   - **SPO-11a-PRE-004** When the change would hold fewer lovelaces than the minimum output value the script exits **0** (SPO-Ptx-PRE-002). (src: L410-L415)
   - **SPO-11a-EXT-002** When either the policy or the payment key is a hardware file, the body is first rewritten to canonical form (`autocorrect_TxBodyFile`, SPO-Ptx-EXT-005); failure exits 1. (src: L442-L449)
   - **SPO-11a-EXT-003** (see the note below) The policy witness is created first, then the payment witness, each into its own witness file; the transaction is assembled from the body and the two witness files in that order. (src: L455-L484, L489-L518, L522-L523)
   - **SPO-11a-PR-001** A hardware policy key: asks "adding the policy witness from a local hardware wallet, continue?" (default Yes; declining exits 2), then starts the hardware session and runs `cardano-hw-cli transaction witness --tx-file <body> --hw-signing-file <policy hwsfile> --out-file <witness>` plus the network magic. The output is classified as in SPO-Ptx-PRE-005. (src: L455-L471)
   - **SPO-11a-PR-002** A hardware payment key: the same question for the payment witness (default Yes; declining exits 2); the device command also passes `--change-output-key-file <pay hwsfile>`. (src: L489-L505)
   - **SPO-11a-EXT-004** A key-file policy or payment key is read into memory with `read_skeyFILE` (an encrypted key asks for its password, see `Ckey`), signs with `cardano-cli transaction witness`, and is unset. A read failure exits 1. (src: L476-L482, L510-L516)
     > **Observed 2026-11-16 (`spo/test/parity/assets_oracle_test.go`):** `cardano-cli build-raw --mint ... --minting-script-file` writes the mint field as key 9 of the body, after the time to live (3) and the certificates (4) and withdrawals (5), and *before* the auxiliary data hash (7); the native scripts go into the witness set of the body file as key 1, a tag-258 set in ascending order of the script hash (the order of the `--minting-script-file` options does not matter, and a script named twice is one script). The signers add key 0. The fee at witness count 2 counts the script. Mint, burn, two policies, a `before` policy with the TTL at its slot, metadata files and a message are byte-equal in the body, the fee, the witnesses and the assembled transaction. Offline, upstream's queued transaction and the port's are byte-equal, as is the asset record apart from `lastUpdate` (`TestMintBurnMatchUpstream`).
- **SPO-11a-INV-004** Either signer may be hardware or file independently: the policy key and the payment key are not required to use the same kind. (src: L455, L473, L489, L507)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-11a-INV-006** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the asset reference, name and amount parsing of SPO-11a-IF-001 to SPO-11a-IF-004, SPO-11a-PRE-001 and SPO-11a-PRE-002, and the files of SPO-11a-IN-001 to SPO-11a-IN-003. (src: L19-L180, L196-L200)
- **SPO-11a-INV-007** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001), with the TTL taken from the policy's `before` slot when it has one and the policy-expired refusal (SPO-11a-INV-001, SPO-11a-PRE-003, SPO-Ptx-INV-001). (src: L182-L194)
- **SPO-11a-INV-008** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001), with only the UTxO-list filter; a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002). (src: L204-L239)
- **SPO-11a-INV-009** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005), with the minted asset preloaded into the totals (SPO-11a-INV-002). (src: L241-L383)
- **SPO-11a-INV-010** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read after the UTxO stage. (src: L385-L391)
- **SPO-11a-INV-011** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005), with `--mint` and `--minting-script-file` attached and witness count 2 (SPO-11a-EXT-001, SPO-11a-INV-003). (src: L393-L406)
- **SPO-11a-INV-012** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with no deposit, so the change is `inputs - fee`, and exit 0 when it is too small (SPO-11a-PRE-004). (src: L408-L417)
- **SPO-11a-INV-013** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee and the same mint arguments; the witness files are `<tempDir>/<policy>.witness` and `<tempDir>/<pay>.witness`, removed first. (src: L419-L439)
- **SPO-11a-INV-014** Stage 9, sign: not the Ptx single-signer form. A policy witness and a payment witness are made independently by hardware or key file (SPO-11a-EXT-002 to SPO-11a-EXT-004, SPO-11a-PR-001, SPO-11a-PR-002, SPO-11a-INV-004) and assembled; the hardware output is classified as SPO-Ptx-PRE-005. (src: L441-L526)
- **SPO-11a-INV-015** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L529-L534)
- **SPO-11a-INV-016** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003); `ENV_SKIP_PROMPT=YES` skips it. (src: L536-L538)
- **SPO-11a-INV-017** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010), with the asset-record update after a successful online or light submit and the `Asset-Minting` queue entry offline (SPO-11a-MODE-001, SPO-11a-MODE-002, SPO-11a-OUT-002). (src: L540-L733)

## Work modes

- **SPO-11a-MODE-001** Online and light: after a successful submit the asset record is updated (SPO-11a-OUT-002) and shown; the registry lookup in the summary is display only. A failed online submit ends the script before the record is updated. (src: L541-L598, L601-L656)
- **SPO-11a-MODE-002** Offline: the signed transaction is queued with `type` `Asset-Minting` and the history entry `minted <amount> '<input name>' on '<pay name>'` (SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012). The asset record is updated **at queue time**, after the read-back succeeds and before anything reaches the chain, with `lastAction` `mint <amount> (only Offline proof)`. A read-back mismatch prints an error, leaves the asset record untouched and exits 0. (src: L659-L730)
  > **Upstream quirk:** the record counts the mint although the transaction may never be executed, may fail, or may expire with the policy. Queueing the same mint twice counts it twice. A port updates the record on confirmed submission, or marks it provisional.
  > **Port decision 2026-11-16 (hazard H9):** a queued mint changes no record. The update is stored under the transaction id (`<txid>.asset-pending`) when the transaction is queued and applied by `assets.Settle` when the transaction is confirmed (superseded by the confirmation decision below: an accepted submit applies nothing, and `SettlingSubmitter` and `ExecuteTx.Assets` no longer exist). After settlement the record equals upstream's offline record apart from `lastUpdate`, `lastAction` included (`mint N (only Offline proof)`). A direct (online or light) submission applies its update, with `mint N`, when it is confirmed. The record keeps upstream's offline skeleton (no `metaDecimals`, an uncut `metaName`) in every mode.
  > **Port decision 2026-11-16 (hazard H9, confirmation):** the record is not written on an accepted submit either. The update is kept as a pending update (`<txid>.pending`, with the transaction's validity bound) and applied when the providers confirm the transaction: by the wait that `asset mint` runs by default in light and online mode, or by `spo tx settle`. Across the air gap `spo asset settle` applies it only when the transfer file's history records the transaction as confirmed (`--accept-submitted` trusts the submit alone). A transaction that expires is discarded, never applied. See SPO-Xconfirm-PR-001, SPO-Xconfirm-PR-012 and SPO-Xconfirm-PR-023; the first version's `<txid>.asset-pending` files are still read.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Policy witness from a hardware wallet (SPO-11a-PR-001) | Yes | Decline exits 2 |
| Payment witness from a hardware wallet (SPO-11a-PR-002) | Yes | Decline exits 2 |
| Does this look good, continue? (SPO-Ptx-PR-002) | No | Skipped when `ENV_SKIP_PROMPT=YES` (SPO-Ptx-PR-003) |
| Key password for encrypted policy or payment key (`Ckey`) | none | Decrypts in memory |

## Outputs

- **SPO-11a-OUT-002** The asset record `<policy>.<asset>.asset` is created when absent and updated after the chain step of SPO-11a-MODE-001 or SPO-11a-MODE-002, by this procedure: start from `{}`, fill missing keys from the skeleton below, then set `minted` to the old `minted` (0 when absent) plus the minted amount in arbitrary-precision arithmetic, and overwrite `name`, `hexname`, `bechName`, `policyID`, `policyValidBeforeSlot` (the expiry or `unlimited`), `subject`, `lastUpdate` (RFC-5322 date) and `lastAction` (`mint <amount>`). Keys already present, such as the operator's `meta*` edits, win over the skeleton. The file is unlocked, rewritten and locked (`0400`), then printed. (src: L553-L596, L611-L654, L681-L720)
- **SPO-11a-OUT-003** The skeleton supplies `metaName` (the readable asset name, cut to 50 characters online and light; uncut offline), empty `metaDescription`, `metaTicker`, `metaUrl`, `metaLogoPNG`, `metaDecimals: "0"` (online and light only, absent offline), the marker keys `---` and `===`, and `minted: "0"`. (src: L559-L567, L617-L625, L684-L691)
- **SPO-11a-INV-005** `hexname` holds the hex name only when the asset name was given as `{hex}`; for an ASCII name it is the empty string. `name` is the readable name without the leading dot; `subject` is `policyid` plus the hex name; `bechName` is the CIP-14 fingerprint (SPO-Cconv-OUT-013). The asset record file name uses the name as typed, so a hex name keeps its braces: `<policy>.{00010203}.asset`. (src: L58, L177-L178, L555-L556, L583)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<policy>.<asset>.asset` | JSON record, SPO-11a-OUT-002 | `0400` | created or replaced after the chain step |
| `<tempDir>/dummy.txbody`, `<pay>.txbody`, `<pay>.tx`, `<policy>.witness`, `<pay>.witness` | transaction artefacts | default | replaced every run (SPO-Pfiles-OUT-039) |
| `<tempDir>/<pay>.transactionMessage.json` | message metadata | default | created when messages exist |
| `offlineTransfer.json` | queued transaction, history | default | updated, offline only |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than three arguments | 1 | SPO-11a-IF-001 |
| Bad or too long asset name | 1 | SPO-11a-IF-003, SPO-11a-PRE-001 |
| Amount below 1 | 1 | SPO-11a-PRE-002 |
| Policy id or script file missing | 1 | SPO-11a-IN-001 |
| Policy signing key and hwsfile missing | 2 | SPO-11a-IN-001 |
| Payment address or key missing | 1 | SPO-11a-IN-002 |
| Unknown or missing extra-parameter file, bad message | 1 | SPO-11a-IF-004 |
| Policy expired | 2 | SPO-11a-PRE-003 |
| No funds on the paying address | 1 | SPO-Ptx-PRE-001 |
| Change below the minimum output value | 0 | SPO-11a-PRE-004 |
| Declined hardware witness | 2 | SPO-11a-PR-001, SPO-11a-PR-002 |
| Hardware rejected, disconnected, error | 1 | SPO-Ptx-PRE-005 |
| Transaction above `maxTxSize` | 1 | SPO-Ptx-PRE-007 |
| Declined final confirmation | 0 | SPO-Ptx-PR-002 |

## Security

- **SPO-11a-SEC-001** Policy and payment signing keys are decrypted and used in memory only (SPO-Ptx-SEC-001). The only secret that can reach the screen is the `enc:` message passphrase (SPO-Pparam-SEC-001). (src: L379, L476-L482, L510-L516)
- **SPO-11a-SEC-002** Minting authority is exactly the policy key: whoever holds it and any funded address can create tokens under the policy until the policy expires, or forever when it is unlimited (SPO-10-SEC-003). (src: L400, L478)

## Domain mapping

Use case `MintAsset(policy, assetName, amount, payer)` on aggregates `MintingPolicy` (key, script, expiry) and `AssetRecord` (running minted total, registry metadata). Pipeline use cases `BuildAndSignTransaction` and `SubmitOrQueueTransaction` do the shared work.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(MintingPolicy files)`, `get/put(AssetRecord)`, `lock` | Policy files and the asset record |
| `ChainQuery` | `tip()`, `utxos(addr)`, `protocolParameters()` | Pipeline |
| `Ledger` | `buildRaw(txSpec with mint, nativeScript, ttl)`, `minFee`, `minOutputValue`, `assemble`, `txId` | Mint body |
| `Ledger` | `assetFingerprint(policyId, name)` *(new, see Cconv)* | `bechName` |
| `Signer` | `witness(body, policyKey)`, `witness(body, paymentKey)` | Two independent witnesses |
| `Vault` | `unseal(policyKeyRef)`, `unseal(paymentKeyRef)` | In-memory keys |
| `Submitter` / `Transport` | `submit`, `enqueueTx` | Per mode |
| `Directory` | `tokenMetadata(subject)` | Summary display |
| `UI` | `confirm` | Hardware witness and final prompts |

## Port notes

* The policy witness and the payment witness are independent and can come from different parties; a remote or multi-party signer collects them in either order. The policy holder never needs the payment key.
* Update the asset record when the submission is confirmed (or when the queued transaction is executed), not at queue time (SPO-11a-MODE-002).
* Validate the amount against the 64-bit range and require exactly one dot in the reference (SPO-11a-IF-002).
* Exit non-zero on the minimum-output refusal (SPO-Ptx-PRE-002).
* Check that the supplied policy id matches the script's hash instead of trusting the id file (SPO-11a-IN-001).

* **Asset update across the air gap (2026-11-16, hazard H9).** The queue entry of a mint or burn carries one extra field, `spoAssetPending` (a string holding the compact JSON of the asset record update: record, policy, name, delta, validity, action, and the transaction id). Upstream's `execute` and `info` read the entry's fields by name with `jq` and ignore any other key, so the entry still executes with the upstream script; the parity test ignores exactly this field. After a submit the port's `execute` adds the key `spoAssetSubmitted` (the same object with the id of the submitted transaction; again a key upstream's readers ignore) to the `tx submit` history entry, and, once a provider says the transaction is in a block, a history entry of its own with `spoConfirmed` (depth, providers; `spoExpired` for an expired one). `spo asset settle` on the machine that holds the record applies each update once, and only when the history records it confirmed (`--accept-submitted` trusts the submit alone), discards one whose transaction left the queue unsubmitted or is recorded expired, and leaves a still-queued or merely submitted one. The field carries the pending update of any kind (pool registrations and retirements use it too; the name is from the first version). No requirement id changes.

## Open questions

* The extension of an asset name given with uppercase letters (`MyToken`) is hex-encoded from the typed case. Whether the node accepts that is a cardano-cli matter and not tested here.
