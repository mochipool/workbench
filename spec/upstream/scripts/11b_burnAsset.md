+++
id = "11b"
kind = "script"
title = "Burn native tokens under a policy"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["native-assets", "transaction-construction"]
use_cases = ["BurnAsset"]
depends_on = ["Ptx","Pparam","Pfiles","Ptransfer","Cutxo","Cconv","Ckey","Chw","Cui"]

upstream_path = "cardano/mainnet/11b_burnAsset.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "1b53e1d8818f8136cbf3489dedf18a23526b036bbc629a003625d44b7bcc0689"
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

# 11b_burnAsset: Burn native tokens under a policy

Burns a positive amount of one native asset held on the paying address, under the policy that minted it ([10](./10_genPolicy.md)). It is the mirror of [11a](./11a_mintAsset.md): the same pipeline, the same two witnesses (policy key and payment key), the same asset record, with a negative mint amount and a check that the address holds enough tokens. The asset record's running `minted` total goes down.

Follows the Ptx pipeline (SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-010). Where 11b behaves exactly like 11a the requirement below points at the 11a id and cites 11b's own lines; differences are stated in full.

## Interface

- **SPO-11b-IF-001** Takes the same three positional words as 11a (SPO-11a-IF-001): `<policy>.<asset>`, the amount to burn, the paying address name; fewer exit 1 with usage. (src: L20-L26, L27-L53)
- **SPO-11b-IF-002** The asset reference splits at dots exactly as in SPO-11a-IF-002, including its quirk. (src: L23-L24)
- **SPO-11b-IF-003** The asset name rules are those of SPO-11a-IF-003, and a name longer than 32 bytes or an amount below 1 exits 1 (SPO-11a-PRE-001, SPO-11a-PRE-002). (src: L55-L59, L64-L65)
- **SPO-11b-IF-004** Extra parameters follow SPO-11a-IF-004 (metadata files, UTxO list, `msg:`, `enc:`, `pass:`; the sibling `utxolimit:` family is refused as a missing file). The message file is built as in SPO-11a-OUT-001. (src: L79-L169)

## Inputs

- **SPO-11b-IN-001** Required files and exit codes as in SPO-11a-IN-001 and SPO-11a-IN-002: policy id and script (exit 1), policy signing key or hwsfile (exit 2), payment address and key (exit 1). The destination of the change, including the remaining tokens, is the paying address. (src: L21-L22, L68-L75, L194-L195)
- **SPO-11b-IN-002** The paying address is validated (SPO-11a-IN-003) and the same environment and settings are read as in SPO-11a-IN-004. (src: L197, L355, L535)

## Behaviour

1. **Establish the validity window.** Identical to SPO-11a-INV-001 and SPO-11a-PRE-003: TTL is the policy's `before` slot or `tip + defTTL`; a TTL not above the current slot exits 2. An expired time-locked policy therefore can no longer be burned. (src: L182-L190)
2. **Gather inputs.** As SPO-Ptx-MODE-002 .. SPO-Ptx-MODE-004 with the UTxO list filter only. (src: L205-L237)
   - **SPO-11b-PRE-001** Zero UTxOs on the paying address end the script with exit **0** (11a exits 1). (src: L237)
3. **Check the holding.**
   - **SPO-11b-INV-001** The asset totals start with the asset at the **negative** burn amount, then the amounts of that asset on the inputs are added. The assets returned in the change output are those with a total above zero, so burning the whole holding leaves the asset out of the change. (src: L244-L252, L358)
   - **SPO-11b-PRE-002** When the total of the burned asset is below zero, the script refuses ("you can only burn N"), where N is the holding, and exits **0**. An asset the address does not hold at all is refused the same way. The check runs after the protocol parameters are read and before any body is built. (src: L380-L392)
   > **Upstream quirk:** a caller sees success when nothing was burned. A port exits non-zero.
4. **Build, sign, submit.**
   - **SPO-11b-EXT-001** Both bodies are built with `--mint "-<amount> <policyid>[.<hexname>]"`, `--minting-script-file <policy>.policy.script`, `--invalid-hereafter <ttl>` and the metadata files. The witness count is 2 (SPO-Ptx-INV-006). (src: L397, L401, L432)
   - **SPO-11b-PRE-003** A change below the minimum output value exits 0 (SPO-Ptx-PRE-002). (src: L407-L412)
   - **SPO-11b-EXT-002** The hardware canonicalisation, the policy witness then payment witness order, the hardware prompts (default Yes, decline exits 2), the key-file path and the assembly are those of SPO-11a-EXT-002, SPO-11a-EXT-003, SPO-11a-PR-001, SPO-11a-PR-002, SPO-11a-EXT-004 and SPO-11a-INV-004. (src: L439-L446, L452-L520)
   - **SPO-11b-INV-002** Size check, confirmation (`ENV_SKIP_PROMPT=YES` skips it) and the submit or queue branches follow SPO-Ptx-PRE-007, SPO-Ptx-PR-002, SPO-Ptx-PR-003 and SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010. (src: L528-L536, L540-L733)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-11b-INV-004** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the argument parsing of SPO-11b-IF-001 to SPO-11b-IF-004 and the files of SPO-11b-IN-001 and SPO-11b-IN-002. (src: L19-L176, L192-L197)
- **SPO-11b-INV-005** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001) with the policy-bound TTL and the policy-expired refusal, as 11a (SPO-11a-INV-001, SPO-11a-PRE-003, SPO-Ptx-INV-001). (src: L178-L190)
- **SPO-11b-INV-006** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004) with the UTxO-list filter only; zero UTxOs exit 0 (SPO-11b-PRE-001); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002). (src: L203-L237)
- **SPO-11b-INV-007** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005), with the burned asset preloaded at the negative amount (SPO-11b-INV-001). (src: L239-L376)
- **SPO-11b-INV-008** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read after the UTxO stage and followed by the holding check of SPO-11b-PRE-002. (src: L378-L392)
- **SPO-11b-INV-009** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with a negative `--mint`, `--minting-script-file` and witness count 2 (SPO-11b-EXT-001). (src: L386, L394-L403)
- **SPO-11b-INV-010** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with no deposit, and exit 0 when the change is too small (SPO-11b-PRE-003). (src: L405-L412)
- **SPO-11b-INV-011** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee; the witness files are `<tempDir>/<policy>.witness` and `<tempDir>/<pay>.witness`, removed first. (src: L414-L437)
- **SPO-11b-INV-012** Stage 9, sign: as 11a, stage 9 (SPO-11b-EXT-002, SPO-11a-EXT-002 to SPO-11a-EXT-004, SPO-11a-PR-001, SPO-11a-PR-002). (src: L438-L524)
- **SPO-11b-INV-013** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007; SPO-11b-INV-002). (src: L527-L532)
- **SPO-11b-INV-014** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003); `ENV_SKIP_PROMPT=YES` skips it. (src: L534-L538)
- **SPO-11b-INV-015** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010), with the asset-record update after a successful online or light submit and the `Asset-Burning` queue entry offline (SPO-11b-MODE-001, SPO-11b-MODE-002, SPO-11b-OUT-001). (src: L540-L733)

## Work modes

- **SPO-11b-MODE-001** Online and light: the asset record is updated after a successful submit (SPO-11b-OUT-001). (src: L540-L596, L601-L654)
- **SPO-11b-MODE-002** Offline: the transaction is queued with `type` `Asset-Burning` and the history entry `burned <amount> '<input name>' on '<pay name>'`; the asset record is updated at queue time, after the read-back succeeds, with `lastAction` `burn <amount> (only Offline proof)`. A read-back mismatch leaves the record untouched and exits 0. The same provisional-count quirk as SPO-11a-MODE-002 applies. (src: L660-L728)

## Prompts

As SPO-11a-PR-001, SPO-11a-PR-002 and SPO-Ptx-PR-002, with the same defaults. The hardware payment prompt names the policy instead of the payment file; display only. (src: L454, L488, L536)

## Outputs

- **SPO-11b-OUT-001** The asset record `<policy>.<asset>.asset` is created when absent and updated as in SPO-11a-OUT-002 and SPO-11a-OUT-003, except that `minted` becomes the old value **minus** the burned amount (it can go negative when the record was created by a burn or lags reality) and `lastAction` is `burn <amount>`. (src: L554-L593, L613-L652, L679-L718)
- **SPO-11b-OUT-002** Offline, the record file name is built from the converted (hex) asset name, not the name as typed: for an ASCII name `mytoken` the offline burn writes `<policy>.6d79746f6b656e.asset`, while an online or light burn writes `<policy>.mytoken.asset`. The offline record's `metaName` is cut to 50 characters, and its skeleton has no `metaDecimals`. (src: L555, L614, L681, L686-L693)
  > **Upstream quirk:** an offline burn does not update the record that the earlier mint created; it starts a second record with a hex name. A port uses one record name for all modes.
  > **Observed 2026-11-16 (`TestMintBurnMatchUpstream`):** an offline burn of `pol.tok` writes `pol.746f6b.asset` with `minted` `-30` when no record exists; the port files it under `pol.tok.asset` (a `{hex}` name under `pol.hex-<hex>.asset`, braces are not allowed in a store name) and its content, once the submit is reported, equals upstream's apart from `lastUpdate`.
- **SPO-11b-INV-003** `hexname` is set only for a `{hex}` input name (empty otherwise), as in SPO-11a-INV-005. (src: L57, L582, L641, L708)

**Upstream file contract:** as 11a, with `type` `Asset-Burning` in the transfer file and the record rules above.

## Failures

As the 11a table, with these differences:

| Condition | Exit | Id |
| --- | --- | --- |
| No UTxOs on the paying address | 0 | SPO-11b-PRE-001 |
| Burn amount above the holding | 0 | SPO-11b-PRE-002 |
| Change below the minimum output value | 0 | SPO-11b-PRE-003 |
| Policy expired | 2 | SPO-11a-PRE-003 (applied by step 1) |

## Security

- **SPO-11b-SEC-001** Key handling is as SPO-11a-SEC-001: keys are used in memory, and only the `enc:` passphrase can appear on screen. (src: L376, L473-L479, L507-L513)
- **SPO-11b-SEC-002** Burning needs the policy key too: a lost policy key makes the tokens permanently unburnable. (src: L397, L475)

## Domain mapping

Use case `BurnAsset(policy, assetName, amount, payer)` on `MintingPolicy` and `AssetRecord`. Ports as 11a (SPO-11a mapping); in addition `ChainQuery.utxos` result is checked for the holding before building.

## Port notes

* As the 11a port notes. Additionally refuse a burn above the holding with a non-zero exit (SPO-11b-PRE-002) and use a single record name (SPO-11b-OUT-002).
* **Record on confirmation (2026-11-16, hazard H9, port deviation).** The burn follows the 11a port decision: the asset record is not written on an accepted submit or a queueing but as a pending update (`<txid>.pending`) that the wait of `asset burn` (default in light and online mode), `spo tx settle`, or across the air gap `spo asset settle` applies when the transaction is confirmed (SPO-Xconfirm-PR-001, SPO-Xconfirm-PR-012, SPO-Xconfirm-PR-023). This departs from SPO-11b-MODE-001 and SPO-11b-OUT-001, which write it after the submit.
* Burn and mint are the same use case with a signed amount; a port can share the implementation and differ only in the check and the sign.

## Open questions

* None blocking.
