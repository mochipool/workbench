+++
id = "01sendAssets"
kind = "script"
title = "Send native assets (with the lovelaces they need)"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "native-assets", "transaction-construction", "air-gap-transfer"]
use_cases = ["SendAssets"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Caddr", "Cutxo", "Cconv", "Cui", "01sendLovelaces"]

upstream_path = "cardano/mainnet/01_sendAssets.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "5eb3860a552d59fdbacb8a40b649795c098119eb0984ac0439e1120bd66257a6"
upstream_lines = 849
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkAdaHandleFormat",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_assetNameASCII2HEX",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "filterFor_UTXO",
  "generate_UTXO",
  "get_addressType",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
  "readOfflineFile",
  "read_skeyFILE",
  "resolveAdahandle",
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
  "transaction sign",
  "transaction submit",
  "transaction txid",
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

# 01_sendAssets: Send native assets

Sends one or more native-asset selections from a payment address to a destination, together with the lovelaces the destination output needs. It follows the shared transaction pipeline ([Ptx](../patterns/Ptx.md)) with one witness and no attachments, the destination grammar of [01_sendLovelaces](./01_sendLovelaces.md), and the extra-parameter grammar of [Pparam](../patterns/Pparam.md). This spec records what is its own: how an asset is named, the amount forms and bulk selection, how selections are matched against the inputs, and the lovelace and minimum-value handling for a transaction that always has two outputs.

All candidate inputs are spent, as in SPO-Ptx-INV-002. Assets that are not selected return to the source in the change output.

## Interface

- **SPO-01sendAssets-IF-001** Takes at least three positional words: source name, destination, and the asset selection, followed by the amount (see SPO-01sendAssets-IF-004). With fewer than two words it prints a refusal and usage on stderr and exits 1. With two words it refuses the missing asset selection with exit 1. (src: L99, L136, L141, L238)
- **SPO-01sendAssets-IF-002** The destination follows SPO-01sendLovelaces-IF-004 .. SPO-01sendLovelaces-IF-008 (file, literal payment address, ADA Handle). Here the source files are checked first, and the destination second, both before the asset selection is parsed. (src: L100-L134)
- **SPO-01sendAssets-IF-003** The third positional word holds one or more selections separated by `|`. Each selection is split on blanks into an asset reference and an amount. A selection is the pair `<asset> <amount>`, for example `"policy.name 10|asset1... ALL"`. (src: L142-L145)
- **SPO-01sendAssets-IF-004** The amount of a selection is a positive integer or the keyword `ALL` (case-insensitive). Zero is refused with exit 1, any other word is refused with usage and exit 1. The amount may be given in the third word after the asset, or, when there is exactly one selection with only the asset reference, as the separate fourth positional word with the same rules. When a single selection has neither, the script refuses with usage and exit 1. A selection other than the sole one must carry its own amount. (src: L147-L169)
- **SPO-01sendAssets-IF-005** The extra parameters start at the fifth positional word, or at the fourth when the amount was inside the third word (SPO-Pparam-IF-001). The acceptance row of Pparam applies: `msg:`, `enc:`, `pass:`, metadata files, `txhash#index`, `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:`, `keeppolicy:` (SPO-Pparam-IF-023) and a digits-only word. (src: L245-L347)
- **SPO-01sendAssets-IF-006** A digits-only extra word sets the lovelaces to send along with the assets; the last such word wins. It is a request for a minimum: it is raised to the minimum output value when lower (SPO-01sendAssets-OUT-003). The default is 0. (src: L247, L255-L256, L670)
- **SPO-01sendAssets-IF-007** An asset reference is classified by the first matching form, in this order: bech32 fingerprint (IF-008); hex string (IF-009); `policy.name` (IF-010); hex bulk (IF-011); ASCII bulk (IF-012); the keywords `ALLASSETS` and `FORCEADA` (IF-013); an asset file (IF-014). A reference that fits none is refused with usage and exit 1. (src: L176-L222)
- **SPO-01sendAssets-IF-008** A reference of exactly 44 characters that starts with `asset` is a CIP-14 fingerprint. It is checked with the `bech32` tool and refused with usage and exit 1 when invalid. (src: L177-L180)
- **SPO-01sendAssets-IF-009** A reference of 28 to 60 hex byte pairs (56 to 120 hex characters) is policy id followed by the hex asset name (the name may be empty); it is converted to its fingerprint. (src: L186)
- **SPO-01sendAssets-IF-010** A reference `<56 hex>.<name>` with an alphanumeric ASCII name of 1 to 32 characters is a policy id and a text name; it is converted to its fingerprint. (src: L189)
- **SPO-01sendAssets-IF-011** A reference of 28 to 59 hex pairs followed by `*` is a bulk selection of every asset of that policy whose hex name starts with the given hex. It requires the amount `ALL`, otherwise it is refused with exit 1. (src: L193-L195)
- **SPO-01sendAssets-IF-012** A reference `<56 hex>.<prefix>*` with an alphanumeric prefix of 0 to 31 characters is a bulk selection of every asset of that policy whose name starts with the text prefix; `<policy>.*` selects every named asset of the policy. It requires the amount `ALL`, otherwise it is refused with exit 1. (src: L199-L204)
- **SPO-01sendAssets-IF-013** The keywords `ALLASSETS` and `FORCEADA` (case-insensitive) select every asset type found on the inputs and need no amount: the amount is forced to `ALL`. `ALLASSETS` refuses with exit 1 when the inputs hold no asset; `FORCEADA` instead proceeds with a lovelace-only transaction in that case. Assets whose policy id is listed by `keeppolicy:` are excluded from the selection. (src: L148-L149, L207, L517-L520, L555-L558, L572-L580)
- **SPO-01sendAssets-IF-014** Any other reference is taken as the name of an asset file `<ref>.asset` (extension optional, directory allowed; see SPO-Pfiles-OUT-033). The fields read are `policyID`, `name` and `hexname`. The fingerprint is built from `hexname` when it is 1 to 32 bytes of hex, else from `name` when it is purely alphanumeric; otherwise the script refuses with exit 1. (src: L174, L210-L218)
- **SPO-01sendAssets-INV-001** Every selection is reduced to its CIP-14 fingerprint (SPO-Cconv-OUT-013) and matched against the assets of the inputs by fingerprint, not by policy and name. (src: L227-L233, L572)
- **SPO-01sendAssets-INV-002** The same asset named twice is one selection. The amounts are added when the operator agrees (SPO-01sendAssets-PR-001); `ALL` in either entry wins over any number. (src: L227-L233)

> **Upstream quirk (IF-006):** the digits-only word is substituted into shell arithmetic as typed, so a leading zero is octal (see SPO-01sendLovelaces-IF-002).

## Inputs

- **SPO-01sendAssets-IN-001** Reads `<source>.addr`, `<source>.skey` or `<source>.hwsfile` (exit 1 when missing, SPO-Ptx-IN-002), the destination (SPO-01sendAssets-IF-002), any asset files named by the selections, and the Ptx inputs for the source address. (src: L100-L104, L133-L134, L210-L213)

## Behaviour

1. **Parse selections** (IF-003 .. IF-014). Everything is resolved before the chain is touched, except bulk and keyword selections, which need the inputs.
2. **Clock, inputs, assets, parameters.** Ptx stages 2 to 5. The totals are over the candidate inputs after the filters of Pparam, and every availability check below uses only those inputs.
   - **SPO-01sendAssets-PRE-001** A failing UTxO query in online or light mode ends the script with exit status 0 (SPO-01sendLovelaces-PRE-001). (src: L410, L421)
3. **Expand bulk selections.** While scanning the inputs, each asset type found that matches a bulk selection is added as an entry with amount `ALL`.
   - **SPO-01sendAssets-INV-003** A `ALLASSETS` or `FORCEADA` selection adds every asset type of the inputs except those whose policy id occurs in the `keeppolicy:` list, matched as a substring of the list text. (src: L517-L520)
   - **SPO-01sendAssets-INV-004** A bulk selection `policy.prefix*` adds each asset of that policy with a non-empty name that starts with the prefix. Nameless assets are never matched and must be selected one by one. A bulk entry that matched nothing stays in the list under its own key and ends in SPO-01sendAssets-PRE-002. (src: L523-L531, L555)
4. **Check availability.** For each selection in order:
   - **SPO-01sendAssets-PRE-002** Refuses with exit 1 when the asset is not present on the candidate inputs ("no assets available on this address or the selected UTxOs"). (src: L576-L580)
   - **SPO-01sendAssets-INV-005** `ALL` is replaced by the total amount of that asset on the inputs. (src: L583)
   - **SPO-01sendAssets-PRE-003** Refuses with exit 1 when the requested amount exceeds the total on the inputs, naming the available maximum. (src: L585-L589)
   - **SPO-01sendAssets-OUT-001** The send output holds `+<amount> <policy>.<namehex>` per selection. The remainder of each asset, and every asset type not selected, returns to the source when its remaining amount is above zero. (src: L593-L598, L630-L631)
5. **Lovelaces and layout.** Let `S` be the send assets and `Rt` the returned assets.
   - **SPO-01sendAssets-EXT-001** The minimum for the send output is the minimum output value of SPO-Ptx-EXT-003 for `<destination>+1000000<S>`; the minimum for the return output is the same for `<destination>+1000000<Rt>`. (src: L667-L668)
     > **Upstream quirk:** the return minimum is computed with the *destination* address, not the source address. When the two addresses have different sizes (a base address and an enterprise address) the minimum is slightly off. A port uses the return output's own address.
     > **Observed 2026-11-16 (`TestSendAssetsMatchesUpstream`):** with the lovelaces given above the minimum, one asset, several assets of two policies, a hex id, a fingerprint, a nameless asset, both bulk forms, an asset file, `ALLASSETS` (with and without `keeppolicy:`), a message and a metadata file, and an explicit input list, the queued transaction of upstream and the port are byte-equal. Where the send rests on the minimum (no lovelace word, or one below it) the destination holds `2 * utxoCostPerByte` lovelace more upstream than in the port, the map-form over-estimate of SPO-Cutxo-INV-007, and the change that much less; the fee is equal.
   - **SPO-01sendAssets-OUT-003** The destination output holds `max(L, min_send)` lovelaces and `S`, where `L` is the lovelace amount of IF-006. (src: L670, L676, L707)
   - **SPO-01sendAssets-OUT-004** The change output goes to the source and holds `total - fee - sent` lovelaces and `Rt`. There are always two outputs, in the order destination, change, even when nothing remains to return. (src: L656, L693, L707)
   - **SPO-01sendAssets-EXT-002** The dummy body has the same two outputs with `total - sent` as the change amount and fee 200000; the witness count is 1 (SPO-Ptx-INV-006). (src: L675-L682)
   - **SPO-01sendAssets-PRE-004** Refuses with exit 1 when the change output holds fewer lovelaces than the return minimum. A request for more lovelaces than the inputs can carry ends here. (src: L693-L695)
6. **Sign, size, confirm, submit.** As Ptx.
   - **SPO-01sendAssets-EXT-003** On the hardware path the change keys are declared whenever the file `<source basename without ".payment">.staking.hwsfile` exists, looked up relative to the working directory: the directory part of the source name is dropped. When it exists both `<source>.hwsfile` and that file are passed as `--change-output-key-file`. (src: L717-L742)
     > **Upstream quirk:** `01_sendLovelaces` keeps the directory part; here a source name with a directory does not find its staking file, and the device then shows the change as an unknown output.

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-01sendAssets-INV-006** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the selection grammar of SPO-01sendAssets-IF-001 to SPO-01sendAssets-IF-014 and SPO-01sendAssets-IN-001; the usage text is display only. (src: L19-L383)
- **SPO-01sendAssets-INV-007** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001): TTL = slot + `defTTL`. (src: L388-L389)
- **SPO-01sendAssets-INV-008** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002); the failing-query exit status is SPO-01sendAssets-PRE-001. (src: L399-L440)
- **SPO-01sendAssets-INV-009** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005), then the selection expansion and availability checks SPO-01sendAssets-INV-003 to SPO-01sendAssets-PRE-003; the return string `Rt` is SPO-01sendAssets-OUT-001. (src: L442-L632)
- **SPO-01sendAssets-INV-010** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006). (src: L658-L662)
- **SPO-01sendAssets-INV-011** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with witness count 1; the dummy body is SPO-01sendAssets-EXT-002. (src: L672-L684)
- **SPO-01sendAssets-INV-012** Stage 7, balance: as Ptx (SPO-Ptx-EXT-003, SPO-Ptx-PRE-002, SPO-Ptx-PRE-003) with the layout SPO-01sendAssets-OUT-003, SPO-01sendAssets-OUT-004 and the minimums and refusal of SPO-01sendAssets-EXT-001 and SPO-01sendAssets-PRE-004 (exit 1). (src: L653-L670, L686-L699)
- **SPO-01sendAssets-INV-013** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003): any earlier body is removed first and a build failure ends the script with cardano-cli's code. (src: L701-L711)
- **SPO-01sendAssets-INV-014** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-SEC-001); the change-output declaration is SPO-01sendAssets-EXT-003. (src: L713-L777)
- **SPO-01sendAssets-INV-015** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007), exit 1. (src: L779-L786)
- **SPO-01sendAssets-INV-016** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003), honouring `ENV_SKIP_PROMPT` (SPO-01sendAssets-PR-002). (src: L789-L791)
- **SPO-01sendAssets-INV-017** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010); the offline entry is SPO-01sendAssets-OUT-002. (src: L793-L835)

## Work modes

Per Ptx. The ADA Handle restriction and the offline filter rules of SPO-01sendLovelaces-MODE-001 and SPO-01sendLovelaces-MODE-002 apply unchanged. (src: L404-L437)

## Prompts

- **SPO-01sendAssets-PR-001** When the same asset appears in more than one selection, asks "do you want to sum the amount up?" with default **No**. A refusal ends the script with exit 1. (src: L227-L231)
- **SPO-01sendAssets-PR-002** The confirmation of SPO-Ptx-PR-002 (default No) is asked after the size check and honours `ENV_SKIP_PROMPT`. (src: L789-L791)

| Prompt | Default | Effect |
| --- | --- | --- |
| Sum up the duplicated asset (SPO-01sendAssets-PR-001) | No | No exits 1 |
| Does this look good, continue? (SPO-01sendAssets-PR-002) | No | No ends with exit 0, nothing sent |

## Outputs

- **SPO-01sendAssets-OUT-002** Offline, the signed transaction is appended to `transactions[]` with `type` `Transaction` and the same fields as SPO-01sendLovelaces-OUT-007. The history entry reads "generated and signed utxo-token-transaction from '<from>' to '<to>'". The common mutations are SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012. (src: L817-L831)

The upstream file contract is that of SPO-01sendLovelaces (the temporary files `tempTo.addr`, `adahandle-resolve.addr`, `<source>.transactionMessage.json`, `dummy.txbody`, `<source>.txbody`, `.txwitness`, `.tx` in the temp directory). The script reads asset files and writes no other file.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two or three positional words | 1 | SPO-01sendAssets-IF-001 |
| Invalid amount, bulk without `ALL`, unresolvable asset | 1 | SPO-01sendAssets-IF-004, SPO-01sendAssets-IF-007 .. SPO-01sendAssets-IF-014 |
| Duplicated asset not summed | 1 | SPO-01sendAssets-PR-001 |
| UTxO query fails (online, light) | **0** | SPO-01sendAssets-PRE-001 |
| Asset absent from the inputs (also an unmatched bulk, `ALLASSETS` without assets) | 1 | SPO-01sendAssets-PRE-002 |
| Amount above what the inputs hold | 1 | SPO-01sendAssets-PRE-003 |
| Change below the return minimum | 1 | SPO-01sendAssets-PRE-004 |
| Others | | as SPO-Ptx table "Failures" |

## Security

- **SPO-01sendAssets-SEC-001** The destination file-name hazard of SPO-01sendLovelaces-SEC-001 applies: the destination travels through `<tempDir>/tempTo.addr` or `adahandle-resolve.addr`. (src: L113, L125, L133)
- **SPO-01sendAssets-SEC-002** `ENV_SKIP_PROMPT=YES` skips the confirmation (SPO-Ptx-SEC-003). Sending an NFT to a wrong destination is irreversible. (src: L791)

## Domain mapping

Use case `SendAssets(source, destination, selections, lovelaces?, extras)` on the `PaymentAccount` aggregate, with a `Selection` value object (`Asset(fingerprint) | Bulk(policy, prefix) | AllAssets(keep) | ForceAda`, plus `Amount = Quantity(n) | All`). It produces a `TxDraft` for the shared pipeline.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(Address)`, `get(AssetRecord)` | Address files, `.asset` files |
| `Ledger` | `assetFingerprint(policy, name)` | CIP-14 matching (SPO-Cconv-OUT-013) |
| `Ledger` | `validateFingerprint(text)` *(new)* | Check a `asset1...` reference (the `bech32` tool upstream) |
| `Directory` | `resolveHandle(handle)` | ADA Handle destination |
| `ChainQuery` | `utxos`, `protocolParameters` | Inputs |
| `Ledger` | `minOutputValue`, `minFee`, `buildRaw`, `assemble` | Layout |
| `Signer`, `Submitter`, `Transport`, `UI` | as Ptx | |

## Port notes

* Parse selections into a typed list first, then expand bulk entries against the inputs; reject an unmatched bulk entry explicitly rather than through the "asset not found" path.
* Compute the return minimum from the source address and the send minimum from the destination (SPO-01sendAssets-EXT-001 quirk), and keep the directory part when looking for the staking hardware file (SPO-01sendAssets-EXT-003 quirk).
* Allow an explicit "lovelaces to send" without silently raising it; surface the raise as a warning.
* A port may match the bulk prefix on the real asset name bytes instead of the greedy text match noted in Open questions.

## Open questions

* The bulk expansion (L524-L530) matches the bulk key with `=~ <policy>\.(.*)-BULK` over the whole selection document. With two bulk selections the greedy `(.*)` can span both, and the prefix then fails to match. Whether this loses the second selection depends on how the selection text is serialised (single line or several); a test with two bulk selections of different policies settles it.
* The effect of `FORCEADA` when it is not the last selection: the script tests the loop variable `assetToSend`, which holds the last selection parsed (L558), so a `FORCEADA` selection followed by another selection may behave as `ALLASSETS`. A test settles it.
