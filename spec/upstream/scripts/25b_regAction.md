+++
id = "25b"
kind = "script"
title = "Submit governance actions"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "transaction-construction"]
use_cases = ["SubmitGovernanceActions"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cconf", "Cchain", "Clight", "Caddr", "Cutxo", "Cconv", "Coffline", "Ckey", "Cui", "Chw", "Ctx"]

upstream_path = "cardano/mainnet/25b_regAction.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "087fae298f192aa01db38ac403227f12c33eed553e5594fc146d252e28afa0a7"
upstream_lines = 981
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_actionUTXO2Bech",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "generate_UTXO",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
  "queryLight_stakeAddressInfo",
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
  "governance action view",
  "query constitution",
  "query protocol-parameters",
  "query stake-address-info",
  "query utxo",
  "transaction assemble",
  "transaction build-raw",
  "transaction calculate-min-fee",
  "transaction calculate-plutus-script-cost offline",
  "transaction calculate-plutus-script-cost online",
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

# 25b_regAction: Submit governance actions

Submits one or more governance proposals, built earlier by [25a](./25a_genAction.md) as `.action` files, in a single transaction paid from one payment address. The transaction spends all UTxOs of the payer, pays the sum of the action deposits and the fee, and returns the rest to the payer. Each proposal's deposit comes back to the return address recorded in its `.action` file.

The script follows the shared transaction pipeline (see SPO-Ptx-IF-001 .. SPO-Ptx-MODE-010 and Table A of [Ptx](../patterns/Ptx.md)) with the variations below. Two kinds of action need a Plutus script: when the constitution names a **guardrails script**, a `TreasuryWithdrawals` or `ParameterChange` proposal must carry that script's witness. The pipeline then gains a *guardrail variant*: the local `guardrails-script.plutus` is attached as proposal script, a pure-lovelace UTxO of the payer is set aside as **collateral**, the script's execution units are computed with `cardano-cli`, the local script hash is compared with the constitution's, and the fee is estimated with the script cost. Everything else is the plain pipeline.

Summary of the variations from the plain pipeline:

| Aspect | Plain pipeline | 25b |
| --- | --- | --- |
| Hardware payer | supported | refused (SPO-25b-PRE-002) |
| UTxO filters (`utxolimit:` etc.) | applied | recognised, ignored (SPO-25b-IF-003) |
| TTL | `defTTL` (100000 slots) | fixed 25000 slots (SPO-25b-INV-003) |
| Attachment | per script | `--proposal-file` per action, deposit sum (SPO-25b-INV-001) |
| Witness count for the fee | per script | 1; 2 in the guardrail variant (SPO-25b-EXT-007) |
| Collateral, script, cost | none | guardrail variant only (SPO-25b-EXT-001 .. SPO-25b-EXT-007) |
| Offline `type` | per script | `Transaction` |

## Interface

- **SPO-25b-IF-001** Takes at least two positional words: the paying address, then extra words from the second word on (SPO-Pparam-IF-001). With fewer than two words it prints usage on stderr and exits 1. (src: L21-L58, L91-L96)
  > **Upstream quirk:** the usage text is a leftover of `24b` (it talks about votes and DRep keys); the script takes `.action` files.
- **SPO-25b-IF-002** The paying address is `<name>` or `<name>.addr`, with an optional directory part (SPO-Pfiles-IN-001). (src: L70)
- **SPO-25b-IF-003** The extra words are classified as in SPO-Pparam-IF-003 with the `25b` row of the acceptance table: `msg:`, `enc:` and `pass:` take effect; `.json` and `.cbor` metadata files take effect (SPO-Pparam-IF-014, SPO-Pparam-IF-015); the UTxO list, `utxolimit:`, `skiputxowithasset:` and `onlyutxowithasset:` are recognised and ignored (SPO-Pparam-IF-007), so **every UTxO of the payer is an input**; purely numeric words are ignored. Any other word is a file word and refused with exit 1 when it does not exist or its extension is not `json`, `cbor` or `action` (SPO-Pparam-PRE-005). (src: L99-L113, L366, L370-L399)
- **SPO-25b-IF-004** A file word whose extension is `action` (any letter case) and which exists is an action file (SPO-Pparam-IF-017). Any number may be given, in any position among the other words. The order of the action files decides the order of the proposals in the transaction body, and with it the action index of each proposal (SPO-25b-OUT-002). (src: L115-L120, L359-L362)
- **SPO-25b-IF-005** An action file is not required: with no `.action` word at all the script still runs and, with a total deposit of 0, builds, asks about and submits a plain transaction that pays the fee and returns everything to the payer. (src: L88, L403, L764-L771, L785)
  > **Upstream quirk:** the only requirement is the second word of SPO-25b-IF-001, which may be a message. A port refuses an empty action list.
- **SPO-25b-IF-006** The same action file given twice is refused with exit 1. The test is a substring test of the new file name against the text of the files collected so far, so a name that is a suffix or other substring of an earlier file's name (`a.action` after `xa.action`) is wrongly refused too. (src: L357-L358)

## Inputs

- **SPO-25b-IN-001** Reads `<pay>.addr` (checked with `check_address`, SPO-Caddr-PRE-001) and `<pay>.skey` (plaintext or encrypted, see SPO-Ckey-OUT-001), both required. (src: L76-L77, L473, L867)
- **SPO-25b-IN-002** From each action file, via `cardano-cli <era> governance action view --output-json --action-file <file>` (stderr discarded), it reads: `governance action.tag`, `governance action.contents`, `deposit`, `anchor.url`, `anchor.dataHash`, `return address.credential.keyHash` and `return address.network`. (src: L118, L201-L208)
- **SPO-25b-IN-003** For treasury withdrawals it reads from `contents` the first withdrawal's amount (`.[0][0][1]`) and receiving credential (`.[0][0][0].credential.keyHash`). Further withdrawals in one action are neither shown nor checked. (src: L267)
- **SPO-25b-IN-004** The guardrails script file named by the setting `guardrailsScriptFile` (default `./guardrails-script.plutus`; see Cconf and SPO-Pfiles-IN-004), read only in the guardrail variant. (src: L669, L692)
- **SPO-25b-IN-005** From the protocol parameters document: `protocolVersion.major`, `maxTxSize`, and the whole document as the protocol-parameters file of cardano-cli; in the guardrail variant offline and in light mode also `eraHistory` and `constitution.script`. (src: L458, L710-L712, L887)
- **SPO-25b-IN-006** Settings and environment read: those of SPO-Ptx-IN-003 (`defTTL` excepted, SPO-25b-INV-003), `genesisfile_byron` (guardrail variant in light and offline mode), `tokenMetaServer`, and `ENV_SKIP_PROMPT`. (src: L625, L716, L893)

## Behaviour

1. **Gates** (SPO-25b-PRE-001 .. SPO-25b-PRE-003).
   - **SPO-25b-PRE-001** When the configured era is `shelley`, `allegra`, `mary`, `alonzo` or `babbage` it prints a notice and **exits 0**. (src: L61-L65)
   - **SPO-25b-PRE-002** When `<pay>.hwsfile` exists the script is refused with exit 1: a hardware wallet cannot pay for or sign a governance action proposal. This is checked before the existence of `<pay>.addr`. (src: L72-L73)
     > **Upstream quirk:** the hardware signing branch of the script (src: L836-L862) can therefore never run; it is dead code, and SPO-Ptx-EXT-005 does not apply to `25b`.
   - **SPO-25b-PRE-003** A missing `<pay>.addr` or `<pay>.skey` is refused with exit 1 before any query. (src: L76-L77)
2. **Read and check each action file** in the order given. All refusals exit 1 unless stated.
   - **SPO-25b-PRE-004** An action file that `governance action view` cannot read is refused. (src: L118-L119)
   - **SPO-25b-PRE-005** An action file without a `deposit` is refused. The deposit is the one stored in the file; it is **not** compared with the chain's current `govActionDeposit`. (src: L203, L220-L225)
   - **SPO-25b-PRE-006** The deposit-return stake address is rebuilt from the file as a **key-hash** stake address: `stake` plus `e1<keyHash>` for network `Mainnet`, `stake_test` plus `e0<keyHash>` for `Testnet` (case-insensitive), by the `bech32` binary. An action whose return credential is a script (no `keyHash`) or whose network is neither value is refused. (src: L227-L240)
   - **SPO-25b-PRE-007** *Online and light.* The return address must be registered as a stake address on chain (node `query stake-address-info --address <addr>`, or `queryLight_stakeAddressInfo`; registered means a non-empty answer): an unregistered address is refused with exit 1 and a pointer to `03b`. A **failure of the query itself** prints the error and exits with status **0**. *Offline:* the check is skipped. (src: L244-L259)
     > **Upstream quirk:** `exit $?` follows an `echo`, so a failed registration query reports success. A port exits non-zero.
   - **SPO-25b-PRE-008** A `TreasuryWithdrawals` action whose receiving credential is not a key hash (a script credential) is refused: the receiving address is rebuilt like SPO-25b-PRE-006 and fails on the missing hash. The registration of the receiving stake address is not checked. The receiving stake address is rebuilt with the network of the **deposit-return** address (`mainnet` gives `e1` and `stake`, `testnet` gives `e0` and `stake_test`), not with a network of the withdrawal target; the `case` has no default branch, so another network value leaves the address empty. (src: L265-L278)
   - **SPO-25b-PRE-009** For each action the tag, anchor, deposit, return address and the type-specific content (receiving address and amount, previous-action id, new constitution anchor, fork version, changed parameters, committee changes and threshold) are shown for the operator's review; this is display only. (src: L212-L354)
   - **SPO-25b-INV-001** Per accepted action file `--proposal-file <file>` is added to the body arguments, the action counter grows by one and the file's deposit is added to the deposit total. (src: L359-L362)
   - **SPO-25b-INV-002** The tag of the **last** action file read decides the variant of the whole transaction (SPO-25b-INV-005). (src: L201, L664, L803)
3. **Messages and metadata.** Message lines, `enc:basic` and `pass:` are handled as in SPO-Pparam-IF-008 .. SPO-Pparam-OUT-002; an `enc:` mode other than `basic` is refused with exit 1 (SPO-Pparam-PRE-003) and `enc:basic` without `openssl` with exit 2 (SPO-Pparam-PRE-004). The message file is `<tempDir>/<pay>.transactionMessage.json`. (src: L370-L436)
4. **Protocol parameters and era.** Per work mode as in SPO-Ptx-MODE-006, before the UTxO query.
   - **SPO-25b-PRE-010** A protocol major version below 9 is refused with exit 1: the chain does not support governance actions. (src: L457-L460)
5. **Clock.**
   - **SPO-25b-INV-003** The validity end is `tip + 25000` slots, a constant of the script that replaces the configured `defTTL` (SPO-Ptx-INV-001, SPO-Cconf-INV-009). The comment gives the reason: on fast test networks the maximum TTL of a transaction carrying a Plutus script is 25920 slots. The constant applies to all variants. (src: L463-L467)
6. **Inputs.** As SPO-Ptx-MODE-002 .. SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002 and SPO-Ptx-INV-003, with these differences:
   - **SPO-25b-INV-004** All UTxOs of the payer are spent, with no filter or limit (SPO-25b-IF-003). The change returns to the payer's own address (`sendToAddr = sendFromAddr`), a single output holding all assets (SPO-Ptx-INV-004). (src: L471-L474, L509-L510, L597)
   - **SPO-25b-PRE-011** *Online and light.* A failed UTxO query prints the error and exits with status **0**. (src: L490-L491, L497-L498)
7. **Select a collateral UTxO** (every variant; used only by the guardrail variant).
   - **SPO-25b-INV-005** The collateral candidate is the **first** UTxO, in the order of the UTxO set, that carries no native assets and holds between 5000000 and 10000000 lovelaces inclusive. If there is none, no collateral is set. (src: L520-L521, L542)
8. **Choose the variant.**
   - **SPO-25b-INV-006** *Guardrail variant* when the tag of the last action file (SPO-25b-INV-002), lower-cased, is `treasurywithdrawals` or `parameterchange`; *plain variant* otherwise, including when there is no action file. The tag of earlier files is not considered: a `ParameterChange` followed by an `InfoAction` gets no guardrails script, and an `InfoAction` followed by a `ParameterChange` gets one for the whole transaction. (src: L664-L666, L762, L803-L805, L822)
     > **Upstream quirk:** the variant should depend on whether **any** action needs the guardrails script.
9. **Guardrail variant: preparation** (src: L666-L685).
   - **SPO-25b-PRE-012** The guardrails script file must exist, otherwise exit 1 with a hint to download it and set `guardrailsScriptFile`. (src: L669)
   - **SPO-25b-PRE-013** A collateral UTxO must exist (SPO-25b-INV-005), otherwise exit 1 with the request to send 5 to 10 ADA to the payer address. (src: L672-L676)
   - **SPO-25b-INV-007** The collateral UTxO is **not an input**: its `--tx-in` is removed from the input list by textual substitution, its lovelaces are subtracted from the total before the output is computed, and the displayed input count drops by one. It is named with `--tx-in-collateral`. Its value is therefore neither spent nor returned in the change output; it stays on the payer address as an unspent output (unless the script fails, SPO-25b-SEC-001). (src: L679-L685, L690)
     > **Upstream quirk:** the substitution `s/--tx-in <utxo>//g` also matches the front of another input of the same transaction whose index starts with the collateral's index (`<tx>#1` and `<tx>#10`), leaving a stray digit in the argument list. A port removes the entry from a list.
10. **Guardrail variant: script cost and hash check.**
    - **SPO-25b-EXT-001** A first body is built into `<tempDir>/dummy.txbody` with `cardano-cli <era> transaction build-raw`: the inputs (collateral excluded), `--tx-in-collateral <utxo>`, one `--tx-out <payer>+<total lovelaces minus collateral><assets>`, `--proposal-script-file <guardrails file>`, `--proposal-redeemer-value {}` (the literal JSON `{}`), `--proposal-execution-units "(0,0)"`, `--protocol-params-file <params>`, `--invalid-hereafter <ttl>`, `--fee 200000`, the metadata arguments and the `--proposal-file` arguments. A failure ends the script with `cardano-cli`'s exit code. (src: L688-L698)
    - **SPO-25b-EXT-002** *Online.* The execution units come from `cardano-cli <era> transaction calculate-plutus-script-cost online --tx-file <dummy> --out-file /dev/stdout` (stderr merged into the result); a failure is refused with exit 1. (src: L703-L704)
    - **SPO-25b-EXT-003** *Light and offline.* The execution units come from `cardano-cli <era> transaction calculate-plutus-script-cost offline --unsafe-extend-safe-zone --genesis-file <Byron genesis> --era-history-file <eraHistory of the params> --protocol-params-file <params> --utxo-file <the payer's UTxO JSON, with quoted integer values turned into numbers> --tx-file <dummy> --out-file /dev/stdout`. A failure is refused with exit 1. When the parameters document has no `eraHistory` the script prints a message and **exits 0**. (src: L709-L723)
    - **SPO-25b-EXT-004** The constitution's guardrails script hash: *online* from `cardano-cli <era> query constitution` at `.script` (stderr merged); *light and offline* from `.constitution.script` of the protocol parameters document, `{}` when absent. (src: L705-L706, L712)
      > **Upstream quirk:** the intended "no constitution in the document" refusal (src: L713) tests a variable that is never set and can never fire; a missing constitution surfaces as the hash mismatch of SPO-25b-PRE-014.
    - **SPO-25b-INV-008** The execution units used are the `steps` and `memory` of the **first** entry of the cost result, written `"(<steps>, <memory>)"`. The local script hash is the `scriptHash` of the same first entry. The cost result is shown. (src: L726-L732)
    - **SPO-25b-PRE-014** When the local script hash differs from the constitution's hash the script prints the two hashes and exits with status **0**, without building anything. This also happens when the constitution has no script (online: the text `null`; offline and light: `{}`), so a treasury withdrawal or parameter change cannot be submitted by this script against a constitution without a guardrails script. (src: L731-L733)
      > **Upstream quirk:** a refusal that exits 0, so a wrapper sees success. A port exits non-zero.
11. **Fee.**
    - **SPO-25b-EXT-005** *Guardrail variant.* A second dummy body is built like SPO-25b-EXT-001 with the real execution units instead of `(0,0)`; its fee is then `cardano-cli <era> transaction calculate-min-fee --output-text --tx-body-file <dummy> --protocol-params-file <params> --witness-count 2 --reference-script-size 0`, the first word of the output. A failure of the build or of the fee call ends the script with `cardano-cli`'s exit code. (src: L735-L757)
    - **SPO-25b-EXT-006** *Plain variant.* One dummy body is built with `build-raw` from the inputs, one `--tx-out <payer>+<total lovelaces><assets>`, `--invalid-hereafter`, `--fee 200000`, the metadata arguments and the `--proposal-file` arguments, and the fee comes from `calculate-min-fee` with `--witness-count 1 --reference-script-size 0`. A build failure ends the script with `cardano-cli`'s code; a fee failure with exit 1. (src: L762-L771)
    - **SPO-25b-EXT-007** The witness count is a constant per variant (SPO-Ptx-INV-006): 1 for plain, 2 for guardrail. The guardrail transaction carries one key witness (the payment key signs spending and collateral), so the guardrail fee is over-estimated by one witness. (src: L752, L767, L872)
    - **SPO-25b-INV-009** The change output holds `total lovelaces (minus collateral in the guardrail variant) − fee − sum of the action deposits`, plus all assets. The refusal rule is SPO-Ptx-PRE-002: when the change is below the minimum output value (SPO-Ptx-EXT-003) the script prints the minimum and exits with status **0**. (src: L657, L776, L785, L791)
12. **Final body** (the `Ptx` stage 8).
    - **SPO-25b-EXT-008** The final body is built into `<tempDir>/<pay>.txbody` with the same arguments as the dummy body of the variant (SPO-25b-EXT-005, SPO-25b-EXT-006), but with the change amount of SPO-25b-INV-009 and the real fee. The guardrail variant uses the real execution units. A failure ends the script with `cardano-cli`'s exit code. (src: L793-L831)
13. **Sign.**
    - **SPO-25b-EXT-009** The payment key is read into memory and the body signed with `cardano-cli <era> transaction sign --tx-body-file <body> --signing-key-file <(key) --out-file <tempDir>/<pay>.tx` (SPO-Ptx-EXT-006). A key read failure is refused with exit 1. The stale `<tempDir>/<pay>.txwitness` is deleted at the start. (src: L794, L864-L878)
    - **SPO-25b-PRE-015** A signed transaction larger than `maxTxSize` is refused with exit 1 (SPO-Ptx-PRE-007). (src: L884-L889)
14. **Confirm, then submit or queue.**
    - **SPO-25b-PR-001** The prompt of SPO-Ptx-PR-002 (default No; a refusal ends with exit 0 and nothing submitted) is skipped when `ENV_SKIP_PROMPT` equals `YES` (SPO-Ptx-PR-003). (src: L893)
    - **SPO-25b-OUT-001** *Online and offline.* After a successful submit (online) or after the transaction is signed (offline, before it is queued), the transaction id is read with `cardano-cli <era> transaction txid --output-text --tx-file <tx>`; the failure of that read ends the script with its code. (src: L906-L907, L942-L943)
    - **SPO-25b-OUT-006** *Light.* The transaction id is the value returned by `submitLight` (SPO-Ptx-MODE-009); `transaction txid` is not called. (src: L920-L923)
    - **SPO-25b-OUT-002** For `i` from 0 to the number of accepted action files minus one the script prints two forms of the action id: the legacy `<txid>#<i>` and the CIP-129 id from `convert_actionUTXO2Bech` (SPO-Cconv-OUT-017). The index `i` is the position of the action file among the accepted ones, in command-line order. Offline the ids are announced as "will be". (src: L909-L914, L927-L932, L945-L950)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-25b-INV-010** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the gates, action-file checks and message handling of SPO-25b-PRE-001 to SPO-25b-PRE-009, SPO-25b-IN-001 and steps 1 to 3 above. A hardware payment wallet is refused (SPO-25b-PRE-002). (src: L19-L436, L87, L210)
- **SPO-25b-INV-011** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001), with the fixed 25000-slot TTL of SPO-25b-INV-003. (src: L463-L467)
- **SPO-25b-INV-012** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001) with no filters (SPO-25b-INV-004); a failing online or light UTxO query exits 0 (SPO-25b-PRE-011). (src: L469-L510)
- **SPO-25b-INV-013** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005), and in the same pass the first pure-lovelace UTxO of 5 to 10 ADA is remembered as collateral candidate (SPO-25b-INV-005). (src: L512-L651)
- **SPO-25b-INV-014** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read before the UTxO stage, with the protocol-major check of SPO-25b-PRE-010. (src: L438-L460)
- **SPO-25b-INV-015** Stage 6, dummy body and fee: the Ptx form in the plain variant (SPO-25b-EXT-006, witness count 1). In the guardrail variant a first dummy body with execution units (0,0), the script-cost call, the constitution hash comparison and a second dummy body precede the fee call (SPO-25b-INV-006, SPO-25b-INV-007, SPO-25b-EXT-001 to SPO-25b-EXT-005, SPO-25b-PRE-012 to SPO-25b-PRE-014, witness count 2, SPO-25b-EXT-007). (src: L657-L774)
- **SPO-25b-INV-016** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with the deposits of all actions subtracted, the guardrail collateral excluded, and exit 0 when the change is too small (SPO-25b-INV-009). (src: L776-L791)
- **SPO-25b-INV-017** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004) with the variant's arguments and the real fee (SPO-25b-EXT-008). (src: L793-L833)
- **SPO-25b-INV-018** Stage 9, sign: key-file signing only, as Ptx (SPO-Ptx-EXT-006, SPO-Ptx-SEC-001; SPO-25b-EXT-009). The hardware branch is unreachable because a hardware payment wallet was refused at the start (SPO-25b-PRE-002). (src: L836-L878)
- **SPO-25b-INV-019** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007; SPO-25b-PRE-015). (src: L884-L889)
- **SPO-25b-INV-020** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003; SPO-25b-PR-001). (src: L891-L895)
- **SPO-25b-INV-021** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010) per SPO-25b-MODE-001 to SPO-25b-MODE-003, and the action ids are shown (SPO-25b-OUT-001, SPO-25b-OUT-002, SPO-25b-OUT-006). (src: L897-L952)

## Work modes

- **SPO-25b-MODE-001** *Online.* Requires the node to be synced (exit 1 otherwise, SPO-Ptx-MODE-002), queries the UTxOs of the payer, the return address registration (SPO-25b-PRE-007), and in the guardrail variant the execution units and the constitution hash from the node (SPO-25b-EXT-002, SPO-25b-EXT-004). The transaction is submitted with `cardano-cli <era> transaction submit --tx-file <tx>`; a submit failure ends the script with the code of `checkError`. A link to the explorer is shown when `transactionExplorer` is set. (src: L486-L494, L898-L918)
- **SPO-25b-MODE-002** *Light.* UTxOs and the registration come from Koios (`queryLight_UTXO`, `queryLight_stakeAddressInfo`); the parameters, the era history and the constitution from the Light-Mode parameters document; the execution units from the offline calculator (SPO-25b-EXT-003), which needs the local Byron genesis file. The transaction is submitted with `submitLight`; a failure prints the error and exits with status **0** (SPO-Ptx-MODE-009). (src: L446-L448, L496-L501, L709-L723, L920-L936)
- **SPO-25b-MODE-003** *Offline.* Parameters, era history, constitution and the payer's UTxOs come from the transfer file (SPO-Ptx-MODE-004, SPO-Ptransfer-IN-001); the payer address missing from it is refused with exit 1; the registration check is skipped (SPO-25b-PRE-007); execution units come from the offline calculator. The signed transaction is not submitted but appended to `transactions[]` of the transfer file with `type` `Transaction`, `toAddr` = `fromAddr` = the payer name and `sendToAddr` = `sendFromAddr` = the payer address, a history entry `signed utxo-transaction from '<pay>' to '<pay>'`, `general.offlineCLI`, and the read-back of SPO-Ptransfer-OUT-012 (SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-011; src: L939-L974). A guardrail transaction queued offline contains the execution units computed from the snapshot's UTxOs and constitution; its validity depends on that snapshot being current when it is executed. (src: L450-L453, L503-L506, L709-L723)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| "Does this look good for you, continue?" (SPO-25b-PR-001) | No | Yes: submit or queue; No: exit 0, nothing happens |

`ENV_SKIP_PROMPT=YES` answers it. There is no other prompt: no hardware confirmation, no unrestricted-mode question.

## Outputs

- **SPO-25b-OUT-003** The only persistent effects are the submitted (or queued) transaction and the scratch files. The `.action` files, the wallet files and all other workspace files are never changed. (src: L793-L801, L898-L974)
- **SPO-25b-OUT-004** Scratch files in the temp directory, all replaced on every run and never deleted (SPO-Pfiles-OUT-039): `dummy.txbody`, `<pay>.txbody`, `<pay>.tx`, and `<pay>.transactionMessage.json` when messages were given. The body and the signed transaction are printed, cropped to 4000 characters when `cropTxOutput` is on (display only). (src: L410, L660-L661, L793-L795, L833, L881)
- **SPO-25b-OUT-005** The transfer file in offline mode, as SPO-25b-MODE-003. (src: L953-L965)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<tempDir>/dummy.txbody` | dummy body for the fee (and, in the guardrail variant, for the script cost) | default | replaced |
| `<tempDir>/<pay>.txbody` | final unsigned body, with `--proposal-file`s | default | replaced |
| `<tempDir>/<pay>.tx` | signed transaction | default | replaced |
| `<tempDir>/<pay>.transactionMessage.json` | CIP-20 or CIP-83 message metadata | default | replaced when messages exist |
| `offlineTransfer.json` | appended `Transaction` entry | not managed | updated (offline only) |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two words | 1 | SPO-25b-IF-001 |
| Era before Conway | **0** | SPO-25b-PRE-001 |
| Hardware payer | 1 | SPO-25b-PRE-002 |
| `<pay>.addr` or `<pay>.skey` missing | 1 | SPO-25b-PRE-003 |
| Unknown, non-existing or wrong-extension file word | 1 | SPO-25b-IF-003 |
| Duplicate action file | 1 | SPO-25b-IF-006 |
| Action file unreadable, no deposit | 1 | SPO-25b-PRE-004, SPO-25b-PRE-005 |
| Return address not derivable (script credential, unknown network) | 1 | SPO-25b-PRE-006 |
| Treasury receiver not a key hash | 1 | SPO-25b-PRE-008 |
| Return address not registered | 1 | SPO-25b-PRE-007 |
| Registration query fails (online, light) | **0** | SPO-25b-PRE-007 |
| Message or `enc:` errors | 1 (2 without `openssl`) | SPO-Pparam-PRE-001 .. SPO-Pparam-PRE-004 |
| Protocol major below 9 | 1 | SPO-25b-PRE-010 |
| Node not synced (online) | 1 | SPO-Ptx-MODE-002 |
| UTxO query fails (online, light) | **0** | SPO-25b-PRE-011 |
| Payer not in transfer file (offline) | 1 | SPO-Ptx-MODE-004 |
| No UTxOs on the payer | 1 | SPO-Ptx-PRE-001 |
| Guardrails script file missing | 1 | SPO-25b-PRE-012 |
| No collateral UTxO (guardrail variant) | 1 | SPO-25b-PRE-013 |
| `build-raw` fails | `cardano-cli`'s code | SPO-25b-EXT-001, SPO-25b-EXT-005, SPO-25b-EXT-008 |
| Script-cost calculation fails | 1 | SPO-25b-EXT-002, SPO-25b-EXT-003 |
| No `eraHistory` in parameters (light, offline) | **0** | SPO-25b-EXT-003 |
| Local script hash differs from the constitution's, or none in the constitution | **0** | SPO-25b-PRE-014 |
| Fee call fails | `cardano-cli`'s code (guardrail), 1 (plain) | SPO-25b-EXT-005, SPO-25b-EXT-006 |
| Change below the minimum output value | **0** | SPO-25b-INV-009 |
| Payment key unreadable | 1 | SPO-25b-EXT-009 |
| Transaction too large | 1 | SPO-25b-PRE-015 |
| Confirmation declined | 0 | SPO-25b-PR-001 |
| Online submit fails | `checkError`'s code | SPO-25b-MODE-001 |
| Light submit fails | **0** | SPO-25b-MODE-002 |
| Offline read-back mismatch | 0 | SPO-25b-MODE-003 |

## Real-tool notes

* Observed 2026-11-16 (cardano-cli 11.2.3.0): a body carries the proposal procedures as body key 20, a tag-258 set **in the order of the action files** (so the action index of each proposal is its position), and the votes as key 19 (see 24a). The plain variant is byte-equal to the port's offline, with the TTL `tip + 25000` and one witness (`TestGovTransactionsMatchUpstream`). The guardrail variant (treasury withdrawal, parameter change) needs a collateral UTxO, the evaluated execution units and the script hash check; the port returns `ErrGuardrailsUnsupported` naming what is missing and builds nothing.

## Security

- **SPO-25b-SEC-001** In the guardrail variant the payer's collateral UTxO (5 to 10 ADA) is at stake: if the guardrails script fails validation on chain the collateral is forfeited. The only protection is the local cost run and the hash comparison of SPO-25b-PRE-014; the proposal deposit is not at risk in that case. (src: L672-L685, L731-L733)
- **SPO-25b-SEC-002** `ENV_SKIP_PROMPT=YES` removes the last check before an irreversible, deposit-locking submission (SPO-Ptx-SEC-003); this script honours it. A governance deposit is typically very large (hundreds of thousands of ADA on mainnet), so the stakes are higher than in the other pipeline scripts. (src: L893)
- **SPO-25b-SEC-003** The payment key is decrypted in memory and handed to `cardano-cli` through an anonymous pipe (SPO-Ptx-SEC-001); the message passphrase is printed in clear when encryption is used (SPO-Pparam-SEC-001); the body and signed transaction are left in the temp directory (SPO-Ptx-SEC-002). (src: L645-L650, L867-L872)
- **SPO-25b-SEC-004** The deposit amount and the return address come from the `.action` file and are trusted as they are shown; no check against the chain's current `govActionDeposit` or against the operator's own stake address is made, so a file edited or swapped after `25a` can lock the deposit on an address the operator does not control. (src: L203, L220-L241)

## Domain mapping

Use case `SubmitGovernanceActions(payer, actionFiles, metadata)` on aggregate `TxDraft` (specialised by a `ProposalSet` of governance actions, an optional proposal script and a collateral reference), through `BuildAndSignTransaction` and `SubmitOrQueueTransaction`. The `GovernanceAction` aggregate of 25a is read-only here.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(GovernanceActionFile)` | The proposals to submit |
| `Ledger` | `viewGovernanceAction(file)` *(new)* | Tag, deposit, anchor, return credential, contents |
| `Ledger` | `encodeAddress(bytes, network)` | Return and receiving stake address from key hash and network |
| `ChainQuery` | `rewardAccount(stakeAddress)` | Deposit-return address is registered |
| `ChainQuery` | `utxos(payer)`, `protocolParameters()`, `tip()` | Inputs, parameters, TTL |
| `ChainQuery` | `constitution()` *(new)* | Guardrails script hash |
| `ChainQuery` | `eraHistory()` *(new)* | Input of the offline script-cost calculation |
| `Store` | `get(GuardrailsScript)` *(new)* | The script bytes (`guardrails-script.plutus`) |
| `Ledger` | `scriptCost(body, utxos, params, eraHistory)` *(new)* | Execution units and script hash of the first redeemer |
| `Ledger` | `buildRaw(txSpec)` (with proposals, proposal script, collateral) / `minFee` / `minOutputValue` / `txId` | Body, fee, change |
| `Ledger` | `convertGovernanceId(id, form)` | CIP-129 action ids |
| `Vault` / `Signer` | `unseal(<pay>.skey)`, `signTx(body, keyRef)` | Payment signature |
| `UI` | `confirm(prompt, default No)` | The single prompt |
| `Submitter` | `submit(signedTx)`, or `Transport.enqueueTx(signedTx)` | Mode-dependent |
| `Directory` | `tokenMetadata(subject)` | Token names for display |

## Port notes

- Decide the guardrail need from **all** proposals: the set is guardrailed when any action is a `TreasuryWithdrawals` or `ParameterChange` (SPO-25b-INV-006), and the script witness must cover every such action. Check how the ledger binds a proposal script to a proposal when several are in one transaction (see Open questions).
- Treat each of the "bare `exit`" refusals (SPO-25b-PRE-014, SPO-25b-INV-009, SPO-25b-EXT-003, the failed queries of SPO-25b-PRE-007 and SPO-25b-PRE-011) as typed failures with a non-zero code.
- A constitution without a guardrails script should simply not take the guardrail path; the script mismatch refusal should apply only when a script is named (SPO-25b-PRE-014).
- Choose the collateral from a UTxO list rather than textual substitution (SPO-25b-INV-007), prefer a UTxO that is not needed for the change, and say plainly when none exists.
- Require at least one action file, refuse a duplicate by exact path, and compare the file's deposit with the live `govActionDeposit` and the return address with the operator's own stake account before asking for confirmation (SPO-25b-IF-005, SPO-25b-IF-006, SPO-25b-SEC-004).
- Replace the fixed TTL constant by a computed validity bound derived from the network's maximum Plutus-transaction TTL (SPO-25b-INV-003).
- Show the confirmation as an explicit summary (deposit total, return addresses, collateral, script hash) and never let an automation skip it by default. A multi-party deployment may require the action's return-address owner to approve.
- Hardware payers are impossible only because upstream refuses them (SPO-25b-PRE-002): a remote or hardware signer that can sign a transaction with proposal procedures lifts that limit.

## Open questions

- Whether `cardano-cli` binds the one `--proposal-script-file` to every `--proposal-file` that needs it, to the first only, or to the one that follows it, when several actions are given (SPO-25b-INV-006, SPO-25b-EXT-001). Here the script options come **before** the proposal files. Settle by building a two-action body with the pinned cli and inspecting the witness set.
- Whether the action index `i` of SPO-25b-OUT-002 equals the command-line order of the proposal files in the body. Settle by building a body and reading the proposal procedures.
- Whether the hosted Light-Mode parameters document contains `eraHistory` and `constitution` (SPO-25b-EXT-003, SPO-25b-EXT-004). Settle by fetching it.
- The meaning of the literal `{}` redeemer (SPO-25b-EXT-001): it is passed unquoted and depends on the cli's script-data JSON schema. Settle with the pinned cli and the constitution's guardrails script.
