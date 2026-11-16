+++
id = "01claimRewards"
kind = "script"
title = "Claim staking rewards"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "stake-delegation", "transaction-construction", "air-gap-transfer"]
use_cases = ["ClaimRewards"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Caddr", "Cutxo", "Cconv", "Cui", "01sendLovelaces"]

upstream_path = "cardano/mainnet/01_claimRewards.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "ecc52b1b87bd9e03d48e10608506928a9515212fb6d33dd53c421305dbfc9579"
upstream_lines = 788
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkAdaHandleFormat",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_actionCIP1292Bech",
  "convert_actionUTXO2Bech",
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
  "queryLight_stakeAddressInfo",
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
  "query stake-address-info",
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
  "koiosAPI",
  "koiosAPI/pool_info",
  "tokenMetaServer",
]
env_vars = [
  "ENV_SKIP_PROMPT",
]
+++

# 01_claimRewards: Claim staking rewards

Withdraws the whole reward balance of one stake account to a destination address, paying the fee from a payment address (by default the destination). It follows the shared transaction pipeline ([Ptx](../patterns/Ptx.md)) with a `--withdrawal` attachment and two witnesses (the stake key and the fee payer), the destination grammar of [01_sendLovelaces](./01_sendLovelaces.md) and the extra-parameter grammar of [Pparam](../patterns/Pparam.md). This spec records its own interface (stake name, destination, fee-payer forms), the reward-state refusals, the output layout and the deviations from the pipeline, the largest being that **no transaction size check exists**.

## Interface

- **SPO-01claimRewards-IF-001** Takes at least two positional words: the stake account name and the destination. With fewer it prints usage on stderr and exits 1. A third positional word, or any extra word that names an existing payment address, selects the fee payer (SPO-01claimRewards-IF-004). (src: L19-L21, L23-L76)
- **SPO-01claimRewards-IF-002** The stake account file is `<name>.staking.addr`: the name always gets `.staking` appended unless it already ends in `.staking`, so `owner` and `owner.staking` are the same account. A trailing `.addr` is not removed, so `owner.staking.addr` names a file that does not exist. A directory part is kept. (src: L20)
- **SPO-01claimRewards-IF-003** The destination follows SPO-01sendLovelaces-IF-004 .. SPO-01sendLovelaces-IF-008 (file, literal payment address, ADA Handle). (src: L180-L203, L249-L251)
- **SPO-01claimRewards-IF-004** The fee payer is given by an extra word that is neither a key (`msg:`, ...), nor a `txhash#index` list, nor empty or numeric, and for which `<word>.addr` (extension optional, directory allowed) exists; that word is not read as metadata. Only when no such file exists is the word treated as a metadata file (SPO-Pparam-IF-030). With several matching words the last wins. (src: L91-L97)
- **SPO-01claimRewards-IF-005** When no fee payer word is given and the destination was an existing `<dest>.addr` file, the destination name is the fee payer. (src: L205-L209)
- **SPO-01claimRewards-PRE-001** When no fee payer is known (the destination was a literal address or an ADA Handle and no payer was given) the script refuses with exit 1. (src: L211-L212)
- **SPO-01claimRewards-IF-006** The extra parameters start at the third positional word (SPO-Pparam-IF-001) and take the full acceptance row of Pparam for the fee payer's inputs: messages, `enc:`, `pass:`, metadata files, a `txhash#index` list, `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:`. The filters act on the UTxOs of the fee payer, not on the stake account. (src: L85-L173, L441-L443)

## Inputs

- **SPO-01claimRewards-IN-001** Reads `<stake>.staking.addr` and refuses with exit 1 when it does not exist. (src: L177, L253)
- **SPO-01claimRewards-PRE-002** Refuses with exit 2 when neither `<stake>.skey` nor `<stake>.hwsfile` exists. (src: L178)
- **SPO-01claimRewards-PRE-003** Refuses with exit 2 when neither `<payer>.skey` nor `<payer>.hwsfile` exists. This check runs after the destination is resolved. (src: L215)
- **SPO-01claimRewards-IN-002** Reads the reward state of the stake account: from `cardano-cli <era> query stake-address-info --address <stake bech32>` online, from Koios in light mode, and from `address."<stake bech32>".rewardsJSON` of the transfer file offline. The fields it reads are the entry count of the answer, `[0].rewardAccountBalance` and `[0].voteDelegation`; the pool, the deposit and the governance-action deposits are display only. (src: L281-L313)

## Behaviour

1. **Arguments, files, destination.** IF-001 .. IF-006, IN-001, PRE-002, PRE-003, the transaction message file (SPO-Pparam-OUT-002, named after the fee payer). The protocol parameters are read here, before the reward state (SPO-Ptx-MODE-006). (src: L259-L268)
2. **Reward state.** Ptx stage 2 (clock) runs before this. Then, in this order:
   - **SPO-01claimRewards-PRE-004** Refuses with exit 1 when the stake address is not registered on chain (the answer has no entry). (src: L315)
   - **SPO-01claimRewards-PRE-005** When the stake account has no vote delegation and the protocol major version is 10 or higher, refuses with exit 1 and advises delegating to a DRep (scripts 22a and 22b). A delegation to a DRep, a DRep script, `alwaysAbstain` or `alwaysNoConfidence` passes. A protocol major below 10, or an absent one, never refuses here. (src: L382-L389)
   - **SPO-01claimRewards-PRE-006** Refuses with exit 1 when the reward balance is zero. This is the last check before inputs are gathered. (src: L421-L422)
   - **SPO-01claimRewards-INV-001** The withdrawal is the whole balance read in this step: `--withdrawal <stake bech32>+<balance>`. There is no partial claim. (src: L421, L605)
   - Information shown but not gating: the delegated pool (with an extra Koios `pool_info` request online when `koiosAPI` is set, failure ignored), the DRep, the governance-action deposits. (src: L326-L419)
3. **Inputs.** Ptx stage 3 and 4 for the fee payer's address (SPO-Ptx-MODE-002 .. SPO-Ptx-PRE-001). The same UTxO-query exit-status quirk as SPO-01sendLovelaces-PRE-001 applies. (src: L434-L470)
4. **Layout.**
   - **SPO-01claimRewards-INV-002** Whether there is one output or two depends on comparing the payer's address with the destination address as text, not the names. Equal addresses give one output, otherwise two. (src: L278)
   - **SPO-01claimRewards-OUT-001** One output: the destination (which is the payer) gets `total - fee + rewards` lovelaces and all assets of the inputs. (src: L610-L612, L631, L660)
   - **SPO-01claimRewards-OUT-002** Two outputs: the payer gets `total - fee` lovelaces and all assets of the inputs, and the destination gets exactly the rewards. In the final body the payer (change) output is first and the destination second. The destination never receives the payer's assets. (src: L615, L641, L662)
5. **Fee.** As SPO-Ptx-EXT-001 .. SPO-Ptx-EXT-002 with `--withdrawal` in the dummy body, the dummy change amount `total + assets` (two outputs) or `total + rewards` (one output), and the witness count 2 (SPO-Ptx-INV-006). (src: L607-L624)
   - **SPO-01claimRewards-PRE-007** Refuses when the output that carries the change is below `M`, the minimum output value (SPO-Ptx-EXT-003) of `<destination>+1000000<all assets>`: for one output when `total - fee + rewards < M`, for two outputs when `total - fee < M`. The exit status is 0. (src: L600, L628-L634, L638-L645)
     > **Upstream quirk:** the exit status is 0 (a bare `exit`), so a caller sees success (SPO-Ptx-PRE-002). In the two-output case `M` is computed for the destination's address but compared with the payer's output; and the reward output to the destination is never compared with its minimum, so rewards below the minimum output value to a different destination produce a body the node rejects.
6. **Sign.** Ptx stage 9 with these combinations (SPO-Ptx-PRE-006):
   - **SPO-01claimRewards-INV-003** The hardware path is taken only when `<payer>.hwsfile` and `<stake>.hwsfile` both exist and the payer name without `.payment` equals the stake name without `.staking` (the same wallet). One `cardano-hw-cli transaction witness` call signs with both files, declares both as `--change-output-key-file` and writes `<tempDir>/<payer>.txwitness-payment` and `-staking`; both witnesses are assembled. (src: L669-L701)
   - **SPO-01claimRewards-INV-004** The key-file path is taken only when `<payer>.skey` and `<stake>.skey` both exist. Both keys are read into memory (payer first, stake second) and passed to one `transaction sign`. (src: L704-L718)
   - **SPO-01claimRewards-PRE-008** Any other combination, such as a hardware stake key with a key-file payer or the reverse, or hardware files of different wallets, is refused with exit 1: a hardware wallet can only claim its own rewards. (src: L720-L722)
7. **Final body.**
   - **SPO-01claimRewards-PRE-009** The final `build-raw` (one-output and two-output branch) is not checked: no `checkError` follows it, and nothing removes `<tempDir>/<payer>.txbody` beforehand (only the dummy body is removed). When the final build fails, the script goes on to display, sign and, with `ENV_SKIP_PROMPT=YES` or a confirmation, submit whatever `<payer>.txbody` an earlier run left behind. Any pipeline script run with the same payer basename writes that file. (src: L609, L659-L665)
     > **Upstream quirk:** this contradicts SPO-Ptx-EXT-004 (a failed build ends the script). A stale body can be signed and submitted. A port builds into a fresh path and checks the status (SPO-01claimRewards-SEC-003).
8. **Size, confirm, submit.**
   - **SPO-01claimRewards-INV-005** No transaction size check is made: the step between signing and the confirmation prompt only prints the signed transaction. A payer with many UTxOs can produce a transaction above `maxTxSize`, which the node then rejects at submission. This is the exception to SPO-Ptx-PRE-007. (src: L723-L731)
   - **SPO-01claimRewards-PR-001** The confirmation of SPO-Ptx-PR-002 (default No) honours `ENV_SKIP_PROMPT`. (src: L729-L731)
   - Submission is as SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010.

## Pipeline stage map

Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-01claimRewards-INV-006** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002), with the stake account, destination and fee-payer forms of SPO-01claimRewards-IF-001 to SPO-01claimRewards-IF-006 and the refusals SPO-01claimRewards-IN-001, SPO-01claimRewards-PRE-001 to SPO-01claimRewards-PRE-003. (src: L19-L257)
- **SPO-01claimRewards-INV-007** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL = slot + `defTTL`. (src: L259-L260, L270)
- **SPO-01claimRewards-INV-008** Stage 3, gather inputs: as Ptx for the fee payer's address (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002); the offline stake-address snapshot is SPO-01claimRewards-MODE-001. (src: L434-L470)
- **SPO-01claimRewards-INV-009** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005); all assets of the fee payer's inputs return to the payer or to the one output (SPO-01claimRewards-OUT-001, SPO-01claimRewards-OUT-002). (src: L472-L598)
- **SPO-01claimRewards-INV-010** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006), read before the reward state (step 1 above). (src: L262-L268)
- **SPO-01claimRewards-INV-011** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with `--withdrawal` and witness count 2; the dummy build failure exits with cardano-cli's code, a fee failure exits 1. (src: L600-L624)
- **SPO-01claimRewards-INV-012** Stage 7, balance: as Ptx (SPO-Ptx-EXT-003, SPO-Ptx-PRE-002, SPO-Ptx-PRE-004) with the layouts of SPO-01claimRewards-OUT-001 and SPO-01claimRewards-OUT-002 and the refusal SPO-01claimRewards-PRE-007 (exit 0). (src: L626-L648)
- **SPO-01claimRewards-INV-013** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004) except that the build status is not checked (SPO-01claimRewards-PRE-009). (src: L650-L665)
- **SPO-01claimRewards-INV-014** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006) with the two-key combinations of SPO-01claimRewards-INV-003, SPO-01claimRewards-INV-004 and SPO-01claimRewards-PRE-008. (src: L669-L723)
- **SPO-01claimRewards-INV-015** Stage 10, size check: skipped (SPO-01claimRewards-INV-005). (src: L723-L731)
- **SPO-01claimRewards-INV-016** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003), honouring `ENV_SKIP_PROMPT` (SPO-01claimRewards-PR-001). (src: L731)
- **SPO-01claimRewards-INV-017** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010); the offline entry is SPO-01claimRewards-OUT-003. (src: L733-L786)

## Work modes

Per Ptx. The differences specific to this script:

- **SPO-01claimRewards-MODE-001** Offline, the stake address must be in the transfer file as `address."<stake bech32>".rewardsJSON`; when it is not, the script prints a notice and ends with exit status 0 (a bare `exit` after the echo). The fee payer's address missing from the file is refused with exit 1 (SPO-Ptx-MODE-004). The registration, DRep and balance checks run on the stored snapshot. (src: L294-L297, L460-L463)
- **SPO-01claimRewards-MODE-002** Online and light, a failing reward-state query prints the error and ends the script with exit status 0 (the `exit` reads the status of the preceding `echo`). (src: L285, L291)
- **SPO-01claimRewards-MODE-003** Offline mode reads the transfer file when the protocol parameters are read, so a missing or invalid transfer file stops the script there (SPO-Ptransfer-IN-001). ADA Handle destinations are refused offline (SPO-01sendLovelaces-MODE-001). (src: L262-L268)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Does this look good for you, continue? (SPO-01claimRewards-PR-001) | No | No ends with exit 0, nothing submitted or queued; skipped by `ENV_SKIP_PROMPT=YES` |

## Outputs

- **SPO-01claimRewards-OUT-003** Offline, the signed transaction is appended to `transactions[]` with `type` `Withdrawal` and the fields `era`, `stakeAddr` (the normalised stake name), `stakingAddr` (stake bech32), `fromAddr` (payer name), `sendFromAddr`, `toAddr`, `sendToAddr`, `txJSON`. The history entry reads "signed rewards withdrawal from '<stake>' to '<to>', payment via '<payer>'". The common mutations are SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012; `execute` re-checks the reward state against the snapshot (SPO-Ptransfer-PRE-005). (src: L757-L781)
- **SPO-01claimRewards-OUT-004** Online and light, no non-secret file other than the temporary files below is written. (src: L735-L755)

**Upstream file contract** (in `<tempDir>`, SPO-Pfiles-OUT-039; modes not managed):

| File | Content | Change |
| --- | --- | --- |
| `tempTo.addr`, `adahandle-resolve.addr` | destination address (as SPO-01sendLovelaces) | replaced, literal or handle destination |
| `<payer>.transactionMessage.json` | message metadata, named after the payer | replaced, when messages exist |
| `dummy.txbody`, `<payer>.txbody`, `.tx` | bodies and signed transaction | replaced |
| `<payer>.txwitness-payment`, `.txwitness-staking` | hardware witnesses | replaced, hardware path only |
| `offlineTransfer.json` | gains one `Withdrawal` entry | updated, offline only |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two positional words | 1 | SPO-01claimRewards-IF-001 |
| Stake address file missing | 1 | SPO-01claimRewards-IN-001 |
| Stake or payer signing file missing | 2 | SPO-01claimRewards-PRE-002, SPO-01claimRewards-PRE-003 |
| No fee payer for a literal or handle destination | 1 | SPO-01claimRewards-PRE-001 |
| Stake address not registered | 1 | SPO-01claimRewards-PRE-004 |
| No DRep delegation, protocol 10 or higher | 1 | SPO-01claimRewards-PRE-005 |
| Zero rewards | 1 | SPO-01claimRewards-PRE-006 |
| Reward or UTxO query fails (online, light) | **0** | SPO-01claimRewards-MODE-002 |
| Stake address missing from the transfer file | **0** | SPO-01claimRewards-MODE-001 |
| Change below the minimum output | **0** | SPO-01claimRewards-PRE-007 |
| Unsupported hardware or key-file mix | 1 | SPO-01claimRewards-PRE-008 |
| Transaction above `maxTxSize` | not checked | SPO-01claimRewards-INV-005 |
| Final body build fails | **not detected**: a stale body is signed | SPO-01claimRewards-PRE-009 |
| Others | | as SPO-Ptx table "Failures" |

## Security

- **SPO-01claimRewards-SEC-001** The reward destination is chosen on the command line and may differ from the stake account's owner. With `ENV_SKIP_PROMPT=YES` nothing checks it before the transaction is submitted (SPO-Ptx-SEC-003). (src: L731)
- **SPO-01claimRewards-SEC-002** The temporary-file hazard of SPO-01sendLovelaces-SEC-001 applies to a literal or handle destination. Two signing keys are held in memory at once (SPO-Ptx-SEC-001). (src: L186, L198, L707-L718)
- **SPO-01claimRewards-SEC-003** A failed final build leaves the previous `<tempDir>/<payer>.txbody` in place and the script signs it (SPO-01claimRewards-PRE-009). With `ENV_SKIP_PROMPT=YES` the stale transaction, possibly built for another destination or amount, is submitted with no human check. (src: L650-L665, L731)

## Domain mapping

Use case `ClaimRewards(stakeAccount, destination, feePayer?, extras)` on the `StakeAccount` aggregate (reward balance and vote delegation, read-only) and the `PaymentAccount` aggregate (fee payer), producing a `TxDraft` with a `Withdrawal` attachment for the shared pipeline.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(Address)` | Stake, destination and payer address files |
| `ChainQuery` | `rewardAccount(stakeAddress)` | Registration, balance, vote delegation (online, light, snapshot) |
| `ChainQuery` | `utxos`, `protocolParameters`, `syncStatus` | Pipeline inputs |
| `Directory` | `resolveHandle(handle)` | ADA Handle destination |
| `Ledger` | `buildRaw` (with withdrawal), `minFee`, `minOutputValue`, `assemble`, `txId` | Body and fee |
| `Signer` | `signTx` / `witness` | Payer plus stake witness |
| `Submitter` / `Transport` | `submit`, `enqueueTx` | Online, light, offline |
| `UI` | `confirm` | The one prompt |

## Port notes

* Build the final body into a fresh path, remove any earlier body first, and stop on a build failure (SPO-01claimRewards-PRE-009, SPO-01claimRewards-SEC-003).
* Apply the size check (SPO-01claimRewards-INV-005) and exit non-zero for the three exit-0 refusals (SPO-01claimRewards-PRE-007, MODE-001, MODE-002).
* Check the reward output against its own minimum, and the change output against the minimum for the source address (SPO-01claimRewards-PRE-007 quirk).
* A remote signer needs the body, the two key references and, for hardware, the change-output declarations; the stake key and the payer key may live with different parties, which upstream cannot express.
* Make the fee payer an explicit input rather than a word that is recognised by file existence (SPO-01claimRewards-IF-004), so a typo cannot turn a payer into a metadata error.
* The DRep refusal (SPO-01claimRewards-PRE-005) is a protocol rule; a port reads it from the protocol parameters rather than from a fixed major version, but must reproduce it at major 10.

## Open questions

* Whether `rewardAccountBalance` in the Koios light-mode answer equals the node's value in all cases; both feed `--withdrawal`, and a mismatch is rejected on chain. A recorded light-mode answer settles it.
* The shape of `voteDelegation` for a script DRep and for `alwaysAbstain` (SPO-01claimRewards-PRE-005 relies on the strings `alwaysAbstain`, `alwaysNoConfidence`, `notSet` and `null`); the cardano-cli version in the release set decides it.
