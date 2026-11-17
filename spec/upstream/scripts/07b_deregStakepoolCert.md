+++
id = "07b"
kind = "script"
title = "Submit the pool retirement transaction"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "transaction-construction", "key-custody", "air-gap-transfer"]
use_cases = ["RetirePool"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cui", "Ckey", "Chw", "Ctx", "Cchain", "Clight", "Cutxo", "Coffline", "Cconv"]

upstream_path = "cardano/mainnet/07b_deregStakepoolCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "e87b80e18209580b7a6c361f296be4ca11a5fe0615ed1cb8ccbb6a4825e4a165"
upstream_lines = 603
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "file_lock",
  "file_unlock",
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
env_vars = []
+++

# 07b_deregStakepoolCert: Submit the pool retirement transaction

Builds, signs and submits (or queues offline) the transaction that carries the retirement certificate made by [07a](./07a_genStakepoolRetireCert.md). It pays the fee from one payment address and is signed by that address and by the pool's cold key. The pool deposit is not part of this transaction: the ledger returns it to the pool's reward account at the retirement epoch, which is why the reward account must stay registered.

It follows the Ptx pipeline (variation row of SPO-Ptx-INV-006: two witnesses; SPO-Ptx-PR-003: it ignores `ENV_SKIP_PROMPT`; SPO-Ptx-OUT-004: records `deregSubmitted`). This spec lists the differences.

## Interface

- **SPO-07b-IF-001** Takes two required arguments: the pool name and the name of the paying address. With fewer, prints usage to stderr and exits 1. (src: L21-L62)
- **SPO-07b-IF-002** The names are normalised as in SPO-Pfiles-IN-001; for the paying address a trailing `.addr` is also dropped. (src: L65-L66)
- **SPO-07b-IF-003** Extra parameters: metadata `.json`/`.cbor` files, `msg:`, `enc:`, `pass:` as in `Pparam` (SPO-Ptx-IF-001). The tokens `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and a UTxO list are recognised but ignored (SPO-Pparam-IF-007), so every UTxO of the paying address is spent. `type:` is not known and fails as a missing file (SPO-Pparam-IF-005). (src: L96-L152)

## Inputs

- **SPO-07b-IN-001** Reads `<pool>.pool.json` and requires the fields `poolName`, `deregCertFile` and `poolMetaTicker` (the ticker is used only to describe the action in the offline history). A missing descriptor, a missing or empty field or invalid JSON exits 1. (src: L69-L84)
- **SPO-07b-IN-002** Requires the certificate file named by `deregCertFile`, `<pool>.node.skey` or `.node.hwsfile`, `<pay>.addr`, and `<pay>.skey` or `.hwsfile`; each missing file exits 1 before any query. (src: L87-L90)
- **SPO-07b-IN-003** The paying address, read from `<pay>.addr`, and the destination (the same address) are validated as addresses (SPO-Ptx-IN-001). (src: L204-L205)

## Behaviour

Stages 2 to 12 of the Ptx pipeline apply, with these specifics.

1. **Certificate and witnesses.**
   - **SPO-07b-INV-001** The one certificate attached is `--certificate <deregCertFile>` and the fee is calculated for **2** witnesses (payer and cold key), in the dummy and final bodies. (src: L402, L406, L436). See SPO-Ptx-INV-006.
   - **SPO-07b-INV-002** The balance is `inputs - fee`, all assets returned to the paying address in one output; there is no deposit and no refund in this transaction. A change below the minimum output value refuses with exit **0** (SPO-Ptx-PRE-002). (src: L412-L424)
   - **SPO-07b-INV-003** The validity end is `tip + defTTL` slots (SPO-Ptx-INV-001). The retirement epoch of the certificate is independent of it and is not re-validated: a certificate made by 07a for an epoch that has become invalid (not after the current epoch, or beyond `eMax`) is submitted anyway and rejected by the ledger. (src: L197-L198, L402)
   - **SPO-07b-PRE-001** A paying address without UTxOs exits 1 (unlike SPO-05c-PRE-007). Offline, a paying address absent from the transfer file exits 1. (src: L245, L250)
2. **Signing.**
   - **SPO-07b-INV-004** The signer set is chosen as a pair: when `<pay>.hwsfile` and `<pool>.node.hwsfile` both exist the hardware path is taken; otherwise when `<pay>.skey` and `<pool>.node.skey` both exist the key-file path is taken. Any other combination, such as hardware payer with key-file cold key, exits 1 with the message that only a hardware cold key can be retired by a payment account on the same hardware wallet (SPO-Ptx-PRE-006). (src: L442, L475, L491-L494)
   - **SPO-07b-EXT-001** *Hardware path.* The body is canonicalised (`autocorrect_TxBodyFile`, see `Ctx`; failure exits 1), the hardware session is started without vendor restriction, `cardano-hw-cli transaction witness --tx-file <body> --hw-signing-file <pay> --hw-signing-file <node> <magic> --out-file <w-payment> --out-file <w-node>` makes both witnesses (output classified as in SPO-Ptx-PRE-005), and `cardano-cli <era> transaction assemble` joins them with the body. No confirmation is asked before the device is used. (src: L442-L472)
   - **SPO-07b-EXT-002** *Key-file path.* Both signing keys are read into memory (`read_skeyFILE`; failure exits 1) and `cardano-cli <era> transaction sign --tx-body-file <body> --signing-key-file <pay key> --signing-key-file <node key> <magic> --out-file <tx>` signs; the variables are unset. (src: L475-L489). See SPO-Ptx-EXT-006.
   - **SPO-07b-PRE-002** A signed transaction larger than `maxTxSize` exits 1 (SPO-Ptx-PRE-007). (src: L500-L505)
3. **Confirm.**
   - **SPO-07b-PR-001** Asks "does this look good, continue?" (default No) with no `ENV_SKIP_PROMPT` bypass (SPO-Ptx-PR-002, SPO-Ptx-PR-003). No ends the script with exit 0 and nothing submitted, queued or changed. (src: L507-L508, L596-L602)
4. **Submit or queue.**
   - **SPO-07b-MODE-001** *Online:* `cardano-cli <era> transaction submit --tx-file <tx>`; a failure exits with cardano-cli's code and leaves the descriptor unchanged; on success records `deregSubmitted` (SPO-07b-OUT-001) and shows the transaction id and explorer link. (src: L511-L526)
   - **SPO-07b-MODE-002** *Light:* `submitLight`; on failure prints the error and exits with the status of the preceding `echo`, that is **0** (SPO-Ptx-MODE-009); on success records `deregSubmitted`. (src: L537-L550)
     > **Upstream quirk:** a failed light submit exits 0. A port exits non-zero.
   - **SPO-07b-MODE-003** *Offline:* appends the queue entry with `type` `PoolRetirement`, the common fields of SPO-Ptransfer-OUT-010 (`fromAddr` and `toAddr` the paying-address name) and `poolMetaTicker`, plus a history entry `signed pool retirement transaction for '<ticker>', payment via '<pay>'` and `general.offlineCLI`; reads `transactions[-1].txJSON` back; on a match records `deregSubmitted` (SPO-07b-OUT-002) and shows the file summary. On a mismatch it prints an error, exits 0 and does not record. (src: L562-L593). See SPO-Ptransfer-OUT-010 to SPO-Ptransfer-OUT-012.
   - **SPO-07b-MODE-004** UTxOs, parameters and era are read as in SPO-Ptx-MODE-002 to SPO-Ptx-MODE-006; online requires a synced node (exit 1). (src: L217-L247, L388-L393)

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-07b-INV-005** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the files and certificate named in the Interface and Inputs sections. The usage text is display only. (src: L19-L195)
- **SPO-07b-INV-006** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), with SPO-07b-INV-003. (src: L197-L198)
- **SPO-07b-INV-007** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-INV-002); no UTxOs exit 1 (SPO-07b-PRE-001), SPO-07b-MODE-004. (src: L200-L250)
- **SPO-07b-INV-008** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L252-L385)
- **SPO-07b-INV-009** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006). (src: L387-L393)
- **SPO-07b-INV-010** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with the retirement certificate attached and witness count 2 (SPO-07b-INV-001). (src: L397-L410)
- **SPO-07b-INV-011** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-EXT-003, SPO-Ptx-PRE-002) with change `inputs - fee`, no deposit and the refusal exit 0 (SPO-07b-INV-002). (src: L395, L412-L424)
- **SPO-07b-INV-012** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003): the body is named after the pool, any earlier body is removed first and a build failure ends the script with cardano-cli's code. (src: L426-L439)
- **SPO-07b-INV-013** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-PRE-006) with the pair of keys of SPO-07b-INV-004, SPO-07b-EXT-001 and SPO-07b-EXT-002. (src: L441-L494)
- **SPO-07b-INV-014** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007), exit 1 (SPO-07b-PRE-002). (src: L496-L505)
- **SPO-07b-INV-015** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002) but without the `ENV_SKIP_PROMPT` bypass (SPO-Ptx-PR-003, SPO-07b-PR-001). (src: L507-L508)
- **SPO-07b-INV-016** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010) with SPO-07b-MODE-001 to SPO-07b-MODE-003 and the descriptor update SPO-07b-OUT-001, SPO-07b-OUT-002 (online, light, and verified offline queueing). (src: L510-L603)

## Work modes

Per SPO-07b-MODE-001 to SPO-07b-MODE-004. No ticker, metadata or chain-state check runs in any mode: unlike 05c, retirement is not validated against the chain (SPO-07b-INV-003).

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Does this look good (SPO-07b-PR-001) | No | No: exit 0, nothing happens |

## Outputs

- **SPO-07b-OUT-001** After a successful online or light submit, adds `deregSubmitted` (RFC-5322 time) to the descriptor (unlock, whole-file rewrite, lock `0400`). The message about keeping the reward account registered to receive the deposit is displayed. (src: L516-L521, L542-L547, L533, L557)
- **SPO-07b-OUT-002** After a verified offline queueing, adds `deregSubmitted` with the suffix ` (only offline, no proof)`. (src: L580-L584)
- **SPO-07b-OUT-003** The retirement certificate `<pool>.pool.dereg-cert` is neither deleted nor locked further, so the same certificate can be submitted again. (src: L514, L540)
  > **Port decision 2026-11-16 (hazard H9, confirmation):** `deregSubmitted` is not written on an accepted submit or a queueing. The command keeps it as a pending update (`<txid>.pending`) and the descriptor records it when the providers confirm the transaction (the wait of `pool retire`, on by default in light and online mode, or `spo tx settle`; across the air gap `spo asset settle`, only on a recorded confirmation). The certificate is deleted when the transaction is sent, as before. While the update is pending, `pool descriptor show` and `pool witness status` say so. This deliberately departs from SPO-07b-OUT-001 and SPO-07b-OUT-002; the final record equals what upstream writes. See SPO-Xconfirm-PR-002 and SPO-Xconfirm-PR-003.
  > **Upstream quirk:** unlike the registration certificate (SPO-05c-OUT-006) it stays. A port retires it after use.
- **SPO-07b-OUT-004** A recorded `deregSubmitted` makes 05c refuse a later registration unless `type:REG` or `type:REREG` is given (SPO-05c-PRE-004). (src: 05c_regStakepoolCert.sh:L229-L231)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.pool.json` | `deregSubmitted` added | `0400` | updated |
| `<tempDir>/<pool>.txbody`, `.tx`, `dummy.txbody`, `<pay>.transactionMessage.json` | body, signed transaction, message metadata | default | created, not deleted |
| `offlineTransfer.json` | queue entry, history (offline) | not managed | updated |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments | 1 | SPO-07b-IF-001 |
| Bad extra parameter | 1 | SPO-Pparam-PRE-005 |
| Descriptor, field or key file missing | 1 | SPO-07b-IN-001, SPO-07b-IN-002 |
| No UTxOs; payer absent from the transfer file | 1 | SPO-07b-PRE-001 |
| Node not synced (online) | 1 | SPO-07b-MODE-004 |
| Change below the minimum output value | **0** | SPO-07b-INV-002 |
| Unsupported hardware and key-file mix | 1 | SPO-07b-INV-004 |
| Hardware rejected, disconnected, error; key unreadable | 1 | SPO-07b-EXT-001, SPO-07b-EXT-002 |
| Transaction too large | 1 | SPO-07b-PRE-002 |
| Confirmation declined | 0 | SPO-07b-PR-001 |
| Online submit fails | cardano-cli's code | SPO-07b-MODE-001 |
| Light submit fails | **0** | SPO-07b-MODE-002 |
| Offline read-back mismatch | **0** | SPO-07b-MODE-003 |

## Security

- **SPO-07b-SEC-001** The cold signing key is used here. With key files it is read into memory (SPO-Ptx-SEC-001, SPO-Ckey-SEC-002); a retired pool's cold key can still re-register the pool, so the signing step needs the same custody as 05c. (src: L475-L489)
- **SPO-07b-SEC-002** The signed transaction and body stay in world-readable temporary files (SPO-Ptx-SEC-002). The message passphrase of `pass:` is displayed (SPO-Pparam-SEC-001). (src: L426-L428, L380-L384)

## Domain mapping

Use case `RetirePool(pool, payer)` on aggregate `StakePool` (retirement state), a `TxIntent` of the shared pipeline with certificate = retirement, witnesses = {payer, cold key}, no deposit effect, post-submit effect = record `deregSubmitted`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get/put(PoolDescriptor)`, `get(PoolRetirementCertificate)` | Descriptor and certificate |
| `ChainQuery` | `tip()`, `protocolParameters()`, `utxos(address)` | Pipeline |
| `Ledger` | `buildRaw`, `minFee`, `minOutputValue`, `canonicalizeForHardware`, `assemble`, `txId` | Body, fee, assembly |
| `Signer` | `signTx(body, keyRefs)` / `witness(body, keyRef)` | Payer and cold key, key file or hardware |
| `Vault` | `unseal(ref, passphrase?)` | In-memory keys |
| `Submitter` | `submit(signedTx)` | Online, light |
| `Transport` | `enqueueTx(signedTx, extras)` | Offline queue |
| `UI` | `confirm(prompt, default)`, `show(view)` | Confirmation, summary |

## Port notes

* Revalidate the retirement epoch against the current epoch and `eMax` at submission, and refuse before spending a fee (SPO-07b-INV-003).
* Make the signer set a function of key locations per signer (payer, cold key) instead of the both-or-neither rule (SPO-07b-INV-004); with a remote `Signer` any mix works.
* Mark the retirement certificate as consumed after submission (SPO-07b-OUT-003).
* Exit non-zero on light failure, on a read-back mismatch and on insufficient funds.
* The hardware path asks no confirmation before the device is used (unlike 05c); keep the device prompt as the approval, and show the decoded intent (pool id, retirement epoch, fee) to a remote signer.
* Warn when the reward account is not registered or is about to be deregistered: the deposit refund would be lost.

## Notes from the oracle (2026-11-16)

* Offline against the pinned scripts (`spo/test/parity/pool_scripts_test.go`): the queued transaction, its fee at two witnesses, the queue entry and the descriptor record are byte-equal to upstream's; the body equals `build-raw` with the retirement certificate (`spo/test/parity/pool_oracle_test.go`).
* SPO-07b-OUT-003 confirmed: the certificate stays after the submission. The port deletes it with the record, and refuses a certificate whose epoch is outside `current+1 .. current+eMax` before a fee is spent (SPO-07b-INV-003 port note).

## Open questions

* Whether the ledger pays the refund to the reward account in the retirement epoch or the next one, and what happens when that account is unregistered at that time, is ledger behaviour, outside the scripts.
