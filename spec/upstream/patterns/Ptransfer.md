+++
id = "Ptransfer"
kind = "pattern"
title = "The offlineTransfer.json schema and its mutation rules"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["air-gap-transfer", "transaction-construction"]
use_cases = ["PrepareOfflineSnapshot", "QueueOfflineTransaction", "ExecuteQueuedTransaction", "CarryFiles"]
depends_on = ["Coffline", "Cutxo", "Cchain", "Clight", "Ptx", "Pfiles"]
sources = [
  "01_workOffline.sh",
  "00_common.sh",
  "01_sendLovelaces.sh",
  "01_sendAssets.sh",
  "01_claimRewards.sh",
  "03b_regStakingAddrCert.sh",
  "05c_regStakepoolCert.sh",
  "05d_poolWitness.sh",
  "06_regDelegationCert.sh",
  "07b_deregStakepoolCert.sh",
  "08b_deregStakingAddrCert.sh",
  "0x_importHelper.sh",
  "11a_mintAsset.sh",
  "11b_burnAsset.sh",
  "21b_regDRepCert.sh",
  "21d_retDRepCert.sh",
  "22b_regVoteDelegCert.sh",
  "23c_regComAuthCert.sh",
  "23e_retComColdKeys.sh",
  "24b_regVote.sh",
  "25b_regAction.sh",
]
+++

# Ptransfer: the offlineTransfer.json schema and its mutation rules

`offlineTransfer.json` is the carry bag between an online machine (work mode `online` or `light`) and an offline (air-gapped) machine. The online machine writes a **snapshot** into it (protocol parameters, era, UTxOs and reward state of chosen addresses, DRep state, token registry names). The offline machine reads the snapshot instead of querying the chain, builds and signs transactions, and appends the **signed transactions** to the same file. The file travels back, and `01_workOffline.sh execute` submits the queued transactions from the online side. Small files (pool metadata, witness files, DRep import data) can ride along as base64 attachments. The file is one JSON document that every writer reads whole, edits with `jq`, and writes whole.

The file is the contract of the `Transport` port (`snapshot`, `importSnapshot`, `enqueueTx`, `dequeueTx`, `attach`, `extract`) and of the offline `ChainQuery` adapter (see `Ptx` for how the pipeline reads it). Display functions (`showOfflineFileInfo`, `info`) are not specified.

## Location and validity

- **SPO-Ptransfer-IF-001** The file lives at the path in the `offlineFile` setting, default `./offlineTransfer.json` (relative to the working directory). An empty setting falls back to the default. (src: 00_common.sh:L59, 00_common.sh:L510)
- **SPO-Ptransfer-IN-001** `readOfflineFile` accepts the file only when it exists, parses as JSON, is not empty, and `.protocol.parameters` is a non-empty object. Otherwise the calling script exits 1 and tells the operator to run `01_workOffline.sh new` in online mode. Every offline transaction script, `attach`, and the offline branches of the query scripts call it. (src: 00_common.sh:L2587-L2601, 01_workOffline.sh:L241-L256)
- **SPO-Ptransfer-IN-002** `cleartx`, `clearhistory`, `clearfiles`, `extract` and `info` do not call `readOfflineFile`: they work on whatever the file contains, and treat a missing or blank file as `{}`. A malformed file is refused with exit 1 by the shared reader at the top of the script. (src: 01_workOffline.sh:L97-L106, 01_workOffline.sh:L46-L49)
  > **Upstream quirk:** `cleartx`/`clearhistory`/`clearfiles` on a missing file create a file holding only a history entry, which `readOfflineFile` then rejects (no protocol parameters).

## Document shape

All top-level keys are optional in the sense that `jq` creates them on first use. After `new` the keys are `general`, `protocol` and `history` only.

| Path | Type | Written by | Read by | Content |
| --- | --- | --- | --- | --- |
| `general.onlineCLI` | string | `new`, `add`, `add-drep` | display | `cardano-cli` version on the online machine |
| `general.onlineNODE` | string | `new`, `add`, `add-drep` | display | `cardano-node` version, or the literal `light` in light mode |
| `general.offlineCLI` | string | every offline transaction script | `execute` (version-mismatch warning) | `cardano-cli` version on the offline machine at signing time |
| `protocol.parameters` | object | `new`, `add`, `add-drep` | every offline script | Protocol parameters JSON (see SPO-Ptransfer-OUT-002) |
| `protocol.era` | string | `new`, `add`, `add-drep` | offline scripts (copied into each queued transaction; era of the offline `cardano-cli` calls) | Lower-case era name, for example `conway` |
| `address."<bech32>"` | object | `add` | offline scripts, `execute` | One snapshot entry per payment or stake address, keyed by the address text |
| `address."<bech32>".name` | string | `add` | display | Address name as given (file base name) |
| `address."<bech32>".type` | string | `add` | display | `payment` or `stake` |
| `address."<bech32>".date` | string | `add` | display | RFC-5322 timestamp (`date -R`) of the snapshot |
| `address."<bech32>".used` | string | `add` (`no`), `execute` (`yes`) | display | Whether a queued transaction from/to this address was executed since the snapshot |
| `address."<bech32>".totalamount` | integer | `add` | display | Payment address: total lovelaces; stake address: reward balance sum |
| `address."<bech32>".totalassetscnt` | integer | `add` (payment only) | display | Number of distinct asset types |
| `address."<bech32>".utxoJSON` | object | `add` (payment only) | every offline transaction script, `execute` | UTxO map, see SPO-Ptransfer-OUT-005 |
| `address."<bech32>".rewardsJSON` | array | `add` (stake only) | `01_claimRewards`, `execute` | Output of the stake-address-info query |
| `drep."<drepid>"` | object | `add-drep` | `21b`, `21d` | One entry per DRep, keyed by the bech32 DRep id read from `<name>.id` |
| `drep."<drepid>".name` | string | `add-drep` | display | DRep name |
| `drep."<drepid>".deposit` | integer or `null` | `add-drep` | display | Deposit of the registered DRep, `null` when unregistered |
| `drep."<drepid>".date` | string | `add-drep` | display | RFC-5322 timestamp |
| `drep."<drepid>".drepStateJSON` | array | `add-drep` | `21b`, `21d` | Single-DRep state: `[]` when not registered, else `[credential, state]` |
| `tokenMetaServer."<subject>"` | object | `add` | token-registry display of offline scripts | `{"name": {...}, "ticker": {...}}` from the registry, `signatures` and `sequenceNumber` removed; `<subject>` is policy id plus hex asset name, no dot |
| `transactions[]` | array | every offline transaction script (append), `execute` (delete one), `cleartx` | `execute`, display | Queue of signed transactions, see SPO-Ptransfer-OUT-006 |
| `history[]` | array | every writer | display | `{"date": <RFC-5322>, "action": <text>}`, append-only except `clearhistory` |
| `files."<path>"` | object | `attach`, `05c`, `05d`, `0x` | `extract` | `{"date", "size", "base64"}`, key is the file path as given at attach time |

## Snapshot (online writers)

- **SPO-Ptransfer-PRE-001** `new`, `clear` (alias of `new`), `add`, `add-drep` and `execute` refuse with exit 1 in offline work mode, and with exit 1 when the online or light node is not fully synced. (src: 01_workOffline.sh:L50-L58, 01_workOffline.sh:L59-L66)
- **SPO-Ptransfer-OUT-001** `new` (and its alias `clear`) discards the previous content entirely and writes a new document that contains only `general`, `protocol`, and a `history` with one entry `new file created - <workMode> mode`. Addresses, DReps, token metadata, queued transactions and attached files are lost. (src: 01_workOffline.sh:L141-L186)
- **SPO-Ptransfer-OUT-002** `protocol.parameters` is, in online mode, the output of `cardano-cli query protocol-parameters` merged with three governance extras: `committee`, `constitution`, `prevActionIDs` (from `query gov-state`; each falls back to `{}` when the query fails) and `eraHistory` (from `query era-history`; falls back to `{}`), all keys sorted. In light mode it is the light-mode parameters document unchanged. (src: 01_workOffline.sh:L148-L170, 01_workOffline.sh:L188-L225, 00_common.sh:L552)
- **SPO-Ptransfer-OUT-003** `protocol.era` is the lower-case era reported by the node (`query tip`), or by the light-mode parameters document (`.sposcriptsLightMode.lastTip.era`). If neither is known (the query printed nothing) it is the literal `auto`. In light mode a light-mode document without `lastTip.era` stores the literal `"null"`, not `auto` (SPO-Cconf-OUT-005). (src: 01_workOffline.sh:L178-L179, 00_common.sh:L650-L658)
- **SPO-Ptransfer-OUT-004** Before every `add` and `add-drep` the snapshot context is refreshed: `general.onlineCLI`, `general.onlineNODE`, `protocol.parameters` and `protocol.era` are overwritten with current values, so a later `add` makes the whole snapshot's parameters newer than the UTxO data of earlier `add`s. Other keys are kept. (src: 01_workOffline.sh:L188-L225)
- **SPO-Ptransfer-OUT-005** `add <name>` for a payment address queries its UTxOs (online: node; light: Koios) and stores `address."<bech32>"` with `name`, `totalamount`, `totalassetscnt`, `date`, `used: "no"`, `type: "payment"` and `utxoJSON`. `utxoJSON` maps `"<txhash>#<index>"` to `{"address": <bech32>, "value": {"lovelace": "<n>", "<policyid>": {"<assethex>": "<n>"}}, "datumhash": <hex>}`; all amounts are **strings**, `datumhash` is present only when the output carries one. Re-adding an address overwrites those fields and resets `used` to `no`. An address without UTxOs is refused with exit 1. (src: 01_workOffline.sh:L268-L302, 01_workOffline.sh:L425-L431, 00_common.sh:L1013-L1105)
- **SPO-Ptransfer-OUT-006** `add <name>` for a stake address (an address of stake type) queries its stake-address-info and stores `address."<bech32>"` with `name`, `totalamount` (sum of `rewardAccountBalance`), `date`, `used: "no"`, `type: "stake"` and `rewardsJSON` (the query result as an array). A stake address that is not registered on chain is refused with exit 1; an address of any other type is refused with exit 1. (src: 01_workOffline.sh:L449-L535, 01_workOffline.sh:L474, 01_workOffline.sh:L532)
- **SPO-Ptransfer-OUT-007** `add <name>.drep` reads the DRep id from `<name>.id` (it must be a valid bech32 string, else exit 1), queries the DRep state, and stores `drep."<drepid>"` with `name`, `deposit`, `date` and `drepStateJSON`. An unregistered DRep is stored too (`drepStateJSON` empty array, `deposit` null). (src: 01_workOffline.sh:L552-L617)
- **SPO-Ptransfer-OUT-008** For each asset type found by `add` of a payment address, when the token-registry query is enabled and returns a name or ticker, `tokenMetaServer."<subject>"` is stored; entries are merged, never removed. (src: 01_workOffline.sh:L405-L416)

> **Port, 2026-11-16:** `tokenMetaServer` is not written (no registry port); a file that has the object keeps it through every rewrite. The citation of this id by the DRep reader of `transferfile` was a mis-citation of SPO-Ptransfer-OUT-007 and is corrected.
- **SPO-Ptransfer-OUT-009** After writing, `add` and `add-drep` read the stored `utxoJSON`, `rewardsJSON` or `drepStateJSON` back and compare it with what was written. A mismatch prints an error and the script ends normally (exit 0). (src: 01_workOffline.sh:L436-L446, 01_workOffline.sh:L517-L527, 01_workOffline.sh:L606-L616)

## Queue (offline writers)

- **SPO-Ptransfer-OUT-010** Every offline transaction script appends one object to `transactions[]` with the common fields `date` (RFC-5322), `type`, `era` (copy of `protocol.era`), `fromAddr` (name of the paying address), `sendFromAddr` (its bech32), `toAddr` (name of the destination or, for certificate scripts, again the paying address), `sendToAddr` (bech32) and `txJSON` (the signed transaction text envelope, embedded as an object `{type, description, cborHex}`). The per-type extra fields and the `type` strings are in the table below. (src: 01_sendLovelaces.sh:L684-L694, 06_regDelegationCert.sh:L689-L700)
- **SPO-Ptransfer-OUT-011** The same script appends to `history[]` one entry describing the action and sets `general.offlineCLI` to its `cardano-cli` version, then rewrites the whole file. (src: 01_sendLovelaces.sh:L696-L698, 06_regDelegationCert.sh:L702-L704)
> **Observed 2026-11-16 (cardano-cli 11.2.3.0):** the `txJSON` of a queued payment is `{"type": "Tx ConwayEra", "description": "Ledger Cddl Format", "cborHex": ...}`, and `general.offlineCLI` is the bare version `11.2.3.0`. The port's `transferfile` adapter writes the same entry (`spo/test/parity/send_lovelaces_test.go` compares the whole file with upstream's but for the dates).

- **SPO-Ptransfer-OUT-012** The script reads the file back, takes `transactions[-1].txJSON` and compares it with the object it stored. On a mismatch it prints an error telling the operator to retry or regenerate the file, but still ends normally (exit 0); on a match it shows the file summary. (src: 01_sendLovelaces.sh:L699-L706, 06_regDelegationCert.sh:L705-L712)
- **SPO-Ptransfer-OUT-013** The queue is append-only from the offline side. Several transactions from the same address can be queued; the second one is built from the same snapshot UTxOs as the first and will conflict when submitted (the first `execute` changes the UTxO set, so the second `execute` refuses at SPO-Ptransfer-PRE-004). (src: 01_sendLovelaces.sh:L282-L285, 01_workOffline.sh:L696-L698)

**Transaction entry types.** `Extras` are the fields added to the common ones. "Executable" says whether `01_workOffline.sh execute` has a branch for the type.

| `type` | Appended by | Extras | `execute` branch |
| --- | --- | --- | --- |
| `Transaction` | `01_sendLovelaces`, `01_sendAssets`, `24b_regVote`, `25b_regAction` | none (`24b`/`25b`: `toAddr` is the paying address) | payment UTxO check |
| `Asset-Minting`, `Asset-Burning` | `11a_mintAsset`, `11b_burnAsset` | none | payment UTxO check (same branch as `Transaction`) |
| `Withdrawal` | `01_claimRewards` | `stakeAddr` (name), `stakingAddr` (bech32) | payment UTxO check and rewards-state check |
| `StakeKeyRegistration` | `03b_regStakingAddrCert` | `stakeAddr` (name) | payment UTxO check |
| `StakeKeyDeRegistration` | `08b_deregStakingAddrCert` | `stakeAddr` (name) | payment UTxO check |
| `DelegationCertRegistration` | `06_regDelegationCert` | `delegName` | payment UTxO check |
| `VoteDelegationCertRegistration` | `22b_regVoteDelegCert` | `delegName` | payment UTxO check |
| `DRepIDRegistration` | `21b_regDRepCert` | `drepName` | payment UTxO check |
| `DRepIDRetirement` | `21d_retDRepCert` | `drepName` | payment UTxO check |
| `PoolRegistration`, `PoolReRegistration` | `05c_regStakepoolCert` | `poolMetaTicker`, `regProtectionKey`, `poolMetaUrl`, `poolMetaHash` | payment UTxO check, ticker protection check, metadata hash check |
| `PoolRetirement` | `07b_deregStakepoolCert` | `poolMetaTicker` | payment UTxO check |
| `CommitteeAuthCertRegistration` | `23c_regComAuthCert` (unreachable, see below) | `comColdName`, `comHotName` | **none** |
| `CommitteeResignationCert` | `23e_retComColdKeys` (unreachable, see below) | `comColdName` | **none** |

(src for the type strings and extras: 01_sendLovelaces.sh:L687-L694, 01_sendAssets.sh:L820-L828, 01_claimRewards.sh:L760-L769, 03b_regStakingAddrCert.sh:L700-L708, 05c_regStakepoolCert.sh:L1124-L1136, 06_regDelegationCert.sh:L692-L700, 07b_deregStakepoolCert.sh:L565-L574, 08b_deregStakingAddrCert.sh:L686-L695, 11a_mintAsset.sh:L662-L671, 11b_burnAsset.sh:L663-L672, 21b_regDRepCert.sh:L816-L825, 21d_retDRepCert.sh:L693-L702, 22b_regVoteDelegCert.sh:L689-L698, 23c_regComAuthCert.sh:L641-L652, 23e_retComColdKeys.sh:L702-L712, 24b_regVote.sh:L759-L768, 25b_regAction.sh:L954-L963)

- **SPO-Ptransfer-INV-001** The `type` strings above are the closed vocabulary that `execute` dispatches on. A queued entry whose type has no branch (or any unknown string) is reported as an unknown transaction type, is **not** submitted and **stays in the queue**. `execute` also accepts `DRepIDReRegistration` (it shares the branch of `DRepIDRegistration` and `DRepIDRetirement`), a type that no upstream script writes (`21b` hard-codes `DRepIDRegistration`); it is accepted but never produced, as in SPO-01workOffline-INV-006. (src: 01_workOffline.sh:L966, 01_workOffline.sh:L677-L1215, 01_workOffline.sh:L1211-L1214)
- **SPO-Ptransfer-INV-003** `23c_regComAuthCert` and `23e_retComColdKeys` contain code that would queue the two committee types, but both scripts stop in offline mode before reaching it (they print that offline mode is not supported yet and exit 0). No committee entry is ever written, and the missing `execute` branch is not reachable from upstream scripts. (src: 23c_regComAuthCert.sh:L206, 23e_retComColdKeys.sh:L216, 23c_regComAuthCert.sh:L641-L652, 23e_retComColdKeys.sh:L702-L712)
  > **Upstream quirk:** committee operations are unavailable offline. A port gives them an offline path and an executor.

## Execute

- **SPO-Ptransfer-IF-002** `execute [n]` takes the 1-based position `n` of a queued transaction, default 1. A position outside `1..count` is refused with exit 1. An empty queue prints a notice and exits 0. (src: 01_workOffline.sh:L56, 01_workOffline.sh:L635-L648)
- **SPO-Ptransfer-PRE-002** A difference between the offline machine's `general.offlineCLI` and the current `cardano-cli` version, or between the entry's `era` and the node's current era, prints a warning and execution continues. (src: 01_workOffline.sh:L645-L660)
- **SPO-Ptransfer-PRE-003** The entry's `txJSON` is written to `<tempDir>/<fromAddr basename>.tmp.txfile` and submitted from there; the file is removed at the end. (src: 01_workOffline.sh:L669-L673, 01_workOffline.sh:L1218)
- **SPO-Ptransfer-PRE-004** Before submitting any type with a branch, `execute` queries the paying address's UTxOs live and compares them with `address."<sendFromAddr>".utxoJSON` of the snapshot. Any difference is refused with exit 1 (the snapshot is stale). The comparison is a text equality of the two JSON renderings. (src: 01_workOffline.sh:L696-L698, 01_workOffline.sh:L764-L766, 01_workOffline.sh:L852-L854, 01_workOffline.sh:L919-L921, 01_workOffline.sh:L986-L988, 01_workOffline.sh:L1056-L1058, 01_workOffline.sh:L1163-L1165)
- **SPO-Ptransfer-PRE-005** `Withdrawal` additionally queries the stake address's reward state live and compares it with `address."<stakingAddr>".rewardsJSON`; a difference is refused with exit 1. (src: 01_workOffline.sh:L745-L786)
- **SPO-Ptransfer-PRE-006** `PoolRegistration` and `PoolReRegistration` additionally (a) ask the ticker-protection web service whether `poolMetaTicker` with `regProtectionKey` is allowed (an unreachable service lets it pass; an answer other than `OK` is refused with exit 1) and (b) download `poolMetaUrl`, require valid JSON, compute its metadata hash and require equality with `poolMetaHash` (a download failure, invalid JSON or a mismatch is refused with exit 1). (src: 01_workOffline.sh:L1035-L1100)
- **SPO-Ptransfer-PR-001** After the checks, `execute` shows the entry and asks "Does this look good for you, continue?" with default **No**. `ENV_SKIP_PROMPT` is not honoured. A "no" ends the script with no change to the file. (src: 01_workOffline.sh:L703, 01_workOffline.sh:L791, 01_workOffline.sh:L860, 01_workOffline.sh:L927, 01_workOffline.sh:L994, 01_workOffline.sh:L1104, 01_workOffline.sh:L1171, 00_common.sh:L754-L786)
- **SPO-Ptransfer-EXT-001** On confirmation the transaction is submitted: online with `cardano-cli <era> transaction submit --tx-file`, light via the Koios submit call (see `Ptx`). A submit failure ends the script and the entry stays in the queue. The exit code is cardano-cli's for an online submit (`checkError`), but **0** in light mode and for a failed live UTxO or stake query (`exit $?` after an `echo`), as in SPO-01workOffline-PRE-013. (src: 01_workOffline.sh:L706-L731, 01_workOffline.sh:L684, 01_workOffline.sh:L689, 01_workOffline.sh:L724)
- **SPO-Ptransfer-OUT-014** After a successful submit the paying address entry gets `used: "yes"`, for the types `Transaction`, `Asset-Minting`, `Asset-Burning` and `Withdrawal` the destination entry too when `address."<sendToAddr>"` exists (`Withdrawal` also marks the stake address entry; the certificate types mark the paying address only), `history[]` gets `tx submit <txid> - ...`, `transactions[<n-1>]` is **deleted**, and the file is rewritten. The remaining queue count is shown. (src: 01_workOffline.sh:L732-L737, 01_workOffline.sh:L820-L826, 01_workOffline.sh:L889-L892, 01_workOffline.sh:L956-L959, 01_workOffline.sh:L1023-L1026, 01_workOffline.sh:L1133-L1136, 01_workOffline.sh:L1200-L1203)
- **SPO-Ptransfer-OUT-015** `cleartx` deletes `transactions` entirely and appends a history entry; it never submits. (src: 01_workOffline.sh:L108-L117)

## History and attachments

- **SPO-Ptransfer-OUT-016** `clearhistory` deletes `history` and then appends a single entry `history cleared`. (src: 01_workOffline.sh:L119-L128)
- **SPO-Ptransfer-OUT-017** `attach <file>` stores `files."<file>"` with `date`, `size` (bytes, as a string) and `base64` (the whole file on one line), appends a history entry and rewrites the file. It requires a valid transfer file (SPO-Ptransfer-IN-001) and an existing source file. Attaching the same path again overwrites that entry. (src: 01_workOffline.sh:L86-L91, 01_workOffline.sh:L241-L256)
- **SPO-Ptransfer-OUT-018** `05c` (pool metadata and extended metadata files), `05d` (witness files) and `0x_importHelper` (the exported pool info) offer to attach their file after writing; each offer asks with default **No** and uses the same entry shape. (src: 05c_regStakepoolCert.sh:L1139-L1155, 05d_poolWitness.sh:L98-L108, 05d_poolWitness.sh:L327-L337, 0x_importHelper.sh:L134-L160)
- **SPO-Ptransfer-OUT-019** `extract` writes every attached file to its `files` key path: an existing target is **skipped** (never overwritten), missing directories are created, the base64 is decoded into the file, and on success a history entry is appended and the `files` entry removed. A failed write leaves the entry. (src: 01_workOffline.sh:L1243-L1291)
- **SPO-Ptransfer-OUT-020** `clearfiles` deletes `files` entirely and appends a history entry. (src: 01_workOffline.sh:L130-L139)
- **SPO-Ptransfer-SEC-001** `extract` trusts the key of each `files` entry as a destination path, including absolute paths and `..` segments, and creates its parent directories. A transfer file from an untrusted party can write files anywhere the user can. (src: 01_workOffline.sh:L1262-L1275)
  > **Upstream quirk:** no path confinement. A port confines the destination to the workspace and rejects absolute or parent-relative keys.
- **SPO-Ptransfer-SEC-002** The file holds no signing key. It does hold signed transactions, UTxO and reward balances of the added addresses, DRep state, and any attached files (for `05d` witness files these contain signed witnesses together with the transaction body). The port treats it as confidential but not secret. (src: 01_workOffline.sh:L425-L431, 05d_poolWitness.sh:L98-L108)
- **SPO-Ptransfer-INV-002** Every writer rewrites the whole file by shell redirection, not atomically, and keeps no lock; two concurrent writers lose updates and a crash can truncate the file. The file's mode is not touched. (src: 01_workOffline.sh:L436, 01_sendLovelaces.sh:L698)

## Domain mapping

Use cases: `PrepareOfflineSnapshot` (new, add, add-drep), `QueueOfflineTransaction` (the offline branch of every transaction use case), `ExecuteQueuedTransaction` (execute), `CarryFiles` (attach, extract). Aggregate: `TransferBundle`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Transport` | `snapshot(addresses, extras)` | `new`/`add`/`add-drep` |
| `Transport` | `importSnapshot()` | `readOfflineFile`, offline `ChainQuery` adapter |
| `Transport` | `enqueueTx(signedTx)` | Offline append with readback |
| `Transport` | `dequeueTx(n)` | Delete after successful `execute` |
| `Transport` | `attach(file)` / `extract(file)` | Carry small files |
| `Transport` | `clear(tx\|history\|files)` *(new)* | `cleartx`, `clearhistory`, `clearfiles` |
| `ChainQuery` | `protocolParameters()`, `utxos(address)`, `rewardAccount(stakeAddress)`, `drepState(drepId)` | Online sources of the snapshot; offline adapter serves the same from the file |
| `Submitter` | `submit(signedTx) -> txId` | `execute` |
| `Directory` | `tokenMetadata(subject)` | Registry names cached in `tokenMetaServer` |
| `Directory` | `fetchUrl(url)` | Pool metadata hash check in `execute` |
| `Directory` | `checkTickerProtection(ticker, key)` *(new)* | The ticker-protection service in `execute` |
| `UI` | `confirm(prompt, default)` | `execute` confirmation |

## Port notes

* Model the file as a versioned schema with typed entries; keep reading upstream files unchanged (import), write the same shape when a carry bag is wanted (`Transport` file adapter), and offer a secure-channel adapter for server mode.
* Compare UTxO and reward snapshots structurally, not as text (SPO-Ptransfer-PRE-004).
* Give every transaction `type` an executor (SPO-Ptransfer-INV-001), write atomically (SPO-Ptransfer-INV-002), confine `extract` (SPO-Ptransfer-SEC-001).
* The queue index is positional (1-based) and shifts after each `execute`; the port uses stable entry ids and keeps the position syntax only as an alias.
* `used` is advisory display data; do not rely on it for decisions.
* Compare the two stored `txJSON` values semantically when reading back, and treat a failed readback as an error exit.

## Open questions

* The exact JSON a Koios-backed light mode stores in `rewardsJSON` and `drepStateJSON` (field names and nesting) comes from the `00_common.sh` light-mode functions, not from `cardano-cli`; the `Clight` common spec settles whether the two sources are interchangeable for the readers listed above.
* The text of the 'ticker protection' service reply other than `OK` is not specified by source; a test against the live service cannot be reproduced offline.
* **Reading a stake address from the snapshot (2026-11-16).** `add` refuses an unregistered stake address (SPO-Ptransfer-OUT-006), so an address that has no entry in the file is *not included*, not *not registered*. The Go snapshot reader answers Unknown for it and "none" only for an entry whose `rewardsJSON` is `[]`. The entry is read as `03c`, `08a` and `01_claimRewards` read it (`.[0].rewardAccountBalance`, `.stakeRegistrationDeposit`, `.stakeDelegation.stakePoolBech32`, `.voteDelegation`, `.govActionDeposits`); a field that is absent is Unknown and not defaulted. A DRep entry is `drep."<id>".drepStateJSON`, `[]` for a DRep that is not registered.
