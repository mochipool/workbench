+++
id = "01workOffline"
kind = "script"
title = "Maintain the offline transfer file and submit queued transactions"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["air-gap-transfer", "chain-access"]
use_cases = ["PrepareOfflineSnapshot", "ExecuteQueuedTransaction", "CarryFiles", "InspectTransferBundle", "ClearTransferBundle"]
depends_on = ["Ptransfer", "Coffline", "Cchain", "Clight", "Cutxo", "Cconv", "Caddr", "Cconf", "Cui", "Pfiles", "Ptx"]

upstream_path = "cardano/mainnet/01_workOffline.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "b18308fa50ddab8a35c96310f2c92ee4c81b3fdc7fe4c4c5e36522c039805f91"
upstream_lines = 1299
uses_common = [
  "ask",
  "checkError",
  "convertToADA",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "generate_UTXO",
  "get_NodeEra",
  "get_addressEra",
  "get_addressType",
  "get_currentSync",
  "queryLight_UTXO",
  "queryLight_drepInfo",
  "queryLight_stakeAddressInfo",
  "readOfflineFile",
  "showOfflineFileInfo",
  "showProcessAnimation",
  "stopProcessAnimation",
  "submitLight",
  "trimString",
]
cli_commands = [
  "query drep-state",
  "query era-history",
  "query gov-state",
  "query protocol-parameters",
  "query stake-address-info",
  "query utxo",
  "stake-pool metadata-hash",
  "transaction submit",
  "transaction txid",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "tokenMetaServer",
]
env_vars = []
+++

# 01_workOffline: Maintain the offline transfer file and submit queued transactions

The tool for the air gap. It is the only script that writes the **snapshot** half of the transfer file (`offlineTransfer.json`, schema in [Ptransfer](../patterns/Ptransfer.md)) and the only one that **submits** what the offline machine queued. The other actions carry small files in the file (`attach`, `extract`), show it (`info`) and empty parts of it (`cleartx`, `clearhistory`, `clearfiles`). One invocation runs exactly one action. This spec states what each action does, in which work modes, what it refuses, and how it changes the file; the shape and meaning of the file's keys are in Ptransfer and are cited, not restated. Every transaction script's offline branch (the *queue* half) is specified in [Ptx](../patterns/Ptx.md).

Display functions (`showOfflineFileInfo` after every write, the per-UTxO and per-asset tables of `add`, the progress animation) are display only and are not specified. `execute` ends in `exit 0` for every outcome except the refusals listed in Failures.

Reading guide: `new` and `clear` are one action. `add` splits into three branches that share the context refresh: a payment address, a stake address, a DRep id.

## Interface

- **SPO-01workOffline-IF-001** The first argument selects the action. The accepted words are `new`, `clear` (alias of `new`), `add`, `info`, `execute`, `attach`, `extract`, `cleartx`, `clearhistory` and `clearfiles`. The match is exact and case-sensitive. (src: L45-L50, L59, L86)
- **SPO-01workOffline-IF-002** Without arguments, or with any other first word, prints the usage to stderr and exits 1. (src: L44, L92)
- **SPO-01workOffline-IF-003** `execute [n]` and `new`/`clear` read the second argument only when exactly two arguments are given; the value is the queue position `n` (see SPO-Ptransfer-IF-002), default 1. `new` and `clear` never use it. With three or more arguments the position is 1 and the rest is ignored. (src: L56)
- **SPO-01workOffline-IF-004** `add` needs exactly one name argument. Without it (or with more than one extra argument) it prints "missing name", the usage, and exits 1. (src: L64, L81-L83)
- **SPO-01workOffline-IF-005** For `add`, a name whose base name contains the text `.drep` anywhere selects the DRep branch (`add-drep`). The DRep name is the argument with a trailing `.id` removed and a leading `./` dropped, and the file `<drepName>.id` must exist as a regular file, else exit 1 with the usage. (src: L67-L73)
- **SPO-01workOffline-IF-006** Any other `add` name selects the address branch. The address name is the argument with a trailing `.addr` removed and a leading `./` dropped (a directory part is kept), and `<addrName>.addr` must exist as a regular file, else exit 1 with the usage. The `<addrName>` string is what the snapshot stores as `name`. (src: L75-L78, L425, L507)
- **SPO-01workOffline-IF-007** `attach <file>` needs exactly one file argument that is an existing regular file, else exit 1 with the usage. This is checked before the transfer file is read. (src: L86-L90)
- **SPO-01workOffline-IF-008** `info`, `extract`, `cleartx`, `clearhistory` and `clearfiles` take no argument; extra arguments are ignored. (src: L46-L49)

## Inputs

- **SPO-01workOffline-IN-001** Before any action runs, the transfer file named by `offlineFile` (default `./offlineTransfer.json`, SPO-Ptransfer-IF-001) is read. A missing file, or a file with no content, is treated as `{}`. This is not `readOfflineFile`: it does not require protocol parameters (SPO-Ptransfer-IN-002). (src: L97-L104)
- **SPO-01workOffline-IN-002** `add` reads the address text from `<addrName>.addr` (whole content, trailing newlines trimmed) or the DRep id from `<drepName>.id`. (src: L270, L554)
- **SPO-01workOffline-IN-003** Settings read: `queryTokenRegistry` and `tokenMetaServer` (token registry lookups of `add`), `transactionExplorer` (a tracking link shown after a submit, display only), `tempDir` (the scratch file of `execute`), the `cardano-cli` and `cardano-node` versions found by the prologue (stored by `new`/`add`, compared by `execute`), and the work mode. (src: L171-L176, L407-L408, L646, L670, L717)

## Behaviour

1. **Gate by work mode and sync state.**
   - **SPO-01workOffline-PRE-001** `new`, `clear`, `add` and `execute` refuse with exit 1 in offline work mode ("you have to be in ONLINE or LIGHT mode"). `info`, `attach`, `extract`, `cleartx`, `clearhistory` and `clearfiles` run in every mode. See SPO-Ptransfer-PRE-001. (src: L50-L52, L59-L61)
   - **SPO-01workOffline-PRE-002** The same four actions refuse with exit 1 when `get_currentSync` is not `synced` (SPO-Cchain-OUT-004). Light mode counts as synced whenever Koios answers the tip query (SPO-Cchain-MODE-010). (src: L53, L62)
   - **SPO-01workOffline-INV-001** The two gates run before the remaining argument checks and before the transfer file is read. In offline mode `add` with a bad name therefore reports the mode error, not the name error. (src: L50-L63, L98)
2. **Load the transfer file.**
   - **SPO-01workOffline-PRE-003** A file that exists but is not valid JSON is refused with exit 1 ("please delete it"), for every action including `new`. The operator must remove it by hand. (src: L98-L100)
3. **Run the action.** Exactly one of the following runs; each section says how it ends.

### cleartx, clearhistory, clearfiles

- **SPO-01workOffline-OUT-001** `cleartx` removes the whole `transactions` queue without submitting anything and appends the history entry `cleared all transactions`. Effects as SPO-Ptransfer-OUT-015. (src: L108-L117)
- **SPO-01workOffline-OUT-002** `clearhistory` removes the whole `history` and then appends the single history entry `history cleared`. Effects as SPO-Ptransfer-OUT-016. (src: L119-L128)
- **SPO-01workOffline-OUT-003** `clearfiles` removes the whole `files` object and appends the history entry `attached files cleared`. Effects as SPO-Ptransfer-OUT-020. (src: L130-L139)
- **SPO-01workOffline-INV-002** The three actions ask no confirmation, change no other key (the `used` flags of addresses stay), work in every work mode, and exit 0 after writing the file. On a missing file they write a file that holds only the history entry (SPO-Ptransfer-IN-002). (src: L108-L139)

### new and clear

- **SPO-01workOffline-OUT-004** Discards the previous content and writes a fresh document with `general`, `protocol` and a one-entry `history` (SPO-Ptransfer-OUT-001). The history entry reads `new file created - <workMode> mode`. Exits 0. (src: L141-L146, L171-L186)
- **SPO-01workOffline-EXT-001** Online: the protocol parameters are `cardano-cli <era> query protocol-parameters`; the governance extras come from `cardano-cli <era> query gov-state` (stderr discarded), reduced to `{committee, constitution, prevActionIDs}` where `prevActionIDs` is `.nextRatifyState.nextEnactState.prevGovActionIds`, and replaced by `{}` when the query or the reduction yields nothing; the era history comes from `cardano-cli <era> query era-history --out-file /dev/stdout` (stderr discarded), wrapped as `{"eraHistory": <output>}`, and replaced by `{"eraHistory": {}}` when empty. The three documents are merged and all keys sorted (SPO-Ptransfer-OUT-002). (src: L148-L162)
- **SPO-01workOffline-EXT-002** Light: the parameters are the light-mode parameters document held by the prologue (SPO-Cconf-EXT-001), stored unchanged. (src: L164-L166)
- **SPO-01workOffline-OUT-005** `general.onlineCLI` is the local `cardano-cli` version. `general.onlineNODE` is the local `cardano-node` version in online mode and the literal `light` in light mode. `protocol.era` is the era from `get_NodeEra` (SPO-Ptransfer-OUT-003). (src: L171-L179)

> **Upstream quirk:** The check after the parameter query tests the status of the last statement of the branch (the merging `jq`), not of `query protocol-parameters`. A failed query is therefore not detected by that check; the merge sees empty input and the script goes on to write a damaged file. The sync gate (SPO-01workOffline-PRE-002) makes this unlikely in practice. (src: L169, L213)

### add (shared context refresh)

- **SPO-01workOffline-OUT-006** Before the per-address work, the snapshot context (`general.onlineCLI`, `general.onlineNODE`, `protocol.parameters`, `protocol.era`) is refreshed from the same queries and with the same values as `new`, in memory only (SPO-Ptransfer-OUT-004, SPO-01workOffline-EXT-001, SPO-01workOffline-EXT-002, SPO-01workOffline-OUT-005). (src: L188-L224)
- **SPO-01workOffline-INV-003** Nothing is written until the address or DRep entry is complete. Every refusal before the write (no funds, unregistered stake address, unknown address type, invalid DRep id) leaves the file exactly as it was, including its older protocol parameters. (src: L302, L436, L474, L517, L532, L558, L607)
- **SPO-01workOffline-OUT-007** `add` does not need a prior `new`: on a missing or empty file it creates the file with `general`, `protocol`, the entry and a history entry, and the offline scripts accept it (SPO-Ptransfer-IN-001). Entries of other addresses are kept, and `new` is the only way to drop them. (src: L98-L104, L188-L224, L436)
- **SPO-01workOffline-PRE-004** A failing chain query in `add`, in the branches below, prints the error text and ends the script **with exit status 0**: the status passed to `exit` is read after an `echo` has reset it. The file is not changed. (src: L288, L295, L462, L468, L568, L574)

> **Upstream quirk:** The exit status after a failed query is 0, so a caller cannot tell a failed `add` from a successful one except by reading the output. The same idiom ends `execute` in SPO-01workOffline-PRE-013. A port exits non-zero.

### add, payment address

- **SPO-01workOffline-EXT-003** The address type must be `payment` (SPO-Caddr-OUT-002). The UTxOs come from `cardano-cli <era> query utxo --output-text --address <addr>` (stderr merged into the captured text) in online mode and from `queryLight_UTXO` in light mode, and are converted by `generate_UTXO` (SPO-Cutxo-IF-001, SPO-Cutxo-OUT-001). (src: L270-L299)
- **SPO-01workOffline-OUT-008** `totalamount` is the sum of the lovelace of all UTxOs, and `totalassetscnt` the number of distinct asset ids (policy id plus asset name) found in them. Amounts of the same asset in several UTxOs are summed, with arbitrary precision. (src: L305-L316, L319-L355, L388, L426-L427)
- **SPO-01workOffline-EXT-004** When `queryTokenRegistry` is on, each distinct asset id is looked up with `GET <tokenMetaServer>/<policy><assetNameHex>` (`curl -sL -m 20`, no dot between policy and name), in both online and light mode. Name and ticker are read from `.name.value` and `.ticker.value`; when either is present the entry of SPO-Ptransfer-OUT-008 is stored. A failed lookup is ignored. (src: L407-L415)
- **SPO-01workOffline-OUT-009** The address entry (SPO-Ptransfer-OUT-005) is stored under the address text with `name`, `totalamount`, `totalassetscnt`, `date`, `used` = `no`, `type` and `utxoJSON`, and the history entry `added utxo-info for '<name>'` is appended. A second `add` of the address overwrites these fields and resets `used`. (src: L425-L433)

> **Port, 2026-11-16:** a datum hash is stored when the reader states one; upstream's light mode drops it (SPO-Clight-OUT-005), its online mode keeps it. A policy that comes back non-adjacently is merged under one key (SPO-Cutxo-OUT-002 would write a duplicate key). Recorded against the live preview service (`spo/test/parity/testdata/airgap`), `new`, `add` of a payment address (9 UTxOs, one asset) and `add` of a registered, delegated stake address are byte-equal to the port but for the `date` values.

### add, stake address

- **SPO-01workOffline-EXT-005** The address type must be `stake` (SPO-Caddr-OUT-002). The reward state comes from `cardano-cli <era> query stake-address-info --address <addr>` (stderr discarded) in online mode, normalised by `jq .`, and from `queryLight_stakeAddressInfo` in light mode (SPO-Clight-OUT-008). (src: L449-L470)
- **SPO-01workOffline-PRE-005** An empty result array means the stake address is not registered: refused with exit 1 ("register it first"). See SPO-Ptransfer-OUT-006. (src: L472-L476)
- **SPO-01workOffline-OUT-010** `totalamount` is the sum of `rewardAccountBalance` over all entries of the result. The entry (SPO-Ptransfer-OUT-006) stores `name`, `totalamount`, `date`, `used` = `no`, `type` and `rewardsJSON`, and the history entry `added stake address rewards-state for '<name>'` is appended. (src: L478-L488, L506-L514)
- **SPO-01workOffline-PRE-006** An address that is neither of type `payment` nor `stake` is refused with exit 1 ("address type unknown"). (src: L530-L533)

### add, DRep

- **SPO-01workOffline-PRE-007** The id read from `<drepName>.id` must decode as bech32 (`bech32` tool exit status); otherwise exit 1. (src: L554-L558)
- **SPO-01workOffline-EXT-006** The DRep state comes from `cardano-cli <era> query drep-state --drep-key-hash <hash> --drep-script-hash <hash> --include-stake` (stderr merged into the captured text; `<hash>` is the bech32-decoded id, passed as both a key hash and a script hash) in online mode, and from `queryLight_drepInfo <id>` in light mode (SPO-Clight-OUT-015). In both modes the outer array is removed (`.[0] // []`): the stored state is `[]` when the DRep is not registered. (src: L563-L577)
- **SPO-01workOffline-OUT-011** The entry (SPO-Ptransfer-OUT-007) is stored under the id text exactly as read, with `name` = the DRep name including its `.drep` part, `deposit` (`.[1].deposit`, null when unregistered), `date` and `drepStateJSON`, and the history entry `added drep-id info for '<name>'` is appended. (src: L579-L584, L598-L604)

### add, write and read back

- **SPO-01workOffline-OUT-012** After writing the whole file, `add` reads back the stored `utxoJSON`, `rewardsJSON` or `drepStateJSON` and compares it with what it wrote. A mismatch prints an error telling the operator to retry or delete the file; the script still exits 0 (SPO-Ptransfer-OUT-009). (src: L436-L446, L517-L527, L607-L616)

### info

- **SPO-01workOffline-INV-004** `info` shows the file (display only, SPO-Coffline-IN-001 to SPO-Coffline-IN-011) and then notices of the number of attached files and of pending transactions, if non-zero. It never writes, runs in every mode, tolerates a missing file (treated as empty) and exits 0. (src: L227-L239)

### attach

- **SPO-01workOffline-PRE-008** Needs a valid transfer file: it calls `readOfflineFile` (SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004), which exits 1 on a missing, unparsable or parameter-less file. It runs in every mode. See SPO-Ptransfer-IN-001. (src: L243)
- **SPO-01workOffline-OUT-013** Stores `files."<file as given>"` = `{date, size, base64}` and appends the history entry `attached file '<file>'`, as SPO-Ptransfer-OUT-017: `size` is the byte count as a string, `base64` the whole file on one line. The key is the path exactly as typed, including a leading `./`. A failure of the `jq` update ends with exit 1 and no write; success exits 0. (src: L244-L254)

> **Upstream quirk:** The base64 text is passed to `jq` as part of the program text on the command line, so the operating system's limit for one argument (128 KiB on Linux) bounds the attachable file at roughly 96 KB; larger files end in the "could not attach" refusal (exit 1). The script states no limit. The same applies to the offer in `0x_importHelper`. (src: L244)

### extract

- **SPO-01workOffline-OUT-014** `extract` takes the keys of `files` in ascending order. For each: an existing regular file at the key path is **skipped** and its entry kept; otherwise the parent directories are created, the base64 is decoded into the file, and on success the history entry `extracted file '<path>'` is appended, the entry is removed and the transfer file is rewritten at once. A failed decode leaves the entry in place and goes on to the next one (SPO-Ptransfer-OUT-019). (src: L1259-L1286)
> **Observed 2026-11-16 (cardano-cli 11.2.3.0, jq 1.8.2):** after the last entry is extracted `files` stays in the document as `{}`; `clearhistory` deletes `history` and appends it again, so it moves behind every other key; `cleartx` and `clearfiles` on a missing file write a file holding only `history`, which `attach` then refuses (exit 1) for its missing parameters. The port reproduces all three byte for byte (`TestWorkOfflineFileActionsMatchUpstream`).
- **SPO-01workOffline-INV-005** It reports "no attached files" and exits 0 when `files` is empty, runs in every mode, tolerates a missing file, creates files with the process's default mode (no `0400`), and ends with exit 0 even when entries were skipped or failed. A notice lists how many entries remain. (src: L1246-L1250, L1273-L1274, L1288-L1290)
- **SPO-01workOffline-SEC-001** The destination of every entry is its key, used as given (SPO-Ptransfer-SEC-001): absolute paths and `..` segments are honoured. (src: L1262, L1270-L1274)

> **Upstream quirk:** The decode writes through a shell redirection, so a failed decode has already created or truncated the target file. The next run then skips it, because it exists. (src: L1273-L1274, L1270)

### execute

The queue position `n` (SPO-Ptransfer-IF-002) names one entry. `execute` handles that entry only, then prints how many remain. The shared rules are SPO-Ptransfer-PRE-002 to SPO-Ptransfer-PRE-006, SPO-Ptransfer-PR-001, SPO-Ptransfer-EXT-001, SPO-Ptransfer-OUT-014 and SPO-Ptransfer-INV-001; this section adds the order and the script-specific facts.

1. **Pre-checks.**
   - **SPO-01workOffline-PRE-009** With an empty queue prints a notice and exits 0, before the position is validated, so `execute 99` on an empty queue also exits 0. (src: L641-L642, L648)
   - **SPO-01workOffline-PRE-010** A position that is not an integer from 1 to the queue length is refused with exit 1; a non-numeric word counts as 0. (src: L648)
   - **SPO-01workOffline-PRE-011** A difference between the stored `general.offlineCLI` and the local `cardano-cli` version, and between the entry's `era` and `get_NodeEra`, only warns (SPO-Ptransfer-PRE-002). (src: L645-L646, L658-L659)
2. **Materialise the entry.**
   - **SPO-01workOffline-OUT-015** The entry's `txJSON` is written to `<tempDir>/<basename of fromAddr>.tmp.txfile` (after removing an older file of that name) and that file is submitted. The write status is checked (exit with its code). See SPO-Ptransfer-PRE-003. (src: L661-L673)
3. **Dispatch on the entry's `type`.**
   - **SPO-01workOffline-INV-006** The types with a branch are `Transaction`, `Asset-Minting`, `Asset-Burning`, `Withdrawal`, `StakeKeyRegistration`, `StakeKeyDeRegistration`, `DelegationCertRegistration`, `VoteDelegationCertRegistration`, `DRepIDRegistration`, `DRepIDReRegistration`, `DRepIDRetirement`, `PoolRegistration`, `PoolReRegistration` and `PoolRetirement`. No upstream script writes `DRepIDReRegistration`; its branch is the same as the other two DRep types. Any other type prints "unknown transaction type", submits nothing, changes nothing and exits 0 (SPO-Ptransfer-INV-001). (src: L677, L743, L832, L899, L966, L1033, L1143, L1212-L1214)
   - **SPO-01workOffline-INV-007** Per type, the extra entry fields read are: `Withdrawal` reads `stakeAddr` and `stakingAddr`; the two stake-key types read `stakeAddr`; the two delegation types read `delegName`; the DRep types read `drepName`; the pool types read `poolMetaTicker`, and `PoolRegistration`/`PoolReRegistration` also `poolMetaUrl`, `poolMetaHash`, `regProtectionKey`. The names are for display and history only. (src: L745-L746, L834, L901, L968, L1035-L1038, L1145)
4. **Live checks, then confirmation.**
   - **SPO-01workOffline-EXT-007** Every branch re-queries the paying address (`sendFromAddr`) the way `add` does: `cardano-cli <era> query utxo --output-text --address <addr>` online (stderr merged), `queryLight_UTXO` in light mode, converted by `generate_UTXO` and normalised by `jq .`, and compares it with the stored snapshot as in SPO-Ptransfer-PRE-004. (src: L680-L698, L748-L766, L836-L854, L903-L921, L970-L988, L1040-L1058, L1147-L1165)
   - **SPO-01workOffline-EXT-008** `Withdrawal` also queries `cardano-cli <era> query stake-address-info --address <stakingAddr>` (stderr discarded; light: `queryLight_stakeAddressInfo`), normalised by `jq .`, and compares it with the stored `rewardsJSON` (SPO-Ptransfer-PRE-005). (src: L768-L785)
   - **SPO-01workOffline-PRE-012** `PoolRegistration` and `PoolReRegistration` run the ticker-protection check and the metadata-hash check of SPO-Ptransfer-PRE-006 after the UTxO comparison and **before** the confirmation, so they refuse with exit 1 without asking. (src: L1064-L1102, L1104)
   - **SPO-01workOffline-EXT-009** Ticker protection: `curl -m 20 -s` to the web service whose URL is stored in the script as hex escapes. It decodes to `https://my-ip.at/checkticker?ticker=<poolMetaTicker>&key=<regProtectionKey>`. A curl failure (service unreachable, timeout) lets the check pass with a notice. Otherwise the body must be exactly `OK`; any other body ends the script with exit 1. (src: L1065-L1076)
   - **SPO-01workOffline-EXT-010** Metadata check: downloads `poolMetaUrl` with `curl -sL` (no timeout, HTTP error pages are not treated as failures) to `<tempDir>/tmpmetadata.json`; a curl failure or a non-JSON body ends with exit 1. The hash is computed by `cardano-cli <era> stake-pool metadata-hash --pool-metadata-file` (a failure ends with its code) and must equal `poolMetaHash`; a mismatch prints both hashes and the remote file and exits 1. (src: L1082-L1101)
   - **SPO-01workOffline-PR-001** After the checks it shows the entry (type, era, date, names, addresses) and asks `Does this look good for you, continue ?`, default **No**. Declining skips the submit and the file write, and the script still exits 0 (SPO-Ptransfer-PR-001). (src: L700-L703, L787-L791, L856-L860, L923-L927, L990-L994, L1060-L1062, L1104, L1167-L1171)

> **Observed 2026-11-16:** the prompt reads `Does this look good for you, continue ? [y/N]` from the terminal; with no terminal the answer is No and the script exits 0 with the file unchanged, with `-y` as well. A light-mode submit whose answer is a quoted id with a trailing newline is refused (`returned TxID is not a valid one`): the id is measured before the newline is stripped. The port, against the same stand-in, submits the same bytes and writes the same file (`TestWorkOfflineExecuteMatchesUpstream`); a decline is `ErrDeclined`, and `ENV_SKIP_PROMPT` is replaced by `ApprovalSkip`, which the result records.
5. **Submit and record.**
   - **SPO-01workOffline-EXT-011** Online: `cardano-cli <era> transaction submit --tx-file <tmp file>`, whose failure ends the script with cardano-cli's code and leaves the queue unchanged; then `cardano-cli <era> transaction txid --output-text --tx-file <tmp file>` gives the transaction id (failure ends with its code). Light: `submitLight` on the tmp file (SPO-Clight-EXT-012, SPO-Clight-OUT-026) gives the id. (src: L706-L727, L795-L815, L864-L884, L931-L951, L998-L1018, L1108-L1128, L1175-L1195)
   - **SPO-01workOffline-PRE-013** In light mode a failing submit or query prints the error text and exits **0** (as SPO-01workOffline-PRE-004); in online mode a failing live query in a branch does the same. The queue and the file are unchanged. (src: L684, L689, L724, L752, L757, L773, L778, L812, L840, L845, L881, L907, L912, L948, L974, L979, L1015, L1044, L1049, L1125, L1151, L1156, L1192)
   - **SPO-01workOffline-OUT-016** After a successful submit, the `used` flags, the history entry and the removal of `transactions[n-1]` follow SPO-Ptransfer-OUT-014 and the file is rewritten whole. The history entry begins `tx submit <txid> - ` and names the entry's type and its names (`utxo from '<from>' to '<to>'` for the three plain types, `withdrawal from '<stake>' to '<to>'`, `<type> for '<name>', payment via '<from>'` for the certificate and DRep types, `<type> for Pool '<ticker>', payment via '<from>'` for the pool types). (src: L732-L736, L820-L825, L889-L892, L956-L959, L1023-L1026, L1133-L1136, L1200-L1203)
   - **SPO-01workOffline-INV-008** At most one entry is processed per run. After it, the script prints how many entries remain (display only). It removes the tmp tx file only on the paths that reach the end of the action; every refusal and error exit leaves `<tempDir>/<name>.tmp.txfile` (a signed transaction) behind. (src: L1217-L1223)
   - **SPO-01workOffline-OUT-017** After a successful `PoolRetirement`, it prints a reminder not to de-register the pool's reward address yet, because the pool deposit is refunded to it (display only). (src: L1206)

## Work modes

- **SPO-01workOffline-MODE-001** Online and light only: `new`, `clear`, `add` and `execute` (SPO-01workOffline-PRE-001). Every mode: `info`, `attach`, `extract`, `cleartx`, `clearhistory`, `clearfiles`. (src: L46, L50, L59, L86)
- **SPO-01workOffline-MODE-002** Online versus light in the snapshot actions: online queries the node (`cardano-cli`) for parameters, UTxOs, stake-address info and DRep state (SPO-01workOffline-EXT-001, SPO-01workOffline-EXT-003, SPO-01workOffline-EXT-005, SPO-01workOffline-EXT-006); light takes the parameters from the prologue's light-mode document and the rest from Koios through `queryLight_*`. The stored `general.onlineNODE` differs (SPO-01workOffline-OUT-005). (src: L146-L166, L284-L299, L458-L470, L563-L577)
- **SPO-01workOffline-MODE-003** Online versus light in `execute`: the live checks use the same split, and the submit goes through the node or through Koios (SPO-01workOffline-EXT-011). (src: L681-L691, L706-L727)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| `Does this look good for you, continue ?` in `execute` (SPO-01workOffline-PR-001) | No | Submits the entry and updates the file; No ends with exit 0 and no change |

No other action prompts, including the destructive `new`, `cleartx`, `clearhistory` and `clearfiles`. `ENV_SKIP_PROMPT` has no effect (SPO-Ptransfer-PR-001).

## Outputs

The file is written whole by shell redirection after every mutating action (SPO-Ptransfer-INV-002). Per-action mutations are in the Behaviour section; the table summarises them.

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `offlineTransfer.json` | per action, see below; schema in Ptransfer | not managed | created or replaced by `new`, `clear`, `add`, `attach`, `cleartx`, `clearhistory`, `clearfiles`; updated by `execute`, `extract` |
| `<tempDir>/<fromAddr basename>.tmp.txfile` | the entry's signed transaction envelope | default | created by `execute`; removed at the end of a normal run |
| `<tempDir>/tmpmetadata.json` | pool metadata downloaded for the hash check | default | overwritten by `execute` of a pool registration |
| each `files` key path | decoded attachment | default | created by `extract` |

| Action | Keys it changes in the file |
| --- | --- |
| `new`, `clear` | everything: only `general`, `protocol`, `history` remain |
| `add` | `general`, `protocol`, `address.<addr>`, `tokenMetaServer`, `history` |
| `add` (DRep) | `general`, `protocol`, `drep.<id>`, `history` |
| `execute` | `address.<from/to>.used`, `transactions` (one entry removed), `history` |
| `attach` | `files.<path>`, `history` |
| `extract` | `files` (entries removed), `history`, and the extracted files |
| `cleartx` | `transactions` removed, `history` |
| `clearhistory` | `history` replaced |
| `clearfiles` | `files` removed, `history` |
| `info` | none |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| No arguments, unknown action | 1 | SPO-01workOffline-IF-002 |
| Missing or invalid name or file argument | 1 | SPO-01workOffline-IF-004, SPO-01workOffline-IF-005, SPO-01workOffline-IF-006, SPO-01workOffline-IF-007 |
| `new`/`clear`/`add`/`execute` in offline mode | 1 | SPO-01workOffline-PRE-001 |
| `new`/`clear`/`add`/`execute` with node or Koios not synced | 1 | SPO-01workOffline-PRE-002 |
| Existing transfer file is not valid JSON | 1 | SPO-01workOffline-PRE-003 |
| `add`: chain query failed | 0 | SPO-01workOffline-PRE-004 |
| `add`: no UTxOs on the payment address | 1 | SPO-Ptransfer-OUT-005 |
| `add`: stake address not registered | 1 | SPO-01workOffline-PRE-005 |
| `add`: address type neither payment nor stake | 1 | SPO-01workOffline-PRE-006 |
| `add`: DRep id is not valid bech32 | 1 | SPO-01workOffline-PRE-007 |
| `attach`: no valid transfer file; jq update failed | 1 | SPO-01workOffline-PRE-008, SPO-01workOffline-OUT-013 |
| `execute`: empty queue | 0 | SPO-01workOffline-PRE-009 |
| `execute`: position out of range | 1 | SPO-01workOffline-PRE-010 |
| `execute`: UTxO or rewards snapshot stale | 1 | SPO-Ptransfer-PRE-004, SPO-Ptransfer-PRE-005 |
| `execute`: ticker protection or metadata hash check failed | 1 | SPO-01workOffline-EXT-009, SPO-01workOffline-EXT-010 |
| `execute`: `cardano-cli` submit or txid failed | cardano-cli's code | SPO-01workOffline-EXT-011 |
| `execute`: query or light-mode submit failed | 0 | SPO-01workOffline-PRE-013 |
| `execute`: unknown type | 0 | SPO-01workOffline-INV-006 |
| `execute`: declined | 0 | SPO-01workOffline-PR-001 |

## Security

- **SPO-01workOffline-SEC-002** The file holds signed transactions and balances but no signing key (SPO-Ptransfer-SEC-002). `execute` submits the stored `txJSON` and never decodes it: the confirmation shows the entry's descriptive fields (`type`, names, addresses, era), which a writer of the file chooses and which are not compared with the transaction body. (src: L654-L703)
- **SPO-01workOffline-SEC-003** For a pool registration, the ticker and the stored `regProtectionKey` are sent to the third-party ticker-protection service in the URL query (SPO-01workOffline-EXT-009). (src: L1065-L1066)
- **SPO-01workOffline-SEC-004** `extract` writes to any path the file names (SPO-01workOffline-SEC-001). A transfer file from an untrusted party is a file-write primitive for the user running the script. (src: L1262-L1274)
> **Port, 2026-11-16:** `app/airgap.Extract` writes through a `FileSink` that owns one directory. A key is accepted only as a plain file name (one leading `./` is dropped); a separator, an absolute path, `..`, a control character or a name over 255 bytes is refused, the entry stays in the bundle, and the run ends in an error. An existing file is skipped unless `Overwrite` is set, and a symbolic link is never written through. `TestExtractFixesThePathTraversal` runs upstream on a bundle with the key `../escape.txt` and shows it writing outside its directory; the port writes nothing there.
- **SPO-01workOffline-SEC-005** Names and paths (address names, attached file paths, `files` keys) are pasted into `jq` program text unescaped, so a double quote in them breaks or alters the update. They come from the operator's own file names, and from the transfer file for `files` keys. (src: L244, L425, L599, L1262-L1263, L1279)

## Domain mapping

Use cases: `PrepareOfflineSnapshot` (`new`, `clear`, `add`), `ExecuteQueuedTransaction` (`execute`), `CarryFiles` (`attach`, `extract`), `InspectTransferBundle` (`info`), `ClearTransferBundle` (`cleartx`, `clearhistory`, `clearfiles`). Aggregate: `TransferBundle` (snapshot, queue, files, history).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Transport` | `snapshot(addresses, extras)` | `new`, `add`: write the snapshot half |
| `Transport` | `importSnapshot()` | Load the bundle (`attach` needs it valid) |
| `Transport` | `dequeueTx(n)` | `execute`: remove the entry after a submit |
| `Transport` | `attach(file)` / `extract(file)` | Carry files |
| `Transport` | `clear(tx\|history\|files)` *(new, see Ptransfer)* | The three clear actions |
| `ChainQuery` | `protocolParameters()`, `utxos(address)`, `rewardAccount(stakeAddress)`, `drepState(drepId)`, `tip()` | Snapshot sources and `execute` live checks |
| `Submitter` | `submit(signedTx) -> txId` | `execute` |
| `Ledger` | `txId(tx)` | The id shown and recorded after an online submit |
| `Ledger` | `addressInfo(address)` | Address type for `add` |
| `Ledger` | `stakePoolMetadataHash(file)` *(new)* | Metadata hash check of a pool registration |
| `Directory` | `tokenMetadata(subject)`, `fetchUrl(url)`, `checkTickerProtection(ticker, key)` *(new, see Ptransfer)* | Registry names, metadata download, ticker check |
| `UI` | `confirm(prompt, default)`, `show(view)` | `execute` confirmation; summaries |

## Port notes

* Make every action atomic and locked (SPO-Ptransfer-INV-002), and write a stable entry id per queued transaction so `execute` does not depend on a shifting position.
* Exit non-zero on a failed query or submit (SPO-01workOffline-PRE-004, SPO-01workOffline-PRE-013), and on a failed read-back (SPO-01workOffline-OUT-012).
* Show the decoded outputs of the transaction in the confirmation, not the entry's descriptive fields (SPO-01workOffline-SEC-002). Compare the UTxO and rewards snapshots structurally (SPO-Ptransfer-PRE-004).
* Confine `extract` to the workspace (SPO-01workOffline-SEC-001). Ask for confirmation before `new`, `cleartx`, `clearfiles`, which destroy queued work.
* Remove the tmp tx file on every exit (SPO-01workOffline-INV-008) or keep it in memory.
* Enforce a size limit on `attach` that fails with a clear message (see the attach quirk), or stream the file instead of passing it through a command line.
* Treat `add` of a stale file as a merge and say so; the refreshed protocol parameters apply to the whole snapshot (SPO-Ptransfer-OUT-004).
* An online machine that serves a signed-transaction queue over a secure channel (server mode) replaces `Transport`; `execute` stays a use case over the `Submitter` port.

## Open questions

* The exit status of the `new` and `add` paths when `query protocol-parameters` fails (SPO-01workOffline-EXT-001 quirk) is derived from the code; running `new` against a node that stops answering after the sync check settles it.
* The 128 KiB limit of the attach quirk depends on the kernel's single-argument limit; a test with a 100 KB file settles the exact threshold.
* Whether the text comparison of SPO-Ptransfer-PRE-004 sees equal key order when the snapshot was taken in light mode and `execute` runs in online mode (or the reverse) depends on the ordering of `cardano-cli query utxo` against Koios; a test with an address holding several UTxOs settles it.
* The shape of `voteDelegation` and `stakeDelegation` inside a stored `rewardsJSON` differs between `cardano-cli` and Koios; consumers are in other scripts (see Ptransfer open questions).
