+++
id = "05c"
kind = "script"
title = "Register or update the pool on chain, collecting owner witnesses"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "transaction-construction", "key-custody", "air-gap-transfer"]
use_cases = ["RegisterPool"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cui", "Ckey", "Chw", "Ctx", "Cchain", "Clight", "Cutxo", "Coffline", "Cconv", "Cconf"]

upstream_path = "cardano/mainnet/05c_regStakepoolCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "d696eab60fed4515e637696f0f1e872c86e2a15df572f2c53a7f13bdc50ccdb2"
upstream_lines = 1210
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "convertToADA",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "file_lock",
  "file_unlock",
  "generate_UTXO",
  "get_currentEpoch",
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
  "query stake-pools",
  "query utxo",
  "stake-pool id",
  "stake-pool metadata-hash",
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
  "koiosAPI",
  "koiosAPI/pool_info",
  "tokenMetaServer",
]
env_vars = []
+++

# 05c_regStakepoolCert: Register or update the pool on chain

Submits the pool registration certificate made by [05a](./05a_genStakepoolCert.md), together with one delegation certificate per owner, in a single transaction that needs several signatures: the pool cold key, the paying address and every owner's stake key. Because owners can sit on other machines or on hardware wallets, the script does not sign and submit in one step. It builds the transaction body once, stores it with one *witness slot* per signer in `<pool>.pool.json` (the *witness collection*, key `regWitness`), fills the slots it can sign itself, and stops while slots are empty. [05d](./05d_poolWitness.md) moves the missing witnesses in. Re-running 05c assembles, checks, confirms and submits once all slots are full. The script decides between a first **registration** (pays the pool deposit) and a **re-registration**, that is, a pool update (no deposit).

It follows the Ptx pipeline (SPO-Ptx-INV-011 is the summary of the variation); this spec lists what differs or is specific to certificates and witnesses. Variation row: SPO-Ptx-INV-006 (witness count `2 + owners`), SPO-Ptx-PR-004 (it never honours `ENV_SKIP_PROMPT`), SPO-Ptx-OUT-004 (post-submit record).

## Interface

- **SPO-05c-IF-001** Takes two required positional arguments: the pool name and the name of the paying address. With fewer than two, prints usage to stderr and exits 1. (src: L20-L61)
- **SPO-05c-IF-002** Both names are normalised: the pool name as in SPO-Pfiles-IN-001, the paying address with a trailing `.addr` and a leading `./` dropped. (src: L64-L65)
- **SPO-05c-IF-003** Words after the second argument are extra parameters. Accepted: metadata `.json`/`.cbor` files, `msg:`, `enc:`, `pass:` (grammar and messages per `Pparam`) and `type:REG` / `type:REREG` (SPO-Pparam-IF-024). A UTxO list word is recognised but has no effect: unlike SPO-Ptx-PRE-001's restriction, 05c always spends every UTxO of the paying address. `utxolimit:`, `skiputxowithasset:` and `onlyutxowithasset:` are not known here and fail as missing metadata files (SPO-Pparam-IF-005). (src: L74-L131)
- **SPO-05c-IF-004** The message and metadata files are collected before anything else is read, so a bad extra parameter refuses with exit 1 before any state is touched. The message metadata file is `<tempDir>/<paying-address basename>.transactionMessage.json` (SPO-Pparam-OUT-002). (src: L74-L166)

## Inputs

- **SPO-05c-IN-001** Reads `<pool>.pool.json` (see the schema in 05a) and requires the fields `poolName`, `poolOwner`, `poolRewards`, `poolPledge`, `poolCost`, `poolMargin`, `regCertFile`, `poolMetaUrl`, `poolMetaHash`, `poolMetaTicker` and `poolIDbech`. Missing, `null` or empty fields exit 1 with the hint to re-run 05a. `regProtectionKey` is optional and treated as empty when absent. (src: L171-L207)
- **SPO-05c-IN-002** Reads from the descriptor the registration record `regSubmitted` (non-empty means "registered before"), `deregSubmitted`, and the witness collection `regWitness`. The pledge, cost, margin and reward-account fields are read for display only: the transaction body is fixed by the certificate file. (src: L173-L183, L218, L231, L456-L469)
- **SPO-05c-IN-003** Per owner of `poolOwner`: `<ownerName>.staking.vkey` and `<ownerName>.deleg.cert` (made by 05b), and `ownerWitness` (see SPO-05c-INV-005). (src: L341-L362, L834)
- **SPO-05c-IN-004** Protocol parameters from the work mode's source (SPO-Ptx-MODE-006): `stakePoolDeposit`, `maxTxSize` and the rest as a file for fee calculation. (src: L447-L454, L670, L1018)
- **SPO-05c-IN-005** The paying address's UTxOs and the TTL basis, as in the pipeline; additionally `tempDir`, `offlineFile`, `transactionExplorer`, `koiosAPI`, `cropTxOutput` settings. (src: L373-L377, L493-L514)

## Behaviour

1. **Parse the parameters** (SPO-05c-IF-003, SPO-05c-IF-004).
2. **Open a new witness collection or resume the stored one.**
   - **SPO-05c-INV-001** A collection is *open* when `regWitness.id` exists and is not 0. The id is the Unix time in seconds at the moment the collection is created in memory. Without an open collection, a fresh in-memory collection `{id, type: "", ttl: 0, regPayName: "", txBody: {}, witnesses: {}}` is started; it is written to the descriptor only at SPO-05c-OUT-001. (src: L176-L183)
   - **SPO-05c-PRE-001** Exits 1 when the descriptor is missing (with the hint to run 05a) or a required field is missing or empty. (src: L171, L186-L206)
   - **SPO-05c-PRE-002** Exits 1 when `<regCertFile>` (the certificate named in the descriptor, normally `<pool>.pool.cert`), `<pool>.node.vkey`, `<pool>.node.skey` or `.node.hwsfile`, `<pay>.addr`, or `<pay>.skey` or `.hwsfile` is missing. A missing certificate means "not generated or already submitted" (05c deletes it after use, SPO-05c-OUT-006). (src: L210-L214)
   - **SPO-05c-PRE-003** With an open collection, exits 1 when a `type:` parameter was given or when any metadata file or message was given: the type and the metadata are fixed by the stored body, and the only way to change them is clearing the collection with 05d. (src: L313-L324). See SPO-Pparam-IF-018 and SPO-Pparam-IF-024.
3. **Decide registration or re-registration** (only for a new collection). The result is the *registration type*: `PoolRegistration` (the descriptor's `regSubmitted` treated as empty) or `PoolReRegistration` (treated as non-empty).
   - **SPO-05c-INV-002** With `type:REG` the type is `PoolRegistration`; with `type:REREG` it is `PoolReRegistration`; the chain is not consulted. (src: L309-L310)
   - **SPO-05c-PRE-004** Without a `type:` parameter, a descriptor that contains `deregSubmitted` (the pool was retired before) exits 1 asking the operator to choose `type:REG` or `type:REREG`. This check precedes every chain query. (src: L229-L231)
   - **SPO-05c-MODE-001** *Online* (no `type:`): requires the node to report synced (exit 1 otherwise) and runs `cardano-cli <era> query stake-pools`; a query failure exits 1. The number of lines containing the pool's bech32 id decides: exactly 1 means registered (re-registration), 0 means not registered (registration), more than 1 exits 1. (src: L238-L254)
   - **SPO-05c-MODE-002** *Light* (no `type:`, and `koiosAPI` configured): POSTs `{"_pool_bech32_ids": ["<poolIDbech>"]}` to `<koiosAPI>/pool_info` with up to five attempts. With HTTP 200 and exactly one array element, `pool_status` `REGISTERED` or `RETIRING` gives a re-registration and `RETIRED` a registration; an empty answer (never registered) gives a registration. Any other status, a failed request or any other HTTP status leaves the descriptor's `regSubmitted` in force. (src: L256-L303)
   - **SPO-05c-MODE-003** *Offline* (no `type:`): no chain query; the descriptor's `regSubmitted` decides, so a pool that was queued offline before counts as registered (SPO-05c-OUT-005). (src: L218, L229-L234)
   - **SPO-05c-INV-003** The type, the deposit decision and the whole transaction are computed once, when the collection is created. A resumed run reads the type from `regWitness.type` and the body from `regWitness.txBody`; later edits to the descriptor or a regenerated certificate do not change the stored transaction. (src: L486-L894, L900-L907, L990)
4. **Check the owners and the certificate list.**
   - **SPO-05c-PRE-005** Exits 1 when an owner's `<ownerName>.staking.vkey` or `<ownerName>.deleg.cert` is missing. (src: L346, L348)
   - **SPO-05c-PRE-006** Exits 1 when an owner's delegation certificate does not delegate to this pool: the last 56 hex characters of the certificate's `cborHex` must equal the hex pool id derived from `<pool>.node.vkey` with `stake-pool id --output-hex`. (src: L336-L338, L352-L354)
   - **SPO-05c-INV-004** The certificates attached are, in this order: the registration certificate, then one `<ownerName>.deleg.cert` per owner in descriptor order. (src: L330, L357)
   - **SPO-05c-INV-006** A hardware wallet is *involved* when `<pool>.node.hwsfile` exists or any owner's `<ownerName>.staking.vkey` has a description containing `Hardware` (SPO-Pfiles-INV-001). The payment address and the reward account are not considered. When a hardware wallet is involved only the registration certificate is attached; the owners' delegation certificates are then left out and have to be registered afterwards, one transaction per owner (06). The flag is stored as `hardwareWalletIncluded`. (src: L333-L334, L347, L364-L368, L731)
   - **SPO-05c-INV-007** The witness count used for the fee estimate is `2 + number of owners` (cold key, payer, each owner), also when delegation certificates were dropped (SPO-Ptx-INV-006). The owner who is also the reward account is not counted separately; a duplicate owner name is counted twice. (src: L331, L345, L662)
5. **Clock and TTL.**
   - **SPO-05c-INV-008** For a new collection the validity end is `tip + defTTL` slots (SPO-Ptx-INV-001); the TTL is stored in the collection. A resumed run keeps the stored TTL, exits 1 when it is lower than the current tip (equal is accepted) and exits 1 when the paying-address name differs from the stored `regPayName`. Time passing therefore *expires* a collection: the only remedy is `05d clear` and a new 05c run with a new id. (src: L373-L387)
6. **Checks against third parties (online and light only).** They run on every invocation, including resumed ones, and before the pipeline stages.
   - **SPO-05c-EXT-001** Ticker protection: asks `GET https://my-ip.at/checkticker?ticker=<poolMetaTicker>&key=<regProtectionKey>` (the URL is stored as hex escapes in the script) with `curl -L -m 20`. A curl failure (service offline) lets the run continue. An answer other than the exact text `OK` exits 1 with the explanation that the ticker is protected and a protection key is needed. (src: L398-L413)
   - **SPO-05c-EXT-002** Metadata hash check: downloads `poolMetaUrl` with `curl -sL`, requires the download to succeed (exit 1) and to be valid JSON (exit 1), computes its hash with `cardano-cli <era> stake-pool metadata-hash --pool-metadata-file`, and requires equality with `poolMetaHash` of the descriptor; a mismatch prints both files and exits 1 ("registration aborted"). The HTTP status is not checked, so an error page fails as invalid JSON. The temporary download is removed only on success. (src: L415-L443)
   - **SPO-05c-MODE-004** In offline mode neither check runs at queueing time. They run at `01_workOffline execute` instead (SPO-Ptransfer-PRE-006). (src: L398)
7. **Inputs, fee and balance** (new collection only; stages 3 to 8 of the pipeline).
   - **SPO-05c-MODE-005** UTxOs, protocol parameters and the era come from node, Koios or the transfer file as in SPO-Ptx-MODE-002 .. SPO-Ptx-MODE-004 and SPO-Ptx-MODE-006. Offline, a paying address absent from the transfer file exits 1. Filter parameters do not exist (SPO-05c-IF-003). (src: L493-L514)
   - **SPO-05c-PRE-007** A paying address without UTxOs ends the script with **exit 0** after a message (a bare `exit`), unlike SPO-Ptx-PRE-001. (src: L516-L517)
     > **Upstream quirk:** success exit code on "no funds". A port exits non-zero.
   - **SPO-05c-INV-009** Fee and balance: the dummy body (fee 200000) holds every UTxO as input, one output with the total, the TTL, the metadata files and the certificates of SPO-05c-INV-004; the fee comes from `calculate-min-fee` with the witness count of SPO-05c-INV-007 (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002). The amount to pay is `deposit + fee`, with `deposit` the protocol parameter `stakePoolDeposit` for `PoolRegistration` and 0 for `PoolReRegistration`. The change output returns `inputs - deposit - fee` and all assets to the paying address (SPO-Ptx-INV-007). (src: L651-L690)
   - **SPO-05c-PRE-008** When the change is below the minimum output value the script refuses with exit **0** (SPO-Ptx-PRE-002). (src: L693-L694)
   - **SPO-05c-EXT-003** The final body is built with `build-raw` into `<tempDir>/<pool>.txbody` (SPO-Ptx-EXT-004), with the real fee and change, the same TTL, metadata and certificates. With a hardware wallet involved the body is rewritten in canonical form (`autocorrect_TxBodyFile`, see `Ctx`) before it is stored; failure exits 1. (src: L696-L717)
   - **SPO-05c-PR-001** The operator is shown the body and asked "does this look good, continue?" (default No); No exits 1 and **nothing is stored**: no witness is made, the descriptor is unchanged. The question is asked only when a new collection is created; a resumed run does not repeat it. (src: L719-L721)
8. **Store the transaction and fill the local witness slots** (new collection only).
   - **SPO-05c-OUT-001** The collection is written to the descriptor (unlock, whole-file rewrite, lock `0400`) only once all local witnesses were produced, so an abort, rejection or refusal during signing leaves the descriptor unchanged. (src: L723-L732, L889-L892)
   - **SPO-05c-OUT-002** The collection has this structure; every value is written at creation, except the filled witnesses (SPO-05c-OUT-003). (src: L179, L224-L225, L360, L725-L732)

     | Key of `regWitness` | Value |
     | --- | --- |
     | `id` | integer, Unix seconds at creation (SPO-05c-INV-001) |
     | `type` | `"PoolRegistration"` or `"PoolReRegistration"` |
     | `ttl` | integer slot, the transaction's `invalid-hereafter` |
     | `regPayName` | normalised paying-address name |
     | `regPayAmount` | integer lovelaces, `deposit + fee` |
     | `regPayReturn` | integer lovelaces returned as change |
     | `txBody` | the unsigned body, a cardano-cli text envelope object (`type`, `description`, `cborHex`) |
     | `hardwareWalletIncluded` | `"yes"` or `"no"` (SPO-05c-INV-006) |
     | `metadataFilesList` | string of quoted file names, display only; the metadata itself is inside `txBody` |
     | `witnesses` | object keyed by witness slot name (below) |

   - **SPO-05c-INV-005** The slots of `witnesses` are created in this order, each `{witness: {}}` until filled: `<poolName>.node` (the cold key), `<regPayName>` (the payer), then `<ownerName>.staking` for every owner in descriptor order. A filled slot holds the cardano-cli witness text envelope (`type`, `description`, `cborHex`). Owners whose `ownerWitness` is absent, empty or `local` (any case) are signed by this run when their key is available; an owner with any other `ownerWitness` value is left to an external signer. (src: L224-L225, L360, L829-L887)
   - **SPO-05c-EXT-004** *Cold key.* With `<pool>.node.skey` present the witness is made with `cardano-cli <era> transaction witness --tx-body-file <body> --signing-key-file <key read into memory> --out-file /dev/stdout`. Else, when `<pool>.node.hwsfile` and `<pay>.hwsfile` both exist, one hardware call makes both witnesses (`cardano-hw-cli transaction witness --tx-file <body> --hw-signing-file <node> --hw-signing-file <pay> <magic> --out-file <w1> --out-file <w2>`), restricted to Ledger or Keystone devices. Else, with only the node `hwsfile`, a hardware call makes the node witness. A key file wins over a hardware file. (src: L735-L805)
   - **SPO-05c-EXT-005** *Payer.* With `<pay>.skey` present and not already filled by the combined hardware call, the payer's witness is made as for the cold key. With only `<pay>.hwsfile` and a key-file cold key, the payer's slot stays empty and is signed externally (see SPO-05c-INV-010). (src: L809-L825)
   - **SPO-05c-EXT-006** *Owners* with a local witness policy: `<owner>.staking.skey` (key wins) is witnessed in memory; otherwise `<owner>.staking.hwsfile` through `cardano-hw-cli transaction witness` (no vendor restriction); an owner with neither exits 1. (src: L836-L881)
   - **SPO-05c-PRE-009** Hardware output is classified as in SPO-Ptx-PRE-005: `REJECTED`, `DISCONNECT` and `ERROR` exit 1, `WARNING` continues. An unreadable key file exits 1 (SPO-Ptx-EXT-006). (src: L738, L760-L771, L786-L797, L813, L844, L862-L873)
   - **SPO-05c-PR-002** Before each hardware step the operator is asked for confirmation (default Yes): for the combined node and payment witness, for the node witness alone, and for each hardware owner. A No exits 2. (src: L753, L780, L858)
   - **SPO-05c-INV-010** The only supported way to fill the payer slot or the cold-key slot externally is by hand-editing the descriptor: 05d signs only `<name>.staking` keys (SPO-05d-IF-003), so a missing payer or cold-key witness cannot be produced with the published workflow. (src: L823-L825, L935)
     > **Upstream quirk:** a payer with only a `.hwsfile` combined with a key-file cold key leaves a slot that no script can fill. A port signs payer and cold key through the `Signer` port, whichever the key location.
9. **Report the collection.** Runs for every invocation (new or resumed).
   - **SPO-05c-OUT-003** For every slot with an empty witness a *witness transfer file* `<pool>_<basename of slot name without ".staking">_<id>.witness` is written, unless a file of that name exists already (it is then left unchanged and reported as "still exists"). Content: `{id, date-created (RFC-5322 of the id), ttl, type, metadataFilesList, poolFile, poolMetaTicker, signing-name (the slot name), signing-vkey (the content of <slot name>.vkey), txBody, signedWitness: {}, date-signed: {}}`. Default file mode. (src: L923-L947). See SPO-Pfiles-OUT-023.
   - **SPO-05c-PRE-010** With at least one empty slot the script exits 1 after listing ready and missing witnesses and the command to clear the collection (`05d clear`). In offline mode it first offers to attach witness files to the transfer file (SPO-05c-PR-007). (src: L950-L982)
10. **Assemble.** Only when every slot is filled.
    - **SPO-05c-EXT-007** Writes the stored body to `<tempDir>/<pool>.txbody`, each witness to a temporary file, and assembles `cardano-cli <era> transaction assemble --tx-body-file <body> --witness-file <w>... --out-file <tempDir>/<pool>.tx`, the witnesses in slot order. The temporary witness files are removed. A failure exits with cardano-cli's code. (src: L988-L1027)
    - **SPO-05c-PRE-011** A signed transaction larger than `maxTxSize` exits 1 (SPO-Ptx-PRE-007). (src: L1015-L1020)
    - **SPO-05c-EXT-008** Derives the hex and bech32 pool id from `<pool>.node.vkey` again (display and offline entry). (src: L1030-L1036)
11. **Confirm.**
    - **SPO-05c-PR-003** Asks "does this look good, do you have enough pledge in your owner account(s), continue and register on chain?" (default No); a warning about respecting the pledge is displayed first when `poolPledge` is above 0 (display only). `ENV_SKIP_PROMPT` is ignored (SPO-Ptx-PR-003, SPO-Ptx-PR-004). (src: L1040-L1046)
    - **SPO-05c-PR-004** On No nothing is submitted or queued; the script then asks whether to delete the witness collection from the descriptor (default No). Yes removes `regWitness` and leaves the descriptor at mode `0600` (the file is unlocked twice instead of relocked); when no collection exists it says so. The exit code is 0. (src: L1189-L1207)
12. **Submit or queue.**
    - **SPO-05c-MODE-006** *Online:* `cardano-cli <era> transaction submit --tx-file <tx>`; on success the descriptor gets `regEpoch` (the current epoch, string), `regSubmitted` (RFC-5322 time) and loses `regWitness`, then `<regCertFile>` is deleted, then the transaction id is shown with the explorer link. A failed submit prints the status and exits 1, leaving the collection and the certificate in place. (src: L1052-L1078)
    - **SPO-05c-MODE-007** *Light:* `submitLight` (SPO-Ptx-MODE-009); on success the same descriptor update and certificate deletion; on failure the message and exit 1. (src: L1086-L1118)
    - **SPO-05c-MODE-008** *Offline:* appends to `transactions[]` an entry with the common fields of SPO-Ptransfer-OUT-010 (`type` = the registration type, `fromAddr` and `toAddr` = the paying-address name, `sendFromAddr` and `sendToAddr` = its address) and the extra fields `poolMetaTicker`, `regProtectionKey`, `poolMetaUrl`, `poolMetaHash`, then a `history` entry `signed pool registration transaction for '<ticker>', payment via '<pay>'`, `general.offlineCLI`, and offers to attach `<pool>.metadata.json` and `<pool>.extended-metadata.json` (SPO-05c-PR-005, SPO-05c-PR-006). After rewriting the file it reads `transactions[-1].txJSON` back; on a match it sets `regEpoch`, `regSubmitted` to `<time> (only offline, no proof)`, removes `regWitness`, shows the file summary and deletes `<regCertFile>`. On a mismatch it prints an error and exits 0 with the descriptor and certificate unchanged. (src: L1121-L1184). See SPO-Ptransfer-OUT-010 to SPO-Ptransfer-OUT-012.
    - **SPO-05c-OUT-004** On online or light success with a hardware wallet involved, the script tells the operator that each owner's delegation certificate must be registered in an additional transaction after the registration (display only; the domain consequence is that a hardware-owner registration is a two-phase workflow, SPO-05c-INV-006). (src: L1080-L1082, L1115-L1117, L1174-L1175)

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-05c-INV-011** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the descriptor, file and owner checks of SPO-05c-IF-001 to SPO-05c-IN-003, SPO-05c-PRE-001 to SPO-05c-PRE-006 and SPO-05c-INV-004, SPO-05c-INV-006. (src: L20-L214, L336-L368)
- **SPO-05c-INV-012** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), except that an open collection keeps its stored TTL (SPO-05c-INV-008). (src: L373-L387)
- **SPO-05c-INV-013** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-INV-002) for the paying address, with SPO-05c-MODE-005; an address without UTxOs ends the script with exit 0 (SPO-05c-PRE-007). The source and the change address are both `<pay>.addr` (one output, SPO-Ptx-INV-007). New collection only. (src: L474-L477, L493-L517)
- **SPO-05c-INV-014** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). New collection only. (src: L519-L650)
- **SPO-05c-INV-015** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006), read before the inputs; `stakePoolDeposit` and `maxTxSize` are SPO-05c-IN-004. (src: L447-L454)
- **SPO-05c-INV-016** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with the certificates of SPO-05c-INV-004 attached and witness count `2 + owners` (SPO-05c-INV-007); the dummy body is SPO-05c-INV-009. (src: L651-L666)
- **SPO-05c-INV-017** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-EXT-003, SPO-Ptx-PRE-002) with change `inputs - fee - pool deposit` (zero deposit for a re-registration, SPO-05c-INV-009) and the refusal exit 0 (SPO-05c-PRE-008). (src: L668-L694)
- **SPO-05c-INV-018** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003): any earlier body is removed first and a build failure ends the script with cardano-cli's code (SPO-05c-EXT-003). (src: L696-L717)
- **SPO-05c-INV-019** Stage 9, sign: replaced by the witness collection (SPO-Ptx-INV-011): the first confirmation (SPO-05c-PR-001), the stored collection and local witnesses (SPO-05c-OUT-001, SPO-05c-OUT-002, SPO-05c-INV-005, SPO-05c-EXT-004 to SPO-05c-EXT-006, SPO-05c-PRE-009, SPO-05c-PR-002) and the report with the witness transfer files (SPO-05c-OUT-003, SPO-05c-PRE-010). (src: L719-L982)
- **SPO-05c-INV-020** Stage 10, size check: runs at assembly, when every slot is filled: as Ptx (SPO-Ptx-PRE-007), exit 1 (SPO-05c-EXT-007, SPO-05c-PRE-011). (src: L988-L1027)
- **SPO-05c-INV-021** Stage 11, confirm: the second confirmation, default No, never honouring `ENV_SKIP_PROMPT` (SPO-Ptx-PR-004, SPO-05c-PR-003, SPO-05c-PR-004). (src: L1040-L1046, L1189-L1207)
- **SPO-05c-INV-022** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010) with the 05c variants SPO-05c-MODE-006 to SPO-05c-MODE-008 (online and light failures exit 1) and the post-submit effects SPO-05c-OUT-004 to SPO-05c-OUT-006. (src: L1052-L1187)

## Work modes

- **SPO-05c-MODE-009** Summary. Online: node sync check, ledger query for the type, ticker and metadata-hash checks, UTxOs from the node, submit through the node. Light: Koios for type, UTxOs and submit, same third-party checks. Offline: no chain queries, no third-party checks; type from the descriptor or `type:`; UTxOs, parameters, era and tip (clock) from the transfer file and genesis files; the signed transaction is queued (SPO-05c-MODE-008). The witness collection and the owner witnesses work identically in all three modes. (src: L234-L307, L398-L445, L493-L514, L1050-L1184)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Body looks good (SPO-05c-PR-001) | No | No exits 1, nothing stored |
| Hardware witness, node and payer / node / owner (SPO-05c-PR-002) | Yes | No exits 2 |
| Does this look good, enough pledge, register (SPO-05c-PR-003) | No | No: nothing submitted, then SPO-05c-PR-004 |
| Delete the witness collection (SPO-05c-PR-004) | No | Yes removes `regWitness` |
| Attach `<pool>.metadata.json` to the transfer file, offline (SPO-05c-PR-005) | No | Yes embeds it |
| Attach `<pool>.extended-metadata.json`, offline (SPO-05c-PR-006) | No | Yes embeds it |
| Attach witness files, offline (SPO-05c-PR-007) | No | Yes embeds them |

- **SPO-05c-PR-005** In offline mode, after queueing and when `<pool>.metadata.json` exists, asks whether to attach it to the transfer file (default No); Yes stores `files."<pool>.metadata.json"` as in SPO-Ptransfer-OUT-017. (src: L1140-L1148)
- **SPO-05c-PR-006** The same for `<pool>.extended-metadata.json`. (src: L1150-L1158)
- **SPO-05c-PR-007** In offline mode, when slots are empty, asks per empty slot whether to attach the file `<pool>.<basename of slot name>.witness` (default No). That name differs from the one written by SPO-05c-OUT-003 (`<pool>_<name>_<id>.witness`), so the file is normally absent and the question is never asked. (src: L952-L976)
  > **Upstream quirk:** the attach offer looks for a file name that is never written. A port attaches the real witness transfer files.

## Outputs

- **SPO-05c-OUT-005** The registration record in the descriptor: `regEpoch` and `regSubmitted` after a successful submit or offline queueing, as in SPO-Ptx-OUT-004. A later 05c run in offline mode therefore sees an offline-queued registration as already registered. (src: L1055-L1070, L1089-L1103, L1163-L1182)
- **SPO-05c-OUT-006** The registration certificate `<regCertFile>` is unlocked and deleted after a successful submit, a successful light submit, and a verified offline queueing, so the same certificate cannot be submitted twice (SPO-Pfiles-OUT-019). It is kept on every failure and refusal. (src: L1064-L1066, L1099-L1101, L1177-L1179)
  > **Port decision 2026-11-16 (hazard H9, confirmation):** `regEpoch` and `regSubmitted` are not written on an accepted submit or a queueing. The command keeps them as a pending update (`<txid>.pending`) and the descriptor records them when the providers confirm the transaction (the wait of `pool register`, on by default in light and online mode, or `spo tx settle`; across the air gap `spo asset settle`, only on a recorded confirmation). The certificate file and the witness collection are consumed when the transaction is sent, as before, in one commit with the transaction id. While the update is pending, `pool descriptor show` and `pool witness status` say so. A transaction that expires is discarded and the registration is never recorded. This deliberately departs from SPO-05c-OUT-005; the final record equals what upstream writes, with the epoch and the time of the submission. See SPO-Xconfirm-PR-001, SPO-Xconfirm-PR-003 and SPO-Xconfirm-PR-007.
- **SPO-05c-OUT-007** Temporary files in `<tempDir>`: `dummy.txbody`, `<pool>.txbody`, `<pool>.tx`, `<pay>.transactionMessage.json`, hardware witness files `<pool>.tmp.witness` and `<pay>.tmp.witness`, `tmpmetadata.json` (removed on success only). They are not cleaned up except as stated. (src: L419, L443, L656, L696, L755-L756, L782, L988)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.pool.json` | descriptor; `regWitness` added, then `regEpoch`, `regSubmitted` added and `regWitness` removed | `0400` after each write (`0600` after SPO-05c-PR-004) | updated |
| `<pool>.pool.cert` (`regCertFile`) | registration certificate | `0400` | deleted after use |
| `<pool>_<slot>_<id>.witness` | witness transfer file, SPO-05c-OUT-003 | default | created per missing slot, never overwritten |
| `offlineTransfer.json` | queued transaction, history, attachments (offline) | not managed | updated |
| `<tempDir>/*` | see SPO-05c-OUT-007 | default | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments | 1 | SPO-05c-IF-001 |
| Bad extra parameter (file, message, `type:`) | 1 | SPO-05c-IF-003, SPO-Pparam-PRE-005 |
| Descriptor or required field missing | 1 | SPO-05c-PRE-001 |
| Certificate, key or address file missing | 1 | SPO-05c-PRE-002 |
| `type:` or metadata given with an open collection | 1 | SPO-05c-PRE-003 |
| Pool retired before and no `type:` | 1 | SPO-05c-PRE-004 |
| Node not synced, ledger query failed, duplicate pool id | 1 | SPO-05c-MODE-001 |
| Owner file missing | 1 | SPO-05c-PRE-005 |
| Delegation certificate targets another pool | 1 | SPO-05c-PRE-006 |
| Stored TTL below tip; payer differs from the collection | 1 | SPO-05c-INV-008 |
| Ticker not allowed | 1 | SPO-05c-EXT-001 |
| Metadata unreachable, invalid, or hash mismatch | 1 | SPO-05c-EXT-002 |
| Payer absent from the transfer file (offline) | 1 | SPO-05c-MODE-005 |
| No UTxOs on the paying address | **0** | SPO-05c-PRE-007 |
| Change below the minimum output value | **0** | SPO-05c-PRE-008 |
| Body not confirmed | 1 | SPO-05c-PR-001 |
| Hardware confirmation declined | 2 | SPO-05c-PR-002 |
| Hardware rejected, disconnected, error; key unreadable; owner key absent | 1 | SPO-05c-PRE-009, SPO-05c-EXT-006 |
| Witnesses missing | 1 | SPO-05c-PRE-010 |
| Assemble failed | cardano-cli's code | SPO-05c-EXT-007 |
| Transaction too large | 1 | SPO-05c-PRE-011 |
| Final confirmation declined | 0 | SPO-05c-PR-003 |
| Submit failed (online, light) | 1 | SPO-05c-MODE-006, SPO-05c-MODE-007 |
| Offline read-back mismatch | 0 | SPO-05c-MODE-008 |

## Security

- **SPO-05c-SEC-001** Signing keys are read into shell variables and handed to cardano-cli through an anonymous pipe, never written to disk (SPO-Ptx-SEC-001, SPO-Ckey-SEC-002). Hardware witnesses are written to temporary files, which are not secret. (src: L738-L746, L755-L773, L813-L821, L844-L852)
- **SPO-05c-SEC-002** The registration protection key and the ticker are sent to a third-party service (`my-ip.at`) in a plain query string on every online or light run, and the key is also stored in clear in the descriptor and in the offline entry. The service decides whether registration proceeds. (src: L401-L402, L1132)
- **SPO-05c-SEC-003** The collection stores the unsigned transaction and the signers' witnesses in the descriptor and in witness transfer files. A witness is bound to the body it signs and is not secret, but whoever holds the descriptor can assemble and submit the transaction before the TTL ends. (src: L723-L732, L1009)
- **SPO-05c-SEC-004** The script prints the descriptor, with `regProtectionKey`, after submit and when queueing; a message passphrase set with `pass:` is shown in clear (SPO-Pparam-SEC-001). (src: L1071-L1073, L1108-L1110, L1165-L1167)
- **SPO-05c-SEC-005** Metadata is fetched from `poolMetaUrl` with no TLS requirement beyond what the URL says and no size limit. (src: L420)

## Domain mapping

Use case `RegisterPool(pool, payer, forcedType?)` on aggregate `PoolRegistration`, which holds the descriptor, the certificate, the registration record and the open *witness collection* (id, type, ttl, body, slots). The witness collection is the multi-party signing aggregate; see SPO-05d for its transitions.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get/put(PoolDescriptor)`, `get/put/delete(WitnessCollection)` *(new)*, `put(WitnessTransferFile)` *(new)* | Descriptor, collection, per-slot transfer files |
| `Store` | `delete(PoolRegistrationCertificate)` | One-time use of the certificate |
| `ChainQuery` | `poolState(poolId)` | Registered or not (online node list, Koios `pool_info`) |
| `ChainQuery` | `tip()`, `protocolParameters()`, `utxos(address)` | Pipeline stages 2, 3 and 5 |
| `Directory` | `checkTickerProtection(ticker, key)` *(new)* | Third-party ticker service |
| `Directory` | `fetchUrl(url)` | Published metadata |
| `Ledger` | `metadataHash(file)` *(new)*, `poolId(vkey, format)` *(new)*, `decodeCertificate(cert)` *(new)* | Hash check, pool id, pool id inside a delegation certificate |
| `Ledger` | `buildRaw`, `minFee`, `minOutputValue`, `canonicalizeForHardware`, `assemble`, `txId` | Body, fee, assembly |
| `Signer` | `witness(body, keyRef) -> witness` | Cold key, payer, local owners; keyRef is a vault key or a hardware file |
| `Vault` | `unseal(ref, passphrase?)` | In-memory signing key |
| `Submitter` | `submit(signedTx)` | Online and light |
| `Transport` | `enqueueTx(signedTx, extras)`, `attach(file)` | Offline queue |
| `UI` | `confirm(prompt, default)` | Prompts |
| `Clock` | `now()` | Offline slot, collection id |

## Port notes

* Make the witness collection a first-class aggregate with explicit states and a store of its own: `Open(incomplete)`, `Open(complete)`, `Expired`, `Submitted`, `Discarded` (see SPO-05d). Persist it atomically with the registration record, never as a field in a shared descriptor.
* The collection id is a Unix timestamp; use a random id, and bind every witness to the id, the body hash and the signer's key hash.
* Sign payer and cold key through the `Signer` port so any slot can be filled remotely (SPO-05c-INV-010), including hardware keys.
* Decide registration versus re-registration in one place, from chain state, with `type:` as an explicit override; compare the pool id exactly rather than by substring count (SPO-05c-MODE-001).
* Exit non-zero on "no funds" and "not enough funds" (SPO-05c-PRE-007, SPO-05c-PRE-008) and on offline read-back mismatch.
* The first confirmation (SPO-05c-PR-001) is the only chance to review the deposit and fee; a remote signer needs the same decoded summary (certificates, deposit, outputs, TTL), not just a transaction body.
* Delete the registration certificate in the same transaction as recording the submission; today a crash between submit and deletion leaves a reusable certificate.
* The hardware-owner flow needs a first-class second phase (delegation certificates per owner) instead of a printed hint (SPO-05c-INV-006).

## Notes from the oracle (2026-11-16)

Run offline against the pinned scripts with a crafted transfer file (`spo/test/parity/pool_scripts_test.go`, `pool_oracle_test.go`).

* The queued transaction (body and signed), the queue entry, the history line and the descriptor record are byte-equal to upstream's for a first registration, a re-registration (the descriptor records an earlier `regSubmitted`) and two owners that both sign locally. The fee uses `2 + owners` witnesses and equals `calculate-min-fee`.
* The body carries the registration certificate first, then the owners' delegation certificates in descriptor order; the witness set is ordered by key hash, as `transaction assemble` orders it.
* **The unsigned body** in a witness collection is a text envelope of type `Tx ConwayEra`, description `Ledger Cddl Format` (cardano-cli 11.2.3.0 gives an unsigned body the type of a signed transaction). A key witness is `TxWitness ConwayEra`, description `Key Witness ShelleyEra`, CBOR `[vkey, signature]`.
* **The witness transfer file** for an owner who signs elsewhere is byte-equal to the Go use case's when both use the same collection id (the clock second) and tip; its fields are those of SPO-05c-OUT-003 in that order.
* `05d sign` (upstream) on that file gives a witness the Go collection imports; the collection completes and the assembled transaction equals upstream's.
* **SPO-05d-INV-006 confirmed**: `05d add` takes a witness whose last signature byte was flipped (it compares only the text of the body); the Go import verifies the signature over the body hash and the key hash of the slot, and refuses it before the slot is touched.
* The port's ticker lookup (hazard H6, requirement SPO-05c-SEC-002) is opt-in and sends the ticker only; the registration protection key is stored in the descriptor (SPO-05a-OUT-012) and never sent.
* Attaching `<pool>.metadata.json` to the transfer file embeds it as `01_workOffline attach` does; the port's shared attach also adds the history line `attached file '<name>'`, which the inline offer of 05c does not.

## Open questions

* The behaviour of `cardano-cli transaction witness` for a body that contains owner delegation certificates is cardano-cli's; whether owners must witness a re-registration when their delegation certificates are absent is a ledger rule that a preview-network test settles.
* Whether the `my-ip.at` ticker service is still operated, and its response contract beyond the text `OK`, cannot be determined from source.
* `ownerWitness` values other than `local`: only `external` is documented in the comments; the script treats every other word the same way (SPO-05c-INV-005).
* Offline mode and the TTL: the offline slot is computed from the wall clock (SPO-Cchain-INV-008); a skewed clock shifts the stored TTL. A test with a fixed clock settles the exact rounding.
