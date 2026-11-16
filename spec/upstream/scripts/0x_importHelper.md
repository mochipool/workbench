+++
id = "0x"
kind = "script"
title = "Import an existing pool (info and keys) into a pool workspace, or export its info for offline use"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["workspace-import", "pool-operations", "key-custody"]
use_cases = ["ImportPoolConfiguration", "ExportPoolInfo"]
depends_on = ["Pfiles", "Ptransfer", "Coffline", "Cui", "Cconf", "Clight", "Ckey"]

upstream_path = "cardano/mainnet/0x_importHelper.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "c53c3c3da63a07738652e0a7aad7f6eebe0999948307ae26a67aca2985eeaaf5"
upstream_lines = 580
uses_common = [
  "ask",
  "checkError",
  "exists",
  "file_lock",
  "readOfflineFile",
  "showOfflineFileInfo",
  "trimString",
]
cli_commands = [
  "address build",
  "key non-extended-key",
  "key verification-key",
  "node key-hash-VRF",
  "node new-counter",
  "query protocol-parameters",
  "stake-address build",
  "stake-address registration-certificate",
  "stake-address stake-delegation-certificate",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI/pool_info",
  "koiosAPI/pool_updates",
]
env_vars = []
+++

# 0x_importHelper: Import an existing pool into a workspace, or export its info for offline use

Brings a pool that was set up with other tools into this script collection's layout. From the pool's public registration data (fetched from Koios, or read from an *info file*) and the operator's existing key files, it builds a new directory `<pool>/` that holds the pool descriptor `<pool>.pool.json`, the cold and VRF keys, and for every owner or reward account the payment and stake keys, addresses and the stake registration and delegation certificates. Used with a third argument, it does only the first half: it writes the pool's info file, so that an offline machine, which cannot query the chain, can import from it.

This script defines the **import use case** for the reimplementation: which sources it accepts, which artefacts it produces, which facts it takes from the chain and which from the operator, what it checks and what it does not. The file names are the contract of the file-system `Store` adapter and of any import of an upstream workspace; other adapters keep the semantics.

The prompts use `read -e -i` (readline with a pre-filled default) on the terminal, so the import part is interactive. The export part has one yes/no prompt.

## Interface

- **SPO-0x-IF-001** Takes two or three arguments: `<ImportName> <PoolID or InfoJSON> [export file]`. With any other count it prints the usage to stderr and exits 1. (src: L21-L26, L28-L49)
- **SPO-0x-IF-002** The pool name used for the directory and all file names is the first argument with a trailing `.json`, then a trailing `.pool`, removed from its base name, and then **every character that is not a letter or a digit removed** (hyphens, underscores and dots too). `my-pool.pool.json` gives `mypool`. The result is not checked for being empty. (src: L23)
- **SPO-0x-IF-003** The second argument is taken as an *info file* when it names an existing regular file. Otherwise, in online and light mode, it is taken as a pool id; in offline mode it is refused (SPO-0x-PRE-001). (src: L24, L53, L61-L63, L125-L127)
- **SPO-0x-IF-004** A third argument selects the export action (SPO-0x-OUT-001). Without it the script imports. (src: L25, L130)

## Inputs

- **SPO-0x-IN-001** An info file must parse as JSON and its `.meta_url` must match `https?://.*` and be at most 64 characters long; otherwise the script exits 1. No other field is checked at this point. (src: L53-L59)
- **SPO-0x-IN-002** A pool id is either 56 hexadecimal digits (converted to the bech32 pool id with the `bech32` tool and the prefix `pool`; failure exits 1), or a 56-character string starting with `pool1` that the `bech32` tool accepts. Anything else exits 1. (src: L63-L85)
- **SPO-0x-IN-003** The *info* (`importJSON`) is one JSON object, whatever its source. The import reads these members of it (the names are Koios `pool_info` names plus three members added by the script, SPO-0x-EXT-002 and SPO-0x-EXT-003): `pledge`, `fixed_cost`, `margin`, `metadata.name`, `metadata.description`, `metadata.ticker`, `metadata.homepage`, optional `metadata.extended`, `pool_status`, `lastupdate_time`, `lastupdate_epoch`, `pool_id_hex`, `pool_id_bech32`, `meta_url`, `vrf_key_hash`, `op_cert_counter`, `relays[]`, `owners[]` and `reward_addr`. (src: L57, L182-L210, L239-L256, L343-L344, L536-L543)
- **SPO-0x-IN-004** Settings read: `koiosAPI` and `koiosAuthorizationHeader` (fetch), `bech32_bin`, `addrformat` (network flag for address building), the work mode, the era argument for `cardano-cli`, `offlineFile`. (src: L66-L69, L89, L494, L501, L508-L513)

## Behaviour: acquire the info

1. **Read the info file, or fetch from Koios.**
   - **SPO-0x-PRE-001** Offline mode with no usable info file exits 1 (a pool id cannot be used offline; fetch the info file on an online machine first). (src: L125-L127)
   - **SPO-0x-EXT-001** Pool: `POST <koiosAPI>/pool_info` with body `{"_pool_bech32_ids":["<bech32 pool id>"]}`, the authorization header, JSON `Accept` and `Content-Type`, 30-second timeout, no retry. The response must be an array with exactly one element (else exit 1); that element is the info. Its `meta_url` must satisfy SPO-0x-IN-001 (else exit 1). (src: L87-L99)
   - **SPO-0x-EXT-002** Latest update: `GET <koiosAPI>/pool_updates?_pool_bech32=<id>`; the first element of the response array is used (empty or unparsable exits 1). Its `block_time` is added to the info as `lastupdate_time` and its `active_epoch_no` as `lastupdate_epoch`. (src: L102-L116)
   - **SPO-0x-EXT-003** Metadata: `GET <meta_url>` with `curl -sL` (no timeout; the status code is not checked), reformatted by `jq -M` and stored as the info's `metadata` member. A curl failure or a body that is not JSON exits 1. (src: L118-L124)
   - **SPO-0x-INV-001** The numeric checks of `block_time` and `active_epoch_no` never refuse: they compare `$((x+0))` with `x`, which agree for every value `bash` can evaluate, and the epoch check uses an undefined variable (`active_epoch_no`) instead of `latestUpdateEpoch`. A missing or malformed value instead makes the following `jq` update fail silently and the info becomes empty, which the field reads of SPO-0x-PRE-004 then refuse. (src: L108-L116)

> **Upstream quirk:** The checks at L109 and L114 are dead code. A port validates both values and refuses at that point.

## Behaviour: export (third argument)

2. **Export instead of import.**
   - **SPO-0x-PRE-002** Refuses with exit 1 in offline mode, because an export needs the online source. This is checked after the info has been acquired, so an offline run with an info file also reaches this check. (src: L130-L131)
   - **SPO-0x-PRE-003** Refuses with exit 1 when the export file already exists. (src: L132)
   - **SPO-0x-OUT-001** Writes the info (SPO-0x-IN-003) to the export file as JSON, with the default file mode, not locked; a write failure ends with its status. The info contains public chain data only. (src: L133-L135)
   - **SPO-0x-PR-001** Asks `Include the '<file>' into '<offlineFile>' to transfer it in one step?`, default **No**. On "yes" the file is attached to the transfer file as in SPO-Ptransfer-OUT-017 and SPO-Ptransfer-OUT-018: the transfer file is read directly (a missing or empty file counts as `{}`, an unparsable one exits 1; `readOfflineFile` is not used), `files."<export file>"` and a history entry are added, the file is rewritten and the summary shown. (src: L137-L161)
   - **SPO-0x-INV-002** The export action always ends with exit 1 after printing "You can now use/transfer this file", even on success, and never starts the import. (src: L163-L164)

> **Upstream quirk:** Export success is reported with exit 1. A caller cannot tell it from a failure except by checking that the export file exists. A port exits 0.

## Behaviour: import

3. **Prepare the workspace directory.**
   - **SPO-0x-PR-002** When the directory `<pool>/` exists, asks whether to continue, default **No**; a "no" exits 1. (src: L170)
   - **SPO-0x-OUT-002** Creates `<pool>/` (with parents) when absent. A failure ends with its status. (src: L173)
   - **SPO-0x-PRE-004** Exits 1 when `<pool>/<pool>.pool.json` already exists. The check runs after the directory was created, so a refused import can leave an empty directory. (src: L176)
   - **SPO-0x-PRE-005** Each member of SPO-0x-IN-003 that the import needs must be present and non-empty, otherwise exit 1 naming the member. These are: `pledge`, `fixed_cost`, `margin`, `metadata.name`, `metadata.description`, `metadata.ticker`, `metadata.homepage`, `pool_status`, `lastupdate_time`, `lastupdate_epoch`, `pool_id_hex`, `pool_id_bech32`. `metadata.extended` is optional (empty when absent). The relays, owners, reward address, VRF hash and counter are not required here. (src: L182-L203)
4. **Build the descriptor.**
   - **SPO-0x-OUT-003** The on-chain counter `op_cert_counter`, when `null` (no block minted yet), is treated as -1 and an informational line is shown. (src: L206-L210)
   - **SPO-0x-OUT-004** The descriptor is a pool JSON (schema of SPO-Pfiles-OUT-017) with: `poolName` = the import name; `poolOwner` = `[]`; `poolRewards` = `""`; `poolPledge`, `poolCost`, `poolMargin` from `pledge`, `fixed_cost`, `margin`; `poolRelays` = `[]`; `poolMetaName`, `poolMetaDescription`, `poolMetaTicker`, `poolMetaHomepage` from `metadata.*`; `poolMetaUrl` from `meta_url`; `poolExtendedMetaUrl` from `metadata.extended` (empty string when absent); a marker member `---` ("DO NOT EDIT OR DELETE BELOW THIS LINE"); `poolID` from `pool_id_hex` and `poolIDbech` from `pool_id_bech32`. All values are strings. (src: L213-L234)
   - **SPO-0x-OUT-005** Each relay of `relays[]` becomes `{relayType, relayEntry, relayPort}`: `relayType` is the name of the single member of the relay that is non-null and not `port` (`ipv4`, `ipv6`, `dns` or `srv`, which `05a` accepts as relay types), `relayEntry` its value, `relayPort` the `port` as a string (empty when null). A relay with no such member, or with an entry longer than 64 characters, exits 1. (src: L239-L258)
   - **SPO-0x-OUT-006** When `pool_status` is `registered`, the descriptor also gets `regEpoch` = `lastupdate_epoch` and `regSubmitted` = the RFC-5322 date of `lastupdate_time` (`date -R --date=@<time>`). (src: L260-L264)
   - **SPO-0x-INV-003** The descriptor is held in memory and shown; it is written only at the end (SPO-0x-OUT-016), after the keys. Owners found while importing keys are added to it (SPO-0x-OUT-014, SPO-0x-OUT-015). (src: L266-L267, L538, L545, L573)
5. **Import the cold key.**
   - **SPO-0x-PR-003** Asks for the path of `node(cold).skey`, pre-filled with `node.skey`; blank skips the import. A leading `~` is replaced by `$HOME`. A failed attempt asks again with the same pre-filled path; the loop ends on success or blank. (src: L316-L325)
   - **SPO-0x-PRE-006** An attempt is refused (and asked again) when the source is not a regular file, when `<pool>/<pool>.node.skey` already exists, or when the source's `.type` does not contain `SigningKey`. (src: L274-L280)
   - **SPO-0x-OUT-007** On success: the source is **copied** to `<pool>/<pool>.node.skey` (locked `0400`); `<pool>.node.vkey` is derived by `cardano-cli <era> key verification-key --signing-key-file ... --verification-key-file ...` (locked); `<pool>.node.counter` is made by `cardano-cli <era> node new-counter --cold-verification-key-file <vkey> --counter-value <N> --operational-certificate-issue-counter-file <counter file>` with **N = on-chain `op_cert_counter` + 1** (0 when none was minted, SPO-0x-OUT-003), its `description` is set to `Next certificate issue number: <N>`, and it is locked. A failing cardano-cli ends the attempt and the prompt repeats. (src: L282-L309)
   - **SPO-0x-INV-004** The cold key is **not** checked against the pool: its verification-key hash is not compared with `pool_id_hex`. Any signing key with a `SigningKey` type is accepted. (src: L271-L312)
6. **Import the VRF key.**
   - **SPO-0x-PR-004** Asks for the path of `vrf.skey`, pre-filled with `vrf.skey`, blank skips; same loop and `~` rule as SPO-0x-PR-003. (src: L363-L374)
   - **SPO-0x-PRE-007** An attempt is refused (and asked again) when the source is not a regular file, `<pool>/<pool>.vrf.skey` exists, the type lacks `SigningKey`, or the key's VRF hash differs from the pool's `vrf_key_hash`. The hash is computed by deriving the verification key of the source (`cardano-cli <era> key verification-key`), dropping the first 4 hex characters of its `cborHex`, and running `cardano-cli <era> node key-hash-VRF --verification-key <hex>`. The check precedes the copy. (src: L333-L345)
   - **SPO-0x-OUT-008** On success the source is copied to `<pool>/<pool>.vrf.skey` and the verification key derived to `<pool>.vrf.vkey`, both locked `0400`. (src: L347-L358)
7. **Import the owner and reward accounts.** The loop below repeats per account.
   - **SPO-0x-PR-005** Asks for an account name (pre-filled `owner`, then `owner-2`, `owner-3`, ... and `owner_andor_rewards` after the go-back prompt); blank ends the account loop. The name is used unchecked as a file-name prefix (SPO-0x-SEC-002). (src: L450-L458, L554-L557, L566)
   - **SPO-0x-PR-006** For each account asks for the path of `payment.skey` (pre-filled `payment.skey`; blank gives up this account) and then of `stake.skey` (pre-filled `stake.skey`; blank gives up the rest of the account). A failed attempt asks again. The staking key is only asked for after a successful payment key. (src: L461-L486)
   - **SPO-0x-PRE-008** A payment or stake key attempt is refused (and asked again) when the source is not a regular file, `<pool>/<account>.payment.skey` (or `.staking.skey`) already exists, or the type lacks `SigningKey`. (src: L380-L386, L416-L422)
   - **SPO-0x-OUT-009** On success the source is copied to `<pool>/<account>.payment.skey` (or `.staking.skey`) and locked `0400`; the verification key is derived to `<account>.payment.vkey` (or `.staking.vkey`); when the derived key's type contains `EXTENDED` (any letter case) it is converted in place to a normal verification key with `cardano-cli <era> key non-extended-key`; it is locked `0400`. (src: L388-L407, L424-L443)
   - **SPO-0x-OUT-010** With both keys imported, `<pool>/<account>.payment.addr` is built from the payment and stake verification keys (`cardano-cli <era> address build --payment-verification-key-file ... --staking-verification-key-file ... <addrformat>`) and `<account>.staking.addr` with `cardano-cli <era> stake-address build --staking-verification-key-file ... <addrformat>`; both are locked `0400`. (src: L492-L504)
   - **SPO-0x-OUT-011** `<account>.staking.cert`, the stake address registration certificate, is made with `cardano-cli <era> stake-address registration-certificate --staking-verification-key-file ... --key-reg-deposit-amt <deposit> --out-file ...` and locked. `<deposit>` is `.stakeAddressDeposit` of the protocol parameters of the current work mode (SPO-0x-MODE-001). A failure ends the script with its status. (src: L506-L521)
   - **SPO-0x-OUT-012** `<account>.deleg.cert`, the delegation certificate to this pool, is made with `cardano-cli <era> stake-address stake-delegation-certificate --stake-verification-key-file ... --cold-verification-key-file <pool>/<pool>.node.vkey --out-file ...` and locked, only when `<pool>.node.vkey` and the account's staking verification key exist, i.e. only when the cold key was imported before. (src: L523-L530)
   - **SPO-0x-OUT-013** Neither certificate is submitted; they are inputs for the registration scripts (SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007). (src: L506-L530)
   - **SPO-0x-OUT-014** When the account's staking address (`<account>.staking.addr`) appears in the info's `owners[]`, the descriptor's `poolOwner` gets `{ownerName: <account>, ownerWitness: "local"}`. (src: L533-L540)
   - **SPO-0x-OUT-015** When the account's staking address equals the info's `reward_addr`, the descriptor's `poolRewards` is set to the account name. (src: L542-L547)
   - **SPO-0x-INV-005** An account that matches neither is still imported (keys, addresses, certificates), but is not recorded in the descriptor. No other relation between the supplied keys and the on-chain pool is verified. (src: L532-L547)
   - **SPO-0x-PR-007** After the account loop, when `poolRewards` is still empty, asks `Currently there is no rewards account included, do you wanna go back and add a payment/staking keypair for the rewards account?`, default **Yes**: "yes" repeats the account loop, "no" leaves it. When a rewards account was found the question is skipped. (src: L560-L568)
8. **Write the descriptor.**
   - **SPO-0x-OUT-016** Writes the descriptor to `<pool>/<pool>.pool.json` and locks it `0400`, then shows it. A write failure ends with its status. (src: L571-L577)

## Work modes

- **SPO-0x-MODE-001** Reading an info file works in every mode. Fetching from Koios (a pool id) and export need online or light mode; light mode adds the Koios token header (SPO-Cconf-MODE-004), online mode sends the request without one. The stake deposit of SPO-0x-OUT-011 comes from `cardano-cli <era> query protocol-parameters` (online), the light-mode parameters document (light), or `.protocol.parameters` of the transfer file read through `readOfflineFile` (offline; an unusable file exits 1, SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004). Nothing else in the import touches the chain. (src: L61, L125-L131, L508-L514)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Attach the export file to the transfer file (SPO-0x-PR-001) | No | Adds `files."<export file>"` |
| Destination directory exists, continue (SPO-0x-PR-002) | No | No: exit 1 |
| Path of `node(cold).skey` (SPO-0x-PR-003) | `node.skey`; blank skips | Imports the cold key |
| Path of `vrf.skey` (SPO-0x-PR-004) | `vrf.skey`; blank skips | Imports the VRF key |
| Account name (SPO-0x-PR-005) | `owner`, `owner-N`; blank ends | Names the files of an owner or reward account |
| Path of `payment.skey`, `stake.skey` (SPO-0x-PR-006) | `payment.skey`, `stake.skey`; blank gives up | Imports the account keys |
| No rewards account yet, go back (SPO-0x-PR-007) | Yes | Repeats the account loop |

## Outputs

**Upstream file contract.** Import (`<pool>` as in SPO-0x-IF-002, `<acc>` the account name):

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>/` | directory | default | created |
| `<pool>/<pool>.node.skey` | copy of the supplied cold signing key | `0400` | created |
| `<pool>/<pool>.node.vkey` | derived verification key | `0400` | created |
| `<pool>/<pool>.node.counter` | `NodeOperationalCertificateIssueCounter`, next number = chain counter + 1 | `0400` | created |
| `<pool>/<pool>.vrf.skey`, `.vrf.vkey` | copy of the VRF signing key, derived verification key | `0400` | created |
| `<pool>/<acc>.payment.skey`, `.payment.vkey`, `.payment.addr` | copied key, derived (non-extended) key, base address | `0400` | created |
| `<pool>/<acc>.staking.skey`, `.staking.vkey`, `.staking.addr` | copied key, derived (non-extended) key, stake address | `0400` | created |
| `<pool>/<acc>.staking.cert` | stake registration certificate with the current deposit | `0400` | created |
| `<pool>/<acc>.deleg.cert` | delegation certificate to the pool | `0400` | created (cold key imported first) |
| `<pool>/<pool>.pool.json` | descriptor, SPO-0x-OUT-004 to SPO-0x-OUT-006, SPO-0x-OUT-014, SPO-0x-OUT-015 | `0400` | created |

Export: the export file (the info JSON, default mode, created) and, on request, `offlineTransfer.json` (entry `files."<export file>"` added, SPO-0x-PR-001). Not produced by the import: the KES keys and counters, the pool metadata file `<pool>.metadata.json`, `<pool>.pool.id`, the registration certificate and the pool witness files. Success of the import is exit 0.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Wrong argument count | 1 | SPO-0x-IF-001 |
| Info file invalid, or `meta_url` invalid | 1 | SPO-0x-IN-001 |
| Pool id malformed | 1 | SPO-0x-IN-002 |
| Offline with a pool id | 1 | SPO-0x-PRE-001 |
| Koios or metadata fetch failed or not unique | 1 | SPO-0x-EXT-001, SPO-0x-EXT-002, SPO-0x-EXT-003 |
| Export in offline mode, or export file exists | 1 | SPO-0x-PRE-002, SPO-0x-PRE-003 |
| Export succeeded | 1 | SPO-0x-INV-002 |
| Directory exists and operator declines | 1 | SPO-0x-PR-002 |
| `<pool>.pool.json` exists | 1 | SPO-0x-PRE-004 |
| Required info member missing or empty | 1 | SPO-0x-PRE-005 |
| Relay without usable entry, or entry too long | 1 | SPO-0x-OUT-005 |
| Key attempt refused | re-prompt, no exit | SPO-0x-PRE-006, SPO-0x-PRE-007, SPO-0x-PRE-008 |
| cardano-cli or write failure for a certificate, address or descriptor | cardano-cli's code or 1 | SPO-0x-OUT-010 to SPO-0x-OUT-012, SPO-0x-OUT-016 |
| Offline file unusable (deposit lookup) | 1 | SPO-0x-MODE-001 |

A failure inside a key attempt (SPO-0x-OUT-007, SPO-0x-OUT-008, SPO-0x-OUT-009) ends only that attempt, which runs in a subshell, and the prompt repeats; the steps already done are not undone. Because the copy exists, the next attempt hits "destination exists" (SPO-0x-PRE-006, SPO-0x-PRE-008) until the operator deletes the file by hand or skips.

## Security

- **SPO-0x-SEC-001** The signing keys are **copied** to the workspace as they are: plaintext stays plaintext, with mode `0400`. The source files remain, so each key then exists twice. An **encrypted** key (SPO-Ckey-OUT-001) cannot be imported: the cardano-cli cannot derive its verification key, the attempt fails after the copy (cold, payment, stake) or at the VRF hash probe (VRF), and no decryption is offered. (src: L282-L293, L342-L345, L388-L397, L424-L433)
- **SPO-0x-SEC-002** The account name, unlike the pool name, is not sanitised: the intended filter (`${ownerName//[^[:alnum:]]-_/}`) matches only a non-alphanumeric character followed by the two characters `-_`, so nearly every name passes. A name such as `../x` makes the script write key, address and certificate files outside `<pool>/`. (src: L458, L557)
- **SPO-0x-SEC-003** The pool id, pool and metadata data are fetched from third parties (Koios and the pool's metadata URL) and written into the descriptor without further validation beyond SPO-0x-PRE-005 and the relay length limit; a hostile metadata server controls descriptor text such as `poolMetaName`. The values are pasted into a JSON text by shell string interpolation, so a double quote in them breaks the descriptor. (src: L118-L124, L213-L234)
- **SPO-0x-SEC-004** The script prints the descriptor and calls to `cardano-cli`, never key contents. No password is read. (src: L266-L267, L576-L577)

## Domain mapping

Use cases: `ImportPoolConfiguration(infoSource, keySources)` and `ExportPoolInfo(poolId, destination)`. Aggregates: `ImportPlan` (workspace-import) producing a `StakePool` with its `PoolRegistration` descriptor, `KeyPair`s for cold and VRF and an owner `PaymentAccount` / `StakeAccount` pair per account.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Directory` | `poolInfo(poolId)` *(new)* | Koios `pool_info` (SPO-0x-EXT-001) |
| `Directory` | `poolUpdates(poolId)` *(new)* | Koios `pool_updates` (SPO-0x-EXT-002) |
| `Directory` | `fetchUrl(url)` | Metadata (SPO-0x-EXT-003) |
| `Transport` | `attach(file)` | Optional attach of the export file |
| `Store` | `put(artefact)`, `exists(artefact)`, `lock(artefact)` | Workspace files |
| `Vault` | `seal(secret, policy)` | Imported signing keys (upstream: plain copy) |
| `KeyGen` | `deriveVerificationKey(signingKey)` *(new)* | `key verification-key`, `non-extended-key` |
| `Ledger` | `vrfKeyHash(vkey)` *(new)* | `node key-hash-VRF` |
| `Ledger` | `newOpCertCounter(coldVkey, value)` *(new)* | `node new-counter` |
| `Ledger` | `buildAddress(credentials)` | Payment and stake addresses |
| `Ledger` | `makeCertificate(kind, params)` | Stake registration and delegation certificates |
| `ChainQuery` | `protocolParameters()` | Stake address deposit |
| `UI` | `askText(prompt, default)` *(new)*, `confirm(prompt, default)`, `show(view)` | Prompts with a pre-filled default |

## Port notes

* Split the two use cases: export is a read of public data with a destination, and exits 0 (SPO-0x-INV-002). Import becomes a plan that the operator reviews before anything is written, instead of a stream of file writes.
* Seal imported signing keys at once and verify that the key belongs to the pool: compare the cold key's hash with `pool_id_hex`, the VRF key's hash with `vrf_key_hash` (upstream does this only for VRF, SPO-0x-INV-004), and each account's stake address against `owners[]` and `reward_addr`. Offer to decrypt an encrypted source key through `Vault.unseal` instead of failing (SPO-0x-SEC-001).
* Make the import atomic: build everything in a staging area and publish it at once, so that a refused attempt leaves nothing behind (SPO-0x-PRE-004, SPO-0x-PRE-006).
* Validate `block_time` and `active_epoch_no` really (SPO-0x-INV-001), sanitise account names (SPO-0x-SEC-002), build the descriptor with a JSON library (SPO-0x-SEC-003) and refuse an empty pool name (SPO-0x-IF-002). Keep the name sanitising rule for compatibility with existing workspaces, or reject unsafe names instead of silently dropping characters.
* The `ownerWitness` of an imported owner is always `local`. A port supports an owner whose key stays elsewhere (external witness, hardware wallet) by recording the owner without importing a key.
* The counter in `<pool>.node.counter` must never be lower than the chain's; an import should refuse a lower stored value and show the chain's value next to it (SPO-0x-OUT-007).
* A non-interactive import (a manifest of key paths and account names) is needed for server mode.

## Open questions

* Whether Koios returns `pool_updates` newest first, so that the first element is the latest update (SPO-0x-EXT-002); and whether `op_cert_counter` is the counter of the last block (so that `+ 1` is the next counter to use). A query against a known pool settles both.
* The behaviour when `koiosAPI` is empty (networks without a Koios endpoint) in light mode or online mode: nothing checks it, so the request goes to a relative URL and fails at SPO-0x-EXT-001.
* What happens when a relay has more than one non-null member besides `port` (SPO-0x-OUT-005): the two values are read as one multi-line string; the resulting descriptor is probably invalid. Koios documents one per relay.
* The interplay of the `returnCode` variable across account iterations (SPO-0x-PR-006): a blank answer at the payment prompt leaves the previous iteration's value in place, and the guard that should skip the stake prompt then depends on the shell's handling of an empty `[ ! == "" ]`. A test with two accounts, the second skipped, settles whether the stake prompt appears.
