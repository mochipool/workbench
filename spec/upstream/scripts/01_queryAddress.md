+++
id = "01queryAddress"
kind = "script"
title = "Show the UTxOs or stake status of an address"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "chain-access"]
use_cases = ["QueryAddress"]
depends_on = ["Caddr", "Cutxo", "Cconv", "Clight", "Coffline", "Cchain", "Cconf", "Ptransfer", "Pfiles"]

upstream_path = "cardano/mainnet/01_queryAddress.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "1d7746cc6ee07d1892268fc585cbdcac526218ac3a5a921532259a9b54ba0d3f"
upstream_lines = 361
uses_common = [
  "checkAdaHandleFormat",
  "checkError",
  "convertToADA",
  "convert_actionCIP1292Bech",
  "convert_actionUTXO2Bech",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "generate_UTXO",
  "get_addressEra",
  "get_addressType",
  "get_currentSync",
  "queryLight_UTXO",
  "queryLight_stakeAddressInfo",
  "readOfflineFile",
  "resolveAdahandle",
  "showProcessAnimation",
  "stopProcessAnimation",
  "trimString",
]
cli_commands = [
  "query stake-address-info",
  "query utxo",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI",
  "koiosAPI/pool_info",
  "tokenMetaServer",
]
env_vars = []
+++

# 01_queryAddress: Show the UTxOs or stake status of an address

A read-only report on one address. For a payment address it lists the UTxOs, the total lovelace and the native assets (summed per asset, with registry names). For a stake address it reports the registration, the deposit, the rewards balance, the pool delegation (with pool info), the vote delegation and the governance actions the account is used in. The address comes from a name (`<name>.addr`), a literal address, or an ADA Handle. In offline mode the data comes from the snapshot in the transfer file ([Ptransfer](../patterns/Ptransfer.md)) instead of the chain. The script changes no state apart from two scratch files in the temp directory.

The tables are display only and are not specified. This spec records what is queried, from where, what is reported, and what stops the script. For a stake address the reported facts are the use case's result and are listed as `OUT` requirements; their wording and layout are free.

## Interface

- **SPO-01queryAddress-IF-001** Takes exactly one non-empty argument. Otherwise it prints `ERROR - Usage: ...` on **stdout** and exits 2. (src: L20)
- **SPO-01queryAddress-IF-002** The argument is an address name, a literal address, or an ADA Handle. A name is accepted with or without the `.addr` extension and with a directory part; a leading `./` is dropped (SPO-Pfiles-IN-001). (src: L20)

## Inputs

- **SPO-01queryAddress-IN-001** The address is the whole content of `<name>.addr` (trailing newlines trimmed). (src: L49)
- **SPO-01queryAddress-IN-002** Offline mode reads `.address."<addr>".utxoJSON` (payment) or `.address."<addr>".rewardsJSON` (stake), and `.tokenMetaServer."<subject>"` (registry names), from the transfer file via `readOfflineFile` (SPO-Ptransfer-IN-001, SPO-Ptransfer-OUT-005, SPO-Ptransfer-OUT-006, SPO-Ptransfer-OUT-008). (src: L85-L86, L197, L234-L235)
- **SPO-01queryAddress-IN-003** Settings read: `queryTokenRegistry`, `tokenMetaServer`, `koiosAPI` and `koiosAuthorizationHeader`, `adahandlePolicyID` (display of handles), `tempDir`, the work mode. (src: L47, L148-L167, L197, L269, L276)

## Behaviour

1. **Resolve the argument into an address file.**
   - **SPO-01queryAddress-IN-004** When `<name>.addr` exists, it is used. Otherwise the argument is trimmed and tried as a literal address: if `get_addressType` says `payment` or `stake` (SPO-Caddr-OUT-002), the argument's base name is written to `<tempDir>/tempAddr.addr` and that file is used. (src: L24-L29)
   - **SPO-01queryAddress-IN-005** Otherwise, when the argument has the form of an ADA Handle (SPO-Caddr-OUT-006), the lower-cased handle is resolved with `resolveAdahandle` (SPO-Caddr-IF-002), the resulting address is written to `<tempDir>/adahandle-resolve.addr`, and the handle is shown in place of the file name. Resolution failures end the script as in SPO-Caddr-INV-002; in offline mode resolution is refused (SPO-Caddr-PRE-002). (src: L32-L40, L47)
   - **SPO-01queryAddress-PRE-001** Otherwise exits 1 ("destination address can't be resolved"). (src: L43)
2. **Classify.**
   - **SPO-01queryAddress-INV-001** The address type decides the branch: `payment` for the UTxO report, `stake` for the stake report. Any other type prints "Address type unknown" and the script ends with exit 0. (src: L51-L54, L212, L357-L360)

### Payment address

3. **Fetch the UTxOs.**
   - **SPO-01queryAddress-EXT-001** Online: `cardano-cli <era> query utxo --output-text --address <addr>` (stderr merged into the captured text); light: `queryLight_UTXO`; both are converted by `generate_UTXO` (SPO-Cutxo-IF-001, SPO-Cutxo-OUT-001). When the Handle resolution has already left the UTxO text of the address (SPO-Caddr-OUT-007), it is used and no query is made. (src: L63-L82)
   - **SPO-01queryAddress-PRE-002** Online, when a query is needed, the node must be `synced` (SPO-Cchain-OUT-004), else exit 1. Light mode has no sync check here. (src: L64-L66)
   - **SPO-01queryAddress-PRE-003** A failing query prints the error text and ends the script with exit status 0 (the status passed to `exit` is read after an `echo`). (src: L69, L78)
   - **SPO-01queryAddress-MODE-001** Offline: `readOfflineFile` (exit 1 when the file is unusable, SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004), then the stored `utxoJSON` of the address. An address that is not in the file is refused with exit 1 ("include it first online"). (src: L85-L87)

> **Observed 2026-11-16:** offline, an address that is not in the file exits 1 for a payment address and 0 for a stake address (SPO-01queryAddress-PRE-006), and a Handle exits 1. The port answers all three with typed errors (`ErrNotInSnapshot` for both address kinds, `ErrAdaHandleUnsupported`) and, offline, reports the snapshot's `date` and `used` flag. The facts of the report equal the facts of the file (`TestQueryAddressOfflineMatchesTheSnapshot`).
   - **SPO-01queryAddress-PRE-004** Exits 1 ("no funds on the address") when the UTxO set is empty. (src: L91-L92)
4. **Report.**
   - **SPO-01queryAddress-OUT-001** Reports each UTxO (`<hash>#<index>`, lovelace, datum hash when present), the total lovelace (sum over all UTxOs), and, per distinct asset id, the total amount, the CIP-14 fingerprint (SPO-Cconv-OUT-013) and the asset name in readable form where possible (SPO-Cconv-OUT-016). ADA Handle assets are labelled as handles. Display only; nothing is written. (src: L91-L207)
   - **SPO-01queryAddress-EXT-002** When `queryTokenRegistry` is on, each distinct asset id is looked up for its ticker and name: online and light with `GET <tokenMetaServer>/<policy><assetNameHex>` (`curl -sL -m 20`), offline from the stored `tokenMetaServer` entry. A failed lookup shows no name. (src: L195-L200)

### Stake address

5. **Fetch the reward state.**
   - **SPO-01queryAddress-EXT-003** Online: `cardano-cli <era> query stake-address-info --address <addr>` (stderr discarded), compacted by `jq`; light: `queryLight_stakeAddressInfo` (SPO-Clight-OUT-008); offline: the stored `rewardsJSON`. (src: L221-L237)
   - **SPO-01queryAddress-PRE-005** A failing query prints the error text (empty for the cli, whose stderr is discarded) and ends the script with exit status 0, as in SPO-01queryAddress-PRE-003. (src: L225, L231)
   - **SPO-01queryAddress-PRE-006** Offline, an address that is not in the file prints the "include it first online" notice and ends the script with exit status 0. This differs from the payment branch, which exits 1. (src: L236)
   - **SPO-01queryAddress-PRE-007** Exits 1 ("not on the chain, register it first") when the result array is empty. (src: L255)
6. **Read the account.**
   - **SPO-01queryAddress-IN-006** Only the first element of the result is read: `stakeDelegation.stakePoolBech32`, `stakeRegistrationDeposit`, `rewardAccountBalance`, `voteDelegation` and the object `govActionDeposits` (action id to deposit). (src: L241-L253)
7. **Report.**
   - **SPO-01queryAddress-OUT-002** Reports: the account is registered with its deposit; the rewards balance, or that there are none; whether it is delegated to a pool and its id. (src: L256-L267, L303)
   - **SPO-01queryAddress-OUT-003** The vote delegation is reported as one of: always-no-confidence (`alwaysNoConfidence`), always-abstain (`alwaysAbstain`), not delegated (`notSet` or `null`), or delegated to a DRep or DRep script, in which case the CIP-129 id (`.cip129Bech32`), the legacy id (`convert_actionCIP1292Bech`, SPO-Cconv-OUT-020) and the key or script hash (`.keyHash` or `.scriptHash`) are shown. (src: L309-L337)
   - **SPO-01queryAddress-OUT-004** The governance actions that hold a deposit of this account are listed as bech32 action ids (`convert_actionUTXO2Bech`, SPO-Cconv-OUT-017) with the deposit in ADA. (src: L341-L354)
   - **SPO-01queryAddress-EXT-004** When the account is delegated, and the work mode is online or light, and `koiosAPI` is non-empty, the pool is described by `POST <koiosAPI>/pool_info` with body `{"_pool_bech32_ids":["<pool id>"]}`, the authorization header (empty in online mode, SPO-Cconf-MODE-004), 30-second timeout, up to 5 attempts one second apart on a transport failure. Only a status 200 with exactly one array element is used; the pool's `meta_json.name`, `meta_json.ticker` and `pool_status` (each `-` when absent) are shown. Any other outcome shows nothing. This call is made in full online mode too, although the node is the data source of everything else. (src: L266-L299)

## Work modes

- **SPO-01queryAddress-MODE-002** Payment and stake data come from the node (online), Koios (light) or the transfer file (offline); see SPO-01queryAddress-EXT-001, SPO-01queryAddress-EXT-003, SPO-01queryAddress-MODE-001. The stake report's pool-info call goes to Koios in online and light mode (SPO-01queryAddress-EXT-004) and is skipped offline. ADA Handles need online or light mode (SPO-Caddr-PRE-002). (src: L63-L89, L221-L239, L269)

## Prompts

No prompts.

## Outputs

Nothing is written for the report. **Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<tempDir>/tempAddr.addr` | the literal address argument | default | created or overwritten for a literal address |
| `<tempDir>/adahandle-resolve.addr` | the address a Handle resolved to | default | created or overwritten for a Handle |

Exit status 0 after a report. Other exits: see Failures.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Not exactly one non-empty argument | 2 | SPO-01queryAddress-IF-001 |
| Argument is no file, address or Handle | 1 | SPO-01queryAddress-PRE-001 |
| Handle cannot be resolved; offline Handle | 1 | SPO-01queryAddress-IN-005 |
| Payment, online: node not synced | 1 | SPO-01queryAddress-PRE-002 |
| Payment or stake: chain query failed | 0 | SPO-01queryAddress-PRE-003, SPO-01queryAddress-PRE-005 |
| Payment, offline: address not in the file | 1 | SPO-01queryAddress-MODE-001 |
| Payment: no UTxOs | 1 | SPO-01queryAddress-PRE-004 |
| Stake, offline: address not in the file | 0 | SPO-01queryAddress-PRE-006 |
| Stake: not registered | 1 | SPO-01queryAddress-PRE-007 |
| Address type is neither payment nor stake | 0 | SPO-01queryAddress-INV-001 |
| Offline file unusable | 1 | SPO-Coffline-PRE-001 |

## Security

- **SPO-01queryAddress-SEC-001** No secret is read or printed. Each lookup discloses to its third party what is asked: the address's stake pool to Koios (SPO-01queryAddress-EXT-004), asset ids to the token registry (SPO-01queryAddress-EXT-002) and Handles to Koios and the Handle API (SPO-Caddr-EXT-002, SPO-Caddr-EXT-004). In online mode these calls go out even though the node is the primary source. (src: L197, L276)

## Domain mapping

Use case `QueryAddress(addressRef)` producing a read model of a `PaymentAccount` (UTxOs, balance, assets) or a `StakeAccount` (registration, rewards, delegations).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(artefact)` | `<name>.addr` |
| `Ledger` | `addressInfo(address)` | Address type and era |
| `ChainQuery` | `utxos(address)`, `rewardAccount(stakeAddress)`, `tip()` | Online and light sources; offline adapter serves the snapshot |
| `Transport` | `importSnapshot()` | Offline source |
| `Directory` | `resolveHandle(handle)`, `tokenMetadata(subject)` | Handles, registry names |
| `Directory` | `poolInfo(poolId)` *(new)* | Pool name, ticker and status of the delegation |
| `UI` | `show(view)` | The report |

## Port notes

* Return a structured result and render it separately. The upstream report mixes querying and printing.
* Exit non-zero on every failed query (SPO-01queryAddress-PRE-003, SPO-01queryAddress-PRE-005), and use one exit code for "address not in the snapshot" in both branches (SPO-01queryAddress-MODE-001, SPO-01queryAddress-PRE-006).
* Resolve literals and Handles in memory; the two scratch files exist only to feed the shared file-based code path.
* In offline mode, show the snapshot's date (`.address.<addr>.date`) and the `used` flag next to the data, since the data can be stale.
* Take the pool info from the same `ChainQuery` adapter as the rest where possible, so that a node-only setup makes no third-party call.

## Open questions

* The shape of `stakeDelegation` in `cardano-cli query stake-address-info` for the release set in use: this script reads `.stakeDelegation.stakePoolBech32` (an object, as Koios light mode builds it, SPO-Clight-OUT-009), whereas 01_workOffline reads `.delegation // .stakeDelegation`. If the cli prints a plain pool id string, the field read here fails. Running the script against a registered, delegated stake address in online mode settles it.
* The shape of `voteDelegation` that `cardano-cli` prints (string, or object with `cip129Bech32`), which decides the branch of SPO-01queryAddress-OUT-003 in online mode.
