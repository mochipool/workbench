+++
id = "Coffline"
kind = "common"
title = "Transfer file read and display"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["air-gap-transfer"]
use_cases = []
depends_on = ["Cconv", "Cconf"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
showOfflineFileInfo = "55fb034e2c5a0d1558ca01f4da0d314fe4a7864e8438731de570fc570bc1a2c8"
readOfflineFile = "2cefbeb4367c014ea2c7757393810d66305c5580da33a4880b811870c0c0929f"
+++

# Coffline: transfer file read and display

The air-gap transfer file (`offlineTransfer.json`, see the `Ptransfer` pattern for the full schema and who writes it) is how an offline machine gets chain state and how it hands signed transactions back. `readOfflineFile` loads it into memory and refuses when it is unusable; every offline-mode query and every upload/queue action starts with it. `showOfflineFileInfo` prints a summary, and it is also the only place in this file that documents which fields of the transfer file the scripts *consume* for display.

Both functions work on two globals: the path `offlineFile` (default `./offlineTransfer.json`, set at L59 and defaulted again when empty at L510) and the in-memory copy `offlineJSON`.

## readOfflineFile

All callers invoke it directly as a statement (`"offline") readOfflineFile;`), never in `$(...)`. An `exit 1` therefore ends the whole script.

- **SPO-Coffline-IN-001** Reads the file named by `offlineFile`. (src: L2588-L2589)
- **SPO-Coffline-PRE-001** Refuses with exit 1 when `offlineFile` is not a regular file (missing, or a directory). The message says the file is absent and points to `01_workOffline.sh new` for creating it. (src: L2588, L2594-L2595)
- **SPO-Coffline-PRE-002** Refuses with exit 1 when `jq` cannot parse the file as JSON. (src: L2589-L2590)
- **SPO-Coffline-PRE-003** Refuses with exit 1 when the parsed content is empty, which happens for a zero-length or whitespace-only file. (src: L2591)
- **SPO-Coffline-PRE-004** Refuses with exit 1 when `.protocol.parameters` does not have a positive `length`: absent, `null`, `{}`, `[]` and `""` all fail. This is the only schema check. (src: L2592)
- **SPO-Coffline-OUT-001** On success, sets the global `offlineJSON` to the pretty-printed re-serialisation of the file (`jq .`) and returns status 0. Nothing is written to disk and no field other than `protocol.parameters` has been checked, so a file without `protocol.era`, addresses or history is accepted. (src: L2589, L2592-L2598)

> **Upstream quirk:** `jq length` on a number returns its absolute value and fails on a boolean. A file with `"parameters": 5` is accepted, and one with `"parameters": true` is refused by the failed `jq` call. Neither occurs in files written by upstream scripts. (src: L2592)

> **Upstream quirk:** The missing-file branch assigns `offileJSON=null`, a misspelt variable that is never read. `offlineJSON` keeps whatever it held before. Since the branch always exits, this has no effect. (src: L2594)

## showOfflineFileInfo

- **SPO-Coffline-IF-001** Takes no argument and requires `offlineJSON` to be loaded already by `readOfflineFile`. It uses the globals `offlineFile` (for the file name shown), `offlineMode`, and `addrTypePayment` (`payment`, L354). It prints to the terminal only, changes no state, never calls `exit`, and returns 0. All output is display only and its wording is out of scope. (src: L2444-L2582)

The fields it reads, which document the transfer file schema as consumed, are given below. A missing field is printed as the text `null` by `jq -r`; only the cases noted below are handled.

- **SPO-Coffline-IN-002** `.protocol.parameters`: counted with `length`; the summary says "present" when above 0, else "missing". (src: L2449)
- **SPO-Coffline-IN-003** `.protocol.era`: shown when not `null`, else "missing". (src: L2451)
- **SPO-Coffline-IN-004** `.history`: an array. Its length is shown; when above 0, the last element's `.action` and `.date` are shown as the last action. (src: L2453-L2456)
- **SPO-Coffline-IN-005** `.tokenMetaServer`: an object; its entry count is shown when above 0. (src: L2458-L2459)
- **SPO-Coffline-IN-006** `.general.onlineCLI` and `.general.onlineNODE`, in offline mode (the file was produced on the online side): shown as `cli x / node y`. Outside offline mode `.general.offlineCLI` is shown instead. A `null` value is shown as `-.--.-`. (src: L2461-L2468)
- **SPO-Coffline-IN-007** `.address`: an object keyed by payment or stake address. For each key, in `jq` `keys` order (code-point ascending), it reads `.name`, `.totalamount` (lovelace, shown as ADA via `convertToADA`), `.totalassetscnt` (shown as "+ N Asset-Types" when above 0), `.date`, `.used` and `.type`. The entry reads "used" when `.used` equals `yes`, with ", but can receive" added when `.type` equals `payment`. (src: L2472-L2490)
- **SPO-Coffline-IN-008** `.drep`: an object keyed by DRep id. For each key, in ascending order, it reads `.name`, `.date` and `.deposit`. A present, non-empty `.deposit` is shown as "Deposit: N ADA", otherwise "not registered". (src: L2495-L2504)
- **SPO-Coffline-IN-009** `.files`: an object keyed by the attached file's path. For each key, in ascending order, it reads `.date` and `.size` (bytes). (src: L2509-L2516)
- **SPO-Coffline-IN-010** `.transactions`: an array of queued transactions, shown in array order. Every entry's `.type`, `.era`, `.date`, `.fromAddr` (payment account name), `.sendFromAddr` (payment address), `.toAddr` and `.sendToAddr` are read. (src: L2519-L2529)
- **SPO-Coffline-IN-011** Further fields per `.transactions[].type`, which doubles as the list of types the scripts write: `Transaction`, `Asset-Minting`, `Asset-Burning` need nothing more; `Withdrawal` reads `.stakeAddr` (name) and `.stakingAddr` (address); `StakeKeyRegistration` and `StakeKeyDeRegistration` read `.stakeAddr`; `DelegationCertRegistration` and `VoteDelegationCertRegistration` read `.delegName`; `PoolRegistration`, `PoolReRegistration` and `PoolRetirement` read `.poolMetaTicker`; `DRepIDRegistration`, `DRepIDReRegistration` and `DRepIDRetirement` read `.drepName`. Any other type is shown as an unknown transaction type. (src: L2531-L2576)

Fields that exist in the file but are not read here (`.address.<a>.utxoJSON`, signed transaction bodies and so on) belong to the `Ptransfer` schema.

## Mode

Mode-independent as a function. Callers use `readOfflineFile` in offline mode (as the `ChainQuery` adapter: it serves the snapshot) and in `01_workOffline` on the online side. `showOfflineFileInfo` switches its version line on `offlineMode`, per SPO-Coffline-IN-006.

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `Transport` | `importSnapshot()` | Loads the transfer bundle; raises one typed refusal for each of SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004 |
| `ChainQuery` | `protocolParameters()` | Offline adapter, served from the bundle's `protocol.parameters` |
| `UI` | `show(view)` | The summary of `showOfflineFileInfo` |

## Port notes

* The in-memory bundle should be a typed `TransferBundle`, validated once on load against the schema in `Ptransfer`. A reader that checks only `protocol.parameters` lets later steps fail with a confusing error.
* The global `offlineJSON` is what lets the offline adapter act as a `ChainQuery`; with a typed bundle there is no global.
* Keys are listed in sorted order here; a UI is free to order them differently.

## Open questions

None.
