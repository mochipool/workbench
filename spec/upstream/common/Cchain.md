+++
id = "Cchain"
kind = "common"
title = "Chain position: epoch, tip, TTL and sync state"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["chain-access", "configuration"]
use_cases = []
depends_on = ["Cconf", "Clight"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
get_currentEpoch = "8fa5d567579bf67abefcce8a704f705db571289521ffee218b3be5f6b43501ce"
get_timeUntilNextEpoch = "2a347a49ae4284d230e88866bd16872f569799e703fca2e90afc5099c81095e7"
get_currentTip = "76a9cd62d57b81efdf0546f68f1107859525955d76c3c313c6d018b55a72874d"
get_currentTTL = "9016b4023afffae967af87571f2a681c7e5422fb9935761f07050ce66d5a9ac0"
get_currentSync = "0fb6d79eb9bb37a3d96aaf4cb3ce4c57919709ee576235bbe2f3d0f8a17b484c"
+++

# Cchain: Chain position: epoch, tip, TTL and sync state

Five small functions answer "where is the chain now?": the current epoch, the current tip slot, how long until the next epoch, the transaction expiry slot (tip plus a default lifetime) and whether the node is synced. Each works differently per work mode (see [Cconf](./Cconf.md)): **online** asks the local node through cardano-cli, **light** asks Koios (see [Clight](./Clight.md)), **offline** computes from the genesis files and the **local wall clock**. The offline arithmetic is specified exactly below because an offline adapter must reproduce it; it does not read the transfer file.

In the reimplementation these are a single `ChainQuery.tip()` (slot, epoch, era, sync progress) for online and light, plus a `Clock` adapter that computes slot and epoch from genesis parameters for offline.

## Calling convention

- **SPO-Cchain-INV-001** On failure these functions do not return a non-zero code. They print an error banner through `majorError` (stderr) and call `exit 1` (see SPO-Cconf-INV-024). Called directly, that ends the calling script. Called inside `$(...)` (the usual form), it ends only the command-substitution subshell: the caller sees an empty value and exit status 1 and continues unless it checks. (src: L835, L842, L848-L849, L884, L910, L917, L923-L924, L963, L981)
- **SPO-Cchain-INV-002** On success each function prints a single value to stdout and returns 0. (src: L873, L892, L953, L964, L985, L990, L994)

## get_currentEpoch

- **SPO-Cchain-OUT-001** Prints the current epoch number as a decimal integer. (src: L873)
- **SPO-Cchain-MODE-001** Online: runs `cardano-cli latest query tip <magicparam>` (stderr discarded) and reads the `.epoch` field. (src: L830)
- **SPO-Cchain-MODE-002** Online: when the field is empty (an upstream cardano-cli bug is the stated reason), the query is repeated up to two more times (three queries in total, no delay). If all three are empty it exits 1 with a banner saying the query failed and asking whether the node runs and the socket path is correct. (src: L833-L835)
- **SPO-Cchain-MODE-003** Light: the epoch is the `epoch_no` of the Koios tip (see `queryLight_epoch` in Clight). A failure prints that function's message through `majorError` and exits 1. (src: L841-L842)
- **SPO-Cchain-MODE-004** Offline: exits 1 when the Shelley genesis file or the Byron genesis file is missing, checked in that order. The transfer file is not consulted. (src: L848-L849)
- **SPO-Cchain-INV-003** Offline inputs. From the Byron genesis JSON: `blockVersionData.slotDuration` (milliseconds, `byronSlotLength`), `protocolConsts.k` (`byronK`), `startTime` (UTC seconds, `byronStartTimeSec`). From the Shelley genesis JSON: `slotLength` (seconds) and `epochLength` (slots per epoch). `byronToShelleyEpochs` (`E_b`) comes from the network profile (see Cconf). A missing JSON field is read as the text `null`; no validation follows. (src: L855, L862)
- **SPO-Cchain-INV-004** Offline Byron derivations, all integer arithmetic: `byronEpochLength = 10 * byronK` (slots per Byron epoch); `byronEndTimeSec = byronStartTimeSec + (E_b * byronEpochLength * byronSlotLength) / 1000` (multiply first, then integer-divide). (src: L856-L857, L931-L932)
- **SPO-Cchain-INV-005** Offline epoch: `epoch = E_b + ((now - byronEndTimeSec) / slotLength / epochLength)`, with `now` the local UTC time in whole seconds and two successive truncating integer divisions. (src: L865, L868)

Worked example (Mainnet values: `byronStartTimeSec=1506203091`, `byronK=2160`, `byronSlotLength=20000`, `E_b=208`, `slotLength=1`, `epochLength=432000`): `byronEpochLength=21600`, `byronEndTimeSec=1506203091+(208*21600*20000)/1000=1596059091`. At `now = 1596059091 + 10*432000 + 5`, epoch = `208 + 4320005/1/432000 = 218`.

> **Upstream quirk:** The comments call `epochLength` "In Secs" but the arithmetic treats it as slots (it is divided after `slotLength`). The result is right only because the genesis field is a slot count.

> **Upstream quirk:** Offline, a `now` earlier than `byronEndTimeSec` yields `E_b` (within one Shelley epoch length before the boundary; division truncates toward zero) or a smaller number, not the real Byron epoch; the function does not model the Byron era.

> **Upstream quirk:** The offline epoch depends entirely on the local clock; the transfer file's snapshot is ignored.

## get_timeUntilNextEpoch

- **SPO-Cchain-INV-006** Mode-independent: always computed from the Shelley genesis file and the local clock, even in online and light mode. It exits 1 when the Shelley genesis file is missing. (src: L884, L887-L891)
- **SPO-Cchain-OUT-002** Prints the number of seconds until the next epoch boundary as a decimal integer, in the range 1 to `epochLength`. Exactly on a boundary it prints `epochLength`. (src: L892)
- **SPO-Cchain-INV-007** Formula: `elapsed = now - systemStartSec`; `e = elapsed / epochLength` (truncating); `remaining = epochLength - elapsed + e * epochLength`, which equals `epochLength - (elapsed mod epochLength)`. `systemStartSec` is the Unix time of the genesis `systemStart` date string. (src: L888-L891)

> **Upstream quirk:** `epochLength` is a slot count but is used as a duration in seconds. That is correct only for networks with 1-second slots (all current ones). It also assumes every epoch since `systemStart` has the same length, which holds for the preconfigured networks.

## get_currentTip

- **SPO-Cchain-OUT-003** Prints the current tip slot number as a decimal integer. (src: L953)
- **SPO-Cchain-MODE-005** Online: runs `cardano-cli latest query tip <magicparam>` and reads `.slot`. (src: L905)
- **SPO-Cchain-MODE-006** Online: empty result is retried like SPO-Cchain-MODE-002 (three queries in total), then exits 1. (src: L908-L910)
- **SPO-Cchain-MODE-007** Light: the slot is the `abs_slot` of the Koios tip (see `queryLight_tip` in Clight). Failure prints that function's message through `majorError` and exits 1. (src: L916-L917)
- **SPO-Cchain-MODE-008** Offline: exits 1 when the Shelley or Byron genesis file is missing; the transfer file is not consulted. Reads the same genesis inputs as SPO-Cchain-INV-003 (only `slotLength` from the Shelley file). (src: L923-L924, L930, L936)
- **SPO-Cchain-INV-008** Offline slot: if `now < byronEndTimeSec` (still in the Byron era), `slot = ((now - byronStartTimeSec) * 1000) / byronSlotLength`; otherwise `slot = E_b * byronEpochLength + (now - byronEndTimeSec) / slotLength`, with the Byron derivations of SPO-Cchain-INV-004 and truncating integer division. (src: L939-L948)

Worked example (same Mainnet values as above): at `now = 1596059091 + 4320005` the slot is `208*21600 + 4320005 = 8812805`.

## get_currentTTL

- **SPO-Cchain-INV-009** Prints `tip + defTTL` as a decimal integer, with `tip` from `get_currentTip` in the current work mode and `defTTL = 100000` (see SPO-Cconf-INV-009). The result is the expiry slot for a new transaction (a little over a day at 1-second slots). (src: L962, L964)
- **SPO-Cchain-PRE-001** When `get_currentTip` fails inside the command substitution the function prints the (empty) message through `majorError` and exits 1. (src: L962-L963)

> **Upstream quirk:** The source marks this function "should not be used anymore"; scripts are meant to compute `tip + defTTL` themselves. Only one script (`12a_genAssetMeta.sh`) still calls it.

## get_currentSync

- **SPO-Cchain-OUT-004** Prints exactly one word: `synced`, `unsynced` or `offline`. (src: L985, L990, L994)
- **SPO-Cchain-MODE-009** Online: runs `cardano-cli latest query tip <magicparam>` and reads `.syncProgress` (a string). The result is `synced` only when it equals the exact text `100.00`, otherwise `unsynced`. (src: L976, L985)
- **SPO-Cchain-PRE-002** Online: when the first query returns an empty value the function always ends with a banner and exit 1, even if the repeated queries would have succeeded. (src: L979-L981)

> **Upstream quirk:** The two "retries" at L979-L980 assign to the wrong variables (`currentSyncp`, `currentTip`) so `currentSync` is never refilled. The empty-first-answer case is therefore always fatal. The second retry also overwrites the shell-global `currentTip` with the sync-progress string.

- **SPO-Cchain-MODE-010** Light: calls `queryLight_tip`; success prints `synced`, any failure prints `unsynced`. It never aborts: Koios answering with a tip is taken to mean its database is synced. (src: L989-L990)
- **SPO-Cchain-MODE-011** Offline: prints `offline` without any query. Callers compare against `synced`, so offline counts as not synced. (src: L994)

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `tip()` | Slot, epoch, era and sync progress; node socket and Koios adapters |
| `ChainQuery` | `syncStatus()` *(new)* | `synced` / `unsynced` / `offline`; the node adapter compares progress to 100.00, the Koios adapter treats a successful answer as synced |
| `Clock` | `now()` *(new)* | Local UTC seconds |
| `Clock` | `slotAt(instant, genesis)` *(new)*, `epochAt(instant, genesis)` *(new)* | Offline arithmetic of SPO-Cchain-INV-004, INV-005, INV-008 |
| `Clock` | `timeUntilNextEpoch(genesis)` *(new)* | SPO-Cchain-INV-007 |
| `Store` | `get(Genesis)` *(new)* | Shelley and Byron genesis files (paths from configuration) |

## Port notes

* The offline slot and epoch should be computed from one `GenesisParameters` value (Byron and Shelley slot lengths, `byronToShelleyEpochs`, start times) and tested against the worked examples, including a time inside the Byron era, which upstream gets wrong.
* Prefer the transfer file's snapshot tip when a snapshot is newer than the local clock suggests; upstream trusts the clock only. A fixed `Clock` makes the offline path testable.
* Return typed errors (`NodeUnreachable`, `GenesisMissing`) instead of exiting, so a caller in a command substitution cannot lose the failure.
* Fix the sync retry so that the repeated queries can recover, and compare progress numerically (for example at least 99.99) rather than against the string `100.00`.
* `timeUntilNextEpoch` should use the network's real slot length and, online, the node's tip.

## Open questions

* How does the shell treat the `null` text that a missing genesis field produces in the offline arithmetic? Settle by running the function with an incomplete genesis file.
* Does any current cardano-cli print `syncProgress` as something other than a two-decimal string? Settle with the release-set cli.
