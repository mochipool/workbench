+++
id = "04e"
kind = "script"
title = "Check an operational certificate counter against the chain"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "chain-access"]
use_cases = ["CheckOperationalCertificate", "QueryOpCertCounter"]
depends_on = ["Cui", "Cchain", "Cconv", "Cconf", "Pfiles", "04d"]

upstream_path = "cardano/mainnet/04e_checkNodeOpCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "6b259379bf9d260d4f1b8a0189d8076ff2965d18ff93d3b02ba450cf3b67e7ba"
upstream_lines = 393
uses_common = [
  "ask",
  "checkError",
  "get_currentEpoch",
  "get_currentSync",
  "get_currentTip",
  "int_from_cbor",
  "majorError",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = [
  "query kes-period-info",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI",
  "koiosAPI/pool_info",
]
env_vars = []
+++

# 04e_checkNodeOpCert: Check an operational certificate counter against the chain

A read-only check with two subjects. Given an opcert file (or a pool name from which the newest opcert file is found) and a check type `current` or `next`, it compares the counter and the KES validity window inside the opcert with the chain and prints a verdict. Given only a pool id (bech32 or hex) or a pool name with a `.pool.id-bech` file, it asks Koios for the last opcert counter the chain has seen and tells the operator which counter the next opcert needs. It writes nothing. Offline mode is refused. **The verdict is display only: every completed check, including a failed one, exits 0.**

## Interface

- **SPO-04e-IF-001** Takes one or two positional arguments. Two arguments: `<opcert file | pool name> <current|next>` (second argument case-insensitive). One argument: `<bech32 pool id | hex pool id | pool name>`. (src: L24, L70-L76, L99)
- **SPO-04e-IF-002** Prints usage to stderr and exits 1 when no argument is given or when two arguments are given and the second is not `current`/`next`. (src: L70, L73)
- **SPO-04e-IF-003** With three or more arguments no subject is selected: the script does nothing and exits 0. (src: L70-L99, L148, L356, L391-L392)
- **SPO-04e-IF-004** With two arguments, if the first is not an existing file the script takes the last entry, in version-sort order, of `<arg>.node-*.opcert` and asks "Should the file '<f>' be used for the check?" with default Yes. A "no" exits 1. When no such file exists it exits 1 with a hint to create one with 04c and 04d. (src: L83-L95)
- **SPO-04e-IF-005** With one argument, the subject is selected in this order: (1) 56 hex digits (case-insensitive): converted to bech32 with `bech32 pool`, a failed conversion exits 1; (2) a string of 56 characters starting `pool1` (case-insensitive): must decode as valid bech32, else exit 1; (3) an existing file `<arg>.pool.id-bech`: confirmed with default Yes (SPO-04e-PR-001), its content becomes the pool id; (4) otherwise exits 1. (src: L100-L138)
- **SPO-04e-PR-001** Asks "Should the Pool-ID from the file '<arg>.pool.id-bech' be used for the OpCertCounter query?" with default Yes after pointing out that a second argument selects the detailed check. On No it prints an error and the usage; when an opcert exists for the pool it exits 1 with a suggested command, otherwise it continues with no subject selected and exits 0. (src: L122-L135)

## Inputs

- **SPO-04e-IN-001** Local-file checks read the opcert file, the Shelley genesis file (`slotLength`, `slotsPerKESPeriod`, `maxKESEvolutions`) and, in light mode, nothing else on disk. (src: L169-L170, L203)
- **SPO-04e-IN-002** The opcert counter is a decimal; both `onDisk` and the on-chain value are integers. A missing on-chain counter is represented as -1 (see SPO-04e-INV-001). (src: L191, L221, L233)

## Behaviour

1. **Offline refusal.**
   - **SPO-04e-PRE-001** Exits 1 in offline mode for both subjects: "online or light mode needed". It runs after the argument resolution and its prompts, so a prompt can appear before the refusal. (src: L152, L359)
2. **Local opcert file** (two arguments).
   - **SPO-04e-PRE-002** In full online mode exits 2 when the node is not synced (SPO-Cchain-OUT-004), once up front and again immediately before the query. Light mode has no sync check. (src: L155-L158, L182-L183)
   - **SPO-04e-EXT-001** Takes the tip slot (`get_currentTip`, SPO-Cchain-OUT-003) and the epoch (`get_currentEpoch`, display only) in the active work mode; a failure ends the script. (src: L165-L166)
   - **SPO-04e-PRE-003** Exits 1 when the Shelley genesis file is missing. (src: L169)
   - **SPO-04e-INV-002** `currentKESperiod = floor(tipSlot / (slotsPerKESPeriod * slotLength))`, negative results become 0 (same formula and quirk as SPO-04d-INV-001). (src: L170-L174)
   - **SPO-04e-INV-001** `onChain` is the last opcert counter the chain has seen for the pool, or -1 when none; `nextChain = onChain + 1`. (src: L191, L221-L223, L277)
   - **SPO-04e-INV-003** `expireKESperiod = onDiskKESStart + maxKESEvolutions` where `onDiskKESStart` is the KES start period recorded in the opcert. (src: L247)
   - **SPO-04e-OUT-001** KES-interval verdict: **OK** when `onDiskKESStart <= currentKESperiod < expireKESperiod`; otherwise **FALSE, out of range**. When OK it reports the remaining time `expireKESperiod * slotsPerKESPeriod * slotLength - tipSlot` seconds (display colour thresholds one week and three weeks, display only); when out of range it reports `tipSlot - expireKESperiod * slotsPerKESPeriod * slotLength` seconds since expiry. (src: L250-L273)
   - **SPO-04e-OUT-002** For `next`: **OK** when `onDisk == nextChain`, else **FALSE, not latest+1**. A FALSE result also prints the counter to use, `nextChain`, with the commands `04c` then `04d <pool> <nextChain>`. When the KES check failed but the counter is OK it advises re-issuing with the same counter. (src: L279-L305)
   - **SPO-04e-OUT-003** For `current`: **OK, no block yet** when `onChain == -1` and `onDisk == 0`; **OK** when `onChain == onDisk`; otherwise **FALSE, OnChain NOT equal to File Counter**. With a KES error and an OK counter it advises re-issuing with `nextChain`. (src: L307-L346)
   - **SPO-04e-INV-004** The script exits 0 after any verdict, OK or FALSE: the verdicts of SPO-04e-OUT-001 to SPO-04e-OUT-003 are not reflected in the exit status. A caller must parse the verdict text or rerun the logic. (src: L391-L392)
3. **Pool id only** (one argument).
   - **SPO-04e-EXT-002** Sends `POST <koiosAPI>/pool_info` with body `{"_pool_bech32_ids":["<poolID>"]}`, headers `authorization` (`koiosAuthorizationHeader`), `Accept` and `Content-Type` JSON, `-L`, 30-second timeout, one attempt. The request is made in full online mode as well as light mode. (src: L361-L366)
   - **SPO-04e-PRE-004** Exits 1 when the response is not a JSON array of exactly one element ("could not query, maybe pool not registered yet"), including an empty response. (src: L368-L369)
   - **SPO-04e-OUT-004** Prints the pool name and ticker when present and, when `.[0].op_cert_counter` is non-null, that value and `nextChain = counter + 1` with the command lines `04c` then `04d <pool> <nextChain>`. A null counter prints that the pool has not made a block yet and that the current counter should be 0. Exit 0. (src: L370-L387)

## Work modes

- **SPO-04e-MODE-001** Offline is refused (SPO-04e-PRE-001). (src: L152, L359)
- **SPO-04e-MODE-002** Online (full), local file: runs `cardano-cli <era> query kes-period-info --op-cert-file <file> --out-file <tempDir>/opcert.query`; a failure prints cardano-cli's text and exits 2. `onChain` is `qKesNodeStateOperationalCertificateNumber` (null or absent: -1), `onDisk` is `qKesOnDiskOperationalCertificateNumber`, `onDiskKESStart` is `qKesStartKesInterval`. The query file is deleted. (src: L186-L194)
- **SPO-04e-MODE-003** Light, local file: reads `onDisk` and `onDiskKESStart` from the opcert's `cborHex`: the first and the second unsigned integer starting at hex offset 72 (`int_from_cbor`, SPO-Cconv-IF-001); a read or decode failure exits 2. (src: L203-L208)
- **SPO-04e-MODE-004** Light, local file: derives the pool id as `bech32("pool", blake2b-224(last 32 bytes of the opcert))` (the cold verification key at the end of the certificate), then sends the request of SPO-04e-EXT-002. A response that `jq` cannot parse exits 2; a one-element array yields `onChain = .[0].op_cert_counter // -1`; any other parseable response, including an empty body from a failed request, yields `onChain = -1` (same quirk as SPO-04d-MODE-003). (src: L210-L234)

> **Observed 2026-11-16 (Koios preview, cardano-cli 11.2.3.0):** for a freshly generated pool Koios answers `pool_info` with `[]`; upstream in light mode reads that as `onChain = -1` and prints `OK, no block generated yet. File Counter 0 is the right current one.` with exit 0. The port reads the same answer as Unknown (`koios does not know this pool`), never as no block. For every other combination (file counter 0 and 3, chain counter none, 2, 3 and 4, `current` and `next`: 16 runs against a stand-in that serves the counter) upstream's `OK` or `FALSE` equals the port's counter verdict and every run exits 0 (`TestCheckOpCertMatchesUpstream`; the live-service run is `TestCheckOpCertUnknownPoolAgainstLiveKoios`). In the pool-id mode an empty answer is exit 1 (`could not query`) and an Unknown report in the port.
- **SPO-04e-MODE-005** The `light` and `online` branches are the only two; any other work mode exits (unreachable). (src: L176-L178, L199, L237)

> **Upstream quirk:** (a) a failed Koios request in light mode with a local file is read as "no block yet" (`onChain = -1`) and produces a confident verdict; (b) the pool-id subject calls Koios in online mode, where `koiosAuthorizationHeader` may be empty (SPO-Cconf-MODE-004); (c) the verdict never reaches the exit status (SPO-04e-INV-004). The handoff question "which exit code does 04e use on a counter mismatch" is therefore answered: none, it exits 0.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Use the newest `<pool>.node-*.opcert` (SPO-04e-IF-004) | Yes | No exits 1 |
| Use the pool id from `<pool>.pool.id-bech` (SPO-04e-PR-001) | Yes | No: print usage; exit 1 or 0 |

## Outputs

No files are written, apart from the transient `<tempDir>/opcert.query` of SPO-04e-MODE-002. The outputs are the verdicts and values of SPO-04e-OUT-001 to SPO-04e-OUT-004, and the exit status.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| No arguments; bad second argument | 1 | SPO-04e-IF-002 |
| Opcert not found, or newest opcert declined | 1 | SPO-04e-IF-004 |
| Pool id not convertible or not valid bech32, or not resolvable | 1 | SPO-04e-IF-005 |
| Offline mode | 1 | SPO-04e-PRE-001 |
| Not synced (online) | 2 | SPO-04e-PRE-002 |
| Genesis file missing | 1 | SPO-04e-PRE-003 |
| `kes-period-info` failed; Koios response not JSON; opcert unreadable or undecodable | 2 | SPO-04e-MODE-002, SPO-04e-MODE-003, SPO-04e-MODE-004 |
| Pool id not found at Koios (not exactly one element) | 1 | SPO-04e-PRE-004 |
| Any completed check, including FALSE | 0 | SPO-04e-INV-004 |
| Three or more arguments; `.pool.id-bech` declined with no opcert | 0 | SPO-04e-IF-003, SPO-04e-PR-001 |

## Security

No secret is read or printed. The Koios request discloses the pool id and the machine's IP address to the Koios operator; it is sent without TLS pinning. (src: L361-L366)

## Domain mapping

Use cases `CheckOperationalCertificate(opcertRef | pool, current|next)` and `QueryOpCertCounter(poolId)`, read-only on aggregate `StakePool` (`OperationalCertificate`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(OperationalCertificate)`, `latest(OperationalCertificate, pool)` *(new)*, `get(PoolId)` | Opcert files and `.pool.id-bech` |
| `ChainQuery` | `tip()`, `opCertCounter(poolId)` *(new)*, `kesPeriodInfo(opcert)` *(new)* | Slot, on-chain counter, node-side state |
| `Clock` | `kesPeriod(slot)` *(new)* | Genesis arithmetic |
| `Ledger` | `decodeOpCert(opcert)` *(new)*, `poolId(coldVkey)` *(new)* | Counter, KES start and cold key from CBOR |
| `UI` | `confirm`, `show` | Prompts and verdict |

## Port notes

* Return a typed verdict (`Ok`, `Mismatch(expected, actual)`, `KesOutOfRange`, `Unknown`) and map `Mismatch` and `KesOutOfRange` to a non-zero status so that workflows can gate on it; keep exit 0 only for `Ok`.
* Distinguish an unreachable chain source from "no blocks yet" (SPO-04e-MODE-004); return `Unknown`.
* The workbench orchestrator can run this check as the gate after `04d` in offline-then-online hand-offs: it has the opcert file and chain access on the online side.

## Open questions

* The KES-start period of an opcert is the second integer at hex offset 72 in light mode (SPO-04e-MODE-003) but `qKesStartKesInterval` in online mode. They should agree; settle by comparing both on one opcert.
