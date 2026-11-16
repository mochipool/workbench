+++
id = "05e"
kind = "script"
title = "Check a pool's on-chain status"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "chain-access"]
use_cases = ["CheckPoolOnChain"]
depends_on = ["Cchain", "Clight", "Cconf", "Cconv", "Pfiles"]

upstream_path = "cardano/mainnet/05e_checkPoolOnChain.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9d2931d5070afaca17498266e73b7a2e33730347c2678e85fb3ecd7c0dba797a"
upstream_lines = 221
uses_common = [
  "checkError",
  "convertToADA",
  "get_currentSync",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = [
  "query stake-pools",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI",
  "koiosAPI/pool_info",
]
env_vars = []
+++

# 05e_checkPoolOnChain: Check a pool's on-chain status

Resolves a pool identity (a pool name, a hex or bech32 pool id, or a pool file) to a bech32 pool id, then reports whether the pool is registered on chain: in full online mode from the node's ledger state, in light mode from Koios. It reads state only and writes nothing. Its exit code is a predicate in online mode (0 only for "registered") and a connectivity check in light mode. [05c](./05c_regStakepoolCert.md) repeats the same registered-or-not decision internally when it chooses between registration and re-registration (SPO-05c-MODE-001, SPO-05c-MODE-002).

## Interface

- **SPO-05e-IF-001** Takes exactly one non-empty argument: a pool name (path stem), a hex pool id, a bech32 pool id, or the name of a `.pool.id`, `.pool.id-bech` or `.pool.json` file. Any other argument count, or an empty argument, prints usage and exits 1. (src: L21-L26)
- **SPO-05e-IF-002** For file resolution the argument is stripped of the suffixes `.json`, `.id`, `.id-bech` and `.pool`, in that nesting order, and of a leading `./`. For id resolution the whole argument is lower-cased. (src: L22-L23)
- **SPO-05e-PRE-001** Exits 1 in offline mode: it needs node or Koios access. (src: L30)

## Inputs

- **SPO-05e-IN-001** The identity is resolved in this order, the first match wins (src: L34-L119):

  | Order | Argument or file | Test | Result |
  | --- | --- | --- | --- |
  | 1 | the argument | 56 hex digits | converted to bech32 with `bech32 pool` |
  | 2 | the argument | starts with `pool1`, 56 characters | decoded with the `bech32` tool to prove it is valid; used as is |
  | 3 | `<name>.pool.id-bech` | file exists; first line is `pool1...`, 56 characters, decodes | its content |
  | 4 | `<name>.pool.id` | file exists; first line is 56 hex digits | converted as in 1 |
  | 5 | `<name>.pool.json` | file exists; `poolIDbech` valid bech32, else `poolID` valid hex | the bech32 value, or the hex converted |
  | 6 | none | | exit 1 "could not resolve" |

- **SPO-05e-PRE-002** Exits 1 when a conversion or decoding step fails (the `bech32` tool returns non-zero), when a `.pool.id` file or `.pool.json` holds no valid id, or when nothing resolves. (src: L40, L48, L61, L81, L85, L100, L110, L114, L118)
- **SPO-05e-INV-001** A `<name>.pool.id-bech` file whose content is not a valid bech32 pool id prints an error but does **not** exit: the lookup then proceeds with an empty pool id. (src: L65-L67)
  > **Upstream quirk:** the missing `exit 1` makes the later checks run with an empty id (Koios returns nothing; online, `grep ""` matches every line and the "more than once" refusal fires). A port refuses.

## Behaviour

1. **Resolve** the bech32 pool id (SPO-05e-IN-001).
2. **Query Koios, if configured.**
   - **SPO-05e-EXT-001** When `koiosAPI` is set, POSTs `{"_pool_bech32_ids": ["<bech32>"]}` to `<koiosAPI>/pool_info` with the configured authorization header and up to five attempts. With HTTP 200 and exactly one array element the script shows name, ticker, status, set and live pledge, fixed cost, margin, reward address, metadata URL and hash, op-cert counter and VRF key hash, and the status words `REGISTERED`, `RETIRED`, `RETIRING` (with the retiring epoch); another status is echoed. With HTTP 200 and a different length it states that the pool was never registered. Display only. (src: L128-L192)
3. **Decide the exit code by work mode.**
   - **SPO-05e-MODE-001** *Online.* Requires the node to report synced (exit 1 otherwise), runs `cardano-cli <era> query stake-pools` (failure exits 1) and counts the lines that contain the bech32 id: exactly 1 is "registered" and exits 0; 0 prints "not registered" and exits 1; more than 1 exits 1 as an impossible state. The Koios output above is shown too, but the node decides. (src: L196-L212)
   - **SPO-05e-MODE-002** *Light.* Exits 1 only when the Koios request failed in all five attempts. A pool that is not registered, retired or unknown exits 0: the status text is the result. With `koiosAPI` empty nothing is queried and the exit code is 0. (src: L130-L141, L214-L217)

## Work modes

Online and light only (SPO-05e-PRE-001); the differences are SPO-05e-MODE-001 and SPO-05e-MODE-002.

## Prompts

No prompts.

## Outputs

No state is written. The output is display only: the resolved id, the Koios fields and the registered-or-not statements.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Wrong argument count | 1 | SPO-05e-IF-001 |
| Offline mode | 1 | SPO-05e-PRE-001 |
| Identity unresolvable or invalid | 1 | SPO-05e-PRE-002 |
| Online: node not synced, query failed, pool absent, id duplicated | 1 | SPO-05e-MODE-001 |
| Light: Koios unreachable | 1 | SPO-05e-MODE-002 |

## Security

No secrets are read or written. The pool id is public.

## Domain mapping

Use case `CheckPoolOnChain(poolRef)` on aggregate `StakePool` (read-only).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(PoolId)`, `get(PoolDescriptor)` | File-based resolution |
| `Ledger` | `convertPoolId(id, format)` *(new)* | Hex to bech32 and validation (`bech32` tool) |
| `ChainQuery` | `poolState(poolId)` | Node `query stake-pools` or Koios `pool_info`; returns registered, retiring, retired, unknown plus metadata, pledge, op-cert counter |
| `UI` | `show(view)` | Report |

## Port notes

* Return a structured `PoolState` (`Unregistered`, `Registered`, `Retiring(epoch)`, `Retired`) instead of an exit-code convention that differs per mode (SPO-05e-MODE-001, SPO-05e-MODE-002). The workbench's own use (a predicate) is the online meaning.
* Count with an exact match of the id, not a substring count over lines.
* Refuse on an invalid id file (SPO-05e-INV-001).
* The same state query feeds the registration-type decision of `RegisterPool`; share one operation.

## Open questions

* The `RETIRING` status in online mode: the node's `query stake-pools` still lists a retiring pool, so online reports it as registered; whether the port should report the retirement epoch from `query pool-state` is a design choice, not an upstream behaviour.
