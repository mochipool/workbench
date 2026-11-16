+++
id = "13a"
kind = "script"
title = "Answer an SPO poll (CIP-94): build the answer metadata"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["community"]
use_cases = ["BuildPollAnswer"]
depends_on = ["Cconv","Clight","Cconf"]

upstream_path = "cardano/testnet/13a_spoPoll.sh"
variants = ["testnet"]
upstream_sha256 = "9aad4e15351cfc5187252b99e6b3eaf1222ea0ccb0841d35acd7aad16ad187ed"
upstream_lines = 146
uses_common = [
  "ask",
  "showProcessAnimation",
  "stopProcessAnimation",
  "to_cbor",
]
cli_commands = []
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI/tx_metadata",
]
env_vars = []
+++

# 13a_spoPoll: Answer an SPO poll (CIP-94), build the answer metadata

Reads an SPO poll question that was published on chain as transaction metadata (CIP-94, label 94), shows the question and its answer options, asks the operator to choose an option, and writes the answer as a CBOR metadata file `spopoll_<questionHash>.cbor`. The file is not submitted by this script: [13b](./13b_sendSpoPoll.md) attaches it to a transaction that the pool's cold key also signs, which is what proves the answer comes from the pool. This script is shipped only in the `testnet` script directory (the spec's `upstream_path` is the testnet path); it contains no network-specific logic and uses the configured `koiosAPI`.

## Interface

- **SPO-13a-IF-001** Takes exactly one argument: a 64-character hex transaction hash (case-insensitive, lower-cased on use). Any other argument count, or a value that is not 64 hex characters, prints usage to stderr and exits **2**. (src: L20)

## Inputs

- **SPO-13a-IN-001** Reads the question from the chain through Koios: the `koiosAPI` setting and the `koiosAuthorizationHeader` (empty unless `light` mode has a Koios token, SPO-Cconf-MODE-004). The poll transaction is identified only by its hash; no node, no key and no wallet file is read. (src: L31)
- **SPO-13a-IN-002** Reads the work mode only to refuse `offline`. (src: L23)

## Behaviour

1. **Refuse offline mode.**
   - **SPO-13a-PRE-001** Exits 1 in `offline` work mode ("SPO-Poll is only supported in online mode"), after the hash argument is validated. `light` mode and `online` mode behave the same, since both use Koios and neither needs the node. (src: L23)
2. **Fetch the question.**
   - **SPO-13a-EXT-001** Sends `POST <koiosAPI>/tx_metadata` with the body `{"_tx_hashes":["<hash>"]}` (JSON, `accept: application/json`, plus the `koiosAuthorizationHeader`, which is non-empty only in `light` mode with a configured token, SPO-Cconf-MODE-004), 10 second timeout, one attempt. (src: L31)
   - **SPO-13a-PRE-002** Exits 1 unless the response is a JSON array with exactly one element. (src: L37-L39)
   - **SPO-13a-PRE-003** Exits 1 when that element has no `metadata."94"`. (src: L43-L46)
   - **SPO-13a-PRE-004** Exits 1 when the question array `metadata."94"."0"` is empty or absent, and when the options array `metadata."94"."1"` is empty or absent. (src: L60-L63, L75-L78)
3. **Re-encode the question to CBOR.**
   - **SPO-13a-INV-001** The *question CBOR* is rebuilt locally from the metadata JSON, not taken from the chain: the definite-length CBOR of the map `{94: {0: [<question strings>], 1: [[<option strings>], ...]}}`, built with the encoders of `Cconv` (SPO-Cconv-OUT-003 .. SPO-Cconv-OUT-008). Strings are the question lines in order, then for each option an array of its text lines. (src: L54-L57, L64-L72, L79-L93)
   - **SPO-13a-INV-002** The question hash is the BLAKE2b-256 digest of the question CBOR bytes (`b2sum -l 256`). (src: L122)
   > **Upstream quirk:** the string encoder interprets backslash escapes (SPO-Cconv-OUT-007), so a question or option line containing `\` sequences encodes differently from the on-chain bytes and yields a different hash. A hash computed from the transaction's own metadata bytes would not have this problem; the CIP-94 rule for the hash input is the settling reference (see Open questions).
4. **Show and choose.**
   - **SPO-13a-PR-001** The question (its lines concatenated) and the options (each option's lines concatenated, numbered from 0) are displayed. The operator is asked for an answer index; the prompt repeats until the answer is digits only and below the number of options. An empty answer exits 1. This prompt reads the standard input, not the terminal device. (src: L96-L113)
   - **SPO-13a-PR-002** After the choice the operator is asked "Is this correct?" with default **Yes**; declining exits 1 without writing anything. (src: L116-L119)
5. **Write the answer.**
   - **SPO-13a-OUT-001** The answer CBOR is the definite-length encoding of `{94: {2: <32-byte question hash>, 3: <answer index>}}` (byte string for the hash, unsigned integer for the index). It is shown as hex. (src: L125-L138)
   - **SPO-13a-OUT-002** The CBOR is written as binary to `spopoll_<questionHash hex>.cbor` in the working directory, replacing an existing file; a write failure exits 1. The file is not locked. (src: L140-L144)
   - **SPO-13a-OUT-003** The script then tells the operator to submit the file with [13b](./13b_sendSpoPoll.md) and exits 0. It submits nothing and signs nothing. (src: L146)

## Work modes

- **SPO-13a-MODE-001** Online and light behave identically (Koios); offline is refused (SPO-13a-PRE-001). (src: L23, L31)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Answer index (SPO-13a-PR-001) | none; empty exits 1 | Selects the option |
| Is this correct? (SPO-13a-PR-002) | Yes | No exits 1 |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `spopoll_<questionHash>.cbor` | binary CBOR `{94: {2: questionHash, 3: index}}` | default | created or replaced |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad argument count or hash | 2 | SPO-13a-IF-001 |
| Offline mode | 1 | SPO-13a-PRE-001 |
| Koios answer not exactly one entry | 1 | SPO-13a-PRE-002 |
| No label 94 | 1 | SPO-13a-PRE-003 |
| No question or option strings | 1 | SPO-13a-PRE-004 |
| Empty answer | 1 | SPO-13a-PR-001 |
| Declined confirmation | 1 | SPO-13a-PR-002 |
| Write failure | 1 | SPO-13a-OUT-002 |

## Security

- **SPO-13a-SEC-001** Handles no secrets. The answer is public once submitted. The script does not check that the transaction is a genuine poll, who published it, or whether the poll is still open: it trusts the Koios answer for that hash, so a wrong or malicious Koios could substitute a different question, which changes the hash that the answer commits to. (src: L31-L46, L122)

## Domain mapping

Use case `BuildPollAnswer(questionTxHash)` on aggregate `PollResponse` (the `community` context).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Directory` | `txMetadata(txHash)` *(new)* | Read the CIP-94 question through Koios |
| `Ledger` | `encodeCbor(value)`, `blake2b256(bytes)` *(new)* | Question hash and answer CBOR |
| `Store` | `put(PollAnswerCbor)` | Output file |
| `UI` | `ask(index)`, `confirm` | Choice |

## Port notes

* Compute the question hash from the exact on-chain metadata bytes where the node or Koios can return them, instead of re-encoding the JSON view (SPO-13a-INV-001).
* Verify that the question transaction exists, is a CIP-94 poll, and is within its voting window before answering.
* Take the answer index as an argument as well as interactively, so a remote or scripted run can supply it.
* Let the use case hand the answer metadata straight to the shared transaction pipeline instead of passing a file between two scripts.

## Open questions

* Whether CIP-94 defines the question hash over the CBOR re-encoding exactly as this script builds it (definite-length, key order 0 then 1). Settle by checking CIP-94 and a real poll transaction.
* Koios response shape for a transaction without metadata (an entry with `metadata: null`, which leads to SPO-13a-PRE-003, versus an empty array, which leads to SPO-13a-PRE-002) depends on the Koios release.

> **Observed 2026-11-16:** run through the workbench in light mode against a stand-in Koios that answers `tx_metadata` with a hand-written label-94 poll, the testnet script writes `spopoll_<hash>.cbor` with the same bytes as the port's `BuildPollAnswer` (`spo/test/parity/poll_scripts_test.go`). No real poll transaction was recorded; the Koios shape of label 94 (`"0"` lines, `"1"` option line arrays) is the one the script reads.
