+++
id = "04f"
kind = "script"
title = "Generate the pool BLS key pair (testnet only)"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "key-custody"]
use_cases = ["GenerateBlsKey"]
depends_on = ["Cui", "Ckey", "Pfiles", "04b", "04c"]

upstream_path = "cardano/testnet/04f_genBLSKeys.sh"
variants = ["testnet"]
upstream_sha256 = "9809dc54897e3f0713599bdc5c774c0bcc6285ef01896afaa1d19817360c1f02"
upstream_lines = 144
uses_common = [
  "ask",
  "ask_pass",
  "checkError",
  "encrypt_skeyJSON",
  "file_lock",
  "file_unlock",
  "is_strong_password",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = [
  "node key-gen-BLS",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 04f_genBLSKeys: Generate the pool BLS key pair (testnet only)

Creates the BLS key pair `<pool>.bls.vkey` / `<pool>.bls.skey` that `05a` requires for the pool registration certificate when the protocol major version is 12 or higher (SPO-Pfiles-OUT-016). The script exists only in the testnet tree (`cardano/testnet/`), not in the mainnet tree. It is a line-for-line sibling of [04b](./04b_genVRFKeys.md), with `bls` in place of `vrf`, `node key-gen-BLS` in place of `node key-gen-VRF`, and the era forced to `dijkstra`. Mode-independent: it never touches the chain.

## Interface

- **SPO-04f-IF-001** Takes two positional arguments: the pool name and a key type of `cli` or `enc` (case-insensitive). (src: L20, L32-L33)
- **SPO-04f-IF-002** Prints usage to stderr and exits 1 when fewer than two arguments are given or the key type is not `cli`/`enc`. (src: L20-L30)

## Behaviour

1. **Fix the era.**
   - **SPO-04f-INV-001** Sets the cardano-cli era argument to the literal `dijkstra` after the prologue, regardless of the configured or detected era and of `ENV_USEERA`. The comment in the source says it will become `latest` later. (src: L44-L45)
2. **Refuse to overwrite.**
   - **SPO-04f-PRE-001** Exits 2 when `<pool>.bls.vkey` or `<pool>.bls.skey` already exists. (src: L48-L49)
3. **Generate with `cli`.**
   - **SPO-04f-EXT-001** Runs `cardano-cli dijkstra node key-gen-BLS --verification-key-file <pool>.bls.vkey --signing-key-file <pool>.bls.skey`. A non-zero exit ends the script with that code (SPO-Cui-INV-001). (src: L57-L58)
   - **SPO-04f-OUT-001** Locks the `.vkey` and `.skey` (mode `0400`, SPO-Pfiles-INV-003). (src: L59-L60)
4. **Generate with `enc`.**
   - **SPO-04f-EXT-002** Runs the same command with the signing key written to stdout and captured in memory; stderr is not discarded. The `.vkey` is locked at once. (src: L71-L73)
   - **SPO-04f-INV-002** With `enc` the plaintext BLS signing key is never written to disk. (src: L71, L119-L128)
   - **SPO-04f-PR-001** Asks for a password and a confirmation, repeating until they match and each passes SPO-Ckey-INV-001, as SPO-04c-PR-001. (src: L81-L108)
   - **SPO-04f-PRE-002** An empty entry at any of the four password prompts aborts with exit 1 and deletes the `.vkey` (as SPO-04b-PRE-002). (src: L88, L92, L98, L102)
   - **SPO-04f-PR-002** After a matching pair, asks whether to show the password for 5 seconds (default No). (src: L116)
   - **SPO-04f-OUT-002** Writes the signing key as the encrypted envelope of `encrypt_skeyJSON` (SPO-Ckey-OUT-001) and locks it. A write failure exits 1. (src: L119-L131)
   - **SPO-04f-PRE-003** An encryption failure exits 1 and leaves the `.vkey` with no `.skey`. (src: L121)
   - **SPO-04f-PRE-004** An interrupt (SIGINT) between the start of the password dialogue and the end of the write deletes the `.vkey` and exits 1. (src: L36-L41, L79, L133)

## Work modes

Mode-independent. In particular the forced era (SPO-04f-INV-001) applies in every work mode.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password and confirmation, `enc` only (SPO-04f-PR-001) | none; empty aborts | Encrypts the signing key |
| Show password for 5 seconds (SPO-04f-PR-002) | No | Display only |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.bls.vkey` | text envelope, BLS verification key | `0400` | created |
| `<pool>.bls.skey` | text envelope, plaintext (`cli`) or encrypted envelope (`enc`) | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-04f-IF-002 |
| Either key file exists | 2 | SPO-04f-PRE-001 |
| cardano-cli failure (for example a release without `dijkstra`) | cardano-cli's code | SPO-04f-EXT-001, SPO-04f-EXT-002 |
| Empty password or confirmation | 1 | SPO-04f-PRE-002 |
| Encryption or write failure | 1 | SPO-04f-PRE-003, SPO-04f-OUT-002 |
| SIGINT during `enc` | 1 | SPO-04f-PRE-004 |

## Security

- **SPO-04f-SEC-001** Prints the verification key and then the signing key file to stdout. With `cli` this is the **plaintext BLS signing key**; a caller must never capture, log or tee the output. (src: L62-L67)
- **SPO-04f-SEC-002** With `enc` prints the encrypted envelope, and the password in clear for 5 seconds if the operator accepts SPO-04f-PR-002. (src: L116, L135-L136)

## Domain mapping

Use case `GenerateBlsKey(pool, protection)` on aggregate `StakePool` (its `BlsKey`, testnet profiles only).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(BLS)` *(new key kind)* | New key pair |
| `Vault` | `seal(blsSigningKey, policy)` | `cli` = none, `enc` = passphrase |
| `Store` | `put(BlsVerificationKey)`, `exists`, `lock` | Public artefact and refusal to overwrite |
| `UI` | `askPassword`, `confirm` | `enc` only |

## Port notes

* Gate the use case on the network profile (testnet) and the era capability instead of a separate script tree; refuse with a clear message when the pinned cardano-cli cannot produce BLS keys.
* Seal by default; make generation atomic (SPO-04f-PRE-003 leaves an orphaned `.vkey` that triggers SPO-04f-PRE-001 on retry).
* Replace the hard-coded `dijkstra` with the era selected by the network profile once the era is released.

## Open questions

* Whether mainnet will gain this script once the BLS key becomes mandatory is not settled by source; re-check at the next upstream tag.

> **Observed 2026-11-16:** the pinned cardano-cli 11.2.3.0 runs `dijkstra node key-gen-BLS`. The text envelopes it writes have the types `BlsVerificationKey_bls12-381-BLS-Signature-Mininimal-Signature-Size` and `BlsSigningKey_bls12-381-BLS-Signature-Mininimal-Signature-Size` (note "Mininimal": a typo of the cli) with the descriptions `BLS12-381 verification key` and `BLS12-381 signing key`; the verification key is a CBOR byte string of 96 bytes (`5860`, 196 hex digits) and the signing key one of 32 bytes (`5820`, 68 hex digits), indented by four spaces. bursa's envelopes spell the type "Minimal"; the native generator writes the cli's spelling. The same cli has no command that reads a BLS key back, so the shape is what the parity test compares.
