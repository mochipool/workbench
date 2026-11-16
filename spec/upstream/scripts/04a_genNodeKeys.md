+++
id = "04a"
kind = "script"
title = "Generate the pool cold keys and the opcert issue counter"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "key-custody"]
use_cases = ["GenerateColdKey"]
depends_on = ["Cui", "Ckey", "Chw", "Pfiles", "04c"]

upstream_path = "cardano/mainnet/04a_genNodeKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "15af161057c9bd652eea0617ee988059ba4764e34b2c87aac7fb8d4dab217896"
upstream_lines = 207
uses_common = [
  "ask",
  "ask_pass",
  "checkError",
  "encrypt_skeyJSON",
  "file_lock",
  "file_unlock",
  "is_strong_password",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
]
cli_commands = [
  "node key-gen",
]
hwcli_commands = [
  "node key-gen",
]
signer_commands = []
http_endpoints = []
env_vars = [
  "ENV_SKIP_PROMPT",
]
+++

# 04a_genNodeKeys: Generate the pool cold keys and the opcert issue counter

Creates the pool's cold (offline) key pair, which is the pool's identity, together with the operational-certificate issue counter (`<pool>.node.counter`) that [04d](./04d_genNodeOpCert.md) increments on every opcert it issues. The signing half is produced in one of three protections: a plaintext cardano-cli key (`cli`), a cardano-cli key encrypted under a password (`enc`), or a hardware-wallet reference (`hw`, a Ledger or Keystone derivation path, with no signing key on disk). It never touches the chain.

## Interface

- **SPO-04a-IF-001** Takes positional arguments: the pool name, a key type of `cli`, `enc` or `hw` (case-insensitive), and, for `hw` only, an optional cold key index. A third argument given with `cli` or `enc` is ignored. (src: L22, L38-L39, L162-L164)
- **SPO-04a-IF-002** Prints usage to stderr and exits 1 when fewer than two arguments are given or the key type is not one of `cli`/`enc`/`hw`. (src: L22-L36)
- **SPO-04a-IF-003** The cold key index defaults to 0. A given index must be a non-negative decimal integer not above 2147483647 (2^31-1); an empty, non-numeric, negative or larger value exits 2. (src: L160-L166)

## Inputs

- **SPO-04a-IN-001** Reads `ENV_SKIP_PROMPT`; the value `YES` skips the confirmation for a given cold key index (SPO-04a-PR-003). (src: L169)

## Behaviour

1. **Refuse to overwrite.**
   - **SPO-04a-PRE-001** Exits 2 when any of `<pool>.node.vkey`, `<pool>.node.skey`, `<pool>.node.hwsfile` or `<pool>.node.counter` already exists. This check runs before the key type is acted on, so before the index validation (SPO-04a-IF-003) and before any prompt. (src: L54-L57)
2. **Generate with `cli`.**
   - **SPO-04a-EXT-001** Runs `cardano-cli <era> node key-gen --verification-key-file <pool>.node.vkey --signing-key-file <pool>.node.skey --operational-certificate-issue-counter-file <pool>.node.counter`. A non-zero exit ends the script with the same code (SPO-Cui-INV-001). (src: L65-L66)
   - **SPO-04a-OUT-001** Locks (mode `0400`) the `.vkey`, `.skey` and `.counter` after generation (SPO-Pfiles-INV-003). (src: L67-L69)
3. **Generate with `enc`.**
   - **SPO-04a-EXT-002** Runs the same cardano-cli command with the signing key written to stdout, which is captured in memory; cardano-cli stderr is discarded. The `.vkey` and `.counter` are written to disk by cardano-cli and locked at once. (src: L83-L86)
   - **SPO-04a-INV-001** With `enc` the plaintext cold signing key is never written to disk. (src: L83, L133-L141)
   - **SPO-04a-PR-001** Asks for a password and a confirmation and repeats until they match, each passing the strong-password rule (SPO-Ckey-INV-001), exactly as SPO-04c-PR-001. (src: L94-L121)
   - **SPO-04a-PRE-002** An empty entry at any of the four password prompts (first, first retry after a weak entry, confirmation, confirmation retry) aborts with exit 1 and deletes the `<pool>.node.vkey` **and** `<pool>.node.counter`. Unlike SPO-04c-PRE-004, the confirmation prompt cleans up too. (src: L101, L105, L111, L115)
   - **SPO-04a-PR-002** After a matching pair, asks whether to show the password for 5 seconds (default No), as SPO-04c-PR-002. (src: L129)
   - **SPO-04a-OUT-002** Writes the signing key as the encrypted envelope of `encrypt_skeyJSON` (SPO-Ckey-OUT-001) to `<pool>.node.skey` and locks it. A write failure exits 1. (src: L133-L144)
   - **SPO-04a-PRE-003** An encryption failure exits 1 and leaves the `.vkey` and `.counter` on disk with no `.skey`. (src: L134)
   - **SPO-04a-PRE-004** An interrupt (SIGINT) between the start of the password dialogue and the end of the write deletes the `.vkey` and `.counter` and exits 1. Before the dialogue and after the write there is no handler. (src: L43-L50, L92, L146)
4. **Generate with `hw`.**
   - **SPO-04a-PR-003** A cold key index argument, whenever one is given (a third positional argument, even an explicit `0`), is confirmed with "ColdKeyIndex is not default(0), continue ?" (default No) unless `ENV_SKIP_PROMPT=YES`. A "no" exits 1. Not asked when no index is given. (src: L162, L169-L176)
   - **SPO-04a-INV-002** The derivation path is `1853H/1815H/0H/<index>H`. (src: L181, L186)
   - **SPO-04a-EXT-003** Opens a hardware-wallet session restricted to Ledger or Keystone devices (`start_HwWallet "Ledger|Keystone"`, see SPO-Chw-IF-001, SPO-Chw-PRE-003); any session failure ends the script with exit 1. (src: L185)
   - **SPO-04a-EXT-004** Runs `cardano-hw-cli node key-gen --path <path> --cold-verification-key-file <pool>.node.vkey --hw-signing-file <pool>.node.hwsfile --operational-certificate-issue-counter-file <pool>.node.counter`, stderr merged into the captured text. (src: L186)
   - **SPO-04a-PRE-005** When the captured text contains `ERROR` or `DISCONNECT` (case-insensitive) the script prints it and exits 1; any files already written stay. (src: L187)
   - **SPO-04a-OUT-003** Locks the `.vkey`, `.hwsfile` and `.counter`. (src: L189-L191)

## Work modes

Mode-independent. No chain access and no work-mode flag is consulted.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password and confirmation, `enc` only (SPO-04a-PR-001) | none; empty aborts | Encrypts the signing key |
| Show password for 5 seconds (SPO-04a-PR-002) | No | Display only |
| Cold key index given (even `0`), `hw` only (SPO-04a-PR-003) | No; skipped by `ENV_SKIP_PROMPT=YES` | "No" exits 1 |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.node.vkey` | text envelope, stake-pool verification key (cardano-cli, or cardano-hw-cli for `hw`) | `0400` | created |
| `<pool>.node.skey` | text envelope, plaintext (`cli`) or encrypted envelope (`enc`); absent for `hw` | `0400` | created |
| `<pool>.node.hwsfile` | hardware signing file (path and public key, no private key); `hw` only | `0400` | created |
| `<pool>.node.counter` | text envelope `NodeOperationalCertificateIssueCounter`, initial next-issue number 0 | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-04a-IF-002 |
| Any of the four target files exists | 2 | SPO-04a-PRE-001 |
| Cold key index invalid | 2 | SPO-04a-IF-003 |
| cardano-cli failure | cardano-cli's code | SPO-04a-EXT-001, SPO-04a-EXT-002 |
| Empty password or confirmation | 1 | SPO-04a-PRE-002 |
| Encryption or write failure | 1 | SPO-04a-PRE-003, SPO-04a-OUT-002 |
| SIGINT during `enc` | 1 | SPO-04a-PRE-004 |
| Cold key index confirmation declined | 1 | SPO-04a-PR-003 |
| Hardware session failure | 1 | SPO-04a-EXT-003 |
| `ERROR` or `DISCONNECT` from cardano-hw-cli | 1 | SPO-04a-PRE-005 |

## Security

- **SPO-04a-SEC-001** After generation the script prints the verification key, the signing key file and the counter file to stdout. With `cli` this is the **plaintext cold signing key** (the pool's identity). A caller must never capture, log or tee the output. (src: L71-L78)
- **SPO-04a-SEC-002** With `enc` the script prints the encrypted signing envelope, and the chosen password in clear for 5 seconds when the operator accepts SPO-04a-PR-002. (src: L129, L148-L149)
- **SPO-04a-SEC-003** With `hw` it prints the `.hwsfile`, which carries the derivation path and public key only. (src: L197-L198)
- **SPO-04a-SEC-004** With `cli` the signing key exists in plaintext on disk from cardano-cli's write until at least the lock (SPO-04a-OUT-001); its mode in that window is whatever cardano-cli sets. (src: L65-L68)

## Domain mapping

Use case `GenerateColdKey(pool, protection, coldKeyIndex?)` on aggregate `StakePool` (its `ColdKey` and `OpCertIssueCounter`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(cold)` | cli adapter; the hardware adapter derives `1853H/1815H/0H/<index>H` |
| `Vault` | `seal(coldSigningKey, policy)` | `cli` = no protection, `enc` = passphrase, `hw` = reference only |
| `Store` | `put(ColdVerificationKey)`, `put(OpCertIssueCounter)`, `exists`, `lock` | Public artefacts and refusal to overwrite |
| `UI` | `askPassword`, `confirm` | `enc` password, non-default index |

## Port notes

* Offer no unprotected `cli` mode by default; seal on creation, as for SPO-04c.
* Make generation atomic: SPO-04a-PRE-003 and SPO-04a-PRE-005 leave partial artefacts, which then block a retry through SPO-04a-PRE-001.
* The cold key is the only key that cannot be rotated without re-registering the pool; the port should require a backup acknowledgement.
* The counter file is cardano-cli's own text envelope; a native port keeps the integer in the `StakePool` aggregate and writes the envelope only on export.

## Open questions

* The exact `description` text cardano-cli writes into the fresh counter file ("Next certificate issue number: 0") is not in the script. Settle by running `cardano-cli node key-gen` on the pinned release.
