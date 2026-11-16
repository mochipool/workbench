+++
id = "04b"
kind = "script"
title = "Generate the pool VRF key pair"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "key-custody"]
use_cases = ["GenerateVrfKey"]
depends_on = ["Cui", "Ckey", "Pfiles", "04c"]

upstream_path = "cardano/mainnet/04b_genVRFKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "f522d1670169e11f26b22397e5d9b73292983d29209692a9852e63769bef2303"
upstream_lines = 140
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
  "node key-gen-VRF",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 04b_genVRFKeys: Generate the pool VRF key pair

Creates the VRF (verifiable random function) key pair a block producer uses for slot-leader election: `<pool>.vrf.vkey` and `<pool>.vrf.skey`. The signing key is stored plaintext (`cli`) or password-encrypted (`enc`). There is no hardware-wallet form and no counter. Mode-independent: it never touches the chain. The password dialogue is the one of [04c](./04c_genKESKeys.md), with the cleanup differences noted below.

## Interface

- **SPO-04b-IF-001** Takes two positional arguments: the pool name and a key type of `cli` or `enc` (case-insensitive). (src: L20, L32-L33)
- **SPO-04b-IF-002** Prints usage to stderr and exits 1 when fewer than two arguments are given or the key type is not `cli`/`enc`. (src: L20-L30)

## Behaviour

1. **Refuse to overwrite.**
   - **SPO-04b-PRE-001** Exits 2 when `<pool>.vrf.vkey` or `<pool>.vrf.skey` already exists. (src: L44-L45)
2. **Generate with `cli`.**
   - **SPO-04b-EXT-001** Runs `cardano-cli <era> node key-gen-VRF --verification-key-file <pool>.vrf.vkey --signing-key-file <pool>.vrf.skey`. A non-zero exit ends the script with that code (SPO-Cui-INV-001). (src: L53-L54)
   - **SPO-04b-OUT-001** Locks the `.vkey` and `.skey` (mode `0400`, SPO-Pfiles-INV-003). (src: L55-L56)
3. **Generate with `enc`.**
   - **SPO-04b-EXT-002** Runs the same command with the signing key written to stdout and captured in memory. Unlike 04a, cardano-cli stderr is not discarded. The `.vkey` is locked at once. (src: L67-L69)
     > **Upstream quirk (observed 2026-11-16, cardano-cli 11.2.3.0):** this path fails for a non-root operator, for the reason given under SPO-04c-INV-002: `node key-gen-VRF` cannot write its signing key to `/dev/stdout` or to a pipe (`/dev/: openTempFile: permission denied`, exit 1).
   - **SPO-04b-INV-001** With `enc` the plaintext VRF signing key is never written to disk. (src: L67, L115-L124)
   - **SPO-04b-PR-001** Asks for a password and a confirmation, repeating until they match and each passes the strong-password rule (SPO-Ckey-INV-001), as SPO-04c-PR-001. (src: L77-L104)
   - **SPO-04b-PRE-002** An empty entry at any of the four password prompts aborts with exit 1 and deletes the `.vkey`. Unlike SPO-04c-PRE-004, the confirmation prompt cleans up too. (src: L84, L88, L94, L98)
   - **SPO-04b-PR-002** After a matching pair, asks whether to show the password for 5 seconds (default No), as SPO-04c-PR-002. (src: L112)
   - **SPO-04b-OUT-002** Writes the signing key as the encrypted envelope of `encrypt_skeyJSON` (SPO-Ckey-OUT-001) and locks it. A write failure exits 1. (src: L115-L127)
   - **SPO-04b-PRE-003** An encryption failure exits 1 and leaves the `.vkey` with no `.skey`. (src: L117)
   - **SPO-04b-PRE-004** An interrupt (SIGINT) between the start of the password dialogue and the end of the write deletes the `.vkey` and exits 1. (src: L36-L41, L75, L129)

## Work modes

Mode-independent.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password and confirmation, `enc` only (SPO-04b-PR-001) | none; empty aborts | Encrypts the signing key |
| Show password for 5 seconds (SPO-04b-PR-002) | No | Display only |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.vrf.vkey` | text envelope, VRF verification key | `0400` | created |
| `<pool>.vrf.skey` | text envelope, plaintext (`cli`) or encrypted envelope (`enc`) | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-04b-IF-002 |
| Either key file exists | 2 | SPO-04b-PRE-001 |
| cardano-cli failure | cardano-cli's code | SPO-04b-EXT-001, SPO-04b-EXT-002 |
| Empty password or confirmation | 1 | SPO-04b-PRE-002 |
| Encryption or write failure | 1 | SPO-04b-PRE-003, SPO-04b-OUT-002 |
| SIGINT during `enc` | 1 | SPO-04b-PRE-004 |

## Security

- **SPO-04b-SEC-001** Prints the verification key and then the signing key file to stdout. With `cli` this is the **plaintext VRF signing key**; a caller must never capture, log or tee the output. (src: L58-L63)
- **SPO-04b-SEC-002** With `enc` prints the encrypted envelope, and the password in clear for 5 seconds if the operator accepts SPO-04b-PR-002. (src: L112, L131-L132)
- **SPO-04b-SEC-003** The VRF key must be present in plaintext on the block producer, so protecting it at rest only helps on the machine that generates and stores it. (src: L67)

## Domain mapping

Use case `GenerateVrfKey(pool, protection)` on aggregate `StakePool` (its `VrfKey`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(VRF)` | New key pair |
| `Vault` | `seal(vrfSigningKey, policy)` | `cli` = none, `enc` = passphrase |
| `Store` | `put(VrfVerificationKey)`, `exists`, `lock` | Public artefact and refusal to overwrite |
| `UI` | `askPassword`, `confirm` | `enc` only |

## Port notes

* Seal by default; export plaintext only through the audited `Vault.exportPlaintext` for the block producer.
* SPO-04b-PRE-003 leaves an orphaned `.vkey` which then triggers SPO-04b-PRE-001 on retry; make generation atomic.
