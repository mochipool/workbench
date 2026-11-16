+++
id = "04c"
kind = "script"
title = "Generate the next KES key pair"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "key-custody"]
use_cases = ["GenerateKesKey"]
depends_on = ["Cui", "Ckey", "Pfiles"]

upstream_path = "cardano/mainnet/04c_genKESKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "405e2d60d040b1d8e0bd36b04a09ae408fb346cb77e22edf5139ee4ba696d0fe"
upstream_lines = 186
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
  "node key-gen-KES",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 04c_genKESKeys: Generate the next KES key pair

Creates the KES (key-evolving signature) key pair a block producer uses for the next operational certificate. The pool keeps two KES counters: the number of the newest key generated (`kes.counter`) and the number the next key must have (`kes.counter-next`). This script generates key number `next` and advances `kes.counter` to it. It refuses when a key has been generated that no opcert has consumed yet. [04d](./04d_genNodeOpCert.md) consumes it and advances `kes.counter-next`. The two scripts together form the KES rotation state machine:

```
          04c (generate)                     04d (issue opcert)
current < next  ───────────▶  current == next  ───────────▶  current < next+1
```

Mode-independent: it never touches the chain.

## Interface

- **SPO-04c-IF-001** Takes two positional arguments: the pool name, and a key type of `cli` or `enc` (case-insensitive). (src: L21, L33-L34)
- **SPO-04c-IF-002** Prints usage to stderr and exits 1 when fewer than two arguments are given or the key type is not `cli`/`enc`. (src: L21-L31)

## Inputs

- **SPO-04c-IN-001** Reads the current KES counter from `<pool>.kes.counter` when that file exists, interpreted as a base-10 integer even with leading zeros. A missing file means "no key generated yet". (src: L50-L55)
- **SPO-04c-IN-002** Reads the next KES counter from `<pool>.kes.counter-next` when that file exists, interpreted as base 10. (src: L72-L73)

## Behaviour

1. **Establish the next counter.**
   - **SPO-04c-OUT-001** When `<pool>.kes.counter-next` does not exist, creates it, with value `current + 1` if a current counter exists, else `0`. It is then locked read-only. This happens before any later check, so the file persists even if the script then refuses. (src: L59-L70)
2. **Refuse an unconsumed key.**
   - **SPO-04c-PRE-001** Exits 2 without generating anything when the current counter equals the next counter. That state means the newest KES key has not yet been used for an opcert ([SPO-04d-OUT-003](./04d_genNodeOpCert.md) advances the next counter). (src: L82)
3. **Refuse to overwrite.**
   - **SPO-04c-PRE-002** Exits 2 when `<pool>.kes-<NNN>.vkey` or `<pool>.kes-<NNN>.skey` already exists for the next number. (src: L86-L87)
4. **Generate the key pair.**
   - **SPO-04c-EXT-001** Generates a KES key pair with `cardano-cli <era> node key-gen-KES`. A non-zero exit from cardano-cli ends the script with that same exit code (see SPO-Cui-INV-001). (src: L93-L94, L105-L106)
   - **SPO-04c-INV-001** The key number is the next counter, formatted as at least three zero-padded digits (`000`, `001`, ...). Numbers above 999 are written unpadded with more digits. (src: L64-L66, L73)
5. **Protect the signing key (enc only).**
   - **SPO-04c-INV-002** With key type `enc`, the plaintext signing key is never written to disk: cardano-cli writes it to stdout, which is captured in memory, then encrypted and written. (src: L105, L155, L162)
     > **Upstream quirk (observed 2026-11-16, cardano-cli 11.2.3.0):** this path fails for a non-root operator. `node key-gen-KES` writes the signing key by creating a temporary file beside the destination and renaming it, so `--signing-key-file /dev/stdout` ends with `/dev/: openTempFile: permission denied` and exit 1. The verification key is not written either. Upstream discards stderr here, so the operator sees only the failure exit. A pipe path (`/dev/fd/N`) fails the same way. `address key-gen` and `node key-gen` (cold key) do accept a pipe. Port decision: see the X2 finding in the concerns register.
   - **SPO-04c-PR-001** With key type `enc`, asks for a password, then a confirmation, and repeats both until they match. Each must pass the strong-password rule (SPO-Ckey-INV-001); a weak entry is asked again. (src: L116-L142)
   - **SPO-04c-PRE-003** An empty first password aborts with exit 1 and deletes the already-written `.vkey`. (src: L122, L126)
   - **SPO-04c-PRE-004** An empty confirmation password aborts with exit 1 but leaves the `.vkey` in place. (src: L132, L136)
   - **SPO-04c-PR-002** After a matching pair, asks whether to show the password on screen for 5 seconds (default No). (src: L150)
   - **SPO-04c-OUT-002** Writes the signing key as the encrypted envelope produced by `encrypt_skeyJSON` (SPO-Ckey-OUT-001), then locks it. (src: L155-L164)
   - **SPO-04c-PRE-005** An interrupt (SIGINT) during password entry or encryption deletes the `.vkey` and exits 1. (src: L38-L43, L113, L167)
6. **Record the new key.**
   - **SPO-04c-OUT-003** Sets `<pool>.kes.counter` to the next counter, unlocking, writing and relocking it. The next counter is not changed. (src: L177-L179)

## Work modes

Mode-independent. It needs only a local cardano-cli.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password, `enc` only (SPO-04c-PR-001) | none; empty aborts | Encrypts the signing key |
| Confirm password (SPO-04c-PR-001) | none; empty aborts | Must match |
| Show password for 5 seconds (SPO-04c-PR-002) | No | Display only |

## Outputs

- **SPO-04c-OUT-004** With key type `cli`, writes the signing key in plaintext cardano-cli text-envelope format and locks both key files. (src: L93, L95-L96)

**Upstream file contract** (`<NNN>` is the next counter, see SPO-04c-INV-001):

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.kes.counter-next` | decimal, zero-padded to 3 digits | `0400` | created when absent |
| `<pool>.kes-<NNN>.vkey` | text envelope `KesVerificationKey_ed25519_kes_2^6` | `0400` | created |
| `<pool>.kes-<NNN>.skey` | text envelope, plaintext (`cli`) or encrypted envelope (`enc`) | `0400` | created |
| `<pool>.kes.counter` | decimal, zero-padded to 3 digits | `0400` | created or replaced |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-04c-IF-002 |
| Current counter equals next counter | 2 | SPO-04c-PRE-001 |
| Key files for the next number exist | 2 | SPO-04c-PRE-002 |
| cardano-cli failure | cardano-cli's code | SPO-04c-EXT-001 |
| Empty password or confirmation | 1 | SPO-04c-PRE-003, SPO-04c-PRE-004 |
| Encryption failure or write failure | 1 | SPO-04c-OUT-002 |
| SIGINT during `enc` | 1 | SPO-04c-PRE-005 |

## Security

- **SPO-04c-SEC-001** Prints the signing key file to stdout after creating it. With `cli` this is the **plaintext KES signing key**. A caller must never capture, log or tee the output. (src: L173-L174)
- **SPO-04c-SEC-002** With `enc`, prints the chosen password in clear for 5 seconds if the operator accepts SPO-04c-PR-002. (src: L150)

## Domain mapping

Use case `GenerateKesKey(pool, protection)` on aggregate `StakePool` (its `KesState`: `current`, `next`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get/put(KesCounter)`, `get/put(KesCounterNext)` | Counter state |
| `KeyGen` | `generate(KES)` | New key pair |
| `Vault` | `seal(kesSigningKey, policy)` | Store the signing key; upstream `cli` = no protection, `enc` = passphrase |
| `Store` | `put(KesVerificationKey[n])`, `lock` | Verification key |
| `UI` | `askPassword`, `confirm` | `enc` only |

The invariant the aggregate must enforce: **`current == next` blocks generation**, and only issuing an opcert moves `next`.

## Port notes

* Seal by default. The port should have no unprotected `cli` mode, except through an explicit, audited export, because the block producer needs a plaintext KES key.
* Never echo the signing key. The verification key may be displayed.
* SPO-04c-PRE-004 leaves an orphaned `.vkey`; the port should make generation atomic (all artefacts or none).
* SPO-04c-OUT-001 creates `kes.counter-next` even on refusal. That is harmless, but an atomic port would create it in the same transaction as the key.
* The password is passed to gpg on its command line (see SPO-Ckey-SEC-001); a native vault removes this.
