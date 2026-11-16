+++
id = "02"
kind = "script"
title = "Generate a payment-only (enterprise) address with its keys"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "key-custody"]
use_cases = ["GeneratePaymentAccount"]
depends_on = ["Cui", "Ckey", "Chw", "Pfiles"]

upstream_path = "cardano/mainnet/02_genPaymentAddrOnly.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "760b6678180fbd0ca7b95f782bc4558399de415cb95c4175c6609a472e1c102f"
upstream_lines = 254
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
  "address build",
  "address key-gen",
]
hwcli_commands = [
  "address key-gen",
]
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 02_genPaymentAddrOnly: Generate a payment-only (enterprise) address with its keys

Creates a payment key pair and the enterprise address built from it (no stake part), under one of four protections: plaintext key file (`cli`), passphrase-encrypted key file (`enc`), or a key that stays on a Ledger/Trezor device (`hw`, `hwmulti`), for which only the verification key and a hardware signing file are stored. Mode-independent: it never queries the chain. The file layout is SPO-Pfiles-OUT-001 to SPO-Pfiles-OUT-004; the encryption is [Ckey](../common/Ckey.md); the device session is [Chw](../common/Chw.md).

## Interface

- **SPO-02-IF-001** Usage is `<AddressName> <cli|enc|hw|hwmulti> [Acc#] [Idx#]`. The key type is case-insensitive. With fewer than two arguments or another key type the usage goes to stderr and the script exits 1. (src: L21-L37)
- **SPO-02-IF-002** The address name is the first argument with a trailing `.addr` removed from its base name, a directory part kept and a leading `./` dropped. (src: L38)
- **SPO-02-IF-003** The optional third argument is the hardware account number, the fourth (read only when exactly four arguments are given) the address index. Each must be a non-negative integer of at most 2147483647, else exit 2. Default 0 for both. They are validated for every key type and used only by `hw` and `hwmulti`. (src: L40-L53)

## Behaviour

1. **Refuse to overwrite.**
   - **SPO-02-PRE-001** Exits 2 when `<name>.vkey` exists, when `<name>.skey` or `<name>.hwsfile` exists, or when `<name>.addr` exists. Nothing is created before this check. (src: L72-L74)
2. **Create the keys, by key type.**
   - **SPO-02-EXT-001** `cli`: `cardano-cli <era> address key-gen --verification-key-file <name>.vkey --signing-key-file <name>.skey`; failure ends the script with its code. Both files are locked `0400`. (src: L78-L81)
   - **SPO-02-EXT-002** `enc`: the same command with the signing key written to stdout (stderr discarded) and captured in memory; only the `.vkey` is written (locked). The plaintext signing key never reaches disk. (src: L103-L105)
   - **SPO-02-PR-001** `enc` asks for a password and a confirmation until they match, each passing the strong-password rule (SPO-Ckey-INV-001), as in SPO-04c-PR-001. An empty entry prints "Aborted", deletes the `.vkey` and exits 1. (src: L113-L140)
   - **SPO-02-PR-002** Then asks whether to show the password on screen for 5 seconds, default **No**. (src: L148)
   - **SPO-02-OUT-001** `enc` encrypts with `encrypt_skeyJSON` (SPO-Ckey-OUT-001), writes `<name>.skey` as the encrypted envelope and locks it. An encryption failure exits 1 and leaves the `.vkey`; a write failure exits 1. (src: L151-L163)
   - **SPO-02-PRE-002** From the key generation until the skey is written, SIGINT deletes `<name>.vkey` and `<name>.skey` and exits 1. (src: L61-L68, L111, L165)
   - **SPO-02-EXT-003** `hw` / `hwmulti`: first the device session (`start_HwWallet`, SPO-Chw-PRE-001 to SPO-Chw-PRE-005), then `cardano-hw-cli address key-gen --path <1852H|1854H>/1815H/<acc>H/0/<idx> --verification-key-file <name>.vkey --hw-signing-file <name>.hwsfile` with stderr merged. `hw` uses purpose 1852H, `hwmulti` (multisig path) 1854H. Output containing `ERROR` or `DISCONNECT` (any case) exits 1. (src: L185-L187, L217-L219)
   - **SPO-02-OUT-002** For hardware keys the `.vkey` description is rewritten to `Payment Hardware Verification Key` (SPO-Pfiles-INV-001), and `.vkey` and `.hwsfile` are locked. (src: L191-L194, L223-L226)
3. **Build the address.**
   - **SPO-02-EXT-004** `cardano-cli <era> address build --payment-verification-key-file <name>.vkey <addrformat>` writes `<name>.addr` (an enterprise address); failure ends with its code; locked `0400`. Same for all key types. (src: L91-L93, L172-L174, L204-L206, L236-L238)

## Work modes

Mode-independent; hardware key types need an attached device.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password, confirmation, `enc` (SPO-02-PR-001) | none; empty aborts | Encrypts the key |
| Show password 5 s (SPO-02-PR-002) | No | Display only |

## Outputs

- **SPO-02-OUT-003** The script prints the verification key file and the key file or hardware signing file it created, and the address. For `cli` this is the **plaintext signing key** on stdout. (src: L83-L88, L167-L168, L199-L200, L231-L232)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<name>.vkey` | text envelope; hardware description for `hw`/`hwmulti` | `0400` | created |
| `<name>.skey` | plaintext (`cli`) or encrypted envelope (`enc`) | `0400` | created (not for hardware) |
| `<name>.hwsfile` | hardware signing file | `0400` | created (hardware only) |
| `<name>.addr` | enterprise address | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-02-IF-001 |
| Acc#/Idx# invalid | 2 | SPO-02-IF-003 |
| Output file exists | 2 | SPO-02-PRE-001 |
| cardano-cli failure | its code | SPO-02-EXT-001, SPO-02-EXT-004 |
| Empty password, encrypt or write failure, SIGINT | 1 | SPO-02-PR-001, SPO-02-OUT-001, SPO-02-PRE-002 |
| Hardware error or disconnect | 1 | SPO-02-EXT-003 |

## Security

- **SPO-02-SEC-001** `cli` prints the plaintext signing key (SPO-02-OUT-003); a caller must not capture the output. `enc` with "show password" prints the password in clear for 5 seconds. (src: L87, L148)
- **SPO-02-SEC-002** The password reaches gpg on its command line (SPO-Ckey-SEC-001). (src: L153)

> **Upstream quirk:** An encryption failure leaves the `.vkey` behind (SPO-02-OUT-001), so the next run refuses with SPO-02-PRE-001. The unknown-key-type branch (L246-L249) is unreachable because the argument check already rejects it.

## Domain mapping

Use case `GeneratePaymentAccount(name, protection, hwPath?)` on `PaymentAccount`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(payment)` | cardano-cli key pair, or hardware key via cardano-hw-cli |
| `Vault` | `seal(secret, policy)` | `cli` none, `enc` passphrase, hardware reference |
| `Ledger` | `buildAddress(credentials)` | Enterprise address |
| `Store` | `put(artefact)`, `exists(artefact)`, `lock(artefact)` | Files |
| `UI` | `askPassword`, `confirm` | `enc` |

## Port notes

* Make creation atomic (no orphan `.vkey` after a failed encryption) and seal by default; never print the key.
* Hardware accounts need no secret: store the derivation path with the verification key.

## Open questions

* Whether `cardano-hw-cli` ever reports failure only by exit code with neither `ERROR` nor `DISCONNECT` in its output, which the check at L187 would miss.
