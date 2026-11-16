+++
id = "01protectKey"
kind = "script"
title = "Encrypt or decrypt an existing signing key file in place"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["key-custody"]
use_cases = ["ProtectSigningKey", "UnprotectSigningKey"]
depends_on = ["Cui", "Ckey", "Pfiles"]

upstream_path = "cardano/mainnet/01_protectKey.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "8f98ef3f0983ed12ba714390b9a528ccf06b41f51dfcd1d52c50d86f038455c8"
upstream_lines = 233
uses_common = [
  "ask",
  "ask_pass",
  "decrypt_skeyJSON",
  "encrypt_skeyJSON",
  "exists",
  "file_lock",
  "file_unlock",
  "is_strong_password",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = []
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 01_protectKey: Encrypt or decrypt an existing signing key file in place

Converts one existing signing key file between its two stored forms: the plaintext cardano-cli text envelope and the passphrase-encrypted envelope of [Ckey](../common/Ckey.md). The action (`enc` or `dec`) and the key file are arguments. The script shows what it is about to do, asks for the passphrase and for a final go-ahead, and then **overwrites the same file**. It never touches the chain, so it is mode-independent and works on the air-gapped machine. Use `enc` for keys created without protection (`cli` key type of the generation scripts, for example [04c](./04c_genKESKeys.md)) and for keys brought in by [0x_importHelper](./0x_importHelper.md); use `dec` to go back, for instance for the KES key that a block producer must read without a passphrase.

The cryptography is not here: `encrypt_skeyJSON` and `decrypt_skeyJSON` are specified in Ckey (SPO-Ckey-EXT-001, SPO-Ckey-OUT-001, SPO-Ckey-EXT-002, SPO-Ckey-OUT-002) and the password rule in SPO-Ckey-INV-001. This spec records the interaction, the refusals, the write and the secrets the script prints.

## Interface

- **SPO-01protectKey-IF-001** Usage is `<ENC|ENCRYPT|DEC|DECRYPT> <name of SKEY file>`. The action word is matched case-insensitively. With fewer than two arguments the script prints the usage to stderr and exits 1. (src: L43-L47)
- **SPO-01protectKey-IF-002** An unknown action word prints the usage and an error and exits 1. (src: L66)
- **SPO-01protectKey-IF-003** The key file is the second argument as given when it is a regular file, else the argument with `.skey` appended when that is a regular file, else the script prints the usage and an error and exits 1. A leading `./` is dropped from the name. (src: L51-L55)
- **SPO-01protectKey-IF-004** With more than two arguments the usage is printed but the script goes on, using the first two. (src: L48)

> **Upstream quirk:** The check for extra arguments prints the usage without exiting, so the third and further arguments are silently ignored. (src: L48)

## Inputs

- **SPO-01protectKey-IN-001** Reads the whole key file as text. The file's `.type` is read with `jq`. The state "encrypted" is decided by a text search: the file contains `encrHex` or `Encrypted` on any line, as in SPO-Ckey-IN-001. (src: L84, L89, L176, L181)

## Behaviour

1. **Check the file and the tool.**
   - **SPO-01protectKey-PRE-001** Exits 1 unless the file's `.type` contains the text `SigningKey` (anywhere in the type). A file that is not JSON fails the same way. The check runs for both actions and before the tool check. (src: L58)
   - **SPO-01protectKey-PRE-002** Exits 1 when `gpg` is not installed, with an install hint. (src: L62)
2. **Show the current file, check the direction.**
   - **SPO-01protectKey-SEC-001** For `enc` the script prints the file's current content to stdout before checking whether it is already encrypted, so a plaintext signing key goes to the terminal. (src: L83-L86)
   - **SPO-01protectKey-PRE-003** `enc` exits 1 (error on stderr) when the file is already encrypted (SPO-01protectKey-IN-001). (src: L89)
   - **SPO-01protectKey-PRE-004** `dec` exits 1 (error on stderr) when the file is not encrypted. The encrypted content is shown first. (src: L175-L181)
   - **SPO-01protectKey-PR-001** Asks `Is this correct, continue?`, default **No**, for both actions. A "no" prints "Aborted" and exits 1 without changes. (src: L92, L184)

### enc

3. **Choose the passphrase.**
   - **SPO-01protectKey-PR-002** Asks for a passphrase, then for a confirmation, and repeats both until they match. A weak entry (SPO-Ckey-INV-001) is asked for again. The same rule is applied to the confirmation. An empty entry at either prompt prints "Aborted" and exits 1 without changes. (src: L96-L123)
   - **SPO-01protectKey-PR-003** After a match, asks whether to show the passphrase on screen for 5 seconds, default **No**. (src: L132)
   - **SPO-01protectKey-SEC-002** With "yes" the passphrase is printed in clear for 5 seconds. (src: L132)
4. **Encrypt.**
   - **SPO-01protectKey-EXT-001** The key text is encrypted with `encrypt_skeyJSON` (SPO-Ckey-EXT-001, SPO-Ckey-OUT-001). A failure prints the error and exits 1 without changes. (src: L136-L138)
   - **SPO-01protectKey-INV-001** The result is not verified by decrypting it before it replaces the file: the encrypted envelope is written as produced, and only the two matching passphrase entries stand between a typo and a key that cannot be decrypted. (src: L136-L158)
5. **Write.**
   - **SPO-01protectKey-PR-004** Shows the encrypted envelope and asks `Write encrypted SKEY-File to disc?`, default **No**. A "no" prints "Aborted" and exits 1; the file is unchanged. (src: L141-L146, L156)
   - **SPO-01protectKey-OUT-001** On "yes" the file is unlocked (`0600`), overwritten in place with the encrypted envelope and a trailing newline, and locked (`0400`). The file ends at `0400` whatever its mode was. (src: L148-L153)
   - **SPO-01protectKey-PRE-005** A failed write exits 1 after printing the **original plaintext key** on the terminal so the operator can restore it. The file is left unlocked and possibly truncated. (src: L150-L151)
   - **SPO-01protectKey-SEC-003** Afterwards prints the file's new content (the encrypted envelope, not secret). (src: L161-L163)

### dec

3. **Ask for the passphrase.**
   - **SPO-01protectKey-PR-005** Asks once for the passphrase. An empty entry prints "Aborted" and exits 1. A passphrase that is not strong is not tried (it cannot be the right one, SPO-Ckey-PR-002) and is asked for again, with no attempt limit. `ENV_DECRYPT_PASSWORD` is not read. (src: L188-L196)
4. **Decrypt.**
   - **SPO-01protectKey-EXT-002** The envelope is decrypted with `decrypt_skeyJSON` (SPO-Ckey-EXT-002, SPO-Ckey-OUT-002). A failure, including a wrong passphrase (SPO-Ckey-PRE-007), prints the error and exits 1 without changes. There is no retry. (src: L199-L202)
   - **SPO-01protectKey-SEC-004** The decrypted, **plaintext** key is printed to stdout before the write is confirmed. (src: L204-L206)
5. **Write.**
   - **SPO-01protectKey-PR-006** Asks `Write decrypted SKEY-File to disc?`, default **No**. A "no" prints "Aborted" and exits 1; the file is unchanged. (src: L209, L220)
   - **SPO-01protectKey-OUT-002** On "yes" the file is unlocked (`0600`), overwritten in place with the plain envelope as formatted by `jq` (SPO-Ckey-OUT-002) and a trailing newline, and locked (`0400`). The original cardano-cli formatting of the file is not preserved. (src: L211-L216)
   - **SPO-01protectKey-PRE-006** The check after the write tests the status of the preceding `unset`, not of the write, so a failed write is not detected: the script reports success. (src: L213-L217)
   - **SPO-01protectKey-SEC-005** Afterwards prints the file's new content, the **plaintext signing key**. (src: L224-L227)

> **Upstream quirk:** For `enc` the failed write is detected (SPO-01protectKey-PRE-005); for `dec` it is not (SPO-01protectKey-PRE-006).

## Work modes

Mode-independent. Nothing is queried; the script needs `gpg`, `jq` and a terminal for the prompts.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| `Is this correct, continue?` (SPO-01protectKey-PR-001) | No | No: exit 1, unchanged |
| Passphrase, then confirmation, `enc` (SPO-01protectKey-PR-002) | none; empty aborts | Chosen passphrase |
| Show the passphrase for 5 seconds, `enc` (SPO-01protectKey-PR-003) | No | Display only |
| Passphrase, `dec` (SPO-01protectKey-PR-005) | none; empty aborts | Decrypts |
| `Write encrypted SKEY-File to disc?` (SPO-01protectKey-PR-004) | No | No: exit 1, unchanged |
| `Write decrypted SKEY-File to disc?` (SPO-01protectKey-PR-006) | No | No: exit 1, unchanged |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| the key file (`<name>.skey` or the path given) | `enc`: encrypted envelope (SPO-Ckey-OUT-001); `dec`: plain envelope (SPO-Ckey-OUT-002) | `0400` | replaced in place |

No other file is read or written. The matching `.vkey`, address and certificate files are not touched. Success is exit 0.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments, unknown action, file not found | 1 | SPO-01protectKey-IF-001, SPO-01protectKey-IF-002, SPO-01protectKey-IF-003 |
| `.type` lacks `SigningKey` or file is not JSON | 1 | SPO-01protectKey-PRE-001 |
| `gpg` missing | 1 | SPO-01protectKey-PRE-002 |
| `enc` of an encrypted file; `dec` of a plain file | 1 | SPO-01protectKey-PRE-003, SPO-01protectKey-PRE-004 |
| Any "no" at a confirmation | 1 | SPO-01protectKey-PR-001, SPO-01protectKey-PR-004, SPO-01protectKey-PR-006 |
| Empty passphrase or confirmation | 1 | SPO-01protectKey-PR-002, SPO-01protectKey-PR-005 |
| Encryption or decryption failed (wrong passphrase) | 1 | SPO-01protectKey-EXT-001, SPO-01protectKey-EXT-002 |
| `enc` write failed | 1 | SPO-01protectKey-PRE-005 |
| `dec` write failed | 0 (not detected) | SPO-01protectKey-PRE-006 |

## Security

- **SPO-01protectKey-SEC-006** The passphrase is passed to gpg on its command line (SPO-Ckey-SEC-001) and is read by `ask_pass`, which returns it in clear in a shell variable (SPO-Cui-SEC-001). It is unset after use. (src: L127-L139, L189-L202)
- **SPO-01protectKey-SEC-007** The file is overwritten in place with no backup. Between the write and the final lock it is `0600`; a crash between unlock and lock leaves it unlocked (SPO-Cui-INV-004). (src: L149-L152, L212-L216)

Secrets on stdout, in total: the plaintext key for `enc` (SPO-01protectKey-SEC-001), the passphrase when shown (SPO-01protectKey-SEC-002), the plaintext key twice for `dec` (SPO-01protectKey-SEC-004, SPO-01protectKey-SEC-005) and, on a failed `enc` write, once more (SPO-01protectKey-PRE-005). A caller never captures or logs this output.

## Domain mapping

Use cases: `ProtectSigningKey(key, passphrase)` for `enc` and `UnprotectSigningKey(key, passphrase, destination)` for `dec`, on the `SealedKey` of the `key-custody` context.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Vault` | `unseal(ref, passphrase?)` | Read the current key (plain, or encrypted for `dec`) |
| `Vault` | `seal(secret, policy)` | `enc`: store the key under the passphrase policy |
| `Vault` | `exportPlaintext(ref, destination)` | `dec`: write the plain key back to the file; a named, audited operation |
| `Store` | `exists(artefact)`, `lock(artefact)`, `unlock(artefact)` | File lookup and write protection |
| `UI` | `askPassword(prompt)`, `confirm(prompt, default)`, `show(view)` | Prompts |

## Port notes

* Never print the key (SPO-01protectKey-SEC-001, SPO-01protectKey-SEC-004, SPO-01protectKey-SEC-005, SPO-01protectKey-PRE-005); show only the key type, the description and a verification-key fingerprint to let the operator confirm the file.
* Verify before replacing: decrypt the new envelope with the passphrase and compare with the original (SPO-01protectKey-INV-001), write to a temporary file and rename it, and keep the original until the operator confirms (SPO-01protectKey-SEC-007).
* Detect a failed write for `dec` as well (SPO-01protectKey-PRE-006).
* In a vault-backed adapter `enc` becomes "import the plain key and seal it", and `dec` should be an audited export with a reason; ordinary signing never needs it, because the `Signer` port unseals in memory.
* With remote or multi-party signing, sealing is the point where a key leaves the operator's custody. Record who sealed it and with which policy.
* Apply the password policy to `enc` only (SPO-Ckey-INV-001); do not make the strength rule a gate on `dec` for new envelopes.

## Open questions

* The type of a hardware signing file (`.hwsfile`) is expected not to contain `SigningKey`, which would make this script refuse it (SPO-01protectKey-PRE-001); a look at a real `cardano-hw-cli` file settles it.
* Whether the formatting change of `dec` (SPO-01protectKey-OUT-002) matters to any consumer: the cardano-cli reads the envelope by field, so it is not expected to.
