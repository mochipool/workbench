+++
id = "21a"
kind = "script"
title = "Generate DRep keys and the DRep id"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "key-custody"]
use_cases = ["GenerateDRepKey"]
depends_on = ["Cconf", "Cconv", "Cui", "Ckey", "Chw", "Pfiles", "Pparam"]

upstream_path = "cardano/mainnet/21a_genDRepKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "4ce155b00fffd5d255f2a06c9e63ddd7000bcd2bc800ad316ebfd53c5ab0b43c"
upstream_lines = 311
uses_common = [
  "ask",
  "ask_pass",
  "checkError",
  "encrypt_skeyJSON",
  "exists",
  "file_lock",
  "file_unlock",
  "is_strong_password",
  "majorError",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
  "trimString",
  "versionCheck",
]
cli_commands = [
  "governance drep id",
  "governance drep key-gen",
]
hwcli_commands = [
  "address key-gen",
]
signer_commands = [
  "keygen",
]
http_endpoints = []
env_vars = []
+++

# 21a_genDRepKeys: Generate DRep keys and the DRep id

Creates the key material of a delegated representative (DRep) and derives the DRep id from the verification key. A DRep named `<drep>` is the file family `<drep>.drep.*`. The signing side takes one of four forms chosen by the key type argument: a plain cardano-cli key (`cli`), a cardano-cli key sealed with a password (`enc`), a mnemonic-derived extended key that can be imported into a light wallet (`mnemonics`), or a hardware-wallet reference (`hw`). The script never touches the chain; registration is a separate step ([21b](./21b_regDRepCert.md)).

Only key-hash DReps are created. Script-hash DReps (`drep_script1...`) are not supported by this script or by 21b and 21d; only [21c](./21c_checkDRepOnChain.md) can look them up.

Mode-independent: no query is made in any work mode.

## Interface

- **SPO-21a-IF-001** Takes two positional arguments: the DRep name and a key type of `cli`, `enc`, `hw` or `mnemonics` (case-insensitive). A trailing `.id` on the name is dropped, and a leading `./` is dropped (see SPO-Pfiles-IN-001). (src: L21, L59-L60)
- **SPO-21a-IF-002** Prints usage on stderr and exits 1 when fewer than two arguments are given or the key type is not one of the four. (src: L21-L45)
- **SPO-21a-IF-003** The words after the key type are scanned left to right for `acc:<n>`, `idx:<n>` and `mnemonics:<24 words>` with the grammar of SPO-Pparam-IF-027 and SPO-Pparam-IF-028. Any other word is silently ignored (there is no file-word or metadata handling). Defaults: account 0, index 0, no mnemonics. (src: L62-L93)
- **SPO-21a-IF-004** `acc`, `idx` and the derivation path are used only by key types `hw` and `mnemonics`; `mnemonics:` only by `mnemonics`. With `cli` and `enc` they are validated but have no effect. (src: L126, L199, L165, L169, L275)
- **SPO-21a-PRE-001** An `acc:` or `idx:` value that is not an integer in 0..2147483647 is refused with exit 1; the message for a bad `idx:` wrongly says "Account#". (src: L76-L84)
- **SPO-21a-PRE-002** `mnemonics:` with a word count other than 24 is refused with exit 1. The words are lower-cased and repeated blanks are squeezed before counting. (src: L86-L91)
- **SPO-21a-PRE-003** On a chain that is not yet in Conway era (the configured era is Shelley through Babbage) the script prints an informational notice and exits 0 without creating anything. (src: L49-L54)

## Inputs

- **SPO-21a-IN-001** Reads the configured `cardano-cli` era, the `cardano-cli` binary (`cliEra`), and for `mnemonics` the `cardano-signer` binary and its minimum version; for `hw` the `cardano-hw-cli` binary. (src: L50, L126, L148-L158, L274)
- **SPO-21a-PRE-004** Refuses with exit 2 when `<drep>.drep.vkey` already exists. (src: L114)
- **SPO-21a-PRE-005** Refuses with exit 2 when `<drep>.drep.skey` or `<drep>.drep.hwsfile` already exists: only one signer form per DRep name. (src: L115)
- **SPO-21a-PRE-006** Refuses with exit 2 when `<drep>.drep.id` already exists. (src: L116)
- **SPO-21a-PRE-007** With key type `mnemonics` only, refuses with exit 1 when `<drep>.drep.mnemonics` already exists. The other key types do not look for that file. (src: L142)

## Behaviour

The three existence refusals run before any generation, in the order above. Then exactly one of the four forms runs.

1. **Key type `cli`.**
   - **SPO-21a-EXT-001** Runs `cardano-cli <era> governance drep key-gen --verification-key-file <drep>.drep.vkey --signing-key-file <drep>.drep.skey`. A non-zero exit ends the script with that code (SPO-Cui-INV-001). Both files are then locked (mode 0400). (src: L126-L129)
2. **Key type `enc`.**
   - **SPO-21a-EXT-002** Runs the same `key-gen` with the signing key directed to stdout, which the script captures in memory; only the verification key is written to a file, then locked. (src: L199-L201)
   - **SPO-21a-INV-001** The plaintext signing key is never written to disk in this form. (src: L199, L248-L258)
   - **SPO-21a-PR-001** Asks for a password and a confirmation, repeating both until they match; each must satisfy the strong-password rule (SPO-Ckey-INV-001) and a weak entry is asked again. (src: L209-L236)
   - **SPO-21a-PRE-008** An empty password or an empty confirmation (at any ask) aborts with exit 1 and deletes the already-written `.vkey`. Unlike 04c, both prompts delete it. (src: L216, L220, L226, L230)
   - **SPO-21a-PR-002** After a matching pair, asks whether to show the password for 5 seconds on screen (default No). (src: L244)
   - **SPO-21a-OUT-001** Writes the signing key as the encrypted envelope of SPO-Ckey-OUT-001 (the original `type`, the description prefixed with "Encrypted", and `encrHex`) to `<drep>.drep.skey`, then locks it. An encryption or write failure exits 1. (src: L248-L259)
   - **SPO-21a-PRE-009** An interrupt (SIGINT) during password entry or encryption runs a cleanup that deletes `.vkey` and exits 1. (src: L99-L110, L207, L261)
3. **Key type `mnemonics`.**
   - **SPO-21a-PRE-010** Requires a working `cardano-signer` of at least the configured minimum version: first the configured path, else `<scriptDir>/cardano-signer`; a missing binary, a failing `--version` or an old version exits 1. (src: L148-L158)
   - **SPO-21a-EXT-003** Runs `cardano-signer keygen --path 1852H/1815H/<acc>H/3/<idx> [--mnemonics "<24 words>"] --json-extended --out-vkey <drep>.drep.vkey --out-skey <drep>.drep.skey`. The mnemonics option is passed only when the operator supplied words; otherwise the tool generates them and the script reads them from the `.mnemonics` member of the JSON result. A non-zero exit prints the tool's output and exits 1. (src: L162-L172)
   - **SPO-21a-INV-002** The derivation path is `1852H/1815H/<acc>H/3/<idx>` (role index 3 is the DRep role of CIP-1852/CIP-105). (src: L145, L165, L169)
   - **SPO-21a-OUT-002** Writes the 24 words, space separated and newline terminated, to `<drep>.drep.mnemonics` and locks it together with the vkey and skey. A write failure exits 1. (src: L176-L186)
   - **SPO-21a-OUT-003** The signing key is written in plaintext and cannot be encrypted in this form; the upstream usage guide shows it with type `DRepExtendedSigningKey_ed25519_bip32`. That type comes from cardano-signer and is not asserted by the script. (src: L165-L169, L185-L186)
4. **Key type `hw`.**
   - **SPO-21a-PRE-011** Opens a hardware session restricted to Ledger and Keystone devices; a Trezor, an absent device or an old app or firmware version exits 1 (see SPO-Chw-PRE-003). (src: L274)
   - **SPO-21a-EXT-004** Runs `cardano-hw-cli address key-gen --path 1852H/1815H/<acc>H/3/<idx> --verification-key-file <drep>.drep.vkey --hw-signing-file <drep>.drep.hwsfile`. Output containing `ERROR` or `DISCONNECT` (case-insensitive) is printed and exits 1; no other output is inspected. (src: L275-L276)
   - **SPO-21a-OUT-004** Rewrites the `type` of the verification key to `DRepVerificationKey_ed25519` and its description to `Hardware Delegate Representative Verification Key` (the hardware marker of SPO-Pfiles-INV-001), then locks vkey and hwsfile. The hwsfile content is left as the tool wrote it. (src: L279-L287)
5. **Derive the DRep id (all forms).**
   - **SPO-21a-EXT-005** Runs `cardano-cli <era> governance drep id --drep-verification-key-file <drep>.drep.vkey --out-file <drep>.drep.id` and locks the result. A non-zero exit ends the script with that code. (src: L299-L301)
   - **SPO-21a-INV-003** The id is the bech32 id that cardano-cli prints. The upstream usage guide shows the 56-character legacy (CIP-105) `drep1...` form; the later scripts treat the file content that way (see SPO-Cconv-OUT-019 and [21c](./21c_checkDRepOnChain.md)). (src: L299-L304)

## Work modes

Mode-independent. The script needs only the local tools.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password and confirmation, `enc` only (SPO-21a-PR-001) | none; empty aborts | Encrypts the signing key |
| Show the password for 5 seconds (SPO-21a-PR-002) | No | Display only |

## Outputs

**Upstream file contract** (`<drep>` as normalised by SPO-21a-IF-001):

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<drep>.drep.vkey` | text envelope; `DRepVerificationKey_ed25519` (type rewritten for `hw`) | `0400` | created |
| `<drep>.drep.skey` | text envelope, plaintext (`cli`, `mnemonics`) or encrypted envelope (`enc`); absent for `hw` | `0400` | created |
| `<drep>.drep.hwsfile` | hardware signing file, no private key (`hw` only) | `0400` | created |
| `<drep>.drep.mnemonics` | 24 words in clear (`mnemonics` only) | `0400` | created |
| `<drep>.drep.id` | bech32 DRep id | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-21a-IF-002 |
| Bad `acc:`/`idx:`, bad word count | 1 | SPO-21a-PRE-001, SPO-21a-PRE-002 |
| Pre-Conway era (nothing done) | 0 | SPO-21a-PRE-003 |
| vkey, skey/hwsfile or id file exists | 2 | SPO-21a-PRE-004, SPO-21a-PRE-005, SPO-21a-PRE-006 |
| mnemonics file exists (`mnemonics`) | 1 | SPO-21a-PRE-007 |
| Empty password or confirmation, SIGINT (`enc`) | 1 | SPO-21a-PRE-008, SPO-21a-PRE-009 |
| cardano-signer missing, old or failing | 1 | SPO-21a-PRE-010, SPO-21a-EXT-003 |
| Hardware device unavailable, hw-cli error | 1 | SPO-21a-PRE-011, SPO-21a-EXT-004 |
| cardano-cli failure | cardano-cli's code | SPO-21a-EXT-001, SPO-21a-EXT-005 |

> **Upstream quirk:** the interrupt cleanup removes `.drep.vkey` twice and never the signing key, so it deletes less than it appears to. The signing key does not exist before the final write, so the effect is limited to a window of a few milliseconds. (src: L99-L110)

> **Upstream quirk:** a failure after some files were written (hardware tool error, mnemonic file write error, cardano-cli failure while deriving the id) leaves the earlier files in place, and the next run refuses with exit 2. Only the `enc` abort paths clean up.

## Security

- **SPO-21a-SEC-001** With `cli` and `mnemonics` the script prints the signing key file to stdout after creating it: the **plaintext DRep signing key**. A caller must never capture, log or tee the output. With `enc` it prints the encrypted envelope; with `hw` the hwsfile (no private key). (src: L133-L134, L191-L192, L263-L264, L292-L293)
- **SPO-21a-SEC-002** With `mnemonics` the 24 words are printed on stdout, whether supplied or generated, and written in clear to `<drep>.drep.mnemonics`. They reproduce the signing key (SPO-Pfiles-SEC-003). (src: L163, L173, L176)
- **SPO-21a-SEC-003** Supplied mnemonics are passed to `cardano-signer` on its command line, where other local users can read them in the process list. (src: L165)
- **SPO-21a-SEC-004** With `enc`, the chosen password is printed in clear for 5 seconds if the operator accepts SPO-21a-PR-002, and travels to gpg on a command line (SPO-Ckey-SEC-001). (src: L244, L249)

## Domain mapping

Use case `GenerateDRepKey(name, protection, derivation?)` on aggregate `DRep` (identity: the DRep credential hash; the id string is derived).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(DRep)` | `cli`/`enc`: cardano-cli; `mnemonics`: cardano-signer with path and optional words; `hw`: cardano-hw-cli |
| `Vault` | `seal(drepSigningKey, policy)` | `cli` = no protection, `enc` = passphrase; `hw` stores only a reference |
| `Store` | `put(DRepVerificationKey / DRepId / HardwareSigningFile / Mnemonics)`, `exists`, `lock` | Artefacts and the refuse-to-overwrite checks |
| `Ledger` | `deriveId(DRep verification key)` *(new)* | The id that cardano-cli prints; the native form should return both CIP-105 and CIP-129 |
| `Signer` | `openHardwareSession(Ledger, Keystone)` | `hw` only |
| `Toolchain` | `locate`/`version(cardano-signer)` | `mnemonics` only |
| `UI` | `askPassword`, `confirm` | `enc` only |

## Port notes

* Seal by default. Offer `cli` only as an explicit, audited export; never print signing keys or mnemonics. Show mnemonics once, on request, and never write them in clear next to the key.
* Make generation atomic: all artefacts or none, and clean up on every failure path, not just `enc`.
* Derive the id natively and store both the CIP-105 and CIP-129 forms; the CIP-129 id is what governance explorers and the ledger's own JSON now use.
* Script-hash DReps (`drep_script`) cannot be created here; a port that wants them needs a credential model with a key-hash or script-hash variant.
* The 04c remarks on gpg and password handling apply unchanged.

## Open questions

* Which form `cardano-cli governance drep id` prints (CIP-105 or CIP-129, and whether that depends on the pinned cardano-cli 11.x). A real run against the pinned release settles it; see also [21c](./21c_checkDRepOnChain.md).
