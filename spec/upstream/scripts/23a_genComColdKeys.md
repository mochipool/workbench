+++
id = "23a"
kind = "script"
title = "Generate constitutional committee cold keys"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "key-custody"]
use_cases = ["GenerateCommitteeColdKey"]
depends_on = ["Cconf", "Cconv", "Cui", "Ckey", "Chw", "Pfiles", "Pparam"]

upstream_path = "cardano/mainnet/23a_genComColdKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "64b2f8e3bc014ecc97f0ee11ffe8d3659719b4cc84d18a89d7593424605076a0"
upstream_lines = 308
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
  "governance committee key-gen-cold",
  "governance committee key-hash",
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

# 23a_genComColdKeys: Generate constitutional committee cold keys

Creates the cold key of a constitutional committee (CC) member and its key hash. The cold credential is the member's long-term identity: the ledger's committee state is keyed by it, it signs the authorisation of a hot key ([23c](./23c_regComAuthCert.md)) and the resignation ([23e](./23e_retComColdKeys.md)). The cold key never votes. A member named `<com>` has the cold files `<com>.cc-cold.*`; the hot key is generated separately by [23b](./23b_genComHotKeys.md).

The four key forms (`cli`, `enc`, `hw`, `mnemonics`) and the parameters are those of [21a](./21a_genDRepKeys.md); this spec states them again because the commands, path and file names differ. Only key-hash credentials are created; committee script credentials are not supported by any of the 23x scripts except for lookups in [23d](./23d_checkComOnChain.md).

Mode-independent: it never touches the chain.

## Interface

- **SPO-23a-IF-001** Takes two positional arguments: the member name and a key type of `cli`, `enc`, `hw` or `mnemonics` (case-insensitive). A trailing `.hash` on the name is dropped (not `.cc-cold`), and a leading `./` is dropped. (src: L21, L56-L57)
- **SPO-23a-IF-002** Prints usage on stderr and exits 1 when fewer than two arguments are given or the key type is not one of the four. (src: L21-L45)
- **SPO-23a-IF-003** The words after the key type accept `acc:<n>`, `idx:<n>` and `mnemonics:<24 words>` (SPO-Pparam-IF-027, SPO-Pparam-IF-028), defaults 0, 0 and none; other words are silently ignored. `acc`, `idx` and the path apply to `hw` and `mnemonics` only. (src: L59-L90)
- **SPO-23a-PRE-001** A bad `acc:` or `idx:` (not an integer in 0..2147483647) or a `mnemonics:` with other than 24 words exits 1. The message for a bad `idx:` says "Account#". (src: L73-L87)
- **SPO-23a-PRE-002** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0 without creating anything. (src: L48-L53)

## Inputs

- **SPO-23a-PRE-003** Refuses with exit 2 when `<com>.cc-cold.vkey` exists, when `<com>.cc-cold.skey` or `<com>.cc-cold.hwsfile` exists, or when `<com>.cc-cold.hash` exists. (src: L111-L113)
- **SPO-23a-PRE-004** With key type `mnemonics` only, refuses with exit 1 when `<com>.cc-cold.mnemonics` exists. (src: L139)

## Behaviour

1. **Key type `cli`.**
   - **SPO-23a-EXT-001** Runs `cardano-cli <era> governance committee key-gen-cold --cold-verification-key-file <com>.cc-cold.vkey --cold-signing-key-file <com>.cc-cold.skey`, then locks both files. A failure ends the script with cardano-cli's code. (src: L123-L126)
2. **Key type `enc`.**
   - **SPO-23a-EXT-002** Runs `key-gen-cold` with the signing key directed to stdout, captured in memory; only the verification key is written and locked. (src: L196-L198)
   - **SPO-23a-INV-001** The plaintext signing key never reaches the disk in this form. (src: L196, L244-L255)
   - **SPO-23a-PR-001** Asks for a password and a confirmation until they match, each satisfying SPO-Ckey-INV-001; a weak entry is asked again. (src: L206-L233)
   - **SPO-23a-PRE-005** An empty password or confirmation at any ask exits 1 and deletes the `.vkey`. (src: L213, L217, L223, L227)
   - **SPO-23a-PR-002** After a matching pair, asks whether to show the password for 5 seconds (default No). (src: L241)
   - **SPO-23a-OUT-001** Writes the encrypted envelope of SPO-Ckey-OUT-001 to `<com>.cc-cold.skey` and locks it; a failure exits 1. (src: L245-L256)
   - **SPO-23a-PRE-006** An interrupt during password entry or encryption deletes the `.vkey` and exits 1. (src: L96-L107, L204, L258)
3. **Key type `mnemonics`.**
   - **SPO-23a-PRE-007** Requires `cardano-signer` of at least the minimum version (configured path, else `<scriptDir>/cardano-signer`); otherwise exit 1. (src: L145-L157)
   - **SPO-23a-EXT-003** Runs `cardano-signer keygen --path 1852H/1815H/<acc>H/4/<idx> [--mnemonics "<words>"] --json-extended --out-vkey <com>.cc-cold.vkey --out-skey <com>.cc-cold.skey`. Without supplied words the generated ones are read from `.mnemonics` of the JSON result. A tool failure exits 1. (src: L162-L170)
   - **SPO-23a-INV-002** The cold derivation path is `1852H/1815H/<acc>H/4/<idx>` (role index 4, CIP-1852 constitutional committee cold role). (src: L142, L162, L166)
   - **SPO-23a-OUT-002** Writes the 24 words to `<com>.cc-cold.mnemonics` and locks it with the vkey and skey; a write failure exits 1. The signing key is plaintext. (src: L173-L183)
4. **Key type `hw`.**
   - **SPO-23a-PRE-008** Opens a hardware session restricted to Ledger and Keystone; anything else, an absent device or an old version exits 1. (src: L271)
   - **SPO-23a-EXT-004** Runs `cardano-hw-cli address key-gen --path 1852H/1815H/<acc>H/4/<idx> --verification-key-file <com>.cc-cold.vkey --hw-signing-file <com>.cc-cold.hwsfile`. Output containing `ERROR` or `DISCONNECT` exits 1. (src: L272-L273)
   - **SPO-23a-OUT-003** The verification key and hwsfile keep the type and description the tool wrote (the type rewrite exists only as commented-out code, unlike 23b and 21a), and both are locked. (src: L276-L284)
5. **Derive the key hash (all forms).**
   - **SPO-23a-EXT-005** Runs `cardano-cli <era> governance committee key-hash --verification-key-file <com>.cc-cold.vkey` and redirects stdout to `<com>.cc-cold.hash`, then locks it. The redirection creates the file before cardano-cli has succeeded; a failure ends the script with cardano-cli's code and leaves an empty `.hash` behind. (src: L296-L298)
   - **SPO-23a-INV-003** The hash is the 56-hex-digit credential hash that the committee state, [23c](./23c_regComAuthCert.md) and [23d](./23d_checkComOnChain.md) use. Its bech32 spellings are described in 23d. (src: L296-L301)

## Work modes

Mode-independent.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password and confirmation, `enc` only (SPO-23a-PR-001) | none; empty aborts | Encrypts the signing key |
| Show the password for 5 seconds (SPO-23a-PR-002) | No | Display only |

## Outputs

**Upstream file contract** (`<com>` as normalised by SPO-23a-IF-001):

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<com>.cc-cold.vkey` | text envelope of the cold verification key | `0400` | created |
| `<com>.cc-cold.skey` | plaintext (`cli`, `mnemonics`) or encrypted envelope (`enc`); absent for `hw` | `0400` | created |
| `<com>.cc-cold.hwsfile` | hardware signing file, no private key (`hw`) | `0400` | created |
| `<com>.cc-cold.mnemonics` | 24 words in clear (`mnemonics`) | `0400` | created |
| `<com>.cc-cold.hash` | 56 hex digits and a newline | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-23a-IF-002 |
| Bad `acc:`/`idx:`/words | 1 | SPO-23a-PRE-001 |
| Pre-Conway era (nothing done) | 0 | SPO-23a-PRE-002 |
| vkey, skey/hwsfile or hash exists | 2 | SPO-23a-PRE-003 |
| mnemonics file exists | 1 | SPO-23a-PRE-004 |
| Empty password/confirmation, SIGINT (`enc`) | 1 | SPO-23a-PRE-005, SPO-23a-PRE-006 |
| cardano-signer missing, old or failing | 1 | SPO-23a-PRE-007, SPO-23a-EXT-003 |
| Hardware unavailable, hw-cli error | 1 | SPO-23a-PRE-008, SPO-23a-EXT-004 |
| cardano-cli failure | cardano-cli's code | SPO-23a-EXT-001, SPO-23a-EXT-005 |

> **Upstream quirk:** the interrupt cleanup removes `.cc-cold.vkey` twice and never the signing key (same defect as 21a). (src: L96-L107)

> **Upstream quirk:** the key-hash redirection leaves an empty, unlocked `.hash` when cardano-cli fails, and the next run then refuses with exit 2 (SPO-23a-PRE-003). (src: L296-L297)

## Security

- **SPO-23a-SEC-001** With `cli` and `mnemonics` the script prints the signing key file to stdout: the **plaintext cold signing key**. With `enc` it prints the encrypted envelope, with `hw` the hwsfile. A caller must never capture or log the output. (src: L131, L189, L261, L290)
- **SPO-23a-SEC-002** With `mnemonics` the 24 words are printed on stdout and written in clear to `.cc-cold.mnemonics`; supplied words travel on the `cardano-signer` command line (SPO-Pfiles-SEC-003). (src: L160, L170, L173, L162)
- **SPO-23a-SEC-003** With `enc` the password is shown for 5 seconds if the operator accepts SPO-23a-PR-002 and goes to gpg on a command line (SPO-Ckey-SEC-001). (src: L241, L246)

## Domain mapping

Use case `GenerateCommitteeColdKey(name, protection, derivation?)` on aggregate `CommitteeMember` (cold credential; identity is the cold credential hash).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(CommitteeCold)` | cardano-cli, cardano-signer (path role 4) or cardano-hw-cli |
| `Vault` | `seal(coldSigningKey, policy)` | `cli` none, `enc` passphrase; `hw` reference |
| `Ledger` | `credentialHash(CommitteeCold verification key)` *(new)* | `committee key-hash` |
| `Store` | `put(CommitteeColdVerificationKey / Hash / HardwareSigningFile / Mnemonics)`, `exists`, `lock` | Artefacts and refusals |
| `Signer` | `openHardwareSession(Ledger, Keystone)` | `hw` |
| `Toolchain` | `locate`/`version(cardano-signer)` | `mnemonics` |
| `UI` | `askPassword`, `confirm` | `enc` |

## Port notes

* Observed 2026-11-16 (cardano-cli 11.2.3.0, cardano-signer 1.35.0): `governance committee key-gen-cold` writes type `ConstitutionalCommitteeColdVerificationKey_ed25519` / `ConstitutionalCommitteeColdSigningKey_ed25519` with descriptions `Constitutional Committee Cold Verification Key` / `... Cold Signing Key`; `committee key-hash` prints the 56 hex digits **with** a trailing newline, which is what the `.cc-cold.hash` file holds. The `mnemonics` form (cardano-signer, path role 4) writes the extended signing key as type `ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32`, description `Constitutional Committee Cold Extended Signing Key`, two-space indent. The port is byte-equal for both forms (`TestGovKeyGenerationParity`, `TestGovMnemonicKeysMatchUpstream`).

* The cold key is the most valuable CC credential and should be kept offline; a port should refuse `cli` plaintext by default and prefer a hardware or sealed form.
* Store the hash natively and never through a redirection that can leave an empty file; make generation atomic as in 21a.
* A committee member needs a cold key and a hot key; a port can offer both in one use case and keep the separate scripts as thin wrappers.

## Open questions

* Whether `cardano-cli governance committee key-hash` accepts the hardware verification key whose type is not rewritten (23b rewrites the hot one and 23a does not). A hardware run settles it.
