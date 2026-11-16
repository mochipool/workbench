+++
id = "23b"
kind = "script"
title = "Generate constitutional committee hot keys"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "key-custody"]
use_cases = ["GenerateCommitteeHotKey"]
depends_on = ["Cconf", "Cconv", "Cui", "Ckey", "Chw", "Pfiles", "Pparam"]

upstream_path = "cardano/mainnet/23b_genComHotKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "b3dc04d57dab6532375c2c7fe7857e775e877e6e9cb6dac1bf30a08e58b3f2ef"
upstream_lines = 328
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
  "governance committee key-gen-hot",
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

# 23b_genComHotKeys: Generate constitutional committee hot keys

Creates the hot key of a committee member and its key hash. The hot credential is the one that signs committee votes (`24b_regVote.sh` upstream); it is authorised by the member's cold key through a certificate ([23c](./23c_regComAuthCert.md)). The hot key is replaceable: a new hot key can be authorised later without changing the member's identity. The hot files are `<com>.cc-hot.*`.

It is the sibling of [23a](./23a_genComColdKeys.md) with the derivation role 5 and with one behavioural difference: an existing hot key of the same name can be replaced after a confirmation instead of being refused. The key forms and parameters are those of 21a and 23a.

Mode-independent: it never touches the chain.

## Interface

- **SPO-23b-IF-001** Takes two positional arguments: the member name and a key type of `cli`, `enc`, `hw` or `mnemonics` (case-insensitive). A trailing `.hash` on the name is dropped, and a leading `./` is dropped. (src: L21, L56-L57)
- **SPO-23b-IF-002** Prints usage on stderr and exits 1 when fewer than two arguments are given or the key type is not one of the four. (src: L21-L45)
- **SPO-23b-IF-003** The words after the key type accept `acc:<n>`, `idx:<n>` and `mnemonics:<24 words>` (SPO-Pparam-IF-027, SPO-Pparam-IF-028), defaults 0, 0 and none; other words are silently ignored. `acc`, `idx` and the path apply to `hw` and `mnemonics` only. (src: L59-L90)
- **SPO-23b-PRE-001** A bad `acc:` or `idx:` or a `mnemonics:` with other than 24 words exits 1. (src: L73-L87)
- **SPO-23b-PRE-002** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0. (src: L48-L53)

## Inputs

- **SPO-23b-PR-001** When any of `<com>.cc-hot.vkey`, `.skey`, `.hwsfile` or `.hash` exists, asks "delete them and generate new ones?" with default **No**. Declining exits 1 and changes nothing. Accepting unlocks and removes the existing files (see the quirk below) and continues. There is no exit-2 refusal in this script. (src: L110-L130)
- **SPO-23b-PRE-003** With key type `mnemonics` only, refuses with exit 1 when `<com>.cc-hot.mnemonics` still exists after the previous step. A mnemonics file that is the only leftover is not covered by the previous prompt. (src: L157)

> **Upstream quirk:** the replace branch removes `.cc-hot.vkey` twice and never `.cc-hot.skey` (it only unlocks it). A leftover signing key therefore survives a replace; with `hw` it then sits next to the new hwsfile and makes the signer ambiguous (SPO-Pfiles-INV-002). With the other forms the new key is written over it. (src: L114-L123)

## Behaviour

1. **Key type `cli`.**
   - **SPO-23b-EXT-001** Runs `cardano-cli <era> governance committee key-gen-hot --verification-key-file <com>.cc-hot.vkey --signing-key-file <com>.cc-hot.skey`, then locks both. A failure ends the script with cardano-cli's code. (src: L141-L144)
2. **Key type `enc`.**
   - **SPO-23b-EXT-002** Runs `key-gen-hot` with the signing key directed to stdout, captured in memory; only the verification key is written and locked. (src: L214-L216)
   - **SPO-23b-INV-001** The plaintext signing key never reaches the disk in this form. (src: L214, L262-L273)
   - **SPO-23b-PR-002** Asks for a password and a confirmation until they match, each satisfying SPO-Ckey-INV-001. (src: L224-L250)
   - **SPO-23b-PRE-004** An empty password or confirmation at any ask exits 1 and deletes the `.vkey`. (src: L231, L235, L241, L245)
   - **SPO-23b-PR-003** After a matching pair, asks whether to show the password for 5 seconds (default No). (src: L259)
   - **SPO-23b-OUT-001** Writes the encrypted envelope of SPO-Ckey-OUT-001 to `<com>.cc-hot.skey` and locks it; a failure exits 1. (src: L263-L274)
   - **SPO-23b-PRE-005** An interrupt during password entry or encryption deletes the `.vkey` and exits 1. (src: L96-L107, L222, L276)
3. **Key type `mnemonics`.**
   - **SPO-23b-PRE-006** Requires `cardano-signer` of at least the minimum version (configured path, else `<scriptDir>/cardano-signer`); otherwise exit 1. (src: L163-L175)
   - **SPO-23b-EXT-003** Runs `cardano-signer keygen --path 1852H/1815H/<acc>H/5/<idx> [--mnemonics "<words>"] --json-extended --out-vkey <com>.cc-hot.vkey --out-skey <com>.cc-hot.skey`. Without supplied words the generated ones are read from the JSON result. A tool failure exits 1. (src: L180-L188)
   - **SPO-23b-INV-002** The hot derivation path is `1852H/1815H/<acc>H/5/<idx>` (role index 5, CIP-1852 constitutional committee hot role). (src: L160, L180, L184)
   - **SPO-23b-OUT-002** Writes the 24 words to `<com>.cc-hot.mnemonics` and locks it with the vkey and skey; a write failure exits 1. The signing key is plaintext. (src: L191-L201)
4. **Key type `hw`.**
   - **SPO-23b-PRE-007** Opens a hardware session restricted to Ledger and Keystone; anything else, an absent device or an old version exits 1. (src: L289)
   - **SPO-23b-EXT-004** Runs `cardano-hw-cli address key-gen --path 1852H/1815H/<acc>H/5/<idx> --verification-key-file <com>.cc-hot.vkey --hw-signing-file <com>.cc-hot.hwsfile`. Output containing `ERROR` or `DISCONNECT` exits 1. (src: L290-L291)
   - **SPO-23b-OUT-003** Rewrites the `type` of the verification key to `ConstitutionalCommitteeHotVerificationKey_ed25519` and the `type` of the hwsfile to `ConstitutionalCommitteeHotHWSigningFile_ed25519`, leaving the descriptions, then locks both. So cardano-cli accepts the key as a hot credential. (src: L294-L302)
5. **Derive the key hash (all forms).**
   - **SPO-23b-EXT-005** Runs `cardano-cli <era> governance committee key-hash --verification-key-file <com>.cc-hot.vkey` with stdout redirected to `<com>.cc-hot.hash`, then locks it. A failure ends the script with cardano-cli's code and leaves an empty `.hash`. (src: L316-L318)
   - **SPO-23b-INV-003** The hash is the 56-hex-digit credential hash that [23c](./23c_regComAuthCert.md) compares with the authorised hot credential and encodes as `cc_hot1...`. (src: L316-L321)

## Work modes

Mode-independent.

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Replace existing hot keys (SPO-23b-PR-001) | No | Deletes the existing files, else exit 1 |
| Password and confirmation, `enc` (SPO-23b-PR-002) | none; empty aborts | Encrypts the signing key |
| Show the password for 5 seconds (SPO-23b-PR-003) | No | Display only |

## Outputs

**Upstream file contract** (`<com>` as normalised by SPO-23b-IF-001):

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<com>.cc-hot.vkey` | text envelope of the hot verification key (type rewritten for `hw`) | `0400` | created, replacing an accepted replace |
| `<com>.cc-hot.skey` | plaintext (`cli`, `mnemonics`) or encrypted envelope (`enc`); absent for `hw` | `0400` | created |
| `<com>.cc-hot.hwsfile` | hardware signing file, type rewritten (`hw`) | `0400` | created |
| `<com>.cc-hot.mnemonics` | 24 words in clear (`mnemonics`) | `0400` | created |
| `<com>.cc-hot.hash` | 56 hex digits and a newline | `0400` | created |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments, bad parameters | 1 | SPO-23b-IF-002, SPO-23b-PRE-001 |
| Pre-Conway era (nothing done) | 0 | SPO-23b-PRE-002 |
| Existing hot keys and replace declined | 1 | SPO-23b-PR-001 |
| mnemonics file exists | 1 | SPO-23b-PRE-003 |
| Empty password/confirmation, SIGINT (`enc`) | 1 | SPO-23b-PRE-004, SPO-23b-PRE-005 |
| cardano-signer missing, old or failing | 1 | SPO-23b-PRE-006, SPO-23b-EXT-003 |
| Hardware unavailable, hw-cli error | 1 | SPO-23b-PRE-007, SPO-23b-EXT-004 |
| cardano-cli failure | cardano-cli's code | SPO-23b-EXT-001, SPO-23b-EXT-005 |

## Security

- **SPO-23b-SEC-001** With `cli` and `mnemonics` the script prints the signing key file to stdout: the **plaintext hot signing key**. With `enc` it prints the encrypted envelope, with `hw` the hwsfile. A caller must never capture or log the output. (src: L149, L207, L279, L309)
- **SPO-23b-SEC-002** With `mnemonics` the 24 words are printed on stdout and written in clear to `.cc-hot.mnemonics`; supplied words travel on the `cardano-signer` command line (SPO-Pfiles-SEC-003). (src: L178, L188, L191, L180)
- **SPO-23b-SEC-003** With `enc` the password is shown for 5 seconds if the operator accepts SPO-23b-PR-003 and goes to gpg on a command line (SPO-Ckey-SEC-001). (src: L259, L264)
- **SPO-23b-SEC-004** The replace prompt deletes the old hot signing material it removes without a backup. A hot key that is still authorised on chain stays authorised until a new authorisation (23c) replaces it. (src: L110-L127)

## Domain mapping

Use case `GenerateCommitteeHotKey(name, protection, derivation?, replace?)` on aggregate `CommitteeMember` (hot credential; replaceable).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(CommitteeHot)` | cardano-cli, cardano-signer (path role 5) or cardano-hw-cli |
| `Vault` | `seal(hotSigningKey, policy)` | `cli` none, `enc` passphrase; `hw` reference |
| `Ledger` | `credentialHash(CommitteeHot verification key)` *(new)* | `committee key-hash` |
| `Store` | `put`, `exists`, `delete`, `lock` | Artefacts, replace |
| `Signer` | `openHardwareSession(Ledger, Keystone)` | `hw` |
| `Toolchain` | `locate`/`version(cardano-signer)` | `mnemonics` |
| `UI` | `askPassword`, `confirm` | `enc`, replace |

## Port notes

* Observed 2026-11-16 (cardano-cli 11.2.3.0, cardano-signer 1.35.0): the hot key is `ConstitutionalCommitteeHotVerificationKey_ed25519` / `ConstitutionalCommitteeHotSigningKey_ed25519`; the `mnemonics` form (path role 5) writes `ConstitutionalCommitteeHotExtendedSigningKey_ed25519_bip32`. The upstream replace prompt (SPO-23b-PR-001) is answered in the port by the explicit `Replace` option, and the replacement deletes the signing key too (the upstream branch leaves it). Without input upstream exits 1 on the prompt (the default is No), the port refuses with an error and writes nothing (`TestGovKeyRefusalsMatchUpstream`).

* Rotation: a port should model "replace the hot key" as a versioned credential, keep the old one until the new authorisation is confirmed on chain, and delete it afterwards, instead of deleting first.
* Fix the replace branch so it removes the signing key; keep the hardware type rewrites as a Ledger-adapter concern (they only make cardano-cli accept the device key).
* Atomicity and sealing remarks of 21a apply.

## Open questions

* Whether cardano-cli overwrites an existing `.cc-hot.skey` that the replace branch left in place. If it refuses, `cli` and `mnemonics` replacement fails after the old files were deleted. A real run settles it.
