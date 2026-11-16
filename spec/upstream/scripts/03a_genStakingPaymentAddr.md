+++
id = "03a"
kind = "script"
title = "Generate a wallet: payment and staking keys and addresses"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "key-custody", "stake-delegation"]
use_cases = ["GenerateWalletAccount"]
depends_on = ["Cconf", "Cui", "Ckey", "Chw", "Pfiles", "Pparam"]

upstream_path = "cardano/mainnet/03a_genStakingPaymentAddr.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "d5022c70f02ce9ee4432339f0efec65f61faacc4f40437dbf9b6559c5f3e82dd"
upstream_lines = 494
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
  "address build",
  "address key-gen",
  "key non-extended-key",
  "stake-address build",
  "stake-address key-gen",
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

# 03a_genStakingPaymentAddr: Generate a wallet (payment and staking keys, base address, stake address)

Creates one wallet account: a payment key pair, a staking key pair, the base payment address (payment plus staking credential) and the stake (reward) address. The keys come from one of nine *key types* that decide where the secret lives: a plain `cardano-cli` key file, a password-encrypted key file, a hardware wallet (normal or multi-sig derivation root), a hybrid (hardware payment key, `cardano-cli` staking key, optionally encrypted), or a mnemonic-derived key made by `cardano-signer`. The registration of the stake address is a separate step ([03b](./03b_regStakingAddrCert.md)). The script never touches the chain.

## Interface

- **SPO-03a-IF-001** Takes a wallet name and a key type as the first two positional words. The key type is matched case-insensitively against `cli`, `enc`, `hw`, `hwmulti`, `hybrid`, `hybridmulti`, `hybridenc`, `hybridmultienc`, `mnemonics`. (src: L21, L58-L59)
- **SPO-03a-IF-002** Prints usage to stderr and exits 1 when fewer than two words are given or the key type is not in that list. (src: L21-L54)
- **SPO-03a-IF-003** The wallet name loses a trailing `.addr` and a leading `./`; no other extension is stripped, so `owner.payment` yields files named `owner.payment.payment.*`. All artefacts are named `<name>.payment.*` and `<name>.staking.*` (SPO-Pfiles-IN-003). (src: L58)
- **SPO-03a-IF-004** Words from the third position on are the optional parameters `acc:<n>`, `idx:<n>` and `mnemonics:<24 words>`, with the validation of SPO-Pparam-IF-027 and SPO-Pparam-IF-028 (exit 1 when out of range or not 24 words). They are validated for every key type, including the key types that ignore them. Any other word is silently ignored. Defaults: account 0, index 0, no mnemonics. (src: L61-L92)
- **SPO-03a-IF-005** The key type fixes the form of each key as follows (`root` is `1854` when the type name contains `MULTI`, else `1852`): (src: L121-L128, L135, L151, L217, L288, L321, L338, L373, L445)

  | Key type | Payment key | Staking key | Secret protection |
  | --- | --- | --- | --- |
  | `cli` | `cardano-cli` key pair | `cardano-cli` key pair | plaintext `.skey`, locked |
  | `enc` | `cardano-cli` key pair | `cardano-cli` key pair | each `.skey` encrypted with its own password |
  | `hw`, `hwmulti` | hardware, root 1852 / 1854 | hardware, same root | `.hwsfile`, no secret on the host |
  | `hybrid`, `hybridmulti` | hardware, root 1852 / 1854 | `cardano-cli` key pair | staking `.skey` plaintext |
  | `hybridenc`, `hybridmultienc` | hardware, root 1852 / 1854 | `cardano-cli` key pair | staking `.skey` encrypted |
  | `mnemonics` | `cardano-signer` derivation, root 1852 | `cardano-signer` derivation, same words | plaintext extended `.skey` plus `.mnemonics` file |


## Inputs

- **SPO-03a-IN-001** Reads configuration `cardanocli`, `cliEra`, `addrformat` (address network flag), `cardanohwcli` (hardware types), `cardanosigner` and the pinned minimum cardano-signer version (`mnemonics` only). No chain state, transfer file or work mode is read. (src: L138, L160-L170, L473)

## Behaviour

1. **Refuse to overwrite.**
   - **SPO-03a-PRE-001** Exits 2, before anything is generated, when any of `<name>.payment.vkey`, `.payment.skey`, `.payment.hwsfile`, `.payment.addr`, `.staking.vkey`, `.staking.skey`, `.staking.hwsfile`, `.staking.addr` or `.staking.cert` exists. The `.staking.cert` check protects the certificate that 03b writes. (src: L113-L119)
   - **SPO-03a-PRE-002** With key type `mnemonics`, exits 1 when `<name>.payment.mnemonics` already exists. This check comes after SPO-03a-PRE-001 and before any key is made. (src: L154)
2. **Check the signer tool (`mnemonics` only).**
   - **SPO-03a-PRE-003** Locates `cardano-signer` at the `cardanosigner` setting, falling back to `<scriptDir>/cardano-signer`. Exits 1 when it is not found, when `--version` fails, or when its version is below the pinned minimum (SPO-Cconf-INV-008). (src: L160-L172)
3. **Build the payment key.**
   - **SPO-03a-EXT-001** `cli`: `cardano-cli <era> address key-gen --verification-key-file <name>.payment.vkey --signing-key-file <name>.payment.skey`. `enc`: the same command with the signing key written to `/dev/stdout` (stderr discarded) and captured in memory. A non-zero exit ends the script with that code (SPO-Cui-INV-001). (src: L138-L139, L220-L221)
   - **SPO-03a-EXT-002** Hardware types: starts the hardware session (SPO-Chw-PRE-001 .. SPO-Chw-PRE-005), then runs `cardano-hw-cli address key-gen --path <root>H/1815H/<acc>H/0/<idx> --verification-key-file <name>.payment.vkey --hw-signing-file <name>.payment.hwsfile`. Output containing `ERROR` or `DISCONNECT` (case-insensitive) exits 1. (src: L290, L294-L297)
   - **SPO-03a-EXT-003** `mnemonics`: runs `cardano-signer keygen --path <root>H/1815H/<acc>H/0/<idx> --with-chain-code --json-extended --out-skey <name>.payment.skey`, with `--mnemonics "<words>"` when words were given. stderr is merged into the captured JSON; a non-zero exit prints it and exits 1. Without given words the result's `.mnemonics` is the newly generated 24 words. (src: L174-L187)
   - **SPO-03a-INV-001** The derivation path is `<root>H/1815H/<acc>H/0/<idx>` for the payment key. The staking path is `<root>H/1815H/<acc>H/2/0` for hardware types (the index is not used), and `<root>H/1815H/<acc>H/2/<idx>` for `mnemonics`. (src: L157, L177, L181, L290, L295, L349, L452)

     > **Upstream quirk:** The `mnemonics` banner prints the staking path as `.../2/0` while the command uses the index (L340 against L349). The key is the one in L349.
   - **SPO-03a-OUT-001** Hardware types rewrite the `description` of the imported verification key to `Payment Hardware Verification Key` (and `Stake Hardware Verification Key` for staking). This is the hardware marker of SPO-Pfiles-INV-001. (src: L299-L301, L456-L458)
   - **SPO-03a-OUT-002** `mnemonics` writes the payment verification key from the signer's `.output.vkey`, converted to a non-extended key with `cardano-cli <era> key non-extended-key`, with description `Payment Verification Key` (`Stake Verification Key` for staking). The signing key stays the extended key written by the signer. (src: L196-L202, L352-L358)
   - **SPO-03a-OUT-003** `mnemonics` writes the 24 words, one line, to `<name>.payment.mnemonics`; a write failure exits 1. The staking key is derived from the same words (SPO-03a-INV-001); no `.staking.mnemonics` is written. (src: L188-L193, L343-L349)
4. **Build the staking key.**
   - **SPO-03a-EXT-004** `cli`, `hybrid`, `hybridmulti`: `cardano-cli <era> stake-address key-gen --verification-key-file <name>.staking.vkey --signing-key-file <name>.staking.skey`. `enc`, `hybridenc`, `hybridmultienc`: the same with the signing key on `/dev/stdout`, captured. `hw`, `hwmulti`: `cardano-hw-cli address key-gen` as in SPO-03a-EXT-002 with path `<root>H/1815H/<acc>H/2/0` and `--hw-signing-file <name>.staking.hwsfile`. `mnemonics`: `cardano-signer keygen` as in SPO-03a-EXT-003 with the stake path and the payment step's words. (src: L324-L325, L376-L377, L451-L454, L349-L350)
5. **Protect each encrypted key (`enc`, `hybridenc`, `hybridmultienc`).**
   - **SPO-03a-INV-002** An encrypted signing key is never written in plaintext: it is held in memory from the cardano-cli stdout capture until the encrypted envelope (SPO-Ckey-OUT-001) is written to `<name>.<role>.skey` and locked. (src: L220, L269-L279, L376, L425-L435)
   - **SPO-03a-PR-001** For each encrypted key separately (payment first, then staking where applicable) asks for a password and a confirmation, repeating until they match. Each must satisfy the strong-password rule (SPO-Ckey-INV-001); a weak entry is asked again. (src: L230-L257, L386-L413)
   - **SPO-03a-PRE-004** An empty password or empty confirmation aborts with exit 1 and deletes the `.vkey` of the key being protected. Earlier artefacts (for the staking stage, the finished payment key files) are kept. (src: L237, L241, L247, L251, L393, L397, L403, L407)
   - **SPO-03a-PR-002** After a matching pair asks whether to show the password on screen for 5 seconds; the default is No. (src: L265, L421)
   - **SPO-03a-PRE-005** SIGINT during an encrypted stage runs a cleanup that exits 1 after deleting `<name>.payment.vkey`, `<name>.staking.vkey` and `<name>.staking.skey`. It does not delete `<name>.payment.skey`. (src: L97-L109, L228, L282, L384, L438)

     > **Upstream quirk:** The cleanup intends to delete `.payment.skey` but repeats `rm -f .payment.vkey` (L103). A Ctrl-C during the staking password stage leaves the finished encrypted `.payment.skey` behind with no matching `.vkey`.
6. **Build the addresses.**
   - **SPO-03a-EXT-005** `cardano-cli <era> address build --payment-verification-key-file <name>.payment.vkey --staking-verification-key-file <name>.staking.vkey <addrformat>` writes `<name>.payment.addr` (a base address); `cardano-cli <era> stake-address build --staking-verification-key-file <name>.staking.vkey <addrformat>` writes `<name>.staking.addr`. A non-zero exit ends the script with that code. (src: L473-L475, L483-L485)
   - **SPO-03a-OUT-004** Every artefact the script creates (`.vkey`, `.skey`, `.hwsfile`, `.mnemonics`, `.addr`) is locked to mode `0400` as soon as it is complete (SPO-Pfiles-INV-003). (src: L140-L141, L205-L207, L222, L279, L303-L304, L326-L327, L361-L362, L378, L435, L460-L461, L475, L485)

## Work modes

Mode-independent: no chain access, no transfer file. The configuration prologue still runs (SPO-Cconf-INV-001).

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password for the payment or staking key, encrypted types only (SPO-03a-PR-001) | none; empty aborts | Encrypts that `.skey` |
| Confirm password (SPO-03a-PR-001) | none; empty aborts | Must match |
| Show password for 5 seconds (SPO-03a-PR-002) | No | Display only |

Hardware types also need the operator to approve the key export on the device; that is the device's own prompt, not a script prompt.

## Outputs

Upstream file contract (`<name>` per SPO-03a-IF-003; all mode `0400`):

| File | Content | Types | Change |
| --- | --- | --- | --- |
| `<name>.payment.vkey` | verification key envelope; description `... Hardware ...` for hardware types | all | created |
| `<name>.payment.skey` | plaintext envelope (`cli`, `mnemonics` extended key) or encrypted envelope (`enc`) | `cli`, `enc`, `mnemonics` | created |
| `<name>.payment.hwsfile` | hardware signing file (SPO-Pfiles-OUT-004) | `hw*`, `hybrid*` | created |
| `<name>.payment.mnemonics` | 24 words, one line | `mnemonics` | created |
| `<name>.staking.vkey` | stake verification key envelope | all | created |
| `<name>.staking.skey` | plaintext or encrypted envelope | `cli`, `enc`, `hybrid*`, `mnemonics` | created |
| `<name>.staking.hwsfile` | hardware signing file | `hw`, `hwmulti` | created |
| `<name>.payment.addr` | base address, one line | all | created |
| `<name>.staking.addr` | stake address, one line | all | created |

See SPO-Pfiles-OUT-001 .. SPO-Pfiles-OUT-005 for the shared catalogue entries.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two words or unknown key type | 1 | SPO-03a-IF-002 |
| `acc:`/`idx:` out of range, not 24 mnemonic words | 1 | SPO-03a-IF-004 |
| Any target artefact exists | 2 | SPO-03a-PRE-001 |
| `.payment.mnemonics` exists | 1 | SPO-03a-PRE-002 |
| cardano-signer missing or too old | 1 | SPO-03a-PRE-003 |
| cardano-cli failure | cardano-cli's code | SPO-03a-EXT-001, SPO-03a-EXT-004, SPO-03a-EXT-005 |
| Hardware error or disconnect, device checks | 1 | SPO-03a-EXT-002, SPO-Chw-INV-002 |
| cardano-signer failure, `.mnemonics` write failure | 1 | SPO-03a-EXT-003, SPO-03a-OUT-003 |
| Empty password or confirmation | 1 | SPO-03a-PRE-004 |
| Encryption or key file write failure | 1 | SPO-03a-INV-002 |
| SIGINT during an encrypted stage | 1 | SPO-03a-PRE-005 |

## Security

- **SPO-03a-SEC-001** For `cli`, `hybrid`, `hybridmulti` and `mnemonics` the script prints the plaintext signing key file (payment and/or staking) to stdout after creating it. A caller must never capture, log or tee the output. (src: L145-L146, L211-L212, L332-L333, L367-L368)
- **SPO-03a-SEC-002** For `mnemonics` the 24 words are printed in clear to stdout (given or generated) in addition to the `.mnemonics` file; given words are also passed on the `cardano-signer` command line, visible in the process list. (src: L175, L177, L181, L185, L349)
- **SPO-03a-SEC-003** The `.mnemonics` file is created with the default file mode of the process and is only locked to `0400` after the verification key has been written, so for a moment (and permanently if the script dies in between) it is group/world readable according to the umask. The signer's own `.skey` has the signer's mode until the same lock. (src: L188, L196-L207)
- **SPO-03a-SEC-004** With the optional password display the chosen password is printed in clear for 5 seconds. For encrypted keys the encrypted envelope is printed to stdout. The password reaches gpg on its command line (SPO-Ckey-SEC-001). (src: L265, L284-L285, L421, L440-L441)
- **SPO-03a-SEC-005** Hardware verification keys and signing files are printed; they identify the device account but hold no private key. (src: L307-L310, L464-L467)

## Domain mapping

Use case `GenerateWalletAccount(name, keyType, account?, index?, mnemonics?)` on aggregate `Wallet` (a `PaymentAccount` plus its `StakeAccount` credentials).

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(payment)`, `generate(stake)` | cli key types |
| `KeyGen` | `deriveFromMnemonics(path, words?)` *(new)* | `cardano-signer keygen`; returns extended key, non-extended vkey and the words |
| `KeyGen` | `exportHardwareKey(path)` *(new)* | `cardano-hw-cli address key-gen`: vkey plus hardware signing reference |
| `Signer` | `openHardwareSession(allowedVendors?, minVersions?)` *(new)* | hardware types (see Chw) |
| `Vault` | `seal(signingKey, policy)` | `cli` = no protection, `enc` = passphrase |
| `Ledger` | `buildAddress(credentials)` | base and stake address |
| `Store` | `exists`, `put(vkey)`, `put(address)`, `put(hwsfile)`, `lock` | Artefacts per SPO-Pfiles |
| `UI` | `askPassword`, `confirm` | encrypted types |

## Port notes

* Seal by default and never print signing keys or mnemonics to a stream the caller may log; offer an explicit reveal for the mnemonics once, at creation.
* Make generation atomic: either all of the wallet's artefacts exist or none do. SPO-03a-PRE-004 and SPO-03a-PRE-005 leave partial wallets, and the staking stage can leave an orphan `.payment.skey`.
* Hybrid wallets mix a hardware payment key with a software stake key, which lets 03b, 06, 08b and 22b refuse them (SPO-Ptx-PRE-006); the port should model signer per credential so that combination is usable or rejected up front.
* Derive the staking key from the same account/index for hardware types as for mnemonics if parity with `idx:` is not required; upstream fixes the hardware staking index at 0.
* Mnemonics should be written once into the sealed store, not to a plaintext file, and never passed on a command line.

## Open questions

* The exact envelope `type` strings written by cardano-cli, cardano-hw-cli and cardano-signer for these keys are not asserted by the script; an inventory run settles them (see Pfiles open questions).
* Whether `cardano-hw-cli address key-gen` reports a rejected device prompt with the words `ERROR` or `DISCONNECT`; the script only matches those two (SPO-03a-EXT-002).
