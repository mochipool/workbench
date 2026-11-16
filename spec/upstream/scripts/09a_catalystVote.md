+++
id = "09a"
kind = "script"
title = "Catalyst voting keys and CIP-36 registration"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["community", "key-custody"]
use_cases = ["GenerateVotingKey", "BuildCatalystRegistration", "ExportVotingKeyQr", "QueryCatalystVotingPower"]
depends_on = ["Cconf","Caddr","Chw","Ckey","Cchain","Pfiles"]

upstream_path = "cardano/mainnet/09a_catalystVote.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "8796e9d0c061982ea91e58d2a9644a88aa5f64c33efbb6a96df9a158c5ee59b9"
upstream_lines = 614
uses_common = [
  "checkAdaHandleFormat",
  "checkError",
  "convertToADA",
  "exists",
  "file_lock",
  "get_addressType",
  "get_currentTip",
  "majorError",
  "read_skeyFILE",
  "resolveAdahandle",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
  "trimString",
  "versionCheck",
]
cli_commands = []
hwcli_commands = [
  "address key-gen",
  "vote registration-metadata",
]
signer_commands = [
  "keygen",
  "sign",
]
http_endpoints = [
  "catalystAPI",
  "catalystAPI/registration/delegations/0x",
  "catalystAPI/registration/voter/0x",
]
env_vars = []
+++

# 09a_catalystVote: Project Catalyst voting keys and CIP-36 registration

A four-subcommand tool for Project Catalyst voting (CIP-36): `new` creates a voting key pair (from a fresh or given 24-word mnemonic, or on a hardware wallet), `genmeta` builds the signed registration metadata (CBOR) that delegates a stake key's voting power to one or more voting keys and names a rewards address, `qrcode` renders a voting key as the PIN-protected QR code of the Catalyst mobile app, and `query` asks the Catalyst API for a voting key's power and delegators. None of the subcommands builds or submits a transaction: the registration takes effect only when the `.cbor` file produced by `genmeta` is attached to a transaction, for example with `01_sendLovelaces.sh <wallet> <wallet> min <file>.cbor` ([01_sendLovelaces](../patterns/Ptx.md), SPO-Pparam-IF-015).

The signing work is done by external tools: `cardano-signer` (key generation and signing for key-file stake keys), `cardano-hw-cli` (hardware stake keys and hardware voting keys), `catalyst-toolbox` (QR code) and the `bech32` binary (key format conversion).

## Interface

- **SPO-09a-IF-001** The first argument selects the subcommand, case-insensitively: `new`, `genmeta`, `qrcode` or `query`. Any other value, or none, prints usage to stderr and exits 1. (src: L69, L611-L612)
- **SPO-09a-IF-002** `new <cli|hw> <voteKeyName> [<24 words>]`: at least three arguments, else usage and exit 1. The method is `cli` or `hw` (case-insensitive); anything else exits 1. A leading `./` of the name is dropped. The optional fourth argument (mnemonic words) applies to `cli` only. (src: L127-L133, L146, L249-L250)
- **SPO-09a-IF-003** `genmeta <delegation> <stakeAccount> <rewardsAddress>`: exactly four arguments in total, else usage and exit 1. `<delegation>` is one voting key or several joined with `|`, each optionally followed by a space and a positive integer weight (for example `"myvote 3|other 1"`); a missing weight is 1. The weights are relative to each other. (src: L260-L263, L309-L322)
- **SPO-09a-IF-004** `qrcode <voteKeyName> <pin>`: at least three arguments in total, else usage and exit 1. (src: L72-L74, L88-L89)
- **SPO-09a-IF-005** `query <voteKey>`: exactly two arguments in total, else usage and exit 1; the check happens after the offline and API-availability checks of SPO-09a-PRE-011 and SPO-09a-PRE-012. (src: L450-L469)
- **SPO-09a-IF-006** A *voting key reference* (used by `genmeta` and `query`) is resolved in this order, first match wins: (1) `<ref>.voting.pkey` exists and holds a valid bech32 string, which is converted to the `cvote_vk` form; (2) `<ref>.voting.vkey` exists, its `cborHex` minus the first four characters is taken and cut to its first 64 hex characters (the public key, also for an extended key); (3) the reference is 64 or 128 hex characters: the first 64 are used; (4) the reference is a valid bech32 string, converted to `cvote_vk`. Otherwise exit 1. The resulting key is always in `cvote_vk` bech32 form. (src: L324-L357, L471-L504)
  > **Upstream quirk:** a `.pkey` and a `.vkey` for the same name are not cross-checked; the `.pkey` wins. A hardware voting key has no `.pkey` (SPO-09a-OUT-009), so it is read from its `.vkey`.

## Inputs

- **SPO-09a-IN-001** Tool paths come from the settings `cardanosigner`, `cardanohwcli`, `catalyst_toolbox_bin` and `bech32_bin`; the minimum versions (cardano-signer 1.35.0, catalyst-toolbox 0.5.0) are pinned (SPO-Cconf-INV-008). For `cardano-signer` and `catalyst-toolbox` the script falls back to a binary of that name in the script directory, else exits 1 with the download location. The tool must answer `--version` and satisfy the minimum (SPO-Cconf-OUT-003), else exit 1. (src: L77-L86, L151-L160, L418-L427)
- **SPO-09a-IN-002** `genmeta` reads the stake account `<stake>.staking.skey` or `.hwsfile` (the name is taken with an optional `.addr` and `.staking` suffix removed), the rewards address, the voting keys, the work mode and network magic, and the current slot. (src: L266-L268, L368-L372)
- **SPO-09a-IN-003** `query` reads `catalystAPI` (the network's Catalyst API, empty for networks without one, SPO-Cconf-IN-005) and `magicparam`. (src: L453-L460, L563)

## Behaviour: `new cli`

1. **Refuse to overwrite.**
   - **SPO-09a-PRE-001** Exits 1 when `<name>.voting.vkey`, `<name>.voting.skey` or `<name>.voting.hwsfile` already exists, before any tool is invoked. (src: L135-L137)
2. **Validate the optional mnemonic.**
   - **SPO-09a-PRE-002** A mnemonic argument is lower-cased and trimmed and must contain exactly 24 words, else exit 1. The words are not checked against a word list by the script. (src: L164-L169)
3. **Generate.**
   - **SPO-09a-EXT-001** Runs `cardano-signer keygen --cip36 [--mnemonics "<words>"] --json-extended --out-skey <name>.voting.skey --out-vkey <name>.voting.vkey`. Without a given mnemonic the tool creates one and returns it in the JSON output's `mnemonics`; the output's `publicKeyBech` is the bech32 public key. A failure ends the script with the tool's code. The key pair is the CIP-36 voting key at derivation path `1694H/1815H/0H/0/0` (account, role and index are fixed at 0; the path is displayed). (src: L141, L171-L182, L197)
   - **SPO-09a-OUT-001** `<name>.voting.skey` (extended signing key, JSON) and `<name>.voting.vkey` are written by the tool and then locked. (src: L186-L194)
   - **SPO-09a-OUT-002** `<name>.voting.pkey` receives the bech32 `cvote_vk` public key and a newline, and is locked. (src: L197-L204)
   - **SPO-09a-OUT-003** `<name>.voting.mnemonics` receives the 24 words and a newline, in plaintext, and is locked. The mnemonic is the only backup of the key. (src: L207-L212)
   - **SPO-09a-SEC-001** The script prints the mnemonic words (given or created), the **plaintext signing key file**, the public keys and the mnemonics file to stdout, and passes a given mnemonic on the `cardano-signer` command line. A caller must never capture, log or tee the output. (src: L172, L181, L187-L189, L207-L212)
   - **SPO-09a-INV-001** The voting key is never encrypted by this script; `cli` produces plaintext only. (src: L174-L188)

## Behaviour: `new hw`

- **SPO-09a-EXT-002** Starts the hardware session requiring a Ledger Cardano app of at least 6.0.3 (the second argument of the session function, see SPO-Chw-IF-001), then runs `cardano-hw-cli address key-gen --path 1694H/1815H/0H/0/0 --verification-key-file <name>.voting.vkey --hw-signing-file <name>.voting.hwsfile`. Output matching `ERROR` or `DISCONNECT` (case-insensitive) exits 1. (src: L218-L224)
- **SPO-09a-OUT-004** The descriptions are rewritten to `Hardware Catalyst Vote Signing File` in the hwsfile and `Hardware Catalyst Vote Verification Key` in the vkey, and both files are locked. No `.pkey` and no mnemonics file are written. (src: L226-L235)

## Behaviour: `genmeta`

1. **Resolve the stake account.**
   - **SPO-09a-PRE-003** Exits 1 when neither `<stake>.staking.skey` nor `<stake>.staking.hwsfile` exists. (src: L266-L268)
2. **Choose the output name.**
   - **SPO-09a-OUT-005** The output file is `<stakeName>_<yymmddHHMMSS>.vote-registration.cbor` in the working directory, with the current local time. Exits 1 when it already exists. (src: L271-L273)
3. **Resolve the rewards address.**
   - **SPO-09a-IN-004** `<rewards>` is resolved in this order: an existing `<rewards>.addr` file (extension optional, SPO-Pfiles-IN-001), whose content must have address type `payment`; else an ADA Handle (SPO-Caddr-OUT-006), resolved through the handle API and required to resolve to a `payment` address (SPO-Caddr-PRE-009); else the argument itself, trimmed, as a bech32 payment address. A non-payment address, or an unresolvable value, exits 1. (src: L279-L304)
   - **SPO-09a-INV-002** An ADA Handle is resolved once, at generation: the registered rewards address stays fixed if the handle later moves. After a successful key-file registration the script says so. (src: L288-L295, L437)
4. **Resolve the voting keys and weights.**
   - **SPO-09a-PRE-004** Every weight must consist of digits only (zero is accepted by the script); otherwise exit 1. A missing weight is 1. (src: L313, L319-L322)
   - **SPO-09a-PRE-005** Each voting key reference is resolved as SPO-09a-IF-006, in the order given; a failure exits 1. For each, the key, its source and its weight are displayed. (src: L317-L359)
5. **Set the nonce.**
   - **SPO-09a-INV-003** The CIP-36 nonce is the current slot (`get_currentTip` in the active work mode; a failure exits 1 through the error handler). A later registration therefore supersedes an earlier one only if its slot is higher; a registration queued offline carries the slot of its creation, not of its submission. (src: L368-L372)
6. **Sign, by stake key type.**
   - **SPO-09a-EXT-003** *Key-file stake key.* Checks `cardano-signer` (SPO-09a-IN-001), then runs `cardano-signer sign --cip36 --vote-public-key <bech> --vote-weight <w> (repeated) --payment-address <addr> --nonce <slot> <network magic> --secret-key <stake>.skey --out-cbor <file>`. The stake key file is handed to the tool by path and must be an unencrypted cardano-cli key file. (src: L417-L431)
   > **Upstream quirk:** an encrypted `.staking.skey` is not decrypted (`read_skeyFILE` is not used), so the tool fails on it. A port decrypts in memory (SPO-Ptx-SEC-001).
   - **SPO-09a-PRE-006** A failing `cardano-signer sign` prints the tool's output and ends the script with the status of the animation-stop helper, which is **0**. (src: L430-L433)
   > **Upstream quirk:** a failed signing exits 0 with no file written; a caller sees success. A port exits non-zero.
   - **SPO-09a-PRE-007** After signing the script exits 1 when the output file does not exist. Otherwise it prints how to submit it. (src: L435-L441)
   - **SPO-09a-EXT-004** *Hardware stake key (`<stake>.staking.hwsfile`).* Starts the hardware session with the Ledger minimum 6.0.3 (SPO-Chw-IF-001) and runs `cardano-hw-cli vote registration-metadata --vote-public-key-string <bech> --vote-weight <w> (repeated) --payment-address <addr> --nonce <slot> <network magic> [--payment-address-signing-key-hwsfile <rewards.hwsfile>] --stake-signing-key-hwsfile <stake>.staking.hwsfile --metadata-cbor-out-file <file>`. Output matching `ERROR` or `DISCONNECT` exits 1; the output file must exist, else exit 1. (src: L376-L404)
   - **SPO-09a-INV-004** `--payment-address-signing-key-hwsfile` is passed only when `<rewards>.hwsfile` exists and the rewards account name equals the staking account name (with an optional `.payment` suffix removed): the rewards go to the same hardware wallet, which avoids the device's "unusual request" warning. (src: L379-L385)
   - **SPO-09a-INV-005** The choice between the two paths depends on the stake account only: a hardware stake key signs with the device whatever the voting keys are (they are public keys), and a key-file stake key signs with `cardano-signer`. (src: L376, L407)
7. **Outputs.**
   - **SPO-09a-OUT-006** The `.cbor` file is the CIP-36 registration metadata (label 61284 with the delegations, stake public key, payment address and nonce, and label 61285 with the witness signature). It is public, not locked, and not a transaction. (src: L431, L395)

## Behaviour: `qrcode`

1. **Preconditions.**
   - **SPO-09a-PRE-008** Checks `catalyst-toolbox` presence and version first (SPO-09a-IN-001), then exits 1 when `<name>.voting.skey` is missing (a hardware voting key has no signing key file and cannot be exported). (src: L76-L90)
   - **SPO-09a-PRE-009** The PIN must be digits only, at least four characters, and between 0 and 9999, else exit 1; in effect exactly four digits. (src: L91)
   - **SPO-09a-PRE-010** Exits 1 when `<name>.catalyst-qrcode.png` already exists. (src: L92)
2. **Render.**
   - **SPO-09a-EXT-005** The signing key is read with `read_skeyFILE` (an encrypted key asks for its password, see `Ckey`; failure exits 1), characters 5 to 132 of its `cborHex` (the 64-byte extended key) are converted with `bech32 ed25519e_sk`, and `catalyst-toolbox qr-code encode --pin <pin> --input <key as file> --output <name>.catalyst-qrcode.png img` writes the image. A tool failure ends the script with its code. (src: L100-L113)
   - **SPO-09a-OUT-007** The same tool is run a second time without `--output`, which shows the QR code in the terminal. `<name>.voting.skey` is locked afterwards. The PNG is not locked. (src: L114-L116)
   - **SPO-09a-SEC-002** The PIN is printed on the screen and passed on the `catalyst-toolbox` command line. The QR code contains the voting signing key encrypted with the PIN only: four digits give no protection against offline guessing, so the PNG and the terminal image are as sensitive as the key. (src: L96, L106, L112, L116)

## Behaviour: `query`

- **SPO-09a-PRE-011** Exits 1 in `offline` work mode. (src: L453-L455)
- **SPO-09a-PRE-012** Exits 1 when no Catalyst API is configured for the network. (src: L458-L460)
- **SPO-09a-EXT-006** Sends `GET <catalystAPI>/registration/voter/0x<public key hex>?with_delegators=true` (10 second timeout), where the hex key is the voting key reference's public key. A curl failure is retried, five attempts in total; after the last, exit 1. A response with an empty or null `voter_info` exits 1 at once ("no data yet"). (src: L511-L536)
- **SPO-09a-OUT-008** Displays the last update time, the `final` flag, the voting power (lovelace shown as ADA) and the delegator count of `voter_info`; for each delegator it derives the stake address from the delegator key and then asks `GET <catalystAPI>/registration/delegations/0x<delegator key>` (five attempts) for its `reward_address` and `raw_power`. A failure for one delegator shows "query error" for it and does not stop the script. Success exits 0. Display only. (src: L538-L607)
- **SPO-09a-INV-006** The stake address of a delegator is the bech32 of header byte `e1` (mainnet) or `e0` (any other magic) followed by the 28-byte BLAKE2b-224 hash of the delegator's 32-byte public key (`stake` or `stake_test` prefix). Mainnet is detected by the word `mainnet` in `magicparam`. (src: L560-L567)

## Work modes

- **SPO-09a-MODE-001** `new` and `qrcode` touch no chain data and are mode-independent. `genmeta` needs the current slot (SPO-09a-INV-003): node in `online`, Koios in `light`, genesis arithmetic in `offline`; an ADA Handle rewards address needs the handle API (`online` or `light`). `query` needs `online` or `light` and a Catalyst API (SPO-09a-PRE-011). (src: L368, L288-L295, L453)

## Prompts

None of this script's own, except the key password of an encrypted voting key in `qrcode` (SPO-09a-EXT-005); the hardware wallet asks on the device.

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<name>.voting.skey` | extended voting signing key (cli) | `0400` | created (`new cli`), locked again by `qrcode` |
| `<name>.voting.vkey` | verification key; hardware description for `hw` | `0400` | created |
| `<name>.voting.pkey` | bech32 `cvote_vk` public key; cli only | `0400` | created |
| `<name>.voting.mnemonics` | 24 words; cli only | `0400` | created |
| `<name>.voting.hwsfile` | hardware signing file; hw only | `0400` | created |
| `<stake>_<yymmddHHMMSS>.vote-registration.cbor` | CIP-36 registration metadata | default | created (`genmeta`) |
| `<name>.catalyst-qrcode.png` | QR code image | default | created (`qrcode`) |

- **SPO-09a-OUT-009** A hardware voting key is represented by `.voting.vkey` and `.voting.hwsfile` only; later `genmeta` and `query` calls therefore resolve it through the `.vkey` rule of SPO-09a-IF-006. (src: L222-L235, L332-L339)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Unknown subcommand, wrong argument count | 1 | SPO-09a-IF-001 .. SPO-09a-IF-005 |
| Voting key files exist (`new`) | 1 | SPO-09a-PRE-001 |
| Mnemonic not 24 words | 1 | SPO-09a-PRE-002 |
| Tool missing or too old | 1 | SPO-09a-IN-001 |
| Stake signing files missing | 1 | SPO-09a-PRE-003 |
| Output `.cbor` already exists | 1 | SPO-09a-OUT-005 |
| Bad weight, unresolvable key or rewards address | 1 | SPO-09a-PRE-004, SPO-09a-PRE-005, SPO-09a-IN-004 |
| `cardano-signer sign` fails | **0** | SPO-09a-PRE-006 |
| Hardware error or disconnect | 1 | SPO-09a-EXT-002, SPO-09a-EXT-004 |
| Output file missing after signing | 1 | SPO-09a-PRE-007 |
| `qrcode`: skey missing, bad PIN, PNG exists | 1 | SPO-09a-PRE-008 .. SPO-09a-PRE-010 |
| `query`: offline, no API, no data, API unreachable | 1 | SPO-09a-PRE-011, SPO-09a-PRE-012, SPO-09a-EXT-006 |

## Security

- **SPO-09a-SEC-003** `genmeta` handles the stake signing key (a key-file stake key is read by `cardano-signer` from its file path) and produces no secret output. The CIP-36 registration is a public on-chain statement of which keys vote with this stake and where rewards go. (src: L431)
- **SPO-09a-SEC-004** The voting key controls how the delegated stake votes, not the funds; its loss or leak is a governance risk, not a spending risk. Registering a voting key whose secret is unknown to the operator forfeits voting. (src: L174-L182)

## Domain mapping

Use cases: `GenerateVotingKey(name, method, mnemonic?)`, `BuildCatalystRegistration(delegations, stakeAccount, rewardsAddress)`, `ExportVotingKeyQr(name, pin)`, `QueryCatalystVotingPower(votingKey)`. Aggregate: `VotingKey` (the `community` or `governance` context), with the stake account and rewards address as references.

| Port | Operation | Purpose |
| --- | --- | --- |
| `KeyGen` | `generate(votingKey, mnemonic?)` | cardano-signer keygen or hardware key |
| `Store` | `put(VotingKeyFiles)`, `put(RegistrationMetadata)`, `lock` | Artefacts |
| `Vault` | `seal(votingSigningKey)`, `unseal` | Voting key (upstream plaintext) |
| `Signer` | `signMessage(cip36Payload, stakeKey)` | CIP-36 registration signature *(new: CIP-36 registration signing)* |
| `ChainQuery` | `tip()` | Nonce |
| `Ledger` | `addressInfo`, `bech32Convert(key, hrp)` *(new)* | Payment address type, key formats |
| `Directory` | `resolveHandle(handle)`, `catalystVoter(key)` *(new)*, `catalystDelegation(key)` *(new)* | Rewards handle, voting power |
| `UI` | `show(qr)` *(new)*, `askPassword` | QR code, key password |

## Port notes

* The CIP-36 registration (labels 61284 and 61285, nonce, delegations with weights) can be built and signed natively; the external tools are only adapters.
* Seal the voting key and the mnemonic by default, and never print them; show the mnemonic once at creation through an explicit reveal.
* Fix the exit 0 on a failed signing (SPO-09a-PRE-006), decrypt an encrypted stake key in memory (SPO-09a-EXT-003), and cross-check `.pkey` against `.vkey`.
* The nonce should be the slot at submission or a monotonic counter, not the creation slot; a remote or offline signer will hold the metadata for a long time (SPO-09a-INV-003).
* A remote or multi-party signer can sign the registration with the stake key while a different party holds the voting keys, since only voting public keys are inputs.
* QR code: use a stronger PIN or a passphrase, and never save the PNG next to the key without a warning.
* Make the account, role and index (`1694H/1815H/<acct>H/0/<idx>`) parameters instead of constants.

## Open questions

* The exact CBOR layout produced by `cardano-signer sign --cip36` and `cardano-hw-cli vote registration-metadata` (label 61284/61285 structure, stake address versus payment address fields) is the tools' behaviour. A test would decode a fixture and compare.
* Whether `cardano-signer keygen --cip36` uses the fixed path `1694H/1815H/0H/0/0` (the script only displays it) is the tool's behaviour.
* The `catalyst-toolbox qr-code encode` second invocation without `--output`: the tool's stdout format (terminal image) is assumed from the subcommand name `img`.
