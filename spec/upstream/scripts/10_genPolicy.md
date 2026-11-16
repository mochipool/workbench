+++
id = "10"
kind = "script"
title = "Generate a minting policy (keys, script, policy id)"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["native-assets", "key-custody"]
use_cases = ["GeneratePolicy"]
depends_on = ["Cui", "Ckey", "Chw", "Cchain", "Pfiles"]

upstream_path = "cardano/mainnet/10_genPolicy.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "c419a6ba2b60619d09fde60b6709ea9d60550048c358ab3773565d2ba7a1b8bd"
upstream_lines = 219
uses_common = [
  "ask",
  "ask_pass",
  "checkError",
  "encrypt_skeyJSON",
  "file_lock",
  "file_unlock",
  "get_currentTip",
  "is_strong_password",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
]
cli_commands = [
  "address key-gen",
  "address key-hash",
  "transaction policyid",
]
hwcli_commands = [
  "address key-gen",
  "transaction policyid",
]
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 10_genPolicy: Generate a minting policy (keys, script, policy id)

Creates a native-asset minting policy: a payment-type key pair (the *policy key*), a native script that requires that key's signature and optionally a *time lock* (the policy becomes invalid after a slot), and the policy id (the script hash). The key lives as a plain cardano-cli key (`cli`), as a password-encrypted key (`enc`) or on a hardware wallet (`hw`). The policy is later consumed by [11a](./11a_mintAsset.md) and [11b](./11b_burnAsset.md), which sign with the policy key and use the script, and by [12a](./12a_genAssetMeta.md), which reads the policy id and key.

## Interface

- **SPO-10-IF-001** Takes a policy name and a key type of `cli`, `enc` or `hw` (case-insensitive), and an optional third argument: the policy lifetime in slots. The policy name may carry a directory part (for example `assets/mypolicy`). (src: L21, L38-L39)
- **SPO-10-IF-002** Prints usage to stderr and exits 1 when fewer than two arguments are given or the key type is not one of `cli`, `enc`, `hw`. (src: L21-L36)
- **SPO-10-IF-003** A lifetime is honoured only when exactly three arguments are given and the third is greater than zero; the policy then expires at `current slot + lifetime`. With no third argument, or a value of zero or below, the policy is unlimited. Arguments beyond the third make the policy unlimited silently. (src: L40)
  > **Upstream quirk:** a non-numeric third argument is an arithmetic error in the shell test, not a usage error. A port validates the argument as a non-negative integer and refuses otherwise.
- **SPO-10-INV-001** The lifetime is measured in slots, which are seconds on all current networks, and starts at the moment the script runs, not at the first mint. (src: L40, L181)

## Inputs

- **SPO-10-IN-001** The current slot, obtained as `get_currentTip` does in the active work mode (see SPO-Cchain-*; offline computes it from the genesis files and the wall clock). It is read twice: before anything is created, to compute the expiry slot, and again after the keys exist, to display the "current slot". Only the first read influences the script; a failure of the second one ends the script (exit 1) after all key material exists. (src: L40, L181-L183)
- **SPO-10-IN-002** The work mode, the era for `cardano-cli`, and for `hw` the hardware wallet (see `Chw`). The script never queries UTxOs or protocol parameters and submits nothing. (src: L17, L67, L82, L157)

## Behaviour

1. **Compute the expiry slot.**
   - **SPO-10-INV-002** The expiry slot is `tip + lifetime` as in SPO-10-IF-003, computed before the existence checks of step 2. The tip is read inside a command substitution, so a failure there (SPO-Cchain-MODE-006, SPO-Cchain-MODE-007) ends only the substitution (see SPO-Cui-INV-001): the script goes on and the expiry becomes the bare lifetime as a slot number. (src: L40)
   > **Upstream quirk:** with a lifetime and a failing tip query the policy expires at an early slot (for example slot 600), which makes it unusable for minting. A port aborts on a failed tip read before creating anything.
2. **Refuse to overwrite.**
   - **SPO-10-PRE-001** Exits 2 when any of `<policy>.policy.vkey`, `<policy>.policy.skey`, `<policy>.policy.hwsfile`, `<policy>.policy.script` or `<policy>.policy.id` already exists. The checks are in the order vkey, skey/hwsfile, script, id; nothing is written before all five pass. (src: L55-L58)
3. **Create the destination directory.**
   - **SPO-10-OUT-001** Creates the directory part of the policy name, with parents, when it does not exist. A failure ends the script through the generic error handler (see SPO-Cui-INV-001). (src: L61-L62)
4. **Generate the policy key (by key type).**
   - **SPO-10-EXT-001** `cli` and `enc` generate a key pair with `cardano-cli <era> address key-gen`, producing a payment-type key (not a dedicated policy key type). (src: L67, L82)
   - **SPO-10-OUT-002** `cli`: the verification key and the plaintext signing key are written by cardano-cli to `<policy>.policy.vkey` and `.policy.skey`, then both are locked (`0400`). A cardano-cli failure ends the script with its exit code. (src: L67-L70)
   - **SPO-10-INV-003** `enc`: the plaintext signing key is never written to disk. cardano-cli writes it to stdout, which is captured in memory with stderr discarded; only the verification key file is written, then locked. (src: L82-L84)
   - **SPO-10-PR-001** `enc`: asks for a password, then a confirmation, and repeats both until they match. Each entry must satisfy the strong-password rule (SPO-Ckey-INV-001); a weak entry is asked again. (src: L94-L119)
   - **SPO-10-PRE-002** `enc`: an empty first password or an empty confirmation aborts with exit 1 and deletes the already-written `.vkey`. (Unlike [04c](./04c_genKESKeys.md), the confirmation abort also removes it.) (src: L99, L103, L109, L113)
   - **SPO-10-PR-002** `enc`: after a matching pair, asks whether to show the password on screen for 5 seconds (default No). (src: L127)
   - **SPO-10-OUT-003** `enc`: the signing key is written as the encrypted envelope produced by `encrypt_skeyJSON` (SPO-Ckey-OUT-001) and locked. An encryption failure exits 1 without a `.skey`; a write failure exits 1. (src: L132, L137-L142)
   - **SPO-10-PRE-003** `enc`: an interrupt (SIGINT) after the verification key exists, until the signing key is written, deletes `.policy.vkey` and `.policy.skey` and exits 1. (src: L44-L51, L90, L144)
   - **SPO-10-EXT-002** `hw`: starts the hardware session (see `Chw`), then runs `cardano-hw-cli address key-gen --path 1855H/1815H/0H` producing `<policy>.policy.vkey` and `<policy>.policy.hwsfile`. Output matching `ERROR` or `DISCONNECT` (case-insensitive) exits 1. The path is CIP-1855 (forging policy keys) with policy index 0, so every hardware policy of one wallet derives from the same key. (src: L155-L159)
   > **Upstream quirk:** every `hw` policy created from one device uses the account-0 key, so two hardware policies share one key hash and differ only by their time lock.
   - **SPO-10-OUT-004** `hw`: the verification key's `description` is rewritten to `Mint Hardware Verification Key`, which marks it as hardware-backed (see SPO-Pfiles-INV-001); then `.policy.vkey` and `.policy.hwsfile` are locked. (src: L162-L165)
5. **Derive the key hash.**
   - **SPO-10-EXT-003** The key hash is `cardano-cli <era> address key-hash --payment-verification-key-file <policy>.policy.vkey`. A failure ends the script with its exit code, after the key files already exist. (src: L177-L178)
6. **Write the policy script.**
   - **SPO-10-OUT-005** Unlimited policy: `<policy>.policy.script` is `{ "keyHash": "<hash>", "type": "sig" }`. Time-locked policy: `{ "type": "all", "scripts": [ { "slot": <expiry>, "type": "before" }, { "keyHash": "<hash>", "type": "sig" } ] }`. The file is written on one line and then locked. (src: L187-L193)
   - **SPO-10-INV-004** The `before` slot is exclusive: a transaction minting or burning under this policy must have its validity end (`--invalid-hereafter`) at or before it. [11a](./11a_mintAsset.md) and [11b](./11b_burnAsset.md) take that slot as their TTL (see SPO-Ptx-INV-001). (src: L190)
7. **Derive and record the policy id.**
   - **SPO-10-EXT-004** `cli` and `enc`: the policy id is `cardano-cli <era> transaction policyid --script-file <policy>.policy.script`. (src: L197-L199)
   - **SPO-10-EXT-005** `hw`: the policy id is the output of `cardano-hw-cli transaction policyid --script-file <script> --hw-signing-file <hwsfile>`, after starting the hardware session; the device displays the expiry slot. Output matching `ERROR` or `DISCONNECT` exits 1. Both paths yield the same hash for the same script. (src: L201-L208)
   - **SPO-10-OUT-006** `<policy>.policy.id` holds the policy id and a trailing newline; it is then locked. (src: L212-L215)

## Work modes

- **SPO-10-MODE-001** The script talks to the chain only to learn the slot (SPO-10-IN-001). In `online` mode that needs a working node socket; in `light` mode Koios; in `offline` mode it needs the Byron and Shelley genesis files and a correct clock, and no transfer file or network (SPO-Cchain-MODE-008). The generated artefacts are mode-independent. (src: L40, L181)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Password, `enc` only (SPO-10-PR-001) | none; empty aborts | Encrypts the policy key |
| Confirm password (SPO-10-PR-001) | none; empty aborts | Must match |
| Show password for 5 seconds (SPO-10-PR-002) | No | Display only |

No confirmation is asked for `cli` and `hw` beyond the device's own prompts.

## Outputs

**Upstream file contract** (`<policy>` is the policy name with its directory part):

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<policy>.policy.vkey` | text envelope, payment verification key; `Mint Hardware Verification Key` description for `hw` | `0400` | created |
| `<policy>.policy.skey` | `cli`: plaintext text envelope; `enc`: encrypted envelope; absent for `hw` | `0400` | created |
| `<policy>.policy.hwsfile` | hardware signing file; only for `hw` | `0400` | created |
| `<policy>.policy.script` | native script JSON (SPO-10-OUT-005) | `0400` | created |
| `<policy>.policy.id` | policy id hex plus newline | `0400` | created |

- **SPO-10-INV-005** The artefacts are created in the order verification key, signing key (or hwsfile), script, id. A failure part-way leaves the earlier ones in place, and a rerun is then refused by SPO-10-PRE-001; only the `enc` SIGINT path (SPO-10-PRE-003) and the `enc` password aborts (SPO-10-PRE-002) clean up. (src: L55-L58, L67-L70, L177-L215)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Bad arguments | 1 | SPO-10-IF-002 |
| Any policy artefact already exists | 2 | SPO-10-PRE-001 |
| cardano-cli failure (key-gen, key-hash) | cardano-cli's code | SPO-10-OUT-002, SPO-10-EXT-003 |
| Empty password or confirmation (`enc`) | 1 | SPO-10-PRE-002 |
| Encryption or write failure (`enc`) | 1 | SPO-10-OUT-003 |
| SIGINT during `enc` | 1 | SPO-10-PRE-003 |
| Hardware error or disconnect | 1 | SPO-10-EXT-002, SPO-10-EXT-005 |

## Security

- **SPO-10-SEC-001** With `cli`, prints the **plaintext policy signing key** to stdout after creating it. A caller must never capture, log or tee the output. With `enc` and `hw` it prints the encrypted envelope and the hardware signing file respectively; neither is a usable secret on its own. (src: L75-L76, L146-L147, L170-L171)
- **SPO-10-SEC-002** With `enc`, prints the chosen password in clear for 5 seconds if the operator accepts SPO-10-PR-002. (src: L127)
- **SPO-10-SEC-003** The policy key authorises all future minting and burning under the policy id. Losing an unlimited policy's key forfeits the ability to burn; a leaked key lets anyone mint, for an unlimited policy, forever. A time lock (SPO-10-IF-003) is the only protection that does not depend on key custody. (src: L187-L191)

## Domain mapping

Use case `GeneratePolicy(name, keyProtection, lifetimeSlots?)` on aggregate `MintingPolicy` (key hash, script, policy id, expiry slot).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `exists(PolicyArtefact)` | Overwrite check (SPO-10-PRE-001) |
| `KeyGen` | `generate(policyKey)` | cardano-cli payment key, or hardware key at `1855H/1815H/0H` |
| `Vault` | `seal(policySigningKey, policy)` | `cli` = no protection, `enc` = passphrase, `hw` = reference only |
| `Ledger` | `keyHash(vkey)`, `policyId(script)` | Hash and id *(new: `keyHash`, `policyId`)* |
| `Ledger` | `makeNativeScript(sig, before?)` | The script of SPO-10-OUT-005 *(new)* |
| `ChainQuery` | `tip()` | Expiry slot |
| `Signer` | `policyId` via hardware | `hw` id display *(new)* |
| `Store` | `put(PolicyVkey, PolicyScript, PolicyId)`, `lock` | Public artefacts |
| `UI` | `askPassword`, `confirm` | `enc` only |

## Port notes

* Seal by default; offer a plaintext export only through `Vault.exportPlaintext`.
* Make creation atomic (all five artefacts or none); upstream leaves a half-written policy that blocks the name (SPO-10-INV-005).
* Compute the expiry before any side effect, abort when the tip read fails, and accept an absolute slot or timestamp as well as a lifetime.
* Use a per-policy hardware derivation index instead of the fixed `0H` (SPO-10-EXT-002), or record clearly that policies share a key.
* A remote or multi-party signer would hold the policy key; the script only needs the key hash, so a port can create a policy from a supplied key hash without ever seeing a key.

## Open questions

* None blocking. The exact text-envelope type of the generated key (`PaymentVerificationKeyShelley_ed25519`) depends on the pinned cardano-cli.
