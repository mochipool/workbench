+++
id = "08a"
kind = "script"
title = "Generate a stake address de-registration certificate"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation"]
use_cases = ["GenerateStakeDeregistrationCertificate"]
depends_on = ["Cconf", "Clight", "Caddr", "Cconv", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/08a_genStakingAddrRetireCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "8f65704170c286d2ff1bf3201b7e9b8d894804c82be6dbce1eedea6bc699cbcf"
upstream_lines = 235
uses_common = [
  "checkError",
  "convertToADA",
  "convert_actionCIP1292Bech",
  "convert_actionUTXO2Bech",
  "file_lock",
  "file_unlock",
  "get_addressEra",
  "get_addressType",
  "queryLight_stakeAddressInfo",
  "readOfflineFile",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = [
  "query stake-address-info",
  "stake-address deregistration-certificate",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI",
  "koiosAPI/pool_info",
]
env_vars = []
+++

# 08a_genStakingAddrRetireCert: Generate a stake address de-registration certificate

Checks that a stake address can be retired and, if so, writes the de-registration certificate. The account must be registered on chain, hold no rewards and have no open governance-action deposit. From the Conway era on the certificate carries the key deposit that was actually paid, read from the live account state, so the refund in [08b](./08b_deregStakingAddrCert.md) matches. Works in all three work modes.

## Interface

- **SPO-08a-IF-001** Takes exactly one non-empty word, the stake account name; any other form prints a usage line on **stdout** and exits 2. The name loses a trailing `.addr`, then a trailing `.staking`, and a leading `./`. (src: L19)

## Inputs

- **SPO-08a-IN-001** Requires `<name>.staking.addr`; a missing file exits 1. Its content must be a stake address, otherwise exits 1. (src: L22, L25-L32)
- **SPO-08a-IN-002** The account state comes from the work mode: online `cardano-cli <era> query stake-address-info --address <addr>` (stderr discarded, no sync gate); light `queryLight_stakeAddressInfo` (SPO-Clight-EXT-005, SPO-Clight-OUT-008 .. SPO-Clight-OUT-013); offline `address."<addr>".rewardsJSON` of the transfer file after the validation of SPO-Ptransfer-IN-001. (src: L41-L59)

## Behaviour

1. **Read the account.**
   - **SPO-08a-PRE-001** A failed online or light query exits with status 0 (the status is read after an `echo`); no certificate is written. (src: L45, L51)
   - **SPO-08a-PRE-002** Offline, an address that is not in the transfer file prints "include it first online" and exits 0. (src: L56)
2. **Check the account can be retired.**
   - **SPO-08a-PRE-003** An account with no entry (not registered) exits 1. (src: L75)
   - **SPO-08a-PRE-004** A reward balance above zero refuses with exit 1; the account must first be emptied with `01_claimRewards`. (src: L79-L83, L201, L203)
   - **SPO-08a-PRE-005** An account that is named in at least one governance-action deposit (`govActionDeposits` not empty) refuses with exit 1: the deposit refund is still pending. Both this and the reward refusal are evaluated before the exit, so both are reported. (src: L161-L173, L200-L203)
   - **SPO-08a-EXT-001** Online with `koiosAPI` configured, when the node reports no governance-action deposit, the script asks Koios (`queryLight_stakeAddressInfo`) for the same account and applies SPO-08a-PRE-005 to that answer. A failed Koios query exits with status 0 and writes no certificate. (src: L175-L198)
3. **Build the certificate.**
   - **SPO-08a-EXT-002** From the Conway era on runs `cardano-cli <era> stake-address deregistration-certificate --stake-address <addr> --key-reg-deposit-amt <deposit> --out-file /dev/stdout`, where `<deposit>` is `stakeRegistrationDeposit` of the account answer (online: node; light: Koios `deposit`, default 2000000 per SPO-Clight-OUT-011; offline: the transfer file). For babbage and older eras the command omits the deposit flag. stderr is discarded; a non-zero exit ends the script with that code. (src: L206-L220)
   - **SPO-08a-OUT-001** Writes the certificate to `<name>.staking.dereg-cert`: unlocked, replaced if present, then locked to `0400`. A write failure exits 1. (src: L221-L225)

## Work modes

- **SPO-08a-MODE-001** All three modes are supported. They differ only in the source of the account state (SPO-08a-IN-002); offline cannot run the Koios double check of SPO-08a-EXT-001, and light has no separate double check because its state already comes from Koios. (src: L41-L59, L175)

## Prompts

No prompts.

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<name>.staking.dereg-cert` | de-registration certificate; carries the deposit from Conway on (SPO-Pfiles-OUT-009) | `0400` | created or replaced |

The other output is display: the account status as in 03c (display only).

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Not exactly one non-empty word | 2 | SPO-08a-IF-001 |
| `.staking.addr` missing or not a stake address | 1 | SPO-08a-IN-001 |
| Query fails (online, light, Koios double check) | 0 | SPO-08a-PRE-001, SPO-08a-EXT-001 |
| Address not in transfer file (offline) | 0 | SPO-08a-PRE-002 |
| Account not registered | 1 | SPO-08a-PRE-003 |
| Rewards or pending governance deposits | 1 | SPO-08a-PRE-004, SPO-08a-PRE-005 |
| cardano-cli failure | cardano-cli's code | SPO-08a-EXT-002 |
| Certificate file write failure | 1 | SPO-08a-OUT-001 |

## Security

No secrets are read or written.

## Domain mapping

Use case `GenerateStakeDeregistrationCertificate(stakeAccount)` on aggregate `StakeAccount` (state must be registered, no rewards, no governance deposits).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(StakeAddress)`, `put(StakeDeregistrationCert)`, `lock` | files |
| `Ledger` | `addressInfo(address)` | stake-type check |
| `ChainQuery` | `rewardAccount(stakeAddress)` | state from node, Koios or the snapshot |
| `Ledger` | `makeCertificate(stakeDeregistration, {stakeAddress, deposit})` | certificate |

## Port notes

* Fold this check into the de-registration use case ([08b](./08b_deregStakingAddrCert.md)) and build the certificate with the live deposit in the same step, so no stale certificate file exists between the two scripts.
* Treat query failures and offline-missing data as errors with a non-zero exit (SPO-08a-PRE-001, SPO-08a-PRE-002, SPO-08a-EXT-001).
* 08b does not repeat the governance-deposit refusal (it only displays it); a port should enforce SPO-08a-PRE-005 at registration time of the transaction too.

## Open questions

* Whether the node's `query stake-address-info` reports `govActionDeposits` for every pinned cardano-cli version; the Koios double check suggests older versions did not. A run against the pinned node settles it.
* Run against a crafted `offlineTransfer.json` on 2026-11-16 (`spo/test/parity/stake_scripts_test.go`): with a zero balance and `stakeRegistrationDeposit` 2000000 or 2500000 the script writes `83088200581c<stake key hash>1a<deposit>` (type `Certificate`, description `Stake Address Deregistration Certificate`, mode 0400), so the deposit is the account's, not the protocol parameter's. With a reward balance above zero, or a `govActionDeposits` entry, it exits 1 and writes nothing; with the address missing from the file it exits 0 and writes nothing (SPO-08a-PRE-002). The offline answer is the shape `01_workOffline add` stores: `stakeRegistrationDeposit`, `rewardAccountBalance`, `stakeDelegation.stakePoolBech32`, `voteDelegation`, `govActionDeposits`.
