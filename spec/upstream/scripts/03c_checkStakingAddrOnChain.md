+++
id = "03c"
kind = "script"
title = "Show the on-chain status of a stake address"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "chain-access"]
use_cases = ["CheckStakeAddressStatus"]
depends_on = ["Cconf", "Clight", "Caddr", "Cconv", "Pfiles"]

upstream_path = "cardano/mainnet/03c_checkStakingAddrOnChain.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "f84265baa25f16932bccc5a2d16e73ea0af3f0888dedc392f77004d03d08371b"
upstream_lines = 182
uses_common = [
  "convertToADA",
  "convert_actionCIP1292Bech",
  "convert_actionUTXO2Bech",
  "get_addressEra",
  "get_addressType",
  "queryLight_stakeAddressInfo",
  "readOfflineFile",
  "showProcessAnimation",
  "stopProcessAnimation",
]
cli_commands = [
  "query stake-address-info",
]
hwcli_commands = []
signer_commands = []
http_endpoints = [
  "koiosAPI",
  "koiosAPI/pool_info",
]
env_vars = []
+++

# 03c_checkStakingAddrOnChain: Show the on-chain status of a stake address

A read-only query. For a stake address (from a wallet's `.staking.addr` file or given literally) it reports whether the account is registered, with its key deposit, reward balance, pool delegation, DRep delegation and open governance-action deposits. The exit status is the machine-readable result: 0 when the account is registered, 1 when it is not. It writes no artefact except one temporary file. Online and light mode only.

## Interface

- **SPO-03c-IF-001** Takes exactly one non-empty word: a stake account name or a stake address. Any other number of words, or an empty word, prints a usage line on **stdout** and exits 2. (src: L20)
- **SPO-03c-IF-002** The name loses a trailing `.addr` and then a trailing `.staking`, and a leading `./`. When `<name>.staking.addr` exists the address is its content. Otherwise the **base name** of the argument (any directory part is dropped) is taken as the address itself and written to `<tempDir>/tempAddr.staking.addr`. (src: L20, L25-L28)
- **SPO-03c-IF-003** The address must be a stake address. For any other type, including an empty or unparsable one, the script prints "Address type unknown" and exits **0** with no query. (src: L30-L33, L178-L182)

## Inputs

- **SPO-03c-IN-001** Reads the stake address file or the literal, and the work mode. In light mode it needs `koiosAPI` (SPO-Cconf-PRE-004). (src: L20-L28, L43-L54)

## Behaviour

1. **Refuse offline.**
   - **SPO-03c-PRE-001** Exits 1 in offline mode, before reading any file. The transfer-file branch later in the script (L56-L59) is therefore unreachable. (src: L23, L56-L59)
2. **Query the account.**
   - **SPO-03c-EXT-001** Online runs `cardano-cli <era> query stake-address-info --address <addr>` (stderr discarded; no sync gate). Light calls `queryLight_stakeAddressInfo` (SPO-Clight-EXT-005, SPO-Clight-OUT-008 .. SPO-Clight-OUT-013). (src: L43-L54)
   - **SPO-03c-PRE-002** A failed query exits with status 0 (the status is read after an `echo`). (src: L47, L53)
3. **Report.**
   - **SPO-03c-OUT-001** When the answer has no entry the account is not registered: the script says so and exits 1. (src: L77)
   - **SPO-03c-OUT-002** For a registered account it reports: the key deposit (`stakeRegistrationDeposit`), the reward balance (shown in ADA and lovelace, or "no rewards"), the delegated pool id or "not delegated", the DRep delegation (always-abstain, always-no-confidence, not delegated, or a DRep or script DRep shown as CIP-129 id, legacy id and hash), and every governance action that holds a deposit for the account with its amount. Exit status is 0. The wording is display only. (src: L63-L75, L78-L176)
   - **SPO-03c-EXT-002** When the account is delegated to a pool and `koiosAPI` is set, queries `POST <koiosAPI>/pool_info` for the pool id (up to 5 attempts, 30 seconds each) and shows name, ticker and status when exactly one entry returns with HTTP 200. Failure of this lookup is silent and does not change the exit status. (src: L88-L121)

## Work modes

- **SPO-03c-MODE-001** Online and light differ only in the account query source (SPO-03c-EXT-001). Offline is refused (SPO-03c-PRE-001). Both online and light make the optional Koios pool lookup, since both set the online flag. (src: L23, L43-L54, L91)

## Prompts

No prompts.

## Outputs

- **SPO-03c-OUT-003** The only write is the temporary file of SPO-03c-IF-002 when the argument is a literal address. (src: L26)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Not exactly one non-empty word | 2 | SPO-03c-IF-001 |
| Offline mode | 1 | SPO-03c-PRE-001 |
| Not a stake address | 0 | SPO-03c-IF-003 |
| Account query fails | 0 | SPO-03c-PRE-002 |
| Account not registered | 1 | SPO-03c-OUT-001 |

## Security

No secrets are read or written. The literal address argument is public information; the temporary file is world-readable by default and is not deleted.

## Domain mapping

Use case `CheckStakeAddressStatus(stakeAddress | accountName)` returning a `StakeAccountStatus` read model (registered, deposit, rewards, pool, DRep delegation, governance deposits).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(StakeAddress)` | name to address |
| `Ledger` | `addressInfo(address)` | stake-type check |
| `ChainQuery` | `rewardAccount(stakeAddress)` | account state; light adapter per Clight |
| `ChainQuery` | `poolState(poolId)` | optional pool name, ticker, status |
| `Ledger` | `convertGovernanceId(id, form)` | CIP-129 to legacy DRep id for display |

## Port notes

* Return a typed result and let the caller render it; exit status 1 for "not registered" is a useful contract to keep for a CLI.
* A failing query should be a distinct non-zero exit (SPO-03c-PRE-002 exits 0), and an unknown address type should be an error (SPO-03c-IF-003 exits 0).
* In offline mode the same use case could answer from the transfer file (`address."<stake>".rewardsJSON`), which the dead branch L56-L59 tried to do.
* Usage output belongs on stderr with exit 1 like the other scripts; this one prints it on stdout with exit 2.

## Open questions

* The `showToAddr` variable in the heading line is never set; the heading shows no name. Display only.
