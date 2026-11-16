+++
id = "05b"
kind = "script"
title = "Generate a stake delegation certificate"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "pool-operations"]
use_cases = ["GeneratePoolDelegationCertificate"]
depends_on = ["Cconf", "Cui", "Pfiles"]

upstream_path = "cardano/mainnet/05b_genDelegationCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "055ca869ac99d8f1f40995c639ee6b36f304a1c622ac23880d982737cd77e6eb"
upstream_lines = 76
uses_common = [
  "checkError",
  "file_lock",
  "file_unlock",
]
cli_commands = [
  "stake-address stake-delegation-certificate",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 05b_genDelegationCert: Generate a stake delegation certificate

Creates the certificate that delegates the stake of one stake key to a pool. The pool is identified by a hex pool id, a bech32 pool id, or the cold verification key of a local pool. The certificate is only a file; [06](./06_regDelegationCert.md) puts it on chain, and script 05c reads it for pool owners (SPO-Pfiles-OUT-007). The script never touches the chain, so it does not check that the pool or the stake address is registered.

## Interface

- **SPO-05b-IF-001** Takes exactly two words: the pool, then the delegator stake account name. Any other number prints usage to stderr and exits 1. (src: L20-L27)
- **SPO-05b-IF-002** The delegator name loses a trailing `.staking` and a leading `./`. The pool word is lower-cased as a whole for the pool-id forms, and also parsed as a pool name by dropping `.json` then `.pool` and a leading `./`. (src: L21-L23)
- **SPO-05b-IF-003** The pool word is classified in this order, first match wins: (1) exactly 56 hexadecimal characters: a hex pool id; (2) starts with `pool1` and is exactly 56 characters: a bech32 pool id; (3) `<pool>.node.vkey` exists: a local pool by its cold verification key; otherwise exits 1. (src: L33, L43, L56, L65-L66)

## Inputs

- **SPO-05b-IN-001** Requires `<delegator>.staking.vkey`; a missing file exits 1 before anything else. (src: L30)
- **SPO-05b-IN-002** For form (3), reads `<pool>.node.vkey`. (src: L56-L61)

## Behaviour

1. **Validate a bech32 pool id.**
   - **SPO-05b-PRE-001** For form (2) the string must decode with the `bech32` tool (exit 0); otherwise exits 1. Only the decoding is checked, not the human-readable part. (src: L46-L47)
2. **Create the certificate.**
   - **SPO-05b-EXT-001** Runs `cardano-cli <era> stake-address stake-delegation-certificate --stake-verification-key-file <delegator>.staking.vkey --out-file <delegator>.deleg.cert` with `--stake-pool-id <id>` for forms (1) and (2) (the lower-cased word is passed as given, hex or bech32), or `--cold-verification-key-file <pool>.node.vkey` for form (3). A non-zero exit re-locks the file and ends the script with that code. (src: L38-L39, L52-L53, L61-L62)
   - **SPO-05b-OUT-001** Replaces any existing `<delegator>.deleg.cert`: it is unlocked before and locked to `0400` after, with no overwrite warning. (src: L37-L40, L51-L54, L60-L63)
   - **SPO-05b-INV-001** The certificate is a stake delegation only; it contains no registration and no deposit, so it works in every era and is independent of the work mode. (src: L38, L52, L61)

## Work modes

Mode-independent.

## Prompts

No prompts.

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<delegator>.deleg.cert` | stake delegation certificate (stake key to pool id); see SPO-Pfiles-OUT-007 | `0400` | created or replaced |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Not exactly two words | 1 | SPO-05b-IF-001 |
| `<delegator>.staking.vkey` missing | 1 | SPO-05b-IN-001 |
| Invalid bech32 pool id | 1 | SPO-05b-PRE-001 |
| Neither a pool id nor an existing `<pool>.node.vkey` | 1 | SPO-05b-IF-003 |
| cardano-cli failure | cardano-cli's code | SPO-05b-EXT-001 |

## Security

No secrets are read or written (verification keys only).

## Domain mapping

Use case `GeneratePoolDelegationCertificate(stakeAccount, poolRef)` on aggregate `StakeAccount` (produces a `Delegation` draft).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(StakeVerificationKey)`, `get(PoolColdVerificationKey)`, `put(DelegationCert)`, `lock` | files |
| `Ledger` | `makeCertificate(stakeDelegation, {stakeKey, poolId \| coldKey})` | certificate |
| `Ledger` | `convertGovernanceId(id, form)` | bech32 validity of the pool id (the `bech32` tool) |

## Port notes

* A native implementation should validate the bech32 checksum and the `pool` human-readable part, and refuse a hex id of the wrong length with a clear message.
* Overwriting an existing certificate silently is harmless here; keep it or add a confirmation.
* The certificate need not be a file: a use case can hand the certificate straight to the registration use case ([06](./06_regDelegationCert.md)).

## Open questions

* ~~The `--stake-pool-id` flag accepts both hex and bech32 in the pinned cardano-cli; the script does not distinguish. Confirm by an inventory run.~~ Resolved 2026-11-16 on cardano-cli 11.2.3.0 (`spo/test/parity/stake_oracle_test.go`): `--stake-pool-id` accepts 56 hex characters and `pool1...` bech32; both, and `--cold-verification-key-file`, give the same certificate bytes `83028200581c<stake key hash>581c<pool id>` (type `Certificate`, description `Stake Delegation Certificate`). The script's word `./mypool.node.vkey` is not a form it accepts (it drops `.json`, then `.pool`, only).
