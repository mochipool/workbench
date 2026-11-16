+++
id = "07a"
kind = "script"
title = "Generate the pool retirement certificate"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations"]
use_cases = ["GeneratePoolRetirementCertificate"]
depends_on = ["Cchain", "Coffline", "Cui", "Pfiles"]

upstream_path = "cardano/mainnet/07a_genStakepoolRetireCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "20f73f362901a9c6891aa59c71a03a7d40b7b21a7c269c4f70d8af3e31f6250d"
upstream_lines = 121
uses_common = [
  "checkError",
  "file_lock",
  "file_unlock",
  "get_currentEpoch",
  "readOfflineFile",
]
cli_commands = [
  "query protocol-parameters",
  "stake-pool deregistration-certificate",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 07a_genStakepoolRetireCert: Generate the pool retirement certificate

Creates the certificate that retires a pool at a chosen epoch and records it in the pool descriptor. The retirement epoch must lie after the current epoch and no later than `eMax` epochs ahead (`poolRetireMaxEpoch`); the script clamps an out-of-range request into that window instead of refusing it. The certificate is submitted by [07b](./07b_deregStakepoolCert.md). Nothing here touches the chain except reading the protocol parameters and the current epoch.

## Interface

- **SPO-07a-IF-001** Takes one required argument, the pool name (normalised as in SPO-Pfiles-IN-001). Without it, or with an empty one, prints usage and exits 1. (src: L20)
- **SPO-07a-IF-002** Takes an optional second argument, the retirement epoch. It is read only when exactly two arguments are given; further arguments are ignored. (src: L22)
- **SPO-07a-IF-003** When `<pool>.pool.json` does not exist, writes a minimal descriptor (`poolName` = the name, `poolOwner` with one placeholder owner, `poolMetaTicker` `EMPTY`) in default mode, prints it, and exits 1. The operator retries; the minimal descriptor is all that retirement needs. (src: L24-L42)

## Inputs

- **SPO-07a-IN-001** Reads `poolName` from the descriptor. A missing, null or empty value, or an unparsable file, exits 2. No other field is read, and `poolName` is not compared with the argument. (src: L44-L55)
- **SPO-07a-IN-002** Requires `<poolName>.node.vkey`; exits 2 when missing. (src: L58)
- **SPO-07a-IN-003** Reads the protocol parameter `poolRetireMaxEpoch` (the ledger's `eMax`) from the work mode's source: node query, Light-Mode document, or the transfer file (`readOfflineFile`). A failing query exits with its code. (src: L63-L72)
- **SPO-07a-IN-004** Reads the current epoch in the work mode (`get_currentEpoch`; offline from genesis files and clock, SPO-Cchain-INV-005). (src: L74)

## Behaviour

1. **Compute the window and clamp.**
   - **SPO-07a-INV-001** The earliest retirement epoch is `current + 1` and the latest `current + poolRetireMaxEpoch`. Without an epoch argument the earliest is used. A requested epoch below the earliest is raised to it and above the latest lowered to it, silently apart from the display of the final value. (src: L75-L86)
   - **SPO-07a-INV-002** The epoch argument is not validated as a number: it is evaluated by bash's arithmetic comparison. A non-numeric word counts as 0 (and so becomes the earliest epoch), and an arithmetic expression is evaluated. (src: L78-L80)
   - **SPO-07a-INV-003** The script does not check that the pool is registered on chain, that no retirement is already pending, or that the pool was not retired before. It can be run for any pool with a cold key. (src: L58-L96)
2. **Create the certificate.**
   - **SPO-07a-EXT-001** Runs `cardano-cli <era> stake-pool deregistration-certificate --cold-verification-key-file <pool>.node.vkey --epoch <epoch> --out-file <pool>.pool.dereg-cert`, after unlocking an existing certificate. A failure ends the script with cardano-cli's code. (src: L94-L97)
3. **Record it.**
   - **SPO-07a-OUT-001** Locks the certificate `0400`. (src: L107)
   - **SPO-07a-OUT-002** Records in the descriptor `deregCertCreated` (RFC-5322 time), `deregCertFile` (`<pool>.pool.dereg-cert`) and `deregEpoch` (the epoch as a **string**), whole-file rewrite, locked `0400`. Other fields, including a previous `deregSubmitted`, stay. (src: L99-L105)
   - **SPO-07a-OUT-003** Prints the certificate and the descriptor (display only). (src: L109-L117)

## Work modes

- **SPO-07a-MODE-001** The parameters and the epoch come from the work mode's source (SPO-07a-IN-003, SPO-07a-IN-004). Offline mode needs the transfer file and the genesis files and trusts the wall clock for the epoch; online and light need node or Koios. (src: L63-L74)

## Prompts

No prompts.

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.pool.dereg-cert` | `CertificateConway` text envelope for the retirement | `0400` | created or replaced |
| `<pool>.pool.json` | descriptor with `deregCertCreated`, `deregCertFile`, `deregEpoch` | `0400` after update; default when created from the template | created (template) or updated |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| No argument | 1 | SPO-07a-IF-001 |
| Descriptor missing (minimal one written) | 1 | SPO-07a-IF-003 |
| `poolName` missing, empty or JSON invalid | 2 | SPO-07a-IN-001 |
| `<pool>.node.vkey` missing | 2 | SPO-07a-IN-002 |
| Parameter or epoch query failed | the failing command's code | SPO-07a-IN-003, SPO-07a-IN-004 |
| cardano-cli failure | cardano-cli's code | SPO-07a-EXT-001 |

## Security

- **SPO-07a-SEC-001** The epoch argument reaches a bash arithmetic comparison unvalidated. Bash evaluates array-index expressions in that context with command substitution, so a crafted argument can execute commands; a wrapper must pass only a decimal integer. (src: L78-L80)

## Domain mapping

Use case `GeneratePoolRetirementCertificate(pool, epoch?)` on aggregate `StakePool` (retirement intent).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `tip()` (epoch), `protocolParameters()` | Current epoch and `poolRetireMaxEpoch` |
| `Ledger` | `makeCertificate(retirement, {coldVkey, epoch})` | Retirement certificate |
| `Store` | `get/put(PoolDescriptor)`, `put(PoolRetirementCertificate)` | Descriptor update and certificate |
| `Store` | `get(ColdVerificationKey)` | Cold vkey |

## Port notes

* Validate the epoch as an integer and report the clamped value as a warning, not silently; keep the clamp as the default to stay at parity.
* Check on-chain state (registered, already retiring) and warn: retiring an unregistered pool wastes a transaction.
* The chosen epoch is fixed at certificate time while submission happens later (07b); a retirement certificate whose epoch has become invalid fails only at the ledger. Record the validity window in the aggregate and recheck at submission.

## Notes from the oracle (2026-11-16)

* Offline against the pinned scripts (`spo/test/parity/pool_scripts_test.go`): the certificate and the descriptor record are byte-equal to upstream's for no epoch (the earliest), an epoch inside the window, the last epoch of the window, an epoch below it (raised) and one above it (lowered).
* `cardano-cli conway stake-pool deregistration-certificate` writes the description `Stake Pool Retirement Certificate`.
* The `deregEpoch` field is a string.

## Open questions

* The ledger's exact rule is `current < epoch <= current + eMax` (the script mirrors it); a preview-network test confirms the boundary `epoch == current + eMax`.
