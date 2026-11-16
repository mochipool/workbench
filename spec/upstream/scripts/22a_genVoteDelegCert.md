+++
id = "22a"
kind = "script"
title = "Generate a vote delegation certificate"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "governance"]
use_cases = ["GenerateVoteDelegationCertificate"]
depends_on = ["Cconf", "Cconv", "Cui", "Pfiles"]

upstream_path = "cardano/mainnet/22a_genVoteDelegCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "4bfe87f76141d79d5e77bbe2ee93a4a058a6c961c25853cd32b7400a3353165a"
upstream_lines = 148
uses_common = [
  "checkError",
  "convert_actionCIP1292Bech",
  "file_lock",
  "file_unlock",
]
cli_commands = [
  "governance drep id",
  "stake-address vote-delegation-certificate",
]
hwcli_commands = []
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 22a_genVoteDelegCert: Generate a vote delegation certificate

Creates the certificate that delegates the voting power of a stake key to a DRep, to the always-abstain predefined DRep, or to the always-no-confidence predefined DRep. The DRep is given as a hex key hash, a bech32 DRep id (legacy key or script form, or CIP-129), or the name of a local DRep. The certificate is a file; [22b](./22b_regVoteDelegCert.md) registers it. The script never touches the chain and does not check that the DRep is registered.

## Interface

- **SPO-22a-IF-001** Takes exactly two words: the DRep target, then the delegator stake account name. Any other number prints usage to stderr and exits 1. The delegator name loses a trailing `.staking` and a leading `./`. (src: L20-L27)
- **SPO-22a-IF-002** The target word is lower-cased as a whole and then classified in this order, first match wins: (1) exactly 56 hexadecimal characters: a DRep key hash; (2) starts with `drep1` and is 56 characters: a legacy bech32 DRep key id; (3) starts with `drep_script1` and is 63 characters: a legacy bech32 DRep script id; (4) starts with `drep1` and is 58 characters: a CIP-129 DRep id; (5) `<name>.drep.vkey` exists, with the name taken from the original word minus a trailing `.id`, then `.drep`, and a leading `./`: a local DRep; (6) `always-abstain`; (7) `always-no-confidence`; otherwise exits 1. Because of the lower-casing, the keywords are case-insensitive. (src: L21-L23, L41, L51, L64, L77, L99, L115, L124, L133-L134)

## Inputs

- **SPO-22a-IN-001** Requires `<delegator>.staking.vkey`; a missing file exits 1. This check follows the era gate. (src: L38)
- **SPO-22a-IN-002** For form (5) reads `<name>.drep.vkey`. (src: L99-L111)

## Behaviour

1. **Gate on the era.**
   - **SPO-22a-PRE-001** When the era is before Conway (`babbage`, `alonzo`, `mary`, `allegra`, `shelley`) the script prints an information that it works from Conway on and exits **0** without creating anything. In offline mode the era comes from the transfer file. (src: L29-L34)
2. **Validate bech32 forms.**
   - **SPO-22a-PRE-002** Forms (2), (3) and (4) must decode with the `bech32` tool (exit 0); otherwise exits 1. Only decoding is checked, not the human-readable part or the length of the payload. (src: L54-L55, L67-L68, L79-L80)
3. **Create the certificate.** All forms run `cardano-cli <era> stake-address vote-delegation-certificate --stake-verification-key-file <delegator>.staking.vkey --out-file <delegator>.vote-deleg.cert` with one target flag:
   - **SPO-22a-EXT-001** (1) and (2): `--drep-key-hash <word>`, the hex or the bech32 string as given (lower-cased). (src: L46, L60)
   - **SPO-22a-EXT-002** (3): `--drep-script-hash <hex>`, the hex the `bech32` tool decodes from the id. (src: L67, L73)
   - **SPO-22a-EXT-003** (4): the id is converted to its legacy form (SPO-Cconv-OUT-020). A result starting `drep1` runs `--drep-key-hash <legacy bech32>`; a result starting `drep_script1` runs `--drep-script-hash <decoded hex without its first byte>` (the CIP-129 header). (src: L84-L95)
   - **SPO-22a-EXT-004** (5): first prints the DRep id of the key file (`cardano-cli <era> governance drep id --drep-verification-key-file <name>.drep.vkey --out-file /dev/stdout`, display only, a failure exits with its code), then runs `--drep-verification-key-file <name>.drep.vkey`. (src: L105-L111)
   - **SPO-22a-EXT-005** (6) runs `--always-abstain`; (7) runs `--always-no-confidence`. (src: L120, L129)
   - **SPO-22a-OUT-001** The certificate file is unlocked before the call and locked to `0400` after, replacing any existing `<delegator>.vote-deleg.cert` without warning. A cardano-cli failure re-locks it and ends the script with that code. (src: L45-L48, L59-L62, L72-L75, L86-L97, L110-L113, L119-L131)

## Work modes

Mode-independent, except that the era gate reads the era of the active mode (SPO-22a-PRE-001).

## Prompts

No prompts.

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<delegator>.vote-deleg.cert` | vote delegation certificate (stake key to DRep or predefined DRep); see SPO-Pfiles-OUT-008 | `0400` | created or replaced |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Not exactly two words | 1 | SPO-22a-IF-001 |
| Era before Conway | 0, nothing created | SPO-22a-PRE-001 |
| `<delegator>.staking.vkey` missing | 1 | SPO-22a-IN-001 |
| Invalid bech32 DRep id | 1 | SPO-22a-PRE-002 |
| Unrecognised target (no DRep file, not an id, not a keyword) | 1 | SPO-22a-IF-002 |
| cardano-cli failure | cardano-cli's code | SPO-22a-EXT-001 .. SPO-22a-EXT-005 |

> **Upstream quirk:** The unrecognised-target message names `<name>.node.vkey` although the file looked for is `<name>.drep.vkey` (copy-paste). Display only.

## Security

No secrets are read or written (verification keys only).

## Domain mapping

Use case `GenerateVoteDelegationCertificate(stakeAccount, drepTarget)` on aggregate `StakeAccount` (produces a vote `Delegation` draft). `drepTarget` is a sum type: key hash, script hash, local DRep, always-abstain, always-no-confidence.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(StakeVerificationKey)`, `get(DRepVerificationKey)`, `put(VoteDelegationCert)`, `lock` | files |
| `Ledger` | `makeCertificate(voteDelegation, {stakeKey, target})` | certificate |
| `Ledger` | `convertGovernanceId(id, form)` | CIP-129 to legacy and bech32 decoding |

## Port notes

* Decode and classify the DRep id structurally (human-readable part, header byte, payload length) rather than by string length, so a CIP-129 script id and a legacy key id cannot be confused (SPO-22a-EXT-003 relies on the converter's prefix test).
* The 56-hex form is always a key hash; a hex script hash cannot be given. A port could accept a typed form (`key:`, `script:`).
* Reject a pre-Conway era with a non-zero exit instead of exit 0 with an information.
* The certificate need not be a file; a use case can hand it straight to [22b](./22b_regVoteDelegCert.md).

## Open questions

* `--drep-key-hash` is given a bech32 DRep id in forms (2) and (4); that the pinned cardano-cli accepts bech32 there is assumed by the script. An inventory run settles it.
