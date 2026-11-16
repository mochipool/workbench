+++
id = "22b"
kind = "script"
title = "Register a vote delegation certificate"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "governance", "transaction-construction"]
use_cases = ["RegisterVoteDelegation"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cconf", "Cchain", "Clight", "Cconv", "Chw", "Ckey", "Ctx", "Cui"]

upstream_path = "cardano/mainnet/22b_regVoteDelegCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "5099d6a91d63137259704c1f1de427ad8c9ce475c7ff1e6a1ef87618fddb6838"
upstream_lines = 716
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_actionBech2CIP129",
  "convert_actionCIP1292Bech",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "generate_UTXO",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
  "queryLight_drepInfo",
  "queryLight_stakeAddressInfo",
  "readOfflineFile",
  "read_skeyFILE",
  "showOfflineFileInfo",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
  "submitLight",
  "trimString",
]
cli_commands = [
  "query drep-state",
  "query protocol-parameters",
  "query stake-address-info",
  "query utxo",
  "transaction assemble",
  "transaction build-raw",
  "transaction calculate-min-fee",
  "transaction sign",
  "transaction submit",
  "transaction txid",
]
hwcli_commands = [
  "transaction witness",
]
signer_commands = []
http_endpoints = [
  "tokenMetaServer",
]
env_vars = []
+++

# 22b_regVoteDelegCert: Register a vote delegation on chain

Submits the vote delegation certificate made by [22a](./22a_genVoteDelegCert.md): the voting power of the stake key goes to a DRep or to a predefined DRep. A payment address pays the fee; there is no deposit. Follows the shared pipeline ([Ptx](../patterns/Ptx.md)) and is structurally the twin of [06](./06_regDelegationCert.md). This spec records the variations: the era gate, the certificate decoding, the DRep and stake address checks, and the signer rules.

## Interface

- **SPO-22b-IF-001** Takes the stake account name (a trailing `.staking` is dropped) and the paying address name (a trailing `.addr` is dropped), then extra parameters (SPO-Ptx-IF-001). Fewer than two words prints usage and exits 1 (SPO-Ptx-IF-002). (src: L21-L24, L69-L70)
- **SPO-22b-IF-002** Extra parameters follow the Pparam acceptance table; the UTxO restrictions are recognised and ignored (SPO-Pparam-IF-007) and `enc:` other than `basic` exits 1 (SPO-Pparam-PRE-003). (src: L80-L172)

## Inputs

- **SPO-22b-IN-001** Requires `<deleg>.vote-deleg.cert` (made by 22a), `<deleg>.staking.skey` or `<deleg>.staking.hwsfile`, `<pay>.addr`, and `<pay>.skey` or `<pay>.hwsfile`; each missing file exits 1 (SPO-Ptx-IN-002). (src: L74-L78)

## Behaviour

1. **Gate on the era.**
   - **SPO-22b-PRE-001** When the era is before Conway the script prints an information and exits **0** before reading any file. (src: L60-L65)
2. **Decode the certificate.**
   - **SPO-22b-IN-002** The target is read from the `cborHex` of the certificate: the four characters at offset 68 select the form, `8200` a DRep key hash, `8201` a DRep script hash (hash = last 56 hex characters), `8102` always-abstain, `8103` always-no-confidence. Any other value leaves the target undecided: the DRep check is skipped and the run continues. For hash forms the bech32 id (`drep` or `drep_script`) and its CIP-129 form are derived for display. A failed bech32 conversion is **not detected**: the check after it reads the status of the trailing `tr`, not of the converter, so the id stays empty and the registration check of the DRep (online and light, which needs a non-empty id) is skipped silently, and the transaction is built anyway. The stake credential is the 56 hex characters at offset 12. (src: L178-L221, L225, L266-L271)
     > **Upstream quirk:** the conversion check (L186-L187, L198-L199) cannot fire, so a failed conversion falls through to the skipped DRep check. A port treats it as an error.
3. **Check chain state (online, light).**
   - **SPO-22b-PRE-002** For a DRep hash target the DRep must be registered. Online: after the sync gate (SPO-Ptx-MODE-002), `cardano-cli <era> query drep-state --drep-key-hash <hash> --drep-script-hash <hash>` (the same hash for both flags); light: `queryLight_drepInfo` with the bech32 DRep id (SPO-Clight-EXT-007, SPO-Clight-OUT-014). An answer with no entry exits 1 "DRep not registered". The two predefined DReps need no check. A failed online or light query exits with status 0 (the status is read after an `echo`). (src: L225-L261)
   - **SPO-22b-PRE-003** The stake address rebuilt from the certificate (`e1` header for mainnet, `e0` otherwise, bech32 `stake` / `stake_test`, chosen by whether `magicparam` contains `mainnet`) must be registered: after the sync gate, online reads `query stake-address-info`, light `queryLight_stakeAddressInfo`; no entry exits 1 "register it first". The current vote delegation is displayed only; re-delegation proceeds. A failed query exits with status 0. (src: L264-L344)
4. **Build.**
   - **SPO-22b-INV-001** Follows SPO-Ptx-EXT-001 .. SPO-Ptx-EXT-004 with `--certificate <deleg>.vote-deleg.cert` in both bodies, witness count 2 (SPO-Ptx-INV-006) and change `inputs − fee`: no deposit, no refund. The minimum-funds check refuses with exit 0 (SPO-Ptx-PRE-002; not listed for 22b there). (src: L546, L550, L555-L568, L580)
5. **Sign.**
   - **SPO-22b-INV-002** The hardware path needs `<pay>.hwsfile` and `<deleg>.staking.hwsfile` and equal wallet names (payment name without `.payment` equals the delegator name). The key-file path needs `<pay>.skey` and `<deleg>.staking.skey`. Any other combination exits 1 (SPO-Ptx-PRE-006). (src: L588-L591, L625, L642-L643)
   - **SPO-22b-EXT-001** Hardware path: canonicalise (SPO-Ptx-EXT-005), one `cardano-hw-cli transaction witness` with `--hw-signing-file <deleg>.staking.hwsfile --hw-signing-file <pay>.hwsfile` (stake first), both as `--change-output-key-file`, writing `<tempDir>/<pay>.txwitness-staking` and `-payment`; `transaction assemble` takes the payment then the stake witness. Key-file path: `transaction sign` with the payment then the stake key (SPO-Ptx-EXT-006). (src: L591-L640)
6. **Confirm and submit.**
   - **SPO-22b-PR-001** Size check (SPO-Ptx-PRE-007), then "Does this look good for you ?" with default No. `ENV_SKIP_PROMPT` is ignored (SPO-Ptx-PR-003). (src: L650-L658)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-22b-INV-003** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the files of SPO-22b-IN-001, and, specific to this script, the certificate decoding and the DRep and stake-address registration checks of steps 2 and 3 (SPO-22b-IN-002, SPO-22b-PRE-002, SPO-22b-PRE-003, SPO-22b-MODE-001). (src: L19-L343)
- **SPO-22b-INV-004** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L348-L350)
- **SPO-22b-INV-005** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002); the payer address is read from `<pay>.addr` and validated (SPO-Ptx-IN-001). (src: L354-L398)
- **SPO-22b-INV-006** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L399-L528)
- **SPO-22b-INV-007** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read after the UTxO stage. (src: L530-L536)
- **SPO-22b-INV-008** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with the delegation certificate attached and witness count 2 (SPO-22b-INV-001). (src: L538-L552)
- **SPO-22b-INV-009** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with no deposit, so the change is `inputs - fee`, and exit 0 when it is too small (SPO-22b-INV-001). (src: L553-L572)
- **SPO-22b-INV-010** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee and `--certificate <deleg>.vote-deleg.cert`. (src: L573-L590)
- **SPO-22b-INV-011** Stage 9, sign: the hardware path with the stake and payment hwsfile of one wallet or the key-file path with both `.skey` files, a mix being refused (SPO-22b-INV-002, SPO-22b-EXT-001, SPO-Ptx-PRE-005, SPO-Ptx-PRE-006). (src: L591-L648)
- **SPO-22b-INV-012** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L650-L656)
- **SPO-22b-INV-013** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002), but `ENV_SKIP_PROMPT` is ignored (SPO-22b-PR-001, SPO-Ptx-PR-003). (src: L658)
- **SPO-22b-INV-014** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010) with the exit codes of SPO-22b-MODE-002 and the queue entry of SPO-22b-MODE-003. (src: L659-L716)

## Work modes

- **SPO-22b-MODE-001** Online and light run the checks of Behaviour step 3; offline runs none and reads only the transfer file (UTxOs of the paying address, protocol parameters, era). (src: L225, L264, L387-L390, L532-L535)
- **SPO-22b-MODE-002** Online submission failure prints a message and exits **0**, as in 06 and 08b (`exit $?` after an `echo`); SPO-Ptx-MODE-008 does not list 22b. (src: L665-L666)
- **SPO-22b-MODE-003** Offline appends a transaction of type `VoteDelegationCertRegistration` with the extra field `delegName` (SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012); history text "signed vote-delegation cert registration transaction for '<deleg>', payment via '<pay>'". (src: L686-L709)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| "Does this look good for you ?" (SPO-22b-PR-001) | No, always asked | Submits or queues |
| Hardware device approval | n/a | During the witness call |

## Outputs

- **SPO-22b-OUT-001** Writes only the temporary files of SPO-Ptx-OUT-003 (`dummy.txbody`, `<pay>.txbody`, `.txwitness-staking`, `.txwitness-payment`, `.tx`, `<pay>.transactionMessage.json`) and, offline, the transfer file. The certificate is read, never modified. (src: L570-L572, L686-L709)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Too few words | 1 | SPO-Ptx-IF-002 |
| Era before Conway | 0 | SPO-22b-PRE-001 |
| Missing cert, address or signing file | 1 | SPO-22b-IN-001 |
| DRep not registered | 1 | SPO-22b-PRE-002 |
| Stake address not registered | 1 | SPO-22b-PRE-003 |
| DRep or stake-address query fails | 0 | SPO-22b-PRE-002, SPO-22b-PRE-003 |
| Hardware/key-file mix | 1 | SPO-22b-INV-002 |
| Change below minimum output | 0 | SPO-22b-INV-001 |
| Online submit fails | 0 | SPO-22b-MODE-002 |
| Others | per Ptx failure table | |

> **Upstream quirk:** The missing-certificate message says to create it "with script 22b"; the generator is 22a. Display only.

## Security

- **SPO-22b-SEC-001** Signing keys stay in memory (SPO-Ptx-SEC-001); the signed transaction and body stay in world-readable temporary files (SPO-Ptx-SEC-002). (src: L570-L572, L625-L640)

## Domain mapping

Use case `RegisterVoteDelegation(stakeAccount, payer, extras)` on aggregate `StakeAccount` (sets or changes its `voteDelegation`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `decodeCertificate(cert)` *(new)* | target, hash and stake credential out of the certificate |
| `Ledger` | `convertGovernanceId(id, form)` | bech32 and CIP-129 ids for display |
| `ChainQuery` | `drepState(drepId)`, `rewardAccount(stakeAddress)` | DRep and account checks |
| `ChainQuery` | `syncStatus()` *(new)* | online gate |
| `Store` | `get(VoteDelegationCert)` | certificate |
| `Ledger`, `Signer`, `Submitter`, `Transport`, `UI` | per Ptx domain mapping | build, sign (payment + stake witness), submit or queue, confirm |

## Port notes

* Decode the certificate structurally; an unknown form should be an error, not a skipped check (SPO-22b-IN-002).
* Check DRep and account state offline from the transfer file when the snapshot holds them (`add-drep` stores `drepStateJSON`).
* A failed query and a failed submission should exit non-zero (SPO-22b-PRE-002, SPO-22b-MODE-002).
* The two witnesses (payment, stake) can come from different parties in remote signing; hybrid wallets are refused here and should be allowed with per-credential signers.

## Open questions

* The online DRep query passes the same hash as key hash and as script hash; whether the node accepts this for a hash that is only one of the two is assumed by the script. A run against a node settles it.
* Run offline on 2026-11-16 (`spo/test/parity/stake_scripts_test.go`): with `always-abstain` and with a DRep key hash the queued transaction is byte-equal to the Go use case's. The target selector at character offset 68 reads `8200` for a DRep key hash and `8102` for always-abstain, as SPO-22b-IN-002 says. The script asks its confirmation on the controlling terminal and ignores `ENV_SKIP_PROMPT`.
