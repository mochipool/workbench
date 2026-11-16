+++
id = "08b"
kind = "script"
title = "De-register a stake address on chain"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "transaction-construction", "wallet"]
use_cases = ["DeregisterStakeAddress"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cconf", "Cchain", "Clight", "Cconv", "Chw", "Ckey", "Ctx", "Cui"]

upstream_path = "cardano/mainnet/08b_deregStakingAddrCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "907d303e6774d3ffb0877077f0e229fb3d0887eaea7112fd69de61548a4b71f1"
upstream_lines = 713
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_actionCIP1292Bech",
  "convert_actionUTXO2Bech",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "generate_UTXO",
  "get_addressType",
  "get_currentSync",
  "get_currentTip",
  "int_from_cbor",
  "queryLight_UTXO",
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
  "koiosAPI",
  "koiosAPI/pool_info",
  "tokenMetaServer",
]
env_vars = []
+++

# 08b_deregStakingAddrCert: De-register a stake address on chain

Submits the de-registration certificate made by [08a](./08a_genStakingAddrRetireCert.md). The key deposit comes back to the paying address as part of the change output. Follows the shared pipeline ([Ptx](../patterns/Ptx.md)); this spec records the certificate, the refund arithmetic, the chain checks and the signer rules.

## Interface

- **SPO-08b-IF-001** Takes the stake account name (`.staking` is appended when absent) and the paying address name (a trailing `.addr` is dropped), then extra parameters (SPO-Ptx-IF-001). Fewer than two words prints usage and exits 1 (SPO-Ptx-IF-002). (src: L22-L25, L62-L63)
- **SPO-08b-IF-002** Extra parameters follow the Pparam acceptance table; the UTxO restrictions are recognised and ignored (SPO-Pparam-IF-007) and `enc:` other than `basic` exits 1 (SPO-Pparam-PRE-003). (src: L79-L165)

## Inputs

- **SPO-08b-IN-001** Requires `<stake>.dereg-cert`, `<stake>.addr` and `<stake>.skey` or `<stake>.hwsfile`; a missing one exits **2**. Requires `<pay>.addr` and `<pay>.skey` or `<pay>.hwsfile`; a missing one exits 1 (SPO-Ptx-IN-002). (src: L67-L72)
- **SPO-08b-IN-002** The refund is read from the certificate, not from chain state: `cborHex` is decoded from character offset 68 as an unsigned integer (`int_from_cbor`, SPO-Cconv-IF-001). When decoding fails the certificate is taken to be pre-Conway and the refund is 2000000 lovelace. An unreadable certificate file exits 2. (src: L324-L335)

## Behaviour

1. **Check the stake address.**
   - **SPO-08b-PRE-001** Exits 2 when `<stake>.addr` does not hold a stake address (all work modes). (src: L173-L177)
2. **Check chain state (online, light).**
   - **SPO-08b-EXT-001** Online reads `cardano-cli <era> query stake-address-info --address <stake>`, light `queryLight_stakeAddressInfo` (SPO-Clight-EXT-005 .. SPO-Clight-OUT-013). No sync gate precedes this query. A failed query exits with status 0 (the status is read after an `echo`). (src: L181-L199)
   - **SPO-08b-PRE-002** An account with no entry exits 1 "register it first". (src: L203-L219)
   - **SPO-08b-PRE-003** A reward balance above zero exits 1 ("withdraw them first"). (src: L221-L226)
   - **SPO-08b-INV-001** Governance-action deposits, current pool and DRep delegation are displayed only. Unlike 08a, pending governance deposits do not stop this script. (src: L228-L317)
3. **Balance.**
   - **SPO-08b-INV-002** Follows SPO-Ptx-INV-007 with change `inputs − fee + deposit`, where `deposit` is the refund of SPO-08b-IN-002. The minimum funds shown are `max(minimum output value, minimum output value + fee − deposit)`. When the change is below the minimum output value the script refuses with exit **0** (SPO-Ptx-PRE-002). (src: L548-L562)
   - **SPO-08b-INV-003** Both bodies carry `--certificate <stake>.dereg-cert`; the fee uses witness count 2 (SPO-Ptx-INV-006): the payment key and the stake key. (src: L536, L540, L574)
4. **Sign.**
   - **SPO-08b-INV-004** The hardware path needs `<pay>.hwsfile` and `<stake>.hwsfile` and equal wallet names (payment name without `.payment` equals the stake name without `.staking`). The key-file path needs `<pay>.skey` and `<stake>.skey`. Any other combination exits 1 (SPO-Ptx-PRE-006). (src: L583-L586, L618, L635-L637)
   - **SPO-08b-EXT-002** Hardware path: canonicalise (SPO-Ptx-EXT-005), one `cardano-hw-cli transaction witness` with `--hw-signing-file <pay>.hwsfile --hw-signing-file <stake>.hwsfile`, both as `--change-output-key-file`, writing `<tempDir>/<pay>.txwitness-payment` and `.txwitness-staking`; `transaction assemble` takes both in that order. (src: L586-L616)
   - **SPO-08b-EXT-003** Key-file path: `cardano-cli <era> transaction sign` with the payment then the stake key and, only in this script, also the network flag (`magicparam`); keys are read in memory (SPO-Ptx-EXT-006). (src: L618-L633)
5. **Confirm and submit.**
   - **SPO-08b-PR-001** Size check (SPO-Ptx-PRE-007), then "Does this look good for you, continue ?" with default No. `ENV_SKIP_PROMPT` is ignored (SPO-Ptx-PR-003). (src: L645-L653)

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-08b-INV-005** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the stake and payment files of the Interface and Inputs sections and SPO-08b-PRE-001 to SPO-08b-INV-001; the chain-state refusals (online and light) also run here, before the clock. The usage text is display only. (src: L19-L337)
- **SPO-08b-INV-006** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001): TTL = slot + `defTTL`. (src: L339-L340)
- **SPO-08b-INV-007** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002); a failing UTxO query exits 0 as in SPO-Ptx-MODE-002. (src: L342-L384)
- **SPO-08b-INV-008** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L386-L516)
- **SPO-08b-INV-009** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006). (src: L520-L526)
- **SPO-08b-INV-010** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with the de-registration certificate attached and witness count 2 (SPO-08b-INV-003). (src: L530-L542)
- **SPO-08b-INV-011** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-EXT-003, SPO-Ptx-PRE-002) with change `inputs - fee + deposit` and the refusal exit 0 (SPO-08b-INV-002). (src: L528, L544-L560)
- **SPO-08b-INV-012** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003): any earlier body and transaction file are removed first and a build failure ends the script with cardano-cli's code. (src: L562-L581)
- **SPO-08b-INV-013** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-PRE-006) with SPO-08b-INV-004, SPO-08b-EXT-002 and SPO-08b-EXT-003. (src: L583-L643)
- **SPO-08b-INV-014** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007), exit 1 (SPO-08b-PR-001). (src: L645-L651)
- **SPO-08b-INV-015** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002) but without the `ENV_SKIP_PROMPT` bypass (SPO-Ptx-PR-003, SPO-08b-PR-001). (src: L653)
- **SPO-08b-INV-016** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010) with the online failure exiting 0 (SPO-08b-MODE-002) and the offline entry SPO-08b-MODE-003. (src: L655-L713)

## Work modes

- **SPO-08b-MODE-001** Online and light run the checks of Behaviour step 2; offline runs none and reads only the transfer file (UTxOs of the paying address, protocol parameters, era). The deposit is the same in all modes (the certificate). (src: L181, L376-L379, L520-L526)
- **SPO-08b-MODE-002** Online submission failure prints a message and exits **0** (SPO-Ptx-MODE-008). (src: L660-L661)
- **SPO-08b-MODE-003** Offline appends a transaction of type `StakeKeyDeRegistration` with the extra field `stakeAddr` (SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012); history text "signed staking key deregistration transaction for '<stake>', payment via '<pay>'". (src: L683-L706)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| "Does this look good for you, continue ?" (SPO-08b-PR-001) | No, always asked | Submits or queues |
| Hardware device approval | n/a | During the witness call |

## Outputs

- **SPO-08b-OUT-001** Writes only the temporary files of SPO-Ptx-OUT-003 (`dummy.txbody`, `<pay>.txbody`, `.txwitness-payment`, `.txwitness-staking`, `.tx`, `<pay>.transactionMessage.json`) and, offline, the transfer file. The certificate is not modified or deleted, even after a successful submit. (src: L564-L566, L683-L706)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Too few words | 1 | SPO-Ptx-IF-002 |
| Missing de-registration certificate, stake address or stake signing file | 2 | SPO-08b-IN-001 |
| Missing payment address or signing file | 1 | SPO-08b-IN-001 |
| Not a stake address | 2 | SPO-08b-PRE-001 |
| Account query fails | 0 | SPO-08b-EXT-001 |
| Account not registered, rewards above zero | 1 | SPO-08b-PRE-002, SPO-08b-PRE-003 |
| Certificate unreadable | 2 | SPO-08b-IN-002 |
| Hardware/key-file mix | 1 | SPO-08b-INV-004 |
| Change below minimum output | 0 | SPO-08b-INV-002 |
| Online submit fails | 0 | SPO-08b-MODE-002 |
| Others | per Ptx failure table | |

## Security

- **SPO-08b-SEC-001** Signing keys stay in memory (SPO-Ptx-SEC-001); the signed transaction and body stay in world-readable temporary files (SPO-Ptx-SEC-002). De-registration is irreversible for the deposit's lock: the confirmation is the only gate. (src: L564-L566, L618-L633, L653)

## Domain mapping

Use case `DeregisterStakeAddress(stakeAccount, payer, extras)` on aggregate `StakeAccount` (registered to unregistered; deposit refunded to the payer).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `decodeCertificate(cert)` *(new)* | refund amount out of the certificate |
| `ChainQuery` | `rewardAccount(stakeAddress)` | registered and rewards checks |
| `Store` | `get(StakeDeregistrationCert)` | certificate |
| `Ledger`, `Signer`, `Submitter`, `Transport`, `UI` | per Ptx domain mapping | build, sign (payment + stake witness), submit or queue, confirm |

## Port notes

* Use the deposit of the live account state, not of a stored certificate: if the certificate was made before a deposit change, the ledger rejects the transaction (SPO-08b-IN-002).
* Enforce the governance-deposit refusal of 08a here too (SPO-08b-INV-001).
* A failed account query and a failed submission should exit non-zero (SPO-08b-EXT-001, SPO-08b-MODE-002).
* The pre-Conway fallback of 2000000 lovelace is a guess; a port can read the deposit from the protocol parameters of the era.
* Remote signing: two witnesses (payment, stake) as in 03b.

## Open questions

* Whether `int_from_cbor` on the empty remainder of a pre-Conway certificate always returns non-zero, which triggers the 2000000 fallback (SPO-08b-IN-002); only a run against bash settles it (see Cconv open questions).
* Run offline on 2026-11-16 (`spo/test/parity/stake_scripts_test.go`): the refund decodes from character offset 68 of the certificate (`83088200581c` is 12 characters and the 56-character credential follows, so `1a001e8480` starts at 68). With a reward balance or a governance deposit in the snapshot the script still queues the transaction, because offline runs none of the checks (SPO-08b-MODE-001); the ledger would reject it. The script ignores `ENV_SKIP_PROMPT` and reads its answer from the controlling terminal: a test must run it on a pseudo terminal (the tests use `script(1)` with `y` on its input).
