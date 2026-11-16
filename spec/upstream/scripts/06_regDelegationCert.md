+++
id = "06"
kind = "script"
title = "Register a stake delegation certificate"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "transaction-construction", "pool-operations"]
use_cases = ["RegisterPoolDelegation"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cconf", "Cchain", "Clight", "Chw", "Ckey", "Ctx", "Cui"]

upstream_path = "cardano/mainnet/06_regDelegationCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "f66b66db8ce8ae26be5f211b3c916f21d6ac0a99849bcb859ad9474d3dcdd7c7"
upstream_lines = 719
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "generate_UTXO",
  "get_currentSync",
  "get_currentTip",
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
  "query stake-pools",
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

# 06_regDelegationCert: Register a stake delegation on chain

Submits the delegation certificate made by [05b](./05b_genDelegationCert.md): the stake key of the account is delegated to the pool named in the certificate. A payment address pays the fee. Follows the shared pipeline ([Ptx](../patterns/Ptx.md)); this spec records the variations: the certificate, the chain checks on the pool and the stake address, the fee-only balance and the signer rules. There is no deposit.

## Interface

- **SPO-06-IF-001** Takes the stake account name (a trailing `.staking` is dropped) and the paying address name (a trailing `.addr` is dropped), then extra parameters (SPO-Ptx-IF-001, SPO-Pparam-IF-001). Fewer than two words prints usage and exits 1 (SPO-Ptx-IF-002). (src: L21-L24, L61-L62)
- **SPO-06-IF-002** Extra parameters follow the Pparam acceptance table for this script; `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and `txhash#index` are recognised and ignored (SPO-Pparam-IF-007) and `enc:` other than `basic` exits 1 (SPO-Pparam-PRE-003). (src: L75-L164)

## Inputs

- **SPO-06-IN-001** Requires `<deleg>.deleg.cert` (made by 05b), `<deleg>.staking.skey` or `<deleg>.staking.hwsfile`, `<pay>.addr`, and `<pay>.skey` or `<pay>.hwsfile`. Each missing file exits 1 (SPO-Ptx-IN-002). (src: L66-L70)
- **SPO-06-IN-002** The pool id is the **last 56 hex characters** of the certificate's `cborHex`. The stake credential is the 56 hex characters at offset 12 of the same string. Nothing else of the certificate is parsed. (src: L167-L168, L257-L261)

## Behaviour

1. **Check chain state (online, light).**
   - **SPO-06-PRE-001** The pool id is converted to bech32 with the `bech32` tool; a failure exits 1. (src: L181-L182)
   - **SPO-06-PRE-002** The pool must be registered. Online: after the sync gate (SPO-Ptx-MODE-002), `cardano-cli <era> query stake-pools` is searched for the bech32 id; it must occur exactly once (zero exits 1 "pool not on the chain", more than one exits 1; a failed query exits 1). Light: the Koios `pool_info` answer (SPO-06-EXT-001) must contain exactly one entry whose `pool_status` is `registered` (case-insensitive); otherwise, including an unreachable Koios, exits 1. (src: L218-L252)
   - **SPO-06-EXT-001** Queries `POST <koiosAPI>/pool_info` with the bech32 pool id (up to 5 attempts, 30 seconds each, HTTP 200 and exactly one entry required) when `koiosAPI` is set; the name, ticker and status are shown. Online this is display only; light uses it for SPO-06-PRE-002. (src: L186-L216, L239-L249)
   - **SPO-06-PRE-003** The stake address is rebuilt from the certificate (header byte `e1` for mainnet, `e0` otherwise, plus the stake credential hash; bech32 `stake` / `stake_test`, chosen by whether `magicparam` contains `mainnet`). It must be registered: after the sync gate, online reads `query stake-address-info`, light `queryLight_stakeAddressInfo`; no entry exits 1 "register it first". A failed query exits with status 0 (the status is read after an `echo`). (src: L256-L300)
   - **SPO-06-INV-001** An account that is already delegated is only reported (current pool and its Koios info); re-delegation, also to the same pool, proceeds. (src: L303-L343)
2. **Build.**
   - **SPO-06-INV-002** Follows SPO-Ptx-EXT-001 .. SPO-Ptx-EXT-004 with `--certificate <deleg>.deleg.cert` in the dummy and the final body, witness count 2 (SPO-Ptx-INV-006), and change `inputs − fee`: no deposit and no refund. The minimum-funds check refuses with exit 0 (SPO-Ptx-PRE-002). (src: L550, L554, L559-L572, L584)
3. **Sign.**
   - **SPO-06-INV-003** The hardware path needs `<pay>.hwsfile` and `<deleg>.staking.hwsfile` and equal wallet names (the payment name with `.payment` removed equals the delegator name). The key-file path needs `<pay>.skey` and `<deleg>.staking.skey`. Any other combination exits 1 (SPO-Ptx-PRE-006). (src: L592-L595, L628, L645-L647)
   - **SPO-06-EXT-002** Hardware path: canonicalise (SPO-Ptx-EXT-005), then one `cardano-hw-cli transaction witness` with `--hw-signing-file <deleg>.staking.hwsfile --hw-signing-file <pay>.hwsfile` (stake first), both as `--change-output-key-file`, writing `<tempDir>/<pay>.txwitness-staking` and `<pay>.txwitness-payment`; `transaction assemble` takes the payment then the stake witness. The key-file path signs with the payment then the stake key (SPO-Ptx-EXT-006). (src: L595-L643)
4. **Confirm and submit.**
   - **SPO-06-PR-001** Size check (SPO-Ptx-PRE-007), then the confirmation "Does this look good for you ?" with default No. `ENV_SKIP_PROMPT` is ignored: the prompt is always asked (SPO-Ptx-PR-003). (src: L653-L661)

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-06-INV-004** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with SPO-06-IF-001, SPO-06-IF-002, SPO-06-IN-001, SPO-06-IN-002; the pool and stake-address checks of SPO-06-PRE-001 to SPO-06-INV-001 (online and light) also run here, before the clock. (src: L19-L351)
- **SPO-06-INV-005** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001): TTL = slot + `defTTL`. (src: L353-L354)
- **SPO-06-INV-006** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002); a failing UTxO query exits 0 as in SPO-Ptx-MODE-002. (src: L358-L398)
- **SPO-06-INV-007** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L400-L530)
- **SPO-06-INV-008** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006). (src: L534-L540)
- **SPO-06-INV-009** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with the delegation certificate attached and witness count 2 (SPO-06-INV-002). (src: L546-L556)
- **SPO-06-INV-010** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-EXT-003, SPO-Ptx-PRE-002) with change `inputs - fee` and the refusal exit 0. (src: L542, L558-L572)
- **SPO-06-INV-011** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003): any earlier body and transaction file are removed first and a build failure ends the script with cardano-cli's code. (src: L574-L593)
- **SPO-06-INV-012** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-PRE-006) with SPO-06-INV-003 and SPO-06-EXT-002. (src: L595-L648)
- **SPO-06-INV-013** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007), exit 1 (SPO-06-PR-001). (src: L650-L658)
- **SPO-06-INV-014** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002) but without the `ENV_SKIP_PROMPT` bypass: the prompt is always asked (SPO-Ptx-PR-003, SPO-06-PR-001). (src: L661)
- **SPO-06-INV-015** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010) with SPO-06-MODE-002 (online failure exits 0) and the offline entry SPO-06-MODE-003. (src: L663-L719)

## Work modes

- **SPO-06-MODE-001** Online and light run the chain checks of Behaviour step 1; offline runs none of them and reads only the transfer file (UTxOs of the paying address, protocol parameters, era). (src: L178, L391-L394, L536-L538)
- **SPO-06-MODE-002** Online submission failure prints a message (the text mentions the pool) and exits **0** (SPO-Ptx-MODE-008). (src: L668-L669)
- **SPO-06-MODE-003** Offline appends a transaction of type `DelegationCertRegistration` with the extra field `delegName` (SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012); history text "signed delegation cert registration transaction for '<deleg>', payment via '<pay>'". (src: L689-L712)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| "Does this look good for you ?" (SPO-06-PR-001) | No, always asked | Submits or queues |
| Hardware device approval | n/a | During the witness call |

## Outputs

- **SPO-06-OUT-001** Writes no artefact outside the temporary files of SPO-Ptx-OUT-003 (`dummy.txbody`, `<pay>.txbody`, `.txwitness-staking`, `.txwitness-payment`, `.tx`, `<pay>.transactionMessage.json`) and, offline, the transfer file. The certificate is read, never modified. (src: L574-L576, L689-L712)

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Too few words | 1 | SPO-Ptx-IF-002 |
| Missing cert, address or signing file | 1 | SPO-06-IN-001 |
| Pool not registered, listed twice, query or conversion failed | 1 | SPO-06-PRE-001, SPO-06-PRE-002 |
| Stake address not registered | 1 | SPO-06-PRE-003 |
| Stake-address query fails | 0 | SPO-06-PRE-003 |
| Hardware/key-file mix | 1 | SPO-06-INV-003 |
| Change below minimum output | 0 | SPO-06-INV-002 |
| Online submit fails | 0 | SPO-06-MODE-002 |
| Others | per Ptx failure table | |

## Security

- **SPO-06-SEC-001** Signing keys stay in memory (SPO-Ptx-SEC-001); the signed transaction and body are left in temporary files (SPO-Ptx-SEC-002). (src: L628-L643, L574-L576)

## Domain mapping

Use case `RegisterPoolDelegation(stakeAccount, payer, extras)` on aggregate `StakeAccount` (adds a pool `Delegation`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `decodeCertificate(cert)` *(new)* | pool id and stake credential out of the certificate |
| `ChainQuery` | `poolState(poolId)`, `rewardAccount(stakeAddress)` | pool and account checks |
| `ChainQuery` | `syncStatus()` *(new)* | online gate (see Cchain) |
| `Store` | `get(DelegationCert)` | certificate |
| `Ledger`, `Signer`, `Submitter`, `Transport`, `UI` | per Ptx domain mapping | build, sign (payment + stake witness), submit or queue, confirm |

## Port notes

* Decode the certificate with a real CBOR parser, not by string offsets (SPO-06-IN-002).
* Offline, check pool and account state from the transfer file when the snapshot holds them, so a bad delegation is caught before signing.
* A failed account query and a failed submission should exit non-zero (SPO-06-PRE-003, SPO-06-MODE-002 exit 0).
* The two required witnesses (payment, stake) can come from different parties in a remote-signing flow; hybrid wallets (hardware payment, software stake) are refused here and should be allowed by a port with per-credential signers.

## Open questions

* The `query stake-pools` listing format is matched by a substring count (`grep` of the bech32 id); a pool id that is a prefix of another line cannot occur, but the output format of the pinned cardano-cli is the assumption. An inventory run settles it.
* Run offline on 2026-11-16 (`spo/test/parity/stake_scripts_test.go`) against a certificate made by 05b: the queued transaction is byte-equal to the Go use case's. The pool id is the last 56 hex characters of the certificate and the stake credential sits at offset 12, as SPO-06-IN-002 says. The script asks its confirmation on the controlling terminal and ignores `ENV_SKIP_PROMPT`.
