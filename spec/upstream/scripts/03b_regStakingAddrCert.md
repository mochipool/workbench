+++
id = "03b"
kind = "script"
title = "Register a stake address on chain"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["stake-delegation", "transaction-construction", "wallet"]
use_cases = ["RegisterStakeAddress"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Cconf", "Cchain", "Clight", "Chw", "Ckey", "Ctx", "Cui"]

upstream_path = "cardano/mainnet/03b_regStakingAddrCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "98f169e1e8076521a67d837bce2a8310090e5c0bb6d320b3a1246cd29a00fa5c"
upstream_lines = 728
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
  "file_lock",
  "file_unlock",
  "generate_UTXO",
  "get_addressType",
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
  "query utxo",
  "stake-address registration-certificate",
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
env_vars = [
  "ENV_SKIP_PROMPT",
]
+++

# 03b_regStakingAddrCert: Register a stake address on chain

Builds the stake-address registration certificate for an existing stake address and registers it in a transaction paid from a payment address. The key deposit (`stakeAddressDeposit`) is taken from the change output. The script follows the shared transaction pipeline ([Ptx](../patterns/Ptx.md)) with the variations below; this spec records only what differs from it. The inverse operation is [08a](./08a_genStakingAddrRetireCert.md) plus [08b](./08b_deregStakingAddrCert.md).

## Interface

- **SPO-03b-IF-001** Takes the stake account name and the paying address name, in that order, then extra parameters (SPO-Ptx-IF-001, SPO-Pparam-IF-001). The stake name has `.staking` appended when absent (so `owner` and `owner.staking` are the same account); the paying name loses `.addr`. Fewer than two words prints usage and exits 1 (SPO-Ptx-IF-002). (src: L21-L24, L61-L62)
- **SPO-03b-IF-002** Accepts metadata files and `msg:`/`enc:`/`pass:` words per the Pparam acceptance table. `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and `txhash#index` words are recognised and ignored (SPO-Pparam-IF-007); all UTxOs of the paying address are spent. An `enc:` mode other than `basic` exits 1 (SPO-Pparam-PRE-003). (src: L76-L161)

## Inputs

- **SPO-03b-IN-001** Requires `<stake>.addr` and `<stake>.skey` or `<stake>.hwsfile`, and `<pay>.addr` and `<pay>.skey` or `<pay>.hwsfile`; a missing one exits 1 before any query (SPO-Ptx-IN-002). (src: L66-L70)
- **SPO-03b-IN-002** The deposit is `stakeAddressDeposit` of the protocol parameters of the work mode's source (SPO-Ptx-IN-004, SPO-Ptx-MODE-006); offline it comes from `.protocol.parameters` of the transfer file. (src: L322-L332)

## Behaviour

1. **Check the stake address.**
   - **SPO-03b-PRE-001** Exits 2 when the content of `<stake>.addr` is not a stake address. This check runs in all work modes before any chain query. (src: L169-L173)
2. **Check chain state (online, light).**
   - **SPO-03b-EXT-001** Online reads `cardano-cli <era> query stake-address-info --address <stake>`, light `queryLight_stakeAddressInfo` (SPO-Clight-EXT-005 .. SPO-Clight-OUT-013). No sync gate precedes this query; the sync gate of SPO-Ptx-MODE-002 applies only at the later UTxO query. (src: L177-L195, L385)
   - **SPO-03b-PRE-002** When the account is already registered (the answer has at least one entry) the script shows its status (deposit, rewards, delegations, governance deposits; display only) and **exits 0 without building a certificate or a transaction**. (src: L199-L215, L314)
   - **SPO-03b-PRE-003** A failed account query exits with status 0, because the status is read after an `echo`. No certificate or transaction is built. (src: L186, L192)
3. **Build the certificate.**
   - **SPO-03b-EXT-002** From the Conway era on runs `cardano-cli <era> stake-address registration-certificate --stake-address <addr> --key-reg-deposit-amt <deposit> --out-file /dev/stdout`; for babbage and older eras the same command without the deposit flag. stderr is discarded; a non-zero exit ends the script with that code. (src: L334-L348)
   - **SPO-03b-OUT-001** Writes the certificate to `<stake>.cert` (that is `<name>.staking.cert`) on every run, replacing an existing one, and locks it to `0400`. A write failure exits 1. The certificate is built before the UTxO query, so it exists even if the run later refuses for lack of funds or the operator declines. (src: L349-L353)
4. **Balance.**
   - **SPO-03b-INV-001** Follows SPO-Ptx-INV-007 with change `inputs − fee − deposit` (all assets kept). The minimum-funds figure shown is `deposit + fee + minimum output value`. When the change is below the minimum output value the script refuses with exit **0** (SPO-Ptx-PRE-002). (src: L547-L577)
   - **SPO-03b-INV-002** The dummy and the final body carry `--certificate <stake>.cert`, and the fee uses witness count 2 (SPO-Ptx-INV-006): one for the payment key, one for the stake key. (src: L552, L556, L589)
5. **Sign.**
   - **SPO-03b-INV-003** The hardware path is taken when `<pay>.hwsfile` and `<stake>.hwsfile` both exist **and** the payment name (with `.payment` removed) equals the stake name (with `.staking` removed), so only a hardware wallet's own stake key can be registered by it. The key-file path is taken when `<pay>.skey` and `<stake>.skey` both exist. Any other combination exits 1 (SPO-Ptx-PRE-006). (src: L598-L601, L637, L653-L655)
   - **SPO-03b-EXT-003** Hardware path: before the canonicalisation of SPO-Ptx-EXT-005 the body file text has the byte sequence `04d90102818307` replaced by `04818307`, removing the tag-258 set wrapper around the single type-7 certificate. Then one `cardano-hw-cli transaction witness` call with `--hw-signing-file <pay>.hwsfile --hw-signing-file <stake>.hwsfile`, both also as `--change-output-key-file`, writes `<tempDir>/<pay>.txwitness` (payment) and `.txwitness2` (stake); `transaction assemble` joins them. (src: L603-L635)
   - **SPO-03b-EXT-004** Key-file path: `cardano-cli <era> transaction sign` with the payment and then the stake signing key, each read into memory and passed through an anonymous pipe (SPO-Ptx-EXT-006, SPO-Ptx-SEC-001). (src: L637-L651)
6. **Confirm and submit.**
   - **SPO-03b-PR-001** The size check (SPO-Ptx-PRE-007) and the confirmation (SPO-Ptx-PR-002, default No) apply. `ENV_SKIP_PROMPT=YES` skips the confirmation in this script (SPO-Ptx-PR-003). (src: L662-L670)

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-03b-INV-004** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with SPO-03b-IF-001, SPO-03b-IF-002, SPO-03b-IN-001, SPO-03b-PRE-001; the registration check and certificate (SPO-03b-EXT-001 to SPO-03b-OUT-001) also happen here, before the clock. The usage text is display only. (src: L19-L359)
- **SPO-03b-INV-005** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001): TTL = slot + `defTTL`, read after the certificate is built. (src: L361-L362)
- **SPO-03b-INV-006** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002); the paying address file is `<pay>.addr`. (src: L364-L406)
- **SPO-03b-INV-007** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L408-L546)
- **SPO-03b-INV-008** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006), read before the clock, because the certificate needs `stakeAddressDeposit` (SPO-03b-IN-002). (src: L322-L334)
- **SPO-03b-INV-009** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with the certificate attached and witness count 2 (SPO-03b-INV-002). (src: L548-L560)
- **SPO-03b-INV-010** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-EXT-003, SPO-Ptx-PRE-002) with change `inputs - fee - deposit` and the refusal exit 0 (SPO-03b-INV-001). (src: L562-L577)
- **SPO-03b-INV-011** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003): any earlier body, witness files and transaction file are removed first and a build failure ends the script with cardano-cli's code. (src: L579-L596)
- **SPO-03b-INV-012** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-PRE-006) with the combinations of SPO-03b-INV-003, SPO-03b-EXT-003 and SPO-03b-EXT-004. (src: L598-L658)
- **SPO-03b-INV-013** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007), exit 1 (SPO-03b-PR-001). (src: L662-L666)
- **SPO-03b-INV-014** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003), honouring `ENV_SKIP_PROMPT` (SPO-03b-PR-001). (src: L668-L670)
- **SPO-03b-INV-015** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010); the offline entry is SPO-03b-MODE-002. (src: L672-L728)

## Work modes

- **SPO-03b-MODE-001** Online and light run the chain-state check of SPO-03b-PRE-002; offline skips it, so a registration of an already registered key can be signed and queued and is only rejected when executed. Submission is per SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010. (src: L177, L674-L723)
- **SPO-03b-MODE-002** Offline appends the transaction with type `StakeKeyRegistration` and the extra field `stakeAddr` (the stake name) to the transfer file (SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012); the history entry reads "signed staking key registration transaction for '<stake>', payment via '<pay>'". (src: L697-L721)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| "Does this look good for you, continue ?" (SPO-03b-PR-001) | No; skipped by `ENV_SKIP_PROMPT=YES` | Submits or queues |
| Hardware device approval | n/a | Device prompt during the witness call |

## Outputs

- **SPO-03b-OUT-002** Beyond SPO-03b-OUT-001 and the temporary files of SPO-Ptx-OUT-003 (`dummy.txbody`, `<pay>.txbody`, `.txwitness`, `.txwitness2`, `.tx`), a successful submit changes the chain, and offline mode changes the transfer file. Nothing else in the working directory is written. (src: L349-L353, L579-L582, L674-L723)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<name>.staking.cert` | stake registration certificate, with deposit from Conway on | `0400` | created or replaced |
| `<tempDir>/<pay>.transactionMessage.json` | metadata of `msg:` words | default | created when messages given |
| `offlineTransfer.json` | queued entry `StakeKeyRegistration` | default | offline only |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Too few words | 1 | SPO-Ptx-IF-002 |
| Missing address or signing file | 1 | SPO-03b-IN-001 |
| `<stake>.addr` is not a stake address | 2 | SPO-03b-PRE-001 |
| Stake address already registered | 0, nothing built | SPO-03b-PRE-002 |
| Stake-address query fails | 0 | SPO-03b-PRE-003 |
| Hardware/key-file mix, or hardware names differ | 1 | SPO-03b-INV-003 |
| Change below minimum output value | 0 | SPO-03b-INV-001 |
| All other pipeline failures | as in the Ptx failure table | SPO-Ptx-PRE-001 .. SPO-Ptx-MODE-010 |

## Security

- **SPO-03b-SEC-001** Signing keys never touch the disk (SPO-Ptx-SEC-001). The signed transaction and body are left in world-readable temporary files (SPO-Ptx-SEC-002). The certificate carries no secret. (src: L579-L582, L637-L651)
- **SPO-03b-SEC-002** `ENV_SKIP_PROMPT=YES` removes the last human check before an irreversible registration that locks the key deposit (SPO-Ptx-SEC-003). (src: L670)

## Domain mapping

Use case `RegisterStakeAddress(stakeAccount, payer, extras)` on aggregate `StakeAccount` (state: unregistered, registered with deposit).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `rewardAccount(stakeAddress)` | already-registered check (online, light) |
| `ChainQuery` | `protocolParameters()` | `stakeAddressDeposit` |
| `Ledger` | `makeCertificate(stakeRegistration, {stakeAddress, deposit})` | certificate |
| `Store` | `put(StakeRegistrationCert)`, `lock` | `<name>.staking.cert` |
| `Ledger`, `Signer`, `Submitter`, `Transport` | per Ptx domain mapping | build, sign (payment + stake witness), submit or queue |
| `UI` | `confirm(prompt, No)` | confirmation |

## Port notes

* Build the certificate in memory and persist it only with the transaction record; a failed or declined run should not leave `<name>.staking.cert` behind, and the deposit in it should be the one in force when the transaction is built.
* Check "already registered" in offline mode too when the transfer file holds the stake address (`01_workOffline add` stores `rewardsJSON`).
* Treat an unreachable account query as a failure with a non-zero exit (SPO-03b-PRE-003 exits 0).
* A hybrid wallet (hardware payment, software stake key) is refused by SPO-03b-INV-003; with signer-per-credential a port can sign it with two signers.
* The remote-signing variant needs the payment and stake witnesses from possibly different parties: the draft carries both witness slots.

## Open questions

* Whether the Koios `account_info` answer in light mode always reports an unregistered account as `[]` (SPO-Clight-OUT-007); only a run against Koios settles it.
* The `sed` of SPO-03b-EXT-003 only matches when cardano-cli emits the certificate set as tag 258; an inventory run of the pinned cardano-cli confirms the encoding.
