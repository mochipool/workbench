+++
id = "21d"
kind = "script"
title = "Retire a DRep and reclaim the deposit"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "transaction-construction", "key-custody", "air-gap-transfer"]
use_cases = ["RetireDRep"]
depends_on = ["Cconf", "Cchain", "Clight", "Coffline", "Chw", "Ckey", "Cui", "Ctx", "Ptx", "Pparam", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/21d_retDRepCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "6231b6ee6a2f79f036f2fc46809619d22a9297f9516971806461dbd6c52b7cb3"
upstream_lines = 721
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
  "file_lock",
  "file_unlock",
  "generate_UTXO",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
  "queryLight_drepInfo",
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
  "governance drep id",
  "governance drep retirement-certificate",
  "query drep-state",
  "query protocol-parameters",
  "query utxo",
  "transaction assemble",
  "transaction build-raw",
  "transaction calculate-min-fee",
  "transaction sign",
  "transaction submit",
  "transaction txid",
  "transaction witness",
]
hwcli_commands = [
  "transaction witness",
]
signer_commands = []
http_endpoints = [
  "tokenMetaServer",
]
env_vars = [
  "ENV_SKIP_PROMPT",
]
+++

# 21d_retDRepCert: Retire a DRep and reclaim the deposit

Retires a registered DRep. The retirement certificate carries the deposit that the DRep paid at registration, and the same amount is added to the change output that returns to the paying address. The script is the mirror of [21b](./21b_regDRepCert.md) and shares its signing logic: the payment key and the DRep key sign.

The script follows the Ptx pipeline (SPO-Ptx-IF-001, SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-010) with the variations below. The signing forms, the unrestricted-mode prompt, the final prompt and the offline queueing are those of 21b except for the `type` of the queue entry; they are restated as references, not repeated.

## Interface

- **SPO-21d-IF-001** Takes two positional arguments, the DRep name (a trailing `.drep` is dropped) and the paying address name (a trailing `.addr` is dropped), then extra parameters from the third word. Fewer than two arguments print usage on stderr and exit 1. (src: L21-L58, L69-L70)
- **SPO-21d-IF-002** The extra parameters are metadata files, `msg:`, `enc:`, `pass:` and the ignored UTxO tokens (SPO-Pparam-IF-001, SPO-Pparam-IF-007). Unlike 21b it does not know `url:` and `hash:`: such a word is classified as a metadata file word and refused with exit 1 (SPO-Pparam-IF-005). (src: L88-L136)
- **SPO-21d-PRE-001** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0. (src: L60-L65)

## Inputs

- **SPO-21d-IN-001** Requires `<drep>.drep.vkey` and `<drep>.drep.skey` or `<drep>.drep.hwsfile`, and the payer files as in SPO-Ptx-IN-002; each missing file exits 1 before any query. (src: L74-L78)
- **SPO-21d-IN-002** Reads the protocol parameters of the work mode (SPO-Ptx-MODE-006) and `protocolVersion.major`; it does not read `dRepDeposit`. (src: L177-L197)

## Behaviour

1. **Check the era from the parameters.**
   - **SPO-21d-PRE-002** Exits 1 when `protocolVersion.major` is below 9. (src: L194-L197)
2. **Derive the DRep id** exactly as SPO-21b-EXT-001. (src: L199-L201)
3. **Read the DRep state.**
   - **SPO-21d-EXT-001** Online: `cardano-cli <era> query drep-state --drep-key-hash <id>` (no `--include-stake`), element 0 of the result; light: `queryLight_drepInfo <id>`, element 0 or `[]`; offline: `drep."<id>".drepStateJSON` of the transfer file. A failed query prints the error and exits **0** (status of the `echo` in `echo ...; exit $?`; L210 online, L216 light). (src: L206-L224)
     > **Upstream quirk:** a failed DRep-state query looks like success to a caller. A port exits non-zero.
   - **SPO-21d-PRE-003** Offline: an id missing from the transfer file prints "include it first online" and exits 0. (src: L222)
   - **SPO-21d-PRE-004** When the state is empty (the DRep is not registered) the script reports that there is nothing to retire and exits **0**; no certificate, no transaction. (src: L226-L233)
   - **SPO-21d-INV-001** The deposit is read from the **on-chain state** (`.[1].deposit`, 0 when absent), not from the protocol parameters, so a deposit paid under an earlier `dRepDeposit` value is refunded correctly. (src: L226, L237)
4. **Build the certificate.**
   - **SPO-21d-EXT-002** `cardano-cli <era> governance drep retirement-certificate --drep-key-hash <id> --deposit-amt <on-chain deposit> --out-file /dev/stdout`; a failure ends the script with its code. (src: L243-L245)
   - **SPO-21d-OUT-001** The certificate is written to `<drep>.drep-ret.cert` (unlock, write, lock to 0400), replacing the previous one. A write failure exits 1. (src: L246-L249)
5. **Build, sign and submit** as in Ptx, with these variations:
   - **SPO-21d-INV-002** The body carries `--certificate <drep>.drep-ret.cert`; the witness count is 2. (src: L448, L452, L487)
   - **SPO-21d-INV-003** The change output pays the paying address `inputs - fee + deposit` with all assets (SPO-Ptx-INV-007). (src: L469, L487)
   - **SPO-21d-PRE-005** Refuses with exit 0 when the change would be below the minimum output value (SPO-Ptx-PRE-002). (src: L461-L462, L475)
   - **SPO-21d-INV-004** The four signing forms, the unrestricted-mode prompt (default Yes, declining exits 2), the hardware-answer classification, the size check, the confirmation prompt (default No, `ENV_SKIP_PROMPT=YES` skips it) and the submission are the same as in 21b (SPO-21b-INV-006, SPO-21b-PR-001, SPO-21b-PRE-009, SPO-21b-PR-002; SPO-Ptx-PRE-007). (src: L496-L716)
   - **SPO-21d-OUT-002** Offline mode queues the signed transaction with `type` `DRepIDRetirement` and the extra fields of 21b, and the history text "signed drep-id retirement transaction". (src: L667-L716)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-21d-INV-005** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the DRep and payer files of SPO-21d-IN-001, and, specific to this script, the DRep id, the on-chain state lookup and the retirement certificate of steps 2 to 4 (SPO-21d-EXT-001, SPO-21d-EXT-002, SPO-21d-PRE-003, SPO-21d-PRE-004, SPO-21d-INV-001, SPO-21d-OUT-001). (src: L19-L175, L199-L254)
- **SPO-21d-INV-006** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L256-L260)
- **SPO-21d-INV-007** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002); the payer address is read from `<pay>.addr` and validated (SPO-Ptx-IN-001). (src: L262-L305)
- **SPO-21d-INV-008** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L307-L437)
- **SPO-21d-INV-009** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read before the UTxO stage, with the protocol-major check of SPO-21d-PRE-002. (src: L177-L197)
- **SPO-21d-INV-010** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with the retirement certificate attached and witness count 2 (SPO-21d-INV-002). (src: L443-L454)
- **SPO-21d-INV-011** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with the on-chain deposit added back to the change (SPO-21d-INV-003), and exit 0 when it is too small (SPO-21d-PRE-005). (src: L456-L475)
- **SPO-21d-INV-012** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee, the refund-increased change and `--certificate <drep>.drep-ret.cert`. (src: L477-L493)
- **SPO-21d-INV-013** Stage 9, sign: as 21b stage 9 (SPO-21d-INV-004, SPO-21b-INV-006, SPO-21b-PR-001, SPO-21b-PRE-009, SPO-Ptx-PRE-005). (src: L494-L652)
- **SPO-21d-INV-014** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L654-L659)
- **SPO-21d-INV-015** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003); `ENV_SKIP_PROMPT=YES` skips it. (src: L661-L663)
- **SPO-21d-INV-016** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010), with the queue entry of SPO-21d-OUT-002. (src: L665-L719)

## Work modes

- **SPO-21d-MODE-001** Online, light and offline as in 21b; no anchor handling exists in this script. In offline mode the DRep state is the snapshot's; a DRep retired after the snapshot makes the queued transaction fail on chain. (src: L177-L224, L667-L716)

## Prompts

As SPO-21d-INV-004: the unrestricted-mode prompt (hardware payer, key-file DRep, default Yes) and the final confirmation (default No).

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<drep>.drep-ret.cert` | retirement certificate envelope | `0400` | created or replaced, also when the prompt is declined |
| Ptx working files | as in 21b (SPO-Ptx-OUT-003) | default | replaced per run |
| `offlineTransfer.json` | queued transaction (offline) | unchanged | updated |

The DRep key files and the `.drep.id` are kept after retirement.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments | 1 | SPO-21d-IF-001 |
| `url:`/`hash:` given | 1 | SPO-21d-IF-002 |
| Pre-Conway era by configuration | 0 | SPO-21d-PRE-001 |
| DRep or payer files missing | 1 | SPO-21d-IN-001 |
| Protocol major below 9 | 1 | SPO-21d-PRE-002 |
| Offline: DRep not in transfer file | 0 | SPO-21d-PRE-003 |
| DRep not registered | 0 | SPO-21d-PRE-004 |
| Not enough funds for the change output | 0 | SPO-21d-PRE-005 |
| Signing, hardware, prompt refusals | as 21b | SPO-21d-INV-004 |

## Security

- **SPO-21d-SEC-001** The retirement is irreversible for this registration and releases the deposit; with `ENV_SKIP_PROMPT=YES` nothing asks before submission (SPO-Ptx-SEC-003). Key handling is as in SPO-Ptx-SEC-001. (src: L663)

## Domain mapping

Use case `RetireDRep(drep, payer, metadata?)` on aggregate `DRep` (registered to retired; deposit returned).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `protocolParameters()`, `drepState(drepId)`, `utxos(address)`, `tip()` | Era check, deposit, inputs, TTL |
| `Ledger` | `makeCertificate(drepRetirement, {drepId, deposit})` | Certificate |
| `Ledger` | `buildRaw`, `minFee`, `minOutputValue`, `assemble` | Ptx body |
| `Store` | `put(DRepRetirementCertificate)` | Certificate file |
| `Signer` | `witness(body, keyRef)` x2 | Payment key, DRep key |
| `Submitter` / `Transport` | `submit` / `enqueueTx` | Per work mode |
| `UI` | `confirm` | Unrestricted mode, final prompt |

## Port notes

* A DRep that is delegated to still holds delegated stake after retirement; delegators must be told. The script does not warn. A port should show the delegated stake (as 21c does) before the confirmation.
* Retiring is also a way to lose the DRep's activity; offer "update" (21b) as the alternative.
* Make the "nothing to retire" case a distinct result instead of exit 0.

## Open questions

* None beyond those of [21b](./21b_regDRepCert.md).
