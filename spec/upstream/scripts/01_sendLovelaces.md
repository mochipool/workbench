+++
id = "01sendLovelaces"
kind = "script"
title = "Send lovelaces (the canonical payment transaction)"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["wallet", "transaction-construction", "air-gap-transfer"]
use_cases = ["SendLovelaces"]
depends_on = ["Ptx", "Pparam", "Pfiles", "Ptransfer", "Caddr", "Cutxo", "Cconv", "Cui"]

upstream_path = "cardano/mainnet/01_sendLovelaces.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "af80e7adc3056e618fc4de67affa4190df080c27cfc72d7d736fb9ca7897d478"
upstream_lines = 716
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkAdaHandleFormat",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "filterFor_UTXO",
  "generate_UTXO",
  "get_addressType",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
  "readOfflineFile",
  "read_skeyFILE",
  "resolveAdahandle",
  "showOfflineFileInfo",
  "showProcessAnimation",
  "start_HwWallet",
  "stopProcessAnimation",
  "submitLight",
  "trimString",
]
cli_commands = [
  "query protocol-parameters",
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
env_vars = [
  "ENV_SKIP_PROMPT",
]
+++

# 01_sendLovelaces: Send lovelaces

Builds, signs and submits (or queues, offline) a payment from one payment address to a destination. It is the canonical instance of the shared transaction pipeline: everything not stated here, from UTxO gathering to submission, is [Ptx](../patterns/Ptx.md) unchanged, the extra-parameter grammar is [Pparam](../patterns/Pparam.md), and queued entries follow [Ptransfer](../patterns/Ptransfer.md). This spec records only the script's own interface (the destination forms and the amount forms), how each amount form lays out the outputs and which minimum-value checks it applies, and the deviations from the pipeline.

The script attaches nothing to the transaction and uses one witness (SPO-Ptx-INV-006). It never selects coins: every candidate UTxO of the source is spent (SPO-Ptx-INV-002), so the amount form decides only the outputs.

## Interface

- **SPO-01sendLovelaces-IF-001** Takes at least three positional words: the source name (the paying address), the destination, and the amount. With fewer it prints usage on stderr and exits 1. All further words are extra parameters. (src: L19-L23, L70)
- **SPO-01sendLovelaces-IF-002** The amount is a keyword or a non-negative integer. The word is upper-cased, so `all`, `Min` and `allfunds` are the keywords. Accepted: `ALL`, `ALLFUNDS`, `MIN`, or a word made only of decimal digits. Anything else, including an empty word, a sign, a decimal point or digit grouping, is refused with exit 1 before any file or network access. Zero passes this check and is refused later by SPO-01sendLovelaces-PRE-004. (src: L22, L72-L73)
- **SPO-01sendLovelaces-IF-003** Extra parameters start at the fourth word and follow SPO-Pparam-IF-001 .. SPO-Pparam-IF-022 with the full acceptance row of the Pparam table: `msg:`, `enc:`, `pass:`, metadata files, a `txhash#index` list, `utxolimit:`, `skiputxowithasset:` and `onlyutxowithasset:` all take effect. They are validated before the source and destination files are looked at. (src: L79-L164)
- **SPO-01sendLovelaces-IF-004** The destination is resolved from three forms, tried in this order: (1) a name for which `<dest>.addr` exists as a file (extension optional, directory part allowed, SPO-Pfiles-IN-001); (2) a literal address whose `get_addressType` is `payment` (SPO-Caddr-OUT-002); (3) an ADA Handle, that is a word matching SPO-Caddr-OUT-006. The first match wins, so an existing file named like an address shadows the literal. (src: L173-L197)
- **SPO-01sendLovelaces-IF-005** A destination that matches none of the three forms, including a stake address or a malformed address, is refused with exit 1 before anything is queried. (src: L193-L195)
- **SPO-01sendLovelaces-IF-006** A literal destination is trimmed of blanks and written as `<tempDir>/tempTo.addr`, which then stands in for `<dest>.addr`. (src: L175-L179). See SPO-Pfiles-IN-002.
- **SPO-01sendLovelaces-IF-007** An ADA Handle destination is lower-cased and resolved with the procedure of SPO-Caddr-IF-001 .. SPO-Caddr-SEC-001, which exits 1 on any failure. The resolved address is written as `<tempDir>/adahandle-resolve.addr` and the handle, not the address, is what the summary shows as destination. The UTxO list the lookup may have left behind is discarded: the holder's UTxOs play no part in the transaction. (src: L181-L191, L234)
- **SPO-01sendLovelaces-IF-008** After resolution the source and destination addresses are both validated with `check_address` (SPO-Caddr-PRE-001). The content of an existing `<dest>.addr` file is not checked for being a payment address, only for being an address `cardano-cli` accepts. Nothing refuses a destination equal to the source. (src: L228-L232)

> **Upstream quirk (IF-002):** the amount is substituted into shell arithmetic as typed. A leading zero makes it octal in the balance (`010` is 8, `08` aborts the script on a bash arithmetic error) while the same text is passed unchanged to `build-raw` as the output amount. See Open questions.

## Inputs

- **SPO-01sendLovelaces-IN-001** Reads `<source>.addr` and either `<source>.skey` or `<source>.hwsfile`, refusing with exit 1 when either is missing (SPO-Ptx-IN-002). The check happens after the extra parameters are validated and before the destination is resolved. (src: L170-L171)
- **SPO-01sendLovelaces-IN-002** Reads the destination address per SPO-01sendLovelaces-IF-004 .. SPO-01sendLovelaces-IF-008, the protocol parameters, the UTxOs of the source address and, with `queryTokenRegistry` on, token metadata (display only). All per Ptx. (src: L228-L229, L256-L286, L423-L429)

## Behaviour

1. **Validate and resolve.** Arguments (IF-001 .. IF-003), source files (IN-001), destination (IF-004 .. IF-008), the transaction message file (SPO-Pparam-OUT-002).
2. **Clock, inputs, assets, parameters.** Ptx stages 2 to 5.
   - **SPO-01sendLovelaces-PRE-001** A failing UTxO query in online or light mode prints the error and ends the script with exit status 0, because the `exit` reads the status of the preceding `echo`. This refines SPO-Ptx-MODE-002 and SPO-Ptx-MODE-003. (src: L262, L273)
     > **Upstream quirk:** a caller sees success. A port exits non-zero.
3. **Lay out the outputs from the amount.** Let `total` be the sum of lovelaces over the inputs, `fee` the minimum fee of SPO-Ptx-EXT-002 and `M(addr, assets)` the minimum output value of SPO-Ptx-EXT-003 for an output at `addr` holding `assets` and a placeholder of 1000000 lovelaces (the `+1000000` in the tx-out text). "All assets" is the set of SPO-Ptx-INV-004.
   - **SPO-01sendLovelaces-OUT-001** `ALLFUNDS` produces one output to the destination holding `total - fee` lovelaces and all assets. (src: L438-L439, L490-L491, L566-L567)
   - **SPO-01sendLovelaces-OUT-002** `ALL` with no assets on the inputs produces one output to the destination holding `total - fee` lovelaces. (src: L448, L519-L523, L566-L567)
   - **SPO-01sendLovelaces-OUT-003** `ALL` with at least one asset produces two outputs: the destination gets `total - fee - R` lovelaces, and the source gets `R` lovelaces with all assets, where `R = M(source, all assets)`. The destination receives no assets. (src: L441-L446, L509-L517, L569-L570)
   - **SPO-01sendLovelaces-OUT-004** `MIN` produces two outputs: the destination gets `M(destination, no assets)` lovelaces, and the source gets the remainder `total - fee - M(destination, no assets)` with all assets. (src: L451-L454, L528-L534, L569-L570)
   - **SPO-01sendLovelaces-OUT-005** An integer amount `N` produces two outputs: the destination gets `N` lovelaces, and the source gets `total - fee - N` with all assets. (src: L456-L460, L542-L548, L569-L570)
   - **SPO-01sendLovelaces-INV-001** In every form `inputs = outputs + fee`. Assets only ever move with `ALLFUNDS`; in all other forms every asset stays on the source address. (src: L403, L438-L554)
   - **SPO-01sendLovelaces-OUT-006** In the final body of a two-output transaction the destination output is first and the source (change) output second. The dummy body of the fee estimate has them in the opposite order, which does not change its size. (src: L472, L570)
4. **Dummy body and fee.** As SPO-Ptx-EXT-001 .. SPO-Ptx-EXT-002 with witness count 1.
   - **SPO-01sendLovelaces-EXT-001** The dummy body uses one output for `ALLFUNDS` and for `ALL` without assets (the destination, holding `total` and all assets), and two outputs otherwise. The dummy amounts are `ALL` with assets: destination `total`, source `M(destination, all assets)`; `MIN`: destination `M(destination, no assets)`, source `total`; `N`: destination `N`, source `total`. The dummy amounts have the same CBOR size class as the final amounts in practice, so the estimated fee equals the fee of the final body. They are not always at least as large: for `ALL` with assets the dummy return amount is `M(<destination>, all assets)` (L445) while the final return amount is `M(<source>, all assets)` (L512), and with an enterprise destination (29-byte address) and a base-address source (57 bytes) the dummy is about 28 times the per-byte cost smaller; the encoding width, and so the fee, is unaffected. (src: L436-L474, L445, L512)
5. **Minimum-value checks.** Each refuses with exit 1 and nothing is built, signed or queued. They run after the fee is known.
   - **SPO-01sendLovelaces-PRE-002** `ALLFUNDS` and `ALL` without assets: refuses when `total - fee < M(destination, all assets)` (for `ALL` without assets the asset set is empty). (src: L492-L495, L521-L525)
   - **SPO-01sendLovelaces-PRE-003** `ALL` with assets: refuses when `total - fee - R < R`, that is when the destination amount is below the minimum of the *source's* output with all assets. (src: L512-L518)
     > **Upstream quirk:** the destination output, which holds no assets, is compared with the minimum of the return output, not with its own. It over-refuses when assets are present. A port compares each output with its own minimum.
   - **SPO-01sendLovelaces-PRE-004** Integer amount: refuses when `N < M(destination, no assets)`. This covers zero. (src: L543-L546)
   - **SPO-01sendLovelaces-PRE-005** `MIN`: refuses when the remainder is below `M(source, all assets)`, evaluated with the 1000000 placeholder. When the amount sent is not below `total` the refusal also advises using `ALL`. (src: L535-L538)
   - **SPO-01sendLovelaces-PRE-006** Integer amount: refuses when the remainder `total - fee - N` is below `M(source, all assets)` evaluated with the actual remainder as the lovelace amount. A negative remainder, which is an `N` above `total - fee`, is refused here. The refusal advises using `ALL` when `N >= total`. (src: L547-L552)
6. **Final body, signing, size, confirmation, submission.** As SPO-Ptx-EXT-004, SPO-Ptx-INV-008 .. SPO-Ptx-EXT-006, SPO-Ptx-PRE-007, SPO-Ptx-PR-002, SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010, with the script-specific points below.
   - **SPO-01sendLovelaces-EXT-002** On the hardware path the witness is made for `<source>.hwsfile` only. When the transaction has two outputs and the file `<dir of source>/<source basename without ".payment">.staking.hwsfile` exists, `--change-output-key-file` is passed for both `<source>.hwsfile` and that staking file, so the device recognises the change output. With a single output no change key is declared. (src: L583-L610)

## Pipeline stage map
Stage numbers are those of [Ptx](../patterns/Ptx.md).

- **SPO-01sendLovelaces-INV-002** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IF-002, SPO-Ptx-IN-001, SPO-Ptx-IN-002); the forms are SPO-01sendLovelaces-IF-001 to SPO-01sendLovelaces-IF-008 and SPO-01sendLovelaces-IN-001. (src: L19-L232)
- **SPO-01sendLovelaces-INV-003** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001): TTL = slot + `defTTL`. (src: L240-L243)
- **SPO-01sendLovelaces-INV-004** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-Ptx-INV-002); the failing-query exit status is SPO-01sendLovelaces-PRE-001. (src: L256-L292)
- **SPO-01sendLovelaces-INV-005** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L294-L420)
- **SPO-01sendLovelaces-INV-006** Stage 5, protocol parameters: as Ptx (SPO-Ptx-MODE-006). (src: L423-L429)
- **SPO-01sendLovelaces-INV-007** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005) with witness count 1; the dummy outputs are SPO-01sendLovelaces-EXT-001. (src: L436-L479)
- **SPO-01sendLovelaces-INV-008** Stage 7, balance: as Ptx (SPO-Ptx-EXT-003, SPO-Ptx-PRE-002, SPO-Ptx-PRE-003, SPO-Ptx-PRE-004) with the amount layouts SPO-01sendLovelaces-OUT-001 to SPO-01sendLovelaces-OUT-005 and the refusals SPO-01sendLovelaces-PRE-002 to SPO-01sendLovelaces-PRE-006, all exit 1. (src: L481-L554)
- **SPO-01sendLovelaces-INV-009** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003); output order SPO-01sendLovelaces-OUT-006. A build failure ends the script with cardano-cli's code. (src: L556-L575)
- **SPO-01sendLovelaces-INV-010** Stage 9, sign: as Ptx (SPO-Ptx-INV-008, SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Ptx-PRE-005, SPO-Ptx-EXT-006, SPO-Ptx-SEC-001); the change-output declaration is SPO-01sendLovelaces-EXT-002. (src: L583-L640)
- **SPO-01sendLovelaces-INV-011** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007), exit 1. (src: L648-L653)
- **SPO-01sendLovelaces-INV-012** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003), honouring `ENV_SKIP_PROMPT` (SPO-01sendLovelaces-PR-001). (src: L656-L658)
- **SPO-01sendLovelaces-INV-013** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010, SPO-Ptx-INV-010); the offline entry is SPO-01sendLovelaces-OUT-007. (src: L660-L707)

## Work modes

Per Ptx (SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-010) with these script-specific points.

- **SPO-01sendLovelaces-MODE-001** An ADA Handle destination works online and in light mode only: offline it is refused by SPO-Caddr-PRE-002 with exit 1. A file or literal destination works in every mode. (src: L181-L191)
- **SPO-01sendLovelaces-MODE-002** Offline, `utxolimit:`, `skiputxowithasset:` and `onlyutxowithasset:` are accepted but not applied, and the `txhash#index` list is applied (SPO-Pparam-IF-019 .. SPO-Pparam-IF-022). (src: L282-L289)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| "Does this look good for you, continue?" (SPO-Ptx-PR-002) | No | A "no" ends the script with exit 0 and nothing is submitted or queued. Skipped when `ENV_SKIP_PROMPT=YES` (SPO-Ptx-PR-003). |

- **SPO-01sendLovelaces-PR-001** The confirmation is asked after the size check and honours `ENV_SKIP_PROMPT`; it is the only prompt. (src: L656-L658)

## Outputs

- **SPO-01sendLovelaces-OUT-007** Offline, the signed transaction is appended to `transactions[]` of the transfer file with `type` `Transaction` and the fields `era`, `fromAddr` (the normalised source name), `sendFromAddr` (source bech32), `toAddr` (the destination as the script held it: the normalised file name, or `<tempDir>/tempTo` or `<tempDir>/adahandle-resolve` for a literal or an ADA Handle), `sendToAddr` (destination bech32) and `txJSON`. The history entry reads "signed utxo-transaction from '<from>' to '<to>'". The common mutations are SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012. (src: L684-L698)
- **SPO-01sendLovelaces-OUT-008** Online and light, the only effect on state is the submitted transaction. The script updates no non-secret file other than the temporary files below. (src: L662-L682)

**Upstream file contract** (all in `<tempDir>`, see SPO-Pfiles-OUT-039; modes are not managed, so the creating process's default applies):

| File | Content | Change |
| --- | --- | --- |
| `tempTo.addr` | the literal destination address, one line | replaced, literal destination only |
| `adahandle-resolve.addr` | the resolved handle address, one line | replaced, handle destination only |
| `<source>.transactionMessage.json` | CIP-20 or CIP-83 message metadata (SPO-Pparam-OUT-002) | replaced, when messages exist |
| `dummy.txbody` | body for the fee estimate | replaced |
| `<source>.txbody`, `.txwitness`, `.tx` | body, hardware witness, signed transaction | replaced; `.txwitness` on the hardware path only |
| `offlineTransfer.json` | gains one `Transaction` entry | updated, offline only |

## Failures

Only the refusals that differ from or refine Ptx's table are listed; the rest are in SPO-Ptx table "Failures".

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than three positional words | 1 | SPO-01sendLovelaces-IF-001 |
| Amount is not a keyword or digits | 1 | SPO-01sendLovelaces-IF-002 |
| Destination matches no form | 1 | SPO-01sendLovelaces-IF-005 |
| Handle resolution fails, or offline | 1 | SPO-01sendLovelaces-IF-007, SPO-01sendLovelaces-MODE-001 |
| UTxO query fails (online, light) | **0** | SPO-01sendLovelaces-PRE-001 |
| Minimum-value checks | 1 | SPO-01sendLovelaces-PRE-002 .. SPO-01sendLovelaces-PRE-006 |
| Confirmation declined | 0 | SPO-Ptx-PR-002 |

## Security

- **SPO-01sendLovelaces-SEC-001** The destination of a literal or ADA Handle send travels from the step that resolves it to the step that reads it through a fixed file name in the shared temporary directory (`tempTo.addr`, `adahandle-resolve.addr`). A second run, or another local user able to write there, can replace the file in between, and the funds then go to the replaced address. The summary printed before the confirmation shows the address that was read. (src: L179, L191, L229, L248)
- **SPO-01sendLovelaces-SEC-002** `ENV_SKIP_PROMPT=YES` removes the only check before an irreversible payment (SPO-Ptx-SEC-003). The signed transaction and the passphrase of an encrypted message are printed (SPO-Ptx-SEC-002, SPO-Pparam-SEC-001). (src: L417, L645, L658)

## Domain mapping

Use case `SendLovelaces(source, destination, amount, extras)` on the `PaymentAccount` aggregate of the wallet context, producing a `TxDraft` for `BuildAndSignTransaction` and `SubmitOrQueueTransaction` (SPO-Ptx). `Amount` is a closed type: `Lovelaces(n)`, `All`, `AllFunds`, `Min`. `Destination` is a value object resolved before the use case runs: `StoredAddress(name)`, `LiteralAddress(bech32)` or `AdaHandle(handle)`.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(Address)` | Source and destination address files |
| `Ledger` | `addressInfo(address)` | Destination type test, `check_address` |
| `Directory` | `resolveHandle(handle)` | ADA Handle destination (online and light) |
| `ChainQuery` | `utxos`, `protocolParameters`, `syncStatus` | Pipeline inputs |
| `Ledger` | `minOutputValue`, `minFee`, `buildRaw`, `assemble`, `txId` | Layouts and checks of this spec |
| `Signer` | `signTx`, `witness` | Key-file or hardware signing |
| `Submitter` / `Transport` | `submit`, `enqueueTx` | Online, light, offline |
| `UI` | `confirm` | The one prompt |

## Port notes

* Model the destination and the amount as types and resolve them once, in memory. Do not route the destination through a file: that removes SPO-01sendLovelaces-SEC-001 and the odd `toAddr` values of SPO-01sendLovelaces-OUT-007.
* Compute each output against its own minimum (fixes SPO-01sendLovelaces-PRE-003) and refuse non-numeric or zero-padded amounts at parse time (fixes the IF-002 quirk).
* Exit non-zero when the UTxO query fails (SPO-01sendLovelaces-PRE-001) and for every minimum-value refusal; upstream already exits 1 for the latter.
* Offer `ALL` and `MIN` to a destination that may receive assets as an explicit option; upstream keeps assets on the source in every form but `ALLFUNDS`.
* A remote signer or hardware wallet receives the body and the change-output declarations of SPO-01sendLovelaces-EXT-002 and returns a witness; the paying key stays out of the use case.

## Notes from the oracle (2026-11-16)

* Run offline against a recorded snapshot (`spo/test/parity/send_lovelaces_test.go`, `workbench -y exec 01_sendLovelaces.sh w d <amount>`), the queued transaction is byte-equal to the port's for an explicit amount with and without assets, `ALLFUNDS`, `ALL` without assets and a `msg:` message. `MIN` and `ALL` with assets differ in the two amounts they derive from the minimum output value, by exactly `2 * utxoCostPerByte`, for the reason given under SPO-Cutxo-INV-007 in Cutxo; fee, inputs and addresses are equal.
* `-y` on the `workbench` command line sets `ENV_SKIP_PROMPT=YES` (SPO-01sendLovelaces-PR-001); the offline entry carries `general.offlineCLI` `11.2.3.0`, the bare version number.
* **Port decisions** (each recorded in `spo/internal/app/wallet/send_lovelaces_test.go` and `spo/internal/domain/txbuild/txbuild_test.go`): a zero-padded amount is refused at parse time (IF-002 quirk); each output is compared with its own minimum (PRE-003 quirk); a destination file must hold a payment address (IF-008); a Byron destination is refused until the open question below is settled; an ADA Handle is refused with a typed error until Caddr is ported; a decline is `ErrDeclined`, never success; a network mismatch of either address is refused before any query.

## Open questions

* How `cardano-cli` reads an output amount with a leading zero (`+010`) in `build-raw`. If it reads decimal, the body of an octal-affected run does not balance and the node rejects it. A recorded `build-raw` run settles it.
* The minimum computed for a negative remainder in SPO-01sendLovelaces-PRE-006 depends on the encoder of SPO-Cutxo-INV-010 for a non-numeric amount. The refusal is expected in every case but is not settled by source.
* Whether `cardano-cli address info` reports Byron addresses as type `payment`, which would make a Byron literal a valid destination under SPO-01sendLovelaces-IF-004. A recorded `address info` on a Byron address settles it.
