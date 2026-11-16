+++
id = "21b"
kind = "script"
title = "Register or update a DRep on chain"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "transaction-construction", "key-custody", "air-gap-transfer"]
use_cases = ["RegisterOrUpdateDRep"]
depends_on = ["Cconf", "Cchain", "Clight", "Cconv", "Coffline", "Chw", "Ckey", "Cui", "Ctx", "Ptx", "Pparam", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/21b_regDRepCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "6ad7e67aa3810e00f5b1e72051f5ac0e85826f035f8e2a434ca833c297820b09"
upstream_lines = 844
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
  "governance drep registration-certificate",
  "governance drep update-certificate",
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

# 21b_regDRepCert: Register or update a DRep on chain

Registers a DRep (key created by [21a](./21a_genDRepKeys.md)) on chain, or, when the DRep is already registered, submits an update certificate that replaces its anchor. A registration locks the protocol's `dRepDeposit`; an update locks nothing. The optional anchor is a URL plus the BLAKE2b-256 hash of the JSON document at that URL (the CIP-100 governance metadata). The transaction is paid from a payment address and signed by the payment key and the DRep key.

The script follows the Ptx pipeline (SPO-Ptx-IF-001, SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-010) with the variations below. Requirements are given only for what differs.

## Interface

- **SPO-21b-IF-001** Takes two positional arguments: the DRep name (a trailing `.drep` is dropped) and the paying address name (a trailing `.addr` is dropped), then extra parameters. (src: L21, L70-L71)
- **SPO-21b-IF-002** Prints usage on stderr and exits 1 with fewer than two arguments. (src: L21-L60)
- **SPO-21b-IF-003** Extra parameters start at the third word (SPO-Pparam-IF-001) and accept the Pparam grammar: metadata files, `msg:`, `enc:`, `pass:`, plus `url:` and `hash:` (SPO-Pparam-IF-025, SPO-Pparam-IF-026). The UTxO tokens `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and a `hash#index` list are recognised and ignored (SPO-Pparam-IF-007). (src: L90-L152)
- **SPO-21b-PRE-001** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0 without doing anything. (src: L62-L67)

## Inputs

- **SPO-21b-IN-001** Requires `<drep>.drep.vkey` (exit 1 when missing) and `<drep>.drep.skey` or `<drep>.drep.hwsfile` (exit 1 when neither exists). The payer files `<pay>.addr` and `<pay>.skey` or `<pay>.hwsfile` are required as in SPO-Ptx-IN-002. All four checks run before any query or parameter parsing. (src: L75-L79)
- **SPO-21b-IN-002** Reads the protocol parameters of the work mode (SPO-Ptx-MODE-006) and from them `protocolVersion.major` and `dRepDeposit`. (src: L194-L218)
- **SPO-21b-IN-003** In offline mode reads `drep."<id>".drepStateJSON` of the transfer file, where `<id>` is the id derived from the vkey (SPO-Ptransfer-OUT-007). (src: L305-L306)

## Behaviour

1. **Check the era from the parameters.**
   - **SPO-21b-PRE-002** Exits 1 when `protocolVersion.major` is below 9 (before Conway). (src: L211-L213)
   - **SPO-21b-PRE-003** Exits 1 when `dRepDeposit` is absent or negative in the parameters. (src: L216-L218)
2. **Derive the DRep id.**
   - **SPO-21b-EXT-001** Runs `cardano-cli <era> governance drep id --drep-verification-key-file <drep>.drep.vkey --out-file /dev/stdout`; a failure ends the script with its code. The id is the bech32 text returned and is what later steps pass as `--drep-key-hash` and use as the transfer-file key. The `.drep.id` file is not read. (src: L221-L222)
3. **Resolve the anchor (online and light only).**
   - **SPO-21b-MODE-001** The anchor content is fetched only when the work mode is online or light and a `url:` was given. Offline mode never fetches and uses the `hash:` the operator supplied. (src: L225-L228)
   - **SPO-21b-EXT-002** The URL is fetched with `curl -sL -m 30` (redirects followed, 30 second limit), up to 5 attempts with a 1 second pause after a transport failure. An `ipfs://<path>` URL is fetched from `https://ipfs.io/ipfs/<path>`; the original `ipfs://` URL stays in the certificate. (src: L233-L243)
   - **SPO-21b-PRE-004** HTTP 404 is refused with exit 1 ("upload the file first"); any other status other than 200, and a transport failure after 5 attempts, exit 1. (src: L246-L275)
   - **SPO-21b-PRE-005** On 200 the body must parse as JSON, otherwise exit 1. (src: L254-L255)
   - **SPO-21b-EXT-003** The anchor hash is the 256-bit BLAKE2b digest (`b2sum -l 256`) of the downloaded bytes, computed on the file and not on any re-serialisation. (src: L256, L261)
   - **SPO-21b-INV-001** A `hash:` given together with a fetched `url:` is ignored: the computed hash always wins in online and light mode. (src: L260-L261)
   - **SPO-21b-PRE-006** After this step `url:` without a hash, and a `hash:` without a `url:`, are refused with exit 1. In offline mode this means both words are required together. (src: L284-L285)
4. **Read the DRep state and decide the kind.**
   - **SPO-21b-EXT-004** Online runs `cardano-cli <era> query drep-state --drep-key-hash <id> --include-stake` and takes element 0 of the result; light calls `queryLight_drepInfo <id>` (SPO-Clight-OUT-014, SPO-Clight-OUT-015) and takes element 0; offline takes the stored state. A failed query prints the error and exits **0** (the line is `echo ...; exit $?`, so the status is that of the `echo`; L295 online, L301 light). (src: L293-L308)
     > **Upstream quirk:** a failed DRep-state query looks like success to a caller. A port exits non-zero.
   - **SPO-21b-PRE-007** In offline mode an id that is absent from the transfer file prints "include it first online" and exits 0 without building anything. (src: L307)
   - **SPO-21b-INV-002** The state is empty (length 0) when the DRep is not registered: the kind is **registration** (REG). Any non-empty state, including an expired or inactive DRep, makes it an **update** (UPD). Nothing else is compared. (src: L313-L334)
5. **Build the certificate.**
   - **SPO-21b-EXT-005** REG: `cardano-cli <era> governance drep registration-certificate --drep-key-hash <id> --key-reg-deposit-amt <dRepDeposit> [--drep-metadata-url <url> --drep-metadata-hash <hash>] --out-file /dev/stdout`. (src: L343-L347)
   - **SPO-21b-EXT-006** UPD: `cardano-cli <era> governance drep update-certificate --drep-key-hash <id> [--drep-metadata-url <url> --drep-metadata-hash <hash>] --out-file /dev/stdout`, and the deposit used for the balance below is 0. (src: L356-L361)
   - **SPO-21b-INV-003** The anchor flags are passed only when a `url:` was given (and then always together with the hash). Without a `url:` the certificate carries no anchor, also for an update. (src: L346, L360)
   - **SPO-21b-OUT-001** The certificate is written to `<drep>.drep-reg.cert` (unlock, write, lock to 0400), replacing the previous one, for both kinds. A write failure exits 1. (src: L349-L352, L363-L366)
6. **Build, sign and submit** as in SPO-Ptx-EXT-001 .. SPO-Ptx-MODE-010, with these variations:
   - **SPO-21b-INV-004** The body carries one certificate, `--certificate <drep>.drep-reg.cert`; the fee is estimated with a witness count of 2 (payment key and DRep key). (src: L570, L574, L609)
   - **SPO-21b-INV-005** The single change output pays the paying address `inputs - fee - deposit` with all assets, where deposit is `dRepDeposit` for REG and 0 for UPD (SPO-Ptx-INV-007). (src: L591, L609)
   - **SPO-21b-PRE-008** Refuses with exit 0 when that change would be below the minimum output value (SPO-Ptx-PRE-002). The displayed "minimum funds" is `deposit + fee + minimum output`. (src: L584, L597)
   - **SPO-21b-INV-006** Signing uses the first matching form, tested in this order. Both on hardware: one `cardano-hw-cli transaction witness` call with the payment hwsfile then the DRep hwsfile (`--change-output-key-file` for the payment and staking hwsfile when a `.staking.hwsfile` exists next to the payer), assembled from the two witness files. Both key files: `cardano-cli transaction sign` with both keys. Payment on hardware and DRep key file: after the unrestricted-mode prompt, `--allow-unrestricted-mode` is added to the hardware witness and the DRep witness is made with cardano-cli, then assembled. Payment key file and DRep on hardware: the DRep witness comes from the device, the payment witness from cardano-cli. No other combination exists; an unmatched state prints "unknown combination" and exits 1. (src: L619-L771)
   - **SPO-21b-PR-001** In the hardware-payer and key-file-DRep form, asks "allow unrestricted-mode on your HW-Wallet to pay for the CLI DRep-ID cert?" (default **Yes**); declining exits 2. (src: L673-L678)
   - **SPO-21b-PRE-009** In that form a device answer containing `SECURITY` exits 1 with advice to enable the device's expert mode; `REJECTED`, `DISCONNECT` and `ERROR` exit 1; `WARNING` continues. In the other hardware forms `SECURITY` is not singled out. (src: L640-L651, L699-L716, L745-L756)
   - **SPO-21b-PR-002** The final confirmation is the Ptx prompt (default No, honoured `ENV_SKIP_PROMPT`; SPO-Ptx-PR-002, SPO-Ptx-PR-003). (src: L786)
   - **SPO-21b-OUT-002** Offline mode queues the signed transaction with `type` `DRepIDRegistration` and the extra fields `drepName`, `fromAddr`, `sendFromAddr`, `toAddr` (= `fromAddr`) and `sendToAddr`, plus a history entry (SPO-Ptransfer-OUT-010 .. SPO-Ptransfer-OUT-012). Online and light submit (SPO-Ptx-MODE-008, SPO-Ptx-MODE-009). (src: L790-L839)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-21b-INV-007** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the DRep and payer files of SPO-21b-IN-001, and, specific to this script, the DRep id, the anchor resolution, the DRep-state lookup and the certificate of steps 2 to 5 (SPO-21b-EXT-001 to SPO-21b-EXT-006, SPO-21b-OUT-001). (src: L19-L190, L219-L376)
- **SPO-21b-INV-008** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L378-L380)
- **SPO-21b-INV-009** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-21b-MODE-002); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002); the payer address is read from `<pay>.addr` and validated (SPO-Ptx-IN-001). (src: L382-L389, L397-L425)
- **SPO-21b-INV-010** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L427-L546)
- **SPO-21b-INV-011** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read before the UTxO stage, with the protocol-major and `dRepDeposit` checks of SPO-21b-PRE-002 and SPO-21b-PRE-003. (src: L192-L218)
- **SPO-21b-INV-012** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with the DRep certificate attached and witness count 2 (SPO-21b-INV-004). (src: L565-L576)
- **SPO-21b-INV-013** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with the deposit of SPO-21b-INV-005, and exit 0 when the change is too small (SPO-21b-PRE-008). (src: L578-L597)
- **SPO-21b-INV-014** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee, the deposit-reduced change and `--certificate <drep>.drep-reg.cert`. (src: L599-L613)
- **SPO-21b-INV-015** Stage 9, sign: the four forms of SPO-21b-INV-006, the unrestricted-mode prompt of SPO-21b-PR-001, the device-output classification of SPO-21b-PRE-009 and SPO-Ptx-PRE-005, with the combined refusal for an unknown combination. (src: L615-L775)
- **SPO-21b-INV-016** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L777-L782)
- **SPO-21b-INV-017** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003; SPO-21b-PR-002); `ENV_SKIP_PROMPT=YES` skips it. (src: L784-L786)
- **SPO-21b-INV-018** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010), with the queue entry of SPO-21b-OUT-002. (src: L788-L840)

## Work modes

- **SPO-21b-MODE-002** Online: node synced check, UTxO and parameter queries, node submit. Light: Koios for UTxOs, DRep state and submit; the anchor is still fetched directly from the operator's machine. Offline: UTxOs, parameters and DRep state from the transfer file (the DRep must have been added with `01_workOffline add-drep`), anchor hash taken from `hash:`, transaction queued. (src: L194-L208, L291-L309, L401-L422, L790-L839)
- **SPO-21b-MODE-003** In offline mode the REG/UPD decision uses the state as of the snapshot; a DRep registered after the snapshot is submitted as a second registration and fails on chain when executed. (src: L305-L334)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Allow unrestricted mode, hardware payer with key-file DRep (SPO-21b-PR-001) | Yes | No means exit 2 |
| Does this look good, continue (SPO-21b-PR-002) | No | No means exit 0, nothing submitted |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<drep>.drep-reg.cert` | registration or update certificate envelope | `0400` | created or replaced, also when the prompt is declined |
| `<tempDir>/DRepAnchorURLContent.tmp` | downloaded anchor content | default | created, deleted on success and on a non-JSON 200; left behind after 404 or another status |
| `<tempDir>/<pay>.txbody`, `.txwitness`, `.txwitness2`, `.tx`, `dummy.txbody`, `<pay>.transactionMessage.json` | Ptx working files (SPO-Ptx-OUT-003, SPO-Pparam-OUT-002) | default | replaced per run |
| `offlineTransfer.json` | queued transaction (offline only) | unchanged | updated |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments | 1 | SPO-21b-IF-002 |
| Pre-Conway era by configuration | 0 | SPO-21b-PRE-001 |
| DRep or payer files missing | 1 | SPO-21b-IN-001 |
| Protocol major below 9, `dRepDeposit` missing | 1 | SPO-21b-PRE-002, SPO-21b-PRE-003 |
| Anchor fetch failed, 404, not JSON | 1 | SPO-21b-PRE-004, SPO-21b-PRE-005 |
| `url:` without `hash:` or the reverse | 1 | SPO-21b-PRE-006 |
| Offline: DRep not in transfer file | 0 | SPO-21b-PRE-007 |
| Not enough funds for the change output | 0 | SPO-21b-PRE-008 |
| Unrestricted mode declined | 2 | SPO-21b-PR-001 |
| Hardware error, rejection, unknown combination | 1 | SPO-21b-PRE-009, SPO-21b-INV-006 |
| Bad `url:`/`hash:`, bad metadata, bad message, `enc:` other than `basic` | 1 | SPO-Pparam-IF-025, SPO-Pparam-IF-026, SPO-Pparam-PRE-003 |
| Funds, size and other Ptx refusals | per Ptx | SPO-Ptx-PRE-001, SPO-Ptx-PRE-007 |

## Security

- **SPO-21b-SEC-001** The script fetches an operator-supplied URL from the machine that runs it, following redirects, with no host allow-list and no size limit. The content is parsed only as JSON and hashed; it is never executed. In light mode too, the fetch comes from the operator's host, not from Koios. (src: L233-L262)
- **SPO-21b-SEC-002** The anchor hash binds the certificate to the bytes fetched at that moment; nothing later checks that the document stays the same. (src: L256-L261)
- **SPO-21b-SEC-003** Unrestricted mode lets the hardware device sign a transaction whose certificate it does not own; the prompt SPO-21b-PR-001 defaults to Yes. (src: L673-L678)
- **SPO-21b-SEC-004** `ENV_SKIP_PROMPT=YES` removes the final confirmation (SPO-Ptx-SEC-003). The DRep and payment keys are read into memory and passed through anonymous pipes (SPO-Ptx-SEC-001); the certificate and transaction files are not secret. (src: L660-L666, L786)

## Domain mapping

Use case `RegisterOrUpdateDRep(drep, payer, anchor?, metadata?)` on aggregate `DRep` (registration state: absent, registered with deposit and anchor).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `protocolParameters()`, `drepState(drepId)`, `utxos(address)`, `tip()` | Deposit, REG/UPD decision, inputs, TTL |
| `Directory` | `fetchUrl(anchorUrl)` | Anchor document (online, light) |
| `Ledger` | `anchorHash(bytes)` *(new)* | BLAKE2b-256 of the anchor bytes |
| `Ledger` | `makeCertificate(drepRegistration \| drepUpdate, params)` | Certificate |
| `Ledger` | `buildRaw`, `minFee`, `minOutputValue`, `assemble` | Ptx body |
| `Store` | `put(DRepRegistrationCertificate)`, `get(DRepVerificationKey)` | Certificate file |
| `Signer` | `witness(body, keyRef)` x2 | Payment key, DRep key (key file or hardware) |
| `Submitter` / `Transport` | `submit` / `enqueueTx` | Per work mode |
| `UI` | `confirm` | Unrestricted mode, final prompt |

## Port notes

* Separate the two meanings of the same file name: the certificate name `drep-reg.cert` serves both REG and UPD; a port should record the kind.
* Make the REG/UPD decision from the freshest state at submission time, not at build time, so an offline-built registration cannot become a duplicate.
* The update without an anchor drops the anchor on chain if the ledger treats a missing anchor as "clear". Ask the operator before an update that omits `url:` when a registered anchor exists.
* Fetch anchors with a size cap (as 21c does with 10 MB), a scheme allow-list and a redirect limit, and offer IPFS through a configured gateway.
* Multi-party signing: the DRep witness can be produced elsewhere (a hardware wallet or a remote signer) and merged; the payment and DRep witnesses are independent, as the mixed forms of SPO-21b-INV-006 already show.

## Open questions

* What an update certificate without anchor does on chain for the pinned ledger (clears versus keeps the anchor). The Conway ledger specification settles it.
* Whether `--include-stake` changes the shape of element 1 in a way the later `jq` expressions depend on; a real `query drep-state` on a registered DRep settles it.
