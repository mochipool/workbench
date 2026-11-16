+++
id = "23e"
kind = "script"
title = "Resign a committee cold key"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "transaction-construction", "key-custody"]
use_cases = ["ResignCommitteeColdKey"]
depends_on = ["Cconf", "Cchain", "Clight", "Cconv", "Chw", "Ckey", "Cui", "Ctx", "Ptx", "Pparam", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/23e_retComColdKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "30ed92e02e9ea75402f05513538c1bf53a6feeb95a9bd3e7b99720936fa229d7"
upstream_lines = 729
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
  "queryLight_committeeState",
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
  "governance committee create-cold-key-resignation-certificate",
  "query committee-state",
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
env_vars = []
+++

# 23e_retComColdKeys: Resign a committee cold key

Submits the resignation certificate of a committee member: the cold credential announces that it leaves the committee, with an optional anchor (a URL and the hash of a JSON document giving the reason). After the resignation the hot key authorised for this cold key stops being valid for votes, and [23c](./23c_regComAuthCert.md) refuses to authorise the cold key again. The cold key and the payment key sign.

The script follows the Ptx pipeline (SPO-Ptx-IF-001, SPO-Ptx-MODE-001, SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-006 .. SPO-Ptx-MODE-009) with the variations below. **It does not support offline mode:** in offline mode it prints a notice and exits 0 before building anything, and it never queues a transaction (SPO-23e-MODE-001).

## Interface

- **SPO-23e-IF-001** Takes two positional arguments: the cold name (a trailing `.cc-cold` is dropped) and the paying address name (a trailing `.addr` is dropped), then extra parameters from the third word. Fewer than two arguments print usage on stderr and exit 1. (src: L21-L60, L71-L72, L90)
- **SPO-23e-IF-002** The extra parameters are metadata files, `msg:`, `enc:`, `pass:`, `url:` and `hash:` (SPO-Pparam-IF-025, SPO-Pparam-IF-026), plus the ignored UTxO tokens (SPO-Pparam-IF-007). (src: L90-L152)
- **SPO-23e-PRE-001** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0. (src: L62-L67)

## Inputs

- **SPO-23e-IN-001** Requires `<cold>.cc-cold.vkey`, `<cold>.cc-cold.skey` or `<cold>.cc-cold.hwsfile`, `<cold>.cc-cold.hash`, `<pay>.addr`, and `<pay>.skey` or `<pay>.hwsfile`; each missing one exits 1 before the parameters are parsed. (src: L76-L81)
- **SPO-23e-IN-002** The cold hash is the content of `<cold>.cc-cold.hash`. (src: L196)

## Behaviour

1. **Parse parameters, write the message file.** As SPO-Pparam-IF-008 .. SPO-Pparam-OUT-002. In offline mode this still happens before the refusal, so a message metadata file may be left behind. (src: L156-L189)
2. **Query the committee state of the cold key.**
   - **SPO-23e-EXT-001** Online: `cardano-cli <era> query committee-state --cold-verification-key-hash <hash>`; light: `queryLight_committeeState <hash>` (SPO-Clight-IN-003); a failed query prints the error and exits **0** (status of the `echo` in `echo ...; exit $?`; L207 online, L213 light). (src: L204-L214)
     > **Upstream quirk:** a failed committee-state query looks like success to a caller. A port exits non-zero.
   - **SPO-23e-MODE-001** Offline: prints that offline mode is not supported yet ("waiting for Koios support") and exits **0**. Nothing is built, signed, queued or written (except the message file). The code that would queue a `CommitteeResignationCert` transaction (SPO-Ptransfer-INV-003) is unreachable. (src: L216, L699-L724)
   - **SPO-23e-OUT-001** The raw committee-state JSON is printed to stdout, pretty-printed, before any decision. It contains verification hashes and expiry data, no secrets. (src: L224)
3. **Decide.**
   - **SPO-23e-INV-001** The script reads the entry count and, for the entry `keyHash-<hash>`, the authorised hot hash, the expiry, the status and the next-epoch change. Only key-hash credentials are looked up. (src: L246-L250)
   - **SPO-23e-PRE-002** When the committee state has no entries the script reports that the key is not on chain and that there is nothing to retire, and exits **0**. No other state, including an already resigned key, stops the script; resigning twice is submitted again. (src: L252-L269)
4. **Resolve the anchor (online and light only).**
   - **SPO-23e-MODE-002** The anchor content is fetched only in online and light mode when a `url:` was given. The fetch, the retries, the `ipfs://` mapping, the 200/404 handling, the JSON requirement and the BLAKE2b-256 hash are those of SPO-21b-EXT-002, SPO-21b-PRE-004, SPO-21b-PRE-005, SPO-21b-EXT-003 and SPO-21b-INV-001, with the temporary file `<tempDir>/CommitteeAnchorURLContent.tmp`. A `hash:` given with a fetched `url:` is ignored. (src: L273-L329)
   - **SPO-23e-PRE-003** After this step `url:` without a hash and a `hash:` without a `url:` are refused with exit 1. (src: L333-L334)
5. **Build the certificate.**
   - **SPO-23e-EXT-002** Runs `cardano-cli <era> governance committee create-cold-key-resignation-certificate --cold-verification-key-file <cold>.cc-cold.vkey [--resignation-metadata-url <url> --resignation-metadata-hash <hash>] --out-file /dev/stdout`; a failure ends the script with its code. The anchor flags are passed only when a `url:` was given. (src: L341-L343)
   - **SPO-23e-OUT-002** The certificate is written to `<cold>.cc-cold-ret.cert` (unlock, write, lock 0400), replacing the previous one. A write failure exits 1. (src: L344-L347)
6. **Build, sign and submit** as in Ptx, with these variations:
   - **SPO-23e-INV-002** The body carries `--certificate <cold>.cc-cold-ret.cert`; the witness count is 2 (payment key and cold key); the change is `inputs - fee` with all assets, there is no deposit or refund. (src: L554, L558, L570, L588)
   - **SPO-23e-PRE-004** Refuses with exit 0 when the change would be below the minimum output value (SPO-Ptx-PRE-002). (src: L576)
   - **SPO-23e-INV-003** Signing is as in 23c: both hardware (cold and payment hwsfile; witness files `<pay>.txwitness-coldkey` and `<pay>.txwitness-payment`) or both key files; any mix exits 1 (SPO-23c-INV-006, SPO-Ptx-PRE-006). (src: L599-L657)
   - **SPO-23e-PR-001** After the size check (SPO-Ptx-PRE-007) asks "Does this look good for you?" with default **No**; `ENV_SKIP_PROMPT` is ignored (SPO-Ptx-PR-003). A refusal exits 0 and submits nothing. The certificate file stays. (src: L663-L671)
   - **SPO-23e-MODE-003** Online and light submit as in 23c (SPO-23c-MODE-002): a failure exits 0 in both modes. The failure message of the online branch wrongly says "make sure the pool is already registered". (src: L675-L696)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-23e-INV-004** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the files of SPO-23e-IN-001, and, specific to this script, the committee-state lookup, the decision, the anchor resolution and the resignation certificate of steps 2 to 5 (SPO-23e-EXT-001, SPO-23e-EXT-002, SPO-23e-MODE-001, SPO-23e-MODE-002, SPO-23e-INV-001, SPO-23e-PRE-002, SPO-23e-PRE-003, SPO-23e-OUT-001, SPO-23e-OUT-002). (src: L19-L352)
- **SPO-23e-INV-005** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L355-L358)
- **SPO-23e-INV-006** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-23e-MODE-004); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002); the payer address is read from `<pay>.addr` and validated (SPO-Ptx-IN-001). (src: L360-L402)
- **SPO-23e-INV-007** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L404-L536)
- **SPO-23e-INV-008** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read after the UTxO stage. (src: L538-L544)
- **SPO-23e-INV-009** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with the resignation certificate attached and witness count 2 (SPO-23e-INV-002). (src: L546-L565)
- **SPO-23e-INV-010** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with no deposit and no refund, so the change is `inputs - fee`, and exit 0 when it is too small (SPO-23e-PRE-004). (src: L566-L576)
- **SPO-23e-INV-011** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee and `--certificate <cold>.cc-cold-ret.cert`. (src: L578-L592)
- **SPO-23e-INV-012** Stage 9, sign: as 23c stage 9 (SPO-23e-INV-003, SPO-23c-INV-006, SPO-Ptx-PRE-005, SPO-Ptx-PRE-006). (src: L594-L660)
- **SPO-23e-INV-013** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L663-L668)
- **SPO-23e-INV-014** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002), but `ENV_SKIP_PROMPT` is ignored (SPO-23e-PR-001, SPO-Ptx-PR-003). (src: L670-L671)
- **SPO-23e-INV-015** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010) with the exit codes of SPO-23e-MODE-003 and the unreachable queue block of the offline mode (SPO-23e-MODE-001). (src: L672-L729)

## Work modes

- **SPO-23e-MODE-004** Online: node-synced check, committee-state and UTxO queries from the node, node submit. Light: Koios for committee state, UTxOs and submit. Offline: unsupported, see SPO-23e-MODE-001. The anchor is fetched in online and light mode from the operator's host. (src: L202-L222, L274, L675-L696)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Does this look good for you (SPO-23e-PR-001) | No | No means exit 0, nothing submitted |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<cold>.cc-cold-ret.cert` | cold key resignation certificate envelope | `0400` | created or replaced, also when the prompt is declined |
| `<tempDir>/CommitteeAnchorURLContent.tmp` | downloaded anchor content | default | deleted after a successful fetch; left behind after 404, another status or a non-JSON body |
| `<tempDir>/<pay>.transactionMessage.json`, Ptx working files | as in 23c | default | replaced per run |

No entry is ever written to `offlineTransfer.json`.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than two arguments | 1 | SPO-23e-IF-001 |
| Pre-Conway era by configuration | 0 | SPO-23e-PRE-001 |
| Cold or payer files missing | 1 | SPO-23e-IN-001 |
| Offline mode | 0 | SPO-23e-MODE-001 |
| Cold key not on chain | 0 | SPO-23e-PRE-002 |
| Anchor fetch failed, 404, not JSON | 1 | SPO-23e-MODE-002 |
| `url:` without `hash:` or the reverse | 1 | SPO-23e-PRE-003 |
| Not enough funds for the change output | 0 | SPO-23e-PRE-004 |
| Mixed hardware and key-file signers | 1 | SPO-23e-INV-003 |
| Submit failure (online or light) | 0 | SPO-23e-MODE-003 |
| Committee-state query failure | **0** (status of the `echo`) | SPO-23e-EXT-001 |
| Bad `url:`/`hash:`, metadata, message, `enc:` | 1 | SPO-Pparam-IF-025, SPO-Pparam-IF-026, SPO-Pparam-PRE-003 |

> **Upstream quirk:** the offline queueing block copies the history text and the field `comHotName` from 23c, although 23e has no hot name; since the block is unreachable the defect has no effect. (src: L699-L724)

> **Upstream quirk:** the state check does not look at `MemberResigned`; a resigned key is resigned again, which the ledger may reject, and the script then exits 0 after a failed submit. (src: L252-L269, L675-L696)

## Security

- **SPO-23e-SEC-001** The cold key signs; hardware or key-file handling is as in 23c (SPO-23c-SEC-001). The resignation is irreversible for the cold key, with no way to authorise it again from these scripts (SPO-23c-PRE-002), and the final prompt cannot be skipped. (src: L663-L671)
- **SPO-23e-SEC-002** The anchor URL is fetched from the operator's host following redirects, with no host allow-list and no size limit (SPO-21b-SEC-001). (src: L289)

## Domain mapping

Use case `ResignCommitteeColdKey(cold, payer, anchor?, metadata?)` on aggregate `CommitteeMember` (authorisation to resigned; terminal).

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `committeeState(coldCredential)`, `utxos(address)`, `protocolParameters()`, `tip()` | Membership check, inputs |
| `Directory` | `fetchUrl(anchorUrl)` | Anchor document |
| `Ledger` | `anchorHash(bytes)` *(new)* | BLAKE2b-256 of the anchor |
| `Ledger` | `makeCertificate(committeeColdResignation, {coldVkey, anchor?})` | Certificate |
| `Ledger` | `buildRaw`, `minFee`, `minOutputValue`, `assemble` | Ptx body |
| `Store` | `put(ResignationCertificate)`, `get(CommitteeHash)` | Certificate file |
| `Signer` | `witness(body, keyRef)` x2 | Payment key, cold key |
| `Submitter` | `submit` | Online, light |
| `Transport` | `enqueueTx` | Not used upstream; a port should support it |
| `UI` | `confirm` | Final prompt |

## Port notes

* Same offline and exit-code remarks as 23c: add the committee state to the transfer snapshot, queue the transaction offline, and return a non-zero code for a failed submission.
* Detect `MemberResigned` and report it as already done instead of submitting again.
* Show the hot key and its pending votes that the resignation invalidates, before the confirmation.
* Anchor handling is shared with 21b; a port should implement it once.

## Open questions

* What the ledger does with a second resignation of the same cold key. The Conway ledger rules settle whether the transaction is rejected.
