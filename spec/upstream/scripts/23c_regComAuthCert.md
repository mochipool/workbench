+++
id = "23c"
kind = "script"
title = "Authorize a committee hot key with the cold key"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "transaction-construction", "key-custody"]
use_cases = ["AuthorizeCommitteeHotKey"]
depends_on = ["Cconf", "Cchain", "Clight", "Chw", "Ckey", "Cui", "Ctx", "Ptx", "Pparam", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/23c_regComAuthCert.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "e0a9718859089889504e3c1d3059bdaba3f48e7865791db77765661d9b630d3b"
upstream_lines = 669
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
  "governance committee create-hot-key-authorization-certificate",
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

# 23c_regComAuthCert: Authorize a committee hot key with the cold key

Submits the certificate that authorises a hot credential (from [23b](./23b_genComHotKeys.md)) to vote on behalf of a committee member identified by a cold credential (from [23a](./23a_genComColdKeys.md)). The certificate is built from the two verification keys and **signed by the cold key**, together with the payment key; the hot key is only named in the certificate and never signs here. Authorising a new hot key for a cold key that already has one replaces the authorisation on chain.

The script follows the Ptx pipeline (SPO-Ptx-IF-001, SPO-Ptx-MODE-001, SPO-Ptx-MODE-002, SPO-Ptx-MODE-003, SPO-Ptx-MODE-006 .. SPO-Ptx-MODE-009) with the variations below. **It does not support offline mode:** in offline mode it prints a notice and exits 0 before building anything, and it never queues a transaction (SPO-23c-MODE-001).

## Interface

- **SPO-23c-IF-001** Takes three positional arguments: the cold name (a trailing `.cc-cold` is dropped), the hot name (a trailing `.cc-hot` is dropped) and the paying address name (a trailing `.addr` is dropped), then extra parameters from the fourth word. Fewer than three arguments print usage on stderr and exit 1. (src: L21-L58, L68-L70, L91)
- **SPO-23c-IF-002** The extra parameters are metadata files, `msg:`, `enc:`, `pass:` and the ignored UTxO tokens (SPO-Pparam-IF-001, SPO-Pparam-IF-007). `url:` and `hash:` are not known here and would be refused as file words (SPO-Pparam-IF-005). (src: L91-L141)
- **SPO-23c-PRE-001** On a chain not yet in Conway era (configured era Shelley through Babbage) the script prints a notice and exits 0. (src: L60-L65)

## Inputs

- **SPO-23c-IN-001** Requires, each missing one exiting 1 before parameters are parsed: `<cold>.cc-cold.vkey`, `<cold>.cc-cold.skey` or `<cold>.cc-cold.hwsfile`, `<cold>.cc-cold.hash`, `<hot>.cc-hot.vkey`, `<hot>.cc-hot.hash`, `<pay>.addr`, and `<pay>.skey` or `<pay>.hwsfile`. The hot key needs no signing file. (src: L74-L82)
- **SPO-23c-IN-002** The cold hash is the content of `<cold>.cc-cold.hash` and the hot hash the content of `<hot>.cc-hot.hash`; the hot id shown is `bech32 cc_hot <hash>`, a legacy `cc_hot1...` id (see SPO-Cconv-OUT-019 for the CIP-129 form). (src: L184, L271-L274)

## Behaviour

1. **Parse parameters and write the message file.** As SPO-Pparam-IF-008 .. SPO-Pparam-OUT-002. In offline mode this still happens before the refusal below, so a message metadata file may be written and left behind. (src: L143-L176)
2. **Query the committee state of the cold key.**
   - **SPO-23c-EXT-001** Online: runs `cardano-cli <era> query committee-state --cold-verification-key-hash <cold hash>`; a failed query prints the error and exits **0** (status of the `echo` in `echo ...; exit $?`, L196; the light call at L203 does the same). (src: L192-L197)
     > **Upstream quirk:** a failed committee-state query looks like success to a caller. A port exits non-zero.
   - **SPO-23c-EXT-002** Light: calls `queryLight_committeeState` with the intended filter, but the script passes an undefined variable (`commColdHash` instead of `comColdHash`), so the filter is empty and the state lists every committee member. (src: L200-L204)
   - **SPO-23c-MODE-001** Offline: prints that offline mode is not supported yet ("waiting for Koios support") and exits **0**. Nothing is built, signed, queued or written (the exception is the message file of step 1). The branches that would queue a transaction of type `CommitteeAuthCertRegistration` (SPO-Ptransfer-INV-003) are unreachable. (src: L206, L638-L663)
3. **Interpret the state.**
   - **SPO-23c-INV-001** From the state the script reads the number of committee entries, and for the entry `keyHash-<cold hash>`: the authorised hot key hash, the authorisation tag, the expiry epoch, the status and the next-epoch change. A missing member reads as `-`. Only key-hash credentials are looked up; a script credential entry is not found. (src: L237-L242)
   - **SPO-23c-PRE-002** When the entry's authorisation tag is `MemberResigned` the script reports that a resigned cold key cannot be authorised again and exits **0**. (src: L250-L253)
   - **SPO-23c-INV-002** When the state has no entries the key is reported as not on chain and the script continues to authorise it; when it has entries the member is reported as registered and the current hot hash, status, expiry and next change are shown. Neither case stops the script. In light mode the unfiltered state makes the entry count non-zero for any non-empty committee, so a cold key that is not a member is displayed as registered with `-` values. (src: L245-L264)
   - **SPO-23c-PRE-003** When the authorised hot hash of the entry equals the hot hash of `<hot>.cc-hot.hash` the script reports that the same hot key is already authorised and exits **0** without building a transaction. (src: L275)
   - **SPO-23c-INV-003** The comparison reads only a `keyHash` hot credential; an authorised hot **script** credential is not seen, so it never equals the hot hash. (src: L242, L275)
4. **Build the certificate.**
   - **SPO-23c-EXT-003** Runs `cardano-cli <era> governance committee create-hot-key-authorization-certificate --cold-verification-key-file <cold>.cc-cold.vkey --hot-verification-key-file <hot>.cc-hot.vkey --out-file /dev/stdout`; a failure ends the script with its code. (src: L281-L282)
   - **SPO-23c-OUT-001** The certificate is written to `<hot>.cc-hot.cert` (unlock, write, lock 0400), replacing the previous one. The file is named after the **hot** key. A write failure exits 1. (src: L283-L286)
5. **Build, sign and submit** as in Ptx, with these variations:
   - **SPO-23c-INV-004** The body carries `--certificate <hot>.cc-hot.cert`; the witness count is 2 (payment key and cold key); the change output is `inputs - fee` with all assets, there is no deposit. (src: L493, L497, L509, L527)
   - **SPO-23c-PRE-004** Refuses with exit 0 when the change would be below the minimum output value (SPO-Ptx-PRE-002). (src: L515)
   - **SPO-23c-INV-005** The check of the paying address (`check_address`) is not followed by a failure test, so an invalid address stops the script only through the later query errors. (src: L303)
   - **SPO-23c-INV-006** Signing: if both the payer and the cold key are hardware files, one `cardano-hw-cli transaction witness` call with the cold hwsfile and the payment hwsfile (`--change-output-key-file` for a payment and staking hwsfile pair) writes `<pay>.txwitness-coldkey` and `<pay>.txwitness-payment`, assembled with cardano-cli; if both are key files, `cardano-cli transaction sign` with both. Any mix exits 1 ("a hardware wallet can only be used to register its own certificate"; SPO-Ptx-PRE-006). The hot key never signs. (src: L538-L596)
   - **SPO-23c-PR-001** After the size check (SPO-Ptx-PRE-007) asks "Does this look good for you?" with default **No**; `ENV_SKIP_PROMPT` is ignored (SPO-Ptx-PR-003). A refusal exits 0 and submits nothing. The certificate file stays. (src: L602-L610)
   - **SPO-23c-MODE-002** Online submits with `cardano-cli transaction submit`; a failure prints a message and exits with `$?` of the preceding `echo`, i.e. **0** (SPO-Ptx-MODE-008 names `06` and `08b` for this, `23c` and `23e` do it too). Light submits through Koios and likewise exits 0 on failure (SPO-Ptx-MODE-009). (src: L614-L635)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-23c-INV-007** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) with the files of SPO-23c-IN-001, and, specific to this script, the committee-state lookup, the state checks and the hot-key authorization certificate of steps 2 to 4 (SPO-23c-EXT-001 to SPO-23c-EXT-003, SPO-23c-MODE-001, SPO-23c-INV-001 to SPO-23c-INV-003, SPO-23c-PRE-002, SPO-23c-PRE-003, SPO-23c-OUT-001). (src: L19-L292)
- **SPO-23c-INV-008** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L294-L297)
- **SPO-23c-INV-009** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002); the payer address is read from `<pay>.addr` and its validation is not followed by a failure test (SPO-23c-INV-005). (src: L299-L344)
- **SPO-23c-INV-010** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L345-L475)
- **SPO-23c-INV-011** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read after the UTxO stage. (src: L477-L483)
- **SPO-23c-INV-012** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with the authorization certificate attached and witness count 2 (SPO-23c-INV-004). (src: L485-L503)
- **SPO-23c-INV-013** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with no deposit, so the change is `inputs - fee`, and exit 0 when it is too small (SPO-23c-PRE-004). (src: L505-L515)
- **SPO-23c-INV-014** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee and `--certificate <hot>.cc-hot.cert`. (src: L517-L531)
- **SPO-23c-INV-015** Stage 9, sign: the hardware path when payer and cold key are both hardware files, the key-file path when both are key files, and a refusal for a mix (SPO-23c-INV-006, SPO-Ptx-PRE-005, SPO-Ptx-PRE-006). (src: L533-L600)
- **SPO-23c-INV-016** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L602-L607)
- **SPO-23c-INV-017** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002), but `ENV_SKIP_PROMPT` is ignored (SPO-23c-PR-001, SPO-Ptx-PR-003). (src: L609-L610)
- **SPO-23c-INV-018** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010) with the exit codes of SPO-23c-MODE-002 and the unreachable queue block of the offline mode (SPO-23c-MODE-001). (src: L611-L665)

## Work modes

- **SPO-23c-MODE-003** Online: node-synced check, committee-state and UTxO queries from the node, node submit. Light: Koios for the unfiltered committee state, UTxOs and submit. Offline: unsupported, see SPO-23c-MODE-001. (src: L190-L214, L316-L336, L613-L665)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Does this look good for you (SPO-23c-PR-001) | No | No means exit 0, nothing submitted |

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<hot>.cc-hot.cert` | hot-key authorisation certificate envelope | `0400` | created or replaced, also when the prompt is declined |
| `<tempDir>/<pay>.transactionMessage.json` | message metadata (when `msg:` given) | default | created, also in offline mode before the refusal |
| Ptx working files | `dummy.txbody`, `<pay>.txbody`, `.txwitness-*`, `.tx` | default | replaced per run |

No entry is ever written to `offlineTransfer.json`.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than three arguments | 1 | SPO-23c-IF-001 |
| Pre-Conway era by configuration | 0 | SPO-23c-PRE-001 |
| Cold, hot or payer files missing | 1 | SPO-23c-IN-001 |
| Offline mode | 0 | SPO-23c-MODE-001 |
| Cold key already resigned | 0 | SPO-23c-PRE-002 |
| Same hot key already authorised | 0 | SPO-23c-PRE-003 |
| Not enough funds for the change output | 0 | SPO-23c-PRE-004 |
| Mixed hardware and key-file signers | 1 | SPO-23c-INV-006 |
| Submit failure (online or light) | 0 | SPO-23c-MODE-002 |
| Committee-state query failure | **0** (status of the `echo`) | SPO-23c-EXT-001, SPO-23c-EXT-002 |
| Funds, size and parameter refusals | per Ptx, Pparam | SPO-Ptx-PRE-001, SPO-Ptx-PRE-007, SPO-Pparam-PRE-003 |

> **Upstream quirk:** the light-mode filter variable is misspelled (SPO-23c-EXT-002). The effect is limited to the display of an unknown cold key, because the entry of the cold key is still found by its name in the full list.

> **Upstream quirk:** the offline queueing block (type `CommitteeAuthCertRegistration`, fields `comColdName`, `comHotName`, `fromAddr`, `sendFromAddr`, `toAddr`, `sendToAddr`, `txJSON`) is complete but unreachable, so no consumer of the transfer file knows this type. (src: L638-L663)

## Security

- **SPO-23c-SEC-001** The cold key signs; it is the member's long-term key and should be offline. A hardware or sealed cold key is read into memory only for signing (SPO-Ptx-SEC-001). (src: L577-L592)
- **SPO-23c-SEC-002** The final prompt cannot be skipped, but the script always exits 0 after a failed submission, which hides the failure from callers. (src: L614-L635)

## Domain mapping

Use case `AuthorizeCommitteeHotKey(cold, hot, payer, metadata?)` on aggregate `CommitteeMember` (hot authorisation: none, authorised(hot), resigned). Authorisation is replaced by a later one; `resigned` is terminal for the cold key.

| Port | Operation | Purpose |
| --- | --- | --- |
| `ChainQuery` | `committeeState(coldCredential)`, `utxos(address)`, `protocolParameters()`, `tip()` | Resigned check, same-hot check, inputs |
| `Ledger` | `makeCertificate(committeeHotAuthorization, {coldVkey, hotVkey})` | Certificate |
| `Ledger` | `buildRaw`, `minFee`, `minOutputValue`, `assemble` | Ptx body |
| `Store` | `put(HotAuthorizationCertificate)`, `get(CommitteeHash)` | Certificate file |
| `Signer` | `witness(body, keyRef)` x2 | Payment key, cold key (key file or hardware) |
| `Submitter` | `submit` | Online, light |
| `Transport` | `enqueueTx` | Not used upstream; a port should support it |
| `UI` | `confirm` | Final prompt |

## Port notes

* Observed 2026-11-16 (cardano-cli 11.2.3.0): the authorisation certificate is `83 0e 8200 581c<cold> 8200 581c<hot>` (type 14), the resignation `83 0f 8200 581c<cold> <anchor | f6>` (type 15); descriptions `Constitutional Committee Hot Key Registration Certificate` and `Constitutional Committee Cold Key Resignation Certificate`. Offline, 23c and 23e print that offline is not supported and exit 0 with nothing queued; the port returns `ErrOfflineUnsupported` (`TestGovOfflineRefusalsMatchUpstream`).

* Offline: the script refuses because the committee state cannot come from Koios into the transfer file. A port should add the committee state to the transfer snapshot (an `add-committee` counterpart of `add-drep`) and then queue the transaction like the DRep scripts.
* Return a non-zero code for a failed submission, and a distinct result for "already authorised" and "resigned".
* Look up script credentials as well as key hashes, and compare the hot credential by type.
* Keep the certificate in the store keyed by the pair (cold, hot), not by the hot name alone.

## Open questions

* The exact shape of `query committee-state --cold-verification-key-hash` for a key that is not a committee member (the upstream comment shows an entry with status `Unrecognized`, the filter then returns that entry). A real query settles whether SPO-23c-INV-002's "no entries" branch is reachable online.
* Whether the certificate for a cold key that is not yet a member is accepted by the ledger (authorisation before election). The Conway ledger rules settle it.
