+++
id = "13b"
kind = "script"
title = "Send a poll answer signed by the pool cold key"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["community", "transaction-construction", "key-custody"]
use_cases = ["SubmitPollAnswer"]
depends_on = ["Ptx","Pparam","Ptransfer","Cutxo","Ckey","Chw","Cui"]

upstream_path = "cardano/testnet/13b_sendSpoPoll.sh"
variants = ["testnet"]
upstream_sha256 = "0121ff15beb191243df430706d74d4bbe56f04ffdbb87c0359a7b4cbfe0fc2f2"
upstream_lines = 722
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
  "key verification-key",
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

# 13b_sendSpoPoll: Send a poll answer, signed by the pool cold key

Sends a transaction that carries an SPO poll answer (the CBOR file produced by [13a](./13a_spoPoll.md)) and that the pool's cold key must also sign: the cold key's hash goes into the body's *required signers* and its witness is added. The transaction moves lovelace like [01_sendLovelaces](./01_sendLovelaces.md) (which this script is a modified copy of, adding a node key and a mandatory metadata file); on chain it is the pool operator's answer to the poll. Shipped only in the `testnet` script directory (the spec's `upstream_path` is the testnet path).

Follows the Ptx pipeline (SPO-Ptx-MODE-001 .. SPO-Ptx-MODE-010) and the 01_sendLovelaces behaviour (SPO-01sendLovelaces-IF-002, SPO-01sendLovelaces-IF-004 .. SPO-01sendLovelaces-IF-008, SPO-01sendLovelaces-OUT-001 .. SPO-01sendLovelaces-OUT-006, SPO-01sendLovelaces-EXT-001 .. SPO-01sendLovelaces-PRE-006, SPO-01sendLovelaces-MODE-001 .. SPO-01sendLovelaces-PR-001) for the amount keywords, the destination forms, outputs and minimum-value checks; this spec lists only the differences.

## Interface

- **SPO-13b-IF-001** Takes at least four positional words: the paying address name, the destination (address file, literal payment address or ADA Handle), the amount (`ALL`, `ALLFUNDS`, `MIN` or lovelaces, as SPO-01sendLovelaces-IF-002) and the pool name. Fewer print usage to stderr and exit 1. (src: L20-L24, L26-L72, L74-L75)
- **SPO-13b-IF-002** The pool name is normalised by removing an optional `.skey` and then an optional `.node`, with the directory part kept: `mypool`, `mypool.node` and `mypool.node.skey` name the same pool. The files used are `<pool>.node.skey`. (src: L24)
- **SPO-13b-IF-003** Extra parameters start at the **fifth** word and follow `Pparam` with the full acceptance row of 01_sendLovelaces (SPO-01sendLovelaces-IF-003): metadata files, a UTxO list, `msg:`, `enc:`, `pass:`, `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:`. (src: L84-L169)

## Inputs

- **SPO-13b-IN-001** Requires `<pay>.addr` and `<pay>.skey` or `<pay>.hwsfile` (exit 1 when missing), then `<pool>.node.skey` (exit **2** when missing). A hardware-wallet cold key (`<pool>.node.hwsfile`) is not supported: only the key-file form is accepted. The checks run after the extra parameters were validated. (src: L172-L178)
- **SPO-13b-IN-002** The pool cold signing key is read into memory with `read_skeyFILE` (an encrypted key asks for its password, see `Ckey`); a failure exits 1. It is read before the body is built, after the amount and balance checks. (src: L566-L568)

## Behaviour

1. **Require a metadata file.**
   - **SPO-13b-PRE-001** The transaction must carry at least one metadata **file** (`.json` or `.cbor`, SPO-Pparam-IF-014, SPO-Pparam-IF-015); messages given with `msg:` do not count. When none was given the script exits **2** ("please attach your SPO-Poll-Answer metadata file"). The check runs in the summary step, after the UTxOs of the paying address have been queried and listed, and before the protocol parameters are read. The file's content is not checked to be a poll answer. (src: L420-L424)
2. **Derive the required signer.**
   - **SPO-13b-EXT-001** The required-signer hash is the BLAKE2b-224 digest (28 bytes, hex) of the cold key's public key: `cardano-cli key verification-key` on the in-memory key, `cborHex` minus its first four characters, hashed. This equals the pool id in hex. It is displayed as "Pool-ID". (src: L569-L570)
3. **Build, fee, balance.**
   - **SPO-13b-EXT-002** Both the dummy and the final body are built with `--required-signer-hash <hash>` in addition to the 01_sendLovelaces arguments (SPO-Ptx-EXT-001, SPO-Ptx-EXT-004). The dummy uses a fixed placeholder hash of 56 decimal digits `1234...56`, which has the same length as a real hash. (src: L476-L482, L579-L582)
   - **SPO-13b-INV-001** The fee estimate uses witness count **2**: the payment key and the pool cold key. (src: L487)
   > **Upstream quirk:** the fee command is piped into `awk`, so its failure is not detected; a failed estimate leaves an empty fee instead of exiting (SPO-Ptx-EXT-002 says it exits 1). Several `checkError` calls that 01_sendLovelaces makes after the minimum-output computations are also absent. A port checks every step.
   - **SPO-13b-INV-002** All other amounts, minimum-value refusals and the output layout are those of SPO-01sendLovelaces-OUT-001 .. SPO-01sendLovelaces-PRE-006. Typical use sends `MIN` (or a small amount) back to the same address, so the transaction only carries the answer. (src: L434-L557)
4. **Sign.**
   - **SPO-13b-EXT-003** *Key-file payment key:* signs with `cardano-cli transaction sign --signing-key-file <pay> --signing-key-file <cold>` using in-memory keys, then unsets both. (src: L636-L646)
   - **SPO-13b-EXT-004** *Hardware payment key:* the body is canonicalised (`autocorrect_TxBodyFile`), the hardware session started, and the payment witness made with `cardano-hw-cli transaction witness` (with `--change-output-key-file` for the payment and stake hwsfile when the transaction has two outputs and the stake hwsfile exists, SPO-01sendLovelaces-EXT-002). Output matching `ERROR` or `DISCONNECT` exits 1. The cold-key witness is then made with `cardano-cli transaction witness` from the in-memory key into `<tempDir>/<pool>.txnodewitness`, and the transaction is assembled from the body and the two witnesses. A key-file cold key with a hardware payment key is therefore **allowed** here, unlike the mixed combinations refused by SPO-Ptx-PRE-006. (src: L594-L632)
   - **SPO-13b-SEC-001** In the hardware path the in-memory cold key is not unset after use, unlike the key-file path; it stays in shell memory until the script ends. (src: L625-L646)
5. **Size check, confirmation, submit or queue.** Per SPO-Ptx-PRE-007 and SPO-Ptx-PR-002; `ENV_SKIP_PROMPT=YES` skips the confirmation. The queued entry has `type` `Transaction` and the history text `signed utxo-transaction from '<from>' to '<to>'`. (src: L657-L664, L694-L702)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-13b-INV-003** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-001, SPO-Ptx-IN-002) and 01_sendLovelaces (SPO-01sendLovelaces-IF-001 and its argument rules), with the pool name and the extra parameters from the fifth word (SPO-13b-IF-001 to SPO-13b-IF-003, SPO-13b-IN-001, SPO-13b-IN-002). (src: L19-L242)
- **SPO-13b-INV-004** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L247-L249)
- **SPO-13b-INV-005** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001, SPO-13b-MODE-001, SPO-13b-EXT-005); a failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002). (src: L260-L300)
- **SPO-13b-INV-006** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L302-L433)
- **SPO-13b-INV-007** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read after the UTxO stage. (src: L435-L442)
- **SPO-13b-INV-008** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001 to SPO-Ptx-EXT-003, SPO-Ptx-INV-005) with the placeholder required-signer hash and witness count 2 (SPO-13b-EXT-002, SPO-13b-INV-001). (src: L474-L490)
- **SPO-13b-INV-009** Stage 7, balance: as 01_sendLovelaces, including the amount keywords and minimum-value refusals (SPO-13b-INV-002, SPO-Ptx-PRE-002, SPO-Ptx-PRE-003, SPO-Ptx-PRE-004). (src: L444-L472, L492-L557)
- **SPO-13b-INV-010** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004, SPO-Ptx-OUT-003) with the real fee and the real required-signer hash derived from the in-memory cold key (SPO-13b-EXT-001, SPO-13b-EXT-002). (src: L559-L587)
- **SPO-13b-INV-011** Stage 9, sign: key-file path with both the payment and the cold key, or the hardware path with the payment witness from the device and the cold-key witness in memory (SPO-13b-EXT-003, SPO-13b-EXT-004, SPO-13b-SEC-001, SPO-Ptx-PRE-005, SPO-Ptx-INV-009). (src: L588-L651)
- **SPO-13b-INV-012** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L654-L659)
- **SPO-13b-INV-013** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003); `ENV_SKIP_PROMPT=YES` skips it. (src: L662-L664)
- **SPO-13b-INV-014** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010), with the queue entry of type `Transaction`. (src: L664-L722)

## Work modes

- **SPO-13b-MODE-001** As 01_sendLovelaces (SPO-01sendLovelaces-MODE-001, SPO-01sendLovelaces-MODE-002, SPO-Ptx-MODE-008 .. SPO-Ptx-MODE-010). Offline mode queues the signed transaction as type `Transaction` (SPO-Ptransfer-OUT-010); the cold key therefore has to be present on the offline machine, which is the expected place for it. (src: L269-L285, L664-L722)
- **SPO-13b-EXT-005** The online UTxO query and the fee and txid calls omit `--output-text`, which the other scripts pass; behaviour relies on the text format being the pinned cardano-cli default. (src: L269, L487, L676)

## Prompts

As SPO-Ptx-PR-002 (default No, `ENV_SKIP_PROMPT` honoured) and the key password prompts of `Ckey` for an encrypted payment or cold key. No other prompt.

## Outputs

As 01_sendLovelaces (SPO-01sendLovelaces-OUT-007, SPO-01sendLovelaces-OUT-008), plus `<tempDir>/<pool>.txnodewitness` in the hardware path. No workspace file is changed.

## Failures

As 01_sendLovelaces, with:

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than four positional words | 1 | SPO-13b-IF-001 |
| `<pool>.node.skey` missing | 2 | SPO-13b-IN-001 |
| No metadata file attached | 2 | SPO-13b-PRE-001 |
| Cold key unreadable or wrong password | 1 | SPO-13b-IN-002 |
| Hardware error or disconnect | 1 | SPO-13b-EXT-004 |

## Security

- **SPO-13b-SEC-002** Uses the pool **cold signing key**, the most sensitive pool key, on a machine that also runs cardano-cli online in `online` and `light` modes. The key is decrypted and held in memory and handed to cardano-cli through an anonymous pipe (SPO-Ptx-SEC-001); it is never printed. The operator should run this offline, queue the transaction, and submit it from an online machine. (src: L566-L568, L626, L642)
- **SPO-13b-SEC-003** A poll answer is public and attributable to the pool id; a signed answer cannot be withdrawn, though a later one may supersede it depending on the poll's rules. (src: L569-L582)

## Domain mapping

Use case `SubmitPollAnswer(payer, destination, amount, pool, answerFile)` on aggregate `PollResponse`; the payment part is the shared pipeline (`BuildAndSignTransaction`, `SubmitOrQueueTransaction`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `buildRaw(txSpec with requiredSigners, metadata)`, `keyHash(vkey)` *(new)* | Body with the cold key as required signer |
| `Vault` | `unseal(coldKeyRef)`, `unseal(paymentKeyRef)` | In-memory keys |
| `Signer` | `witness(body, paymentKey)`, `witness(body, coldKey)` | Two witnesses |
| `ChainQuery` / `Submitter` / `Transport` | as Ptx | Per mode |
| `Store` | `get(PollAnswerCbor)` | Metadata file |

## Port notes

* The cold key witness is independent of the payment witness: a remote or multi-party signer can have the pool operator sign the required-signer witness on an air-gapped machine while another party pays and submits.
* Accept a hardware cold key, validate that the attached metadata is a CIP-94 answer for the intended question, and do not require a file when the answer is supplied by the use case.
* Check the fee estimate and the minimum-output computations explicitly (SPO-13b-INV-001), and unset the cold key in every path (SPO-13b-SEC-001).
* Run the metadata check (SPO-13b-PRE-001) before any chain query, so a missing answer costs nothing.

## Open questions

* The structure of a valid CIP-94 answer transaction on chain (whether the required-signer hash must equal the pool id, and whether other required signers are allowed) is the poll specification's rule; the script only shows it is the cold key hash.
