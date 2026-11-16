+++
id = "24b"
kind = "script"
title = "Submit governance votes"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["governance", "transaction-construction", "key-custody", "chain-access", "air-gap-transfer"]
use_cases = ["SubmitVotes"]
depends_on = ["Cconf", "Cchain", "Clight", "Cutxo", "Cconv", "Coffline", "Chw", "Ckey", "Cui", "Ctx", "Ptx", "Pparam", "Pfiles", "Ptransfer"]

upstream_path = "cardano/mainnet/24b_regVote.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "0c824ebf8380d58b0cd00195fd88776a43d0d9f47316e3e5e0f8271cd407aae8"
upstream_lines = 786
uses_common = [
  "ask",
  "autocorrect_TxBodyFile",
  "byteLength",
  "calc_minOutUTXO",
  "checkError",
  "check_address",
  "convertToADA",
  "convert_actionUTXO2Bech",
  "convert_assetNameHEX2ASCII",
  "convert_assetNameHEX2ASCII_ifpossible",
  "convert_tokenName2BECH",
  "exists",
  "generate_UTXO",
  "get_currentSync",
  "get_currentTip",
  "queryLight_UTXO",
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
  "governance vote view",
  "key verification-key",
  "query protocol-parameters",
  "query utxo",
  "transaction assemble",
  "transaction build-raw",
  "transaction calculate-min-fee",
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

# 24b_regVote: Submit governance votes

Puts one or more vote files (made by [24a](./24a_genVote.md)) on chain. The script builds a transaction that carries the votes, pays its fee from one payment address, has it witnessed by the **voter key** (DRep, committee hot or pool cold key) and by the payment key, and submits it. There is no deposit and no certificate. All votes in one run must come from the same voter and target different actions.

It follows the shared pipeline (SPO-Ptx-*, see the 24b rows of its tables A and B) with the variations below. Requirements already given there are not repeated.

## Interface

- **SPO-24b-IF-001** Takes at least three positional arguments: the voter name, the paying address name, then one or more extra words. With fewer than three it prints usage to stderr and exits 1. (src: L21-L58)
- **SPO-24b-IF-002** The voter argument, with a trailing `.` dropped, names the signing file by stem: `<voter>.skey` or `<voter>.hwsfile` where the stem already ends `.drep`, `.cc-hot` or `.node`, or `<name>.drep|cc-hot|node` plus `.skey`/`.hwsfile` when only the bare name is given. A `.vkey` suffix on the argument is dropped; the base name has `.drep`, `.cc-hot`, `.node`, `.skey` and `.hwsfile` stripped in turn. (src: L72-L74)
- **SPO-24b-IF-003** The paying address is a name `<pay>` or `<pay>.addr`. (src: L77)
- **SPO-24b-IF-004** Extra words (from the third argument on) follow SPO-Pparam-IF-001 to SPO-Pparam-IF-016 with the 24b column of the acceptance table: file words (`.json`, `.cbor` metadata, and `.vote` files, SPO-Pparam-IF-017), `msg:`, `enc:`, `pass:`; the keys `utxolimit:`, `skiputxowithasset:`, `onlyutxowithasset:` and a UTxO list are recognised and ignored. A file word that does not exist or whose extension is none of `json`, `cbor`, `vote` exits 1. (src: L162-L287)
- **SPO-24b-IF-005** A `.vote` file is read with `cardano-cli <era> governance vote view --output-json --vote-file <file>`; failure to read exits 1. From the first voter entry the script takes the voter key (`committee-…`, `drep-…` or `stakepool-…`, the hash after the last dash), the action id `<txid>#<ix>`, the anchor URL and data hash when present, and the decision (`VoteYes`, `VoteNo`, `Abstain`; other values are shown as unknown but not rejected), and from the file itself the `description`. The votes are attached to the body in the order given, as `--vote-file <file>`. Only the first entry of a file is examined. (src: L185-L252)

## Inputs

- **SPO-24b-IN-001** The voter signing file is the first that exists, in this order: `<voter>.skey` (type DRep, Committee-Hot or Pool by the stem ending, any other ending exits 1), `<voter>.hwsfile` (the hardware types, same rule), then `<name>.drep.skey`, `<name>.drep.hwsfile`, `<name>.cc-hot.skey`, `<name>.cc-hot.hwsfile`, `<name>.node.skey`, `<name>.node.hwsfile`; if none exists it exits 1. A key file wins over a hardware file for the same stem. See SPO-Pfiles-OUT-004, SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-024, SPO-Pfiles-OUT-026. (src: L80-L142)
- **SPO-24b-IN-002** The paying address needs `<pay>.addr` and `<pay>.skey` or `<pay>.hwsfile`, exit 1 before any query if one is missing (SPO-Ptx-IN-002). (src: L145-L146)
- **SPO-24b-IN-003** Settings read are those of SPO-Ptx-IN-003. `ENV_SKIP_PROMPT` is honoured (SPO-Ptx-PR-003). (src: L359, L728)

## Behaviour

1. **Era gate.**
   - **SPO-24b-PRE-001** For the eras `babbage`, `alonzo`, `mary`, `allegra`, `shelley` the script says that the chain is not yet in Conway and exits 0. (src: L61-L65)
   - **SPO-24b-PRE-002** When the protocol major version of the parameters (SPO-Ptx-MODE-006) is below 9 it exits 1: the era does not support votes. DReps are not blocked in the bootstrap phase here. (src: L330-L353)
2. **Validate the vote files** (while the words are read, before any chain access).
   - **SPO-24b-PRE-003** The voter type of each vote file must fit the signing key's type: the key's type name must contain `Committee`, `DRep` or `Pool` as taken from the vote's voter prefix `committee`, `drep`, `stakepool`; an unknown prefix or a mismatch exits 1. A hardware key counts as its plain type. (src: L207-L214)
   - **SPO-24b-PRE-004** All vote files must carry the same voter hash, otherwise exit 1. (src: L240-L242)
   - **SPO-24b-PRE-005** An action id may appear in only one vote file of the run, otherwise exit 1. (src: L245-L246)
   - **SPO-24b-INV-001** No check is made against chain state: the action may be unknown or expired, the voter unregistered, or the vote a repeat. A node, Koios or the later submission rejects such a transaction. Nor is the number of vote files checked: with none, the body carries no vote and the run ends at the voter-key check of SPO-24b-PRE-008 with a message about a wrong key. (src: L185-L252, L612, L687)
3. **Hardware unrestricted mode.**
   - **SPO-24b-PR-001** When more than one vote file is given and the payment key or the voter key is a hardware file, asks whether to allow `--allow-unrestricted-mode` on the device to sign several proposals at once, default **Yes**. On yes the flag is passed to the body autocorrection (SPO-Ctx-IF-001) and to every `cardano-hw-cli transaction witness` call. On no the script prints an abort notice and exits **2**. With a single vote the flag is not used. (src: L289-L294, L595, L620, L651)
4. **Messages and metadata.** As in SPO-Pparam-OUT-001, SPO-Pparam-OUT-002 and the `enc:`/`pass:` rules (SPO-Pparam-IF-010 to SPO-Pparam-IF-012, SPO-Pparam-PRE-003); the message file is `<tempDir>/<pay>.transactionMessage.json`. (src: L257-L326)
5. **Gather inputs, fee and balance.** The slot, TTL, UTxO gathering per work mode, totals and assets, parameters, dummy body, fee and change follow SPO-Ptx-MODE-001 to SPO-Ptx-MODE-007, SPO-Ptx-EXT-001, SPO-Ptx-EXT-002 and SPO-Ptx-INV-007, with these specifics: (src: L358-L586)
   - **SPO-24b-OUT-001** There is a single output, back to the paying address, with all input assets and `inputs - fee` lovelaces; nothing is deposited or withdrawn. Both the dummy body (fee 200000) and the final body carry the same metadata and `--vote-file` parameters. (src: L544-L550, L567, L575-L586)
   - **SPO-24b-INV-002** The witness count for the fee is the constant 2 (SPO-Ptx-INV-006), whatever the number of votes. (src: L553)
   - **SPO-24b-PRE-006** When `inputs - fee` is below the minimum output value of the change (SPO-Ptx-EXT-003) the script says so and ends with exit **0** (SPO-Ptx-PRE-002). (src: L544, L572-L573)
   - **SPO-24b-PRE-007** The UTxO set must not be empty (exit 1, SPO-Ptx-PRE-001) and in offline mode the payment address must be in the transfer file (exit 1, SPO-Ptx-MODE-004). (src: L396-L404)
6. **Canonical body for hardware.** When the payment key or the voter key is hardware, the body is rewritten in canonical hardware form, with the unrestricted flag of SPO-24b-PR-001, as in SPO-Ptx-EXT-005 step 1 and SPO-Ctx-IF-001. (src: L591-L600)
7. **Sign.** Exactly one of four combinations, selected by the payment key and the voter key. Witness slot order for assembly is voter, then payment. Two witness files are created, `<tempDir>/<voter file name>.vote_txwitness` and `<tempDir>/<pay>.pay_txwitness`. (src: L575-L708)
   - **SPO-24b-EXT-001** *Payment hardware, voter hardware.* Checks the hardware voter file (SPO-24b-PRE-008), warns that both must be on the same device, asks "adding the payment and voter witness from a local hardware wallet, continue?" (default Yes, no exits 2), starts the Ledger session (SPO-Chw-IF-001 with vendor `Ledger`), and runs one `cardano-hw-cli transaction witness` with both signing files, `--change-output-key-file <pay>.hwsfile`, the network option, and two `--out-file` options (payment witness, voter witness). (src: L608-L638)
   - **SPO-24b-EXT-002** *Payment key file, voter hardware.* Checks the hardware voter file (SPO-24b-PRE-008), asks "adding the voter witness from a local hardware wallet, continue?" (default Yes, no exits 2), starts the Ledger session, produces the voter witness with `cardano-hw-cli`, then reads the payment key into memory (SPO-Ptx-EXT-006) and produces the payment witness with `cardano-cli transaction witness`. (src: L641-L677)
   - **SPO-24b-EXT-003** *Payment key file, voter key file.* Reads the voter key into memory, checks it (SPO-24b-PRE-008), witnesses with `cardano-cli transaction witness`, then does the same for the payment key. A read failure exits 1. (src: L680-L702)
   - **SPO-24b-PRE-008** The voter key must match the voter hash of the vote files, otherwise exit 1 with a message that the signing file is not the one for that hash. For a hardware voter file the hash is blake2b-224 of the key bytes in `cborXPubKeyHex` (after the 2-byte header); for a key file it is derived from the signing key with `cardano-cli key verification-key`. An empty derived hash passes the check. (src: L610-L614, L643-L647, L685-L690)
   - **SPO-24b-PRE-009** *Payment hardware, voter key file.* Refused with exit 1 before any witness is made (SPO-Ptx-PRE-006): the script prints that, with a hardware payment, the voter must also sign on the same hardware wallet, or the payment must come from a key-file wallet. The signing chain has four branches, payment hardware with voter hardware, payment key file with voter hardware, payment key file with voter key file, and this `else` that refuses; every other branch writes both witness files before `assemble`, so stale witnesses are never used. (src: L705-L708, L576-L577)
     > **Upstream quirk:** the `rm ${txWitnessFile}` and `rm ${txWitnessFile2}` before signing name variables that are never set, so they remove nothing. This is harmless, because the refusal above and the witness writing of the other branches leave no way to assemble stale files.
   - **SPO-24b-PRE-010** The output of `cardano-hw-cli` is classified as in SPO-Ptx-PRE-005; in addition `SECURITY` stops the script with exit 1, with the advice to enable expert mode on the device when unrestricted mode was requested, and otherwise reporting that the device declined for security reasons. (src: L621-L638, L652-L669)
8. **Assemble.**
   - **SPO-24b-EXT-004** The signed transaction is `cardano-cli <era> transaction assemble --tx-body-file <body> --witness-file <voter witness> --witness-file <payment witness> --out-file <tx>`; a failure exits with its code. (src: L711-L713)
9. **Size, confirm, submit.** As SPO-Ptx-PRE-007, SPO-Ptx-PR-002, SPO-Ptx-PR-003 (`ENV_SKIP_PROMPT=YES` skips it), SPO-Ptx-INV-010, with the work-mode behaviour below. (src: L719-L784)

## Pipeline stage map

This script follows the shared pipeline [`Ptx`](../patterns/Ptx.md). One requirement per stage, with this script's own lines.

- **SPO-24b-INV-003** Stage 1, prepare: as Ptx (SPO-Ptx-IF-001, SPO-Ptx-IN-002), with the voter-file, vote-file and message handling of SPO-24b-IF-002 to SPO-24b-IF-005 and SPO-24b-PRE-003 to SPO-24b-PRE-005; the paying address is read from `<pay>.addr` and validated, and is also the single output address (SPO-Ptx-IN-001). (src: L19-L326, L365-L368)
- **SPO-24b-INV-004** Stage 2, clock: as Ptx (SPO-Ptx-MODE-001, SPO-Ptx-INV-001), TTL is `slot + defTTL`. (src: L358-L361)
- **SPO-24b-INV-005** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-002 to SPO-Ptx-MODE-004, SPO-Ptx-PRE-001), but without the `utxolimit`, `skiputxowithasset` and `onlyutxowithasset` filters (SPO-24b-IF-004). A failing online or light UTxO query exits 0 (SPO-Ptx-MODE-002). (src: L374-L404)
- **SPO-24b-INV-006** Stage 4, collect assets: as Ptx (SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-MODE-005). (src: L406-L522)
- **SPO-24b-INV-007** Stage 5, parameters: as Ptx (SPO-Ptx-MODE-006), read before the UTxO stage, with the protocol-major check of SPO-24b-PRE-002. (src: L330-L353)
- **SPO-24b-INV-008** Stage 6, dummy body and fee: as Ptx (SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005), with the vote files attached and witness count 2 (SPO-24b-INV-002). (src: L544-L555)
- **SPO-24b-INV-009** Stage 7, balance: as Ptx (SPO-Ptx-INV-007, SPO-Ptx-PRE-002) with no deposit and no withdrawal, so the change is `inputs - fee` (SPO-24b-OUT-001, SPO-24b-PRE-006). (src: L560-L573)
- **SPO-24b-INV-010** Stage 8, final body: as Ptx (SPO-Ptx-EXT-004) with the real fee and the same votes and metadata. (src: L575-L588)
- **SPO-24b-INV-011** Stage 9, sign: not the Ptx single-signer form. The body is canonicalised for hardware (SPO-24b-PR-001, SPO-Ptx-EXT-005 step 1), a voter witness and a payment witness are made in one of the combinations of SPO-24b-EXT-001 to SPO-24b-EXT-003 or refused (SPO-24b-PRE-009), and the witnesses are assembled (SPO-24b-EXT-004). (src: L591-L713)
- **SPO-24b-INV-012** Stage 10, size check: as Ptx (SPO-Ptx-PRE-007). (src: L719-L724)
- **SPO-24b-INV-013** Stage 11, confirm: as Ptx (SPO-Ptx-PR-002, SPO-Ptx-PR-003); `ENV_SKIP_PROMPT=YES` skips it. (src: L726-L728)
- **SPO-24b-INV-014** Stage 12, submit or queue: as Ptx (SPO-Ptx-MODE-008 to SPO-Ptx-MODE-010) per SPO-24b-MODE-001 to SPO-24b-MODE-003. (src: L728-L784)

## Work modes

- **SPO-24b-MODE-001** *Online.* Node must be synced for the UTxO query (SPO-Ptx-MODE-002); submission is `transaction submit` then `transaction txid`, SPO-Ptx-MODE-008. (src: L380-L388, L733-L744)
- **SPO-24b-MODE-002** *Light.* UTxOs from Koios, submission through `submitLight`, SPO-Ptx-MODE-003, SPO-Ptx-MODE-009. (src: L390-L395, L746-L753)
- **SPO-24b-MODE-003** *Offline.* UTxOs and protocol parameters come from the transfer file and the signed transaction is queued as a `Transaction` entry (SPO-Ptransfer-OUT-010 to SPO-Ptransfer-OUT-012) with `toAddr` equal to the paying address name and `sendToAddr` equal to its address. Signing works offline, so a hardware wallet or a key on the offline machine can vote. **Upstream quirk:** the history line reads "from '<pay>' to ''" because it prints an unset variable. (src: L340-L343, L397-L400, L756-L779)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Allow unrestricted mode, only with several votes and hardware (SPO-24b-PR-001) | Yes; no exits 2 | flag for hardware signing |
| Add hardware witness(es) (SPO-24b-EXT-001, SPO-24b-EXT-002) | Yes; no exits 2 | signing |
| Does this look good, continue? (SPO-Ptx-PR-002) | No; skipped by `ENV_SKIP_PROMPT=YES` | submit or queue |

## Outputs

- **SPO-24b-OUT-002** On success: online or light, a transaction with the votes is submitted; offline, it is appended to the transfer file. No file in the workspace is created or changed in online and light mode. In all modes, intermediate files are written to `<tempDir>` (below) and kept. (src: L575-L578, L733-L779)

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<tempDir>/dummy.txbody` | body for the fee estimate | default | created |
| `<tempDir>/<pay>.txbody`, `<tempDir>/<pay>.tx` | body and signed transaction, SPO-Pfiles-OUT-039 | default | replaced each run |
| `<tempDir>/<voter file name>.vote_txwitness`, `<tempDir>/<pay>.pay_txwitness` | witnesses | default | created in every reachable signing branch; the `rm` that should clear them names unset variables (SPO-24b-PRE-009) |
| `<tempDir>/<pay>.transactionMessage.json` | CIP-20 message metadata | default | created with messages |
| `offlineTransfer.json` | queue entry, offline only | default | updated |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| Fewer than three arguments | 1 | SPO-24b-IF-001 |
| No voter signing file; payment `.addr` or signing file missing | 1 | SPO-24b-IN-001, SPO-24b-IN-002 |
| Pre-Conway era | 0 | SPO-24b-PRE-001 |
| Protocol major below 9 | 1 | SPO-24b-PRE-002 |
| Bad extra word, unreadable vote file | 1 | SPO-24b-IF-004, SPO-24b-IF-005 |
| Voter type mismatch, mixed voter hashes, repeated action | 1 | SPO-24b-PRE-003 to SPO-24b-PRE-005 |
| Unrestricted mode declined | 2 | SPO-24b-PR-001 |
| No UTxOs; address missing offline; node unsynced | 1 | SPO-24b-PRE-007, SPO-24b-MODE-001 |
| Not enough funds for the change | 0 | SPO-24b-PRE-006 |
| Hardware witness declined | 2 | SPO-24b-EXT-001, SPO-24b-EXT-002 |
| Hardware wallet rejected, disconnected, security or error | 1 | SPO-24b-PRE-010 |
| Voter key does not match the vote files | 1 | SPO-24b-PRE-008 |
| Payment hardware with voter key file | 1 | SPO-24b-PRE-009 |
| Too large | 1 | SPO-Ptx-PRE-007 |
| Confirmation declined | 0 | SPO-Ptx-PR-002 |
| Light submit fails; offline read-back mismatch | 0 | SPO-Ptx-MODE-009, SPO-Ptx-MODE-010 |

## Security

- **SPO-24b-SEC-001** Signing keys never touch disk: each is decrypted into a shell variable and handed to `cardano-cli` through an anonymous pipe (SPO-Ptx-SEC-001). (src: L671-L702)
- **SPO-24b-SEC-002** A key file whose hash is not the voter hash is detected only after the body is built; the check protects against signing a transaction whose votes the key cannot authorise, and prevents wasted fees. (src: L685-L690)
- **SPO-24b-SEC-003** The transaction message passphrase is printed in clear (SPO-Pparam-SEC-001). The signed transaction and body stay in `<tempDir>` (SPO-Ptx-SEC-002). (src: L532-L537)

## Domain mapping

Use case `SubmitVotes(voter, payer, votes[], messages?)` on aggregate `Vote`, producing a `TxDraft` for the shared pipeline.

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get(VoteFile)`, `get(SigningRef)` | votes and key references |
| `Ledger` | `viewVote(voteFile)` *(new)* | decode a vote file (voter, action id, decision, anchor) |
| `Ledger` | `buildRaw(txSpec)`, `minFee`, `minOutputValue`, `assemble`, `txId` | shared pipeline, votes added as a transaction field |
| `ChainQuery` | `tip`, `protocolParameters`, `utxos` | pipeline inputs |
| `Signer` | `witness(body, voterKeyRef)`, `witness(body, payerKeyRef)` | two witnesses; hardware for both in one session, unrestricted option *(new)* |
| `Vault` | `unseal(ref)` | in-memory keys for the key-file path |
| `Submitter` | `submit(signedTx)` | node or Koios; offline: `Transport.enqueueTx` |
| `UI` | `confirm` | unrestricted mode, hardware, final |

## Port notes

* Treat a voting transaction as a multi-party signing job: the voter (DRep or committee hot key, or the pool cold key) is a different custodian from the payer. A native design asks each custodian's `Signer` (local vault, hardware, or remote) for its witness and assembles them; the payer can even be a third party, because the transaction does not pay a deposit. This removes the "payment hardware, voter key file" refusal as a restriction.
* The votes could be validated against chain state before building: action active, voter registered or eligible, no vote already cast under the same credential (cast again changes the answer on chain, which upstream allows).
* Create the tmp witness files in a fresh private directory and delete them; do not rely on `rm` of unset variables.
* A declined unrestricted-mode prompt should exit non-zero and decline of the confirmation likewise should be distinguishable.
* Large batches: hardware limits mean one vote per transaction unless unrestricted mode is allowed; a port can split votes into several transactions automatically.

## Open questions

* Whether the `Abstain` decision text in `vote view` output is `Abstain` in every cardano-cli version in the release set; the script tests for exactly this string. Settle with a captured output.
* Whether a vote file for a committee member with a script-credential hot key can be signed by this flow; only key-file and hardware witnesses are handled.
