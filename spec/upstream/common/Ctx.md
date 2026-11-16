+++
id = "Ctx"
kind = "common"
title = "Transaction body correction for hardware wallets"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["transaction-construction", "key-custody"]
use_cases = []
depends_on = ["Chw", "Cconf"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
autocorrect_TxBodyFile = "88ac9ef3e68287cf999b0ff9bf155d5286856eb0fc64c12815a181eed0805e38"
autocorrect_TxBodyFile_withAuxDataHashCorrection = "a1bcff33ade937ed29fe549b64d1d03c69c5b0917b006d78395843b754a64a82"
+++

# Ctx: transaction body correction for hardware wallets

A hardware wallet signs the bytes of the transaction body, and it accepts only a body in the encoding it expects (canonical ordering and definite-length forms, "new cddl format" in the upstream comment). The bodies that `cardano-cli transaction build-raw` writes are not always in that form. Before a hardware wallet witnesses a transaction, upstream therefore rewrites the body file through `cardano-hw-cli transaction transform`. The rewrite changes the serialised bytes. As the transaction id is the hash of the body bytes, **every witness (hardware or cli key) has to be created after this step, over the corrected body**, which is why the callers run it immediately before signing.

Neither function edits CBOR itself except for the hash patch in the second one: the corrected bytes are whatever `cardano-hw-cli transform` produces. The exact transformation rules belong to cardano-hw-cli; the script only runs it and checks that it succeeded.

Both functions work on the file in place, and both end with `exit`. Every caller invokes them as `tmp=$(autocorrect_TxBodyFile "${txBodyFile}")` and tests `$?`, so the `exit` ends only the subshell and the caller sees the status. On a failure the caller prints `$tmp` in colour and exits 1.

## autocorrect_TxBodyFile

Called as `autocorrect_TxBodyFile <txBodyFile> [<hwUnrestrictedMode>]`. It is the only variant any script calls: every transaction script that can be signed by a hardware wallet (`01_*`, `03b`, `05c`, `06`, `07b`, `08b`, `11a`, `11b`, `21b`, `21d`, `22b`, `23c`, `23e`, `24b`, `25b`).

- **SPO-Ctx-IF-001** The first argument is the path of the transaction body file, a cardano-cli text envelope whose `cborHex` holds the transaction. The optional second argument is inserted unquoted into the hw-cli command: empty, or `--allow-unrestricted-mode`. The latter is passed by `21b`, `21d` and `24b` (the `hwUnrestrictedMode` variable) after the user allowed unrestricted mode, so that a hardware wallet may pay for a transaction whose certificate or vote it does not own. (src: L2706-L2708, L2717)
- **SPO-Ctx-PRE-001** Exits 1 with a message when the `cardanohwcli` binary is not found. (src: L2711)
- **SPO-Ctx-PRE-002** Exits 1 with a version error through `majorError` when cardano-hw-cli is older than `minHardwareCliVersion`; it reads the version, and compares it, exactly as in SPO-Chw-EXT-001, SPO-Chw-INV-001 and SPO-Chw-PRE-002, including the pass on an empty version. (src: L2712-L2714)
- **SPO-Ctx-EXT-001** Runs `cardano-hw-cli transaction transform <hwUnrestrictedMode> --tx-file <txBodyFile> --out-file <txBodyFile>-corrected`, stderr merged into the captured output. (src: L2717)
- **SPO-Ctx-PRE-003** Prints the captured output and exits 1 when `transform` returns a non-zero status. The original file is unchanged. (src: L2719)
- **SPO-Ctx-PRE-004** Prints the captured output and exits 1 when the **last line** of the output contains `ERROR` (case-insensitive), even if the status was 0. The original file is unchanged. (src: L2720-L2721)
- **SPO-Ctx-OUT-001** On success, replaces the body file with the corrected file by `mv`, in the same directory. A failed `mv` prints a message and exits 1. (src: L2724)
- **SPO-Ctx-OUT-002** On success, prints the last line of the hw-cli output on stdout and exits 0. It is shown to the user as the result line. (src: L2720, L2727)

> **Upstream quirk:** On a failure after the transform ran (SPO-Ctx-PRE-003, SPO-Ctx-PRE-004) a partial `<txBodyFile>-corrected` can remain on disk. It is not deleted and will be overwritten by the next run. (src: L2717-L2721)

## autocorrect_TxBodyFile_withAuxDataHashCorrection

Called as `autocorrect_TxBodyFile_withAuxDataHashCorrection <txBodyFile>`. **No script in this tag calls it.** It is specified because it owns lines of the file and because it shows a hazard that applies to the first variant as well: a body can carry the hash of its auxiliary data (metadata), and transforming the transaction can change the serialised auxiliary data and with it that hash.

- **SPO-Ctx-IF-002** Takes only the body file path. It has no unrestricted-mode argument and runs `transform` without one. (src: L2737, L2753)
- **SPO-Ctx-PRE-005** Performs the same cardano-hw-cli presence and version checks as SPO-Ctx-PRE-001 and SPO-Ctx-PRE-002, and the same `transform` call and error handling as SPO-Ctx-EXT-001, SPO-Ctx-PRE-003 and SPO-Ctx-PRE-004 (its temporary file name is the same `<txBodyFile>-corrected`). (src: L2742-L2756)
- **SPO-Ctx-IN-001** Before the transform, detects the auxiliary data by a **text search** of the file for the hex bytes `f5d90103`. `f5` is the CBOR `true` of the transaction's validity flag and `d90103` is tag 259, the wrapper of Alonzo-and-later auxiliary data. The greedy match picks the **last** occurrence on its line, and the auxiliary data is the hex from `d90103` up to the closing quote of the `cborHex` value. The candidate hash is the BLAKE2b-256 digest (32 bytes) of those bytes, in hex. (src: L2749)
- **SPO-Ctx-IN-002** The candidate hash counts as `currentAuxHash` only when the same hex string also occurs in the file's text (that is, in the body's auxiliary-data-hash field). When it does not occur, `currentAuxHash` is empty and no patch is made. This is also the result for a transaction without metadata, because `f5` is then followed by `f6` (null) and the digest of empty input is not in the file. (src: L2750)
- **SPO-Ctx-OUT-003** After the transform, computes `newAuxHash` from the corrected file in the same way. When `currentAuxHash` is non-empty and differs from `newAuxHash`, it replaces **every** occurrence of the old hash in the corrected file with the new one (`sed -i 's/old/new/g'`), and a failed replacement exits 1. The body then carries the hash of the re-serialised auxiliary data. (src: L2759-L2762)
- **SPO-Ctx-OUT-004** Replaces the body file with the corrected file by `mv`, as SPO-Ctx-OUT-001. (src: L2766)
- **SPO-Ctx-OUT-005** On success, prints the last line of the hw-cli output, followed, when the hash was patched, by a note "Corrected the AuxHash from '<old>' to '<new>' too!", and exits 0. The note contains literal `\e[91m` and `\n` text, since it is printed by a plain `echo`. (src: L2762, L2769)

> **Upstream quirk:** The detection is a text heuristic with no CBOR parsing. A body whose stored hash was already wrong, or whose auxiliary data does not start with `f5d90103`, is left unrepaired and silently accepted. The comment above the function says so ("no deep cbor analysis"). (src: L2748-L2750)

## Work modes

Mode-independent. Both functions are local file and subprocess operations. They run on the machine that holds the hardware wallet, which in offline mode is the offline machine.

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| cardano-hw-cli missing | 1 | SPO-Ctx-PRE-001 |
| cardano-hw-cli too old | 1 | SPO-Ctx-PRE-002 |
| `transform` non-zero status | 1 | SPO-Ctx-PRE-003 |
| `ERROR` on the last output line | 1 | SPO-Ctx-PRE-004 |
| Hash patch or `mv` fails | 1 | SPO-Ctx-OUT-001, SPO-Ctx-OUT-003 |

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `Ledger` | `canonicalizeBody(body, unrestricted?)` *(new)* | The transform: produces the body in the hardware-wallet encoding, as a new `TxBody` |
| `Ledger` | `auxDataHash(auxData)` *(new)* | BLAKE2b-256 of the serialised auxiliary data; sets the body's hash field after any re-serialisation |
| `Ledger` | `txId(tx)` | Changes with the corrected bytes; recomputed after the correction |
| `Store` | `put(TxBody)` | Replace the draft body with the corrected one |
| `Signer` | `witness(body, keyRef)` | Always over the corrected body |

The invariant for the `TxDraft` aggregate: **a `TxBody` that is handed to any `Signer` must be the canonical one, and its id must be computed after canonicalisation.** The auxiliary-data hash must agree with the serialised auxiliary data of the final body.

## Port notes

* A native `Ledger` that builds bodies in canonical form from the start needs no correction step, and no byte-level search. The hash then comes from the structured metadata.
* Do the replacement as a new body value instead of an in-place file move, so that a failure leaves nothing behind.
* Do not copy the `sed` replacement of the old hash everywhere in the file; set the field.
* If the hw-cli adapter is kept, it should treat an `ERROR` line as failure (SPO-Ctx-PRE-004) because the CLI can print an error with status 0.

## Open questions

* The exact rewrite rules of `cardano-hw-cli transaction transform` (key ordering, definite lengths, set and map forms) are not in this repository. They must be taken from the pinned hw-cli release (1.20.0) if a native canonicaliser replaces it, and compared against its output on a corpus of bodies.
* Whether the first variant would also need the hash patch for transactions with metadata is not answered by upstream. Callers that attach metadata should be tested with a hardware wallet.
