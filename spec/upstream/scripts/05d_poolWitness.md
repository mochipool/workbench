+++
id = "05d"
kind = "script"
title = "Sign, import and manage pool registration witnesses"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["pool-operations", "key-custody", "air-gap-transfer"]
use_cases = ["SignPoolWitness", "ImportPoolWitness", "ClearPoolWitnessCollection", "InspectPoolWitnessCollection"]
depends_on = ["Cui", "Ckey", "Chw", "Cchain", "Coffline", "Ptransfer", "Pfiles"]

upstream_path = "cardano/mainnet/05d_poolWitness.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "cf0ba5138bf5611a82f02693e936c9ffb3ddbf827bec504a2e78bffcbf2b3b46"
upstream_lines = 470
uses_common = [
  "ask",
  "checkError",
  "file_lock",
  "file_unlock",
  "get_currentTip",
  "readOfflineFile",
  "read_skeyFILE",
  "start_HwWallet",
]
cli_commands = [
  "transaction witness",
]
hwcli_commands = [
  "transaction witness",
]
signer_commands = []
http_endpoints = []
env_vars = []
+++

# 05d_poolWitness: Multi-party witness workflow for pool registration

The companion of [05c](./05c_regStakepoolCert.md). A pool registration transaction needs signatures from several parties (SPO-05c-INV-005). 05c stores the unsigned transaction and one empty *witness slot* per signer in `<pool>.pool.json` under `regWitness` (the *witness collection*), and writes one *witness transfer file* per empty slot. 05d is the other half of that protocol, with four subcommands:

* `sign` produces a signature on the machine that holds a signer's key, inside the witness transfer file;
* `add` imports a signed witness into the collection;
* `info` shows which slots are filled;
* `clear` throws the collection away.

Nothing in 05d builds, assembles or submits a transaction: after the last `add`, the operator re-runs 05c.

This spec is the main input for a remote multi-party signing design. The section *Witness collection lifecycle* specifies every state and transition of the collection and of the transfer file, the time window that bounds them, and the integrity checks that exist (and those that do not). Mode-independent except for the slot source of the clock (see Work modes).

## Interface

- **SPO-05d-IF-001** Without arguments prints usage to stderr and exits 1. (src: L132)
- **SPO-05d-IF-002** The first argument selects the subcommand: `sign`, `add`, `clear` or `info` (lower case, exact). Any other word prints usage and exits 1. (src: L133-L157)
- **SPO-05d-IF-003** `sign <witnessfile> <signingkey>` takes exactly two further arguments; any other count prints "missing parameters" and the usage and exits 1. `<witnessfile>` gets `.witness` appended unless it already ends in `.witness`. `<signingkey>` is normalised by removing a trailing `.staking` and appending `.staking`, so the key files are always `<name>.staking.skey` or `.hwsfile`, and `<name>.staking.vkey`. A leading `./` is dropped from both. (src: L22-L23, L135-L141)
- **SPO-05d-IF-004** `add <witnessfile> <poolFileName>` takes exactly two further arguments, normalised as above and as in SPO-Pfiles-IN-001. (src: L25-L26, L143-L148)
- **SPO-05d-IF-005** `clear <poolFileName>` and `info <poolFileName>` take exactly one further argument. (src: L28-L31, L150-L154)
- **SPO-05d-PRE-001** Argument checks refuse with exit 1: `sign` when the witness file, or both `<key>.skey` and `<key>.hwsfile`, or `<key>.vkey` does not exist; `add` when the witness file or `<pool>.pool.json` does not exist; `clear` and `info` when `<pool>.pool.json` does not exist. (src: L138-L140, L146-L147, L153)

## Inputs

- **SPO-05d-IN-001** The *witness transfer file* (written by 05c, SPO-05c-OUT-003) is a JSON object with `id`, `date-created`, `ttl`, `type`, `metadataFilesList`, `poolFile`, `poolMetaTicker`, `signing-name`, `signing-vkey`, `txBody`, `signedWitness` and `date-signed`. `sign` reads `id`, `date-created`, `type`, `txBody`, `ttl`, `signing-name`, `signing-vkey`, `poolMetaTicker`, `metadataFilesList` and `signedWitness`; `add` reads all but `ttl`, `poolFile` and `metadataFilesList`. (src: L204-L211, L362-L370)
- **SPO-05d-IN-002** The witness collection `regWitness` of `<pool>.pool.json` (SPO-05c-OUT-002) and the descriptor's `poolMetaTicker`. A collection exists when `regWitness` has any content; an absent `regWitness` or an empty object means "no collection". (src: L38-L47, L167, L187, L199, L213-L222)
- **SPO-05d-IN-003** `sign` reads the signer's `<name>.staking.vkey` (always), and either `<name>.staking.skey` (cardano-cli key, plain or encrypted, via `read_skeyFILE`, see `Ckey`) or `<name>.staking.hwsfile`. (src: L139-L140, L397-L443)
- **SPO-05d-IN-004** `sign`, `add` and `info` read the current tip slot of the work mode (SPO-Cchain-OUT-003); a failure exits 1 through the common function. (src: L46, L221, L371)

## Behaviour

### Witness collection lifecycle (state machine)

The collection stored under `regWitness` moves through these states. The state is not stored; it is derived from the descriptor and the clock.

| State | Derivation | How it is entered |
| --- | --- | --- |
| **Absent** | no `regWitness` | initial; after Discarded or Submitted |
| **Open, incomplete** | collection present, `ttl >= tip`, at least one slot has an empty `witness` | 05c creates it (SPO-05c-OUT-001); `add` into a collection with more than one empty slot |
| **Open, complete** | collection present, `ttl >= tip`, every slot filled | the last `add`; 05c when every slot could be signed locally |
| **Expired** | collection present, `ttl < tip` | the tip passes `ttl` (no write happens) |
| **Submitted** | `regWitness` removed, `regSubmitted` set | 05c final confirmation and successful submit or queue (SPO-05c-MODE-006 to SPO-05c-MODE-008) |
| **Discarded** | `regWitness` removed, `regSubmitted` unchanged | `clear` with confirmation (SPO-05d-PR-001) or the delete prompt of 05c (SPO-05c-PR-004) |

| Transition | Trigger | Guard | Effect |
| --- | --- | --- | --- |
| Absent to Open | `05c` first run | body confirmed (SPO-05c-PR-001), local witnesses produced | collection written (SPO-05c-OUT-001); transfer file per empty slot |
| Open, incomplete to Open, incomplete or complete | `add` | window open; id, type, ticker, body equal; witness signed; slot known; overwrite confirmed if filled | slot filled, descriptor rewritten, transfer file deleted |
| Open, complete to Submitted | `05c` re-run | window open, same payer, assemble ok, size ok, confirmation Yes | submit, record, remove collection |
| Open, complete to Open, complete | `05c` re-run, confirmation No | none | nothing changes unless the delete prompt is answered Yes |
| Open or Expired to Discarded | `clear` Yes, or 05c delete prompt Yes | collection present | `regWitness` removed |
| Open to Expired | time | tip above `ttl` | none stored; every later `add`, `sign`, `info` and 05c refuses (SPO-05d-INV-003) |
| Expired, Open to Open | `add` over a filled slot, confirmed | window open | slot overwritten |

- **SPO-05d-INV-001** The only operation that removes a collection without submitting it is `clear` (or the delete prompt of 05c). An expired or abandoned collection stays in the descriptor until then, and blocks a new registration: 05c refuses `type:` and metadata while a collection is open (SPO-05c-PRE-003) and resumes the stored body otherwise. (src: L163-L181, 05c_regStakepoolCert.sh:L313-L324)
- **SPO-05d-INV-002** A slot is *ready* when its `witness` object is non-empty (`length > 0`) and *missing* otherwise. `info` and the end of `add` list the slots in the order they were created and print the expected transfer file name `<pool>.<slot basename>.witness` for each missing slot. That name differs from the transfer file 05c writes (`<pool>_<name>_<id>.witness`, SPO-05c-OUT-003); the printed name is display only. (src: L69-L83, L299-L313)
- **SPO-05d-INV-003** *Time window.* The collection's `ttl` is the transaction's validity end, fixed by 05c at creation as `tip + defTTL` slots (default 100000, about 27.8 hours at one-second slots; SPO-Ptx-INV-001). The window is open while `ttl >= tip`, with `tip` read in the current work mode at the moment of each command. It is enforced by: `info` (exit 1 when expired), `add` (exit 1 when expired), `sign` (exit 1 when the **transfer file's own `ttl`** is below the tip) and 05c resume (SPO-05c-INV-008). It is never extended: the only way forward from Expired is `clear` and a fresh 05c run, which makes a new id, a new body and new transfer files. (src: L53-L57, L228-L232, L377-L381)
- **SPO-05d-INV-004** *Witness transfer file lifecycle.* Created unsigned by 05c (`signedWitness` and `date-signed` empty objects), never overwritten by 05c while it exists, signed in place by `sign` (SPO-05d-OUT-001), and deleted by `add` after the signed witness was read back from the descriptor (SPO-05d-OUT-003). A file that `add` refuses stays on disk. The collection id in the file name and in the content separates files of different collections. (src: L284, L392, L462). See SPO-05c-OUT-003.
- **SPO-05d-INV-005** *Integrity checks that exist.* `add` verifies textual equality of four values between the transfer file and the collection: `id`, `type`, `poolMetaTicker` and `txBody` (the whole body object), plus that the file's `signing-name` is a slot of the collection. `sign` verifies that the content of `<key>.staking.vkey` equals the file's `signing-vkey`. (src: L242-L254, L394-L398)
- **SPO-05d-INV-006** *Integrity checks that do not exist.* Nothing verifies that `signedWitness` is a valid signature on the body, that its key hash is the slot's key, or that the file's `ttl` equals the collection's. A wrong or forged witness is accepted by `add` and fails only at assembly or submission in 05c. `sign` does not compare the file with any descriptor and `add` does not look at the file's `poolFile`. (src: L242-L254, L261, L267)
- **SPO-05d-INV-007** *Only owner-staking slots are signable.* Because `sign` always uses the key files `<name>.staking.*`, a witness transfer file whose slot is the cold key (`<pool>.node`) or the paying address cannot be signed with 05d: the vkey comparison fails against `<name>.staking.vkey`. `add` itself accepts a witness for any slot name (SPO-05d-INV-005). (src: L137, L396-L398, L253-L254)
- **SPO-05d-INV-008** *The signer sees little.* `sign` displays the id, the creation date, the tip and TTL, the type, the ticker, the metadata file list and the slot name, but not the transaction's certificates, outputs, fee or deposit, and it asks no confirmation. The signer approves by running the command. (src: L373-L389, L400-L468)

### `sign`

1. **Check the file.**
   - **SPO-05d-PRE-002** Exits 1 when the witness file is not valid JSON. (src: L359-L360)
   - **SPO-05d-PRE-003** Exits 1 when the file's `ttl` is lower than the current tip. (src: L371, L377-L378). See SPO-05d-INV-003.
   - **SPO-05d-PRE-004** Exits 1 when `signedWitness` is already non-empty: a witness is signed once. (src: L391-L392)
   - **SPO-05d-PRE-005** A `signing-name` that differs from the normalised signing key name prints a warning and continues; the vkey comparison decides. (src: L387-L388)
   - **SPO-05d-PRE-006** Exits 1 when `<key>.staking.vkey`, normalised as JSON, differs from the file's `signing-vkey`: "wrong signing key". (src: L394-L398)
2. **Sign.** The body signed is the file's `txBody`, written to `<tempDir>/<key basename>.tmp.witnessTxBody` and removed afterwards, together with the temporary witness file.
   - **SPO-05d-EXT-001** *Hardware.* When the description of `<key>.staking.vkey` contains `Hardware`, requires `<key>.staking.hwsfile` (exit 1 otherwise), starts the hardware session without vendor restriction (see `Chw`) and runs `cardano-hw-cli transaction witness --tx-file <body> --hw-signing-file <hwsfile> <magic> --out-file <witness>`. Output is classified as in SPO-Ptx-PRE-005 (`REJECTED`, `DISCONNECT`, `ERROR` exit 1; `WARNING` continues). No confirmation prompt precedes it. (src: L409-L426)
   - **SPO-05d-EXT-002** *Key file.* Otherwise reads `<key>.staking.skey` into memory with `read_skeyFILE` (password prompt for an encrypted key, see `Ckey`; failure exits 1) and runs `cardano-cli <era> transaction witness --tx-body-file <body> --signing-key-file <key> --out-file /dev/stdout`; the key variable is unset afterwards. A cardano-cli failure ends the script with its code. (src: L436-L451)
   - **SPO-05d-OUT-001** On success the transfer file is rewritten in place with `signedWitness` set to the witness text envelope and `date-signed` set to the current time (RFC-5322). The file keeps its mode. (src: L430-L433, L445-L448, L462-L464)
     > **Upstream quirk:** when the final write fails the script prints an error but still exits 0 (bare `exit`).
   - **SPO-05d-OUT-002** `sign` writes nothing else: neither the descriptor nor the transfer file of the pool's other slots. It needs no pool files, so it runs on the signer's machine with only the transfer file and the signer's keys. (src: L357-L468)

### `add`

1. **Check, in this order.**
   - **SPO-05d-PRE-007** Exits 1 when the descriptor holds no collection. (src: L199)
   - **SPO-05d-PRE-008** Exits 1 when the witness file is not valid JSON. (src: L201-L202)
   - **SPO-05d-PRE-009** Exits 1 when the collection's `ttl` is lower than the current tip. (src: L221-L232)
   - **SPO-05d-PRE-010** Exits 1 when the file's `id` differs from the collection's `id`, when `signedWitness` is empty ("not signed yet"), when the file's `type` differs from the collection's `type`, when its `poolMetaTicker` differs from the descriptor's, or when its `txBody` differs from the collection's `txBody`. (src: L242-L250)
   - **SPO-05d-PRE-011** Exits 1 when the collection has no slot named by the file's `signing-name`. (src: L252-L254)
   - **SPO-05d-PR-002** When the slot is already filled, asks "witness already in the pool file, overwrite?" (default No); No exits 1, Yes replaces the witness. (src: L256-L263)
2. **Import.**
   - **SPO-05d-OUT-003** Sets `regWitness.witnesses."<signing-name>".witness` to the file's `signedWitness`, rewrites the descriptor (unlock, whole-file rewrite, lock `0400`), reads the slot back and compares it with the imported witness. On a match it deletes the witness transfer file; on a mismatch it exits 1 and keeps the file. (src: L267-L290)
3. **Report.**
   - **SPO-05d-OUT-004** Lists the slots as ready or missing (SPO-05d-INV-002) and prints either "no missing witnesses, re-run 05c" or "there are missing witnesses". The exit code is 0 in both cases, except in offline mode with a slot missing, where the transfer file is read first and an invalid file exits 1 (SPO-05d-PRE-015). (src: L294-L354)

- **SPO-05d-PRE-015** In offline mode with at least one slot still missing after the import, `add` reads the transfer file the same way (SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004) and exits 1 when it is not valid. This happens after the slot was written to the descriptor and the witness transfer file was deleted (SPO-05d-OUT-003), so the import is persisted although the exit status reports failure. (src: L318-L320, L267-L290)
  > **Upstream quirk:** a caller sees a failed `add` although the witness was imported. A port reads the transfer file before the import, or exits 0 once the import is persisted.

### `info`

- **SPO-05d-PRE-012** Without a collection prints "no witnesses" and exits 0. (src: L187-L193)
- **SPO-05d-PRE-014** In offline mode with at least one slot still missing, `info` reads the transfer file before it offers to embed the missing witness files, and exits 1 through SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004 when the file is missing, not valid JSON, blank or without protocol parameters. The report has already been printed. (src: L88-L90)
- **SPO-05d-PRE-013** With a collection prints its id, creation date, current tip, TTL, type, ticker, paying address name, metadata list and the slot list (SPO-05d-INV-002). Exits 1 when the TTL is below the tip (the report is cut off at that point); otherwise exits 0, also when slots are missing, except in offline mode with a missing slot (SPO-05d-PRE-014). (src: L37-L124, L184-L194)

### `clear`

- **SPO-05d-PR-001** With a collection, asks "do you really want to delete the witness collection?" (default No). Yes removes `regWitness` from the descriptor. Without a collection prints "no witnesses". The exit code is 0 in every case, including No. (src: L163-L182)
- **SPO-05d-OUT-005** After a Yes the descriptor stays at mode `0600` (unlocked at both ends instead of relocked). Witness transfer files are not touched. (src: L170-L175)

## Work modes

- **SPO-05d-MODE-001** The tip is read in the work mode in use: node (`query tip`), Koios, or in offline mode computed from the genesis files and the wall clock (SPO-Cchain-MODE-008). `sign` therefore works on an air-gapped signer that has the genesis files and a correct clock but no transfer file; the clock decides whether the window is open. (src: L46, L221, L371)
- **SPO-05d-MODE-002** In offline mode, `info` and `add` read the transfer file (`readOfflineFile`) when a slot is missing, and offer to embed the missing slots' transfer files in it (SPO-05d-PR-003). `sign` and `clear` never read it. The read is a hard precondition: SPO-05d-PRE-014 and SPO-05d-PRE-015. (src: L88-L114, L318-L344)

## Prompts

| Prompt | Default | Effect |
| --- | --- | --- |
| Delete the collection, `clear` (SPO-05d-PR-001) | No | Yes removes `regWitness` |
| Overwrite a filled slot, `add` (SPO-05d-PR-002) | No | Yes replaces; No exits 1 |
| Include a witness file in the transfer file, offline (SPO-05d-PR-003) | No | Yes embeds it |

- **SPO-05d-PR-003** Offline, for each missing slot whose file `<pool>.<slot basename>.witness` exists, asks whether to attach it to `offlineTransfer.json` (default No); Yes embeds it as in SPO-Ptransfer-OUT-017 and rewrites the file. That file name is not the one 05c writes, so the offer normally never appears (see SPO-05d-INV-002). (src: L97-L108, L327-L338). See SPO-Ptransfer-OUT-018.

## Outputs

**Upstream file contract:**

| File | Content | Mode | Change |
| --- | --- | --- | --- |
| `<pool>.pool.json` | descriptor; `regWitness` slots filled (`add`) or `regWitness` removed (`clear`) | `0400` after `add`; `0600` after `clear` | updated |
| `<pool>_<name>_<id>.witness` | witness transfer file | unchanged | rewritten in place by `sign`; deleted by `add` |
| `offlineTransfer.json` | attached witness files (offline, SPO-05d-PR-003) | not managed | updated |
| `<tempDir>/<key>.tmp.witnessTxBody`, `<key>.tmp.witness` | body and witness during `sign` | default | created, removed |

## Failures

| Condition | Exit | Id |
| --- | --- | --- |
| No arguments, unknown subcommand, bad argument count | 1 | SPO-05d-IF-001 to SPO-05d-IF-005 |
| Missing file argument | 1 | SPO-05d-PRE-001 |
| `sign`: invalid JSON, expired, already signed, wrong key, no hwsfile, hardware refused, key unreadable | 1 | SPO-05d-PRE-002, SPO-05d-PRE-003, SPO-05d-PRE-004, SPO-05d-PRE-006, SPO-05d-EXT-001, SPO-05d-EXT-002 |
| `add`: no collection, invalid JSON, expired, mismatch, unsigned, unknown slot, overwrite declined, read-back mismatch | 1 | SPO-05d-PRE-007 to SPO-05d-PRE-011, SPO-05d-PR-002, SPO-05d-OUT-003 |
| `info`: expired | 1 | SPO-05d-PRE-013 |
| `info`, offline, slot missing, transfer file missing or invalid | 1 | SPO-05d-PRE-014 |
| `add`, offline, slot still missing, transfer file missing or invalid (after the import) | 1 | SPO-05d-PRE-015 |
| `info`, `clear`: no collection | 0 | SPO-05d-PRE-012, SPO-05d-PR-001 |
| `clear` declined or done | 0 | SPO-05d-PR-001 |
| `sign` write failure | 0 | SPO-05d-OUT-001 |

## Security

- **SPO-05d-SEC-001** `sign` reads the signing key into memory only (SPO-Ckey-SEC-002) and passes it to cardano-cli through an anonymous pipe; the witness is the only artefact written, and it is not secret. (src: L441-L451)
- **SPO-05d-SEC-002** The transfer file contains the full unsigned transaction body. Anyone who can alter it before signing can make the signer sign a different body: `sign` has no trusted copy to compare with and the body is not decoded for the signer (SPO-05d-INV-008). The attack is caught at `add` only by the `txBody` equality (SPO-05d-INV-005), which protects the collection's owner, not the signer. (src: L362-L370, L405, L250)
- **SPO-05d-SEC-003** An imported witness is not authenticated (SPO-05d-INV-006); the descriptor is trusted as the single source of the body, id and TTL. (src: L242-L267)

## Domain mapping

Use cases on the `WitnessCollection` part of aggregate `PoolRegistration`:

* `SignPoolWitness(transferFile, signerKey)` (`sign`);
* `ImportPoolWitness(transferFile, pool)` (`add`);
* `InspectPoolWitnessCollection(pool)` (`info`);
* `ClearPoolWitnessCollection(pool)` (`clear`).

| Port | Operation | Purpose |
| --- | --- | --- |
| `Store` | `get/put/delete(WitnessCollection)` *(new)* | The collection; atomic slot update |
| `Store` | `get/put/delete(WitnessTransferFile)` *(new)*, `get(StakeVerificationKey)` | Per-slot request and response artefacts |
| `Signer` | `witness(body, keyRef) -> witness` | `sign`: vault key or hardware wallet |
| `Vault` | `unseal(ref, passphrase?)` | In-memory signing key |
| `ChainQuery` | `tip()` | Window check |
| `Clock` | `now()` | Offline tip, `date-signed` |
| `Transport` | `attach(file)` | Offline attach offer |
| `UI` | `confirm`, `show` | Prompts and the collection report |

## Port notes

Implications for the remote multi-party signing design (non-normative):

* **Model the collection as an aggregate with states** `OpenIncomplete`, `OpenComplete`, `Expired`, `Submitted`, `Discarded` and a derived state function, as in the lifecycle table. Persist the state and the slot witnesses atomically; `add` is a compare-and-set on the slot, not a file rewrite.
* **The witness transfer file is the request/response message** between the coordinator and each signer: request fields `id`, `ttl`, `type`, `txBody`, `signing-name`, `signing-vkey`; response `signedWitness`, `date-signed`. In server mode this is an authenticated API call; the file adapter keeps the upstream format for air-gapped carry.
* **Show the signer a decoded transaction.** Display certificates, the deposit or its absence, outputs, fee, TTL and the pool id before a signature is made, and require explicit approval (SPO-05d-INV-008). The signer's machine should recompute the body hash itself.
* **Verify on import** that the witness is a valid signature on the stored body and that its key hash equals the slot's key hash (SPO-05d-INV-006); reject otherwise with a precise reason, before the slot is touched.
* **Make payer and cold-key slots signable** through the same flow (SPO-05d-INV-007, SPO-05c-INV-010). Per-slot signer assignment (`local`, `external`, a named remote party) replaces the loose `ownerWitness` word.
* **Bind a witness to the collection** with a random id (not a clock second) and the body hash; unknown or stale ids are rejected.
* **Expiry** is a function of the stored `ttl` and the chain tip; expose it as state. A signer service refuses to sign an expired body. Allow extending by building a new collection explicitly, not by clearing.
* **Idempotency and concurrency:** signing the same request twice returns the same witness (not "already signed" exit 1); two parties importing at once must not lose an update (upstream rewrites the whole descriptor).
* **Audit:** record who signed which slot when, and who cleared a collection; `clear` upstream leaves no trace.
* **Exit codes:** `info` on an expired collection and `sign` write failures need distinct, non-zero results.

## Open questions

* Whether a `cardano-cli transaction witness` envelope carries enough information (key hash) to verify slot ownership on import without the vkey; the envelope is a CBOR pair of vkey and signature, which a test against a recorded witness settles.
* Whether anything but `external` is used in the wild for `ownerWitness`; only `local` and `external` appear in the comments.
* The rounding of the offline tip near the window boundary depends on the clock (SPO-Cchain-INV-008); a test with a fixed clock settles equality (`ttl == tip` is still open).
