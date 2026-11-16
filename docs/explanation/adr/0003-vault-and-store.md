# ADR 0003: Sealed single-file store

Status: accepted, 2026-11-16; revised the same day after seven security reviews of the implementation; the seventh found nothing further that is required before real keys. Closes E1, E2, E3 and S1; sets the audit design for S3. The code is `spo/internal/platform/seal` (primitives), `spo/internal/platform/secret` (guarded memory) and `spo/internal/adapters/sqlitestore`. Byte layouts are pinned by committed test vectors in both packages.

## Context

One file per operator workspace holds everything. Decision D7 seals every record payload. The construction must not depend on a database feature, so that the same records work on another back end later.

## Decision

### Files

| File | Contents |
| --- | --- |
| `workspace.spo` | SQLite database (pure-Go driver, WAL mode, `secure_delete`, `synchronous=FULL`, `trusted_schema` off, `cell_size_check` on, SQLite's defensive mode) |
| `workspace.spo-wal`, `-shm` | SQLite's own, while a handle is open |
| `workspace.spo.head` | The newest audit sequence number and MAC, as text |
| `workspace.spo.head.lock` | Lock file for updating the head file |

All are mode `0600`. Open refuses a store that is not a regular file, is owned by another user, or is readable or writable by group or others.

The database itself is not encrypted. Every payload is sealed before it is written. What the file reveals without the passphrase is listed under *What the file reveals*.

### Schema

Five strict tables and nothing else: `meta`, `keyslots`, `records`, `audit`, `schema_version`. The schema is compared with an exact allow-list (the expected tables with their exact definitions and SQLite's automatic indexes) at every open, after a migration, at the start of every write transaction on the connection that writes, before a backup, and in every verification. A trigger, view, extra table, extra index or altered column is refused. This matters because a planted trigger could otherwise rewrite rows behind a write that reports success.

Running `ANALYZE`, `PRAGMA optimize` or a database tool that does so creates a statistics table, and the store then refuses to open. `VACUUM`, backup and restore pass.

### Keys

```
passphrase ──Argon2id──▶ slot key ─┐
recovery key ──HKDF────▶ slot key ─┼─unwrap──▶ master key (32 random bytes)
(later: hardware token) ▶ slot key ─┘                │ HKDF-SHA256, one versioned label per purpose
                                                     ├─▶ record-wrapping key
                                                     ├─▶ index key
                                                     └─▶ audit key
```

* **Passphrase slot.** Argon2id over the passphrase bytes as typed (no Unicode normalisation) with a 16-byte random salt. Default 256 MiB, 3 passes, 4 lanes. Parameters below 64 MiB or 3 passes, or above 1 GiB or 10 passes, are refused, so a modified file can neither weaken them nor force a huge allocation.
* **Recovery slot.** 32 random bytes, shown once as 14 groups of 4 base32 characters with a 24-bit checksum. It has full entropy, so it goes through HKDF, not Argon2id.
* **Each slot** wraps the master key with XChaCha20-Poly1305 and stores a commitment (an HMAC under the slot key) that is checked before the cipher is tried. The associated data binds format version, workspace id, slot id, slot kind, the KDF parameters and the commitment.
* **A workspace always has at least one passphrase slot and one recovery slot.**
* **Key epoch.** `meta` holds a random epoch and an HMAC of it under the audit key. A slot that unwraps to a master key of another epoch is refused. Every operation of an open handle compares the epoch inside its own transaction and refuses when another handle has rekeyed.

### Records

Each record write draws a fresh 32-byte data key and a random 24-byte nonce, seals the payload with XChaCha20-Poly1305, and wraps the data key under the record-wrapping key.

The associated data of both operations is the canonical CBOR encoding of `[format version, workspace id, record id, kind, owner, class, record version, payload format]`, where the owner is the name and number of the artefact. A ciphertext moved to another record, kind, owner, class, version or workspace fails to open (this closes SPO-Ckey-SEC-004). The class is not stored: it follows from the kind.

* Record ids are random. A record is found through a lookup tag: an HMAC under the index key over the name, kind and number.
* The owner name is stored sealed beside the record, padded to a fixed 160 bytes, so that a rekey can recompute lookup tags.
* **Secret** payloads are framed as a 4-byte length, the payload, and zero padding up to the next power of two of at least 256 bytes, so the stored size does not reveal a key type or a mnemonic's word count. They are decrypted directly into guarded memory.
* **Sensitive** payloads are stored unpadded and opened into ordinary memory.

### Writes and the audit log

* An update is one SQL transaction with a version check per record. A lost race returns a conflict error. Each write runs on its own new connection: `BEGIN IMMEDIATE`, a schema reload, the epoch and schema checks, then the statements. Before commit, the rows just written are read back and compared.
* A write can be cancelled only before `COMMIT`. If `COMMIT` reports an error, the store reads the file back on a new connection to learn what happened. If even that fails it reports the outcome as unknown, and the operator must run `spo store verify` before retrying, because repeating an operation that did take effect (issuing an operational certificate, for example) would apply it twice.
* Each update appends one audit row inside the same transaction. The row lists every record touched with its version and a hash over its stored bytes (kind, lookup tag, nonce, wrapped key, sealed owner, ciphertext), and carries an HMAC under the audit key over the row and the previous row's MAC. The event description is itself a sealed, padded record.
* Slot changes append audit rows that record a hash of the whole slot table.

### Verification

`Verify` checks, in this order: the schema allow-list; SQLite's own integrity check; the epoch MAC; every audit row's MAC and link; that each record's current version and hash are the last ones the chain recorded for it, that no record exists that the chain never recorded, and that no version ever goes backwards; the slot-table hash against the newest recorded one; and the head file.

* **Every open runs the full verification** on a read-only connection before anything is written. Open reads the meta row and the slots under the file lock, releases it while it derives the key from the passphrase, takes it again, and requires the key to match the file's current epoch. A wrong credential or a failed verification leaves the database, its write-ahead log and the head file unchanged; SQLite may create or rebuild its `-shm` file. Verification time grows with the audit chain: about 20 ms for 3,000 records, about 200 ms for 5,000 records and 50,000 audit rows.
* The store never removes or truncates SQLite's `-wal` and `-shm` files on its own, except in `restore`, which replaces the database they belong to.
* While a handle is open it keeps the verified version and hash of every record and checks each row it reads against them, so a record rolled back behind its back is refused, not laundered by the next write.
* `spo store verify --deep` additionally decrypts every record.

### Rekey: what changing a credential does

Changing the passphrase, replacing the recovery key or recovering with the recovery key is a **rekey**:

1. It takes the file lock exclusively and refuses while any other handle is open.
2. It runs the full verification under the old keys and refuses on any problem.
3. In one transaction it draws a new master key and epoch, re-wraps every data key and owner blob, recomputes every lookup tag, replaces all slots by one passphrase slot and one new recovery slot, and appends a rollover row. That row records the old chain's head and a hash over every earlier audit row, so earlier history stays tamper-evident.
4. The new recovery key is returned as soon as the transaction has committed. Scrubbing the old key material from the file (vacuum and WAL truncation) follows, and is retried at the next open or close if it fails.
5. If the commit reports an error other than "busy", the outcome is treated as unknown: the new recovery key is still shown, marked valid only if the change took effect, with instructions for finding out by reopening.

**What a rekey does not do.** It does not rotate data keys or re-encrypt payloads. Anyone who holds an old copy of the file together with an old credential can still open everything that copy held. After a suspected compromise, the keys themselves must be rotated (new KES key and opcert; an exposed cold key means retiring the pool). Old pages can also survive on SSDs, copy-on-write file systems, snapshots and backups, whatever the store does.

### Rollback

* The head file records the newest audit sequence and MAC. It only moves forward. On open, a store that does not contain the recorded head is refused as rolled back, unless the operator passes `--accept-rollback` after a deliberate restore.
* The head file is not authenticated. **Someone who replaces the store and its head file together with an older pair is not detected from the files.** `spo store verify` and `spo store backup` print the head so the operator can record it off the machine.

### Backup and recovery

* `spo store backup` writes a consistent copy with `VACUUM INTO` and verifies it. Records in it are already sealed and it carries the same key slots.
* `spo store restore` verifies the backup, refuses a backup of another workspace, refuses an older backup over a newer workspace unless told to, and refuses while the workspace is open. Under its exclusive lock it first checkpoints any write-ahead log of the workspace being replaced, and refuses if it cannot, so that an old log is never replayed into the restored file. After a restore that reports an error or is interrupted, investigate before opening with `--accept-rollback`.
* `spo store recover` unlocks with the recovery key, requires a new passphrase, and rekeys.

### Memory

* The master key, derived keys and secret payloads live only in locked, guarded buffers. The amount a process may lock is limited (`ulimit -l`); the binary raises its soft limit, budgets every buffer, and returns an error instead of crashing when the budget is exhausted. Reading a 1 MiB secret needs about 3 MiB of lockable memory, and writing one about twice that; 8 MiB is a safe minimum.
* Copies the code cannot wipe: the key schedules inside the cipher and HMAC implementations, Argon2's working memory, and the outputs of the KDF functions (wiped on a best-effort basis). Swap should be off or encrypted (concern E4).

### Concurrency

One long-lived read connection and one gate per handle; every write uses its own short-lived connection. A call made from inside a callback of the same handle blocks until its context ends. Each handle holds a shared advisory file lock for its whole life. An open takes the lock exclusively for a moment while it reads, and others wait up to 5 seconds for it. A rekey or a restore needs the file exclusively and fails at once while any handle has it open, a read-only verify included. File locking is implemented for Unix systems only. Advisory locks do not bind a process that ignores them, and are unreliable on network file systems: keep the workspace on a local disk. The epoch check is what stops a stale handle from writing.

### What the file reveals without the passphrase

* The workspace id, key epoch and creation time.
* The number of slots, their kinds and KDF parameters.
* Per record: its random id, kind, version, time of last write, and that it is the same reference over time.
* The size bucket of each secret payload and the exact length of each sensitive payload.
* The number of audit rows, each row's kind and time, which record ids and versions it touched, and its event length to within 256 bytes.

Names of pools, wallets and parties are never stored in clear and never appear in error text.

## Operating conditions

The store's guarantees assume that:

* the system is Unix (Linux or macOS) and the workspace is on a local disk;
* the workspace and backup directories are writable only by the operator;
* nothing but `spo` opens or writes the file: no `sqlite3`, database browsers or sync clients;
* the head printed by `store verify` and `store backup` is recorded off the machine;
* the lockable-memory limit is at least 8 MiB;
* after a suspected compromise, the keys are rotated, not only the passphrase.

## Consequences

* Reading anything needs an unlock, `status` included.
* SQLCipher and CGO are avoided.
* The store is more than a key-value file: its integrity rules are what make counters (opcert, KES) trustworthy, and they cost one verification per open.
