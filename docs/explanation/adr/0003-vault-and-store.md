# ADR 0003: Sealed single-file store

Status: accepted, 2026-11-16. Closes E1, E2, E3 and S1; sets the audit design for S3.

## Context

One file per operator workspace holds everything (roadmap). Decision D7 seals every record payload. The construction must not depend on a database feature, so that the same records work on another back end later.

## Decision

### Database

SQLite through the pure-Go `modernc.org/sqlite` driver. The database itself is not encrypted. Every payload is sealed by the application before it is written, and every payload is opened after it is read. Table and column names, record ids, kinds, versions and timestamps of writes are visible to someone who holds the file; nothing else is ([ADR 0004](./0004-data-classification.md)).

### Keys

```
passphrase ──Argon2id──▶ slot key ─┐
recovery key ──HKDF────▶ slot key ─┼─unwrap──▶ master key (32 random bytes, made at init)
(later: hardware token) ▶ slot key ─┘                │ HKDF-SHA256, one label per purpose
                                                     ├─▶ record-wrapping key
                                                     ├─▶ index key (keyed hashes for lookups)
                                                     └─▶ audit key (hash-chain MAC)
```

* **Key slots.** The master key is stored once per slot, wrapped with XChaCha20-Poly1305 under that slot's key. A workspace has at least one passphrase slot and one recovery slot. A slot can be added or removed without re-encrypting records. A later hardware-token slot is another row.
* **Passphrase slot.** Argon2id with a 16-byte random salt. Defaults: 256 MiB memory, 3 passes, 4 lanes. The parameters are stored in the slot. The binary refuses parameters below 64 MiB and 3 passes, so a modified file cannot weaken them unnoticed.
* **Recovery slot.** 32 random bytes generated at init and shown once, as grouped text to print. It has full entropy, so it goes through HKDF, not Argon2id.
* **Associated data of a slot:** format version, workspace id, slot id, slot kind and the KDF parameters.

### Records

Each record has its own random 32-byte data key. The payload is sealed with XChaCha20-Poly1305 under the data key with a random 24-byte nonce. The data key is wrapped under the record-wrapping key.

The associated data of both operations is the canonical CBOR encoding of `[format version, workspace id, record id, kind, owner aggregate id, class, record version]`. A ciphertext moved to another record, kind, owner, class or version fails to open (this closes SPO-Ckey-SEC-004).

Lookups by a sensitive value (an address, a pool id) use a keyed hash of the value under the index key. The value itself is never a column.

### Unlocking

There is no background agent in the first version. A command prompts for the passphrase, or reads it from a file descriptor given with `--passphrase-fd`. The TUI unlocks once per session. The master key and everything derived from it live in guarded memory (E4).

### Writes, versions and the audit log

* An aggregate is written in one SQLite transaction with a version check (S2).
* The audit log is an append-only table. Each row carries the event, the ids and ciphertext hashes of the records written with it, and a MAC under the audit key over the row and the previous row's MAC.
* `spo store verify` walks the chain and checks that every record's current ciphertext hash is the last one the chain recorded for it. This detects a record rolled back to an older ciphertext. Replacing the whole file with an older copy cannot be detected from the file alone; the threat model says so.

### Backup and recovery

* `spo store backup` writes a consistent copy of the file. Records in it are already sealed, so the copy needs no further encryption, and it carries the same key slots.
* `spo store verify --backup <file>` opens a backup read-only and runs the full verification without restoring it.
* `spo store restore` replaces the workspace from a verified backup.
* A test restores a backup into an empty directory and signs with a restored key.

### Test vectors

Vectors for slot wrapping, record sealing and the associated-data encoding are committed under `spo/internal/platform/seal/testdata/` and checked by the unit tests. A change to the format bumps the format version and adds vectors; old vectors keep passing.

## Consequences

* Reading anything needs an unlock, `status` included.
* The file reveals how many records of each kind exist and when they changed.
* SQLCipher and CGO are avoided.
