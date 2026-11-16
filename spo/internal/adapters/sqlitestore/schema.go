package sqlitestore

// migrations are applied in order; schema_version holds the number applied.
// Never edit an entry once released: append a new one (S3). (No store existed
// before format version 1 was finalised, so entry 1 is the schema as it now
// stands.)
//
// SCHEMA. Everything in these tables is either structural (ids, kinds,
// versions, times, key-slot parameters, schema version; ADR 0004) or sealed.
//
//	meta      one row: workspace id (16 bytes), format version, creation time,
//	          key_epoch (16 random bytes, new at Init and at every Rekey),
//	          epoch_mac (HMAC-SHA256 under the audit key over the label,
//	          workspace id and key epoch; seal.AuditKey.EpochMAC) and
//	          cleanup_pending (1 from a rekey's commit until its VACUUM and
//	          WAL truncation have succeeded).
//	keyslots  one wrapped copy of the master key per row; see seal.Slot for the
//	          byte layouts. key_commit is HMAC-SHA256(slot key, label).
//	records   one row per artefact. lookup_tag is HMAC-SHA256 under the index
//	          key of the reference (a keyed hash; the name is not stored).
//	          nonce, wrapped_key, owner_sealed and ciphertext are the four
//	          parts of seal.SealedRecord. There is no class column: the class
//	          follows from the kind (ADR 0004) and is bound into the sealed
//	          data.
//	audit     append-only. kind is 'update' (records written or deleted),
//	          'slots' (the workspace was created or a key slot was added) or
//	          'rollover' (a rekey started a new segment under new keys). event
//	          is a sealed seal.SealedRecord.Bytes() of the event names, padded
//	          to a multiple of 256 bytes before sealing. touched is the
//	          canonical CBOR of [[record id, version, hash]...], see
//	          recordHash. slotset is SHA-256 of the canonical CBOR of all
//	          keyslots rows sorted by id (see slotSetHash) in 'slots' and
//	          'rollover' rows, and empty in 'update' rows. mac is the chain MAC
//	          over the row (including slotset) and prev_mac, which is the
//	          previous row's mac (32 zero bytes for the first row).
var migrations = []string{
	// 1: schema of format version 1.
	`
CREATE TABLE meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  workspace_id   BLOB    NOT NULL,
  format_version INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  key_epoch      BLOB    NOT NULL,
  epoch_mac      BLOB    NOT NULL,
  cleanup_pending INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE keyslots (
  id             BLOB PRIMARY KEY,
  kind           TEXT NOT NULL CHECK (kind IN ('passphrase', 'recovery')),
  kdf_memory_kib INTEGER,
  kdf_passes     INTEGER,
  kdf_lanes      INTEGER,
  salt           BLOB,
  key_commit     BLOB NOT NULL,
  nonce          BLOB NOT NULL,
  wrapped_key    BLOB NOT NULL
) STRICT;

CREATE TABLE records (
  id           BLOB    PRIMARY KEY,
  lookup_tag   BLOB    NOT NULL UNIQUE,
  kind         TEXT    NOT NULL,
  version      INTEGER NOT NULL,
  nonce        BLOB    NOT NULL,
  wrapped_key  BLOB    NOT NULL,
  owner_sealed BLOB    NOT NULL,
  ciphertext   BLOB    NOT NULL,
  updated_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE audit (
  seq      INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  kind     TEXT    NOT NULL CHECK (kind IN ('update', 'slots', 'rollover')),
  event    BLOB    NOT NULL,
  touched  BLOB    NOT NULL,
  slotset  BLOB    NOT NULL,
  mac      BLOB    NOT NULL,
  prev_mac BLOB    NOT NULL
) STRICT;
`,
}
