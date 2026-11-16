package sqlitestore

// migrations are applied in order; schema_version holds the number applied.
// Never edit an entry once released: append a new one (S3).
//
// Everything in these tables is either structural (ids, kinds, classes,
// versions, times, key-slot parameters, schema version; ADR 0004) or sealed.
var migrations = []string{
	// 1: initial schema.
	`
CREATE TABLE meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  workspace_id   BLOB    NOT NULL,
  format_version INTEGER NOT NULL,
  created_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE keyslots (
  id             BLOB PRIMARY KEY,
  kind           TEXT NOT NULL CHECK (kind IN ('passphrase', 'recovery')),
  kdf_memory_kib INTEGER,
  kdf_passes     INTEGER,
  kdf_lanes      INTEGER,
  salt           BLOB,
  nonce          BLOB NOT NULL,
  wrapped_key    BLOB NOT NULL
) STRICT;

CREATE TABLE records (
  id          BLOB    PRIMARY KEY,
  lookup_tag  BLOB    NOT NULL UNIQUE,
  kind        TEXT    NOT NULL,
  class       TEXT    NOT NULL CHECK (class IN ('secret', 'sensitive')),
  version     INTEGER NOT NULL,
  nonce       BLOB    NOT NULL,
  wrapped_key BLOB    NOT NULL,
  ciphertext  BLOB    NOT NULL,
  updated_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE audit (
  seq      INTEGER PRIMARY KEY,
  at       INTEGER NOT NULL,
  event    BLOB    NOT NULL,
  touched  BLOB    NOT NULL,
  mac      BLOB    NOT NULL,
  prev_mac BLOB    NOT NULL
) STRICT;
`,
}
