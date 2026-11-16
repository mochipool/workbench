package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// THE SCHEMA ALLOW-LIST
//
// Whoever can write the file can add a trigger, a view or a table to it, or
// rewrite a column definition, and SQLite then runs that code inside the
// store's own statements (a trigger that undoes an UPDATE of wrapped_key makes
// a rekey "succeed" and destroy every record). The audit chain does not cover
// the schema. So the store compares sqlite_master with the exact schema of the
// version the file declares:
//
//   - the expected schema is not written down a second time: it is what the
//     migrations produce. expectedSchema runs migrations[:version] in a private
//     in-memory database and reads its sqlite_master, which is therefore
//     byte-for-byte what SQLite itself writes for those statements (table
//     text, and the automatic indexes for PRIMARY KEY and UNIQUE
//     constraints, whose sql is NULL);
//   - every object of the file must be in that set with the same type,
//     table and text, and every object of that set must be in the file. A
//     trigger, view, extra table or index, a changed column, or a
//     sqlite_sequence table nobody asked for, is an error (ErrVerify wrapping
//     ErrSchema) that names the object's type and name;
//   - the schema_version table must hold exactly one row, the declared
//     version.
//
// The check runs on the read-only connection at Open before anything the file
// says is trusted, again after a migration, at the start of every write
// transaction (withWriteTx, so every Update, slot change and Rekey) and at
// the start of every verification. Reading sqlite_master does not run any
// trigger or view.

// schemaObj is one row of sqlite_master.
type schemaObj struct {
	typ, name, table string
	sql              sql.NullString // NULL for automatic indexes
}

func (o schemaObj) equal(p schemaObj) bool {
	return o.typ == p.typ && o.table == p.table && o.sql == p.sql
}

func readSchema(ctx context.Context, q dbq) (map[string]schemaObj, error) {
	rows, err := q.QueryContext(ctx, `SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]schemaObj{}
	for rows.Next() {
		var o schemaObj
		if err := rows.Scan(&o.typ, &o.name, &o.table, &o.sql); err != nil {
			return nil, err
		}
		out[o.typ+"\x00"+o.name] = o
	}
	return out, rows.Err()
}

var (
	expectedMu    sync.Mutex
	expectedCache = map[string]map[string]schemaObj{}
)

// expectedSchema is sqlite_master after migrations[:version], as described
// above. Results are cached per migration text (tests replace migrations).
func expectedSchema(ctx context.Context, version int) (map[string]schemaObj, error) {
	if version < 1 || version > len(migrations) {
		return nil, fmt.Errorf("sqlitestore: no schema for version %d", version)
	}
	key := strings.Join(migrations[:version], "\x00")
	expectedMu.Lock()
	defer expectedMu.Unlock()
	if m, ok := expectedCache[key]; ok {
		return m, nil
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1) // every new connection to :memory: is another, empty database
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := applyMigrations(ctx, tx, 0, version); err != nil {
		return nil, err
	}
	m, err := readSchema(ctx, tx)
	if err != nil {
		return nil, err
	}
	expectedCache[key] = m
	return m, nil
}

// schemaError is an ErrVerify that is also an ErrSchema.
func schemaError(format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrVerify, ErrSchema, fmt.Sprintf(format, a...))
}

// checkSchema compares the database with the schema of version v and with the
// schema_version row. It names the first difference only, by type and name.
func checkSchema(ctx context.Context, q dbq, v int) error {
	want, err := expectedSchema(ctx, v)
	if err != nil {
		return err
	}
	have, err := readSchema(ctx, q)
	if err != nil {
		return err
	}
	var keys []string
	for k := range have {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys { // extra objects first: they are what an attacker adds
		if _, ok := want[k]; !ok {
			return schemaError("unexpected %s %q", have[k].typ, have[k].name)
		}
	}
	for _, k := range keys {
		if !have[k].equal(want[k]) {
			return schemaError("%s %q differs from the schema of version %d", have[k].typ, have[k].name, v)
		}
	}
	for k, o := range want {
		if _, ok := have[k]; !ok {
			return schemaError("missing %s %q", o.typ, o.name)
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT version FROM schema_version`)
	if err != nil {
		return err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var got int
		if err := rows.Scan(&got); err != nil {
			return err
		}
		if n++; n > 1 || got != v {
			return schemaError("the schema_version table does not hold exactly version %d", v)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n != 1 {
		return schemaError("the schema_version table does not hold exactly version %d", v)
	}
	return nil
}

// declaredVersion reads the schema version the file declares. A file without
// a schema_version table is not a workspace. One whose schema_version is
// missing, empty or zero is a workspace that was modified (the version is
// only ever zero inside the transaction that creates the schema).
func declaredVersion(ctx context.Context, q dbq) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_version'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrNotWorkspace, err)
	}
	if n == 0 {
		return 0, ErrNotWorkspace
	}
	var v int
	err := q.QueryRowContext(ctx, `SELECT version FROM schema_version`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) || err == nil && v < 1 {
		return 0, schemaError("the schema_version table holds no valid version")
	}
	if err != nil {
		return 0, schemaError("the schema_version table cannot be read")
	}
	return v, nil
}
