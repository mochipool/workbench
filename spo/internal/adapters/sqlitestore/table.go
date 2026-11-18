package sqlitestore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
)

// THE SLOT TABLE OF STORE FORMAT 3 (ADR 0011, decisions 3 and 6).
//
// keyslots holds one row per slot of the kinds passphrase, recovery,
// fido2-hmac and composite. Three columns are new: bound (1 when the slot's
// associated data binds the policy and the recovery public key hash; 0 for a
// passphrase or recovery slot carried over from format 2), rec_hash (the
// recovery public key hash the slot binds) and factors (the canonical CBOR of
// the factor entries of a fido2-hmac or composite slot). meta.policy holds the
// workspace policy.
//
// None of these columns is trusted on its own. Every slot of format 3 binds the
// policy and the recovery public key hash in its associated data, and a
// fido2-hmac or composite slot binds its factor entries there too, so a row or
// the policy edited to say something else makes the slot fail to open, whatever
// the opener reads. The opener also runs domain/unlock on the table before any
// factor is asked for: a table that breaks its own policy is refused, and an
// attacker who can edit the file can therefore only make the workspace refuse
// to open, never open it with a weaker factor set.

// ErrPolicyViolated: the slot table breaks the policy it declares. The error
// wraps *unlock.Error and unlock.ErrPolicy.
var ErrPolicyViolated = errors.New("sqlitestore: the slot table breaks its unlock policy")

// ErrFormat2 is returned for a workspace of store format 2.
var ErrFormat2 = errors.New("sqlitestore: this workspace is in store format 2, which has no slot kinds or policy; this version reads format 3. Convert it with: spo workspace migrate")

// tslot is one row of the slot table.
type tslot struct {
	id    []byte
	kind  string
	ps    seal.Slot       // passphrase and recovery slots
	fs    seal.FactorSlot // fido2-hmac and composite slots
	bound bool
	// recPub is the recovery public key (X25519, 32 bytes) a slot built by this
	// process binds the hash of. It is not a column of the slot row: the rekey
	// that writes the table stores it in meta.recovery_pub (cold-role records are
	// wrapped to it). Empty for a slot read from a file and for a table with no
	// recovery path.
	recPub []byte
}

func (t tslot) isFactor() bool { return t.kind == seal.SlotFIDO2HMAC || t.kind == seal.SlotComposite }

func (t tslot) recHash() []byte {
	if t.isFactor() {
		return t.fs.Spec.RecoveryPubKeyHash
	}
	if t.ps.Binding != nil {
		return t.ps.Binding.RecoveryPubKeyHash
	}
	return nil
}

// table is the slot table with its policy and the format the file declares.
type table struct {
	ws     []byte
	format uint64
	policy unlock.Policy
	slots  []tslot
}

func hasColumn(ctx context.Context, q dbq, tbl, col string) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, tbl, col).Scan(&n)
	return n > 0, err
}

// loadTable reads the meta row's policy and every slot row. The schema has been
// checked by now.
func loadTable(ctx context.Context, q dbq, ws []byte, format uint64) (*table, error) {
	t := &table{ws: ws, format: format, policy: unlock.Standard}
	v3, err := hasColumn(ctx, q, "keyslots", "factors")
	if err != nil {
		return nil, err
	}
	if v3 != (format >= seal.StoreFormat) {
		return nil, &VerifyError{Problems: []string{"the schema of the key slots does not match the format version of the meta row (it was modified)"}}
	}
	if v3 {
		var pol string
		if err := q.QueryRowContext(ctx, `SELECT policy FROM meta WHERE id = 1`).Scan(&pol); err != nil {
			return nil, &VerifyError{Problems: []string{"the meta row has no readable policy (it was modified)"}}
		}
		t.policy = unlock.Policy(pol)
	}
	cols := `id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key`
	if v3 {
		cols += `, bound, rec_hash, factors`
	}
	rows, err := q.QueryContext(ctx, `SELECT `+cols+` FROM keyslots ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ts tslot
		var s seal.Slot
		var mem, passes, lanes sql.NullInt64
		var bound sql.NullInt64
		var rec, factors []byte
		dest := []any{&s.ID, &s.Kind, &mem, &passes, &lanes, &s.Salt, &s.Commit, &s.Nonce, &s.Wrapped}
		if v3 {
			dest = append(dest, &bound, &rec, &factors)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		s.KDF = seal.KDFParams{MemoryKiB: uint32(mem.Int64), Passes: uint32(passes.Int64), Lanes: uint8(lanes.Int64)}
		if mem.Int64 < 0 || mem.Int64 > 1<<32-1 || passes.Int64 < 0 || passes.Int64 > 1<<32-1 || lanes.Int64 < 0 || lanes.Int64 > 255 {
			s.KDF = seal.KDFParams{} // out of range values wrap: zero is refused as weak
		}
		ts, err := buildTSlot(t, ws, s, bound.Int64 == 1, rec, factors)
		if err != nil {
			return nil, err
		}
		t.slots = append(t.slots, ts)
	}
	return t, rows.Err()
}

// buildTSlot turns the columns of one slot row into a tslot of table t (whose
// policy it binds). It is the one place a row is parsed: the file reader and the
// layout reader (layoutkeys.go) both use it.
func buildTSlot(t *table, ws []byte, s seal.Slot, bound bool, rec, factors []byte) (tslot, error) {
	var ts tslot
	ts.id, ts.kind, ts.bound = s.ID, s.Kind, bound
	switch s.Kind {
	case seal.SlotPassphrase, seal.SlotRecovery:
		if ts.bound {
			s.Binding = &seal.SlotBinding{Policy: string(t.policy), RecoveryPubKeyHash: rec}
		}
		ts.ps = s
	case seal.SlotFIDO2HMAC, seal.SlotComposite:
		fl, err := seal.DecodeFactors(factors)
		if err != nil {
			return ts, fmt.Errorf("%w: slot %x: %v", ErrCorrupt, s.ID, err)
		}
		ts.fs = seal.FactorSlot{
			Spec: seal.SlotSpec{FormatVersion: seal.StoreFormat, GenesisNonce: ws, SlotID: s.ID, Kind: s.Kind,
				Factors: fl, RecoveryPubKeyHash: rec, Policy: string(t.policy)},
			Commit: s.Commit, Nonce: s.Nonce, Wrapped: s.Wrapped,
		}
	default:
		return ts, fmt.Errorf("%w: slot kind %q", ErrCorrupt, s.Kind)
	}
	return ts, nil
}

// check runs domain/unlock on the table.
func (t *table) check() error {
	ut := unlock.Table{Policy: t.policy}
	for _, s := range t.slots {
		ut.Slots = append(ut.Slots, s.toUnlock())
	}
	if err := unlock.Check(ut); err != nil {
		for _, r := range unlock.Rules(err) {
			if r == unlock.RuleStandardSlots || r == unlock.RuleTable || r == unlock.RuleDailySlot {
				return fmt.Errorf("%w: %w: %w", ErrPolicyViolated, ErrLastSlot, err)
			}
		}
		return fmt.Errorf("%w: %w", ErrPolicyViolated, err)
	}
	return nil
}

func (t tslot) toUnlock() unlock.Slot {
	us := unlock.Slot{ID: t.id, Kind: unlock.SlotKind(t.kind), RecoveryPubKeyHash: t.recHash()}
	switch t.kind {
	case seal.SlotPassphrase:
		us.Factors = []unlock.Factor{{Kind: unlock.Passphrase, ID: t.id}}
		us.Legacy = !t.bound
	case seal.SlotRecovery:
		// One recovery secret derives the bound public key, so every bound
		// recovery factor has the id of that key's hash. Legacy recovery slots
		// are of unknown, possibly several, keys: they share one id and are
		// not told apart (format 2 allowed more than one recovery slot).
		id := t.recHash()
		if !t.bound {
			id = []byte("legacy")
		}
		us.Factors = []unlock.Factor{{Kind: unlock.Recovery, ID: id}}
		us.Legacy = !t.bound
	default:
		for _, f := range t.fs.Spec.Factors {
			uf := unlock.Factor{ID: f.ID}
			switch f.Kind {
			case seal.FactorPassphrase:
				uf.Kind = unlock.Passphrase
			case seal.FactorRecovery:
				uf.Kind = unlock.Recovery
			case seal.FactorFIDO2:
				uf.Kind = unlock.FIDO2
			case seal.FactorBackend:
				uf.Kind = unlock.Backend
			}
			us.Factors = append(us.Factors, uf)
		}
	}
	return us
}

// commonRecHash returns the recovery public key hash the bound slots agree on,
// and whether any slot is bound. ok is false when bound slots disagree.
func (t *table) commonRecHash() (hash []byte, any, ok bool) {
	for _, s := range t.slots {
		if s.kind == seal.SlotPassphrase || s.kind == seal.SlotRecovery {
			if !s.bound {
				continue
			}
		}
		h := s.recHash()
		if !any {
			hash, any = h, true
			continue
		}
		if !bytes.Equal(hash, h) {
			return nil, true, false
		}
	}
	return hash, any, true
}

// insertTSlot writes a slot row.
func insertTSlot(ctx context.Context, q dbq, s tslot) error {
	var mem, passes, lanes, salt, factors any
	bound := int64(0)
	var rec []byte
	var commit, nonce, wrapped []byte
	switch {
	case s.isFactor():
		b, err := seal.EncodeFactors(s.fs.Spec.Factors)
		if err != nil {
			return err
		}
		factors, bound, rec = b, 1, s.fs.Spec.RecoveryPubKeyHash
		commit, nonce, wrapped = s.fs.Commit, s.fs.Nonce, s.fs.Wrapped
	default:
		if s.kind == seal.SlotPassphrase {
			mem, passes, lanes, salt = int64(s.ps.KDF.MemoryKiB), int64(s.ps.KDF.Passes), int64(s.ps.KDF.Lanes), s.ps.Salt
		}
		if s.ps.Binding != nil {
			bound, rec = 1, s.ps.Binding.RecoveryPubKeyHash
		}
		commit, nonce, wrapped = s.ps.Commit, s.ps.Nonce, s.ps.Wrapped
	}
	var recV any
	if bound == 1 {
		recV = append([]byte{}, rec...) // empty, not NULL, when strict binds none
	}
	_, err := q.ExecContext(ctx, `INSERT INTO keyslots (id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key, bound, rec_hash, factors) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.id, s.kind, mem, passes, lanes, salt, commit, nonce, wrapped, bound, recV, factors)
	return err
}

// tslotEqual compares what insertTSlot stores.
func tslotEqual(a, b tslot) bool {
	if a.kind != b.kind || a.bound != b.bound || !bytes.Equal(a.recHash(), b.recHash()) {
		return false
	}
	if a.isFactor() {
		fa, e1 := seal.EncodeFactors(a.fs.Spec.Factors)
		fb, e2 := seal.EncodeFactors(b.fs.Spec.Factors)
		return e1 == nil && e2 == nil && bytes.Equal(fa, fb) && bytes.Equal(a.fs.Commit, b.fs.Commit) && bytes.Equal(a.fs.Nonce, b.fs.Nonce) && bytes.Equal(a.fs.Wrapped, b.fs.Wrapped)
	}
	return slotEqual(a.ps, b.ps)
}

// writePolicy sets meta.policy.
func writePolicy(ctx context.Context, q dbq, p unlock.Policy) error {
	_, err := q.ExecContext(ctx, `UPDATE meta SET policy = ?`, string(p))
	return err
}

// tableSetHash is the slot-set hash of a format 3 file: SHA-256 of the
// canonical CBOR of ["spo/slotset/3", policy, rows] where rows are all twelve
// keyslots columns, sorted by id. The policy is in it, so a 'slots' or
// 'rollover' audit row records the policy together with the slot table.
func tableSetHash(ctx context.Context, q dbq) ([]byte, error) {
	var pol string
	if err := q.QueryRowContext(ctx, `SELECT policy FROM meta WHERE id = 1`).Scan(&pol); err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit, nonce, wrapped_key, bound, rec_hash, factors FROM keyslots ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var all [][]any
	for rows.Next() {
		row := make([]any, 12)
		ptr := make([]any, 12)
		for i := range row {
			ptr[i] = &row[i]
		}
		if err := rows.Scan(ptr...); err != nil {
			return nil, err
		}
		all = append(all, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	b, err := seal.EncodeCanonical([]any{"spo/slotset/3", pol, all})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// Describe reads the policy and the slot table of the workspace file at path
// without any key: structural data only (ADR 0004). It is how a command decides
// which factors to ask for before it prompts. The file is read under the same
// checks as an open's first stage (regular file, owner, mode, schema), and a
// table that breaks its policy is refused here too.
func Describe(path string) (unlock.Policy, []SlotInfo, error) {
	ctx := context.Background()
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	if err := checkFile(abs); err != nil {
		return "", nil, err
	}
	m, t, err := readUnlockInputs(ctx, abs, false) // the connection is read-only either way; false lets an old schema through to the format refusal below
	if err != nil {
		return "", nil, err
	}
	switch uint64(m.format) {
	case seal.LegacyRecordFormat:
		return "", nil, ErrLegacyFormat
	case seal.RecordFormat:
		return "", nil, ErrFormat2
	}
	if err := t.check(); err != nil {
		return "", nil, fmt.Errorf("%w: the slot table of this workspace was edited or is damaged (run `spo store verify` to see what differs): %w", ErrVerify, err)
	}
	return t.policy, t.infos(), nil
}

func (t *table) infos() []SlotInfo {
	var out []SlotInfo
	for _, x := range t.slots {
		info := SlotInfo{ID: x.id, Kind: x.kind, Legacy: !x.bound, RecoveryPubKeyHash: x.recHash()}
		if !x.isFactor() {
			info.KDF = x.ps.KDF
		}
		for _, f := range x.toUnlock().Factors {
			fi := FactorInfo{Kind: string(f.Kind), ID: f.ID}
			if x.isFactor() {
				for _, sf := range x.fs.Spec.Factors {
					if sf.Kind == seal.FactorFIDO2 && bytes.Equal(sf.ID, f.ID) {
						fi.CredentialID = sf.CredentialID
						fi.Touch = sf.Touch
					}
				}
			}
			info.Factors = append(info.Factors, fi)
		}
		out = append(out, info)
	}
	return out
}
