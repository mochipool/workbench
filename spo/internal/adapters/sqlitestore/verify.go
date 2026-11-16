package sqlitestore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// ErrVerify is wrapped by every verification failure.
var ErrVerify = errors.New("sqlitestore: verification failed")

// VerifyError lists everything Verify found wrong.
type VerifyError struct{ Problems []string }

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%v: %d problem(s): %s", ErrVerify, len(e.Problems), strings.Join(e.Problems, "; "))
}

func (e *VerifyError) Is(target error) bool { return target == ErrVerify }

type chainState struct {
	version uint64
	hash    []byte
	deleted bool
}

// Verify checks the audit chain and the records against it, at one snapshot:
//
//   - audit sequence numbers are 1, 2, 3, ... with no gap;
//   - each row's prev_mac is the previous row's mac (zeros for the first);
//   - each row's mac is the MAC of its content under the audit key;
//   - every record's current (version, hash of nonce||wrapped key||ciphertext)
//     equals the last entry the chain recorded for it;
//   - no record exists that the chain never recorded or recorded as deleted,
//     and no record the chain recorded as live is missing.
//
// It does not decrypt records (their owner names are not in the file) and it
// cannot detect replacing the whole file by an older, internally consistent
// copy, nor truncating the newest audit rows together with reverting the
// records they covered.
func (s *Store) Verify(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var problems []string
	bad := func(f string, a ...any) { problems = append(problems, fmt.Sprintf(f, a...)) }

	state := map[string]chainState{}
	rows, err := tx.QueryContext(ctx, `SELECT seq, at, event, touched, mac, prev_mac FROM audit ORDER BY seq`)
	if err != nil {
		return err
	}
	expectSeq := int64(1)
	prevMAC := zeroMAC
	for rows.Next() {
		var seq, at int64
		var event, touchedRaw, mac, prev []byte
		if err := rows.Scan(&seq, &at, &event, &touchedRaw, &mac, &prev); err != nil {
			rows.Close()
			return err
		}
		if seq != expectSeq {
			bad("audit sequence jumps from %d to %d (row missing, added or reordered)", expectSeq-1, seq)
			expectSeq = seq
		}
		expectSeq++
		if !bytes.Equal(prev, prevMAC) {
			bad("audit row %d: prev_mac does not match the previous row", seq)
		}
		rowBytes, err := auditRowBytes(s.ws, uint64(seq), at, event, touchedRaw)
		if err != nil {
			rows.Close()
			return err
		}
		ok, err := s.keys.Audit.Check(prev, rowBytes, mac)
		if err != nil {
			rows.Close()
			return err
		}
		if !ok {
			bad("audit row %d: MAC mismatch (row modified)", seq)
		}
		prevMAC = mac
		var entries []touched
		if err := cbor.Unmarshal(touchedRaw, &entries); err != nil {
			bad("audit row %d: unreadable touched list", seq)
			continue
		}
		for _, e := range entries {
			state[string(e.ID)] = chainState{version: e.Version, hash: e.Hash, deleted: len(e.Hash) == 0}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rrows, err := tx.QueryContext(ctx, `SELECT id, version, nonce, wrapped_key, ciphertext FROM records ORDER BY rowid`)
	if err != nil {
		return err
	}
	defer rrows.Close()
	seen := map[string]bool{}
	for rrows.Next() {
		var id []byte
		var v int64
		var r seal.SealedRecord
		if err := rrows.Scan(&id, &v, &r.Nonce, &r.WrappedKey, &r.Ciphertext); err != nil {
			return err
		}
		seen[string(id)] = true
		name := hex.EncodeToString(id)
		st, ok := state[string(id)]
		switch {
		case !ok:
			bad("record %s is not in the audit chain (injected?)", name)
		case st.deleted:
			bad("record %s is present but the audit chain recorded its deletion (restored?)", name)
		case st.version != uint64(v) || !bytes.Equal(st.hash, sealedHash(r)):
			bad("record %s does not match the audit chain (rolled back or modified; chain has version %d, file has %d)", name, st.version, v)
		}
	}
	if err := rrows.Err(); err != nil {
		return err
	}
	for id, st := range state {
		if !st.deleted && !seen[id] {
			bad("record %s is recorded in the audit chain but missing from the file", hex.EncodeToString([]byte(id)))
		}
	}
	if len(problems) > 0 {
		return &VerifyError{Problems: problems}
	}
	return nil
}

// VerifyFile opens the workspace read-only with the passphrase and runs
// Verify. It writes nothing to the file.
func VerifyFile(path string, passphrase *secret.Buffer) error {
	return verifyFile(path, credential{seal.SlotPassphrase, passphrase})
}

// VerifyFileWithRecovery is VerifyFile with the printed recovery key.
func VerifyFileWithRecovery(path string, recovery *secret.Buffer) error {
	raw, err := seal.DecodeRecoveryKey(recovery)
	if err != nil {
		return err
	}
	defer raw.Destroy()
	return verifyFile(path, credential{seal.SlotRecovery, raw})
}

func verifyFile(path string, cred credential) error {
	s, err := open(path, cred, true)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Verify(context.Background())
}
