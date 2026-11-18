package sqlitestore

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Records implements ports.RecordLister for a transaction of the sealed store:
// the references of the records of one kind, including this transaction's own
// writes and without the ones it deleted. Each committed row is fetched with the
// same record-map comparison Get uses, and its owner blob must imply the row's
// lookup tag, or the result is an ErrVerify error that names nothing.
func (t *txn) Records(kind ports.Kind) ([]ports.Ref, error) {
	rs, err := t.q.QueryContext(t.ctx, `SELECT lookup_tag FROM records WHERE kind = ?`, string(kind))
	if err != nil {
		return nil, err
	}
	var tags [][]byte
	for rs.Next() {
		var tg []byte
		if err := rs.Scan(&tg); err != nil {
			rs.Close()
			return nil, err
		}
		tags = append(tags, tg)
	}
	if err := rs.Close(); err != nil {
		return nil, err
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	set := map[ports.Ref]bool{}
	for _, tg := range tags {
		rec, err := t.fetchTag(tg) // map comparison: ErrVerify on any mismatch
		if err != nil {
			return nil, err
		}
		ref, err := t.s.refOf(rec.id, rec.kind, rec.sealed)
		if err != nil {
			return nil, &VerifyError{Problems: []string{"a record's owner blob does not open"}}
		}
		if ref.Validate() != nil {
			return nil, &VerifyError{Problems: []string{"a record's owner blob names no valid artefact"}}
		}
		if want, err := tagFor(t.s.keys, ref.Anchor, string(kind), ref.Num); err != nil {
			return nil, err
		} else if !bytes.Equal(want, tg) {
			return nil, &VerifyError{Problems: []string{"a record's lookup tag does not match its owner"}}
		}
		set[ref] = true
	}
	for ref, o := range t.ops {
		if ref.Kind != kind {
			continue
		}
		if o.del {
			delete(set, ref)
		} else {
			set[ref] = true
		}
	}
	out := make([]ports.Ref, 0, len(set))
	for ref := range set {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Anchor.Compare(out[j].Anchor); c != 0 {
			return c < 0
		}
		return out[i].Num < out[j].Num
	})
	return out, nil
}

var _ ports.RecordLister = (*txn)(nil)

// ListRecords lists the reference of every record of a kind the catalogue
// knows, sorted by anchor, kind and number. It reads through View, so it takes
// the handle's gate, checks the key epoch and catches the record map up exactly
// as any read does. Every row is fetched with the same map comparison Get uses
// and its owner blob must imply the row's lookup tag; a row that fails to open
// or to match is an ErrVerify error that names nothing, and a record the chain
// lists and the table lacks is the same error. Kinds the catalogue does not
// know are left out. Nothing is written.
func (s *Store) ListRecords(ctx context.Context) ([]ports.Ref, error) {
	var out []ports.Ref
	err := s.View(ctx, func(r ports.Reader) error {
		t, ok := r.(*txn)
		if !ok {
			return errors.New("sqlitestore: unexpected reader")
		}
		type row struct {
			tag  []byte
			kind string
		}
		var rows []row
		rs, err := t.q.QueryContext(ctx, `SELECT lookup_tag, kind FROM records`)
		if err != nil {
			return err
		}
		for rs.Next() {
			var x row
			if err := rs.Scan(&x.tag, &x.kind); err != nil {
				rs.Close()
				return err
			}
			rows = append(rows, x)
		}
		if err := rs.Close(); err != nil {
			return err
		}
		if err := rs.Err(); err != nil {
			return err
		}
		if len(rows) != len(s.known.tags) {
			return errRecordChanged() // the chain lists a record the table lacks, or the table has an extra row
		}
		for _, x := range rows {
			rec, err := t.fetchTag(x.tag) // map comparison: ErrVerify on any mismatch
			if err != nil {
				return err
			}
			if !ports.Kind(x.kind).Known() {
				continue
			}
			ref, err := s.refOf(rec.id, rec.kind, rec.sealed)
			if err != nil {
				return &VerifyError{Problems: []string{"a record's owner blob does not open"}}
			}
			if ref.Validate() != nil {
				return &VerifyError{Problems: []string{"a record's owner blob names no valid artefact"}}
			}
			if want, err := tagFor(s.keys, ref.Anchor, x.kind, ref.Num); err != nil {
				return err
			} else if !bytes.Equal(want, x.tag) {
				return &VerifyError{Problems: []string{"a record's lookup tag does not match its owner"}}
			}
			out = append(out, ref)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if c := a.Anchor.Compare(b.Anchor); c != 0 {
			return c < 0
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Num < b.Num
	})
	return out, nil
}
