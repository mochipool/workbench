package sqlitestore

import (
	"context"
	"errors"
	"sort"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// List implements ports.SourceLister for the sealed store: every record whose
// kind the catalogue knows, as the reference its sealed owner blob names.
//
// It reads through View, so it takes the handle's gate, checks the key epoch
// and catches the record map up exactly as any read does. Each row is then
// fetched with the same map comparison Get uses (fetchTag), its owner blob is
// opened with the handle's keys, and the lookup tag the owner implies must be
// the row's. A row that fails to open or to match is an ErrVerify error that
// names nothing (artefact names are Sensitive); no row is skipped silently. A
// record the chain lists and the table lacks is the same error. Kinds the
// catalogue does not know are not artefacts and are left out. Nothing is
// written. The result is sorted by name, kind and number.
//
// spec: SPO-Pfiles-IN-001
func (s *Store) List(ctx context.Context) (ports.SourceListing, error) {
	var out ports.SourceListing
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
			ownerStr, err := s.keys.OpenOwner(s.ws, rec.id, rec.kind, rec.sealed)
			if err != nil {
				return &VerifyError{Problems: []string{"a record's owner blob does not open"}}
			}
			name, num, err := parseOwner(ownerStr)
			if err != nil {
				return &VerifyError{Problems: []string{"a record's owner blob is malformed"}}
			}
			ref := ports.Ref{Name: name, Kind: ports.Kind(x.kind), Num: num}
			if ref.Validate() != nil {
				return &VerifyError{Problems: []string{"a record's owner blob names no valid artefact"}}
			}
			if want, err := tagFor(s.keys, name, x.kind, num); err != nil {
				return err
			} else if string(want) != string(x.tag) {
				return &VerifyError{Problems: []string{"a record's lookup tag does not match its owner"}}
			}
			out.Entries = append(out.Entries, ports.SourceEntry{Ref: ref})
		}
		return nil
	})
	if err != nil {
		return ports.SourceListing{}, err
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i].Ref, out.Entries[j].Ref
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Num < b.Num
	})
	return out, nil
}

var _ ports.SourceLister = (*Store)(nil)
