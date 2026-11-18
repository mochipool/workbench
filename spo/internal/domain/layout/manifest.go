package layout

import (
	"bytes"
)

// THE MANIFEST. The sealed list of what a head names, in objects of the same
// envelope as records:
//
//	manifest-page, records  ["manifest-page", "records", [[record id, version, object hash]...]]
//	                        entries sorted by record id; at most MaxRecordsPerPage;
//	                        every page but the last holds exactly that many
//	manifest-page, audit    ["manifest-page", "audit", [[seq, object hash]...]]
//	                        AuditPageSize rows a page, consecutive from seq 1, so
//	                        appending rows leaves every full page byte for byte
//	                        as it was and the page's object is reused
//	manifest-root           ["manifest-root", record page hashes, audit page hashes,
//	                         slots object hash, audit head seq, audit head MAC,
//	                         record count, audit count, parent]
//	parent                  [parentFormat, seq, previous head hash]
//
// The root's `parent` is the one provisional part of the manifest: its format
// is the constant ParentFormat, a client refuses another, and stage 5 may
// change it (writing new manifest roots, never re-sealing a record). Nothing
// else in the root may change without a new format.
const (
	// MaxRecordsPerPage is the fixed maximum of a record page: 512 entries of
	// about 60 bytes fit a 32 KiB bucket.
	MaxRecordsPerPage = 512
	// AuditPageSize is the number of rows of an audit page (all but the last).
	AuditPageSize = 1000
	// ParentFormat is the provisional format of the root's parent field.
	ParentFormat = "provisional-1"
	// maxPageHashes bounds the page lists of a root so a decoder cannot be made
	// to build an enormous array from a small body.
	maxPageHashes = 1 << 16
)

// RecordEntry is one record of a record page.
type RecordEntry struct {
	ID      []byte
	Version uint64
	Hash    []byte // the object hash of the record's object
}

// AuditEntry is one audit row of an audit page.
type AuditEntry struct {
	Seq  uint64
	Hash []byte
}

// RecordPage is a page of the manifest's record list.
type RecordPage struct{ Entries []RecordEntry }

func (RecordPage) isObject() {}

// AuditPage is a page of the manifest's audit list.
type AuditPage struct{ Entries []AuditEntry }

func (AuditPage) isObject() {}

// Parent is the provisional part of the root: the sequence number of the
// head this manifest is for and the hash of the previous head note (all zeros
// for the first head).
type Parent struct {
	Format       string
	Seq          uint64
	PreviousHead []byte
}

// Root is the manifest root.
type Root struct {
	RecordPages [][]byte
	AuditPages  [][]byte
	Slots       []byte // object hash of the slots object
	AuditSeq    uint64
	AuditMAC    []byte
	Records     uint64
	Audits      uint64
	Parent      Parent
}

func (Root) isObject() {}

func validRecordPage(p RecordPage) error {
	if len(p.Entries) == 0 || len(p.Entries) > MaxRecordsPerPage {
		return formatErr("a record page holds 1 to %d entries, not %d", MaxRecordsPerPage, len(p.Entries))
	}
	for i, e := range p.Entries {
		if len(e.ID) != 16 || len(e.Hash) != HashSize {
			return formatErr("a record entry is a 16-byte id and a 32-byte hash")
		}
		if e.Version == 0 {
			return formatErr("a record version is at least 1")
		}
		if i > 0 && bytes.Compare(p.Entries[i-1].ID, e.ID) >= 0 {
			return formatErr("record entries are not sorted by id, or repeat")
		}
	}
	return nil
}

func validAuditPage(p AuditPage) error {
	if len(p.Entries) == 0 || len(p.Entries) > AuditPageSize {
		return formatErr("an audit page holds 1 to %d entries, not %d", AuditPageSize, len(p.Entries))
	}
	for i, e := range p.Entries {
		if len(e.Hash) != HashSize || e.Seq == 0 {
			return formatErr("an audit entry is a sequence number from 1 and a 32-byte hash")
		}
		if i > 0 && e.Seq != p.Entries[i-1].Seq+1 {
			return formatErr("audit entries are not consecutive")
		}
	}
	return nil
}

func encodeRecordPage(p RecordPage) ([]byte, error) {
	if err := validRecordPage(p); err != nil {
		return nil, err
	}
	es := make([]any, len(p.Entries))
	for i, e := range p.Entries {
		es[i] = []any{e.ID, e.Version, e.Hash}
	}
	return encodeCBOR([]any{KindManifestPage, pageRecords, es})
}

func encodeAuditPage(p AuditPage) ([]byte, error) {
	if err := validAuditPage(p); err != nil {
		return nil, err
	}
	es := make([]any, len(p.Entries))
	for i, e := range p.Entries {
		es[i] = []any{e.Seq, e.Hash}
	}
	return encodeCBOR([]any{KindManifestPage, pageAudit, es})
}

func decodePage(a []any) (Object, error) {
	if len(a) != 3 {
		return nil, formatErr("a manifest page has 3 items, not %d", len(a))
	}
	kind, err := text(a[1], "the page kind")
	if err != nil {
		return nil, err
	}
	list, ok := a[2].([]any)
	if !ok {
		return nil, formatErr("the page entries are not an array")
	}
	switch kind {
	case pageRecords:
		var p RecordPage
		for _, x := range list {
			e, err := arr(x, 3, "a record entry")
			if err != nil {
				return nil, err
			}
			var re RecordEntry
			if re.ID, err = fixed(e[0], 16, "a record id"); err != nil {
				return nil, err
			}
			if re.Version, err = uint64Of(e[1], "a record version"); err != nil {
				return nil, err
			}
			if re.Hash, err = fixed(e[2], HashSize, "an object hash"); err != nil {
				return nil, err
			}
			p.Entries = append(p.Entries, re)
		}
		return p, validRecordPage(p)
	case pageAudit:
		var p AuditPage
		for _, x := range list {
			e, err := arr(x, 2, "an audit entry")
			if err != nil {
				return nil, err
			}
			var ae AuditEntry
			if ae.Seq, err = uint64Of(e[0], "an audit sequence number"); err != nil {
				return nil, err
			}
			if ae.Hash, err = fixed(e[1], HashSize, "an object hash"); err != nil {
				return nil, err
			}
			p.Entries = append(p.Entries, ae)
		}
		return p, validAuditPage(p)
	}
	return nil, formatErr("unknown manifest page kind %q", kind)
}

func validRoot(r Root) error {
	if len(r.RecordPages) > maxPageHashes || len(r.AuditPages) > maxPageHashes {
		return formatErr("too many pages")
	}
	for _, h := range r.RecordPages {
		if len(h) != HashSize {
			return formatErr("a page hash is 32 bytes")
		}
	}
	for _, h := range r.AuditPages {
		if len(h) != HashSize {
			return formatErr("a page hash is 32 bytes")
		}
	}
	if len(r.Slots) != HashSize || len(r.AuditMAC) != HashSize {
		return formatErr("the slots object hash and the audit MAC are 32 bytes")
	}
	if r.Parent.Format != ParentFormat {
		return formatErr("unknown parent format %q (this version knows %q)", r.Parent.Format, ParentFormat)
	}
	if len(r.Parent.PreviousHead) != HashSize {
		return formatErr("the previous head hash is 32 bytes")
	}
	if r.Parent.Seq == 0 {
		return formatErr("a head sequence number is at least 1")
	}
	if (r.Parent.Seq == 1) != allZero(r.Parent.PreviousHead) {
		return formatErr("the previous head hash is all zeros exactly for the first head")
	}
	return nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func encodeRoot(r Root) ([]byte, error) {
	if err := validRoot(r); err != nil {
		return nil, err
	}
	hl := func(hs [][]byte) []any {
		out := make([]any, len(hs))
		for i, h := range hs {
			out[i] = h
		}
		return out
	}
	return encodeCBOR([]any{KindManifestRoot, hl(r.RecordPages), hl(r.AuditPages), r.Slots, r.AuditSeq, r.AuditMAC, r.Records, r.Audits,
		[]any{r.Parent.Format, r.Parent.Seq, r.Parent.PreviousHead}})
}

func hashList(v any, what string) ([][]byte, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, formatErr("%s is not an array", what)
	}
	if len(l) > maxPageHashes {
		return nil, formatErr("%s has too many entries", what)
	}
	out := make([][]byte, 0, len(l))
	for _, x := range l {
		h, err := fixed(x, HashSize, what)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

func decodeRoot(a []any) (Root, error) {
	if len(a) != 9 {
		return Root{}, formatErr("a manifest root has 9 items, not %d", len(a))
	}
	var r Root
	var err error
	if r.RecordPages, err = hashList(a[1], "the record page list"); err != nil {
		return r, err
	}
	if r.AuditPages, err = hashList(a[2], "the audit page list"); err != nil {
		return r, err
	}
	if r.Slots, err = fixed(a[3], HashSize, "the slots object hash"); err != nil {
		return r, err
	}
	if r.AuditSeq, err = uint64Of(a[4], "the audit head sequence"); err != nil {
		return r, err
	}
	if r.AuditMAC, err = fixed(a[5], HashSize, "the audit head MAC"); err != nil {
		return r, err
	}
	if r.Records, err = uint64Of(a[6], "the record count"); err != nil {
		return r, err
	}
	if r.Audits, err = uint64Of(a[7], "the audit count"); err != nil {
		return r, err
	}
	p, err := arr(a[8], 3, "the parent")
	if err != nil {
		return r, err
	}
	if r.Parent.Format, err = text(p[0], "the parent format"); err != nil {
		return r, err
	}
	if r.Parent.Seq, err = uint64Of(p[1], "the parent sequence"); err != nil {
		return r, err
	}
	if r.Parent.PreviousHead, err = fixed(p[2], HashSize, "the previous head hash"); err != nil {
		return r, err
	}
	return r, validRoot(r)
}

// PageRecords splits entries, sorted by id, into pages of MaxRecordsPerPage
// (the last page may be shorter). The split of a set is unique, so two
// writers agree on it.
func PageRecords(entries []RecordEntry) ([]RecordPage, error) {
	var out []RecordPage
	for i := 0; i < len(entries); i += MaxRecordsPerPage {
		j := min(i+MaxRecordsPerPage, len(entries))
		p := RecordPage{Entries: append([]RecordEntry(nil), entries[i:j]...)}
		if err := validRecordPage(p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	// ids must also be sorted across pages
	for i := 1; i < len(out); i++ {
		if bytes.Compare(out[i-1].Entries[len(out[i-1].Entries)-1].ID, out[i].Entries[0].ID) >= 0 {
			return nil, formatErr("record entries are not sorted by id, or repeat")
		}
	}
	return out, nil
}

// PageAudit splits entries, consecutive from sequence number 1, into pages of
// AuditPageSize. The pages of a prefix are the leading pages of the whole.
func PageAudit(entries []AuditEntry) ([]AuditPage, error) {
	var out []AuditPage
	for i := 0; i < len(entries); i += AuditPageSize {
		j := min(i+AuditPageSize, len(entries))
		p := AuditPage{Entries: append([]AuditEntry(nil), entries[i:j]...)}
		if err := validAuditPage(p); err != nil {
			return nil, err
		}
		if p.Entries[0].Seq != uint64(i)+1 {
			return nil, formatErr("audit entries do not start at sequence number 1 and run on without a gap")
		}
		out = append(out, p)
	}
	return out, nil
}

// VerifyManifest checks the root against the pages it names, which the caller
// has fetched, hashed and decoded (the page hashes in the root are the
// caller's to compare: this package holds no stored bytes). It checks the
// counts, that record ids are sorted across all pages, that every page but the
// last is full, that audit rows run from 1 without a gap to the head sequence
// number, and that the root's own fields are valid.
func VerifyManifest(r Root, rp []RecordPage, ap []AuditPage) error {
	if err := validRoot(r); err != nil {
		return err
	}
	if len(rp) != len(r.RecordPages) || len(ap) != len(r.AuditPages) {
		return formatErr("the root names %d record pages and %d audit pages; %d and %d were given", len(r.RecordPages), len(r.AuditPages), len(rp), len(ap))
	}
	var n uint64
	var last []byte
	for i, p := range rp {
		if err := validRecordPage(p); err != nil {
			return err
		}
		if i < len(rp)-1 && len(p.Entries) != MaxRecordsPerPage {
			return formatErr("record page %d is not full and is not the last", i)
		}
		if last != nil && bytes.Compare(last, p.Entries[0].ID) >= 0 {
			return formatErr("record ids are not sorted across pages, or repeat")
		}
		last = p.Entries[len(p.Entries)-1].ID
		n += uint64(len(p.Entries))
	}
	if n != r.Records {
		return formatErr("the root counts %d records and the pages hold %d", r.Records, n)
	}
	var seq, rows uint64
	for i, p := range ap {
		if err := validAuditPage(p); err != nil {
			return err
		}
		if i < len(ap)-1 && len(p.Entries) != AuditPageSize {
			return formatErr("audit page %d is not full and is not the last", i)
		}
		if p.Entries[0].Seq != seq+1 {
			return formatErr("audit rows do not run from 1 without a gap")
		}
		seq = p.Entries[len(p.Entries)-1].Seq
		rows += uint64(len(p.Entries))
	}
	if rows != r.Audits || seq != r.AuditSeq || r.Audits != r.AuditSeq {
		return formatErr("the root's audit count %d and head sequence %d are not the %d rows and last sequence number %d the pages hold", r.Audits, r.AuditSeq, rows, seq)
	}
	return nil
}
