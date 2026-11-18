package layout_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
)

func recEntries(n int) []layout.RecordEntry {
	var e []layout.RecordEntry
	for i := 0; i < n; i++ {
		id := make([]byte, 16)
		id[0], id[1], id[2] = byte(i>>16), byte(i>>8), byte(i)
		e = append(e, layout.RecordEntry{ID: id, Version: uint64(i%5 + 1), Hash: pat(byte(i), 32)})
	}
	return e
}

func audEntries(from, n int) []layout.AuditEntry {
	var e []layout.AuditEntry
	for i := 0; i < n; i++ {
		e = append(e, layout.AuditEntry{Seq: uint64(from + i), Hash: pat(byte(i), 32)})
	}
	return e
}

func hashOfObj(t *testing.T, o layout.Object) []byte {
	t.Helper()
	b, err := layout.EncodeBody(o)
	if err != nil {
		t.Fatal(err)
	}
	return pat(b[len(b)-1], 32) // a stand-in: only the cross-page checks use hashes as opaque values
}

// spec: SPO-Xlayout-OUT-009
func TestManifestPagesAndRootRoundTrip(t *testing.T) {
	rp, err := layout.PageRecords(recEntries(1100))
	if err != nil {
		t.Fatal(err)
	}
	if len(rp) != 3 || len(rp[0].Entries) != layout.MaxRecordsPerPage || len(rp[2].Entries) != 1100-2*layout.MaxRecordsPerPage {
		t.Fatalf("pages: %d", len(rp))
	}
	ap, err := layout.PageAudit(audEntries(1, 2500))
	if err != nil {
		t.Fatal(err)
	}
	if len(ap) != 3 || len(ap[0].Entries) != 1000 || len(ap[2].Entries) != 500 {
		t.Fatalf("audit pages: %d", len(ap))
	}
	root := layout.Root{
		RecordPages: [][]byte{pat(1, 32), pat(2, 32), pat(3, 32)}, AuditPages: [][]byte{pat(4, 32), pat(5, 32), pat(6, 32)},
		Slots: pat(7, 32), AuditSeq: 2500, AuditMAC: pat(8, 32), Records: 1100, Audits: 2500,
		Parent: layout.Parent{Format: layout.ParentFormat, Seq: 1, PreviousHead: make([]byte, 32)},
	}
	if err := layout.VerifyManifest(root, rp, ap); err != nil {
		t.Fatal(err)
	}
	for _, o := range []layout.Object{rp[0], rp[2], ap[1], root} {
		b, err := layout.EncodeBody(o)
		if err != nil {
			t.Fatal(err)
		}
		got, err := layout.DecodeBody(b, rule)
		if err != nil {
			t.Fatal(err)
		}
		again, err := layout.EncodeBody(got)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("%T: not stable", o)
		}
	}
	if layout.ParentFormat != "provisional-1" || layout.AuditPageSize != 1000 {
		t.Fatal("constants")
	}
}

// Earlier audit pages are reused unchanged when rows are appended.
// spec: SPO-Xlayout-OUT-009
func TestAuditPagesAreAppendOnly(t *testing.T) {
	a, _ := layout.PageAudit(audEntries(1, 2000))
	b, _ := layout.PageAudit(audEntries(1, 2750))
	for i := range a {
		ea, _ := layout.EncodeBody(a[i])
		eb, _ := layout.EncodeBody(b[i])
		if !bytes.Equal(ea, eb) {
			t.Fatalf("page %d changed when rows were appended", i)
		}
	}
	if len(b) != 3 {
		t.Fatal(len(b))
	}
}

// spec: SPO-Xlayout-PRE-009
func TestManifestConsistencyRefusals(t *testing.T) {
	good := func() (layout.Root, []layout.RecordPage, []layout.AuditPage) {
		rp, _ := layout.PageRecords(recEntries(600))
		ap, _ := layout.PageAudit(audEntries(1, 1200))
		return layout.Root{RecordPages: [][]byte{pat(1, 32), pat(2, 32)}, AuditPages: [][]byte{pat(3, 32), pat(4, 32)}, Slots: pat(5, 32),
			AuditSeq: 1200, AuditMAC: pat(6, 32), Records: 600, Audits: 1200,
			Parent: layout.Parent{Format: layout.ParentFormat, Seq: 2, PreviousHead: pat(9, 32)}}, rp, ap
	}
	if r, rp, ap := good(); layout.VerifyManifest(r, rp, ap) != nil {
		t.Fatal("the good manifest was refused")
	}
	type mut func(*layout.Root, *[]layout.RecordPage, *[]layout.AuditPage)
	for name, m := range map[string]mut{
		"record count":   func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) { r.Records++ },
		"audit count":    func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) { r.Audits-- },
		"audit head seq": func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) { r.AuditSeq = 1199 },
		"page count":     func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) { r.RecordPages = r.RecordPages[:1] },
		"record order": func(_ *layout.Root, rp *[]layout.RecordPage, _ *[]layout.AuditPage) {
			(*rp)[0].Entries[0], (*rp)[0].Entries[1] = (*rp)[0].Entries[1], (*rp)[0].Entries[0]
		},
		"duplicate record id": func(_ *layout.Root, rp *[]layout.RecordPage, _ *[]layout.AuditPage) {
			(*rp)[1].Entries[0].ID = (*rp)[0].Entries[511].ID
		},
		"short middle page": func(_ *layout.Root, rp *[]layout.RecordPage, _ *[]layout.AuditPage) {
			(*rp)[0].Entries = (*rp)[0].Entries[:500]
		},
		"audit gap":     func(_ *layout.Root, _ *[]layout.RecordPage, ap *[]layout.AuditPage) { (*ap)[1].Entries[0].Seq++ },
		"audit not 1":   func(_ *layout.Root, _ *[]layout.RecordPage, ap *[]layout.AuditPage) { (*ap)[0].Entries[0].Seq = 2 },
		"parent format": func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) { r.Parent.Format = "provisional-2" },
		"first head with a previous": func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) {
			r.Parent.Seq = 1
		},
		"later head with no previous": func(r *layout.Root, _ *[]layout.RecordPage, _ *[]layout.AuditPage) {
			r.Parent.PreviousHead = make([]byte, 32)
		},
	} {
		r, rp, ap := good()
		m(&r, &rp, &ap)
		err := layout.VerifyManifest(r, rp, ap)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A page over its maximum cannot be built, and one that is decoded is refused.
	if _, err := layout.EncodeBody(layout.RecordPage{Entries: recEntries(layout.MaxRecordsPerPage + 1)}); err == nil {
		t.Error("a record page over the maximum was encoded")
	}
	if _, err := layout.EncodeBody(layout.AuditPage{Entries: audEntries(1, layout.AuditPageSize+1)}); err == nil {
		t.Error("an audit page over the maximum was encoded")
	}
	unsorted := layout.RecordPage{Entries: recEntries(3)}
	unsorted.Entries[0], unsorted.Entries[2] = unsorted.Entries[2], unsorted.Entries[0]
	if _, err := layout.EncodeBody(unsorted); err == nil {
		t.Error("an unsorted record page was encoded")
	}
	if _, err := layout.PageRecords(unsorted.Entries); err == nil {
		t.Error("PageRecords accepted unsorted entries")
	}
	for _, bad := range []layout.Root{
		{Parent: layout.Parent{Format: "x", Seq: 1, PreviousHead: make([]byte, 32)}, Slots: pat(1, 32), AuditMAC: pat(1, 32)},
		{Parent: layout.Parent{Format: layout.ParentFormat, Seq: 1, PreviousHead: make([]byte, 31)}, Slots: pat(1, 32), AuditMAC: pat(1, 32)},
		{Parent: layout.Parent{Format: layout.ParentFormat, Seq: 1, PreviousHead: make([]byte, 32)}, Slots: pat(1, 31), AuditMAC: pat(1, 32)},
		{Parent: layout.Parent{Format: layout.ParentFormat, Seq: 1, PreviousHead: make([]byte, 32)}, Slots: pat(1, 32), AuditMAC: pat(1, 3)},
		{Parent: layout.Parent{Format: layout.ParentFormat, Seq: 1, PreviousHead: make([]byte, 32)}, Slots: pat(1, 32), AuditMAC: pat(1, 32), RecordPages: [][]byte{pat(1, 5)}},
	} {
		if b, err := layout.EncodeBody(bad); err == nil {
			if _, err := layout.DecodeBody(b, rule); err == nil {
				t.Errorf("accepted root %+v", bad)
			}
		}
	}
	_ = fmt.Sprint
}

// A short page that is not the last is refused even when the counts still add
// up; audit pages must also run on without a gap or an overlap across the page
// boundary even when the head sequence and the count both agree with the last
// row.
// spec: SPO-Xlayout-PRE-009
func TestManifestCrossPageChecks(t *testing.T) {
	hashes := func(n int) [][]byte {
		var h [][]byte
		for i := 0; i < n; i++ {
			h = append(h, pat(byte(i), 32))
		}
		return h
	}
	mkRoot := func(rp, ap int, records, audits, auditSeq uint64) layout.Root {
		return layout.Root{RecordPages: hashes(rp), AuditPages: hashes(ap), Slots: pat(5, 32), AuditSeq: auditSeq, AuditMAC: pat(6, 32),
			Records: records, Audits: audits, Parent: layout.Parent{Format: layout.ParentFormat, Seq: 1, PreviousHead: make([]byte, 32)}}
	}
	// record pages 512, 100, 412: sorted, the counts add up, the middle page is short
	all := recEntries(1024)
	short := []layout.RecordPage{{Entries: all[:512]}, {Entries: all[512:612]}, {Entries: all[612:]}}
	if err := layout.VerifyManifest(mkRoot(3, 0, 1024, 0, 0), short, nil); err == nil {
		t.Error("a short middle record page was accepted")
	}
	// audit pages 1000, 100, 1000 with consecutive rows: the middle page is short
	a := audEntries(1, 2100)
	shortA := []layout.AuditPage{{Entries: a[:1000]}, {Entries: a[1000:1100]}, {Entries: a[1100:]}}
	if err := layout.VerifyManifest(mkRoot(0, 3, 0, 2100, 2100), nil, shortA); err == nil {
		t.Error("a short middle audit page was accepted")
	}
	// audit pages [1..1000], [1002..2001], [2001..2100]: a gap, then an overlap;
	// 2100 rows, last sequence number 2100, so the count and the head agree
	gap := append(audEntries(1, 1000), audEntries(1002, 1000)...)
	gap = append(gap, audEntries(2001, 100)...)
	pages := []layout.AuditPage{{Entries: gap[:1000]}, {Entries: gap[1000:2000]}, {Entries: gap[2000:]}}
	if err := layout.VerifyManifest(mkRoot(0, 3, 0, 2100, 2100), nil, pages); err == nil {
		t.Error("audit pages with a gap and an overlap were accepted")
	}
	// and the reviewer's case: [1..1000], [1..200]
	again := []layout.AuditPage{{Entries: audEntries(1, 1000)}, {Entries: audEntries(1, 200)}}
	if err := layout.VerifyManifest(mkRoot(0, 2, 0, 1200, 200), nil, again); err == nil {
		t.Error("audit pages [1..1000] [1..200] were accepted")
	}
}
