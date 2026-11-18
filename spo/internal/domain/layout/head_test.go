package layout_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
)

func sampleHead() layout.Head {
	return layout.Head{Workspace: pat(0x20, 16), Sequence: 2, Previous: pat(0x30, 32), Manifest: pat(0x40, 32), Slots: pat(0x50, 32),
		AuditSeq: 17, AuditMAC: pat(0x60, 32), RecoveryKey: pat(0x70, 32), CheckpointKey: pat(0x80, 32), Epoch: pat(0xf0, 16), Time: time.Date(2026, 11, 18, 12, 30, 5, 0, time.UTC)}
}

// spec: SPO-Xlayout-OUT-012
func TestHeadNoteText(t *testing.T) {
	h := sampleHead()
	note, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := "spo/head-provisional/1\n" +
		"workspace 202122232425262728292a2b2c2d2e2f\n" +
		"sequence 2\n" +
		"previous 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f\n" +
		"manifest 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n" +
		"slots 505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f\n" +
		"audit-seq 17\n" +
		"audit-mac 606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n" +
		"recovery-key 707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f\n" +
		"checkpoint-key 808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\n" +
		"epoch f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\n" +
		"object-format spo/object/1\n" +
		"time 2026-11-18T12:30:05Z\n"
	if string(note) != want {
		t.Fatalf("note:\n%s", note)
	}
	got, err := layout.ParseHead(note)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := got.Encode()
	if !bytes.Equal(again, note) {
		t.Fatal("does not re-encode to itself")
	}
	if layout.HeadPath(2) != "heads/00000000000000000002" || layout.HeadPath(18446744073709551615) != "heads/18446744073709551615" {
		t.Fatalf("path %s", layout.HeadPath(2))
	}
	if layout.NamespaceHead != "spo/head-provisional/v1" || layout.TagHead != "spo/head-provisional/1" {
		t.Fatal("namespace or tag")
	}
	// Blake2b-256 of the note bytes.
	if hh := layout.HeadHash(note); len(hh) != 32 || !bytes.Equal(hh, hx(layout.ObjectName(note))) {
		t.Fatal("the head hash is not Blake2b-256 of the note")
	}
	// the first head: no previous, and none-recovery.
	first := h
	first.Sequence, first.Previous, first.RecoveryKey, first.CheckpointKey = 1, make([]byte, 32), nil, nil
	n1, err := first.Encode()
	if err != nil || !strings.Contains(string(n1), "previous "+strings.Repeat("0", 64)+"\n") || !strings.Contains(string(n1), "recovery-key none\n") || !strings.Contains(string(n1), "checkpoint-key none\n") {
		t.Fatalf("%v %s", err, n1)
	}
	if _, err := layout.ParseHead(n1); err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-Xlayout-PRE-010
func TestHeadParsingIsStrict(t *testing.T) {
	h := sampleHead()
	good, _ := h.Encode()
	s := string(good)
	rep := func(old, new string) string { return strings.Replace(s, old, new, 1) }
	cases := map[string]string{
		"no final line feed":  strings.TrimSuffix(s, "\n"),
		"extra line":          s + "extra 1\n",
		"blank line":          s + "\n",
		"wrong tag":           rep("spo/head-provisional/1", "spo/head-provisional/2"),
		"reordered keys":      rep("sequence 2\nprevious", "previous") + "",
		"upper-case hex":      rep("202122232425262728292a2b2c2d2e2f", "202122232425262728292A2B2C2D2E2F"),
		"leading zero":        rep("sequence 2", "sequence 02"),
		"plus sign":           rep("sequence 2", "sequence +2"),
		"zero sequence":       rep("sequence 2", "sequence 0"),
		"huge number":         rep("audit-seq 17", "audit-seq 18446744073709551616"),
		"short hash":          rep("slots 5051", "slots 51"),
		"workspace length":    rep("workspace 2021", "workspace 21"),
		"double space":        rep("sequence 2", "sequence  2"),
		"tab":                 rep("sequence 2", "sequence\t2"),
		"carriage return":     strings.ReplaceAll(s, "\n", "\r\n"),
		"nul":                 rep("sequence 2", "sequence 2\x00"),
		"time with offset":    rep("2026-11-18T12:30:05Z", "2026-11-18T12:30:05+00:00"),
		"time with fraction":  rep("2026-11-18T12:30:05Z", "2026-11-18T12:30:05.0Z"),
		"recovery none cased": rep("recovery-key 7071", "recovery-key None"),
		"empty":               "",
		"empty value":         rep("audit-seq 17", "audit-seq "),
		"duplicate key":       strings.Replace(s, "slots ", "manifest ", 1),
		"oversize":            s + strings.Repeat("a", 5000),
	}
	for name, c := range cases {
		if _, err := layout.ParseHead([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	zero := h
	zero.Previous = make([]byte, 32)
	if b, err := zero.Encode(); err == nil {
		if _, err := layout.ParseHead(b); err == nil {
			t.Error("a later head with an all-zero previous was accepted")
		}
	}
	first := h
	first.Sequence = 1
	if b, err := first.Encode(); err == nil {
		if _, err := layout.ParseHead(b); err == nil {
			t.Error("the first head with a previous hash was accepted")
		}
	}
	for n := 0; n < len(good); n++ {
		if _, err := layout.ParseHead(good[:n]); err == nil {
			t.Fatalf("truncated to %d bytes: accepted", n)
		}
	}
}
