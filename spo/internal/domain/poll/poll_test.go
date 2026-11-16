package poll

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The question CBOR is the definite-length map {94: {0: [lines], 1: [[option
// lines]]}} and the answer is {94: {2: hash, 3: index}}. Vectors written by
// hand from the encoding rules, and equal to upstream's script on the same
// question (spo/test/parity/poll_scripts_test.go).
//
// spec: SPO-13a-INV-001, SPO-13a-INV-002, SPO-13a-OUT-001, SPO-13a-OUT-002
func TestQuestionAnswerEncoding(t *testing.T) {
	q := Question{Lines: []string{"Q?"}, Options: [][]string{{"Yes"}, {"No", "!"}}}
	// a1 185e | a2 | 00 81 62 "Q?" | 01 82 81 63 "Yes" 82 62 "No" 61 "!"
	want := "a1185ea20081625 13f01828163596573826 24e6f6121"
	want = strings.ReplaceAll(want, " ", "")
	if got := hex.EncodeToString(EncodeQuestion(q)); got != want {
		t.Fatalf("question CBOR %s, want %s", got, want)
	}
	h := Hash(q)
	a := EncodeAnswer(h, 1)
	if hex.EncodeToString(a[:7]) != "a1185ea2025820" {
		t.Errorf("answer prefix %x", a[:7])
	}
	if hex.EncodeToString(a[7:39]) != hex.EncodeToString(h[:]) || hex.EncodeToString(a[39:]) != "0301" {
		t.Errorf("answer %x", a)
	}
	if big := EncodeAnswer(h, 300); len(big) != 39+4 || hex.EncodeToString(big[39:]) != "0319012c" {
		t.Errorf("an index of 300 is not the two-byte form: %x", EncodeAnswer(h, 300)[39:])
	}
	if FileName(h) != "spopoll_"+hex.EncodeToString(h[:])+".cbor" {
		t.Error(FileName(h))
	}
	// Backslashes are text, not escapes (upstream's echo -ne would turn \n into a line feed).
	if x, y := Hash(Question{Lines: []string{`a\nb`}, Options: q.Options}), Hash(Question{Lines: []string{"a\nb"}, Options: q.Options}); x == y {
		t.Error("a backslash sequence was interpreted")
	}
	// A long line takes the one- and two-byte length forms.
	long := Question{Lines: []string{strings.Repeat("x", 64)}, Options: q.Options}
	if b := EncodeQuestion(long); b[6] != 0x78 || b[7] != 64 {
		t.Errorf("string header of 64 bytes: %x", b[:9])
	}
}

// spec: SPO-13a-PRE-004
func TestEmptyQuestionsAreRefused(t *testing.T) {
	for name, q := range map[string]Question{
		"no lines":     {Options: [][]string{{"a"}}},
		"no options":   {Lines: []string{"q"}},
		"empty option": {Lines: []string{"q"}, Options: [][]string{{"a"}, {}}},
	} {
		if err := q.Check(); !errors.Is(err, ErrEmpty) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (Question{Lines: []string{"q"}, Options: [][]string{{"a"}}}).Check(); err != nil {
		t.Error(err)
	}
}
