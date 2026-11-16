package party

import (
	"errors"
	"testing"
)

// The body and the auxiliary data together are the transaction's size.
// spec: SPO-Xparty-INV-008
func TestCheckTxSizeCountsAuxData(t *testing.T) {
	m := SigningRequest{TxBody: make([]byte, 100), AuxData: make([]byte, 60)}
	if err := m.CheckTxSize(160); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := m.CheckTxSize(159); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("one over: %v", err)
	}
	if err := CheckTxSize(100, 60, 159); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("the coordinator's check: %v", err)
	}
	if err := CheckTxSize(1<<62, 1<<62, 10); err == nil {
		t.Fatal("a sum that wraps")
	}
}

// Displayed text refuses the line and paragraph separators, which break a line
// like a newline does.
// spec: SPO-Xparty-PR-002
func TestCleanTextRefusesLineSeparators(t *testing.T) {
	for _, s := range []string{"a b", "a b", "a\nb", "a‮b"} {
		if cleanText(s) {
			t.Errorf("%q is clean", s)
		}
	}
	if !cleanText("plain text, ünïcode ✓") {
		t.Error("plain text refused")
	}
}
