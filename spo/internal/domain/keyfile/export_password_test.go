package keyfile

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"strings"
	"testing"
)

// The generated export password carries 160 random bits, meets upstream's
// strength rule and the 20-character rule, and is different every time.
//
// spec: SPO-Xcustody-IF-003, SPO-Xcustody-PRE-003
func TestGenerateExportPassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		pw, err := GenerateExportPassword(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !IsStrongPassword(pw) || !IsLongExportPassword(pw) || len(pw) != 39 || bytes.ContainsAny(pw, "\\ \n=") {
			t.Fatalf("%q does not meet the rules", pw)
		}
		raw, err := base32.StdEncoding.DecodeString(strings.ToUpper(strings.ReplaceAll(string(pw), "-", "")))
		if err != nil || len(raw) != 20 {
			t.Fatalf("%q is not 160 bits of base32: %v", pw, err)
		}
		if seen[string(pw)] {
			t.Fatal("a repeated password")
		}
		seen[string(pw)] = true
	}
	// The draw is of 20 bytes from the reader, and a short reader is an error.
	if _, err := GenerateExportPassword(bytes.NewReader(make([]byte, 5))); err == nil {
		t.Error("a short random source was accepted")
	}
	if IsLongExportPassword([]byte("Password1!")) || !IsLongExportPassword([]byte("Abcdefghij-12345678!")) || IsLongExportPassword([]byte("Abcdefghij-1234567\\!")) {
		t.Error("the length rule is wrong")
	}
}
