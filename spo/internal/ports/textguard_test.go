package ports

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The text guard of the Calidus `sign`: valid UTF-8 only, and not the signing
// input of a relay statement.
//
// spec: SPO-Xidentity-SEC-008, SPO-Xrelaybind-SEC-018
func TestCheckSignableText(t *testing.T) {
	var k [28]byte
	ss := cose.SigStructure(cose.ProtectedHeader(k[:]), cose.PayloadFor([]byte("spo-relay-binding-v1 device 00 from 0 until 3600"), false))
	for name, tc := range map[string]struct {
		in   []byte
		want error
	}{
		"ordinary text":     {[]byte("hello pool"), nil},
		"empty":             {nil, nil},
		"utf-8":             {[]byte("pool é\U0001F600"), nil},
		"a lone lead byte":  {[]byte{0xc3}, ErrNotText},
		"a continuation":    {[]byte{0x80}, ErrNotText},
		"0xff":              {[]byte("a\xffb"), ErrNotText},
		"a Sig_structure":   {ss, ErrNotText},
		"reserved prefix":   {[]byte("spo-relay-binding-v1 device x"), relaybind.ErrRawStatementInput},
		"reserved slash":    {[]byte("spo/mailbox-auth/v2"), relaybind.ErrRawStatementInput},
		"a bare context":    {[]byte("Signature1"), nil},
		"overlong encoding": {[]byte{0xc0, 0xaf}, ErrNotText},
	} {
		if err := CheckSignableText(tc.in); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// the two refusals are distinct, so a test can tell which rule refused
	if errors.Is(ErrNotText, relaybind.ErrRawStatementInput) {
		t.Error("one error")
	}
}
