package keyfile

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// realGPG is the output of gpg 2.4.9 with the options the export pins
// (--symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-digest-algo SHA512
// --s2k-count 65011712 --force-mdc --set-filename ""), over a 69-octet text.
const realGPG = "8c0d0409030a8adfb8504169b25affd23d016f51abdb8d6d08ee7d3b9efe4fe6614b6bfa92dc07a3c8db0c90e3e9423a4d83aab698a3990c1350544317d54a35c3624ecc413b296552a1cd086b1f"

// pgpMsg builds a message from a session key packet body and a data packet
// (tag, body), old-format headers with a one-octet length.
func pgpMsg(skesk []byte, dataTag int, data []byte) []byte {
	out := []byte{0x80 | 3<<2, byte(len(skesk))}
	out = append(out, skesk...)
	// New format header (tag above 15 needs it), five-octet length.
	out = append(out, 0xc0|byte(dataTag), 0xff, 0, 0, byte(len(data)>>8), byte(len(data)))
	return append(out, data...)
}

func skesk(ver, cipher, mode, hash, count byte) []byte {
	return []byte{ver, cipher, mode, hash, 1, 2, 3, 4, 5, 6, 7, 8, count}
}

func dataBody(version byte, n int) []byte {
	b := bytes.Repeat([]byte{0xAA}, n)
	if n > 0 {
		b[0] = version
	}
	return b
}

// What the gpg adapter emits passes; each parameter that differs is refused.
//
// spec: SPO-Xcustody-INV-004
func TestCheckSymmetricMessageAcceptsExactlyWhatTheExportEmits(t *testing.T) {
	raw, _ := hex.DecodeString(realGPG)
	m, err := CheckSymmetricMessage(raw)
	if err != nil {
		t.Fatalf("the real gpg output: %v", err)
	}
	if m.Version != 4 || m.Cipher != 9 || m.S2KMode != 3 || m.HashAlgo != 10 || m.Count != 65011712 {
		t.Errorf("%+v", m)
	}
	good := skesk(4, 9, 3, 10, 0xff)
	if _, err := CheckSymmetricMessage(pgpMsg(good, 18, dataBody(1, minDataBody))); err != nil {
		t.Fatalf("a message of the least size: %v", err)
	}
	cases := map[string][]byte{
		"data packet version 2":             pgpMsg(good, 18, dataBody(2, 80)),
		"a 2-byte data body":                pgpMsg(good, 18, dataBody(1, 2)),
		"a data body under the MDC minimum": pgpMsg(good, 18, dataBody(1, minDataBody-1)),
		"MD5 S2K":                           pgpMsg(skesk(4, 9, 3, 1, 0xff), 18, dataBody(1, 80)),
		"SHA-256 S2K":                       pgpMsg(skesk(4, 9, 3, 8, 0xff), 18, dataBody(1, 80)),
		"count 1024":                        pgpMsg(skesk(4, 9, 3, 10, 0x10), 18, dataBody(1, 80)),
		"count one step short":              pgpMsg(skesk(4, 9, 3, 10, 0xfe), 18, dataBody(1, 80)),
		"S2K mode 1 (salted, no iteration)": pgpMsg(skesk(4, 9, 1, 10, 0xff), 18, dataBody(1, 80)),
		"AES-128":                           pgpMsg(skesk(4, 7, 3, 10, 0xff), 18, dataBody(1, 80)),
		"a v5 session key packet":           pgpMsg(skesk(5, 9, 3, 10, 0xff), 18, dataBody(1, 80)),
		"the AEAD packet (tag 20)":          pgpMsg(good, 20, dataBody(1, 80)),
		"no integrity (tag 9)":              pgpMsg(good, 9, dataBody(1, 80)),
		"an encrypted session key":          pgpMsg(append(skesk(4, 9, 3, 10, 0xff), 1, 2, 3), 18, dataBody(1, 80)),
		"trailing bytes":                    append(pgpMsg(good, 18, dataBody(1, 80)), 0),
		"a repeated data packet":            append(pgpMsg(good, 18, dataBody(1, 80)), pgpMsg(good, 18, dataBody(1, 80))[15:]...),
		"plain text":                        []byte(`{"cborHex":"5820"}`),
		"empty":                             nil,
	}
	for name, msg := range cases {
		if _, err := CheckSymmetricMessage(msg); !errors.Is(err, ErrNotSymmetricPGP) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The limit of the check, stated as a test: a data packet whose body is
// plaintext of plausible length has the form of an encrypted message and
// passes. That the content is encrypted comes from the producers (the gpg
// adapter, or an upstream-encrypted record kept verbatim), not from this check.
//
// spec: SPO-Xcustody-INV-004
func TestCheckSymmetricMessageCannotTellCiphertextFromPlaintext(t *testing.T) {
	plain := append([]byte{1}, bytes.Repeat([]byte("5820deadbeef"), 8)...)
	if _, err := CheckSymmetricMessage(pgpMsg(skesk(4, 9, 3, 10, 0xff), 18, plain)); err != nil {
		t.Fatalf("documented limit changed: %v", err)
	}
}
