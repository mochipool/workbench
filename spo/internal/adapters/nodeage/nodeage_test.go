package nodeage

import (
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// spec: SPO-Xcustody-IN-003, SPO-Xcustody-EXT-002
func TestRecipientFileHoldsExactlyOneX25519PublicKey(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Recipient().String()
	got, err := ParseRecipientFile([]byte("\n# the block producer\n" + pub + "\n\n"))
	if err != nil || got != pub {
		t.Fatalf("%q %v", got, err)
	}
	other, _ := age.GenerateX25519Identity()
	for name, file := range map[string]string{
		"a secret key":          id.String() + "\n",
		"a secret key, lower":   strings.ToLower(id.String()) + "\n",
		"two recipients":        pub + "\n" + other.Recipient().String() + "\n",
		"none":                  "# nothing\n\n",
		"empty":                 "",
		"a plugin recipient":    "age1yubikey1qtest\n",
		"a post-quantum prefix": "age1pq1qqqq\n",
		"text":                  "hello world\n",
	} {
		s, err := ParseRecipientFile([]byte(file))
		if err == nil {
			// the file parsed; the recipient must still be refused as not X25519
			if _, cerr := (Sealer{}).CheckRecipient(s); cerr == nil {
				t.Errorf("%s was accepted", name)
			}
			continue
		}
		if !errors.Is(err, ErrRecipient) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if id, err := (Sealer{}).CheckRecipient(pub); err != nil || len(id) != 16 {
		t.Errorf("identifier %q %v", id, err)
	}
}

// spec: SPO-Xcustody-EXT-002
func TestIdentityIsExactlyOneX25519SecretKey(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	if _, err := ParseIdentity(secret.Take([]byte("# c\n" + a.String() + "\n"))); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"two":       a.String() + "\n" + b.String() + "\n",
		"none":      "\n",
		"a public":  a.Recipient().String() + "\n",
		"a garbage": "AGE-SECRET-KEY-1NOPE\n",
		"a scrypt":  "scrypt passphrase\n",
	} {
		if _, err := ParseIdentity(secret.Take([]byte(text))); !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// spec: SPO-Xcustody-PRE-012
func TestOpenRefusesAnotherRecipientTamperingAndALargeFile(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	ct, err := (Sealer{}).Seal(nil, a.Recipient().String(), secret.Take([]byte("0123456789")))
	if err != nil {
		t.Fatal(err)
	}
	ia, _ := ParseIdentity(secret.Take([]byte(a.String())))
	ib, _ := ParseIdentity(secret.Take([]byte(b.String())))
	pt, err := ia.Open(ct, 100)
	if err != nil {
		t.Fatal(err)
	}
	pt.Use(func(x []byte) error {
		if string(x) != "0123456789" {
			t.Errorf("%q", x)
		}
		return nil
	})
	if _, err := ib.Open(ct, 100); !errors.Is(err, ErrOpen) {
		t.Errorf("another recipient: %v", err)
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-3] ^= 1
	if _, err := ia.Open(bad, 100); !errors.Is(err, ErrOpen) {
		t.Errorf("tampered: %v", err)
	}
	if _, err := ia.Open(ct, 5); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a file over the limit: %v", err)
	}
	if _, err := ia.Open([]byte("not age"), 100); !errors.Is(err, ErrOpen) {
		t.Errorf("not age: %v", err)
	}
}
