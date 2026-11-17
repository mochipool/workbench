package exportdir

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var ctx = context.Background()

// realGPG is what gpg 2.4.9 emits with the options the export pins.
var realGPG, _ = hex.DecodeString("8c0d0409030a8adfb8504169b25affd23d016f51abdb8d6d08ee7d3b9efe4fe6614b6bfa92dc07a3c8db0c90e3e9423a4d83aab698a3990c1350544317d54a35c3624ecc413b296552a1cd086b1f")

// symMessage builds the packets of gpg's symmetric encryption without gpg: a
// session key packet (version 4, the given cipher, S2K mode, SHA-512, a salt,
// the coded count) and an integrity-protected data packet (tag 18) of `body`
// bytes. cipher 9 is AES-256.
func symMessage(cipher, s2k, count byte, dataTag byte) []byte {
	skesk := []byte{4, cipher, s2k, 10, 1, 2, 3, 4, 5, 6, 7, 8, count}
	msg := append([]byte{0xc3, byte(len(skesk))}, skesk...)
	data := append([]byte{1}, make([]byte, 60)...)
	return append(append(msg, 0xc0|dataTag, byte(len(data))), data...)
}

func encryptedKey(msg []byte) []byte {
	return keyfile.EncryptedEnvelope("PaymentSigningKeyShelley_ed25519", "Payment Signing Key", []byte(hex.EncodeToString(msg)))
}

// The destination checks the ciphertext's OpenPGP packets, not only the shape
// of the envelope: only a session key packet followed by one integrity-protected
// data packet, with an iterated-and-salted S2K and AES-256, is written.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003
func TestRefusesAnEnvelopeThatIsNotPasswordEncrypted(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	good := symMessage(9, 3, 0xff, 18)
	literal := []byte{0xcb, 6, 'b', 0, 0, 0, 0, 0}                            // a literal data packet: not encrypted at all
	partial := append(append([]byte{0xc3, 13}, good[2:15]...), 0xd2, 0xe6, 1) // a partial chunk of 64 bytes ...
	partial = append(partial, make([]byte, 63)...)
	partial = append(partial, 3, 7, 7, 7) // ... and a final chunk of 3
	for name, tc := range map[string]struct {
		msg []byte
		ok  bool
	}{
		"gpg's packets":              {good, true},
		"random bytes":               {[]byte(strings.Repeat("Í", 40)), false},
		"a literal packet":           {literal, false},
		"no data packet":             {good[:15], false},
		"data without integrity":     {symMessage(9, 3, 0xff, 9), false},
		"a public-key packet":        {append([]byte{0xc1, 3, 3, 0, 0}, good[15:]...), false},
		"trailing bytes":             {append(append([]byte(nil), good...), 0xcb, 1, 0), false},
		"a simple S2K":               {symMessage(9, 0, 0, 18), false},
		"a weak cipher":              {symMessage(3, 3, 0xff, 18), false},
		"a truncated data packet":    {good[:len(good)-5], false},
		"a partial-length data body": {partial, true},
		"a count of 1024":            {symMessage(9, 3, 0x10, 18), false},
		"a data body of 2 bytes":     {append(append([]byte(nil), good[:15]...), 0xd2, 2, 1, 0), false},
		"gpg 2.4.9 real output":      {realGPG, true},
	} {
		err := d.Update(ctx, func(w ports.Writer) error {
			b := secret.Take(encryptedKey(tc.msg))
			defer b.Destroy()
			return w.PutSecret(ports.Ref{Name: "w", Kind: ports.AddrSKey}, b)
		})
		if tc.ok != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
		if !tc.ok && !errors.Is(err, ErrNotEncrypted) {
			t.Errorf("%s: %v", name, err)
		}
		os.Remove(filepath.Join(dir, "w.skey"))
	}
}

// The destination of an export accepts a signing key in upstream's encrypted
// form and refuses every other secret, whatever the caller meant: a plain key, a
// mnemonic, a QR code, a verification-key kind passed as a secret.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003
func TestRefusesEverySecretThatIsNotAnEncryptedKey(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("ab", 32) + `"}`)
	enc := encryptedKey(symMessage(9, 3, 0xff, 18))
	for name, tc := range map[string]struct {
		ref  ports.Ref
		data []byte
	}{
		"plain key":         {ports.Ref{Name: "w", Kind: ports.AddrSKey}, plain},
		"plain cold key":    {ports.Ref{Name: "p", Kind: ports.NodeSKey}, plain},
		"garbage as a key":  {ports.Ref{Name: "w", Kind: ports.AddrSKey}, []byte("nope")},
		"mnemonic":          {ports.Ref{Name: "w", Kind: ports.PaymentMnemonics}, []byte("abandon abandon")},
		"encrypted in a QR": {ports.Ref{Name: "v", Kind: ports.CatalystQRCode}, enc},
		"party keys":        {ports.Ref{Name: "local", Kind: ports.PartyKeys}, []byte("x")},
	} {
		err := d.Update(ctx, func(w ports.Writer) error {
			b := secret.Take(append([]byte(nil), tc.data...))
			defer b.Destroy()
			return w.PutSecret(tc.ref, b)
		})
		if err == nil {
			t.Errorf("%s: written", name)
		}
	}
	// A secret kind through Put is refused too.
	if err := d.Update(ctx, func(w ports.Writer) error { return w.Put(ports.Ref{Name: "w", Kind: ports.AddrSKey}, plain) }); !errors.Is(err, ports.ErrSecretKind) {
		t.Errorf("Put of a key: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("something was written: %v", ents)
	}
	// The encrypted form, and a non-secret file, are written, locked.
	err = d.Update(ctx, func(w ports.Writer) error {
		b := secret.Take(append([]byte(nil), enc...))
		defer b.Destroy()
		if err := w.PutSecret(ports.Ref{Name: "w", Kind: ports.AddrSKey}, b); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: "w", Kind: ports.AddrVKey}, []byte("{}"))
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"w.skey", "w.vkey"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o400 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "w.skey")); string(got) != string(enc) {
		t.Error("the encrypted key was changed on the way")
	}
}

// One refused write in an Update leaves the directory as it was.
func TestAFailedUpdateWritesNothing(t *testing.T) {
	dir := t.TempDir()
	d, _ := Open(dir)
	err := d.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(ports.Ref{Name: "w", Kind: ports.AddrVKey}, []byte("{}")); err != nil {
			return err
		}
		b := secret.Take([]byte("clear"))
		defer b.Destroy()
		return w.PutSecret(ports.Ref{Name: "w", Kind: ports.AddrSKey}, b)
	})
	if err == nil {
		t.Fatal("no error")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("files left: %v", ents)
	}
}
