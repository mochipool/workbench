package ports

import (
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Secret is guarded memory for key material (ADR 0004). Use cases name the
// type through this alias because the dependency rule keeps them away from
// the platform packages.
type Secret = secret.Buffer

// NormalizeMnemonic returns the normalised phrase (lowercase, single spaces,
// 24 words, see custody.NormalizeMnemonic) as a new guarded buffer. The
// input stays the caller's. A wrong word count gives custody.ErrMnemonicWords.
func NormalizeMnemonic(given *Secret) (*Secret, error) {
	var out *Secret
	err := given.Use(func(b []byte) error {
		norm, err := custody.NormalizeMnemonic(b)
		if err != nil {
			return err
		}
		out = secret.Take(norm) // Take wipes norm
		return nil
	})
	return out, err
}

// MnemonicFile returns the content of <name>.payment.mnemonics for a
// normalised phrase: the words and one newline, as upstream writes it
// (SPO-03a-OUT-003). It is a new guarded buffer.
func MnemonicFile(words *Secret) (*Secret, error) {
	var out *Secret
	err := words.Use(func(b []byte) error {
		var ferr error
		out, ferr = secret.Fill(len(b)+1, func(dst []byte) error {
			copy(dst, b)
			dst[len(b)] = '\n'
			return nil
		})
		return ferr
	})
	return out, err
}
