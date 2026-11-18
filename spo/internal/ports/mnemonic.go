package ports

import (
	"bytes"
	"errors"
	"fmt"

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

// derivationPrefix starts the optional second line of a cold mnemonic file: the
// account and index the key was derived with (1852H/1815H/<account>H/4/<index>).
// A file without it was derived at account 0, index 0.
const derivationPrefix = "derivation "

// MnemonicFileWithDerivation is MnemonicFile for a committee cold mnemonic derived
// at an account or index other than 0: the words, a newline, and a line
// "derivation <account> <index>". The store releases only the first line to a
// reader (StripDerivation); the second is kept in the sealed record so a recovery
// can check the recovered words at the path they were made with.
func MnemonicFileWithDerivation(words *Secret, account, index uint32) (*Secret, error) {
	var out *Secret
	err := words.Use(func(b []byte) error {
		line := fmt.Sprintf("%s%d %d\n", derivationPrefix, account, index)
		var ferr error
		out, ferr = secret.Fill(len(b)+1+len(line), func(dst []byte) error {
			n := copy(dst, b)
			dst[n] = '\n'
			copy(dst[n+1:], line)
			return nil
		})
		return ferr
	})
	return out, err
}

// SplitMnemonicFile splits a stored cold mnemonic file into its words (the first
// line, without the newline, as a new guarded buffer) and the derivation it
// records (0, 0 when the file has none). A second line that is not a derivation
// line is an error.
func SplitMnemonicFile(file *Secret) (words *Secret, account, index uint32, err error) {
	err = file.Use(func(b []byte) error {
		first, rest, _ := bytes.Cut(b, []byte("\n"))
		rest = bytes.TrimRight(rest, "\n")
		if len(rest) > 0 {
			var a, i uint32
			if _, serr := fmt.Sscanf(string(rest), derivationPrefix+"%d %d", &a, &i); serr != nil || bytes.ContainsRune(rest, '\n') {
				return errors.New("ports: the second line of a cold mnemonic file is not a derivation line")
			}
			account, index = a, i
		}
		words = secret.Take(append([]byte(nil), first...))
		return nil
	})
	return words, account, index, err
}

// StripDerivation returns the file a reader sees: the words and one newline, with
// no derivation line. A file without one is copied unchanged.
func StripDerivation(file *Secret) (*Secret, error) {
	has := false
	_ = file.Use(func(b []byte) error { has = bytes.Contains(b, []byte("\n"+derivationPrefix)); return nil })
	if !has {
		return secret.Fill(file.Len(), func(dst []byte) error {
			return file.Use(func(b []byte) error { copy(dst, b); return nil })
		})
	}
	words, _, _, err := SplitMnemonicFile(file)
	if err != nil {
		return nil, err
	}
	defer words.Destroy()
	return MnemonicFile(words)
}
