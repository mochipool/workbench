// Package txparam is the free-form extra-parameter grammar of the transaction
// scripts (spec/upstream/patterns/Pparam.md), parsed once into a typed value.
//
// Upstream re-implements the same classification loop in every script. Here
// the words are classified once, by an acceptance table per script, into
// Extras: messages, encryption mode, metadata file references, an explicit
// input list and the UTxO filters. The package is pure: it reads no file,
// encrypts nothing and calls no tool. A passphrase is held privately by the
// Extras and leaves it only through TakePassphrase, so the value that is
// logged or compared never carries it.
package txparam

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// MaxMessageBytes is the CIP-20 limit of one message line.
const MaxMessageBytes = 64

// Refusals of the grammar. Each wraps one of these so callers can test with
// errors.Is; the text names the offending word.
var (
	// ErrUnknownKey: a keyed word the script does not know (SPO-Pparam-IF-005).
	ErrUnknownKey = errors.New("unknown extra parameter")
	// ErrBadMessage: a message line over 64 bytes or not UTF-8 (SPO-Pparam-PRE-001).
	ErrBadMessage = errors.New("invalid transaction message")
	// ErrBadEncryption: an encryption mode other than basic (SPO-Pparam-INV-001).
	ErrBadEncryption = errors.New("unsupported message encryption mode")
	// ErrBadMetadataFile: a metadata file word with another extension than
	// .json or .cbor (SPO-Pparam-PRE-005).
	ErrBadMetadataFile = errors.New("invalid metadata file")
	// ErrBadUtxoLimit: utxolimit is not a positive integer (SPO-Pparam-IF-020).
	ErrBadUtxoLimit = errors.New("invalid utxolimit")
	// ErrBadAssetFilter: a skiputxowithasset or onlyutxowithasset list of the
	// wrong shape (SPO-Pparam-IF-021).
	ErrBadAssetFilter = errors.New("invalid asset filter")
	// ErrBadUtxoRef: a txhash#index list with a malformed reference
	// (SPO-Pparam-IF-019).
	ErrBadUtxoRef = errors.New("invalid UTxO reference")
	// ErrBadKeepPolicy: keeppolicy with something other than policy ids
	// (SPO-Pparam-IF-023).
	ErrBadKeepPolicy = errors.New("invalid keeppolicy")
	// ErrBadLovelaces: a digits-only word that is not a lovelace amount
	// (SPO-Pparam-IF-006).
	ErrBadLovelaces = errors.New("invalid lovelace amount")
)

// Mode says what a script does with a token.
type Mode uint8

const (
	// Unknown: the script does not know the token; the word is refused
	// (upstream treats it as a file word and refuses it as a missing file,
	// SPO-Pparam-IF-005).
	Unknown Mode = iota
	// Ignored: recognised, parsed, with no effect (SPO-Pparam-IF-007).
	Ignored
	// Effect: the token takes effect.
	Effect
)

// Accepts is one row of the acceptance table of Pparam: which tokens a
// script takes. Messages, encryption, pass and metadata files are accepted
// by every transaction script.
type Accepts struct {
	UtxoList   Mode // txhash#index
	Limit      Mode // utxolimit:
	Skip       Mode // skiputxowithasset:
	Only       Mode // onlyutxowithasset:
	KeepPolicy Mode // keeppolicy:
	Lovelaces  Mode // a digits-only word
}

// The acceptance rows of the scripts this port implements.
var (
	// ForSendLovelaces is 01_sendLovelaces and 01_claimRewards.
	ForSendLovelaces = Accepts{UtxoList: Effect, Limit: Effect, Skip: Effect, Only: Effect}
	// ForSendAssets is 01_sendAssets: the filters, keeppolicy and the
	// digits-only lovelace word.
	ForSendAssets = Accepts{UtxoList: Effect, Limit: Effect, Skip: Effect, Only: Effect, KeepPolicy: Effect, Lovelaces: Effect}
	// ForMint is 11a and 11b: the UTxO list only; utxolimit and the asset
	// filters are not known (SPO-11a-IF-004).
	ForMint = Accepts{UtxoList: Effect}
	// ForCertificate is the certificate scripts (03b, 06, 08b, ...): the
	// list and the filters are recognised and ignored.
	ForCertificate = Accepts{UtxoList: Ignored, Limit: Ignored, Skip: Ignored, Only: Ignored}
)

// FileFormat is the format of a metadata file.
type FileFormat string

// Metadata file formats.
const (
	FileJSON FileFormat = "json"
	FileCBOR FileFormat = "cbor"
)

// MetadataFile names a user metadata file. The path is as the operator typed
// it; the content is read by a port, never here.
type MetadataFile struct {
	Path   string
	Format FileFormat
}

// UtxoRef is one `txhash#index` reference.
type UtxoRef struct {
	TxID  chain.TxID
	Index uint32
}

func (r UtxoRef) String() string { return fmt.Sprintf("%s#%d", r.TxID, r.Index) }

// AssetMatch names an asset by policy and, optionally, asset name. An entry
// of 56 hex characters is a policy id only; a longer one is the policy id
// followed by the hex asset name.
type AssetMatch struct {
	Policy  [28]byte
	Name    []byte
	HasName bool
}

// Matches reports whether the asset is the one named, or belongs to the
// policy named. The name is compared whole: upstream greps the row text, so a
// shorter name also matches every longer name that starts with it, and so
// does a hash that happens to contain the hex (SPO-Pparam-IF-022); the port
// compares the asset id exactly.
func (m AssetMatch) Matches(a chain.AssetID) bool {
	if m.Policy != a.Policy {
		return false
	}
	return !m.HasName || string(m.Name) == string(a.Name)
}

// Extras is the parsed extra-parameter list of a transaction script.
type Extras struct {
	// Messages are the CIP-20 lines, in order, plain text (SPO-Pparam-IF-008).
	Messages []string
	// Encryption is "" or "basic" (SPO-Pparam-IF-011). It only has an effect
	// with at least one message (SPO-Pparam-IF-013).
	Encryption string
	// MetadataFiles are the user files in command-line order
	// (SPO-Pparam-IF-016).
	MetadataFiles []MetadataFile
	// Inputs is the explicit input list; the last list word wins
	// (SPO-Pparam-IF-019).
	Inputs []UtxoRef
	// UtxoLimit is the maximum number of input UTxOs, zero for no limit.
	UtxoLimit int
	// Skip and Only are the asset filters (SPO-Pparam-IF-021).
	Skip, Only []AssetMatch
	// KeepPolicies are the policy ids an ALLASSETS send keeps on the source
	// (SPO-Pparam-IF-023).
	KeepPolicies [][28]byte
	// Lovelaces is the lovelace to send along with assets (SPO-Pparam-IF-006).
	Lovelaces    chain.Lovelace
	HasLovelaces bool

	passphrase []byte
	hasPass    bool
}

// HasMetadata reports whether the extras attach any transaction metadata.
func (e Extras) HasMetadata() bool { return len(e.Messages) > 0 || len(e.MetadataFiles) > 0 }

// HasFilters reports whether any input selection token is set.
func (e Extras) HasFilters() bool {
	return len(e.Inputs) > 0 || e.UtxoLimit > 0 || len(e.Skip) > 0 || len(e.Only) > 0
}

// HasPassphrase reports whether a `pass:` word was given.
func (e Extras) HasPassphrase() bool { return e.hasPass }

// TakePassphrase returns the passphrase of a `pass:` word and forgets it. The
// caller wraps it in a secret at once and wipes the slice. It returns nil
// when no `pass:` word was given (the default `cardano` is the use case's,
// SPO-Pparam-IF-012).
func (e *Extras) TakePassphrase() []byte {
	if !e.hasPass {
		return nil
	}
	p := e.passphrase
	e.passphrase, e.hasPass = nil, false
	return p
}

// String never shows the passphrase.
func (e Extras) String() string {
	return fmt.Sprintf("extras{messages:%d enc:%q files:%d inputs:%d limit:%d skip:%d only:%d pass:%t}",
		len(e.Messages), e.Encryption, len(e.MetadataFiles), len(e.Inputs), e.UtxoLimit, len(e.Skip), len(e.Only), e.hasPass)
}

// GoString is String, so %#v does not show the passphrase either.
func (e Extras) GoString() string { return e.String() }

var (
	utxoListRE = regexp.MustCompile(`^[0-9A-Fa-f]+#[0-9]+(\|[0-9A-Fa-f]+#[0-9]+)*$`)
	// An upstream UTxO list also matches without the `|` separators; the
	// port requires them.
	looseListRE = regexp.MustCompile(`^([0-9A-Fa-f]+#[0-9]+\|?)+$`)
	keyedRE     = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_-]*):`)
)

// key reports whether the lower-cased word starts with `key:` and returns the
// value taken from the original-case word (SPO-Pparam-IF-002).
func key(word, k string) (string, bool) {
	if len(word) >= len(k)+1 && strings.EqualFold(word[:len(k)+1], k+":") {
		return word[len(k)+1:], true
	}
	return "", false
}

// trimBlanks is upstream's trimString: leading and trailing blanks.
func trimBlanks(s string) string { return strings.Trim(s, " \t\r\n") }

// SplitMessages splits the value of a `msg:` word into lines: trimmed at both
// ends, split at `|`, one trailing empty piece dropped as bash's
// `IFS='|' read -ra` does. The pieces themselves are not trimmed, and an
// empty piece inside the value is an empty line.
//
// spec: SPO-Pparam-IF-008, SPO-Pparam-IF-009
func SplitMessages(value string) []string {
	v := trimBlanks(value)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, "|")
	if parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// CheckMessages refuses a line over 64 UTF-8 bytes (not characters) or one
// that is not valid UTF-8. A double quote or any other character is fine: the
// line is encoded as a JSON string value, not spliced into a jq program.
//
// spec: SPO-Pparam-PRE-001, SPO-Pparam-PRE-002
func CheckMessages(lines []string) error {
	for i, l := range lines {
		if len(l) > MaxMessageBytes {
			return fmt.Errorf("%w: line %d is %d bytes, the limit is %d", ErrBadMessage, i+1, len(l), MaxMessageBytes)
		}
		if !utf8.ValidString(l) {
			return fmt.Errorf("%w: line %d is not valid UTF-8", ErrBadMessage, i+1)
		}
	}
	return nil
}

// Parse classifies the extra words of a script, left to right, by the
// acceptance row. The classification order is that of SPO-Pparam-IF-003: a
// UTxO list, `msg:`, `utxolimit:`, `skiputxowithasset:`,
// `onlyutxowithasset:`, `keeppolicy:`, `enc:`, `pass:`, then a metadata
// file word. A keyed word the script does not know is refused (upstream
// treats it as a file word and refuses it as missing, SPO-Pparam-IF-005); a
// digits-only word is ignored, or is the lovelace amount where the script
// takes one; an empty word is ignored.
//
// spec: SPO-Pparam-IF-001, SPO-Pparam-IF-002, SPO-Pparam-IF-003, SPO-Pparam-IF-004, SPO-Pparam-IF-005,
// spec: SPO-Pparam-IF-006, SPO-Pparam-IF-007, SPO-Pparam-IF-008, SPO-Pparam-IF-009, SPO-Pparam-IF-011,
// spec: SPO-Pparam-IF-012, SPO-Pparam-IF-013, SPO-Pparam-IF-015, SPO-Pparam-IF-016, SPO-Pparam-IF-019,
// spec: SPO-Pparam-IF-020, SPO-Pparam-IF-021, SPO-Pparam-IF-023, SPO-Pparam-PRE-001, SPO-Pparam-PRE-003,
// spec: SPO-Pparam-PRE-005
func Parse(words []string, acc Accepts) (Extras, error) {
	var ex Extras
	for _, w := range words {
		switch {
		case w == "":
			continue
		case utxoListRE.MatchString(w) || (looseListRE.MatchString(w) && strings.Contains(w, "#")):
			if acc.UtxoList == Unknown {
				return Extras{}, fmt.Errorf("%w: %q (a UTxO list is not taken here)", ErrUnknownKey, w)
			}
			refs, err := parseUtxoList(w)
			if err != nil {
				return Extras{}, err
			}
			if acc.UtxoList == Effect {
				ex.Inputs = refs // a later list replaces an earlier one
			}
			continue
		}
		if v, ok := key(w, "msg"); ok {
			lines := SplitMessages(v)
			if err := CheckMessages(lines); err != nil {
				return Extras{}, err
			}
			ex.Messages = append(ex.Messages, lines...)
			continue
		}
		if v, ok := key(w, "utxolimit"); ok {
			if acc.Limit == Unknown {
				return Extras{}, fmt.Errorf("%w: %q", ErrUnknownKey, w)
			}
			n, err := parseLimit(v)
			if err != nil {
				return Extras{}, err
			}
			if acc.Limit == Effect {
				ex.UtxoLimit = n
			}
			continue
		}
		if v, ok := key(w, "skiputxowithasset"); ok {
			if acc.Skip == Unknown {
				return Extras{}, fmt.Errorf("%w: %q", ErrUnknownKey, w)
			}
			m, err := parseAssetFilter(v)
			if err != nil {
				return Extras{}, err
			}
			if acc.Skip == Effect {
				ex.Skip = m
			}
			continue
		}
		if v, ok := key(w, "onlyutxowithasset"); ok {
			if acc.Only == Unknown {
				return Extras{}, fmt.Errorf("%w: %q", ErrUnknownKey, w)
			}
			m, err := parseAssetFilter(v)
			if err != nil {
				return Extras{}, err
			}
			if acc.Only == Effect {
				ex.Only = m
			}
			continue
		}
		if v, ok := key(w, "keeppolicy"); ok {
			if acc.KeepPolicy == Unknown {
				return Extras{}, fmt.Errorf("%w: %q", ErrUnknownKey, w)
			}
			ps, err := parseKeepPolicy(v)
			if err != nil {
				return Extras{}, err
			}
			if acc.KeepPolicy == Effect {
				ex.KeepPolicies = ps
			}
			continue
		}
		if v, ok := key(w, "enc"); ok {
			ex.Encryption = strings.ToLower(trimBlanks(v))
			continue
		}
		if v, ok := key(w, "pass"); ok {
			// Not trimmed: spaces are part of the passphrase (IF-012).
			ex.passphrase, ex.hasPass = []byte(v), true
			continue
		}
		if m := keyedRE.FindStringSubmatch(w); m != nil {
			return Extras{}, fmt.Errorf("%w: %q (the key %q is not known to this command)", ErrUnknownKey, w, m[1])
		}
		if isDigits(w) {
			if acc.Lovelaces == Effect {
				n, err := parseLovelaces(w)
				if err != nil {
					return Extras{}, err
				}
				ex.Lovelaces, ex.HasLovelaces = n, true
			}
			continue // purely numeric words are never file words (IF-004, IF-006)
		}
		f, err := fileWord(w)
		if err != nil {
			return Extras{}, err
		}
		ex.MetadataFiles = append(ex.MetadataFiles, f)
	}
	// An unsupported mode is refused in every script (INV-001: upstream
	// sends the messages in clear in five of them). With no message the mode
	// has no effect and no error (IF-013).
	if len(ex.Messages) > 0 && ex.Encryption != "" && ex.Encryption != "basic" {
		return Extras{}, fmt.Errorf("%w: %q (only basic exists)", ErrBadEncryption, ex.Encryption)
	}
	if len(ex.Messages) == 0 {
		ex.Encryption = ""
	}
	return ex, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// fileWord classifies a metadata file word by its extension, compared
// case-insensitively (SPO-Pparam-IF-014, IF-015, PRE-005). Existence is the
// reader's check.
func fileWord(w string) (MetadataFile, error) {
	i := strings.LastIndexByte(w, '.')
	ext := ""
	if i >= 0 {
		ext = strings.ToLower(w[i+1:])
	}
	switch ext {
	case "json":
		return MetadataFile{Path: w, Format: FileJSON}, nil
	case "cbor":
		return MetadataFile{Path: w, Format: FileCBOR}, nil
	}
	return MetadataFile{}, fmt.Errorf("%w: %q: the file extension must be .json or .cbor", ErrBadMetadataFile, w)
}

func parseUtxoList(w string) ([]UtxoRef, error) {
	if !utxoListRE.MatchString(w) {
		return nil, fmt.Errorf("%w: %q: separate the references with |", ErrBadUtxoRef, w)
	}
	var out []UtxoRef
	for _, ref := range strings.Split(w, "|") {
		h, idx, _ := strings.Cut(ref, "#")
		id, err := chain.ParseTxID(strings.ToLower(h))
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadUtxoRef, ref, err)
		}
		n, err := strconv.ParseUint(idx, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: the index does not fit in 32 bits", ErrBadUtxoRef, ref)
		}
		out = append(out, UtxoRef{TxID: id, Index: uint32(n)})
	}
	return out, nil
}

func parseLimit(v string) (int, error) {
	v = trimBlanks(v)
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%w: %q: use a whole number greater than zero", ErrBadUtxoLimit, v)
	}
	return n, nil
}

func parseAssetFilter(v string) ([]AssetMatch, error) {
	v = strings.ToLower(trimBlanks(v))
	var out []AssetMatch
	for _, e := range strings.Split(v, "|") {
		if len(e)%2 != 0 || len(e) < 56 || len(e) > 120 {
			return nil, fmt.Errorf("%w: %q is not a policy id (+ asset name) of 28 to 60 hex bytes", ErrBadAssetFilter, e)
		}
		raw, err := hex.DecodeString(e)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not hex", ErrBadAssetFilter, e)
		}
		m := AssetMatch{}
		copy(m.Policy[:], raw[:28])
		if len(raw) > 28 {
			m.Name, m.HasName = append([]byte(nil), raw[28:]...), true
		}
		out = append(out, m)
	}
	return out, nil
}

func parseKeepPolicy(v string) ([][28]byte, error) {
	v = strings.ToLower(trimBlanks(v))
	var out [][28]byte
	for _, e := range strings.Split(v, "|") {
		raw, err := hex.DecodeString(e)
		if err != nil || len(raw) != 28 {
			return nil, fmt.Errorf("%w: %q is not a 56 character policy id", ErrBadKeepPolicy, e)
		}
		var p [28]byte
		copy(p[:], raw)
		out = append(out, p)
	}
	return out, nil
}

// parseLovelaces reads a digits-only word. Upstream substitutes it into
// shell arithmetic as typed, so a leading zero is octal there; the port
// refuses a zero-padded number instead of choosing a base.
func parseLovelaces(w string) (chain.Lovelace, error) {
	if len(w) > 1 && w[0] == '0' {
		return 0, fmt.Errorf("%w: %q has leading zeros", ErrBadLovelaces, w)
	}
	n, err := strconv.ParseUint(w, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q does not fit in 64 bits", ErrBadLovelaces, w)
	}
	return chain.Lovelace(n), nil
}
