// Package checkpoint is the vocabulary of ADR 0012 stage 2: the checkpoint
// statement a backup is signed with, the long-lived pin that names the signing
// key, the record the workspace keeps about its checkpoint key, and the
// statement that authorises replacing or removing that key. It is pure: it
// parses and encodes text and checks SSH signatures (domain/sshsig).
//
// Every text here is canonical: one `key value` line per field, the first line
// the domain tag, the keys in a fixed order, numbers without leading zeros, hex
// in lower case, a line feed after every line, a bounded size. The parsers
// accept exactly that and nothing else, and re-encode to compare.
package checkpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
)

// Tags and namespaces. The domain tag is the first line of the text and also
// the SSHSIG namespace, so a signature over one kind of statement cannot be
// taken for another.
const (
	TagCheckpoint = "spo/checkpoint/v1"
	TagReplace    = "spo/checkpoint-replace/v1"
	TagKeyRecord  = "spo/checkpoint-key/v1"
)

// Application is the relying-party id of the checkpoint credential.
const Application = "ssh:spo-checkpoint"

// MaxStatementSize bounds every text this package parses (and the checkpoint
// object a restore fetches is bounded by MaxObjectSize).
const MaxStatementSize = 4 << 10

// MaxObjectSize is the largest checkpoint object a restore reads: the statement
// and its armored signature.
const MaxObjectSize = 16 << 10

// HashSize is the size of every hash here.
const HashSize = 32

var (
	hexRE = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)
	decRE = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,19})$`)
)

// ErrFormat is returned for a text that is not the canonical form.
var ErrFormat = errors.New("checkpoint: not the canonical form")

func formatErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, a...))
}

// field is one line of a canonical text.
type field struct{ key, val string }

// parseFields reads text as tag, then exactly the keys in order.
func parseFields(text []byte, tag string, keys []string) (map[string]string, error) {
	if len(text) > MaxStatementSize {
		return nil, formatErr("longer than %d bytes", MaxStatementSize)
	}
	if len(text) == 0 || text[len(text)-1] != '\n' {
		return nil, formatErr("no final line feed")
	}
	lines := strings.Split(string(text[:len(text)-1]), "\n")
	if len(lines) != len(keys)+1 || lines[0] != tag {
		return nil, formatErr("expected the tag %q and %d fields", tag, len(keys))
	}
	out := make(map[string]string, len(keys))
	for i, k := range keys {
		key, val, ok := strings.Cut(lines[i+1], " ")
		if !ok || key != k || val == "" || strings.ContainsAny(val, " \t\r\x00") {
			return nil, formatErr("line %d is not %q and a value", i+2, k)
		}
		out[k] = val
	}
	return out, nil
}

func hexField(m map[string]string, k string, size int) ([]byte, error) {
	v := m[k]
	if !hexRE.MatchString(v) || (size > 0 && len(v) != 2*size) {
		return nil, formatErr("%s is not lower-case hex of the expected length", k)
	}
	b, _ := hex.DecodeString(v)
	return b, nil
}

func decField(m map[string]string, k string) (uint64, error) {
	v := m[k]
	if !decRE.MatchString(v) {
		return 0, formatErr("%s is not a canonical decimal number", k)
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, formatErr("%s is out of range", k)
	}
	return n, nil
}

const timeLayout = "2006-01-02T15:04:05Z"

func timeField(m map[string]string, k string) (time.Time, error) {
	t, err := time.Parse(timeLayout, m[k])
	if err != nil || t.Format(timeLayout) != m[k] {
		return time.Time{}, formatErr("%s is not a UTC time like 2006-01-02T15:04:05Z", k)
	}
	return t, nil
}

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

// ---- the checkpoint statement ----

// Statement says: this backup file (SHA-256 and size) of this workspace, whose
// audit chain ends at this head and whose slot table has this hash, was made at
// this time and signed by the key with this hash.
type Statement struct {
	WorkspaceID []byte
	Seq         uint64
	HeadMAC     []byte
	SlotTable   []byte
	SHA256      []byte
	Size        uint64
	Time        time.Time
	KeyHash     []byte
}

var statementKeys = []string{"workspace", "sequence", "head-mac", "slot-table", "sha256", "size", "time", "key-hash"}

// Encode is the canonical text.
func (s Statement) Encode() []byte {
	var b bytes.Buffer
	b.WriteString(TagCheckpoint + "\n")
	for _, f := range []field{
		{"workspace", hex.EncodeToString(s.WorkspaceID)},
		{"sequence", strconv.FormatUint(s.Seq, 10)},
		{"head-mac", hex.EncodeToString(s.HeadMAC)},
		{"slot-table", hex.EncodeToString(s.SlotTable)},
		{"sha256", hex.EncodeToString(s.SHA256)},
		{"size", strconv.FormatUint(s.Size, 10)},
		{"time", fmtTime(s.Time)},
		{"key-hash", hex.EncodeToString(s.KeyHash)},
	} {
		b.WriteString(f.key + " " + f.val + "\n")
	}
	return b.Bytes()
}

// ParseStatement reads the canonical text strictly.
func ParseStatement(text []byte) (Statement, error) {
	m, err := parseFields(text, TagCheckpoint, statementKeys)
	if err != nil {
		return Statement{}, err
	}
	var s Statement
	if s.WorkspaceID, err = hexField(m, "workspace", 0); err != nil {
		return Statement{}, err
	}
	if s.Seq, err = decField(m, "sequence"); err != nil {
		return Statement{}, err
	}
	if s.HeadMAC, err = hexField(m, "head-mac", HashSize); err != nil {
		return Statement{}, err
	}
	if s.SlotTable, err = hexField(m, "slot-table", HashSize); err != nil {
		return Statement{}, err
	}
	if s.SHA256, err = hexField(m, "sha256", HashSize); err != nil {
		return Statement{}, err
	}
	if s.Size, err = decField(m, "size"); err != nil {
		return Statement{}, err
	}
	if s.Time, err = timeField(m, "time"); err != nil {
		return Statement{}, err
	}
	if s.KeyHash, err = hexField(m, "key-hash", HashSize); err != nil {
		return Statement{}, err
	}
	if !bytes.Equal(s.Encode(), text) {
		return Statement{}, formatErr("does not re-encode to itself")
	}
	return s, nil
}

// ---- the checkpoint object: statement and signature ----

// SeparatorLine ends the statement in a checkpoint object. The object is the
// statement text, one blank line, then the armored SSH signature, so a reader
// can cut it without parsing the signature first.
const SeparatorLine = "\n"

// Signed is a statement and its armored SSHSIG, as stored in the sink.
type Signed struct {
	Statement []byte // the canonical text
	Armored   []byte // the armored SSH signature
}

// EncodeObject joins them.
func (s Signed) EncodeObject() []byte {
	out := append([]byte(nil), s.Statement...)
	out = append(out, SeparatorLine...)
	return append(out, s.Armored...)
}

// ParseObject splits a checkpoint object into the statement and the armored
// signature. It checks only the framing and the size.
func ParseObject(obj []byte) (Signed, error) {
	if len(obj) > MaxObjectSize {
		return Signed{}, formatErr("the checkpoint is larger than %d bytes", MaxObjectSize)
	}
	i := bytes.Index(obj, []byte("\n\n"))
	if i < 0 {
		return Signed{}, formatErr("no blank line between the statement and the signature")
	}
	return Signed{Statement: obj[:i+1], Armored: obj[i+2:]}, nil
}

// Verify checks the SSHSIG over the statement (namespace TagCheckpoint) against
// the key hash and parses the statement, which must name that key hash itself.
// The public key is trusted only because its hash is wantKeyHash: it travels in
// the signature and is checked against the hash, never taken from the sink.
func (s Signed) Verify(wantKeyHash []byte) (Statement, sshsig.Result, error) {
	blob, err := sshsig.Dearmor(s.Armored)
	if err != nil {
		return Statement{}, sshsig.Result{}, err
	}
	res, err := sshsig.Verify(blob, s.Statement, TagCheckpoint, wantKeyHash, Application)
	if err != nil {
		return Statement{}, sshsig.Result{}, err
	}
	st, err := ParseStatement(s.Statement)
	if err != nil {
		return Statement{}, sshsig.Result{}, err
	}
	if !bytes.Equal(st.KeyHash, res.Key.Hash()) {
		return Statement{}, sshsig.Result{}, errors.New("checkpoint: the statement names another key than the one that signed it")
	}
	return st, res, nil
}

// ObjectName is the name of the checkpoint beside a backup object: the backup's
// name without its ".spo" suffix, and ".checkpoint".
func ObjectName(backupName string) (string, bool) {
	base, ok := strings.CutSuffix(backupName, ".spo")
	if !ok {
		return "", false
	}
	return base + ".checkpoint", true
}

// ---- pins ----

// Pin is what the operator keeps for restores. The exact pin of stage 1 fixes one
// file; the long-lived pin names the workspace and the checkpoint key.
//
//	exact:      <workspace id hex>:<head sequence>:<head MAC hex>:<file SHA-256 hex>
//	long-lived: <workspace id hex>:ck:<key hash hex>[:<minimum sequence>]
type LongPin struct {
	WorkspaceID []byte
	KeyHash     []byte
	// MinSeq is the lowest head sequence a restore accepts; HasMin says it was given.
	MinSeq uint64
	HasMin bool
}

// String is the canonical text.
func (p LongPin) String() string {
	s := hex.EncodeToString(p.WorkspaceID) + ":ck:" + hex.EncodeToString(p.KeyHash)
	if p.HasMin {
		s += ":" + strconv.FormatUint(p.MinSeq, 10)
	}
	return s
}

// WithMin is the pin that also refuses anything older than seq.
func (p LongPin) WithMin(seq uint64) LongPin { p.MinSeq, p.HasMin = seq, true; return p }

// IsLongPin reports whether the text is of the long-lived form (its second field
// is "ck"), so a caller can choose a parser.
func IsLongPin(s string) bool {
	f := strings.Split(s, ":")
	return len(f) >= 2 && f[1] == "ck"
}

// ParseLongPin parses the long-lived pin strictly.
func ParseLongPin(s string) (LongPin, error) {
	f := strings.Split(s, ":")
	if (len(f) != 3 && len(f) != 4) || f[1] != "ck" || !hexRE.MatchString(f[0]) || len(f[2]) != 2*HashSize || !hexRE.MatchString(f[2]) {
		return LongPin{}, errors.New("the pin is not <workspace id hex>:ck:<checkpoint key hash hex>[:<minimum sequence>] (lower-case hex)")
	}
	var p LongPin
	p.WorkspaceID, _ = hex.DecodeString(f[0])
	p.KeyHash, _ = hex.DecodeString(f[2])
	if len(f) == 4 {
		if !decRE.MatchString(f[3]) {
			return LongPin{}, errors.New("the pin's minimum sequence is not a canonical number")
		}
		n, err := strconv.ParseUint(f[3], 10, 64)
		if err != nil {
			return LongPin{}, errors.New("the pin's minimum sequence is out of range")
		}
		p.MinSeq, p.HasMin = n, true
	}
	return p, nil
}

// ---- the key record ----

// KeyRecord is what the sealed store keeps about the checkpoint key. None of it
// is secret (class Sensitive: sealed, ordinary memory); the credential id is
// kept because only this workspace can use it to ask the authenticator.
type KeyRecord struct {
	Key          sshsig.Key
	CredentialID []byte
	Enrolled     time.Time
}

var recordKeys = []string{"key-type", "application", "public-key", "credential-id", "key-hash", "enrolled"}

// Hash is the checkpoint key hash.
func (r KeyRecord) Hash() []byte { return r.Key.Hash() }

// Encode is the canonical text.
func (r KeyRecord) Encode() []byte {
	var b bytes.Buffer
	b.WriteString(TagKeyRecord + "\n")
	for _, f := range []field{
		{"key-type", sshsig.KeyType},
		{"application", r.Key.Application},
		{"public-key", hex.EncodeToString(r.Key.Q)},
		{"credential-id", hex.EncodeToString(r.CredentialID)},
		{"key-hash", hex.EncodeToString(r.Hash())},
		{"enrolled", fmtTime(r.Enrolled)},
	} {
		b.WriteString(f.key + " " + f.val + "\n")
	}
	return b.Bytes()
}

// ParseKeyRecord reads the canonical text strictly and checks that the stored
// hash is the hash of the key.
func ParseKeyRecord(text []byte) (KeyRecord, error) {
	m, err := parseFields(text, TagKeyRecord, recordKeys)
	if err != nil {
		return KeyRecord{}, err
	}
	if m["key-type"] != sshsig.KeyType {
		return KeyRecord{}, formatErr("key-type is not %s", sshsig.KeyType)
	}
	q, err := hexField(m, "public-key", 65)
	if err != nil {
		return KeyRecord{}, err
	}
	cred, err := hexField(m, "credential-id", 0)
	if err != nil {
		return KeyRecord{}, err
	}
	stored, err := hexField(m, "key-hash", HashSize)
	if err != nil {
		return KeyRecord{}, err
	}
	en, err := timeField(m, "enrolled")
	if err != nil {
		return KeyRecord{}, err
	}
	key, err := sshsig.ParseKeyBlob(sshsig.Key{Q: q, Application: m["application"]}.Blob())
	if err != nil {
		return KeyRecord{}, err
	}
	r := KeyRecord{Key: key, CredentialID: cred, Enrolled: en}
	if !bytes.Equal(r.Hash(), stored) {
		return KeyRecord{}, formatErr("key-hash is not the hash of the public key")
	}
	if !bytes.Equal(r.Encode(), text) {
		return KeyRecord{}, formatErr("does not re-encode to itself")
	}
	return r, nil
}

// ---- replacing or removing the key ----

// Replacement is the statement the existing checkpoint key signs to authorise
// a new key (or, with no new key, its removal) in a workspace that has no
// recovery path (strict).
type Replacement struct {
	WorkspaceID []byte
	OldKeyHash  []byte
	// NewKeyHash is nil for a removal.
	NewKeyHash []byte
	Time       time.Time
}

var replaceKeys = []string{"workspace", "old-key-hash", "new-key-hash", "time"}

// Encode is the canonical text.
func (r Replacement) Encode() []byte {
	nk := "none"
	if r.NewKeyHash != nil {
		nk = hex.EncodeToString(r.NewKeyHash)
	}
	var b bytes.Buffer
	b.WriteString(TagReplace + "\n")
	for _, f := range []field{
		{"workspace", hex.EncodeToString(r.WorkspaceID)},
		{"old-key-hash", hex.EncodeToString(r.OldKeyHash)},
		{"new-key-hash", nk},
		{"time", fmtTime(r.Time)},
	} {
		b.WriteString(f.key + " " + f.val + "\n")
	}
	return b.Bytes()
}

// ParseReplacement reads the canonical text strictly.
func ParseReplacement(text []byte) (Replacement, error) {
	m, err := parseFields(text, TagReplace, replaceKeys)
	if err != nil {
		return Replacement{}, err
	}
	var r Replacement
	if r.WorkspaceID, err = hexField(m, "workspace", 0); err != nil {
		return Replacement{}, err
	}
	if r.OldKeyHash, err = hexField(m, "old-key-hash", HashSize); err != nil {
		return Replacement{}, err
	}
	if m["new-key-hash"] != "none" {
		if r.NewKeyHash, err = hexField(m, "new-key-hash", HashSize); err != nil {
			return Replacement{}, err
		}
	}
	if r.Time, err = timeField(m, "time"); err != nil {
		return Replacement{}, err
	}
	if !bytes.Equal(r.Encode(), text) {
		return Replacement{}, formatErr("does not re-encode to itself")
	}
	return r, nil
}

// VerifyReplacement checks that armored is the SSH signature (namespace
// TagReplace) of the existing key, whose record is old, over the replacement
// text, and that the text names this workspace, that key and newKeyHash (nil for
// a removal). The time must be within maxAge of now (a signed statement is not a
// standing permission).
func VerifyReplacement(text, armored []byte, old KeyRecord, workspaceID, newKeyHash []byte, now time.Time, maxAge time.Duration) error {
	blob, err := sshsig.Dearmor(armored)
	if err != nil {
		return err
	}
	if _, err := sshsig.Verify(blob, text, TagReplace, old.Hash(), Application); err != nil {
		return err
	}
	r, err := ParseReplacement(text)
	if err != nil {
		return err
	}
	switch {
	case !bytes.Equal(r.WorkspaceID, workspaceID):
		return errors.New("checkpoint: the replacement statement names another workspace")
	case !bytes.Equal(r.OldKeyHash, old.Hash()):
		return errors.New("checkpoint: the replacement statement names another current key")
	case !bytes.Equal(r.NewKeyHash, newKeyHash):
		return errors.New("checkpoint: the replacement statement names another new key")
	}
	if d := now.Sub(r.Time); d > maxAge || d < -maxAge {
		return errors.New("checkpoint: the replacement statement is not recent")
	}
	return nil
}

// KeyHashOfBlob is SHA-256 of an SSH public key blob.
func KeyHashOfBlob(blob []byte) []byte {
	h := sha256.Sum256(blob)
	return h[:]
}
