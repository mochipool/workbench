package layout

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// THE PROVISIONAL HEAD NOTE (ADR 0012 decisions 3 and 4, stage 3). A canonical
// text that the single local writer commits as heads/<sequence, 20 digits>:
//
//	spo/head-provisional/1
//	workspace <hex>
//	sequence <decimal, from 1>
//	previous <hash of the previous head note, hex; all zeros for the first head>
//	manifest <object hash of the manifest root, hex>
//	slots <object hash of the slots object, hex>
//	audit-seq <decimal>
//	audit-mac <hex>
//	recovery-key <hash of the recovery public key, hex, or none>
//	checkpoint-key <hash of the checkpoint key, hex, or none>
//	epoch <the key epoch, hex>
//	object-format spo/object/1
//	time <UTC, 2006-01-02T15:04:05Z>
//
// A line feed ends every line. The format is provisional: stage 5 may replace
// it after the formal model, and nothing else relies on it until then. This
// package builds and parses the text and names the signature namespace; it
// does not sign.
const (
	// TagHead is the first line of a provisional head note.
	TagHead = "spo/head-provisional/1"
	// NamespaceHead is the SSHSIG namespace a head note is signed in.
	NamespaceHead = "spo/head-provisional/v1"
	// ObjectFormat is the literal that names the object envelope a head's objects
	// are in: the first element of the envelope's associated data.
	ObjectFormat = "spo/object/1"
	// MaxHeadSize bounds a note.
	MaxHeadSize = 4 << 10

	headTimeLayout = "2006-01-02T15:04:05Z"
)

var (
	headKeys = []string{"workspace", "sequence", "previous", "manifest", "slots", "audit-seq", "audit-mac", "recovery-key", "checkpoint-key", "epoch", "object-format", "time"}
	hexRE    = regexp.MustCompile(`^(?:[0-9a-f]{2})+$`)
	decRE    = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,19})$`)
)

// Head is a provisional head.
type Head struct {
	Workspace     []byte // 16 bytes
	Sequence      uint64 // from 1
	Previous      []byte // hash of the previous head note; all zeros for sequence 1
	Manifest      []byte // object hash of the manifest root
	Slots         []byte // object hash of the slots object
	AuditSeq      uint64
	AuditMAC      []byte
	RecoveryKey   []byte // hash of the recovery public key; nil for none
	CheckpointKey []byte // hash of the checkpoint key; nil for none
	Epoch         []byte // the key epoch, 16 bytes
	Time          time.Time
}

// HeadHash is Blake2b-256 of the note's bytes: the hash the next head names as
// its previous.
func HeadHash(note []byte) []byte {
	h := blake2b.Sum256(note)
	return h[:]
}

// HeadPath is heads/<sequence, 20 digits>.
func HeadPath(seq uint64) string { return fmt.Sprintf("heads/%020d", seq) }

func (h Head) validate() error {
	if len(h.Workspace) != 16 {
		return formatErr("a workspace id is 16 bytes")
	}
	if h.Sequence == 0 {
		return formatErr("a head sequence number is at least 1")
	}
	for _, f := range []struct {
		b    []byte
		what string
	}{{h.Previous, "previous"}, {h.Manifest, "manifest"}, {h.Slots, "slots"}, {h.AuditMAC, "audit-mac"}} {
		if len(f.b) != HashSize {
			return formatErr("%s is a 32-byte hash", f.what)
		}
	}
	if h.RecoveryKey != nil && len(h.RecoveryKey) != HashSize {
		return formatErr("recovery-key is a 32-byte hash or none")
	}
	if h.CheckpointKey != nil && len(h.CheckpointKey) != HashSize {
		return formatErr("checkpoint-key is a 32-byte hash or none")
	}
	if len(h.Epoch) != EpochSize {
		return formatErr("the key epoch is %d bytes", EpochSize)
	}
	if (h.Sequence == 1) != allZero(h.Previous) {
		return formatErr("previous is all zeros exactly for the first head")
	}
	if h.Time.IsZero() || h.Time.Year() < 1970 || h.Time.Year() > 9999 || h.Time.Nanosecond() != 0 {
		return formatErr("the time is a whole second in 1970..9999")
	}
	return nil
}

// Encode is the canonical text.
func (h Head) Encode() ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	rk := "none"
	if h.RecoveryKey != nil {
		rk = hex.EncodeToString(h.RecoveryKey)
	}
	ck := "none"
	if h.CheckpointKey != nil {
		ck = hex.EncodeToString(h.CheckpointKey)
	}
	vals := []string{hex.EncodeToString(h.Workspace), strconv.FormatUint(h.Sequence, 10), hex.EncodeToString(h.Previous),
		hex.EncodeToString(h.Manifest), hex.EncodeToString(h.Slots), strconv.FormatUint(h.AuditSeq, 10),
		hex.EncodeToString(h.AuditMAC), rk, ck, hex.EncodeToString(h.Epoch), ObjectFormat, h.Time.UTC().Format(headTimeLayout)}
	var b bytes.Buffer
	b.WriteString(TagHead + "\n")
	for i, k := range headKeys {
		b.WriteString(k + " " + vals[i] + "\n")
	}
	return b.Bytes(), nil
}

// ParseHead reads the canonical text strictly: exact tag and keys in order,
// canonical decimals within 64 bits, lower-case hex of the right lengths, a
// UTC time with no fraction or offset, one line feed per line, at most
// MaxHeadSize bytes, and the text must re-encode to itself.
func ParseHead(note []byte) (Head, error) {
	if len(note) > MaxHeadSize {
		return Head{}, formatErr("a head note is at most %d bytes", MaxHeadSize)
	}
	if len(note) == 0 || note[len(note)-1] != '\n' {
		return Head{}, formatErr("no final line feed")
	}
	lines := strings.Split(string(note[:len(note)-1]), "\n")
	if len(lines) != len(headKeys)+1 || lines[0] != TagHead {
		return Head{}, formatErr("expected %q and %d fields", TagHead, len(headKeys))
	}
	m := map[string]string{}
	for i, k := range headKeys {
		key, val, ok := strings.Cut(lines[i+1], " ")
		if !ok || key != k || val == "" || strings.ContainsAny(val, " \t\r\x00") {
			return Head{}, formatErr("line %d is not %q and a value", i+2, k)
		}
		m[k] = val
	}
	var h Head
	var err error
	hexOf := func(k string, size int) ([]byte, error) {
		if !hexRE.MatchString(m[k]) || len(m[k]) != 2*size {
			return nil, formatErr("%s is not %d bytes of lower-case hex", k, size)
		}
		return hex.DecodeString(m[k])
	}
	decOf := func(k string) (uint64, error) {
		if !decRE.MatchString(m[k]) {
			return 0, formatErr("%s is not a canonical decimal number", k)
		}
		n, err := strconv.ParseUint(m[k], 10, 64)
		if err != nil {
			return 0, formatErr("%s is out of range", k)
		}
		return n, nil
	}
	if h.Workspace, err = hexOf("workspace", 16); err != nil {
		return Head{}, err
	}
	if h.Sequence, err = decOf("sequence"); err != nil {
		return Head{}, err
	}
	if h.Previous, err = hexOf("previous", HashSize); err != nil {
		return Head{}, err
	}
	if h.Manifest, err = hexOf("manifest", HashSize); err != nil {
		return Head{}, err
	}
	if h.Slots, err = hexOf("slots", HashSize); err != nil {
		return Head{}, err
	}
	if h.AuditSeq, err = decOf("audit-seq"); err != nil {
		return Head{}, err
	}
	if h.AuditMAC, err = hexOf("audit-mac", HashSize); err != nil {
		return Head{}, err
	}
	if m["recovery-key"] != "none" {
		if h.RecoveryKey, err = hexOf("recovery-key", HashSize); err != nil {
			return Head{}, err
		}
	}
	if m["checkpoint-key"] != "none" {
		if h.CheckpointKey, err = hexOf("checkpoint-key", HashSize); err != nil {
			return Head{}, err
		}
	}
	if h.Epoch, err = hexOf("epoch", EpochSize); err != nil {
		return Head{}, err
	}
	if m["object-format"] != ObjectFormat {
		return Head{}, formatErr("object-format is not %q", ObjectFormat)
	}
	t, terr := time.Parse(headTimeLayout, m["time"])
	if terr != nil || t.Format(headTimeLayout) != m["time"] {
		return Head{}, formatErr("time is not a UTC time like 2006-01-02T15:04:05Z")
	}
	h.Time = t
	// Every field was checked against its exact spelling above (and the fuzz
	// target requires that what is accepted re-encodes to itself), so the note
	// is not re-encoded here; the validity rules are those of Encode.
	if err := h.validate(); err != nil {
		return Head{}, err
	}
	return h, nil
}
