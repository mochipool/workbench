package layoutread

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// PinKind says what a pin proves.
type PinKind int

const (
	// PinExact names one head: <workspace id>:layout:<sequence>:<head hash>. It
	// proves that head and what the hash chain below it says; it does not
	// authenticate a later head.
	PinExact PinKind = iota + 1
	// PinKey names the workspace and the checkpoint key: <workspace id>:ck:<key
	// hash>[:<minimum sequence>]. It authenticates every head that carries a
	// signature of that key; with no minimum it does not prove the head is the
	// newest.
	PinKey
)

// Pin is what the operator brings to a check. It is required: there is no way
// to check a layout by trusting the directory.
type Pin struct {
	Kind        PinKind
	WorkspaceID []byte
	// Sequence and HeadHash are the pinned head (PinExact).
	Sequence uint64
	HeadHash []byte
	// KeyHash, MinSeq and HasMin are the pinned key and the lowest head
	// sequence number accepted (PinKey).
	KeyHash []byte
	MinSeq  uint64
	HasMin  bool
}

// MaxSequence bounds the head sequence numbers this reader accepts, as the
// exporter's does, so nothing wraps.
const MaxSequence = 1 << 32

var exactPinRE = regexp.MustCompile(`^([0-9a-f]{32}):layout:(0|[1-9][0-9]{0,19}):([0-9a-f]{64})$`)

// ParsePin parses the exact pin the exporter prints, or the long-lived pin of a
// checkpoint key, strictly (lower-case hex, canonical decimals). An empty
// string is ErrNoPin.
func ParsePin(text string) (Pin, error) {
	if text == "" {
		return Pin{}, ErrNoPin
	}
	if checkpoint.IsLongPin(text) {
		lp, err := checkpoint.ParseLongPin(text)
		if err != nil {
			return Pin{}, fmt.Errorf("%w: %v", ErrBadPin, err)
		}
		if len(lp.WorkspaceID) != 16 {
			return Pin{}, fmt.Errorf("%w: the workspace id of a pin is 32 hex digits", ErrBadPin)
		}
		return Pin{Kind: PinKey, WorkspaceID: lp.WorkspaceID, KeyHash: lp.KeyHash, MinSeq: lp.MinSeq, HasMin: lp.HasMin}, nil
	}
	m := exactPinRE.FindStringSubmatch(text)
	if m == nil {
		return Pin{}, fmt.Errorf("%w: it is <workspace id>:layout:<sequence>:<head hash> (what the export printed) or <workspace id>:ck:<checkpoint key hash>[:<minimum sequence>], in lower-case hex", ErrBadPin)
	}
	seq, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil || seq == 0 || seq > MaxSequence {
		return Pin{}, fmt.Errorf("%w: the head sequence number %s is out of range", ErrBadPin, m[2])
	}
	ws, _ := hex.DecodeString(m[1])
	h, _ := hex.DecodeString(m[3])
	return Pin{Kind: PinExact, WorkspaceID: ws, Sequence: seq, HeadHash: h}, nil
}

// PinFromLocal turns the pin this machine keeps beside the workspace file (the
// newest head it exported to this directory) into an exact pin of the
// workspace.
func PinFromLocal(workspaceID []byte, p ports.LayoutPin) Pin {
	return Pin{Kind: PinExact, WorkspaceID: append([]byte(nil), workspaceID...), Sequence: p.Sequence, HeadHash: append([]byte(nil), p.HeadHash...)}
}
