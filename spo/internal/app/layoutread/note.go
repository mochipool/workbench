package layoutread

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// NoteMatchesSnapshot reports whether a head note equals, in every field but its
// time, the note an export would encode for the workspace the snapshot was
// installed as. The manifest root binds the sequence number, the previous head,
// the slots object and the audit head, but not the checkpoint key or the time of
// the note: an importer records the pin of a head only when the note is one the
// workspace would have written, so that the next export never chains onto a note
// it did not write. installedKey is the hash of the checkpoint key the installed
// workspace holds (nil for none); the note may name no key or that key.
func NoteMatchesSnapshot(h layout.Head, snap ports.Snapshot, installedKey []byte) error {
	m := snap.Meta
	if !bytes.Equal(h.Workspace, m.WorkspaceID) {
		return errors.New("the head names another workspace")
	}
	if !bytes.Equal(h.Epoch, m.KeyEpoch) {
		return errors.New("the head names another key epoch")
	}
	var rk []byte
	if m.RecoveryPub != nil {
		s := sha256.Sum256(m.RecoveryPub)
		rk = s[:]
	}
	if !bytes.Equal(h.RecoveryKey, rk) {
		return errors.New("the head names another recovery key")
	}
	var seq uint64
	mac := make([]byte, layout.HashSize)
	if n := len(snap.Audit); n > 0 {
		seq, mac = uint64(snap.Audit[n-1].Seq), snap.Audit[n-1].MAC
	}
	if h.AuditSeq != seq || !bytes.Equal(h.AuditMAC, mac) {
		return fmt.Errorf("the head's audit position (sequence %d) is not the installed workspace's (%d)", h.AuditSeq, seq)
	}
	if h.CheckpointKey != nil && !bytes.Equal(h.CheckpointKey, installedKey) {
		return errors.New("the head names a checkpoint key that the installed workspace does not hold")
	}
	return nil
}
