package relaydir

import (
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// ErrLocked: a directory store's lock is held, so a relay (or another tool)
// has it open. Stop the relay first.
var ErrLocked = errors.New("a directory store is in use by another process (is the relay still running?): stop it first")

// ErrNotAStore: a directory holds what its store would refuse.
var ErrNotAStore = errors.New("the directory is not a store this tool reads")

// Tombstone is one tombstone file: its scope key and the maximum not-before.
type Tombstone struct {
	Key       relayregistry.TombKey
	Name      string
	NotBefore int64
}

// Binding is one binding file, its bytes as the store wrote them.
type Binding struct {
	Device party.Fingerprint
	Record []byte
}

// Entry is one mailbox entry, named by recipient, arrival, id and sender.
type Entry struct {
	Recipient, Sender party.Fingerprint
	Arrival           int64
	Mid               mailbox.Hash
	Size              int64
}
