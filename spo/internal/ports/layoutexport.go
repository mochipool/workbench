package ports

import (
	"context"
	"errors"
)

// PORTS OF THE LAYOUT EXPORTER (ADR 0012 stage 3, spec/extensions/Xlayout.md).
//
// The use case that writes a workspace as sealed objects (app/layoutexport)
// reaches keys, the directory lock and the forward-only pin only through these
// ports. None of them hands a key to the use case.

// ObjectSealer seals the bodies of the objects of one workspace under its
// current key epoch. It is made from an unlocked workspace; the use case never
// sees a key byte. Seal takes a framed body (layout.FrameBody) and returns the
// stored object. Close destroys the keys; it is safe to call twice.
type ObjectSealer interface {
	// Epoch is the 16-byte key epoch the sealer is for.
	Epoch() []byte
	// WorkspaceID is the genesis nonce the sealer binds into every object.
	WorkspaceID() []byte
	Seal(body []byte) (stored []byte, err error)
	Close()
}

// RecordRef is what a record's owner blob says about it: the binary anchor
// identity and the number, and the class the store's kind-to-class rule gives
// the record's kind. The adapter opens the owner blob with the workspace keys
// and checks the lookup tag; the record's payload is never opened.
type RecordRef struct {
	Anchor []byte
	Num    uint64
	Class  string
}

// ErrLayoutLocked is returned by LayoutLocker.Lock when another exporter holds
// the layout directory.
var ErrLayoutLocked = errors.New("another export holds this layout directory")

// ErrLayoutMoved is returned by LayoutLock.Check when the directory is no
// longer the one that was locked (it was replaced or swapped for a link).
var ErrLayoutMoved = errors.New("the layout directory is not the one that was locked: it was replaced while the export ran")

// LayoutLock is the exclusive single-writer lock of a layout directory.
type LayoutLock interface {
	// Check fails with ErrLayoutMoved when the directory has been replaced since
	// the lock was taken.
	Check() error
	Release() error
}

// LayoutLocker takes the single-writer lock of a layout directory without
// waiting.
type LayoutLocker interface {
	Lock(ctx context.Context) (LayoutLock, error)
}

// LayoutPin is the forward-only local record of the newest head this machine
// wrote to a layout directory.
type LayoutPin struct {
	Sequence uint64
	HeadHash []byte
}

// ErrLayoutPinCorrupt is returned by LayoutPins.Load for a pin file that does
// not parse. It is never replaced silently.
var ErrLayoutPinCorrupt = errors.New("the layout pin file is damaged")

// ErrLayoutPinBackwards is returned by LayoutPins.Advance for a pin that is not
// ahead of the recorded one.
var ErrLayoutPinBackwards = errors.New("the layout pin would not move forward")

// LayoutPins keeps the pin of one layout directory in a file beside the
// workspace file (never in the layout directory).
type LayoutPins interface {
	Load() (pin LayoutPin, found bool, err error)
	// Advance records pin atomically. It succeeds without writing when pin is
	// the recorded one, and fails with ErrLayoutPinBackwards when it is behind
	// it or has the same sequence number and another hash.
	Advance(pin LayoutPin) error
}
