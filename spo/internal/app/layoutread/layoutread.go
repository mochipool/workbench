// Package layoutread is the use case of ADR 0012 stage 3, work packages 4 and 5:
// check a sealed object layout in a directory, and rebuild a snapshot of the
// workspace from it. It is the one reader behind `spo store verify --layout` and
// `spo store convert --from-layout` (spec/extensions/Xlayout.md, "The verifier
// and the importer").
package layoutread

import (
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals. Each wraps a message that names what failed.
var (
	ErrNoPin      = errors.New("layoutread: a pin is required")
	ErrBadPin     = errors.New("layoutread: the pin is not valid")
	ErrNoHead     = errors.New("layoutread: the directory has no head the pin can be checked against")
	ErrRolledBack = errors.New("layoutread: the directory is behind the pin")
	ErrPinHash    = errors.New("layoutread: the head is not the head the pin names")
	ErrChain      = errors.New("layoutread: the head chain does not verify")
	ErrWorkspace  = errors.New("layoutread: the directory holds a head of another workspace")
	ErrSignature  = errors.New("layoutread: a head is not signed by the pinned key")
	ErrObject     = errors.New("layoutread: an object is missing or is not what its name says")
	ErrSlots      = errors.New("layoutread: the slots object does not verify")
	ErrManifest   = errors.New("layoutread: the manifest does not verify")
	ErrRecord     = errors.New("layoutread: a record object does not match the manifest or its owner")
	ErrAudit      = errors.New("layoutread: an audit object does not match the manifest")
	ErrLimit      = errors.New("layoutread: the layout is larger than this reader accepts")
	ErrChanged    = errors.New("layoutread: the directory changed while it was read")
	ErrSnapshot   = errors.New("layoutread: the rows rebuilt from the layout are not a valid snapshot")
)

// MaxHeads bounds the heads one check looks at. A head is at most 4 KiB, so the
// bound is 400 MB of reading at the most, and a hostile directory cannot make the
// check run on without end.
var MaxHeads = 100_000

// Options choose among the heads of the directory.
type Options struct {
	// At is the head to use. Without it the check uses the newest head that
	// verifies and stops, naming the head, at the first one that does not.
	At    uint64
	HasAt bool
}

// HeadInfo is a head the check read.
type HeadInfo struct {
	Head layout.Head
	Note []byte
	Hash []byte
	// Signed is true when heads/<sequence>.sig verified (against the pinned key,
	// or against the key the head names when the pin is exact); SignedBy is that
	// key's hash.
	Signed   bool
	SignedBy []byte
}

// Locked is what the locked pass established: no credential was used.
type Locked struct {
	Pin Pin
	// Used is the head the rest of the check relies on; Chain is every head
	// examined, oldest first, Used last.
	Used  HeadInfo
	Chain []HeadInfo
	// Newest is true when no head above Used was found (heads are looked up by
	// number, not listed).
	Newest bool
	// Slots is the parsed slots object the head names.
	Slots layout.SlotsObject
	// ManifestStored is the stored manifest root the head names, hashed and
	// size-checked, sealed.
	ManifestStored []byte
	// SlotsBytes and ManifestBytes are the stored sizes of the two objects.
	SlotsBytes, ManifestBytes int
	Notices                   []string
	// Vouched is the policy of the slot table the pin vouches for: the pinned head's
	// for an exact pin, the used head's for a key pin.
	Vouched string
	// Established and Cannot say what this pass proved and what it cannot.
	Established []string
	Cannot      []string
}

// LockedInput is what the locked pass needs.
type LockedInput struct {
	Reader ports.ObjectReader
	Pin    Pin
	Opt    Options
	// Tables is the store's unlock-policy check on the slot table.
	Tables ports.SlotTableChecker
}
