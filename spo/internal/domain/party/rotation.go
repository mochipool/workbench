package party

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Rotation (SPO-Xparty-IF-008, INV-030 to INV-034): an operator replaces
// their own party identity. The new identity is announced in a statement
// signed by the old key and by the new key; a peer that imports it sees both
// fingerprints and replaces the enrollment only when its operator confirms.

// Domain strings of a rotation statement. Two of them, so that a signature
// made as the old identity cannot stand for the new one or the other way
// round.
const (
	RotationOldDomain = "spo/rotation/v1/old"
	RotationNewDomain = "spo/rotation/v1/new"
	// RotationVersion is the statement version.
	RotationVersion = 1
	// MaxRotationLifetime bounds expires - created of a statement.
	MaxRotationLifetime = 30 * 24 * time.Hour
	// MaxRotationBytes bounds a statement as carried in a message.
	MaxRotationBytes = 4096
	// MaxPendingRotations bounds the statements waiting for an operator.
	MaxPendingRotations = 16
)

// Rotation is a rotation statement. Content is the canonical CBOR both
// signatures cover; adapters/envelope makes a Rotation from bytes and is the
// only producer, so Old, New, Created and Expires are the decoding of Content.
type Rotation struct {
	Old         Fingerprint // the identity being replaced
	New         Document    // the new identity and its own signed document
	Created     time.Time
	Expires     time.Time
	Content     []byte
	OldSig      [64]byte
	NewSig      [64]byte
	NewDocument []byte // the new identity document as carried, for storing
}

// Rotation refusals.
var (
	ErrRotationInvalid = errors.New("party: invalid rotation statement")
	// ErrRotationSignature: one of the two signatures does not verify.
	ErrRotationSignature = errors.New("party: rotation statement signature does not verify")
	ErrRotationExpired   = errors.New("party: rotation statement has expired")
	// ErrRotationUnknown: the statement names an identity that is not enrolled.
	ErrRotationUnknown = errors.New("party: the rotation names an identity that was never enrolled here")
	// ErrRotationRevoked: the identity it replaces is already revoked, as it is
	// after the rotation was accepted: a replayed statement lands here.
	ErrRotationRevoked = errors.New("party: the identity the rotation replaces is already revoked")
	// ErrRotationNodeKey: the new identity has another tailcat node key than
	// the one it replaces; the node key is not part of what is rotated
	// (SPO-Xparty-INV-030).
	ErrRotationNodeKey = errors.New("party: the rotation changes the tailcat node key, which a rotation keeps")
	// ErrRotationSame: old and new are one identity.
	ErrRotationSame = errors.New("party: a rotation to the same identity")
)

// RotationOldMessage and RotationNewMessage are the byte strings the two
// signatures cover.
func RotationOldMessage(content []byte) []byte {
	return append([]byte(RotationOldDomain), content...)
}

func RotationNewMessage(content []byte) []byte {
	return append([]byte(RotationNewDomain), content...)
}

// Verify checks the statement against the signing key the replaced identity is
// enrolled with: the new document verifies (SPO-Xparty-PRE-001), both
// signatures verify, the identities differ, and the statement's window is
// sane and has not passed (SPO-Xparty-INV-030).
func (r Rotation) Verify(oldKey Ed25519Public, now time.Time) error {
	if len(r.Content) == 0 {
		return fmt.Errorf("%w: empty content", ErrRotationInvalid)
	}
	if err := r.New.Verify(); err != nil {
		return fmt.Errorf("%w: the new identity: %v", ErrRotationInvalid, err)
	}
	if err := r.New.Identity.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrRotationInvalid, err)
	}
	if !ed25519.Verify(ed25519.PublicKey(oldKey[:]), RotationOldMessage(r.Content), r.OldSig[:]) {
		return fmt.Errorf("%w: the old key", ErrRotationSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(r.New.Identity.Ed25519[:]), RotationNewMessage(r.Content), r.NewSig[:]) {
		return fmt.Errorf("%w: the new key", ErrRotationSignature)
	}
	if r.New.Identity.Fingerprint() == r.Old {
		return ErrRotationSame
	}
	if r.Expires.Before(r.Created) || r.Expires.Sub(r.Created) > MaxRotationLifetime {
		return fmt.Errorf("%w: window", ErrRotationInvalid)
	}
	if now.After(r.Expires) {
		return ErrRotationExpired
	}
	if r.Created.After(now.Add(ClockSkew)) {
		return fmt.Errorf("%w: created in the future", ErrRotationInvalid)
	}
	return nil
}

// SameNode reports whether two optional node keys are the same: both absent, or
// both present and equal.
func SameNode(a, b *NodeKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// RetiredName is the local name under which a replaced identity is kept. It
// contains a character no enrollment name may (a local name is letters,
// digits, '-' and '_'), so it never collides with one, and the fingerprint
// prefix keeps two rotations of one name apart.
func RetiredName(name string, old Fingerprint) string {
	return name + "~" + old.compact()[:8]
}

// RotationAcceptance is the operator's decision on a statement.
type RotationAcceptance struct {
	// Confirmation is the first four groups of the NEW fingerprint as typed
	// (SPO-Xparty-PR-006). There is no value that skips it.
	Confirmation string
	// CarryScope: the scope recorded for the old identity applies to the new
	// one. Without it the new identity has the scope that allows nothing.
	CarryScope bool
	// Relay is the relay identity of the NEW identity from the binding given
	// with the acceptance, already verified by the caller; nil leaves the new
	// identity with none (SPO-Xparty-INV-042).
	Relay *RelayIdentity
}

// ApplyRotation is the whole of SPO-Xparty-INV-032 as a pure function: from the
// registry as it is (existing), the statement and the operator's decision, it
// returns the old record revoked and renamed and the new record, or refuses and
// the caller changes nothing. The checks run in this order: the identity it
// replaces is enrolled and not revoked; the statement verifies against that
// identity's enrolled key and has not expired; the new identity is not
// already enrolled, and its node key is not another party's; the typed
// fingerprint groups match.
func ApplyRotation(r Rotation, a RotationAcceptance, existing []Party, now time.Time) (retired, next Party, err error) {
	idx := slices.IndexFunc(existing, func(p Party) bool { return p.Fingerprint == r.Old })
	if idx < 0 {
		return Party{}, Party{}, ErrRotationUnknown
	}
	old := existing[idx]
	if !old.Active() {
		return Party{}, Party{}, ErrRotationRevoked
	}
	if err := r.Verify(old.Identity.Ed25519, now); err != nil {
		return Party{}, Party{}, err
	}
	id := r.New.Identity
	fp := id.Fingerprint()
	for _, q := range existing {
		if q.Fingerprint == fp {
			return Party{}, Party{}, ErrAlreadyEnrolled
		}
		if q.Fingerprint != old.Fingerprint && q.Active() && id.Node != nil && q.Identity.Node != nil && *id.Node == *q.Identity.Node {
			return Party{}, Party{}, fmt.Errorf("%w: %s", ErrNodeKeyInUse, q.Name)
		}
	}
	if !SameNode(id.Node, old.Identity.Node) {
		return Party{}, Party{}, ErrRotationNodeKey
	}
	if !ConfirmPrefix(fp, a.Confirmation) {
		return Party{}, Party{}, ErrConfirmation
	}
	if err := CheckRelay(a.Relay, fp); err != nil {
		return Party{}, Party{}, err
	}
	retired, err = Revoke(old)
	if err != nil {
		return Party{}, Party{}, err
	}
	retired.Name = RetiredName(old.Name, old.Fingerprint)
	next = Party{Identity: id, Fingerprint: fp, Name: old.Name, Roles: slices.Clone(old.Roles), State: StateActive,
		EnrolledAt: now.UTC().Truncate(time.Second), Relay: a.Relay.Clone()}
	if a.CarryScope {
		next.Scope = old.Scope
	}
	return retired, next, nil
}

// RotationAnnouncement is the body of a Rotation message: one statement.
// Authorised by SPO-Xparty-INV-010 for any active enrolled party; what it
// causes is only a pending record (SPO-Xparty-INV-031).
type RotationAnnouncement struct {
	Statement []byte
}

func (RotationAnnouncement) Type() Type { return TypeRotation }

func (m RotationAnnouncement) Validate() error {
	if len(m.Statement) == 0 || len(m.Statement) > MaxRotationBytes {
		return bad("rotation statement size %d", len(m.Statement))
	}
	return nil
}
