package party

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// Role is what an enrolled party may do (SPO-Xparty-IF-002).
type Role string

const (
	RoleCoordinator Role = "coordinator" // may send signing requests
	RoleSigner      Role = "signer"      // may be sent signing requests
	RoleMachine     Role = "machine"     // the operator's own other machine
)

// Valid reports whether r is one of the three roles.
func (r Role) Valid() bool {
	return r == RoleCoordinator || r == RoleSigner || r == RoleMachine
}

// State of an enrolled party (SPO-Xparty-OUT-001).
type State string

const (
	StateActive  State = "active"
	StateRevoked State = "revoked"
)

// Party is an enrolled party record, Sensitive (SPO-Xparty-OUT-001).
type Party struct {
	Identity    Identity
	Fingerprint Fingerprint
	Name        string // the operator's local name for it
	Roles       []Role
	// Scope is what this party, as a coordinator, may ask of us
	// (SPO-Xparty-INV-010). It is never what we may ask of it. The zero Scope
	// allows nothing.
	Scope      Scope
	State      State
	EnrolledAt time.Time
	// Relay is the party's relay identity (SPO-Xparty-OUT-007, ADR 0014
	// decision 2), nil when it has none: it is then reachable by file or a direct
	// connection only. It is the address of a put at a relay and grants nothing.
	Relay *RelayIdentity
}

// WalletKeySize is the size of a wallet key hash (Blake2b-224).
const WalletKeySize = 28

// WalletKey is the key hash K of the payment or stake key a party's device is
// bound to at relays (ADR 0014 decision 2).
type WalletKey [WalletKeySize]byte

// RelayIdentity is a party's relay identity: the wallet key, the device it is
// bound to (the party's own fingerprint, so one party has one wallet key) and
// the binding it came from, kept as evidence exactly as given. The caller
// verified the binding (domain/relaypeer); this package only holds it.
type RelayIdentity struct {
	WalletKey WalletKey
	Device    Fingerprint
	// From and Until are the binding's window, unix seconds.
	From, Until int64
	// Statement and Key are the COSE_Sign1 and the COSE_Key of the binding.
	Statement, Key []byte
	// Unverified is why the stored evidence no longer verifies under the current
	// policy (empty when it does). It is set by the registry at load, never
	// stored: such a relay identity is kept, bytes and all, until the operator
	// replaces or clears it, and it is no route (SPO-Xparty-OUT-007).
	Unverified string
}

// ErrRelayIdentity: a relay identity that cannot belong to the party.
var ErrRelayIdentity = errors.New("party: the relay identity is not this party's")

// CheckRelay reports whether r can be the relay identity of the identity with
// fingerprint fp: the device it names is fp, the window is ordered and the
// evidence is present (SPO-Xparty-OUT-007). nil is no relay identity and passes.
func CheckRelay(r *RelayIdentity, fp Fingerprint) error {
	switch {
	case r == nil:
		return nil
	case r.Device != fp:
		return fmt.Errorf("%w: it names another device", ErrRelayIdentity)
	case r.WalletKey == WalletKey{}:
		return fmt.Errorf("%w: no wallet key", ErrRelayIdentity)
	case r.From < 0 || r.Until <= r.From:
		return fmt.Errorf("%w: its window is not ordered", ErrRelayIdentity)
	case len(r.Statement) == 0 || len(r.Key) == 0:
		return fmt.Errorf("%w: no evidence", ErrRelayIdentity)
	}
	return nil
}

// Clone is a deep copy (nil stays nil).
func (r *RelayIdentity) Clone() *RelayIdentity {
	if r == nil {
		return nil
	}
	c := *r
	c.Statement = slices.Clone(r.Statement)
	c.Key = slices.Clone(r.Key)
	return &c
}

// Active reports whether the party's envelopes may be accepted
// (SPO-Xparty-INV-005).
func (p Party) Active() bool { return p.State == StateActive }

// HasRole reports whether p was enrolled with r.
func (p Party) HasRole(r Role) bool { return slices.Contains(p.Roles, r) }

// Enrollment errors.
var (
	ErrInvalidEnrollment = errors.New("party: invalid enrollment")
	ErrConfirmation      = errors.New("party: the typed fingerprint groups do not match")
	ErrNameTaken         = errors.New("party: that local name is already in use")
	ErrAlreadyEnrolled   = errors.New("party: that identity is already enrolled")
	ErrAlreadyRevoked    = errors.New("party: already revoked")
	// ErrNodeKeyInUse: another ACTIVE enrolled party already has that tailcat node
	// key (SPO-Xparty-INV-018). A node key names one machine's connection;
	// two parties sharing it could be taken for each other.
	ErrNodeKeyInUse = errors.New("party: another enrolled party already has that node key")
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	poolRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

// Enrollment is the operator's request to enrol a party.
type Enrollment struct {
	Document Document
	Name     string // local name, chosen by the operator
	Roles    []Role
	// Scope is required for a coordinator: the operator names the key roles
	// and the pools (or Unscoped) it may ask for; there is no default. It is
	// kept for a signer too but never read: what we ask of a signer is not
	// limited by it.
	Scope        Scope
	Confirmation string // the first four fingerprint groups, as typed (PR-001)
	// Relay is the party's relay identity from the binding it gave, already
	// verified by the caller (domain/relaypeer); nil for none. It must name the
	// document's fingerprint (SPO-Xparty-PRE-008). It never replaces the typed
	// check (SPO-Xparty-PR-007).
	Relay *RelayIdentity
}

// Enroll builds the party record for an enrollment, or refuses. The checks
// run in this order: the document signature (SPO-Xparty-PRE-001), the
// operator's fields, the typed fingerprint groups (PR-001), then uniqueness
// against existing. The confirmation is a required input: there is no value
// that skips it, and an empty one never matches.
func Enroll(e Enrollment, existing []Party, now time.Time) (Party, error) {
	if err := e.Document.Verify(); err != nil {
		return Party{}, err
	}
	id := e.Document.Identity
	if err := id.Validate(); err != nil {
		return Party{}, err
	}
	if !nameRE.MatchString(e.Name) {
		return Party{}, fmt.Errorf("%w: local name must be 1-64 letters, digits, '-' or '_'", ErrInvalidEnrollment)
	}
	if len(e.Roles) == 0 {
		return Party{}, fmt.Errorf("%w: at least one role", ErrInvalidEnrollment)
	}
	roles := slices.Clone(e.Roles)
	slices.Sort(roles)
	for i, r := range roles {
		if !r.Valid() || (i > 0 && roles[i-1] == r) {
			return Party{}, fmt.Errorf("%w: role %q", ErrInvalidEnrollment, r)
		}
	}
	scope, err := e.Scope.normalised()
	if err != nil {
		return Party{}, err
	}
	if slices.Contains(roles, RoleCoordinator) && scope.Empty() {
		return Party{}, fmt.Errorf("%w: a coordinator needs a scope: key roles, and pools or unscoped", ErrInvalidEnrollment)
	}
	fp := id.Fingerprint()
	if !ConfirmPrefix(fp, e.Confirmation) {
		return Party{}, ErrConfirmation
	}
	if err := CheckRelay(e.Relay, fp); err != nil {
		return Party{}, err
	}
	for _, q := range existing {
		if q.Fingerprint == fp {
			return Party{}, ErrAlreadyEnrolled
		}
		if q.Name == e.Name {
			return Party{}, ErrNameTaken
		}
		if q.Active() && id.Node != nil && q.Identity.Node != nil && *id.Node == *q.Identity.Node {
			return Party{}, fmt.Errorf("%w: %s", ErrNodeKeyInUse, q.Name)
		}
	}
	return Party{Identity: id, Fingerprint: fp, Name: e.Name, Roles: roles, Scope: scope,
		State: StateActive, EnrolledAt: now.UTC().Truncate(time.Second), Relay: e.Relay.Clone()}, nil
}

// Revoke returns p revoked (SPO-Xparty-IF-003). From the moment the revoked
// record is stored, every envelope of p is refused, including those created
// before (SPO-Xparty-INV-005): the receiver looks the sender up at open time.
func Revoke(p Party) (Party, error) {
	if p.State == StateRevoked {
		return p, ErrAlreadyRevoked
	}
	p.State = StateRevoked
	return p, nil
}

// ErrNotAuthorised is SPO-Xparty-INV-010: the sender's role does not permit
// the message.
var ErrNotAuthorised = errors.New("party: sender is not authorised for this message")

// Concern is what a message is about, as the receiver knows it from its own
// state, never from the sender's claim.
type Concern struct {
	// SlotSigner is the signer assigned to the slot a SigningResponse or
	// SigningRefusal answers; HasSlotSigner is false when no such slot is
	// known.
	SlotSigner    Fingerprint
	HasSlotSigner bool
}

// Authorise decides whether sender may send a message of type t
// (SPO-Xparty-INV-010), by role:
//
//   - SigningRequest, CollectionClosed and Invite need the coordinator role.
//     What a SigningRequest may ask is the sender's Scope, decided by
//     CheckScope once the body is decoded (and again at approval).
//   - SigningResponse and SigningRefusal need the signer role and that the
//     sender is the signer assigned to the slot.
//   - Hello needs the signer role (SPO-Xparty-INV-021).
//   - Bundle needs the machine role.
//   - Rotation needs only that the sender is active (SPO-Xparty-INV-031).
//
// An inactive sender is never authorised.
func Authorise(sender Party, t Type, c Concern) error {
	if !sender.Active() {
		return fmt.Errorf("%w: sender is not active", ErrNotAuthorised)
	}
	switch t {
	case TypeSigningRequest, TypeCollectionClosed, TypeInvite:
		if !sender.HasRole(RoleCoordinator) {
			return fmt.Errorf("%w: not a coordinator", ErrNotAuthorised)
		}
	case TypeSigningResponse, TypeSigningRefusal:
		if !sender.HasRole(RoleSigner) {
			return fmt.Errorf("%w: not a signer", ErrNotAuthorised)
		}
		if !c.HasSlotSigner || c.SlotSigner != sender.Fingerprint {
			return fmt.Errorf("%w: not the signer of that slot", ErrNotAuthorised)
		}
	case TypeHello:
		if !sender.HasRole(RoleSigner) {
			return fmt.Errorf("%w: not a signer", ErrNotAuthorised)
		}
	case TypeRotation:
		// Any enrolled, active party may announce that it changed its own
		// identity; what the announcement causes is only a pending record
		// (SPO-Xparty-INV-031), never a registry change.
	case TypeBundle:
		if !sender.HasRole(RoleMachine) {
			return fmt.Errorf("%w: not a machine party", ErrNotAuthorised)
		}
	default:
		return fmt.Errorf("%w: unknown message type", ErrNotAuthorised)
	}
	return nil
}

// AllowedNodeKeys is the allow-list of the tailcat server (SPO-Xparty-IF-005):
// the node keys of the active parties that are a signer or a machine and have
// one, and no other. A revoked party, a coordinator-only party and a party
// without a node key are not in it.
func AllowedNodeKeys(ps []Party) []NodeKey {
	var out []NodeKey
	for _, p := range ps {
		if p.Active() && p.Identity.Node != nil && (p.HasRole(RoleSigner) || p.HasRole(RoleMachine)) && !slices.Contains(out, *p.Identity.Node) {
			out = append(out, *p.Identity.Node)
		}
	}
	return out
}

// AllowedOwners is AllowedNodeKeys with the fingerprint of the active party that
// holds each key, so a server that follows the registry sees a key change hands
// (one party revoked and another enrolled with the same node key).
func AllowedOwners(ps []Party) map[NodeKey]Fingerprint {
	out := map[NodeKey]Fingerprint{}
	for _, p := range ps {
		if p.Active() && p.Identity.Node != nil && (p.HasRole(RoleSigner) || p.HasRole(RoleMachine)) {
			out[*p.Identity.Node] = p.Fingerprint
		}
	}
	return out
}
