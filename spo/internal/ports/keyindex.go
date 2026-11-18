package ports

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
)

// This file holds what a key identity needs of the store (ADR 0010): the kinds
// of each role's key records, the identity constructor of each role, and
// KeyIndex, the index from an identity to the records that hold the key. The
// implementation lives in ports/labels: it finds the owner whose manifest lists
// the identity and answers with the owner's anchor.

// KeyKinds are the store kinds of one role's key records.
type KeyKinds struct{ VKey, SKey, Hws Kind }

var roleKinds = map[custody.Role]KeyKinds{
	custody.RolePayment:       {AddrVKey, AddrSKey, AddrHwsFile},
	custody.RoleStake:         {StakingVKey, StakingSKey, StakingHwsFile},
	custody.RolePoolCold:      {NodeVKey, NodeSKey, NodeHwsFile},
	custody.RoleVRF:           {VrfVKey, VrfSKey, ""},
	custody.RoleDRep:          {DRepVKey, DRepSKey, DRepHwsFile},
	custody.RoleCommitteeCold: {CCColdVKey, CCColdSKey, CCColdHwsFile},
	custody.RoleCommitteeHot:  {CCHotVKey, CCHotSKey, CCHotHwsFile},
	custody.RolePolicy:        {PolicyVKey, PolicySKey, PolicyHwsFile},
	custody.RoleCalidus:       {CalidusVKey, CalidusSKey, CalidusHwsFile},
	custody.RoleCatalystVote:  {VotingVKey, VotingSKey, VotingHwsFile},
}

// KeyKindsOf returns the store kinds of a role's key records.
func KeyKindsOf(role custody.Role) (KeyKinds, bool) { k, ok := roleKinds[role]; return k, ok }

// ErrNoVerificationKey means a name has no verification key for a role, so no
// identity can be derived for it.
var ErrNoVerificationKey = errors.New("no verification key is stored for it")

// IdentityOfVKey applies the identity constructor of the role to a stored
// verification key envelope (cardano-cli text envelope, 32-byte key).
func IdentityOfVKey(role custody.Role, envelope []byte) (identity.Ref, error) {
	env, err := pool.ParseEnvelope(envelope)
	if err != nil {
		return identity.Ref{}, err
	}
	vk, err := identity.PublicKeyOfCborHex(env.CborHex)
	if err != nil {
		return identity.Ref{}, fmt.Errorf("%s: %w", env.Type, err)
	}
	switch role {
	case custody.RoleVRF:
		return identity.VRFKeyHashOf(vk)
	case custody.RoleKES:
		return identity.KESKeyHashOf(vk)
	case custody.RoleCalidus:
		return identity.CalidusKeyHashOf(vk)
	case custody.RoleCatalystVote:
		return identity.CatalystKeyHashOf(vk)
	}
	return identity.KeyHashOf(vk)
}

// KeyHome is where the store holds the records of one key: the anchor of the
// owner and the number of the key. It says nothing about who answers for the
// key.
type KeyHome struct {
	Role     custody.Role
	Identity identity.Ref
	// Anchor is the anchor identity of the owner whose manifest lists the key.
	Anchor identity.Ref
	// Num is the number of a numbered key (a KES key).
	Num int
	// HasSecret reports a signing key in the vault; HasHardware a hardware
	// signing file (a verification key exported from a device).
	HasSecret, HasHardware bool
	// WrongHardwareFile is set when the stored hardware signing file holds the
	// public key of another key than this identity (another account): the home is
	// not a hardware home, and a demand for the key is refused at planning, before
	// the device is touched.
	WrongHardwareFile bool
}

// ErrWrongHardwareFile means the hardware signing file stored for a key holds
// another account's public key.
var ErrWrongHardwareFile = errors.New("the hardware key is not the key demanded: the stored hardware signing file holds another account's key")

// hwsPubKey returns the 32-byte public key of a hardware signing file (the
// first 32 bytes of `cborXPubKeyHex` after its 2-byte CBOR header).
func hwsPubKey(file []byte) ([]byte, bool) {
	var j struct {
		X string `json:"cborXPubKeyHex"`
	}
	if json.Unmarshal(file, &j) != nil {
		return nil, false
	}
	raw, err := hex.DecodeString(j.X)
	if err != nil || len(raw) < 2+32 || raw[0] != 0x58 {
		return nil, false
	}
	return raw[2 : 2+32], true
}

// HwsPubKey returns the 32-byte public key of a hardware signing file.
func HwsPubKey(file []byte) ([]byte, bool) { return hwsPubKey(file) }

// SecretRef is the store reference of the home's signing key.
func (h KeyHome) SecretRef() Ref {
	k, _ := KeyKindsOf(h.Role)
	return Ref{Anchor: h.Anchor, Kind: k.SKey, Num: h.Num}
}

// HardwareRef is the store reference of the home's hardware signing file.
func (h KeyHome) HardwareRef() Ref {
	k, _ := KeyKindsOf(h.Role)
	return Ref{Anchor: h.Anchor, Kind: k.Hws, Num: h.Num}
}

// VKeyRef is the store reference of the home's verification key.
func (h KeyHome) VKeyRef() Ref {
	k, _ := KeyKindsOf(h.Role)
	return Ref{Anchor: h.Anchor, Kind: k.VKey, Num: h.Num}
}

// KeyIndex finds the stored records of a key identity and its role history.
type KeyIndex interface {
	// Homes lists every stored record set whose verification key has the
	// identity: the owner that lists it, in its role there. An identity belongs to
	// one owner, so at most one home is returned.
	Homes(ctx context.Context, id identity.Ref) ([]KeyHome, error)
	// RoleHistory returns the stored role history of a key identity (ADR 0010
	// decision 1); false when none is stored.
	RoleHistory(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error)
}

// HomeFor returns the home of the identity under a role.
func HomeFor(homes []KeyHome, role custody.Role) (KeyHome, bool) {
	for _, h := range homes {
		if h.Role == role {
			return h, true
		}
	}
	return KeyHome{}, false
}

// SecretHome returns a home of the role whose signing key is in the vault.
func SecretHome(homes []KeyHome, role custody.Role) (KeyHome, bool) {
	for _, h := range homes {
		if h.Role == role && h.HasSecret {
			return h, true
		}
	}
	return KeyHome{}, false
}

// HardwareHome returns a home of the role with a hardware signing file.
func HardwareHome(homes []KeyHome, role custody.Role) (KeyHome, bool) {
	for _, h := range homes {
		if h.Role == role && h.HasHardware {
			return h, true
		}
	}
	return KeyHome{}, false
}

// RoleHistoryOf is the role history of an identity: the stored record of kind
// role-history, written whenever a key is created, imported or used in a role. The
// history is empty (and ok false, the error nil) for an identity the workspace
// has no record of. A record that cannot be read is an error, never an empty
// history: a caller that applies the cold-key rule refuses.
func RoleHistoryOf(ctx context.Context, idx KeyIndex, id identity.Ref) (custody.RoleHistory, bool, error) {
	return idx.RoleHistory(ctx, id)
}

// ErrUnreadableRecords means a record needed to know the roles of an identity
// cannot be read, so they are not certain.
var ErrUnreadableRecords = errors.New("a record that holds the roles recorded for a key cannot be read, so the roles recorded for a key are not certain")

// memoIndex remembers the homes of each identity for the length of one plan, so
// the records of the store are read once per identity, not once per lookup.
type memoIndex struct {
	inner KeyIndex
	m     map[identity.Ref][]KeyHome
}

func (x *memoIndex) Homes(ctx context.Context, id identity.Ref) ([]KeyHome, error) {
	if h, ok := x.m[id]; ok {
		return h, nil
	}
	h, err := x.inner.Homes(ctx, id)
	if err != nil {
		return nil, err
	}
	x.m[id] = h
	return h, nil
}

// RoleHistory passes through (not memoised: it is only asked by the cold rule).
func (x *memoIndex) RoleHistory(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	return x.inner.RoleHistory(ctx, id)
}

// MemoIndex wraps an index for one plan.
func MemoIndex(idx KeyIndex) KeyIndex {
	return &memoIndex{inner: idx, m: map[identity.Ref][]KeyHome{}}
}

// PlanScoped is implemented by a directory that can answer one plan from
// remembered index lookups.
type PlanScoped interface {
	ForPlan() SignerDirectory
}

// ForPlan returns the directory to plan with: the directory itself, or its
// plan-scoped form when it has one.
func ForPlan(d SignerDirectory) SignerDirectory {
	if p, ok := d.(PlanScoped); ok {
		return p.ForPlan()
	}
	return d
}

// OperationDirectory is a directory whose preference depends on the operation:
// upstream's hardware file wins for a signature (SPO-Pfiles-INV-002,
// SPO-15-INV-002) and the software key for an operational certificate
// (SPO-04d-INV-004).
type OperationDirectory interface {
	SignerForOperation(key custody.KeyRef, op custody.Operation) (Signer, error)
}

// SignerForOperation asks the directory for the signer of an operation, or for
// its preferred signer when the directory has no per-operation preference.
func SignerForOperation(d SignerDirectory, key custody.KeyRef, op custody.Operation) (Signer, error) {
	if od, ok := d.(OperationDirectory); ok {
		return od.SignerForOperation(key, op)
	}
	return d.SignerFor(key)
}

// ---- the signer directory ----------------------------------------------------------------

// SignerKind is where a connected signer sits. It is information for the
// planner's preference and for the cold-key rule; a use case never reads it.
type SignerKind string

const (
	SignerLocal    SignerKind = "local vault"
	SignerDevice   SignerKind = "hardware device"
	SignerCoSigner SignerKind = "co-signer party"
)

// ConnectedSigner is one entry of the SignerDirectory for a key: a signer
// connected now that reports holding it.
type ConnectedSigner struct {
	Kind   SignerKind
	Signer Signer
	// Network is true when a demand to this signer travels over a network
	// transport (a carried file is not one).
	Network bool
	// Party is the ADR 0005 fingerprint a co-signer is routed by; empty for a
	// local signer.
	Party []byte
	// Deferred is true when the answer comes later, through an envelope: the
	// demand is sent and answered in another run. A deferred signer is no
	// TxWitnesser for the plan; use cases deferring a slot read this flag and
	// nothing else about where the signer sits.
	Deferred bool
}

// ErrNoSignerFor means no connected signer holds the key.
var ErrNoSignerFor = errors.New("no connected signer holds the key")

// ErrColdOverNetwork means the only connected signers for a key that was
// ever recorded in a cold role sit behind a network transport (ADR 0010
// decision 3; ADR 0005): the demand is not sent, whatever role it names.
var ErrColdOverNetwork = errors.New("a key that was ever a cold key is never asked for over a network transport (carry a file instead)")

func (c ConnectedSigner) String() string {
	return fmt.Sprintf("%s %q", c.Kind, c.Signer.Profile().Name())
}

// ConnectedVia derives Connected from a directory's SignerFor, for a directory
// that has one signer per key (a test double, a wiring with one signer): the
// signer SignerFor returns is the one connected signer; an error is none.
func ConnectedVia(d interface {
	SignerFor(custody.KeyRef) (Signer, error)
}, key custody.KeyRef) ([]ConnectedSigner, error) {
	s, err := d.SignerFor(key)
	if err != nil {
		return nil, nil
	}
	return []ConnectedSigner{{Kind: SignerLocal, Signer: s}}, nil
}

// SignerFunc is a SignerDirectory made of one function.
type SignerFunc func(key custody.KeyRef) (Signer, error)

// SignerFor implements SignerDirectory.
func (f SignerFunc) SignerFor(key custody.KeyRef) (Signer, error) { return f(key) }

// Connected implements SignerDirectory.
func (f SignerFunc) Connected(key custody.KeyRef) ([]ConnectedSigner, error) {
	return ConnectedVia(f, key)
}

var _ SignerDirectory = SignerFunc(nil)
