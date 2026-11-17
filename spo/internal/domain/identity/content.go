package identity

import (
	"fmt"
	"sort"
)

// Tag is the fixed label of one kind of spo-defined object. It is the first
// element of the hashed array [tag, value] (ADR 0010, decision 1), so equal
// bytes of two kinds have two identities, and no concatenation of tag and
// bytes is ever hashed (one tag may be a prefix of another).
//
// Each tag is bound one-to-one to a Kind (the registry below): ContentOf
// derives the kind of the reference from the tag, and a reference of that
// kind names the table that holds the object.
type Tag string

// The registry. A tag is added here and nowhere else; ContentOf refuses an
// unregistered tag. Changing a tag changes every identity of its kind, so a
// tag is never edited, only added.
const (
	// TagPoolDescriptor is the tag of a pool descriptor. The descriptor is
	// mapped from JSON, so its only valid tag carries the mapping version
	// (map1): the bare tag "spo/obj/v1/pool-descriptor" is not registered, so
	// one descriptor cannot get two identities.
	TagPoolDescriptor   Tag = "spo/obj/v1/pool-descriptor/map1"
	TagWitnessColl      Tag = "spo/obj/v1/witness-collection"
	TagPendingRecord    Tag = "spo/obj/v1/pending-record"
	TagPartyIdentityDoc Tag = "spo/obj/v1/party-identity-document"
	TagAuditEvent       Tag = "spo/obj/v1/audit-event"
	TagOwnerManifest    Tag = "spo/obj/v1/owner-manifest"
	TagRoleHistory      Tag = "spo/obj/v1/role-history"
	TagOwnerRecord      Tag = "spo/obj/v1/owner-record"
	// TagLabel anchors a label record (LabelAnchor).
	TagLabel Tag = "spo/obj/v1/label"
	// Tags of kinds that have no owner; their fixed anchor is OwnerlessAnchor.
	TagWorkspaceSettings Tag = "spo/obj/v1/workspace-settings"
	TagProviderToken     Tag = "spo/obj/v1/provider-token"
)

var tags = map[Tag]Kind{
	TagPoolDescriptor:    KindPoolDescriptor,
	TagWitnessColl:       KindWitnessCollection,
	TagPendingRecord:     KindPendingRecord,
	TagPartyIdentityDoc:  KindPartyIdentityDoc,
	TagAuditEvent:        KindAuditEvent,
	TagOwnerManifest:     KindOwnerManifest,
	TagRoleHistory:       KindRoleHistory,
	TagOwnerRecord:       KindOwnerRecord,
	TagLabel:             KindLabel,
	TagWorkspaceSettings: KindWorkspaceSettings,
	TagProviderToken:     KindProviderToken,
}

// Tags lists the registered tags, sorted.
func Tags() []Tag {
	out := make([]Tag, 0, len(tags))
	for t := range tags {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Kind returns the kind bound to the tag, and false for an unregistered tag.
func (t Tag) Kind() (Kind, bool) { k, ok := tags[t]; return k, ok }

// TagOf returns the tag bound to a content kind, and false for a kind that is
// not a content kind.
func TagOf(k Kind) (Tag, bool) {
	for t, kk := range tags {
		if kk == k {
			return t, true
		}
	}
	return "", false
}

// ContentOf is the content hash of an object spo defines: Blake2b-256 over
// the canonical CBOR (RFC 8949 section 4.2) of the two-element array
// [tag, value], where value is the object's canonical value (the model of
// EncodeCanonical). The kind of the result is the kind bound to the tag. It
// is the only function that derives a content identity. A value at the
// maximum nesting depth of the decoder can still be hashed.
func ContentOf(tag Tag, value any) (Ref, error) {
	kind, ok := tags[tag]
	if !ok {
		return Ref{}, fmt.Errorf("identity: unregistered object tag %q", tag)
	}
	enc, err := encodeWrapped(string(tag), value)
	if err != nil {
		return Ref{}, err
	}
	return mustRef(kind, blake256(enc)), nil
}

// ContentOfEncoded is ContentOf for an object that is held as its canonical
// CBOR encoding: the bytes are decoded, refused unless they are canonical
// (ErrNotCanonical), and hashed as the value of [tag, value].
func ContentOfEncoded(tag Tag, canonical []byte) (Ref, error) {
	v, err := DecodeCanonical(canonical)
	if err != nil {
		return Ref{}, err
	}
	return ContentOf(tag, v)
}

// OwnerKind is a kind of owner (ADR 0010, decision 2).
type OwnerKind string

// The kinds of owner.
const (
	OwnerPool      OwnerKind = "pool"
	OwnerWallet    OwnerKind = "wallet"
	OwnerDRep      OwnerKind = "drep"
	OwnerCommittee OwnerKind = "committee"
	OwnerPolicy    OwnerKind = "policy"
)

// OwnerKinds lists every kind of owner.
func OwnerKinds() []OwnerKind {
	return []OwnerKind{OwnerPool, OwnerWallet, OwnerDRep, OwnerCommittee, OwnerPolicy}
}

// OwnerlessAnchor is the fixed anchor of a kind that has no owner (workspace
// settings, provider tokens): the content hash of [tag, ""].
func OwnerlessAnchor(tag Tag) (Ref, error) { return ContentOf(tag, "") }

// LabelAnchor is the anchor of a label record: the content hash of
// [TagLabel, [kind of owner, name]]. The name enters only this hash, which is
// itself sealed in the record; it never appears in associated data.
func LabelAnchor(owner OwnerKind, name string) (Ref, error) {
	known := false
	for _, k := range OwnerKinds() {
		known = known || k == owner
	}
	if !known {
		return Ref{}, fmt.Errorf("identity: unknown kind of owner %q", owner)
	}
	return ContentOf(TagLabel, []any{string(owner), name})
}

// PoolAnchor is the anchor of a pool: its cold key hash (the pool id).
func PoolAnchor(coldKey Ref) (Ref, error) { return only(coldKey, KindKeyHash) }

// DRepAnchor is the anchor of a DRep: its key hash.
func DRepAnchor(drepKey Ref) (Ref, error) { return only(drepKey, KindKeyHash) }

// CommitteeAnchor is the anchor of a committee member: its cold key hash.
func CommitteeAnchor(coldKey Ref) (Ref, error) { return only(coldKey, KindKeyHash) }

// PolicyAnchor is the anchor of a policy: its policy id (the script hash).
func PolicyAnchor(policyID Ref) (Ref, error) { return only(policyID, KindScriptHash) }

// WalletAnchor is the anchor of a wallet, chosen once at creation or first
// import and fixed afterwards: the payment key hash when the wallet has a
// payment key, otherwise its stake key hash. A zero Ref means "no such key".
// It is a pure function of the keys present at that moment; the caller never
// recomputes it for an owner that gained a key later.
func WalletAnchor(payment, stake Ref) (Ref, error) {
	switch {
	case !payment.IsZero():
		return only(payment, KindKeyHash)
	case !stake.IsZero():
		return only(stake, KindKeyHash)
	}
	return Ref{}, fmt.Errorf("identity: a wallet needs a payment or a stake key to have an anchor")
}

func only(r Ref, k Kind) (Ref, error) {
	if err := r.Require(k); err != nil {
		return Ref{}, err
	}
	return r, nil
}
