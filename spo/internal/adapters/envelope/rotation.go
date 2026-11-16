package envelope

import (
	"context"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// rotationContentWire is the content both signatures of a rotation statement
// cover (SPO-Xparty-INV-030):
// [version, old fingerprint, new identity document, created, expires].
type rotationContentWire struct {
	_        struct{} `cbor:",toarray"`
	Version  uint
	Old      []byte
	Document []byte
	Created  int64
	Expires  int64
}

// rotationWire is the statement: [content, old signature, new signature].
type rotationWire struct {
	_       struct{} `cbor:",toarray"`
	Content []byte
	OldSig  []byte
	NewSig  []byte
}

type rotationAnnouncementWire struct {
	_         struct{} `cbor:",toarray"`
	Statement []byte
}

// AnnouncementLifetime is how long a sealed announcement is valid.
const AnnouncementLifetime = 7 * 24 * time.Hour

// NewRotation builds the statement that replaces old by next, signed by both
// (SPO-Xparty-INV-030). Each key signs under its own domain string.
func NewRotation(old, next *Private, now time.Time) ([]byte, error) {
	doc, err := EncodeDocument(next)
	if err != nil {
		return nil, err
	}
	created := now.UTC().Truncate(time.Second)
	oldFP := old.Fingerprint()
	content, err := marshal(rotationContentWire{Version: Version, Old: oldFP[:], Document: doc, Created: created.Unix(),
		Expires: created.Add(party.MaxRotationLifetime).Unix()})
	if err != nil {
		return nil, err
	}
	oldSig, err := old.sign(party.RotationOldMessage(content))
	if err != nil {
		return nil, err
	}
	newSig, err := next.sign(party.RotationNewMessage(content))
	if err != nil {
		return nil, err
	}
	return marshal(rotationWire{Content: content, OldSig: oldSig[:], NewSig: newSig[:]})
}

// ParseRotation decodes a statement strictly. It does not verify the
// signatures: party.Rotation.Verify does, against the key the replaced
// identity is enrolled with. Content is the decoding's source.
func ParseRotation(b []byte) (party.Rotation, error) {
	var w rotationWire
	if err := unmarshal(b, &w); err != nil {
		return party.Rotation{}, err
	}
	var c rotationContentWire
	if err := unmarshal(w.Content, &c); err != nil {
		return party.Rotation{}, err
	}
	if c.Version != Version {
		return party.Rotation{}, fmt.Errorf("%w: rotation version %d", ErrVersion, c.Version)
	}
	var r party.Rotation
	if err := firstErr(fixed(r.OldSig[:], w.OldSig), fixed(r.NewSig[:], w.NewSig), fixed(r.Old[:], c.Old)); err != nil {
		return party.Rotation{}, err
	}
	doc, err := ParseDocument(c.Document)
	if err != nil {
		return party.Rotation{}, err
	}
	r.New, r.NewDocument, r.Content = doc, c.Document, w.Content
	r.Created, r.Expires = time.Unix(c.Created, 0).UTC(), time.Unix(c.Expires, 0).UTC()
	return r, nil
}

// ParseRotation implements ports.IdentityKit.
func (Kit) ParseRotation(b []byte) (party.Rotation, error) { return ParseRotation(b) }

// Rotate implements ports.IdentityKit: it loads the old identity, makes the
// new one (the same node key, a new signing and encryption key pair), signs
// the statement with both and seals one announcement to each peer with the OLD
// identity, because that is the identity the peers have enrolled. Nothing is
// stored here: the caller commits the new keys, the new document and the
// announcements in one transaction, and destroys the old keys with it.
func (k Kit) Rotate(ctx context.Context, req ports.RotateRequest) (ports.GeneratedRotation, error) {
	old, err := k.private(ctx)
	if err != nil {
		return ports.GeneratedRotation{}, err
	}
	defer old.Destroy()
	label := req.Label
	if label == "" {
		label = old.id.Label
	}
	next, err := Generate(label, old.id.Node, req.Now, k.rnd())
	if err != nil {
		return ports.GeneratedRotation{}, err
	}
	fail := func(err error) (ports.GeneratedRotation, error) {
		next.Destroy()
		return ports.GeneratedRotation{}, err
	}
	doc, err := EncodeDocument(next)
	if err != nil {
		return fail(err)
	}
	stmt, err := NewRotation(old, next, req.Now)
	if err != nil {
		return fail(err)
	}
	g := ports.GeneratedRotation{Keys: next.Keys(), Document: doc, Identity: next.Identity(), Old: old.Fingerprint(), Statement: stmt}
	exp := req.Now.Add(AnnouncementLifetime)
	for _, p := range req.Peers {
		env, id, err := Seal(old, p.Identity, party.RotationAnnouncement{Statement: stmt}, req.Now, exp, k.rnd())
		if err != nil {
			return fail(err)
		}
		g.Announcements = append(g.Announcements, ports.SealedAnnouncement{To: p.Fingerprint, ID: id, Envelope: env, Expires: exp})
	}
	return g, nil
}
