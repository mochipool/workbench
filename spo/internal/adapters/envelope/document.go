package envelope

import (
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// identityWire is the CBOR of SPO-Xparty-INV-003:
// [version, label, ed25519 public key, x25519 public key, node key or null, created].
type identityWire struct {
	_       struct{} `cbor:",toarray"`
	Version uint
	Label   string
	Ed25519 []byte
	X25519  []byte
	Node    *[]byte // nil encodes as null
	Created int64   // unix seconds
}

// documentWire is the file: [content, signature], content being the canonical
// CBOR of identityWire as a byte string, signature Ed25519 over
// "spo/identity/v1" || content.
type documentWire struct {
	_         struct{} `cbor:",toarray"`
	Content   []byte
	Signature []byte
}

// EncodeDocument returns the signed public identity document (SPO-Xparty-IF-001).
func EncodeDocument(p *Private) ([]byte, error) {
	id := p.id
	w := identityWire{Version: Version, Label: id.Label, Ed25519: id.Ed25519[:], X25519: id.X25519[:],
		Created: id.Created.Unix()}
	if id.Node != nil {
		n := id.Node[:]
		w.Node = &n
	}
	content, err := marshal(w)
	if err != nil {
		return nil, err
	}
	sig, err := p.sign(party.DocumentMessage(content))
	if err != nil {
		return nil, err
	}
	return marshal(documentWire{Content: content, Signature: sig[:]})
}

// ParseDocument decodes a document strictly. It does not verify the
// signature: Enroll does (party.Document.Verify, SPO-Xparty-PRE-001). Content
// is the decoding's source, so Identity always is what Content says.
func ParseDocument(b []byte) (party.Document, error) {
	var d documentWire
	if err := unmarshal(b, &d); err != nil {
		return party.Document{}, err
	}
	var w identityWire
	if err := unmarshal(d.Content, &w); err != nil {
		return party.Document{}, err
	}
	if w.Version != Version {
		return party.Document{}, fmt.Errorf("%w: document version %d", ErrVersion, w.Version)
	}
	var doc party.Document
	if err := fixed(doc.Signature[:], d.Signature); err != nil {
		return party.Document{}, err
	}
	id := party.Identity{Label: w.Label, Created: time.Unix(w.Created, 0).UTC()}
	if err := fixed(id.Ed25519[:], w.Ed25519); err != nil {
		return party.Document{}, err
	}
	if err := fixed(id.X25519[:], w.X25519); err != nil {
		return party.Document{}, err
	}
	if w.Node != nil {
		id.Node = new(party.NodeKey)
		if err := fixed(id.Node[:], *w.Node); err != nil {
			return party.Document{}, err
		}
	}
	if err := id.Validate(); err != nil {
		return party.Document{}, err
	}
	doc.Identity, doc.Content = id, d.Content
	return doc, nil
}

// witnessWire is a Cardano vkey witness: [vkey, signature].
type witnessWire struct {
	_   struct{} `cbor:",toarray"`
	Key []byte
	Sig []byte
}

// DecodeWitness decodes the witness CBOR of a SigningResponse for
// party.VerifyWitness.
func DecodeWitness(b []byte) (vkey [32]byte, sig [64]byte, err error) {
	var w witnessWire
	if err = unmarshal(b, &w); err != nil {
		return
	}
	if err = fixed(vkey[:], w.Key); err != nil {
		return
	}
	err = fixed(sig[:], w.Sig)
	return
}

// EncodeWitness encodes a vkey witness.
func EncodeWitness(vkey [32]byte, sig [64]byte) ([]byte, error) {
	return marshal(witnessWire{Key: vkey[:], Sig: sig[:]})
}
