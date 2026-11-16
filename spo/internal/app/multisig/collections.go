package multisig

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// CollectionRef says where a collection is kept: in the descriptor of a pool
// (the registration RegisterPool opened), or as a collection of its own for
// any other transaction.
type CollectionRef struct {
	Kind string `json:"kind"` // KindPool or KindStandalone
	Name string `json:"name"` // the pool's name, or the collection's
}

// The two places a collection lives.
const (
	KindPool       = "pool"
	KindStandalone = "standalone"
)

// ErrNoCollection: nothing is stored under the reference.
var ErrNoCollection = errors.New("there is no witness collection there")

// loaded is a collection with what is needed to write it back.
type loaded struct {
	ref  CollectionRef
	coll pool.Collection
	desc *pool.Descriptor
}

func (n Node) collectionRef(ref CollectionRef) (ports.Ref, error) {
	switch ref.Kind {
	case KindPool:
		return ports.Ref{Name: ref.Name, Kind: ports.PoolDescriptor}, nil
	case KindStandalone:
		return ports.Ref{Name: ref.Name, Kind: ports.MultisigCollection}, nil
	}
	return ports.Ref{}, fmt.Errorf("collection kind %q", ref.Kind)
}

// loadCollection reads the collection under ref. The body hash is recomputed
// from the stored body, not trusted (the descriptor parser does it).
func (n Node) loadCollection(r ports.Reader, txids ports.TxIDCalculator, ref CollectionRef) (loaded, error) {
	sref, err := n.collectionRef(ref)
	if err != nil {
		return loaded{}, err
	}
	raw, err := r.Get(sref)
	if errors.Is(err, ports.ErrNotFound) {
		return loaded{}, ErrNoCollection
	}
	if err != nil {
		return loaded{}, err
	}
	d, err := pool.ParseDescriptor(raw)
	if err != nil {
		return loaded{}, err
	}
	c, err := d.Collection(txids.TransactionID)
	if err != nil {
		return loaded{}, err
	}
	if c == nil {
		return loaded{}, ErrNoCollection
	}
	return loaded{ref: ref, coll: *c, desc: d}, nil
}

// saveCollection writes the collection back where it came from.
func (n Node) saveCollection(w ports.Writer, l loaded) error {
	sref, err := n.collectionRef(l.ref)
	if err != nil {
		return err
	}
	l.desc.SetCollection(l.coll)
	return w.Put(sref, l.desc.Render())
}

// newStandalone makes the document a standalone collection is kept in: the
// descriptor's `regWitness`, alone.
func newStandalone() (*pool.Descriptor, error) { return pool.ParseDescriptor([]byte("{}")) }

// collectionID is the 16-byte id a collection carries on the wire. It is
// derived from where the collection lives, its own id and its body hash, so
// a registration that is discarded and made again has another id, and no
// response to the old one can be taken for the new one.
func collectionID(ref CollectionRef, c pool.Collection) party.CollectionID {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("spo/collection/v1\x00" + ref.Kind + "\x00" + ref.Name + "\x00"))
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], c.ID)
	h.Write(u[:])
	h.Write(c.Body.ID[:])
	var id party.CollectionID
	copy(id[:], h.Sum(nil))
	return id
}

// CollectionID is the wire id of the collection under ref, for callers that
// need to name it (a CLI listing requests, a test).
func CollectionID(ref CollectionRef, c pool.Collection) party.CollectionID {
	return collectionID(ref, c)
}
