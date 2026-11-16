package chain

import (
	"errors"
	"time"

	"golang.org/x/crypto/blake2b"
)

// PoolIDOf derives the pool id: the blake2b-224 hash of the cold
// verification key's raw 32 bytes.
func PoolIDOf(coldVKey []byte) (PoolID, error) {
	var id PoolID
	if len(coldVKey) != 32 {
		return id, errors.New("chain: a cold verification key is 32 bytes")
	}
	h, err := blake2b.New(len(id), nil)
	if err != nil {
		return id, err
	}
	h.Write(coldVKey)
	copy(id[:], h.Sum(nil))
	return id, nil
}

// ByronEra holds what the offline slot computation needs about a network's
// Byron era (spec/upstream/common/Cchain.md, SPO-Cchain-INV-004).
type ByronEra struct {
	Start           time.Time     // Byron genesis start time
	SlotDuration    time.Duration // Byron slot duration
	K               uint64        // security parameter; a Byron epoch has 10*K slots
	ToShelleyEpochs uint64        // Byron epochs before the hard fork
}
