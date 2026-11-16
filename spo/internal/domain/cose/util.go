package cose

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// VKeyFromEnvelope reads the 32-byte Ed25519 public key out of a verification
// key text envelope (cborHex "5820" + key). It does not look at the type, so
// payment, stake, pool, Calidus and voting keys all read the same way.
func VKeyFromEnvelope(env []byte) ([32]byte, error) {
	var out [32]byte
	var e struct {
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(env, &e); err != nil {
		return out, errors.New("the verification key is not a text envelope")
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil || len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
		return out, errors.New("the verification key is not a 32-byte Ed25519 key")
	}
	copy(out[:], raw[2:])
	return out, nil
}

// mainnetShelleyStart is the Unix time of mainnet slot 4492800, the first
// Shelley slot (2020-07-29 21:44:51 UTC).
const (
	mainnetShelleyStartUnix = 1596059091
	mainnetShelleyStartSlot = 4492800
)

// MainnetSlotAt is the mainnet slot at a wall-clock time. It is the nonce
// cardano-signer chooses for a CIP-36 or CIP-88 signature when none is given
// ("mainnet slot height calculated from the current machine time"; observed:
// the value for 1794832332 was 203266041), whatever the network.
func MainnetSlotAt(t time.Time) uint64 {
	d := t.Unix() - mainnetShelleyStartUnix
	if d < 0 {
		return mainnetShelleyStartSlot
	}
	return mainnetShelleyStartSlot + uint64(d)
}
