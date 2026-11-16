package chain

import "golang.org/x/crypto/blake2b"

// AssetFingerprint is the CIP-14 fingerprint of an asset: bech32 with the
// human-readable part `asset` of the 20-byte blake2b hash of the policy id
// followed by the asset name (SPO-Cconv-OUT-013).
func AssetFingerprint(a AssetID) string {
	h, _ := blake2b.New(20, nil)
	h.Write(a.Policy[:])
	h.Write(a.Name)
	s, _ := Bech32Encode("asset", h.Sum(nil))
	return s
}
