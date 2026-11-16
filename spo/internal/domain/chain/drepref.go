package chain

import "strings"

// CanonicalDRepText gives one spelling to a DRep reference as a provider
// states it, so that two providers can be compared. A bech32 DRep id is
// returned in the CIP-129 form (29 bytes: a header 0x22 for a key hash, 0x23
// for a script hash, then the 28-byte credential), whether the provider wrote
// that form or the legacy one (28 bytes under "drep", or "drep_script"). A
// predefined choice (drep_always_abstain, drep_always_no_confidence) and any
// text that is not a DRep id are returned unchanged.
func CanonicalDRepText(s string) string {
	if !strings.HasPrefix(s, "drep") {
		return s
	}
	hrp, data, err := Bech32Decode(s)
	if err != nil {
		return s
	}
	switch {
	case hrp == "drep" && len(data) == 29 && (data[0] == 0x22 || data[0] == 0x23):
		return strings.ToLower(s)
	case hrp == "drep" && len(data) == 28:
		data = append([]byte{0x22}, data...)
	case hrp == "drep_script" && len(data) == 28:
		data = append([]byte{0x23}, data...)
	default:
		return s
	}
	out, err := Bech32Encode("drep", data)
	if err != nil {
		return s
	}
	return out
}

// DRepCIP129 is the CIP-129 bech32 form of a DRep id.
func DRepCIP129(id DRepID) string {
	header := byte(0x22)
	if id.Script {
		header = 0x23
	}
	s, _ := Bech32Encode("drep", append([]byte{header}, id.Hash[:]...))
	return s
}
