package pool

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func envJSON(typ, cborHex string) []byte {
	return []byte(`{"type":"` + typ + `","description":"d","cborHex":"` + cborHex + `"}`)
}

func opcertHex() string {
	return "8284" + "5820" + strings.Repeat("11", 32) + "00" + "00" + "5840" + strings.Repeat("22", 64) + "5820" + strings.Repeat("33", 32)
}

func TestValidateHotAcceptsTheExactForms(t *testing.T) {
	kes := envJSON("KesSigningKey_ed25519_kes_2^6", "590260"+strings.Repeat("ab", 608))
	vrf := envJSON("VrfSigningKey_PraosVRF", "5840"+strings.Repeat("cd", 64))
	oc := envJSON(TypeOpCert, opcertHex())
	for k, b := range map[HotKind][]byte{HotKES: kes, HotVRF: vrf, HotOpCert: oc} {
		if err := ValidateHot(k, b); err != nil {
			t.Errorf("kind %d: %v", k, err)
		}
	}
}

// spec: SPO-Xcustody-PRE-010
func TestValidateHotRefusesWhatIsNotExactlyThatKind(t *testing.T) {
	kesOK := "590260" + strings.Repeat("ab", 608)
	vrfOK := "5840" + strings.Repeat("cd", 64)
	cases := []struct {
		name string
		k    HotKind
		data []byte
	}{
		{"a cold key under the KES kind", HotKES, envJSON("StakePoolSigningKey_ed25519", "5820"+strings.Repeat("00", 32))},
		{"KES type with a 32-byte key", HotKES, envJSON("KesSigningKey_ed25519_kes_2^6", "5820"+strings.Repeat("00", 32))},
		{"KES type one byte long", HotKES, envJSON("KesSigningKey_ed25519_kes_2^6", kesOK+"00")},
		{"KES type one byte short", HotKES, envJSON("KesSigningKey_ed25519_kes_2^6", kesOK[:len(kesOK)-2])},
		{"KES type, other CBOR head", HotKES, envJSON("KesSigningKey_ed25519_kes_2^6", "590261"+strings.Repeat("ab", 608))},
		{"VRF type with a 32-byte key", HotVRF, envJSON("VrfSigningKey_PraosVRF", "5820"+strings.Repeat("00", 32))},
		{"VRF type 65 bytes", HotVRF, envJSON("VrfSigningKey_PraosVRF", vrfOK+"00")},
		{"VRF under the KES kind", HotKES, envJSON("VrfSigningKey_PraosVRF", vrfOK)},
		{"an issue counter as a certificate", HotOpCert, envJSON(TypeIssueCounter, opcertHex())},
		{"a certificate with the wrong shape", HotOpCert, envJSON(TypeOpCert, "5820"+strings.Repeat("00", 32))},
		{"a certificate with trailing bytes", HotOpCert, envJSON(TypeOpCert, opcertHex()+"00")},
		{"an extra member", HotVRF, []byte(`{"type":"VrfSigningKey_PraosVRF","description":"d","cborHex":"` + vrfOK + `","note":"x"}`)},
		{"a repeated member", HotVRF, []byte(`{"type":"VrfSigningKey_PraosVRF","type":"VrfSigningKey_PraosVRF","description":"d","cborHex":"` + vrfOK + `"}`)},
		{"a missing member", HotVRF, []byte(`{"type":"VrfSigningKey_PraosVRF","cborHex":"` + vrfOK + `"}`)},
		{"trailing text", HotVRF, append(envJSON("VrfSigningKey_PraosVRF", vrfOK), []byte(`{}`)...)},
		{"not hex", HotVRF, envJSON("VrfSigningKey_PraosVRF", "zz")},
		{"not JSON", HotVRF, []byte("hello")},
		{"unknown kind", HotKind(0), envJSON("VrfSigningKey_PraosVRF", vrfOK)},
		{"empty", HotVRF, nil},
	}
	for _, c := range cases {
		if err := ValidateHot(c.k, c.data); !errors.Is(err, ErrNotHot) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestHotKeyBytes(t *testing.T) {
	b, err := HotKeyBytes(HotVRF, envJSON("VrfSigningKey_PraosVRF", "5840"+strings.Repeat("cd", 64)))
	if err != nil || len(b) != 64 || hex.EncodeToString(b[:2]) != "cdcd" {
		t.Errorf("%v %d", err, len(b))
	}
	if _, err := HotKeyBytes(HotOpCert, envJSON(TypeOpCert, opcertHex())); err == nil {
		t.Error("a certificate has no key bytes")
	}
}
