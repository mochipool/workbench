package native

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func vkeyRaw(t *testing.T, env []byte) []byte {
	t.Helper()
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	k, err := e.Key32()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// spec: SPO-Xcustody-PRE-009
func TestHotKeyDeriverGivesTheVerificationKeys(t *testing.T) {
	ctx := context.Background()
	kp, err := KeyGen{}.GenerateKES(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := HotKeyDeriver{}.DeriveKES(ctx, kp.SKey)
	if err != nil || !bytes.Equal(got, vkeyRaw(t, kp.VKey)) {
		t.Errorf("KES: %v", err)
	}
	vp, err := KeyGen{}.GenerateVRF(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err = HotKeyDeriver{}.DeriveVRF(ctx, vp.SKey)
	if err != nil || !bytes.Equal(got, vkeyRaw(t, vp.VKey)) {
		t.Errorf("VRF: %v", err)
	}
	// the import path (ports.VerificationKeyDeriver) derives them too
	got, err = VKeyDeriver{}.DeriveVerificationKey(ctx, kp.SKey)
	if err != nil || !bytes.Equal(got, vkeyRaw(t, kp.VKey)) {
		t.Errorf("import, KES: %v", err)
	}
	got, err = VKeyDeriver{}.DeriveVerificationKey(ctx, vp.SKey)
	if err != nil || !bytes.Equal(got, vkeyRaw(t, vp.VKey)) {
		t.Errorf("import, VRF: %v", err)
	}
	// two different KES keys have different verification keys
	kp2, _ := KeyGen{}.GenerateKES(ctx)
	if bytes.Equal(vkeyRaw(t, kp.VKey), vkeyRaw(t, kp2.VKey)) {
		t.Error("two KES keys agree")
	}
}

func env(typ, cborHex string) *secret.Buffer {
	b, _ := json.Marshal(map[string]string{"type": typ, "description": "d", "cborHex": cborHex})
	return secret.Take(b)
}

// A file with the hot envelope type and other key material is refused, by the
// deriver and by the import path.
//
// spec: SPO-Xcustody-PRE-009, SPO-Xcustody-PRE-010
func TestHotKeyDeriverRefusesCraftedFiles(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]*secret.Buffer{
		"KES type, a 32-byte key":     env("KesSigningKey_ed25519_kes_2^6", "5820"+strings.Repeat("11", 32)),
		"KES type, 608 bytes of 0x00": env("KesSigningKey_ed25519_kes_2^6", "590260"+strings.Repeat("00", 608)),
	} {
		if name == "KES type, 608 bytes of 0x00" {
			// exact length passes the shape check: its derived key cannot be the stored one
			got, err := HotKeyDeriver{}.DeriveKES(ctx, c)
			real, _ := KeyGen{}.GenerateKES(ctx)
			if err == nil && bytes.Equal(got, vkeyRaw(t, real.VKey)) {
				t.Error("crafted material derived a real key")
			}
			continue
		}
		_, err := HotKeyDeriver{}.DeriveKES(ctx, c)
		if !errors.Is(err, ErrBadHotKey) {
			t.Errorf("%s: %v", name, err)
		}
		_, err = VKeyDeriver{}.DeriveVerificationKey(ctx, c)
		if err == nil || errors.Is(err, ports.ErrKeyTypeUnsupported) {
			t.Errorf("%s through the import path: %v", name, err)
		}
	}
	// a VRF key whose public half is not its seed's
	seed := strings.Repeat("07", 32)
	bad := env("VrfSigningKey_PraosVRF", "5840"+seed+strings.Repeat("09", 32))
	_, derr := HotKeyDeriver{}.DeriveVRF(ctx, bad)
	if !errors.Is(derr, ErrBadHotKey) {
		t.Errorf("VRF halves disagree: %v", derr)
	}
	_, verr := VKeyDeriver{}.DeriveVerificationKey(ctx, bad)
	if verr == nil {
		t.Error("the import path accepted a VRF key whose halves disagree")
	}
	// a cold key under a hot deriver
	_, cerr := HotKeyDeriver{}.DeriveVRF(ctx, env("StakePoolSigningKey_ed25519", "5820"+hex.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	if !errors.Is(cerr, ErrBadHotKey) {
		t.Errorf("cold key: %v", cerr)
	}
}

// A KES key whose seeds were overwritten is refused by the import path (and so by
// `key convert`, which uses the same deriver).
//
// spec: SPO-Xcustody-PRE-009, SPO-Xcustody-PRE-010
func TestImportPathRefusesAKESKeyWithOverwrittenSeeds(t *testing.T) {
	ctx := context.Background()
	kp, _ := KeyGen{}.GenerateKES(ctx)
	var e struct{ Type, Description, CborHex string }
	kp.SKey.Use(func(b []byte) error { return json.Unmarshal(b, &e) })
	raw, _ := hex.DecodeString(e.CborHex)
	copy(raw[3:], bytes.Repeat([]byte{0x42}, 32)) // the leaf seed
	e.CborHex = hex.EncodeToString(raw)
	b, _ := json.Marshal(map[string]string{"type": e.Type, "description": e.Description, "cborHex": e.CborHex})
	if _, err := (VKeyDeriver{}).DeriveVerificationKey(ctx, secret.Take(b)); err == nil {
		t.Fatal("accepted")
	}
}
