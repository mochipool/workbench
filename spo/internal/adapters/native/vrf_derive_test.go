package native

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func TestVRFDeriverMatchesGenerator(t *testing.T) {
	pair, err := KeyGen{}.GenerateVRF(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	got, err := VRFDeriver{}.DeriveVrfVKey(context.Background(), pair.SKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pair.VKey) {
		t.Errorf("derived\n%s\ngenerated\n%s", got, pair.VKey)
	}
	// A key whose public half is not the seed's is refused.
	var bad []byte
	_ = pair.SKey.Use(func(b []byte) error { bad = bytes.Replace(b, []byte("5840"), []byte("5840"), 1); return nil })
	i := bytes.Index(bad, []byte(`"cborHex": "5840`)) + len(`"cborHex": "5840`)
	bad = append([]byte(nil), bad...)
	if bad[i+64] == '0' {
		bad[i+64] = '1'
	} else {
		bad[i+64] = '0'
	}
	buf, err := secret.TryTake(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	if _, err := (VRFDeriver{}).DeriveVrfVKey(context.Background(), buf); !errors.Is(err, ErrBadVRFKey) {
		t.Errorf("inconsistent halves: %v", err)
	}
}
