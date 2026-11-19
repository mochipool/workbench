package envelope

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math/rand"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The local identity signs its own device revoke through a typed method: the
// bytes are the canonical array [label, own fingerprint, not-before] and
// nothing else, the signature is the Ed25519 signature of those bytes by the
// device key (deterministic, so compared with an independent signature), it
// verifies with relaybind, and a not-before outside the statement's range is
// refused with no signature.
//
// spec: SPO-Xrelaybind-INV-005, SPO-Xrelaybind-INV-006, SPO-Xrelaybind-IF-003
func TestLocalSignsOnlyItsOwnDeviceRevoke(t *testing.T) {
	p, err := Generate("dev", nil, time.Unix(1700000000, 0), rand.New(rand.NewSource(7)))
	if err != nil {
		t.Fatal(err)
	}
	l := NewLocal(p, nil)
	var signer relayport.DeviceRevokeSigner = l
	id := signer.Identity()
	fpr := id.Fingerprint()

	const nb = int64(1800000000)
	sig, err := signer.SignRelayDeviceRevoke(nb, nb)
	if err != nil {
		t.Fatal(err)
	}
	// verifies as the relay checks it
	got, err := relaybind.VerifyDeviceRevoke(id.Ed25519, id.X25519, nb, sig, nb, relaybind.DefaultPolicy())
	if err != nil || got.Device() != fpr || got.NotBefore() != nb {
		t.Fatalf("VerifyDeviceRevoke: %v, device %x want %x", err, got.Device(), fpr)
	}
	// exactly the signature over the labelled array of the own fingerprint
	msg, err := relaybind.DeviceRevokeBytes(fpr, nb)
	if err != nil {
		t.Fatal(err)
	}
	var seed []byte
	_ = p.keys.Use(func(b []byte) error { seed = append([]byte(nil), b[:32]...); return nil })
	want := ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)
	if !bytes.Equal(sig[:], want) {
		t.Errorf("signature %x, want the Ed25519 signature of the device-revoke bytes %x", sig, want)
	}
	// and of nothing else: another not-before, another device, no label
	if _, err := relaybind.VerifyDeviceRevoke(id.Ed25519, id.X25519, nb+1, sig, nb+1, relaybind.DefaultPolicy()); err == nil {
		t.Error("the signature verifies for another not-before")
	}
	other := fpr
	other[0] ^= 1
	if o, _ := relaybind.DeviceRevokeBytes(other, nb); ed25519.Verify(id.Ed25519[:], o, sig[:]) {
		t.Error("the signature verifies for another fingerprint")
	}
	if ed25519.Verify(id.Ed25519[:], msg[1:], sig[:]) || ed25519.Verify(id.Ed25519[:], append([]byte("x"), msg...), sig[:]) {
		t.Error("the signature verifies for bytes that are not the array")
	}
	// out of range: refused, no signature
	for _, bad := range []int64{-1, relaybind.MaxTime + 1} {
		if s, err := signer.SignRelayDeviceRevoke(bad, relaybind.MaxTime); err == nil || s != ([64]byte{}) {
			t.Errorf("not-before %d: %v", bad, err)
		}
	}
	// the bound the caller gives: a not-before above it is refused with no
	// signature, at the bound it is signed, and a negative bound refuses all
	for _, c := range []struct {
		nb, bound int64
		ok        bool
	}{{nb, nb, true}, {nb, nb + 1, true}, {nb + 1, nb, false}, {relaybind.MaxTime, nb + 300, false}, {0, -1, false}, {0, 0, true}} {
		s, err := signer.SignRelayDeviceRevoke(c.nb, c.bound)
		if (err == nil) != c.ok || (err != nil && s != ([64]byte{})) || (err != nil && !errors.Is(err, relaybind.ErrRevokeFuture)) {
			t.Errorf("not-before %d, bound %d: %v", c.nb, c.bound, err)
		}
	}
	// a destroyed identity signs nothing
	l.Destroy()
	if s, err := signer.SignRelayDeviceRevoke(nb, nb); err == nil && s != ([64]byte{}) {
		t.Error("a destroyed identity signed")
	}
}
