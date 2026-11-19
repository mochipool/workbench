package relayporttest

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// Wallet is a software wallet key for tests: it signs binding and revoke
// statements the way the software signing path does (CIP-8, the payload
// embedded and not hashed, protected header {1: -8, "address": K}), with a
// deterministic seed. It is a throwaway key, never a real one.
type Wallet struct {
	priv ed25519.PrivateKey
	pub  [32]byte
	// Key is the wallet key hash K, Blake2b-224 of the verification key.
	Key relaybind.KeyHash
}

// NewWallet derives a wallet from one byte.
func NewWallet(n byte) *Wallet {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n + byte(i)*3
	}
	w := &Wallet{priv: ed25519.NewKeyFromSeed(seed)}
	copy(w.pub[:], w.priv.Public().(ed25519.PublicKey))
	h, _ := blake2b.New(28, nil)
	h.Write(w.pub[:])
	copy(w.Key[:], h.Sum(nil))
	return w
}

type deviceKeys struct {
	priv ed25519.PrivateKey
	ed   party.Ed25519Public
	x    party.X25519Public
	fp   party.Fingerprint
}

var devices sync.Map // byte -> deviceKeys; party.Fingerprint -> deviceKeys

func deviceOf(n byte) deviceKeys {
	if v, ok := devices.Load(n); ok {
		return v.(deviceKeys)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 0xd0 ^ n + byte(i)*5
	}
	k := deviceKeys{priv: ed25519.NewKeyFromSeed(seed)}
	copy(k.ed[:], k.priv.Public().(ed25519.PublicKey))
	for i := range k.x {
		k.x[i] = n + byte(i)*7 + 1
	}
	k.fp = party.FingerprintOf(k.ed, k.x)
	devices.Store(n, k)
	devices.Store(k.fp, k)
	return k
}

// Device is the fingerprint of a device made from one byte: the fingerprint of
// real keys (a test device-signed revoke is signed by them: DeviceRevoke).
func Device(n byte) party.Fingerprint { return deviceOf(n).fp }

// DeviceKeysOf are the two public keys of Device(n): their fingerprint is
// Device(n).
func DeviceKeysOf(n byte) mailbox.DeviceKeys {
	k := deviceOf(n)
	return mailbox.DeviceKeys{Ed25519: k.ed, X25519: k.x}
}

func head(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 256:
		return []byte{m | 24, byte(n)}
	default:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	}
}

func bstr(b []byte) []byte { return append(head(2, uint64(len(b))), b...) }

// protectedFlipped is the protected header with its two keys in the other order.
func (w *Wallet) protected(flip bool) []byte { return w.protectedAt(w.Key[:], flip) }

func (w *Wallet) protectedAt(addr []byte, flip bool) []byte {
	alg := []byte{0x01, 0x27}
	adr := append(append([]byte{0x67}, "address"...), bstr(addr)...)
	if flip {
		return append([]byte{0xa2}, append(adr, alg...)...)
	}
	return append([]byte{0xa2}, append(alg, adr...)...)
}

// EnterpriseAddress is the 29-byte enterprise address of the wallet key on the
// network id given (0 for a test network, 1 for mainnet).
func (w *Wallet) EnterpriseAddress(network byte) []byte {
	return append([]byte{0x60 | network&0x0f}, w.Key[:]...)
}

// BindingStatementAt signs a binding of device from..until whose protected
// header carries addr (a form an external CIP-30 wallet writes) instead of the
// bare key hash.
func (w *Wallet) BindingStatementAt(addr []byte, device party.Fingerprint, from, until int64) Statements {
	p := []byte(fmt.Sprintf("spo-relay-binding-v1 device %x from %s until %s", device[:], strconv.FormatInt(from, 10), strconv.FormatInt(until, 10)))
	return Statements{Sign1: w.sign1(w.protectedAt(addr, false), p), COSEKey: w.COSEKey()}
}

// Sign1 signs payload and returns the COSE_Sign1 bytes. With flip the protected
// header has its keys in the other order: another valid signature over the same
// statement (the same StatementID, another full hash).
func (w *Wallet) Sign1(payload []byte, flip bool) []byte {
	return w.sign1(w.protected(flip), payload)
}

// Sign1At is Sign1 with addr in the protected header.
func (w *Wallet) Sign1At(addr, payload []byte) []byte {
	return w.sign1(w.protectedAt(addr, false), payload)
}

func (w *Wallet) sign1(prot, payload []byte) []byte {
	sigStruct := []byte{0x84, 0x6a}
	sigStruct = append(sigStruct, "Signature1"...)
	sigStruct = append(sigStruct, bstr(prot)...)
	sigStruct = append(sigStruct, 0x40)
	sigStruct = append(sigStruct, bstr(payload)...)
	sig := ed25519.Sign(w.priv, sigStruct)
	out := []byte{0x84}
	out = append(out, bstr(prot)...)
	out = append(out, 0xa1, 0x66)
	out = append(out, "hashed"...)
	out = append(out, 0xf4)
	out = append(out, bstr(payload)...)
	return append(out, bstr(sig)...)
}

// COSEKey is the COSE_Key of the verification key, as cose.EncodeKey writes it.
func (w *Wallet) COSEKey() []byte {
	out := []byte{0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21}
	return append(out, bstr(w.pub[:])...)
}

// Statements is a wallet-signed statement with its COSE_Key.
type Statements struct {
	Sign1, COSEKey []byte
}

// BindingStatement signs a binding of device from..until.
func (w *Wallet) BindingStatement(device party.Fingerprint, from, until int64, flip bool) Statements {
	p := []byte(fmt.Sprintf("spo-relay-binding-v1 device %x from %s until %s", device[:], strconv.FormatInt(from, 10), strconv.FormatInt(until, 10)))
	return Statements{Sign1: w.Sign1(p, flip), COSEKey: w.COSEKey()}
}

// RevokeStatement signs a revoke of device (all when all is true).
func (w *Wallet) RevokeStatement(device party.Fingerprint, all bool, notBefore int64) Statements {
	d := fmt.Sprintf("%x", device[:])
	if all {
		d = "all"
	}
	p := []byte(fmt.Sprintf("spo-relay-revoke-v1 device %s not-before %d", d, notBefore))
	return Statements{Sign1: w.Sign1(p, false), COSEKey: w.COSEKey()}
}

// Present verifies a binding of device as the relay would at relay time now, with
// the default policy, and returns it ready to register. It fails the test if the
// binding does not verify.
func (w *Wallet) Present(t testing.TB, device party.Fingerprint, from, until, now int64) relayregistry.Presented {
	t.Helper()
	p, err := w.TryPresent(device, from, until, now, false)
	if err != nil {
		t.Fatalf("a binding that should verify at %d does not: %v", now, err)
	}
	return p
}

// PresentFlipped is Present with the other protected-header key order: another
// signature over the same statement.
func (w *Wallet) PresentFlipped(t testing.TB, device party.Fingerprint, from, until, now int64) relayregistry.Presented {
	t.Helper()
	p, err := w.TryPresent(device, from, until, now, true)
	if err != nil {
		t.Fatalf("a binding that should verify at %d does not: %v", now, err)
	}
	return p
}

// TryPresent verifies at relay time now and returns the error if it fails.
func (w *Wallet) TryPresent(device party.Fingerprint, from, until, now int64, flip bool) (relayregistry.Presented, error) {
	s := w.BindingStatement(device, from, until, flip)
	st, err := relaybind.ParseStatement(s.Sign1)
	if err != nil {
		return relayregistry.Presented{}, err
	}
	vb, err := relaybind.VerifyBinding(st, w.pub, device, now, relaybind.DefaultPolicy())
	if err != nil {
		return relayregistry.Presented{}, err
	}
	return relayregistry.NewPresented(vb, s.Sign1, s.COSEKey)
}

// WalletRevoke is a verified wallet-signed revoke record of one device, at relay
// time now.
func (w *Wallet) WalletRevoke(t testing.TB, device party.Fingerprint, notBefore, now int64) relayregistry.RevokeRecord {
	t.Helper()
	return w.revoke(t, device, false, notBefore, now)
}

// AllRevoke is a verified revoke of every device of the key.
func (w *Wallet) AllRevoke(t testing.TB, notBefore, now int64) relayregistry.RevokeRecord {
	t.Helper()
	return w.revoke(t, party.Fingerprint{}, true, notBefore, now)
}

func (w *Wallet) revoke(t testing.TB, device party.Fingerprint, all bool, notBefore, now int64) relayregistry.RevokeRecord {
	t.Helper()
	s := w.RevokeStatement(device, all, notBefore)
	st, err := relaybind.ParseStatement(s.Sign1)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := relaybind.VerifyRevoke(st, w.pub, now, relaybind.DefaultPolicy())
	if err != nil {
		t.Fatalf("a revoke that should verify at %d does not: %v", now, err)
	}
	rec, err := relayregistry.WalletRevoke(vr)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// DeviceRevokeSignature is the signature of the device Device(n) over its own
// device-signed revoke with the not-before given.
func DeviceRevokeSignature(t testing.TB, n byte, notBefore int64) [64]byte {
	t.Helper()
	k := deviceOf(n)
	msg, err := relaybind.DeviceRevokeBytes(k.fp, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(k.priv, msg))
	return sig
}

// DeviceRevoke is the record of a revoke signed by the device Device(n) made, and
// verified by relaybind.VerifyDeviceRevoke as the relay does (at relay time equal
// to the not-before). device must be one that Device returned.
func DeviceRevoke(t testing.TB, device party.Fingerprint, notBefore int64) relayregistry.RevokeRecord {
	t.Helper()
	v, ok := devices.Load(device)
	if !ok {
		t.Fatalf("device %x is not one of Device(n)", device[:2])
	}
	k := v.(deviceKeys)
	msg, err := relaybind.DeviceRevokeBytes(device, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(k.priv, msg))
	ver, err := relaybind.VerifyDeviceRevoke(k.ed, k.x, notBefore, sig, notBefore, relaybind.DefaultPolicy())
	if err != nil {
		t.Fatalf("a device revoke that should verify does not: %v", err)
	}
	rec, err := relayregistry.DeviceRevoke(ver)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
