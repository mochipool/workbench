package relaybind_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// Unix time used by the tests: 2027-01-15, and a binding of 90 days around it.
const (
	nowT   int64 = 1800000000
	fromT        = nowT - 60
	untilT       = fromT + 90*86400
)

func bs(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func fpOf(start byte) (f party.Fingerprint) {
	copy(f[:], bs(20, start))
	return
}

// The fixed software test key of every vector and test. It is a throwaway
// seed, not a wallet key.
var (
	testPriv  = ed25519.NewKeyFromSeed(bs(32, 7))
	testPub   = [32]byte(testPriv.Public().(ed25519.PublicKey))
	testK     = relaybind.KeyHash(cose.Blake2b224(testPub[:]))
	otherPriv = ed25519.NewKeyFromSeed(bs(32, 99))
	otherPub  = [32]byte(otherPriv.Public().(ed25519.PublicKey))
	testDev   = fpOf(0x30)
)

// --- A small CBOR writer of the tests' own (not the package's). ----------

// head writes a head in its shortest form.
func head(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n < 1<<8:
		return []byte{m | 24, byte(n)}
	case n < 1<<16:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// wide writes a head with a forced argument width of 1, 2, 4 or 8 bytes.
func wide(major byte, n uint64, width int) []byte {
	out := []byte{major<<5 | byte(24+map[int]int{1: 0, 2: 1, 4: 2, 8: 3}[width])}
	for i := width - 1; i >= 0; i-- {
		out = append(out, byte(n>>(8*i)))
	}
	return out
}

func bstr(b []byte) []byte { return append(head(2, uint64(len(b))), b...) }
func tstr(s string) []byte { return append(head(3, uint64(len(s))), s...) }
func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	cFalse = []byte{0xf4}
	cTrue  = []byte{0xf5}
	cNull  = []byte{0xf6}
	// {"hashed": false}
	unprotOK = cat(head(5, 1), tstr("hashed"), cFalse)
	// the integer key 1 and the value -8
	kAlg = head(0, 1)
	vAlg = head(1, 7)
)

// protectedWith builds {1: -8, "address": addr} by hand.
func protectedWith(addr []byte) []byte {
	return cat(head(5, 2), kAlg, vAlg, tstr("address"), bstr(addr))
}

// assemble builds a COSE_Sign1 array of 4 from raw item encodings.
func assemble(prot, unprot, payload, sig []byte) []byte {
	return cat(head(4, 4), prot, unprot, payload, sig)
}

// signed builds a statement the way the software signing path does
// (VaultSignatures.SignMessage): protected header with the address, the
// payload embedded and not hashed, Sig_structure signed with the key.
func signedWith(priv ed25519.PrivateKey, protected, payload []byte) []byte {
	sig := ed25519.Sign(priv, cose.SigStructure(protected, payload))
	return assemble(bstr(protected), unprotOK, bstr(payload), bstr(sig))
}

// signRaw signs arbitrary bytes with the test key.
func signRaw(msg []byte) []byte { return ed25519.Sign(testPriv, msg) }

func signed(addr, payload []byte) []byte {
	return signedWith(testPriv, protectedWith(addr), payload)
}

// goodPayload and goodSign1: a canonical binding for testDev signed by the
// test key with K as the address.
func goodBinding() relaybind.Binding {
	return relaybind.Binding{Device: testDev, From: fromT, Until: untilT}
}

func goodPayload(t testing.TB) []byte {
	t.Helper()
	p, err := goodBinding().Render()
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return p
}

func goodSign1(t testing.TB) []byte {
	t.Helper()
	return signed(testK[:], goodPayload(t))
}

func mustStatement(t testing.TB, b []byte) relaybind.Statement {
	t.Helper()
	st, err := relaybind.ParseStatement(b)
	if err != nil {
		t.Fatalf("ParseStatement(%x): %v", b, err)
	}
	return st
}

// verifies reports whether b parses and verifies as the good binding context.
func verifiesAsBinding(b []byte) error {
	st, err := relaybind.ParseStatement(b)
	if err != nil {
		return err
	}
	_, err = relaybind.VerifyBinding(st, testPub, testDev, nowT, relaybind.DefaultPolicy())
	return err
}

// verifyDevRevoke calls VerifyDeviceRevoke with a Policy of the given skew and
// the ADR's lifetime bound.
func verifyDevRevoke(ed party.Ed25519Public, x party.X25519Public, nb int64, sig [64]byte, now, skew int64) (party.Fingerprint, error) {
	return relaybind.VerifyDeviceRevoke(ed, x, nb, sig, now, relaybind.Policy{Skew: skew, MaxLifetime: relaybind.MaxLifetimeSeconds})
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEqualBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", what, got, want)
	}
}

func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func bindingText(dev party.Fingerprint, from, until string) string {
	return fmt.Sprintf("spo-relay-binding-v1 device %x from %s until %s", dev[:], from, until)
}
