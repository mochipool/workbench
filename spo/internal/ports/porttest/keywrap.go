package porttest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// KeyWrapSubject is a backend under the key-wrap contract and what must never
// appear in its errors (its credential, as the test gave it).
type KeyWrapSubject struct {
	Backend ports.KeyWrapBackend
	// Secrets are strings that no error of the backend may contain: the token,
	// the secret access key, the session token, the JWT.
	Secrets []string
}

// KeyWrapContract is the contract every ports.KeyWrapBackend passes (ADR 0011
// decision 5): a wrap unwraps under its own context only, a changed blob is
// refused, B is exactly 32 bytes in and out and comes back in guarded memory,
// and no error carries B or the credential.
//
// spec: SPO-Xunlock-IF-007, SPO-Xunlock-SEC-008
func KeyWrapContract(t *testing.T, s KeyWrapSubject) {
	t.Helper()
	ctx := context.Background()
	b := make([]byte, ports.BackendSecretSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	forbidden := append([]string{hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), string(b)}, s.Secrets...)
	var errs []error
	note := func(err error) error {
		if err != nil {
			errs = append(errs, err)
		}
		return err
	}
	buf := func(p []byte) *secret.Buffer {
		x, err := secret.Fill(len(p), func(d []byte) error { copy(d, p); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	wc := ports.WrapContext{GenesisNonce: bytes.Repeat([]byte{0x11}, 16), SlotID: bytes.Repeat([]byte{0x22}, 16)}

	in := buf(b)
	blob, err := s.Backend.Wrap(ctx, in, wc)
	in.Destroy()
	if note(err) != nil {
		t.Fatalf("wrap: %v", err)
	}
	if len(blob) == 0 || len(blob) > ports.MaxWrappedBlob {
		t.Fatalf("a wrapped blob of %d bytes", len(blob))
	}
	if bytes.Contains(blob, b) {
		t.Fatal("the wrapped blob holds B in clear")
	}
	got, err := s.Backend.Unwrap(ctx, blob, wc)
	if note(err) != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got.Len() != ports.BackendSecretSize {
		t.Fatalf("B came back as %d bytes", got.Len())
	}
	_ = got.Use(func(p []byte) error {
		if !bytes.Equal(p, b) {
			t.Error("B came back different")
		}
		return nil
	})
	got.Destroy()

	refuse := func(name string, blob []byte, wc ports.WrapContext) {
		t.Helper()
		out, err := s.Backend.Unwrap(ctx, blob, wc)
		note(err)
		if err == nil {
			out.Destroy()
			t.Errorf("%s: unwrapped", name)
		}
		if out != nil && err != nil {
			t.Errorf("%s: a secret with the error", name)
		}
	}
	refuse("another genesis nonce", blob, ports.WrapContext{GenesisNonce: bytes.Repeat([]byte{0x12}, 16), SlotID: wc.SlotID})
	refuse("another slot", blob, ports.WrapContext{GenesisNonce: wc.GenesisNonce, SlotID: bytes.Repeat([]byte{0x23}, 16)})
	refuse("the two ids swapped", blob, ports.WrapContext{GenesisNonce: wc.SlotID, SlotID: wc.GenesisNonce})
	refuse("a short context", blob, ports.WrapContext{GenesisNonce: wc.GenesisNonce[:15], SlotID: wc.SlotID})
	for _, i := range []int{0, len(blob) / 2, len(blob) - 1} {
		x := append([]byte(nil), blob...)
		x[i] ^= 0x01
		refuse(fmt.Sprintf("byte %d changed", i), x, wc)
	}
	refuse("truncated", blob[:len(blob)-1], wc)
	refuse("extended", append(append([]byte(nil), blob...), 0), wc)
	refuse("empty", nil, wc)
	refuse("oversized", make([]byte, ports.MaxWrappedBlob+1), wc)

	if _, err := s.Backend.Wrap(ctx, nil, wc); note(err) == nil {
		t.Error("no B was wrapped")
	}
	for _, n := range []int{31, 33, 64} {
		x := buf(make([]byte, n))
		_, err := s.Backend.Wrap(ctx, x, wc)
		note(err)
		x.Destroy()
		if err == nil {
			t.Errorf("a B of %d bytes was wrapped", n)
		}
	}
	x := buf(b)
	_, err = s.Backend.Wrap(ctx, x, ports.WrapContext{GenesisNonce: wc.GenesisNonce, SlotID: wc.SlotID[:8]})
	x.Destroy()
	if note(err) == nil {
		t.Error("a wrap with a short slot id was made")
	}

	for _, err := range errs {
		for _, f := range forbidden {
			if f != "" && strings.Contains(err.Error(), f) {
				t.Errorf("an error carries a secret: %q", err.Error())
			}
		}
	}
}

// FakeKeyWrap is an in-process backend for tests: AES-256-GCM under a key of
// its own, with the encoded wrap context as associated data, which is what Vault
// Transit does with associated_data. Chosen, when set, is what Unwrap returns
// instead of the true B (a hostile backend); Fail, when set, is returned by
// every call (a backend that is down or refuses).
type FakeKeyWrap struct {
	R      ports.BackendRef
	key    []byte
	mu     sync.Mutex
	Chosen []byte
	Fail   error
	// IgnoreContext makes the fake wrap and unwrap with no associated data: a
	// server that does not know associated_data (Vault before it was added) or
	// drops it, and so unwraps a blob under any context.
	IgnoreContext bool
	// Calls counts Wrap and Unwrap.
	Calls int
}

// NewFakeKeyWrap returns a fake backend with a fresh key.
func NewFakeKeyWrap(ref ports.BackendRef) *FakeKeyWrap {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return &FakeKeyWrap{R: ref, key: k}
}

// Ref implements ports.KeyWrapBackend.
func (f *FakeKeyWrap) Ref() ports.BackendRef { return f.R }

func (f *FakeKeyWrap) ignoresContext() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.IgnoreContext
}

func (f *FakeKeyWrap) aead() cipher.AEAD {
	blk, err := aes.NewCipher(f.key)
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	return g
}

// Wrap implements ports.KeyWrapBackend.
func (f *FakeKeyWrap) Wrap(ctx context.Context, b *secret.Buffer, wc ports.WrapContext) ([]byte, error) {
	f.mu.Lock()
	f.Calls++
	fail := f.Fail
	f.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	ad, err := wc.Encode()
	if err != nil {
		return nil, err
	}
	if b == nil || b.Len() != ports.BackendSecretSize {
		return nil, fmt.Errorf("%w: B must be %d bytes", ports.ErrBackendConfig, ports.BackendSecretSize)
	}
	if f.ignoresContext() {
		ad = nil
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	var out []byte
	err = b.Use(func(p []byte) error { out = f.aead().Seal(nonce, nonce, p, ad); return nil })
	return out, err
}

// Unwrap implements ports.KeyWrapBackend.
func (f *FakeKeyWrap) Unwrap(ctx context.Context, blob []byte, wc ports.WrapContext) (*secret.Buffer, error) {
	f.mu.Lock()
	f.Calls++
	fail, chosen := f.Fail, f.Chosen
	f.mu.Unlock()
	if fail != nil {
		return nil, fail
	}
	ad, err := wc.Encode()
	if err != nil {
		return nil, err
	}
	if len(blob) < 12+16 || len(blob) > ports.MaxWrappedBlob {
		return nil, ports.ErrBackendRefused
	}
	if chosen != nil {
		return secret.Fill(len(chosen), func(d []byte) error { copy(d, chosen); return nil })
	}
	if f.ignoresContext() {
		ad = nil
	}
	pt, err := f.aead().Open(nil, blob[:12], blob[12:], ad)
	if err != nil {
		return nil, ports.ErrBackendRefused
	}
	if len(pt) != ports.BackendSecretSize {
		return nil, ports.ErrBackendResponse
	}
	return secret.TryTake(pt)
}

// ErrFakeDown is a FakeKeyWrap.Fail value for a backend that does not answer.
var ErrFakeDown = errors.Join(ports.ErrBackendUnavailable, errors.New("fake backend down"))
