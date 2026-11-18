// Package hotkeys derives and checks the verification keys of a KES and a VRF
// signing key (ports.HotVKeyDeriver) for `node export` and the block producer's
// start-up helper. It is a subpackage of adapters/native, so the confinement of
// the Blink Labs libraries holds, and it is small so that the helper imports it
// without the rest of native. A KES key is accepted only when its whole Sum6
// structure is consistent with the seeds it actually holds.
package hotkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/kes"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Deriver implements ports.HotVKeyDeriver. It accepts only the exact forms
// pool.ValidateHot accepts.
type Deriver struct{}

var _ ports.HotVKeyDeriver = Deriver{}

// ErrBadHotKey is returned for an envelope that is not a KES or VRF signing key
// of the exact, self-consistent form; it carries no key material.
var ErrBadHotKey = errors.New("the signing key envelope is not a KES or VRF signing key of the exact form")

func wipe(b []byte) { clear(b) }

// DeriveKES implements ports.HotVKeyDeriver: the Sum6 root verification key,
// returned only after the whole structure was checked against its seeds.
func (Deriver) DeriveKES(_ context.Context, env *secret.Buffer) ([]byte, error) {
	var out []byte
	err := env.Use(func(b []byte) error {
		raw, err := pool.HotKeyBytes(pool.HotKES, b)
		if err != nil {
			return ErrBadHotKey
		}
		defer wipe(raw)
		pub, err := sumPublicKey(kes.CardanoKesDepth, raw)
		if err != nil {
			return ErrBadHotKey
		}
		out = pub
		return nil
	})
	return out, err
}

// DeriveKESLeaf implements ports.HotVKeyDeriver.
func (d Deriver) DeriveKESLeaf(ctx context.Context, env *secret.Buffer) ([]byte, error) {
	if _, err := d.DeriveKES(ctx, env); err != nil {
		return nil, err
	}
	var out []byte
	err := env.Use(func(b []byte) error {
		raw, err := pool.HotKeyBytes(pool.HotKES, b)
		if err != nil {
			return ErrBadHotKey
		}
		defer wipe(raw)
		k := ed25519.NewKeyFromSeed(raw[:32]) // the active leaf is the first 32 bytes
		defer wipe(k)
		out = append([]byte(nil), k.Public().(ed25519.PublicKey)...)
		return nil
	})
	return out, err
}

// sumPublicKey checks a Sum_d secret key blob (child key, right seed, left
// public key, right public key at each level, a 32-byte Ed25519 seed at the
// bottom) and returns its root public key. At each level the active child's
// public key must be the stored left key (right seed still present: the key has
// not passed this level) or the stored right key (right seed erased: the key is
// in the right subtree and the left key is no longer backed by any secret); and
// when the right seed is present the right key must be the one it generates.
// A leaf is the Ed25519 public key of its seed. The root is the hash of the two
// stored keys, so the value returned is derived from secrets actually present.
func sumPublicKey(depth uint64, data []byte) ([]byte, error) {
	if depth == 0 {
		if len(data) != 32 {
			return nil, ErrBadHotKey
		}
		k := ed25519.NewKeyFromSeed(data)
		defer wipe(k)
		return append([]byte(nil), k.Public().(ed25519.PublicKey)...), nil
	}
	child := 32 + int(depth-1)*96
	if len(data) != child+96 {
		return nil, ErrBadHotKey
	}
	cpk, err := sumPublicKey(depth-1, data[:child])
	if err != nil {
		return nil, err
	}
	seed, vk0, vk1 := data[child:child+32], data[child+32:child+64], data[child+64:child+96]
	if allZero(seed) {
		if !bytes.Equal(cpk, vk1) {
			return nil, ErrBadHotKey
		}
	} else {
		if !bytes.Equal(cpk, vk0) {
			return nil, ErrBadHotKey
		}
		rp, err := publicFromSeed(depth-1, seed)
		if err != nil || !bytes.Equal(rp, vk1) {
			return nil, ErrBadHotKey
		}
	}
	return append([]byte(nil), kes.HashPair(vk0, vk1)...), nil
}

func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

// publicFromSeed is the Sum_d public key of a seed (the library's KeyGen with
// the secret half discarded, so the construction is the library's).
func publicFromSeed(depth uint64, seed []byte) ([]byte, error) {
	sk, pub, err := kes.KeyGen(depth, seed)
	if err != nil {
		return nil, err
	}
	sk.Zeroize()
	return pub, nil
}

// DeriveVRF implements ports.HotVKeyDeriver: the public key of the seed, which
// must equal the public half stored in the key.
func (Deriver) DeriveVRF(_ context.Context, env *secret.Buffer) ([]byte, error) {
	var out []byte
	err := env.Use(func(b []byte) error {
		raw, err := pool.HotKeyBytes(pool.HotVRF, b)
		if err != nil {
			return ErrBadHotKey
		}
		defer wipe(raw)
		pub, sk, err := bursa.GetVRFKeyPair(raw[:32])
		if err != nil {
			return ErrBadHotKey
		}
		defer wipe(sk)
		if subtle.ConstantTimeCompare(pub, raw[32:]) != 1 {
			return ErrBadHotKey
		}
		out = append([]byte(nil), pub...)
		return nil
	})
	return out, err
}
