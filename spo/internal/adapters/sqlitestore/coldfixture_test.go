package sqlitestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The store refuses a signing key whose key identity it cannot find or whose
// identity has no role history (fail closed, ADR 0011 decision 6). These helpers
// write beside a test's signing key the verification key and the role history a
// real use case writes, so a store-level test can put a key.

func roleOfSKey(k ports.Kind) (custody.Role, ports.Kind, bool) {
	if k == ports.KesSKey {
		return custody.RoleKES, ports.KesVKey, true
	}
	for _, r := range custody.Roles() {
		if kk, ok := ports.KeyKindsOf(r); ok && kk.SKey == k {
			return r, kk.VKey, true
		}
	}
	return "", "", false
}

// seedIdentity writes the verification key of the signing key ref and the role
// history of its identity (the role of the kind, and any extra).
func seedIdentity(w ports.Writer, ref ports.Ref, sec *secret.Buffer, extra ...custody.Role) error {
	role, vk, ok := roleOfSKey(ref.Kind)
	if !ok {
		return nil
	}
	// the "verification key" is the SHA-256 of the signing key's bytes, which is what
	// fakeDeriver derives, so a key that is not the record's pair fails the recovery check
	h := sha256.Sum256(secretBytes(sec))
	env := pool.MarshalEnvelope(pool.Envelope{Type: "VerificationKey_ed25519", Description: "", CborHex: "5820" + hex.EncodeToString(h[:])})
	vref := ports.Ref{Anchor: ref.Anchor, Kind: vk, Num: ref.Num}
	if err := w.Put(vref, env); err != nil {
		return err
	}
	id, err := ports.IdentityOfVKey(role, env)
	if err != nil {
		return err
	}
	hist, err := custody.NewRoleHistory(id, role)
	if err != nil {
		return err
	}
	for _, r := range extra {
		if hist, err = hist.With(r); err != nil {
			return err
		}
	}
	b, err := hist.Canonical()
	if err != nil {
		return err
	}
	return w.Put(ports.Ref{Anchor: id, Kind: ports.RoleHistory}, b)
}

// putKeyW is w.PutSecret for a signing key, with its identity written first.
func putKeyW(w ports.Writer, ref ports.Ref, s *secret.Buffer) error {
	if err := seedIdentity(w, ref, s); err != nil {
		return err
	}
	return w.PutSecret(ref, s)
}

// coldPass is a cold source for the standard policy: it always answers pass.
func coldPass(pass string) *ColdSource {
	return &ColdSource{Passphrase: func(ctx context.Context, create bool) (*secret.Buffer, error) {
		return secret.Take([]byte(pass)), nil
	}}
}

func secretBytes(s *secret.Buffer) []byte {
	var b []byte
	s.Use(func(x []byte) error { b = append([]byte(nil), x...); return nil })
	return b
}

// fakeDeriver is the verification-key deriver of the fixture's keys.
type fakeDeriver struct{}

func (fakeDeriver) DeriveVerificationKey(ctx context.Context, sk *secret.Buffer) ([]byte, error) {
	h := sha256.Sum256(secretBytes(sk))
	return h[:], nil
}
