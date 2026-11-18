// Package fakesk is an in-memory FIDO2 signing authenticator for tests: it
// implements ports.SignatureFactor with real P-256 keys, so what it signs
// verifies with the Go standard library and with ssh-keygen. It is not a
// stand-in for a device's behaviour beyond that (the e2e tests drive the libfido2
// adapter against test/hardware/fakefido).
package fakesk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Source is the authenticator set: devices by path, each with a PIN.
type Source struct {
	mu sync.Mutex
	// PINs maps a device path to its PIN; a device not listed is absent.
	PINs map[string]string
	// DropUP and DropUV clear the flag in the signed authenticator data.
	DropUP, DropUV bool
	// Counter is the signature counter of the next assertion; it increments.
	Counter uint32
	// Enrols and Signs count the calls.
	Enrols, Signs int
	// LastDevice is the device of the last call; LastCredential the credential id of
	// the last enrolment.
	LastDevice     string
	LastCredential []byte
	// OnSign, when set, runs at the start of SignAssert (a test records order).
	OnSign func()
	// FailSign makes SignAssert return this error.
	FailSign error

	keys map[string]*ecdsa.PrivateKey // by credential id
	cred map[string]string            // credential id -> device
}

// New returns a source with the given devices (path to PIN).
func New(pins map[string]string) *Source {
	return &Source{PINs: pins, keys: map[string]*ecdsa.PrivateKey{}, cred: map[string]string{}}
}

var _ ports.SignatureFactor = (*Source)(nil)

func (s *Source) checkPIN(dev string, pin *ports.Secret) error {
	want, ok := s.PINs[dev]
	if !ok {
		return ports.ErrFactorNoDevice
	}
	var got string
	if pin != nil {
		_ = pin.Use(func(b []byte) error { got = string(b); return nil })
	}
	if got != want {
		return ports.ErrFactorPIN
	}
	return nil
}

// EnrolSigner implements ports.SignatureFactor.
func (s *Source) EnrolSigner(_ context.Context, req ports.SignerEnrolRequest) (ports.SignerEnrolment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Enrols++
	s.LastDevice = req.Device
	if err := s.checkPIN(req.Device, req.PIN); err != nil {
		return ports.SignerEnrolment{}, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	id := make([]byte, 48)
	if _, err := rand.Read(id); err != nil {
		return ports.SignerEnrolment{}, err
	}
	s.keys[string(id)] = k
	s.cred[string(id)] = req.Device
	s.LastCredential = id
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	return ports.SignerEnrolment{CredentialID: id, PublicKey: pub, Versions: []string{"FIDO_2_1"}}, nil
}

// SignAssert implements ports.SignatureFactor.
func (s *Source) SignAssert(_ context.Context, req ports.SignRequest) (ports.SignAssertion, error) {
	if s.OnSign != nil {
		s.OnSign()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Signs++
	s.LastDevice = req.Device
	if s.FailSign != nil {
		return ports.SignAssertion{}, s.FailSign
	}
	if err := s.checkPIN(req.Device, req.PIN); err != nil {
		return ports.SignAssertion{}, err
	}
	k, ok := s.keys[string(req.CredentialID)]
	if !ok || s.cred[string(req.CredentialID)] != req.Device {
		return ports.SignAssertion{}, ports.ErrFactorNoCredential
	}
	if len(req.ClientDataHash) != 32 {
		return ports.SignAssertion{}, errors.New("fakesk: the client data hash is not 32 bytes")
	}
	flags := byte(0x01 | 0x04)
	if s.DropUP {
		flags &^= 0x01
	}
	if s.DropUV {
		flags &^= 0x04
	}
	s.Counter++
	app := sha256.Sum256([]byte(req.RPID))
	data := append([]byte(nil), app[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, s.Counter)
	data = append(data, req.ClientDataHash...)
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
	if err != nil {
		return ports.SignAssertion{}, err
	}
	return ports.SignAssertion{Flags: flags, Counter: s.Counter, Signature: sig}, nil
}
