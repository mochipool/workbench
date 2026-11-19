package envelope

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Local is a Private behind the ports of use cases: it seals and opens
// without handing out a key. It implements ports.LocalIdentity.
type Local struct {
	p    *Private
	rand io.Reader
}

var _ ports.LocalIdentity = (*Local)(nil)

// NewLocal wraps a Private. rand is the source of message ids; nil means
// crypto/rand. Local takes ownership of p: Destroy wipes it.
func NewLocal(p *Private, r io.Reader) *Local {
	if r == nil {
		r = rand.Reader
	}
	return &Local{p: p, rand: r}
}

func (l *Local) Identity() party.Identity { return l.p.Identity() }
func (l *Local) Destroy()                 { l.p.Destroy() }

// SignRelayDeviceRevoke implements relayport.DeviceRevokeSigner: the device
// signs its own revoke (ADR 0014 decision 7). The signed bytes are built here
// by relaybind.DeviceRevokeBytes from this identity's own fingerprint and the
// not-before, so the identity cannot be made to sign another device's revoke or
// any other bytes; a not-before outside 0 to relaybind.MaxTime, or above the
// bound the caller gives (relay time plus the skew: the method has no clock), is
// refused and nothing is signed.
//
// spec: SPO-Xrelaybind-INV-005
func (l *Local) SignRelayDeviceRevoke(notBefore, notBeforeBound int64) ([64]byte, error) {
	if notBefore > notBeforeBound {
		return [64]byte{}, fmt.Errorf("%w: not-before %d is above the bound %d", relaybind.ErrRevokeFuture, notBefore, notBeforeBound)
	}
	msg, err := relaybind.DeviceRevokeBytes(l.p.Fingerprint(), notBefore)
	if err != nil {
		return [64]byte{}, err
	}
	return l.p.sign(msg)
}

var _ relayport.DeviceRevokeSigner = (*Local)(nil)

// Seal implements ports.EnvelopeSealer.
func (l *Local) Seal(to party.Identity, body party.Body, now, expires time.Time) ([]byte, party.MessageID, error) {
	return Seal(l.p, to, body, now, expires, l.rand)
}

// Open implements ports.EnvelopeOpener.
func (l *Local) Open(env []byte, lookup func(party.Fingerprint) (party.Party, bool), now time.Time) (ports.OpenedEnvelope, error) {
	o, err := Open(l.p, env, lookup, now)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// Audit implements ports.EnvelopeOpener.
func (l *Local) Audit(err error) (string, party.Fingerprint, bool) { return Audit(err) }

// IsRefusal implements ports.EnvelopeOpener.
func (l *Local) IsRefusal(err error) bool {
	var r *Refusal
	return errors.As(err, &r)
}

// *Opened is a ports.OpenedEnvelope.
var _ ports.OpenedEnvelope = (*Opened)(nil)

// Kit implements ports.IdentityKit over a store and a vault. The private
// keys are read from the vault into guarded memory for one use and wiped by
// the caller with Local.Destroy.
type Kit struct {
	Store ports.NamedStore
	Vault ports.NamedVault
	// Rand is the entropy of key generation and message ids; nil means
	// crypto/rand.
	Rand io.Reader
}

var _ ports.IdentityKit = Kit{}

func (k Kit) rnd() io.Reader {
	if k.Rand == nil {
		return rand.Reader
	}
	return k.Rand
}

// LocalName is the name of the workspace's own identity records.
const LocalName = "local"

// Generate makes a new identity and its signed public document.
func (k Kit) Generate(label string, node *party.NodeKey, now time.Time) (ports.GeneratedIdentity, error) {
	p, err := Generate(label, node, now, k.rnd())
	if err != nil {
		return ports.GeneratedIdentity{}, err
	}
	doc, err := EncodeDocument(p)
	if err != nil {
		p.Destroy()
		return ports.GeneratedIdentity{}, err
	}
	// The key buffer goes to the caller, who stores and destroys it; the
	// Private is not used again.
	return ports.GeneratedIdentity{Keys: p.Keys(), Document: doc, Identity: p.Identity()}, nil
}

// ParseDocument implements ports.IdentityKit.
func (Kit) ParseDocument(b []byte) (party.Document, error) { return ParseDocument(b) }

// ErrNoIdentity: the workspace has no party identity yet.
var ErrNoIdentity = errors.New("envelope: this workspace has no party identity: run the identity initialisation first")

// Local implements ports.IdentityKit.
func (k Kit) Local(ctx context.Context) (ports.LocalIdentity, error) {
	p, err := k.private(ctx)
	if err != nil {
		return nil, err
	}
	return NewLocal(p, k.Rand), nil
}

// private loads the workspace's own identity with its private keys. The caller
// destroys it.
func (k Kit) private(ctx context.Context) (*Private, error) {
	var raw []byte
	err := k.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		raw, err = r.Get(ports.NamedRef{Name: LocalName, Kind: ports.PartyIdentity})
		return err
	})
	if errors.Is(err, ports.ErrNotFound) {
		return nil, ErrNoIdentity
	}
	if err != nil {
		return nil, err
	}
	doc, err := ParseDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("the stored identity document: %w", err)
	}
	if err := doc.Verify(); err != nil {
		return nil, fmt.Errorf("the stored identity document: %w", err)
	}
	keys, err := k.Vault.Open(ctx, ports.NamedRef{Name: LocalName, Kind: ports.PartyKeys})
	if err != nil {
		return nil, fmt.Errorf("the identity's private keys: %w", err)
	}
	return NewPrivate(keys, doc.Identity) // takes ownership of keys
}
