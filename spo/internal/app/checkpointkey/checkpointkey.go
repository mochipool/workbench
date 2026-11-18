// Package checkpointkey is the use case of ADR 0012 stage 2 for the checkpoint
// key of a workspace: enrol one, show it, replace or remove it. The key is a
// FIDO2 credential used as an OpenSSH security-key signing key; the workspace
// keeps its public key, credential id and key hash in one sealed record.
//
// The rules (decision 13):
//   - the authenticator must not be the authenticator of any daily slot;
//   - the recovery authenticator may be the checkpoint authenticator (the trade-off
//     is for the operator: the recovery token is then used at every backup);
//   - the first enrolment needs only the unlocked workspace;
//   - enrolling when one exists, or removing one, needs the current recovery
//     credential (standard and hardware) or, for a strict workspace, which has no
//     recovery path, a valid signature by the EXISTING checkpoint key over a
//     replacement statement.
package checkpointkey

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Records keeps the one record. Load returns nil when there is none.
type Records interface {
	Load(ctx context.Context) (*checkpoint.KeyRecord, error)
	Save(ctx context.Context, r checkpoint.KeyRecord) error
	Delete(ctx context.Context) error
}

// Env is what the operations need of the workspace and the wiring.
type Env struct {
	WorkspaceID []byte
	// Policy is standard, hardware or strict.
	Policy  string
	Records Records
	// DailyCredentials lists the credential ids of the daily slots.
	DailyCredentials func(ctx context.Context) ([][]byte, error)
	Signer           ports.SignatureFactor
	// ProveRecovery presents the current recovery credential (the recovery key
	// and, under hardware, the second authenticator) and checks it against the
	// workspace; it is called only under standard and hardware, before any
	// credential is made.
	ProveRecovery func(ctx context.Context) error
	Now           func() time.Time
	// MaxAge bounds how old a replacement statement may be (default 10 minutes).
	MaxAge time.Duration
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Errors of the rules.
var (
	ErrDailyDevice  = errors.New("the checkpoint authenticator is the daily authenticator of this session: use another token, so that the checkpoint key and the daily slot are never on one authenticator")
	ErrDailyToken   = errors.New("this authenticator recognises a daily credential of the workspace: it is the daily token, however it is named; use another token")
	ErrDailyCred    = errors.New("the checkpoint credential is a credential of a daily slot")
	ErrNoKey        = errors.New("this workspace has no checkpoint key")
	ErrNeedOldKey   = errors.New("this workspace is strict and already has a checkpoint key: it has no recovery path, so replacing or removing the key needs a signature by the EXISTING checkpoint key (--old-checkpoint-device)")
	ErrNeedRecovery = errors.New("this workspace already has a checkpoint key: replacing or removing it needs the current recovery credential")
)

// EnrolInput is the authenticator to enrol and, for a strict workspace that
// already has a key, the existing key's.
type EnrolInput struct {
	Device string
	PIN    func(ctx context.Context) (*ports.Secret, error)
	Notify func(string)
	// SessionDevice is the authenticator the workspace was unlocked with in this
	// command (FactorSession: through FIDO2 factors); it may not be the checkpoint
	// authenticator.
	SessionDevice string
	FactorSession bool
	// DailyRPID is the relying-party id of the daily credentials (spo.<workspace
	// id>), for the probe of the checkpoint token.
	DailyRPID string
	// Old signs the replacement statement with the existing key (strict only).
	Old *OldKey
}

// OldKey is the existing checkpoint key's authenticator.
type OldKey struct {
	Device string
	PIN    func(ctx context.Context) (*ports.Secret, error)
	Notify func(string)
}

func (e Env) signing(old checkpoint.KeyRecord, k *OldKey) interface {
	Sign(context.Context, string, []byte) ([]byte, error)
} {
	return signer{env: e, old: old, key: k}
}

type signer struct {
	env Env
	old checkpoint.KeyRecord
	key *OldKey
}

func (s signer) Sign(ctx context.Context, namespace string, text []byte) ([]byte, error) {
	return signWith(ctx, s.env.Signer, s.old, s.key.Device, s.key.PIN, s.key.Notify, namespace, text)
}

func signWith(ctx context.Context, src ports.SignatureFactor, rec checkpoint.KeyRecord, device string, pinFn func(context.Context) (*ports.Secret, error), notify func(string), namespace string, text []byte) ([]byte, error) {
	signed, err := sshsig.SignedData(namespace, sshsig.SHA512, text)
	if err != nil {
		return nil, err
	}
	var pin *ports.Secret
	if pinFn != nil {
		if pin, err = pinFn(ctx); err != nil {
			return nil, err
		}
		if pin != nil {
			defer pin.Destroy()
		}
	}
	if notify != nil {
		notify("touch the existing checkpoint authenticator to authorise the change")
	}
	a, err := src.SignAssert(ctx, ports.SignRequest{Device: device, RPID: checkpoint.Application, CredentialID: rec.CredentialID, ClientDataHash: sshsig.ClientDataHash(signed), PIN: pin})
	if err != nil {
		return nil, err
	}
	blob, err := sshsig.Encode(rec.Key, namespace, sshsig.SHA512, sshsig.Assertion{Flags: a.Flags, Counter: a.Counter, Signature: a.Signature})
	if err != nil {
		return nil, err
	}
	if _, err := sshsig.Verify(blob, text, namespace, rec.Hash(), checkpoint.Application); err != nil {
		return nil, fmt.Errorf("the answer is not a valid signature by the existing checkpoint key: %w", err)
	}
	return []byte(sshsig.Armor(blob)), nil
}

// authorise applies the rule for changing an existing key: the recovery
// credential under standard and hardware, the old key's signature under strict.
// newKeyHash is nil for a removal. For standard and hardware it must be called
// before any credential is made (call authoriseRecovery); the strict part needs
// the new key's hash and is call after.
func (e Env) authoriseRecovery(ctx context.Context) error {
	if e.Policy == "strict" {
		return nil
	}
	if e.ProveRecovery == nil {
		return ErrNeedRecovery
	}
	return e.ProveRecovery(ctx)
}

func (e Env) authoriseStrict(ctx context.Context, old checkpoint.KeyRecord, k *OldKey, newHash []byte) error {
	if e.Policy != "strict" {
		return nil
	}
	if k == nil {
		return ErrNeedOldKey
	}
	text := checkpoint.Replacement{WorkspaceID: e.WorkspaceID, OldKeyHash: old.Hash(), NewKeyHash: newHash, Time: e.now().UTC().Truncate(time.Second)}.Encode()
	armored, err := e.signing(old, k).Sign(ctx, checkpoint.TagReplace, text)
	if err != nil {
		return err
	}
	maxAge := e.MaxAge
	if maxAge == 0 {
		maxAge = 10 * time.Minute
	}
	return checkpoint.VerifyReplacement(text, armored, old, e.WorkspaceID, newHash, e.now(), maxAge)
}

// Enrol makes the checkpoint key on the authenticator and records it. It returns
// the record and whether it replaced an existing one.
func Enrol(ctx context.Context, e Env, in EnrolInput) (rec checkpoint.KeyRecord, replaced bool, err error) {
	if e.Signer == nil {
		return rec, false, errors.New("this build has no FIDO2 signing support (the libfido2 tools are not in the toolchain manifest): nothing was asked")
	}
	// (a) the same token: the session's device and the checkpoint device compared
	// after the source resolved them (auto-pick, symbolic links), not as typed
	if in.FactorSession {
		sess, dev := in.SessionDevice, in.Device
		if r, ok := e.Signer.(ports.DeviceResolver); ok {
			var err error
			if sess, err = r.ResolveDevice(ctx, in.SessionDevice); err != nil {
				return rec, false, err
			}
			if dev, err = r.ResolveDevice(ctx, in.Device); err != nil {
				return rec, false, err
			}
		}
		if sess == dev {
			return rec, false, ErrDailyDevice
		}
	}
	old, err := e.Records.Load(ctx)
	if err != nil {
		return rec, false, err
	}
	if old != nil {
		replaced = true
		if e.Policy == "strict" && in.Old == nil {
			return rec, false, ErrNeedOldKey
		}
		// before any credential is made, so that a refusal leaves none behind
		if err := e.authoriseRecovery(ctx); err != nil {
			return rec, false, err
		}
	}
	var pin *ports.Secret
	if in.PIN != nil {
		if pin, err = in.PIN(ctx); err != nil {
			return rec, false, err
		}
		if pin != nil {
			defer pin.Destroy()
		}
	}
	// (b) the probe: before a credential is made, ask the candidate token whether it
	// holds any daily credential. Under standard there is none (a passphrase unlocks
	// it), so only rule (a) applies there.
	if pr, ok := e.Signer.(ports.CredentialProber); ok && in.DailyRPID != "" {
		dailyNow, derr := e.DailyCredentials(ctx)
		if derr != nil {
			return rec, false, derr
		}
		for _, d := range dailyNow {
			held, perr := pr.HoldsCredential(ctx, in.Device, in.DailyRPID, d, pin)
			if perr != nil {
				return rec, false, fmt.Errorf("cannot tell whether this authenticator holds a daily credential (%w); nothing was made", perr)
			}
			if held {
				return rec, false, ErrDailyToken
			}
		}
	}
	if in.Notify != nil {
		in.Notify("touch the authenticator to make the checkpoint credential")
	}
	en, err := e.Signer.EnrolSigner(ctx, ports.SignerEnrolRequest{Device: in.Device, RPID: checkpoint.Application, PIN: pin})
	if err != nil {
		return rec, false, err
	}
	daily, err := e.DailyCredentials(ctx)
	if err != nil {
		return rec, false, err
	}
	for _, d := range daily {
		if bytes.Equal(d, en.CredentialID) {
			return rec, false, ErrDailyCred
		}
	}
	key := sshsig.Key{Q: en.PublicKey, Application: checkpoint.Application}
	if _, err := sshsig.ParseKeyBlob(key.Blob()); err != nil {
		return rec, false, fmt.Errorf("the authenticator returned a public key that is not a P-256 point: %w", err)
	}
	rec = checkpoint.KeyRecord{Key: key, CredentialID: en.CredentialID, Enrolled: e.now().UTC().Truncate(time.Second)}
	if old != nil {
		if bytes.Equal(old.Hash(), rec.Hash()) {
			return rec, false, errors.New("the new checkpoint key is the existing one")
		}
		if err := e.authoriseStrict(ctx, *old, in.Old, rec.Hash()); err != nil {
			return checkpoint.KeyRecord{}, false, err
		}
	}
	if err := e.Records.Save(ctx, rec); err != nil {
		return checkpoint.KeyRecord{}, false, err
	}
	return rec, replaced, nil
}

// Remove deletes the checkpoint key record.
func Remove(ctx context.Context, e Env, old *OldKey) error {
	cur, err := e.Records.Load(ctx)
	if err != nil {
		return err
	}
	if cur == nil {
		return ErrNoKey
	}
	if e.Policy == "strict" {
		if old == nil {
			return ErrNeedOldKey
		}
		if e.Signer == nil {
			return errors.New("this build has no FIDO2 signing support: nothing was asked")
		}
		if err := e.authoriseStrict(ctx, *cur, old, nil); err != nil {
			return err
		}
	} else if err := e.authoriseRecovery(ctx); err != nil {
		return err
	}
	return e.Records.Delete(ctx)
}

// Show returns the record, or ErrNoKey.
func Show(ctx context.Context, e Env) (checkpoint.KeyRecord, error) {
	r, err := e.Records.Load(ctx)
	if err != nil {
		return checkpoint.KeyRecord{}, err
	}
	if r == nil {
		return checkpoint.KeyRecord{}, ErrNoKey
	}
	return *r, nil
}
