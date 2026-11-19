package sqlitestore

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// FactorInputs is what OpenWithFactors uses to unlock through a fido2-hmac or
// composite slot (ADR 0011, decisions 3 and 4). Source is required. A callback
// that is nil means the caller cannot provide that factor, and a slot that
// needs it is skipped.
type FactorInputs struct {
	// Source talks to the authenticator.
	Source ports.FactorSource
	// Device selects an authenticator (the source's meaning); empty is the only
	// one connected.
	Device string
	// PIN returns the authenticator PIN, or nil when the authenticator verifies
	// the user itself. It is asked once per assertion, after the capability check
	// and before the authenticator is touched.
	PIN func(ctx context.Context) (*secret.Buffer, error)
	// Passphrase returns the passphrase of a passphrase factor of a composite.
	Passphrase func(ctx context.Context) (*secret.Buffer, error)
	// Recovery returns the raw 32-byte recovery key of a recovery factor of a
	// composite.
	Recovery func(ctx context.Context) (*secret.Buffer, error)
	// Notify, when set, is told what the operator is about to be asked for
	// ("touch the authenticator"), before the authenticator is asked.
	Notify func(msg string)
	// Backend returns the client of the Vault or KMS backend that a backend
	// factor of a slot names (the reference the slot stores). nil: the caller
	// cannot present a backend factor, and a slot with one is skipped. The
	// credential is the client's: the store never sees it.
	Backend func(ctx context.Context, ref ports.BackendRef) (ports.KeyWrapBackend, error)
	// BackendCheck compares the reference a backend factor of a slot claims with
	// the operator's local configuration (spo.toml), with no credential and no
	// call: the slot row is not authenticated until the slot opens. It runs for
	// every backend factor of a slot before any factor of that slot is asked for
	// (no passphrase prompt, no authenticator, no credential loaded); an error
	// ends the open. Inputs with Backend and no BackendCheck fail closed.
	BackendCheck func(ref ports.BackendRef) error
}

// presentable checks, before any factor of the slot is asked for, that the
// inputs can present every factor (errSkipSlot when not) and that every backend
// factor names the backend of the local configuration.
func presentable(ts tslot, in *FactorInputs) error {
	for _, f := range ts.fs.Spec.Factors {
		switch f.Kind {
		case seal.FactorBackend:
			if in.Backend == nil {
				return errSkipSlot
			}
			if err := checkBackendClaim(ts.id, backendRefOf(f), in); err != nil {
				return err
			}
		case seal.FactorPassphrase:
			if in.Passphrase == nil {
				return errSkipSlot
			}
		case seal.FactorRecovery:
			if in.Recovery == nil {
				return errSkipSlot
			}
		case seal.FactorFIDO2:
			if in.Source == nil {
				return errSkipSlot
			}
		}
	}
	return nil
}

// canPresent reports whether the inputs can present any factor of a fido2-hmac
// or composite slot.
func (in *FactorInputs) canPresent() bool {
	return in != nil && (in.Source != nil || in.Backend != nil)
}

// ErrNoFactorSlot: no fido2-hmac or composite slot could be opened with the
// factors the caller can present.
var ErrNoFactorSlot = errors.New("sqlitestore: no slot of the workspace opens with the factors presented")

// OpenWithFactors unlocks the workspace through a fido2-hmac or composite slot.
// The slot table is checked against its policy first, so a table that breaks it
// is refused before any authenticator is asked.
func OpenWithFactors(path string, in FactorInputs, o OpenOptions) (*Store, error) {
	if !in.canPresent() {
		return nil, errors.New("sqlitestore: no factor source")
	}
	return open(path, credential{kind: credFactors, factors: &in}, false, o)
}

// factorOutput produces the output of one factor of the slot spec.
func factorOutput(ctx context.Context, spec seal.SlotSpec, f seal.FactorParams, in *FactorInputs) (*secret.Buffer, error) {
	switch f.Kind {
	case seal.FactorBackend:
		return backendOutput(ctx, spec, f, in)
	case seal.FactorPassphrase:
		if in.Passphrase == nil {
			return nil, errSkipSlot
		}
		if err := f.KDF.Validate(); err != nil {
			return nil, err
		}
		pw, err := in.Passphrase(ctx)
		if err != nil {
			return nil, err
		}
		defer pw.Destroy()
		return seal.PassphraseFactorOutput(pw, f.KDFSalt, f.KDF)
	case seal.FactorRecovery:
		if in.Recovery == nil {
			return nil, errSkipSlot
		}
		return in.Recovery(ctx)
	case seal.FactorFIDO2:
		if in.Source == nil {
			return nil, errSkipSlot
		}
		prof, err := in.Source.Profile(ctx, in.Device)
		if err != nil {
			return nil, err
		}
		if err := ports.CheckFactorProfile(prof, ports.NeedsOfSlot); err != nil {
			return nil, err
		}
		var pin *secret.Buffer
		if in.PIN != nil {
			if pin, err = in.PIN(ctx); err != nil {
				return nil, err
			}
			defer pin.Destroy()
		}
		if in.Notify != nil {
			in.Notify("touch the authenticator")
		}
		a, err := in.Source.Assert(ctx, ports.AssertRequest{Device: in.Device, CredentialID: f.CredentialID, RPID: f.RPID,
			Salt: f.HMACSalt, UserPresence: true, PIN: pin})
		if err != nil {
			return nil, err
		}
		if err := a.Require(ports.Requirement{UserPresence: true, UserVerification: true}); err != nil {
			return nil, err
		}
		if a.NextOutput != nil {
			a.NextOutput.Destroy()
		}
		return a.Output, nil
	}
	return nil, fmt.Errorf("%w: factor kind %d", seal.ErrFormat, f.Kind)
}

var errSkipSlot = errors.New("slot needs a factor the caller cannot present")

func unlockFactors(ctx context.Context, t *table, in *FactorInputs, accept func(*secret.Buffer) (bool, error)) (master *secret.Buffer, used []byte, notices []string, err error) {
	unwrapped, tried := false, false
	work := uint64(0)
	for _, ts := range t.slots {
		if !ts.isFactor() {
			continue
		}
		skip := func(why string) {
			notices = append(notices, fmt.Sprintf("skipped %s slot %x: %s", ts.kind, ts.id[:min(4, len(ts.id))], why))
		}
		var outs []*secret.Buffer
		destroy := func() {
			for _, o := range outs {
				o.Destroy()
			}
		}
		skipSlot := false
		heavy := uint64(0)
		for _, f := range ts.fs.Spec.Factors {
			if f.Kind == seal.FactorPassphrase {
				heavy += uint64(f.KDF.MemoryKiB/1024) * uint64(f.KDF.Passes)
			}
		}
		// before any factor of this slot is asked for: can every factor be
		// presented, and is every backend the one the local configuration names
		switch perr := presentable(ts, in); {
		case errors.Is(perr, errSkipSlot):
			skip("a factor of it is not available")
			continue
		case perr != nil:
			return nil, nil, notices, perr
		}
		if work+heavy > maxUnlockWork {
			skip("the unlock has already done the most key-derivation work it allows")
			continue
		}
		work += heavy
		for _, f := range ts.fs.Spec.Factors {
			o, ferr := factorOutput(ctx, ts.fs.Spec, f, in)
			switch {
			case errors.Is(ferr, errSkipSlot), errors.Is(ferr, ports.ErrFactorNoCredential), errors.Is(ferr, seal.ErrWeakKDF), errors.Is(ferr, seal.ErrFormat):
				skip("a factor of it is not available")
				skipSlot = true
			case ferr != nil:
				destroy()
				return nil, nil, notices, ferr
			default:
				outs = append(outs, o)
			}
			if skipSlot {
				break
			}
		}
		if skipSlot {
			destroy()
			continue
		}
		tried = true
		mk, uerr := ts.fs.Unwrap(outs)
		destroy()
		switch {
		case errors.Is(uerr, seal.ErrAuth):
			continue
		case errors.Is(uerr, seal.ErrFormat):
			skip("malformed")
			continue
		case uerr != nil:
			return nil, nil, notices, uerr
		}
		unwrapped = true
		ok, aerr := accept(mk)
		if aerr != nil || !ok {
			mk.Destroy()
			if aerr != nil {
				return nil, nil, notices, aerr
			}
			skip("it opens a master key of an earlier key epoch (a rekey replaced it)")
			continue
		}
		return mk, ts.id, notices, nil
	}
	switch {
	case unwrapped:
		err = ErrKeyEpoch
	case tried:
		err = ErrWrongCredential
	default:
		err = ErrNoFactorSlot
	}
	return nil, nil, notices, err
}

// Reauthenticate asks the authenticator for a fresh presentation of the factors
// of a slot of the current table (PIN and touch, as an unlock does) and checks
// that it opens the master key this handle holds. It is the approval gate of a
// factor session (ADR 0011, Amends ADR 0005: "a fresh presentation of a factor
// that the workspace policy accepts"). It fails closed: with no factor source it
// refuses, and a presentation that opens a different master key, or no slot,
// is an error. Nothing is written.
func (s *Store) Reauthenticate(ctx context.Context, in FactorInputs) error {
	if !in.canPresent() {
		return errors.New("sqlitestore: no factor source to present a factor to: nothing was approved")
	}
	release, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer release()
	t, err := s.currentTable(ctx)
	if err != nil {
		return err
	}
	if err := t.check(); err != nil {
		return err
	}
	mk, _, _, err := unlockFactors(ctx, t, &in, func(m *secret.Buffer) (bool, error) {
		same := false
		m.Use(func(a []byte) error {
			return s.master.Use(func(b []byte) error { same = len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1; return nil })
		})
		return same, nil
	})
	if err != nil {
		return err
	}
	mk.Destroy()
	return nil
}

// refreshFactorOutput proves possession of a FIDO2 factor with its stored salt
// and in the same assertion (two salts, CTAP 2.1) obtains the output for a fresh
// salt, so a slot re-created by a rotation or a removal does not keep the
// hmac-secret output a removed party may have captured. It returns the factor
// with the new salt and the output for it.
func refreshFactorOutput(ctx context.Context, f seal.FactorParams, in *FactorInputs) (seal.FactorParams, *secret.Buffer, *secret.Buffer, error) {
	prof, err := in.Source.Profile(ctx, in.Device)
	if err != nil {
		return f, nil, nil, err
	}
	if err := ports.CheckFactorProfile(prof, ports.NeedsOfColdSubKey); err != nil {
		return f, nil, nil, err
	}
	var pin *secret.Buffer
	if in.PIN != nil {
		if pin, err = in.PIN(ctx); err != nil {
			return f, nil, nil, err
		}
		defer pin.Destroy()
	}
	next := make([]byte, ports.FactorSaltSize)
	if _, err := rand.Read(next); err != nil {
		return f, nil, nil, err
	}
	if in.Notify != nil {
		in.Notify("touch the authenticator")
	}
	a, err := in.Source.Assert(ctx, ports.AssertRequest{Device: in.Device, CredentialID: f.CredentialID, RPID: f.RPID,
		Salt: f.HMACSalt, NextSalt: next, UserPresence: true, PIN: pin})
	if err != nil {
		return f, nil, nil, err
	}
	if err := a.Require(ports.Requirement{UserPresence: true, UserVerification: true}); err != nil {
		return f, nil, nil, err
	}
	if a.NextOutput == nil {
		a.Output.Destroy()
		return f, nil, nil, fmt.Errorf("%w: no output for the fresh salt", ports.ErrFactorMalformed)
	}
	f.HMACSalt = next
	// The old-salt output is returned, not discarded: the caller unwraps the
	// existing slot with it, so an authenticator that merely answers is not
	// trusted as the slot's factor.
	return f, a.NextOutput, a.Output, nil
}
