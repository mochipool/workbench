package ports

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// A FactorSource is a device or service that reproduces a 32-byte secret on
// request: a FIDO2 authenticator with the hmac-secret extension (ADR 0011,
// decisions 4 and 8). The unlock path (slot keys, the cold-role sub-key) uses
// it; nothing else does.
//
// What the source returns is a factor output. The derivations that turn
// outputs into slot keys are in platform/seal; the rules about which factors a
// workspace may combine are in domain/unlock. This port only talks to the
// authenticator.

// Sizes of the values this port exchanges.
const (
	FactorSaltSize   = 32 // an hmac-secret salt
	FactorOutputSize = 32 // an hmac-secret output
	FactorIDSize     = 32 // see FactorIDOf
)

// CredProtectRequired is the credProtect level a slot needs: user
// verification required for every assertion (ADR 0011, decision 4).
const CredProtectRequired = 3

// Requirement is what an assertion must prove about the person; it is the
// argument of Assertion.Require. No caller builds one for an unlock: Assert
// always requires user verification (decision 4) and takes only UserPresence
// from its caller (AssertRequest.UserPresence). The sub-key assertions of
// decision 6 need presence. The one request that asks without presence is the
// touch probe inside an adapter's Enrol.
type Requirement struct {
	UserPresence     bool
	UserVerification bool
}

// FactorProfile says what a source can do, so that a use case refuses a source
// that cannot, before any prompt (ADR 0008).
type FactorProfile struct {
	HMACSecret       bool // the hmac-secret extension
	TwoSalts         bool // one assertion with a current and a next salt
	CredProtect3     bool // enrolment can require credProtect 3
	UserVerification bool // the authenticator can verify the user (a PIN set, or built-in)
	CTAP21           bool // getInfo reports FIDO_2_1 or FIDO_2_1_PRE
	// ClientPIN and BuiltinUV say how verification is done: a PIN that is set,
	// or a built-in method (a fingerprint reader) that is configured.
	ClientPIN, BuiltinUV bool
}

// FactorNeed is a set of capabilities a use case needs of a source.
type FactorNeed uint8

const (
	NeedHMACSecret FactorNeed = 1 << iota
	NeedTwoSalts
	NeedCredProtect3
	NeedUserVerification
	NeedCTAP21
)

// NeedsOfSlot is what a slot with user verification needs of its source:
// hmac-secret, credProtect 3 and user verification.
const NeedsOfSlot = NeedHMACSecret | NeedCredProtect3 | NeedUserVerification | NeedCTAP21

// NeedsOfColdSubKey adds the two-salt assertion that the rotating salt of the
// cold-role sub-key uses (decision 6).
const NeedsOfColdSubKey = NeedsOfSlot | NeedTwoSalts

// ErrFactorCapability is returned by CheckFactorProfile.
var ErrFactorCapability = errors.New("the factor source lacks a capability this operation needs")

// CheckFactorProfile returns nil when p has every capability in need, else an
// error that names each one that is missing. A caller runs it before it asks
// the operator for anything.
func CheckFactorProfile(p FactorProfile, need FactorNeed) error {
	var missing []string
	add := func(bit FactorNeed, ok bool, name string) {
		if need&bit != 0 && !ok {
			missing = append(missing, name)
		}
	}
	add(NeedHMACSecret, p.HMACSecret, "hmac-secret")
	add(NeedTwoSalts, p.TwoSalts, "assertion with two salts")
	add(NeedCredProtect3, p.CredProtect3, "credProtect level 3")
	add(NeedUserVerification, p.UserVerification, "user verification (no PIN set and no built-in verification)")
	add(NeedCTAP21, p.CTAP21, "CTAP 2.1 (getInfo reports neither FIDO_2_1 nor FIDO_2_1_PRE)")
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrFactorCapability, strings.Join(missing, ", "))
	}
	return nil
}

// TouchProbe is the result of the enrolment probe of ADR 0011, "Limit": an
// assertion with user presence disabled, made with a PIN token.
type TouchProbe uint8

const (
	// TouchProbeNotRun: the source did not run the probe (no PIN given, or a
	// source that cannot).
	TouchProbeNotRun TouchProbe = iota
	// TouchEnforced: the authenticator named a refusal of the request without
	// presence (FIDO_ERR_UP_REQUIRED or FIDO_ERR_OPERATION_DENIED).
	TouchEnforced
	// TouchNotEnforced: the authenticator returned an output without a touch.
	// The slot listing shows "touch not enforced", and the touch requirement of
	// the sub-key is a stated residual risk, not a guarantee.
	TouchNotEnforced
	// TouchUnknown: the probe ran and failed in a way that says nothing about the
	// touch (a deadline, a usage error, malformed output). A listing shows it as
	// not confirmed enforced.
	TouchUnknown
)

func (p TouchProbe) String() string {
	switch p {
	case TouchEnforced:
		return "touch enforced"
	case TouchNotEnforced:
		return "touch not enforced"
	case TouchUnknown:
		return "touch enforcement not confirmed"
	}
	return "touch probe not run"
}

// EnrolRequest asks a source to make a credential.
type EnrolRequest struct {
	// Device selects an authenticator; its meaning is the source's (a path for
	// the libfido2 tools). Empty means the only one connected, and the source
	// fails when there are several or none.
	Device string
	// RPID is the relying-party id, `spo.<genesis nonce in hex>` (decision 4).
	RPID string
	// PIN is the authenticator PIN. When nil the authenticator's own user
	// verification (a fingerprint reader), or the source's own prompt, is used.
	// Enrolment always requires user verification (decision 4); a source refuses
	// an authenticator that cannot verify the user. The source never keeps it.
	PIN *Secret
}

// Enrolment is what making a credential returns.
type Enrolment struct {
	CredentialID []byte
	// CredProtect is the level the authenticator confirmed in the
	// makeCredential output (0 when it confirmed none).
	CredProtect int
	// Versions are the strings of the authenticator's getInfo.
	Versions []string
	// FactorID is FactorIDOf(CredentialID): the id the slot stores and binds.
	FactorID []byte
	// Touch is the result of the probe.
	Touch TouchProbe
}

// AssertRequest asks a source for the hmac-secret output of one credential.
type AssertRequest struct {
	Device       string
	CredentialID []byte
	RPID         string
	// Salt is the current salt (FactorSaltSize bytes).
	Salt []byte
	// NextSalt, when not nil, is a second salt, answered in the same assertion.
	NextSalt []byte
	// UserPresence asks for a touch (the sub-key assertions of decision 6). User
	// verification is always required and cannot be switched off here.
	UserPresence bool
	PIN          *Secret
}

// Assertion is the answer.
type Assertion struct {
	Output     *Secret // for Salt, FactorOutputSize bytes
	NextOutput *Secret // for NextSalt; nil when no next salt was asked
	// UP and UV are the user-presence and user-verification flags of the
	// authenticator data, as the authenticator set them.
	UP, UV bool
}

// Destroy wipes the outputs.
func (a Assertion) Destroy() {
	if a.Output != nil {
		a.Output.Destroy()
	}
	if a.NextOutput != nil {
		a.NextOutput.Destroy()
	}
}

// Errors a FactorSource returns. An implementation wraps them with detail that
// holds no secret.
var (
	ErrFactorNoDevice     = errors.New("no FIDO2 authenticator found, or the choice is ambiguous")
	ErrFactorNoCredential = errors.New("the authenticator does not hold this credential")
	ErrFactorPIN          = errors.New("the authenticator refused the PIN")
	ErrFactorPINBlocked   = errors.New("the authenticator's PIN is blocked")
	ErrFactorTimeout      = errors.New("the authenticator was not touched in time")
	// ErrFactorUPRefused: the authenticator named a refusal of a request made
	// without user presence (FIDO_ERR_UP_REQUIRED, FIDO_ERR_OPERATION_DENIED).
	ErrFactorUPRefused   = errors.New("the authenticator refused the request")
	ErrFactorUnsupported = errors.New("the authenticator cannot serve as a factor")
	// ErrFactorFlags: the assertion lacks the user presence or verification
	// flag that was required. The outputs are destroyed.
	ErrFactorFlags = errors.New("the assertion lacks the required user presence or verification")
	// ErrFactorMalformed: the source's answer has the wrong shape (a wrong
	// length, an output equal to the other output, no output).
	ErrFactorMalformed = errors.New("the factor source returned a malformed answer")
)

// Require is the one caller-side check of the flags (ADR 0011, decision 4,
// "the client's UV-flag check stays as a second line"): it refuses an
// assertion whose UP flag is missing when req asks for presence, or whose UV
// flag is missing when req asks for verification. On refusal the outputs are
// destroyed, so a refused assertion holds no secret. It is not enforcement (an
// attacker runs their own client); the authenticator's credProtect is.
func (a Assertion) Require(req Requirement) error {
	switch {
	case req.UserVerification && !a.UV:
		a.Destroy()
		return fmt.Errorf("%w: the user-verification flag is not set", ErrFactorFlags)
	case req.UserPresence && !a.UP:
		a.Destroy()
		return fmt.Errorf("%w: the user-presence flag is not set", ErrFactorFlags)
	}
	return nil
}

// FactorSource is the port. An implementation reports its profile and must not
// be wired into an operation whose needs the profile does not meet.
type FactorSource interface {
	// Profile reads what the authenticator on the device can do (for the libfido2
	// tools: getInfo). Enrol and Assert check it against NeedsOfSlot before they
	// ask for a PIN or a touch.
	Profile(ctx context.Context, device string) (FactorProfile, error)
	// Enrol makes a credential bound to req.RPID with hmac-secret and credProtect
	// level 3. It refuses an authenticator that does not confirm level 3,
	// whatever versions it reports (decision 4).
	Enrol(ctx context.Context, req EnrolRequest) (Enrolment, error)
	// Assert returns the output for req.Salt, and for req.NextSalt when set. It
	// has applied Assertion.Require (UV always, UP when asked) before it returns.
	Assert(ctx context.Context, req AssertRequest) (Assertion, error)
}

// PINChecker is the optional capability of a FactorSource that can check an
// authenticator PIN without a credential or a touch: a rotation uses it to
// verify the PINs of both authenticators before it makes any credential, so a
// wrong PIN leaves no orphan credential and burns no retry on a loop (ADR 0011
// decision 4, per-device PIN). For the libfido2 tools the check is an assertion
// for a credential id that cannot exist, with user presence off: the PIN token
// is obtained (and a wrong PIN refused) before the authenticator looks for the
// credential, so ErrFactorNoCredential means the PIN was right. That order is
// the CTAP 2.1 flow as libfido2 implements it and has not been run on a device.
type PINChecker interface {
	CheckPIN(ctx context.Context, device string, pin *Secret) error
}

// FactorIDOf is the factor id of a FIDO2 credential: SHA-256 over a label and
// the credential id, so it is fixed-size, public and the same wherever the
// credential id is known (decision 8).
func FactorIDOf(credentialID []byte) []byte {
	h := sha256.New()
	h.Write([]byte("spo/factor-id/fido2-credential\x00"))
	h.Write(credentialID)
	return h.Sum(nil)
}
