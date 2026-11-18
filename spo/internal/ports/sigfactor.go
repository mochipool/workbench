package ports

import "context"

// SignatureFactor is the optional capability of a FIDO2 source that makes a
// signing credential and answers assertions over a caller-chosen client data
// hash (ADR 0012 decision 13, stage 2: the checkpoint key). It is separate from
// FactorSource on purpose: the unlock path never signs, and a source that cannot
// sign does not have to pretend.
//
// A security-key SSH signature is such an assertion (OpenSSH PROTOCOL.u2f): the
// authenticator signs SHA-256(rp id) || flags || counter || client data hash, so
// no key file and no ssh-keygen is needed to make one.
type SignatureFactor interface {
	// EnrolSigner makes a credential (ES256) bound to req.RPID and returns its
	// public key. Enrolment requires user verification.
	EnrolSigner(ctx context.Context, req SignerEnrolRequest) (SignerEnrolment, error)
	// SignAssert asks the authenticator for an assertion over req.ClientDataHash
	// with user presence AND user verification. The answer is checked by the
	// source for the flags and the shape of the authenticator data (37 bytes, no
	// extensions); the verifier checks them again in the signed data.
	SignAssert(ctx context.Context, req SignRequest) (SignAssertion, error)
}

// SignerEnrolRequest asks a source to make a signing credential.
type SignerEnrolRequest struct {
	// Device selects an authenticator (see EnrolRequest.Device).
	Device string
	// RPID is the relying-party id, for the checkpoint key `ssh:spo-checkpoint`.
	RPID string
	// PIN is the authenticator PIN; nil lets the authenticator or the source ask.
	PIN *Secret
}

// SignerEnrolment is what a signing enrolment returns.
type SignerEnrolment struct {
	CredentialID []byte
	// PublicKey is the uncompressed P-256 point: 0x04 || X || Y (65 bytes).
	PublicKey []byte
	// Versions are the strings of the authenticator's getInfo.
	Versions []string
}

// SignRequest asks for one signature.
type SignRequest struct {
	Device       string
	RPID         string
	CredentialID []byte
	// ClientDataHash is the 32 bytes to sign (for an SSH signature, SHA-256 of
	// the SSHSIG signed data).
	ClientDataHash []byte
	PIN            *Secret
}

// SignAssertion is the answer of SignAssert.
type SignAssertion struct {
	// Flags and Counter are those of the authenticator data.
	Flags   byte
	Counter uint32
	// Signature is the ASN.1 DER ECDSA signature.
	Signature []byte
}

// DeviceResolver is the optional capability of a source that can say which
// authenticator a device selector really names: the one a command with no
// selector would auto-pick, and a path with its symbolic links followed. The
// checkpoint key is kept off the daily token by comparing resolved paths, not
// the strings the operator typed.
type DeviceResolver interface {
	ResolveDevice(ctx context.Context, device string) (string, error)
}

// CredentialProber is the optional capability of a source that can ask an
// authenticator whether it holds a credential, without a touch (an assertion with
// user presence off, as the touch probe of an enrolment makes). The checkpoint
// enrolment asks it of the candidate token for each daily credential: an
// authenticator that recognises one is the daily token, however it is named.
type CredentialProber interface {
	// HoldsCredential reports whether the device holds the credential for rpID.
	// An error means the answer is not known.
	HoldsCredential(ctx context.Context, device, rpID string, credentialID []byte, pin *Secret) (bool, error)
}
