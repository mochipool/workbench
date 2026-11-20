package ports

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// A KeyWrapBackend is a Vault or KMS service that wraps and unwraps the 32-byte
// secret B of one backend factor (ADR 0011, decision 5). B is a factor output
// inside a composite slot; the backend alone never opens a slot, because the
// slot also needs a factor the backend does not control (decision 6).
//
// The credential that the backend asks for belongs to the client: the
// operator's own token, OIDC or JWT identity, or cloud role. An adapter obtains
// it on the client machine and never stores it in the workspace, never puts it
// in an error, a log line, an argument vector or the environment of a child.
//
// The port does not decide which slots exist or how B enters the slot key:
// domain/unlock and platform/seal do. It only talks to the backend.

// Sizes of the values this port exchanges.
const (
	// BackendSecretSize is the length of B.
	BackendSecretSize = 32
	// WrapContextIDSize is the length of the genesis nonce and of the slot id.
	WrapContextIDSize = 16
	// MaxWrappedBlob bounds the wrapped form of B that a backend returns and a
	// slot stores. A Vault Transit ciphertext of 32 bytes is about 90 bytes and an
	// AWS KMS ciphertext blob about 200.
	MaxWrappedBlob = 4096
)

// BackendKind names the service behind a backend factor. It is stored in the
// slot and bound in its associated data.
type BackendKind string

const (
	// BackendVaultTransit is HashiCorp Vault's (or OpenBao's) Transit secrets
	// engine: encrypt and decrypt with associated data on a non-derived key.
	BackendVaultTransit BackendKind = "vault-transit"
	// BackendAWSKMS is AWS KMS Encrypt and Decrypt with an encryption context.
	BackendAWSKMS BackendKind = "aws-kms"
)

// BackendRef is what a slot stores of a backend factor and binds in its
// associated data: where the key lives and which key it is. It holds no
// credential. Read from a slot it is only a claim: the slot row is not
// authenticated until the slot opens, so it is checked against the local
// configuration (CheckBackendClaim) before it is used.
type BackendRef struct {
	Kind BackendKind
	// Address is the base URL of the service: a Vault server, or the KMS
	// endpoint of the key's region.
	Address string
	// Namespace is the Vault namespace (Vault Enterprise, HCP Vault), "" for none
	// and for KMS.
	Namespace string
	// Key is "<transit mount>/<key name>" for Vault and the key ARN for KMS.
	Key string
}

var refText = regexp.MustCompile(`^[\x21-\x7e]+$`)

// Validate checks the shape of a reference: a known kind and printable fields
// of bounded length. The adapter checks the meaning (a URL, an ARN).
func (r BackendRef) Validate() error {
	switch r.Kind {
	case BackendVaultTransit, BackendAWSKMS:
	default:
		return fmt.Errorf("%w: unknown backend kind %q", ErrBackendConfig, r.Kind)
	}
	if len(r.Address) == 0 || len(r.Address) > 512 || !refText.MatchString(r.Address) {
		return fmt.Errorf("%w: the backend address is empty, too long or not printable", ErrBackendConfig)
	}
	if len(r.Key) == 0 || len(r.Key) > 512 || !refText.MatchString(r.Key) {
		return fmt.Errorf("%w: the backend key reference is empty, too long or not printable", ErrBackendConfig)
	}
	if len(r.Namespace) > 256 || (r.Namespace != "" && !refText.MatchString(r.Namespace)) {
		return fmt.Errorf("%w: the backend namespace is too long or not printable", ErrBackendConfig)
	}
	if r.Kind == BackendAWSKMS && r.Namespace != "" {
		return fmt.Errorf("%w: a KMS key has no namespace", ErrBackendConfig)
	}
	return nil
}

// String is the reference as a listing shows it.
func (r BackendRef) String() string {
	s := string(r.Kind) + " " + r.Address
	if r.Namespace != "" {
		s += " namespace " + r.Namespace
	}
	return s + " " + r.Key
}

// Fingerprint is a short digest of the whole reference (kind, address,
// namespace, key): the first 8 bytes of SHA-256 over a label and each field
// with its 4-byte length, as 16 hex digits. It is ClientFingerprint with every
// client-side setting at its default (SPO-Xunlock-OUT-023). It is public, as
// the reference is.
func (r BackendRef) Fingerprint() string { return r.ClientFingerprint(nil) }

// BackendSetting is one client-side setting of spo.toml that decides where a
// credential goes or which identity is asked for (a CA file, a token or JWT
// file, a private endpoint, plain http to loopback), by its key name in the
// file and its value as written: a path, not the file's contents.
type BackendSetting struct{ Name, Value string }

// ClientFingerprint is the fingerprint an operator compares: the reference and
// the client-side settings given, in the order given, each name and value
// preceded by its 4-byte length after the four fields of the reference. With no
// setting it is the reference's own fingerprint. Enrolment prints it, slot list
// and every unlock notice show it, so a change of spo.toml's client settings,
// or of both spo.toml and the slot, is visible to an operator who compares it
// with the one noted at enrolment (SPO-Xunlock-OUT-023). It covers paths and
// flags, not what the files hold: a CA or token file replaced in place keeps it.
func (r BackendRef) ClientFingerprint(settings []BackendSetting) string {
	h := sha256.New()
	h.Write([]byte("spo/backend-ref\x00"))
	put := func(f string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	for _, f := range []string{string(r.Kind), r.Address, r.Namespace, r.Key} {
		put(f)
	}
	for _, s := range settings {
		put(s.Name)
		put(s.Value)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// A BackendFingerprinter is a client that knows the fingerprint of the
// reference and the client-side settings it was built with; the unlock notice
// shows it (SPO-Xunlock-OUT-023). A client without it shows the reference's.
type BackendFingerprinter interface {
	BackendFingerprint() string
}

// FingerprintOf is the fingerprint the notice before an unwrap through kb shows.
func FingerprintOf(kb KeyWrapBackend) string {
	if f, ok := kb.(BackendFingerprinter); ok {
		return f.BackendFingerprint()
	}
	return kb.Ref().Fingerprint()
}

// WrapContext is what a wrap is bound to at the backend: the workspace's
// genesis nonce and the slot's id (decision 5; not the workspace id, for the
// reason in decision 4). A blob moved to another slot or another workspace does
// not unwrap at the backend, and the slot's own associated data refuses it too.
type WrapContext struct {
	GenesisNonce []byte
	SlotID       []byte
}

// Validate checks both ids are WrapContextIDSize bytes.
func (c WrapContext) Validate() error {
	if len(c.GenesisNonce) != WrapContextIDSize || len(c.SlotID) != WrapContextIDSize {
		return fmt.Errorf("%w: the wrap context needs a %d-byte genesis nonce and slot id", ErrBackendConfig, WrapContextIDSize)
	}
	return nil
}

// Encode is the canonical CBOR of [genesis nonce, slot id]: Vault Transit's
// associated_data (decision 5). Both are 16-byte byte strings, so the encoding is
// 0x82, 0x50, nonce, 0x50, slot id: 35 bytes, one form only.
func (c WrapContext) Encode() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+2*WrapContextIDSize)
	out = append(out, 0x82, 0x40|WrapContextIDSize)
	out = append(out, c.GenesisNonce...)
	out = append(out, 0x40|WrapContextIDSize)
	return append(out, c.SlotID...), nil
}

// KMSContext is the AWS KMS encryption context of decision 5:
// {"spo-genesis": <nonce hex>, "spo-slot": <slot id hex>}, lower-case hex.
func (c WrapContext) KMSContext() (map[string]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return map[string]string{"spo-genesis": hex.EncodeToString(c.GenesisNonce), "spo-slot": hex.EncodeToString(c.SlotID)}, nil
}

// KeyWrapBackend wraps and unwraps B at one key of one backend.
type KeyWrapBackend interface {
	// Ref is the backend and key this client talks to.
	Ref() BackendRef
	// Wrap encrypts b (exactly BackendSecretSize bytes) bound to wc and returns
	// the wrapped form, at most MaxWrappedBlob bytes. It does not keep b.
	Wrap(ctx context.Context, b *secret.Buffer, wc WrapContext) ([]byte, error)
	// Unwrap decrypts blob bound to wc. The result is exactly BackendSecretSize
	// bytes in guarded memory, owned by the caller. A blob of another context,
	// another key or a changed byte is refused (ErrBackendRefused).
	Unwrap(ctx context.Context, blob []byte, wc WrapContext) (*secret.Buffer, error)
}

// Errors of a backend. None carries the credential, B, or text the backend
// returned.
var (
	// ErrBackendRefused: the backend refused to unwrap (a wrong context, a
	// changed blob, another key).
	ErrBackendRefused = errors.New("the backend refused to unwrap the factor secret")
	// ErrBackendCredential: no usable credential, or the backend did not accept
	// it.
	ErrBackendCredential = errors.New("the backend credential is missing, refused or not short-lived")
	// ErrBackendConfig: the backend or key is not one this tool accepts (an
	// address without TLS, a key type without associated data, a derived key).
	ErrBackendConfig = errors.New("the backend or its key is not usable")
	// ErrBackendUnavailable: the backend did not answer in time or answered
	// with a server error.
	ErrBackendUnavailable = errors.New("the backend is not reachable or did not answer")
	// ErrBackendResponse: the backend's answer is not what the protocol allows
	// (too large, malformed, another key id, a secret of the wrong length, a
	// redirect).
	ErrBackendResponse = errors.New("the backend answered with something this tool does not accept")
	// ErrBackendMismatch: the backend a slot names is not the one the operator's
	// local configuration names. The reference a slot stores is a claim, and
	// the local configuration is the authority: a mismatch is refused before any
	// credential is loaded, any other factor is asked for or any call is made.
	ErrBackendMismatch = errors.New("the backend a slot names is not the one spo.toml names; the workspace file may have been altered")
)

// CheckBackendClaim compares the reference a slot stores (claim) with the one
// the local configuration names (local). Every field must be byte-equal; the
// error shows both, which are public parameters.
func CheckBackendClaim(claim, local BackendRef) error {
	if claim == local {
		return nil
	}
	return fmt.Errorf("%w: the slot names %s, spo.toml names %s", ErrBackendMismatch, claim, local)
}
