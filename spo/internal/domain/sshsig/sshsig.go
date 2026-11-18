// Package sshsig builds and verifies OpenSSH signatures (PROTOCOL.sshsig) made
// by a FIDO2 security key of type sk-ecdsa-sha2-nistp256@openssh.com (the
// signature layout of PROTOCOL.u2f), with the Go standard library only. It is
// pure: no I/O, no adapter.
//
// A security-key signature is a FIDO2 assertion. The authenticator signs
//
//	SHA-256(application) || flags || counter || SHA-256(message)
//
// with ECDSA over P-256 (the assertion's authenticator data is the first 37
// bytes of that, the client data hash the last 32), so a caller can produce one
// from an assertion without ssh-keygen and without a key file. The message of
// the SSHSIG layer is the blob "SSHSIG" || namespace || reserved || hash
// algorithm || H(data) (SignedData), and its SHA-256 is the client data hash.
//
// What this package enforces that a library verifier does not: both the
// user-presence and the user-verification flag must be set in the signed flags
// byte, the namespace must be the expected one, the key type must be the
// expected one, and nothing may follow the structures.
//
// Confirmed against ssh-keygen -Y verify (see the oracle test): the signature
// blob, the SSHSIG framing, the armor and the signed data. Not confirmed on a
// real authenticator: that an assertion whose authenticator data carries no
// extension output is what libfido2 returns for a request without extensions.
package sshsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// KeyType is the one key type this package handles.
const KeyType = "sk-ecdsa-sha2-nistp256@openssh.com"

// Flags of the signed authenticator data.
const (
	FlagUP = 0x01
	FlagUV = 0x04
)

// Armor lines of a signature file.
const (
	ArmorBegin = "-----BEGIN SSH SIGNATURE-----"
	ArmorEnd   = "-----END SSH SIGNATURE-----"
)

const magic = "SSHSIG"

// Key is a security-key public key: the uncompressed P-256 point and the
// application (relying-party id) the credential was made for.
type Key struct {
	Q           []byte // 65 bytes: 0x04 || X || Y
	Application string
}

// ErrFormat is returned for anything that is not exactly the expected form.
var ErrFormat = errors.New("sshsig: malformed")

func formatErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, a...))
}

// ---- SSH wire encoding ----

func putString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

type reader struct{ b []byte }

func (r *reader) string() ([]byte, error) {
	if len(r.b) < 4 {
		return nil, formatErr("truncated")
	}
	n := binary.BigEndian.Uint32(r.b)
	if uint64(n) > uint64(len(r.b)-4) {
		return nil, formatErr("a string is longer than the data")
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, nil
}

func (r *reader) byte() (byte, error) {
	if len(r.b) < 1 {
		return 0, formatErr("truncated")
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}

func (r *reader) uint32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, formatErr("truncated")
	}
	n := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return n, nil
}

func (r *reader) done() error {
	if len(r.b) != 0 {
		return formatErr("%d trailing bytes", len(r.b))
	}
	return nil
}

// mpint encodes a non-negative integer as an SSH mpint.
func mpint(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b
}

// ---- keys ----

// Blob is the SSH wire-format public key.
func (k Key) Blob() []byte {
	var b []byte
	b = putString(b, []byte(KeyType))
	b = putString(b, []byte("nistp256"))
	b = putString(b, k.Q)
	return putString(b, []byte(k.Application))
}

// Hash is SHA-256 of the wire-format public key blob: the value ssh-keygen
// prints as the key's SHA256 fingerprint (base64 of these bytes).
func (k Key) Hash() []byte {
	h := sha256.Sum256(k.Blob())
	return h[:]
}

// Fingerprint is the OpenSSH text of Hash: SHA256:<unpadded base64>.
func (k Key) Fingerprint() string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(k.Hash())
}

// AuthorizedLine is the key as one line of an authorized_keys or
// allowed_signers file (without the principal): "<type> <base64 blob>".
func (k Key) AuthorizedLine() string {
	return KeyType + " " + base64.StdEncoding.EncodeToString(k.Blob())
}

func (k Key) publicKey() (*ecdsa.PublicKey, error) {
	if len(k.Q) != 65 || k.Q[0] != 4 {
		return nil, formatErr("the public point is not an uncompressed P-256 point")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.Q)
	if err != nil {
		return nil, formatErr("the public point is not on the curve")
	}
	return pub, nil
}

// ParseKeyBlob reads a wire-format public key strictly.
func ParseKeyBlob(blob []byte) (Key, error) {
	r := &reader{blob}
	typ, err := r.string()
	if err != nil {
		return Key{}, err
	}
	if string(typ) != KeyType {
		return Key{}, formatErr("the key type is not %s", KeyType)
	}
	curve, err := r.string()
	if err != nil {
		return Key{}, err
	}
	if string(curve) != "nistp256" {
		return Key{}, formatErr("the curve is not nistp256")
	}
	q, err := r.string()
	if err != nil {
		return Key{}, err
	}
	app, err := r.string()
	if err != nil {
		return Key{}, err
	}
	if err := r.done(); err != nil {
		return Key{}, err
	}
	k := Key{Q: append([]byte(nil), q...), Application: string(app)}
	if _, err := k.publicKey(); err != nil {
		return Key{}, err
	}
	return k, nil
}

// KeyFromCOSE builds a key from the x and y of an ES256 COSE public key.
func KeyFromCOSE(x, y []byte, application string) (Key, error) {
	if len(x) != 32 || len(y) != 32 {
		return Key{}, formatErr("a P-256 coordinate is not 32 bytes")
	}
	q := append(append([]byte{4}, x...), y...)
	k := Key{Q: q, Application: application}
	if _, err := k.publicKey(); err != nil {
		return Key{}, err
	}
	return k, nil
}

// ---- the signed data ----

// HashAlgorithm names the hash of the message inside the signed data.
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "sha256"
	SHA512 HashAlgorithm = "sha512"
)

func (h HashAlgorithm) sum(msg []byte) ([]byte, error) {
	switch h {
	case SHA256:
		s := sha256.Sum256(msg)
		return s[:], nil
	case SHA512:
		s := sha512.Sum512(msg)
		return s[:], nil
	}
	return nil, formatErr("unknown hash algorithm %q", string(h))
}

// SignedData is the blob the SSHSIG layer signs: the preamble, the namespace,
// the reserved string, the hash algorithm and the hash of the message. The
// namespace must not be empty.
func SignedData(namespace string, alg HashAlgorithm, message []byte) ([]byte, error) {
	if namespace == "" {
		return nil, formatErr("the namespace is empty")
	}
	h, err := alg.sum(message)
	if err != nil {
		return nil, err
	}
	b := []byte(magic)
	b = putString(b, []byte(namespace))
	b = putString(b, nil)
	b = putString(b, []byte(alg))
	return putString(b, h), nil
}

// ClientDataHash is what the authenticator is asked to sign over: SHA-256 of
// the signed data (OpenSSH passes it to the authenticator as the client data
// hash).
func ClientDataHash(signedData []byte) []byte {
	h := sha256.Sum256(signedData)
	return h[:]
}

// Assertion is the part of an authenticator's answer that a signature needs.
type Assertion struct {
	Flags   byte
	Counter uint32
	// Signature is the ASN.1 DER ECDSA signature (r, s) the authenticator made.
	Signature []byte
}

// skSigned is what the authenticator signed.
func skSigned(application string, flags byte, counter uint32, clientDataHash []byte) []byte {
	app := sha256.Sum256([]byte(application))
	b := append([]byte(nil), app[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, counter)
	return append(b, clientDataHash...)
}

type ecdsaSig struct{ R, S *big.Int }

func parseDER(der []byte) (r, s *big.Int, err error) {
	var sig ecdsaSig
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, nil, formatErr("the ECDSA signature is not a DER sequence of two positive integers")
	}
	return sig.R, sig.S, nil
}

// signatureBlob is the sk-ecdsa signature of PROTOCOL.u2f.
func signatureBlob(r, s *big.Int, flags byte, counter uint32) []byte {
	var inner []byte
	inner = putString(inner, mpint(r))
	inner = putString(inner, mpint(s))
	var b []byte
	b = putString(b, []byte(KeyType))
	b = putString(b, inner)
	b = append(b, flags)
	return binary.BigEndian.AppendUint32(b, counter)
}

// Encode wraps an assertion as an SSHSIG blob (not armored). The caller has
// already made the assertion over ClientDataHash(SignedData(namespace, alg,
// message)); Encode checks nothing about it (Verify does).
func Encode(key Key, namespace string, alg HashAlgorithm, a Assertion) ([]byte, error) {
	if namespace == "" {
		return nil, formatErr("the namespace is empty")
	}
	if _, err := alg.sum(nil); err != nil {
		return nil, err
	}
	r, s, err := parseDER(a.Signature)
	if err != nil {
		return nil, err
	}
	b := []byte(magic)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = putString(b, key.Blob())
	b = putString(b, []byte(namespace))
	b = putString(b, nil)
	b = putString(b, []byte(alg))
	return putString(b, signatureBlob(r, s, a.Flags, a.Counter)), nil
}

// Armor is the text form of a signature blob: 76-column base64 between the
// armor lines.
func Armor(blob []byte) string {
	enc := base64.StdEncoding.EncodeToString(blob)
	var sb strings.Builder
	sb.WriteString(ArmorBegin + "\n")
	for len(enc) > 70 {
		sb.WriteString(enc[:70] + "\n")
		enc = enc[70:]
	}
	if enc != "" {
		sb.WriteString(enc + "\n")
	}
	sb.WriteString(ArmorEnd + "\n")
	return sb.String()
}

// Dearmor reads the armored form strictly: the two armor lines, base64 in
// between, and nothing before or after (one final line feed is allowed).
func Dearmor(text []byte) ([]byte, error) {
	s := string(text)
	s = strings.TrimSuffix(s, "\n")
	lines := strings.Split(s, "\n")
	if len(lines) < 3 || lines[0] != ArmorBegin || lines[len(lines)-1] != ArmorEnd {
		return nil, formatErr("not an armored SSH signature")
	}
	for _, l := range lines[1 : len(lines)-1] {
		if l == "" {
			return nil, formatErr("a blank line in the armored body")
		}
	}
	body := strings.Join(lines[1:len(lines)-1], "")
	if strings.ContainsAny(body, " \t\r") {
		return nil, formatErr("whitespace in the armored body")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(body)
	if err != nil {
		return nil, formatErr("the armored body is not base64")
	}
	return b, nil
}

// Result is what a verified signature says.
type Result struct {
	Key     Key
	Flags   byte
	Counter uint32
}

// Verify checks a signature blob (Dearmor first) over message in namespace.
// The key is whatever the blob carries; wantKeyHash, when not nil, is the hash
// the key must have (Key.Hash) and the application must be wantApplication when
// that is not empty. A signature without both the user-presence and the
// user-verification flag is refused.
func Verify(blob, message []byte, namespace string, wantKeyHash []byte, wantApplication string) (Result, error) {
	if namespace == "" {
		return Result{}, formatErr("the namespace is empty")
	}
	r := &reader{blob}
	if len(r.b) < len(magic) || string(r.b[:len(magic)]) != magic {
		return Result{}, formatErr("no SSHSIG preamble")
	}
	r.b = r.b[len(magic):]
	ver, err := r.uint32()
	if err != nil {
		return Result{}, err
	}
	if ver != 1 {
		return Result{}, formatErr("unknown signature version %d", ver)
	}
	keyBlob, err := r.string()
	if err != nil {
		return Result{}, err
	}
	ns, err := r.string()
	if err != nil {
		return Result{}, err
	}
	reserved, err := r.string()
	if err != nil {
		return Result{}, err
	}
	algName, err := r.string()
	if err != nil {
		return Result{}, err
	}
	sigBlob, err := r.string()
	if err != nil {
		return Result{}, err
	}
	if err := r.done(); err != nil {
		return Result{}, err
	}
	if string(ns) != namespace {
		return Result{}, formatErr("the namespace is %q, not %q", string(ns), namespace)
	}
	if len(reserved) != 0 {
		return Result{}, formatErr("the reserved string is not empty")
	}
	key, err := ParseKeyBlob(keyBlob)
	if err != nil {
		return Result{}, err
	}
	if wantKeyHash != nil && !bytes.Equal(key.Hash(), wantKeyHash) {
		return Result{}, errors.New("sshsig: the signing key is not the expected key")
	}
	if wantApplication != "" && key.Application != wantApplication {
		return Result{}, formatErr("the key's application is %q, not %q", key.Application, wantApplication)
	}
	sr := &reader{sigBlob}
	typ, err := sr.string()
	if err != nil {
		return Result{}, err
	}
	if string(typ) != KeyType {
		return Result{}, formatErr("the signature type is not %s", KeyType)
	}
	inner, err := sr.string()
	if err != nil {
		return Result{}, err
	}
	flags, err := sr.byte()
	if err != nil {
		return Result{}, err
	}
	counter, err := sr.uint32()
	if err != nil {
		return Result{}, err
	}
	if err := sr.done(); err != nil {
		return Result{}, err
	}
	ir := &reader{inner}
	rb, err := ir.string()
	if err != nil {
		return Result{}, err
	}
	sb, err := ir.string()
	if err != nil {
		return Result{}, err
	}
	if err := ir.done(); err != nil {
		return Result{}, err
	}
	rr, ss := new(big.Int).SetBytes(rb), new(big.Int).SetBytes(sb)
	if len(rb) > 0 && rb[0]&0x80 != 0 || len(sb) > 0 && sb[0]&0x80 != 0 {
		return Result{}, formatErr("a negative signature integer")
	}
	if flags&FlagUP == 0 {
		return Result{}, errors.New("sshsig: the signature does not carry the user-presence flag")
	}
	if flags&FlagUV == 0 {
		return Result{}, errors.New("sshsig: the signature does not carry the user-verification flag")
	}
	signed, err := SignedData(namespace, HashAlgorithm(algName), message)
	if err != nil {
		return Result{}, err
	}
	pub, err := key.publicKey()
	if err != nil {
		return Result{}, err
	}
	digest := sha256.Sum256(skSigned(key.Application, flags, counter, ClientDataHash(signed)))
	if !ecdsa.Verify(pub, digest[:], rr, ss) {
		return Result{}, errors.New("sshsig: the signature does not verify")
	}
	return Result{Key: key, Flags: flags, Counter: counter}, nil
}
