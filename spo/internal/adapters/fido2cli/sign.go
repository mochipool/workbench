package fido2cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.SignatureFactor = (*Source)(nil)

// EnrolSigner makes an ES256 credential for req.RPID with user verification
// required and credProtect level 3 (as an unlock credential), and no hmac-secret:
// a signing credential (not resident). It
// returns the credential id and the public key from the attested credential
// data. The PIN handling is that of Enrol: a PIN the caller holds goes to the
// tool's stdin in a session without a terminal; with built-in verification the
// tool asks the authenticator.
//
// What the tools do for these options is read from their man pages and source
// (libfido2 1.16.0) and has not been run on a device.
//
// spec: SPO-Xbackup-EXT-001
func (s *Source) EnrolSigner(ctx context.Context, req ports.SignerEnrolRequest) (ports.SignerEnrolment, error) {
	if err := checkLine("relying-party id", req.RPID); err != nil {
		return ports.SignerEnrolment{}, err
	}
	device, err := s.device(ctx, req.Device)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	in, err := s.getInfo(ctx, device)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	prof := in.profile()
	if err := ports.CheckFactorProfile(prof, ports.NeedUserVerification|ports.NeedCredProtect3); err != nil {
		return ports.SignerEnrolment{}, err
	}
	var (
		uvArgs []execx.Arg
		stdin  io.WriterTo
		noTerm bool
	)
	switch {
	case req.PIN != nil:
		if err := checkPIN(req.PIN); err != nil {
			return ports.SignerEnrolment{}, err
		}
		if !prof.ClientPIN {
			return ports.SignerEnrolment{}, fmt.Errorf("%w: a PIN was given but the authenticator has none set", ports.ErrFactorUnsupported)
		}
		stdin, noTerm = withNewline{req.PIN}, true
	case prof.BuiltinUV:
		uvArgs = execx.Lits("-v", "-q")
	case prof.ClientPIN && s.PromptOnTerminal:
	default:
		return ports.SignerEnrolment{}, fmt.Errorf("%w: it needs a PIN and none was given", ports.ErrFactorUnsupported)
	}
	cdh, err := s.random(32)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	uid, err := s.random(32)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	params := b64(cdh) + "\n" + req.RPID + "\nspo-checkpoint\n" + b64(uid) + "\n"
	args := append(execx.Lits("-M", "-c", fmt.Sprint(ports.CredProtectRequired)), uvArgs...)
	args = append(args, execx.Lit("-i"), execx.SecretIn(strings.NewReader(params)), execx.Lit(device), execx.Lit("es256"))
	path, err := s.tool(ctx, ports.FIDO2Cred)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	res, err := s.Runner.Run(ctx, execx.Cmd{Path: path, Args: args, Env: env, StdinSecret: stdin, NoTerminal: noTerm, MaxOutput: maxText})
	if err != nil {
		return ports.SignerEnrolment{}, classify(ctx, res, err, "fido2-cred -M")
	}
	lines := strings.Split(strings.TrimRight(string(res.Stdout), "\n"), "\n")
	if len(lines) < 6 || lines[1] != req.RPID {
		return ports.SignerEnrolment{}, fmt.Errorf("%w: unexpected fido2-cred output", ports.ErrFactorMalformed)
	}
	credID, err := decodeB64(lines[4])
	if err != nil || len(credID) == 0 {
		return ports.SignerEnrolment{}, fmt.Errorf("%w: credential id", ports.ErrFactorMalformed)
	}
	authData, err := decodeAuthData(lines[3])
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	ad, err := parseCredAuthData(authData, req.RPID)
	if err != nil {
		return ports.SignerEnrolment{}, err
	}
	if !bytes.Equal(ad.credID, credID) {
		return ports.SignerEnrolment{}, fmt.Errorf("%w: the credential id differs from the one in the authenticator data", ports.ErrFactorMalformed)
	}
	if ad.flags&flagUV == 0 {
		return ports.SignerEnrolment{}, fmt.Errorf("%w: the credential was made without user verification", ports.ErrFactorFlags)
	}
	if ad.credProtect != ports.CredProtectRequired {
		return ports.SignerEnrolment{}, fmt.Errorf("%w: the authenticator confirmed credProtect level %d, not %d", ports.ErrFactorUnsupported, ad.credProtect, ports.CredProtectRequired)
	}
	if len(ad.x) != 32 || len(ad.y) != 32 {
		return ports.SignerEnrolment{}, fmt.Errorf("%w: the credential has no ES256 public key", ports.ErrFactorMalformed)
	}
	pub := append(append([]byte{4}, ad.x...), ad.y...)
	return ports.SignerEnrolment{CredentialID: credID, PublicKey: pub, Versions: in.versions}, nil
}

// SignAssert asks for an assertion over req.ClientDataHash, with user
// verification (the PIN, or the authenticator's own method) and user presence,
// and no extension. It refuses an answer whose authenticator data is not the 37
// fixed bytes for this relying party or lacks either flag.
//
// spec: SPO-Xbackup-EXT-002, SPO-Xbackup-IF-005
func (s *Source) SignAssert(ctx context.Context, req ports.SignRequest) (ports.SignAssertion, error) {
	if err := checkLine("relying-party id", req.RPID); err != nil {
		return ports.SignAssertion{}, err
	}
	if len(req.CredentialID) == 0 || len(req.ClientDataHash) != 32 {
		return ports.SignAssertion{}, errors.New("a signature needs a credential id and a 32-byte client data hash")
	}
	device, err := s.device(ctx, req.Device)
	if err != nil {
		return ports.SignAssertion{}, err
	}
	in, err := s.getInfo(ctx, device)
	if err != nil {
		return ports.SignAssertion{}, err
	}
	prof := in.profile()
	if err := ports.CheckFactorProfile(prof, ports.NeedUserVerification); err != nil {
		return ports.SignAssertion{}, err
	}
	vargs, stdin, noTerm, err := s.verifyArgs(req.PIN, prof)
	if err != nil {
		return ports.SignAssertion{}, err
	}
	params := b64(req.ClientDataHash) + "\n" + req.RPID + "\n" + b64(req.CredentialID) + "\n"
	args := append(execx.Lits("-G", "-p"), vargs...)
	var out execx.Captured
	args = append(args, execx.Lit("-i"), execx.SecretIn(strings.NewReader(params)), execx.Lit("-o"), execx.SecretOutMax(&out, maxSecret), execx.Lit(device))
	path, err := s.tool(ctx, ports.FIDO2Assert)
	if err != nil {
		return ports.SignAssertion{}, err
	}
	res, err := s.Runner.Run(ctx, execx.Cmd{Path: path, Args: args, Env: env, StdinSecret: stdin, NoTerminal: noTerm, MaxOutput: maxText})
	captured := out.Buffer()
	if captured != nil {
		defer captured.Destroy()
	}
	if err != nil {
		return ports.SignAssertion{}, classify(ctx, res, err, "fido2-assert -G")
	}
	if captured == nil {
		return ports.SignAssertion{}, fmt.Errorf("%w: no output", ports.ErrFactorMalformed)
	}
	var sa ports.SignAssertion
	err = captured.Use(func(b []byte) error {
		lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
		if len(lines) != 4 || string(lines[1]) != req.RPID {
			return fmt.Errorf("%w: unexpected fido2-assert output", ports.ErrFactorMalformed)
		}
		if got, derr := decodeB64(string(lines[0])); derr != nil || !bytes.Equal(got, req.ClientDataHash) {
			return fmt.Errorf("%w: the tool signed another client data hash", ports.ErrFactorMalformed)
		}
		authData, derr := decodeAuthData(string(lines[2]))
		if derr != nil {
			return derr
		}
		flags, counter, derr := signAuthData(authData, req.RPID)
		if derr != nil {
			return derr
		}
		sig, derr := decodeB64(string(lines[3]))
		if derr != nil || len(sig) == 0 {
			return fmt.Errorf("%w: signature", ports.ErrFactorMalformed)
		}
		sa = ports.SignAssertion{Flags: flags, Counter: counter, Signature: sig}
		return nil
	})
	if err != nil {
		return ports.SignAssertion{}, err
	}
	if sa.Flags&flagUV == 0 {
		return ports.SignAssertion{}, fmt.Errorf("%w: the user-verification flag is not set", ports.ErrFactorFlags)
	}
	if sa.Flags&flagUP == 0 {
		return ports.SignAssertion{}, fmt.Errorf("%w: the user-presence flag is not set", ports.ErrFactorFlags)
	}
	return sa, nil
}

var (
	_ ports.DeviceResolver   = (*Source)(nil)
	_ ports.CredentialProber = (*Source)(nil)
)

// ResolveDevice returns the device a selector names: the only connected one when
// the selector is empty, and a path with its symbolic links followed (a path that
// cannot be resolved is returned cleaned).
//
// spec: SPO-Xbackup-PRE-016
func (s *Source) ResolveDevice(ctx context.Context, device string) (string, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return "", err
	}
	if r, rerr := filepath.EvalSymlinks(d); rerr == nil {
		return r, nil
	}
	return filepath.Clean(d), nil
}

// HoldsCredential asks the authenticator for an assertion on the credential with
// user presence off and user verification on, and no touch. "Holds" is an answer
// with an output, or the named refusal of a request without presence (the
// authenticator found the credential and wanted a touch); "does not hold" is
// FIDO_ERR_NO_CREDENTIALS. Anything else (a wrong PIN, a timeout) is an error.
// Not run on a real authenticator: that credProtect 3 credentials answer this
// way when asked with a PIN token is the CTAP 2.1 flow as libfido2 implements it.
//
// spec: SPO-Xbackup-PRE-016
func (s *Source) HoldsCredential(ctx context.Context, device, rpID string, credentialID []byte, pin *ports.Secret) (bool, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return false, err
	}
	in, err := s.getInfo(ctx, d)
	if err != nil {
		return false, err
	}
	prof := in.profile()
	if err := ports.CheckFactorProfile(prof, ports.NeedUserVerification); err != nil {
		return false, err
	}
	salt, err := s.random(ports.FactorSaltSize)
	if err != nil {
		return false, err
	}
	a, err := s.assertRaw(ctx, ports.AssertRequest{Device: d, CredentialID: credentialID, RPID: rpID, Salt: salt, PIN: pin}, prof, true)
	switch {
	case err == nil:
		a.Destroy()
		return true, nil
	case errors.Is(err, ports.ErrFactorUPRefused):
		return true, nil
	case errors.Is(err, ports.ErrFactorNoCredential):
		return false, nil
	}
	return false, err
}
