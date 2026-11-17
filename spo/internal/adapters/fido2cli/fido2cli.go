// Package fido2cli implements ports.FactorSource by driving the libfido2
// command-line tools fido2-token, fido2-cred and fido2-assert, pinned in the
// toolchain manifest (ADR 0011, decision 8). There is no cgo and no Go CTAP
// library on the unlock path.
//
// What the tools require, read from their man pages and source (libfido2
// 1.16.0, the version the flake pins, and 1.17.0; none of it has been run against a
// device):
//
//   - fido2-cred -M and fido2-assert -G read their parameters as newline
//     separated lines from stdin or from -i, and write their answer to stdout or
//     -o. Here the parameters are on a pipe (-i /dev/fd/N) and an assertion's
//     answer, which holds the hmac secret, is read from a pipe into guarded
//     memory (-o /dev/fd/M). Nothing is written to a file.
//   - The PIN is read by readpassphrase, which opens /dev/tty first and reads
//     stdin only when there is no controlling terminal. A PIN the caller holds is
//     therefore sent on stdin, through a pipe, to a child started in a new
//     session (execx.Cmd.NoTerminal). With no PIN and PromptOnTerminal set the
//     tool prompts on the terminal itself and this process never sees it.
//   - fido2-assert -h takes the hmac salt as one base64 blob that libfido2
//     accepts at 32 or 64 bytes, and prints the hmac secret as one base64 blob of
//     the same length: two salts are one 64-byte blob.
//   - The authenticator data the tools print is the CBOR byte string around the
//     raw data. The UP and UV flags and the credProtect level are read from it.
//
// The adapter never touches a device on its own: it is wired by cmd/spo only,
// and its tests run against test/hardware/fakefido.
package fido2cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Source drives the pinned libfido2 tools.
type Source struct {
	Tools  ports.Toolchain
	Runner execx.Runner
	// PromptOnTerminal lets the tool ask for the PIN on the terminal when the
	// caller holds none. Without it, a request that needs verification and has no
	// PIN uses the authenticator's own user verification (a fingerprint reader).
	PromptOnTerminal bool
	// Rand is the source of client-data hashes, user ids and the probe salt;
	// crypto/rand when nil.
	Rand io.Reader
}

var _ ports.FactorSource = (*Source)(nil)

func (s *Source) rng() io.Reader {
	if s.Rand != nil {
		return s.Rand
	}
	return rand.Reader
}

var env = []string{"LC_ALL=C", "LANGUAGE=C"}

// tool locates one of the three tools through the toolchain.
func (s *Source) tool(ctx context.Context, n ports.ToolName) (string, error) {
	t, err := s.Tools.Tool(ctx, n)
	if err != nil {
		return "", err
	}
	return t.Path, nil
}

// checkLine refuses what cannot be one input line of the tools.
func checkLine(what, v string) error {
	if v == "" || strings.ContainsAny(v, "\n\r\x00") {
		return fmt.Errorf("%s is empty or contains a line break", what)
	}
	return nil
}

// checkDevice refuses a device selector that a tool would read as an option.
func checkDevice(d string) error {
	if err := checkLine("device", d); err != nil {
		return err
	}
	if strings.HasPrefix(d, "-") {
		return errors.New("device selector must not start with '-'")
	}
	return nil
}

// devices lists the authenticators the operating system shows
// (`fido2-token -L`: one line "path: vendor=..., product=... (name)" each).
func (s *Source) device(ctx context.Context, chosen string) (string, error) {
	if chosen != "" {
		if err := checkDevice(chosen); err != nil {
			return "", err
		}
		return chosen, nil
	}
	path, err := s.tool(ctx, ports.FIDO2Token)
	if err != nil {
		return "", err
	}
	res, err := s.Runner.Run(ctx, execx.Cmd{Path: path, Args: execx.Lits("-L"), Env: env, MaxOutput: maxText})
	if err != nil {
		return "", fmt.Errorf("%w: fido2-token -L failed", ports.ErrFactorNoDevice)
	}
	var found []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if p, _, ok := strings.Cut(line, ": "); ok && strings.TrimSpace(p) != "" {
			found = append(found, strings.TrimSpace(p))
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%w: none connected", ports.ErrFactorNoDevice)
	case 1:
		return found[0], checkDevice(found[0])
	}
	return "", fmt.Errorf("%w: %d connected, choose one", ports.ErrFactorNoDevice, len(found))
}

// info is what `fido2-token -I` printed that matters here.
type info struct {
	versions   []string
	extensions []string
	options    map[string]bool // names present as printed: "clientPin" true; "noclientPin" false
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// parseInfo reads the `version strings:`, `extension strings:` and `options:`
// lines. fido2-token prints an option that is false with the prefix "no"
// (tools/token.c, print_opt_array), so only the exact names clientPin, uv and
// pinUvAuthToken are looked up: "noclientPin" is not "clientPin".
func parseInfo(out []byte) info {
	in := info{options: map[string]bool{}}
	for _, line := range strings.Split(string(out), "\n") {
		list := func(prefix string) ([]string, bool) {
			rest, ok := strings.CutPrefix(line, prefix)
			if !ok {
				return nil, false
			}
			var l []string
			for _, f := range strings.Split(rest, ",") {
				if f = strings.TrimSpace(f); f != "" {
					l = append(l, f)
				}
			}
			return l, true
		}
		if l, ok := list("version strings:"); ok {
			in.versions = l
		}
		if l, ok := list("extension strings:"); ok {
			in.extensions = l
		}
		if l, ok := list("options:"); ok {
			for _, o := range l {
				in.options[o] = true
			}
		}
	}
	return in
}

// profile derives the capabilities from getInfo, so a device that cannot do
// what a slot needs is refused before fido2-cred or any PIN prompt.
//
// spec: SPO-Xunlock-IF-002
func (i info) profile() ports.FactorProfile {
	ctap21 := contains(i.versions, "FIDO_2_1") || contains(i.versions, "FIDO_2_1_PRE")
	hmac := contains(i.extensions, "hmac-secret")
	p := ports.FactorProfile{
		HMACSecret:   hmac,
		CredProtect3: contains(i.extensions, "credProtect"),
		CTAP21:       ctap21,
		TwoSalts:     hmac && ctap21,
		ClientPIN:    i.options["clientPin"],
		BuiltinUV:    i.options["uv"],
	}
	p.UserVerification = p.ClientPIN || p.BuiltinUV
	return p
}

func (s *Source) getInfo(ctx context.Context, device string) (info, error) {
	path, err := s.tool(ctx, ports.FIDO2Token)
	if err != nil {
		return info{}, err
	}
	res, err := s.Runner.Run(ctx, execx.Cmd{Path: path, Args: execx.Lits("-I", device), Env: env, MaxOutput: maxText})
	if err != nil {
		return info{}, classify(ctx, res, err, "fido2-token -I")
	}
	return parseInfo(res.Stdout), nil
}

// Profile implements ports.FactorSource: getInfo of the chosen device.
func (s *Source) Profile(ctx context.Context, device string) (ports.FactorProfile, error) {
	d, err := s.device(ctx, device)
	if err != nil {
		return ports.FactorProfile{}, err
	}
	in, err := s.getInfo(ctx, d)
	if err != nil {
		return ports.FactorProfile{}, err
	}
	return in.profile(), nil
}

// Bounds on what a tool may write back (a hostile tool must not make this
// process allocate without limit).
const (
	maxText   = 64 << 10 // stdout and stderr of a call
	maxSecret = 8 << 10  // the answer of fido2-assert: well under 2 KiB
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (s *Source) random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.rng(), b); err != nil {
		return nil, err
	}
	return b, nil
}

// verifyArgs says how an assertion gets its user verification. With a PIN: -v
// (PIN and verification; the PIN on stdin of a child with no controlling
// terminal). Without: the authenticator's built-in verification
// (-t uv=true -t pin=false), or -v with the tool's own terminal prompt when
// PromptOnTerminal is set and a PIN is what the device has. Verification is
// never skipped.
func (s *Source) verifyArgs(pin *secret.Buffer, p ports.FactorProfile) (args []execx.Arg, stdin io.WriterTo, noTerm bool, err error) {
	switch {
	case pin != nil:
		if err := checkPIN(pin); err != nil {
			return nil, nil, false, err
		}
		if !p.ClientPIN {
			return nil, nil, false, fmt.Errorf("%w: a PIN was given but the authenticator has none set", ports.ErrFactorUnsupported)
		}
		return execx.Lits("-v"), withNewline{pin}, true, nil
	case p.BuiltinUV:
		return execx.Lits("-t", "uv=true", "-t", "pin=false"), nil, false, nil
	case p.ClientPIN && s.PromptOnTerminal:
		return execx.Lits("-v"), nil, false, nil
	}
	return nil, nil, false, fmt.Errorf("%w: it needs a PIN and none was given", ports.ErrFactorUnsupported)
}

func checkPIN(pin *secret.Buffer) error {
	if pin.Len() == 0 {
		return errors.New("empty PIN")
	}
	return pin.Use(func(b []byte) error {
		if bytes.ContainsAny(b, "\n\r\x00") {
			return errors.New("a PIN cannot contain a line break")
		}
		return nil
	})
}

// withNewline sends a secret and a line feed: readpassphrase reads a line.
type withNewline struct{ s *secret.Buffer }

func (w withNewline) WriteTo(dst io.Writer) (int64, error) {
	n, err := w.s.WriteTo(dst)
	if err != nil {
		return n, err
	}
	m, err := dst.Write([]byte{'\n'})
	return n + int64(m), err
}

// Enrol makes a credential: hmac-secret and credProtect level 3 requested, user
// verification required, and the answer checked (ADR 0011, decision 4). It makes
// the credential non-resident (no -r), so a refused authenticator keeps nothing
// to clean up.
//
// The option set follows getInfo. fido2-cred -v makes the tool try built-in
// verification first and prompt for a PIN only when the authenticator answers
// PIN_REQUIRED (tools/cred_make.c, 1.16.0 and 1.17.0), which a PIN-only
// authenticator does not do for a request that carries uv=true, so -v is used
// only for an authenticator with built-in verification; with a PIN, no -v is
// passed and the authenticator's PIN_REQUIRED reaches the tool's PIN prompt.
// The UV flag of the answer is checked either way.
//
// spec: SPO-Xunlock-EXT-001, SPO-Xunlock-EXT-003, SPO-Xunlock-OUT-004, SPO-Xunlock-PRE-001, SPO-Xunlock-PRE-002, SPO-Xunlock-PRE-017, SPO-Xunlock-SEC-001, SPO-Xunlock-SEC-002
func (s *Source) Enrol(ctx context.Context, req ports.EnrolRequest) (ports.Enrolment, error) {
	if err := checkLine("relying-party id", req.RPID); err != nil {
		return ports.Enrolment{}, err
	}
	device, err := s.device(ctx, req.Device)
	if err != nil {
		return ports.Enrolment{}, err
	}
	in, err := s.getInfo(ctx, device)
	if err != nil {
		return ports.Enrolment{}, err
	}
	prof := in.profile()
	if err := ports.CheckFactorProfile(prof, ports.NeedsOfSlot); err != nil {
		return ports.Enrolment{}, err
	}

	var (
		uvArgs []execx.Arg
		stdin  io.WriterTo
		noTerm bool
	)
	switch {
	case req.PIN != nil:
		if err := checkPIN(req.PIN); err != nil {
			return ports.Enrolment{}, err
		}
		if !prof.ClientPIN {
			return ports.Enrolment{}, fmt.Errorf("%w: a PIN was given but the authenticator has none set", ports.ErrFactorUnsupported)
		}
		stdin, noTerm = withNewline{req.PIN}, true
	case prof.BuiltinUV:
		uvArgs = execx.Lits("-v", "-q")
	case prof.ClientPIN && s.PromptOnTerminal:
		// the tool prompts on the terminal when the authenticator asks for a PIN
	default:
		return ports.Enrolment{}, fmt.Errorf("%w: it needs a PIN and none was given", ports.ErrFactorUnsupported)
	}

	cdh, err := s.random(32)
	if err != nil {
		return ports.Enrolment{}, err
	}
	uid, err := s.random(32)
	if err != nil {
		return ports.Enrolment{}, err
	}
	params := b64(cdh) + "\n" + req.RPID + "\nspo\n" + b64(uid) + "\n"

	args := execx.Lits("-M", "-h", "-c", fmt.Sprint(ports.CredProtectRequired))
	args = append(args, uvArgs...)
	args = append(args, execx.Lit("-i"), execx.SecretIn(strings.NewReader(params)), execx.Lit(device), execx.Lit("es256"))
	path, err := s.tool(ctx, ports.FIDO2Cred)
	if err != nil {
		return ports.Enrolment{}, err
	}
	res, err := s.Runner.Run(ctx, execx.Cmd{Path: path, Args: args, Env: env, StdinSecret: stdin, NoTerminal: noTerm, MaxOutput: maxText})
	if err != nil {
		return ports.Enrolment{}, classify(ctx, res, err, "fido2-cred -M")
	}
	// stdout: client data hash, rp id, format, authenticator data, credential id, signature, [x5c].
	lines := strings.Split(strings.TrimRight(string(res.Stdout), "\n"), "\n")
	if len(lines) < 6 || lines[1] != req.RPID {
		return ports.Enrolment{}, fmt.Errorf("%w: unexpected fido2-cred output", ports.ErrFactorMalformed)
	}
	credID, err := decodeB64(lines[4])
	if err != nil || len(credID) == 0 {
		return ports.Enrolment{}, fmt.Errorf("%w: credential id", ports.ErrFactorMalformed)
	}
	authData, err := decodeAuthData(lines[3])
	if err != nil {
		return ports.Enrolment{}, err
	}
	ad, err := parseCredAuthData(authData, req.RPID)
	if err != nil {
		return ports.Enrolment{}, err
	}
	if !bytes.Equal(ad.credID, credID) {
		return ports.Enrolment{}, fmt.Errorf("%w: the credential id differs from the one in the authenticator data", ports.ErrFactorMalformed)
	}
	if ad.flags&flagUV == 0 {
		return ports.Enrolment{}, fmt.Errorf("%w: the credential was made without user verification", ports.ErrFactorFlags)
	}
	if !ad.hmacSecret {
		return ports.Enrolment{}, fmt.Errorf("%w: the credential does not carry hmac-secret", ports.ErrFactorUnsupported)
	}
	if ad.credProtect != ports.CredProtectRequired {
		return ports.Enrolment{}, fmt.Errorf("%w: the authenticator confirmed credProtect level %d, not %d", ports.ErrFactorUnsupported, ad.credProtect, ports.CredProtectRequired)
	}
	en := ports.Enrolment{
		CredentialID: credID,
		CredProtect:  ad.credProtect,
		Versions:     in.versions,
		FactorID:     ports.FactorIDOf(credID),
	}
	en.Touch, err = s.probe(ctx, device, req, credID, prof)
	if err != nil {
		return ports.Enrolment{}, err
	}
	return en, nil
}

// probe is the touch probe of ADR 0011, "Limit": an assertion with user presence
// disabled and a PIN token. It runs only with a PIN. Only an answer that returns
// an output (whatever its flags) is "touch not enforced", and only a named
// refusal of the request (FIDO_ERR_UP_REQUIRED, FIDO_ERR_OPERATION_DENIED) is
// "touch enforced"; a PIN error ends the enrolment; everything else (a
// deadline, a usage error, malformed output) is "not confirmed".
//
// spec: SPO-Xunlock-EXT-004, SPO-Xunlock-SEC-004, SPO-Xunlock-OUT-006
func (s *Source) probe(ctx context.Context, device string, req ports.EnrolRequest, credID []byte, prof ports.FactorProfile) (ports.TouchProbe, error) {
	if req.PIN == nil {
		return ports.TouchProbeNotRun, nil
	}
	salt, err := s.random(ports.FactorSaltSize)
	if err != nil {
		return 0, err
	}
	a, err := s.assertRaw(ctx, ports.AssertRequest{Device: device, CredentialID: credID, RPID: req.RPID, Salt: salt, PIN: req.PIN}, prof, true)
	switch {
	case err == nil:
		a.Destroy()
		return ports.TouchNotEnforced, nil
	case errors.Is(err, ports.ErrFactorUPRefused):
		return ports.TouchEnforced, nil
	case errors.Is(err, ports.ErrFactorPIN), errors.Is(err, ports.ErrFactorPINBlocked), errors.Is(err, ports.ErrFactorNoDevice):
		return 0, err
	}
	return ports.TouchUnknown, nil
}

// Assert implements ports.FactorSource. User verification is always required;
// the caller chooses presence only.
//
// spec: SPO-Xunlock-EXT-002, SPO-Xunlock-IN-001, SPO-Xunlock-OUT-005, SPO-Xunlock-PRE-003, SPO-Xunlock-PRE-004, SPO-Xunlock-PRE-005, SPO-Xunlock-SEC-001
func (s *Source) Assert(ctx context.Context, req ports.AssertRequest) (ports.Assertion, error) {
	device, err := s.device(ctx, req.Device)
	if err != nil {
		return ports.Assertion{}, err
	}
	req.Device = device
	in, err := s.getInfo(ctx, device)
	if err != nil {
		return ports.Assertion{}, err
	}
	prof := in.profile()
	need := ports.NeedsOfSlot &^ ports.NeedCredProtect3
	if req.NextSalt != nil {
		need |= ports.NeedTwoSalts
	}
	if err := ports.CheckFactorProfile(prof, need); err != nil {
		return ports.Assertion{}, err
	}
	a, err := s.assertRaw(ctx, req, prof, false)
	if err != nil {
		return ports.Assertion{}, err
	}
	if err := a.Require(ports.Requirement{UserVerification: true, UserPresence: req.UserPresence}); err != nil {
		return ports.Assertion{}, err
	}
	return a, nil
}

// assertRaw runs one fido2-assert and parses the answer without judging its
// flags. noUP is the probe's `-t up=false`; the probe is the only caller that
// sets it, and a normal assertion always asks for verification.
func (s *Source) assertRaw(ctx context.Context, req ports.AssertRequest, prof ports.FactorProfile, noUP bool) (ports.Assertion, error) {
	if err := checkLine("relying-party id", req.RPID); err != nil {
		return ports.Assertion{}, err
	}
	if len(req.CredentialID) == 0 || len(req.Salt) != ports.FactorSaltSize ||
		(req.NextSalt != nil && len(req.NextSalt) != ports.FactorSaltSize) {
		return ports.Assertion{}, errors.New("an assertion needs a credential id and 32-byte salts")
	}
	if req.NextSalt != nil && bytes.Equal(req.Salt, req.NextSalt) {
		return ports.Assertion{}, errors.New("the two salts are equal")
	}
	cdh, err := s.random(32)
	if err != nil {
		return ports.Assertion{}, err
	}
	salts := append(append([]byte{}, req.Salt...), req.NextSalt...)
	params := b64(cdh) + "\n" + req.RPID + "\n" + b64(req.CredentialID) + "\n" + b64(salts) + "\n"

	vargs, stdin, noTerm, err := s.verifyArgs(req.PIN, prof)
	if err != nil {
		return ports.Assertion{}, err
	}
	args := execx.Lits("-G", "-h")
	if req.UserPresence && !noUP {
		args = append(args, execx.Lit("-p"))
	}
	if noUP {
		args = append(args, execx.Lits("-t", "up=false")...)
	}
	args = append(args, vargs...)
	var out execx.Captured
	args = append(args, execx.Lit("-i"), execx.SecretIn(strings.NewReader(params)), execx.Lit("-o"), execx.SecretOutMax(&out, maxSecret), execx.Lit(req.Device))

	path, err := s.tool(ctx, ports.FIDO2Assert)
	if err != nil {
		return ports.Assertion{}, err
	}
	res, err := s.Runner.Run(ctx, execx.Cmd{Path: path, Args: args, Env: env, StdinSecret: stdin, NoTerminal: noTerm, MaxOutput: maxText})
	captured := out.Buffer()
	if captured != nil {
		defer captured.Destroy()
	}
	if err != nil {
		return ports.Assertion{}, classify(ctx, res, err, "fido2-assert -G")
	}
	if captured == nil {
		return ports.Assertion{}, fmt.Errorf("%w: no output", ports.ErrFactorMalformed)
	}
	return parseAssertion(captured, req)
}

// parseAssertion reads the five lines of fido2-assert's answer (client data
// hash, relying-party id, authenticator data, signature, hmac secret) and
// decodes the last into guarded memory.
func parseAssertion(captured *secret.Buffer, req ports.AssertRequest) (ports.Assertion, error) {
	want := ports.FactorOutputSize
	if req.NextSalt != nil {
		want = 2 * ports.FactorOutputSize
	}
	var (
		a   ports.Assertion
		raw *secret.Buffer
		got int
	)
	err := captured.Use(func(b []byte) error {
		lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
		if len(lines) != 5 || string(lines[1]) != req.RPID {
			return fmt.Errorf("%w: unexpected fido2-assert output", ports.ErrFactorMalformed)
		}
		authData, err := decodeAuthData(string(lines[2]))
		if err != nil {
			return err
		}
		flags, err := assertFlags(authData, req.RPID)
		if err != nil {
			return err
		}
		a.UP, a.UV = flags&flagUP != 0, flags&flagUV != 0
		dl := base64.StdEncoding.DecodedLen(len(lines[4]))
		raw, err = secret.Fill(dl, func(dst []byte) error {
			n, derr := base64.StdEncoding.Strict().Decode(dst, lines[4])
			got = n
			if derr != nil || n != want {
				return fmt.Errorf("%w: the hmac secret is not %d bytes", ports.ErrFactorMalformed, want)
			}
			return nil
		})
		return err
	})
	if err != nil {
		if raw != nil {
			raw.Destroy()
		}
		return ports.Assertion{}, err
	}
	defer raw.Destroy()
	if got != want {
		return ports.Assertion{}, fmt.Errorf("%w: the hmac secret is not %d bytes", ports.ErrFactorMalformed, want)
	}
	split := func(from int) (*secret.Buffer, error) {
		return secret.Fill(ports.FactorOutputSize, func(dst []byte) error {
			return raw.Use(func(b []byte) error { copy(dst, b[from:from+ports.FactorOutputSize]); return nil })
		})
	}
	if a.Output, err = split(0); err != nil {
		return ports.Assertion{}, err
	}
	if req.NextSalt != nil {
		if a.NextOutput, err = split(ports.FactorOutputSize); err != nil {
			a.Destroy()
			return ports.Assertion{}, err
		}
		var same bool
		_ = a.Output.Use(func(x []byte) error {
			return a.NextOutput.Use(func(y []byte) error { same = bytes.Equal(x, y); return nil })
		})
		if same {
			a.Destroy()
			return ports.Assertion{}, fmt.Errorf("%w: both salts gave the same output", ports.ErrFactorMalformed)
		}
	}
	return a, nil
}

// classify turns a failed tool call into a typed error. It returns the exit
// status and the tool's own error name, never its output.
//
// spec: SPO-Xunlock-PRE-005, SPO-Xunlock-SEC-003
func classify(ctx context.Context, res execx.Result, err error, what string) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %s", ports.ErrFactorTimeout, what)
	}
	if errors.Is(err, execx.ErrOutputTooLarge) {
		return fmt.Errorf("%w: %s wrote more than its bound", ports.ErrFactorMalformed, what)
	}
	var ee *execx.ExitError
	if !errors.As(err, &ee) {
		return fmt.Errorf("%s: %w", what, err)
	}
	text := string(res.Stderr)
	for _, c := range []struct {
		needle string
		err    error
	}{
		{"FIDO_ERR_NO_CREDENTIALS", ports.ErrFactorNoCredential},
		{"FIDO_ERR_INVALID_CREDENTIAL", ports.ErrFactorNoCredential},
		{"FIDO_ERR_PIN_INVALID", ports.ErrFactorPIN},
		{"FIDO_ERR_PIN_AUTH_INVALID", ports.ErrFactorPIN},
		{"FIDO_ERR_PIN_BLOCKED", ports.ErrFactorPINBlocked},
		{"FIDO_ERR_PIN_AUTH_BLOCKED", ports.ErrFactorPINBlocked},
		{"FIDO_ERR_UV_BLOCKED", ports.ErrFactorPINBlocked},
		{"FIDO_ERR_UP_REQUIRED", ports.ErrFactorUPRefused},
		{"FIDO_ERR_OPERATION_DENIED", ports.ErrFactorUPRefused},
		{"output error", ports.ErrFactorMalformed},
		{"FIDO_ERR_ACTION_TIMEOUT", ports.ErrFactorTimeout},
		{"FIDO_ERR_USER_ACTION_TIMEOUT", ports.ErrFactorTimeout},
		{"FIDO_ERR_UNSUPPORTED_EXTENSION", ports.ErrFactorUnsupported},
		{"fido_dev_open", ports.ErrFactorNoDevice},
	} {
		if strings.Contains(text, c.needle) {
			return fmt.Errorf("%w: %s (exit %d)", c.err, what, res.ExitCode)
		}
	}
	return fmt.Errorf("%s failed (exit %d)", what, res.ExitCode)
}
