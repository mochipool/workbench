package vaultkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/stsweb"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// KMSOptions are the client side of an AWS KMS backend: the credential source
// and, for private endpoints only, other endpoints and trust roots. By default
// the KMS endpoint and the STS endpoint are the public ones of the key ARN's
// partition and region, with the system roots: the signed requests and the web
// identity token go to AWS and nowhere else.
type KMSOptions struct {
	// PrivateEndpoint is private_endpoint of spo.toml: a KMS endpoint that is
	// not the public one of the key's region (a VPC endpoint, a test server).
	// The reference's address must be either the public endpoint or this.
	// PrivateCAFile (private_ca_file) is the CA for it only.
	PrivateEndpoint, PrivateCAFile string
	// PrivateSTSEndpoint is private_sts_endpoint: where the web identity token is
	// exchanged instead of the public STS endpoint of the key's region.
	// PrivateSTSCAFile (private_sts_ca_file) is the CA for it only.
	PrivateSTSEndpoint, PrivateSTSCAFile string
	// AllowLoopbackHTTP is allow_loopback_http: plain http to a loopback IP
	// address for a private endpoint (a test server). Off by default.
	AllowLoopbackHTTP bool
	// RoleARN and WebIdentityTokenFile select AssumeRoleWithWebIdentity; ""
	// reads AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE. RoleSessionName is the
	// session name (default "spo-unlock", or AWS_ROLE_SESSION_NAME).
	RoleARN, WebIdentityTokenFile, RoleSessionName string
	// Timeout bounds each call (default DefaultTimeout).
	Timeout time.Duration
	// Getenv reads the environment (default os.Getenv); Now is the clock.
	Getenv func(string) string
	Now    func() time.Time
}

// KMS is an AWS KMS symmetric key used as a key-wrap backend.
type KMS struct {
	ref       ports.BackendRef
	c         *conn
	host      string
	region    string
	partition string
	o         KMSOptions

	// sts is the STS endpoint, its CA file ("" the system roots) and whether
	// plain http to loopback is allowed for it.
	sts, stsCA string
	stsHTTP    bool

	mu    sync.Mutex
	creds *awsCreds
}

type awsCreds struct {
	keyID   string
	secret  *secret.Buffer
	token   *secret.Buffer
	expires time.Time // zero: unknown (environment credentials)
}

func (c *awsCreds) destroy() {
	if c != nil {
		c.secret.Destroy()
		c.token.Destroy()
	}
}

var (
	kmsARN   = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):kms:([a-z]{2}(-[a-z]+)+-[0-9]):([0-9]{12}):key/([A-Za-z0-9-]{1,128})$`)
	awsKeyID = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
)

// parseARN returns the partition and region of a KMS key ARN. An alias, a key
// id without ARN and any other resource are refused: the answer's key id must
// be compared with the configured key, and only a key ARN can be.
func parseARN(arn string) (partition, region string, err error) {
	m := kmsARN.FindStringSubmatch(arn)
	if m == nil {
		return "", "", fmt.Errorf("%w: the KMS key must be a key ARN (arn:aws:kms:<region>:<account>:key/<id>); an alias or a bare key id is not accepted", ports.ErrBackendConfig)
	}
	return m[1], m[2], nil
}

func endpointFor(partition, service, region string) string {
	return stsweb.EndpointFor(partition, service, region)
}

// DefaultKMSEndpoint is the public KMS endpoint of the key's region.
func DefaultKMSEndpoint(arn string) (string, error) {
	p, r, err := parseARN(arn)
	if err != nil {
		return "", err
	}
	return endpointFor(p, "kms", r), nil
}

// NewKMS checks the reference and the options. It makes no call: the
// credentials are obtained at the first Wrap or Unwrap.
func NewKMS(ref ports.BackendRef, o KMSOptions) (*KMS, error) {
	if ref.Kind != ports.BackendAWSKMS {
		return nil, fmt.Errorf("%w: not an AWS KMS reference", ports.ErrBackendConfig)
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	part, region, err := parseARN(ref.Key)
	if err != nil {
		return nil, err
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PrivateCAFile != "" && o.PrivateEndpoint == "" {
		return nil, fmt.Errorf("%w: private_ca_file is the CA of private_endpoint, and no private_endpoint is set", ports.ErrBackendConfig)
	}
	if o.PrivateSTSCAFile != "" && o.PrivateSTSEndpoint == "" {
		return nil, fmt.Errorf("%w: private_sts_ca_file is the CA of private_sts_endpoint, and no private_sts_endpoint is set", ports.ErrBackendConfig)
	}
	var c *conn
	public := endpointFor(part, "kms", region)
	switch {
	case ref.Address == public:
		c, err = newConn(public, "", o.Timeout, false)
	case o.PrivateEndpoint != "" && ref.Address == o.PrivateEndpoint:
		c, err = newConn(ref.Address, o.PrivateCAFile, o.Timeout, o.AllowLoopbackHTTP)
	default:
		return nil, fmt.Errorf("%w: the KMS address %s is neither the public endpoint of the key's region (%s) nor the private_endpoint of spo.toml", ports.ErrBackendConfig, ref.Address, public)
	}
	if err != nil {
		return nil, err
	}
	k := &KMS{ref: ref, c: c, host: c.base.Host, region: region, partition: part, o: o, sts: endpointFor(part, "sts", region)}
	if o.PrivateSTSEndpoint != "" {
		k.sts, k.stsCA, k.stsHTTP = o.PrivateSTSEndpoint, o.PrivateSTSCAFile, o.AllowLoopbackHTTP
	}
	if _, err := checkBase(k.sts, k.stsHTTP); err != nil {
		return nil, err
	}
	return k, nil
}

// Ref implements ports.KeyWrapBackend.
func (k *KMS) Ref() ports.BackendRef { return k.ref }

// Close destroys the credentials this client holds.
func (k *KMS) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.creds.destroy()
	k.creds = nil
}

const staticKeyRemedy = "static long-lived AWS access keys are refused (ADR 0012): give short-lived credentials with AWS_SESSION_TOKEN (for example from `aws sts get-session-token`, or `aws configure export-credentials --format env` after `aws sso login`), or a web identity token (web_identity_token_file and role_arn, or AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN)"

// credentials returns short-lived credentials: a web identity exchanged at STS
// when configured, else temporary credentials from the environment (with a
// session token). Anything else is refused.
func (k *KMS) credentials(ctx context.Context) (*awsCreds, error) {
	now := k.o.Now()
	if k.creds != nil && (k.creds.expires.IsZero() || k.creds.expires.After(now.Add(time.Minute))) {
		return k.creds, nil
	}
	k.creds.destroy()
	k.creds = nil
	file, role := k.o.WebIdentityTokenFile, k.o.RoleARN
	if file == "" {
		file = k.o.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
	}
	if role == "" {
		role = k.o.Getenv("AWS_ROLE_ARN")
	}
	if file != "" || role != "" {
		if file == "" || role == "" {
			return nil, fmt.Errorf("%w: a web identity needs both a token file and a role ARN", ports.ErrBackendCredential)
		}
		c, err := k.assumeRole(ctx, file, role)
		if err != nil {
			return nil, err
		}
		k.creds = c
		return c, nil
	}
	id, sk, st := k.o.Getenv("AWS_ACCESS_KEY_ID"), k.o.Getenv("AWS_SECRET_ACCESS_KEY"), k.o.Getenv("AWS_SESSION_TOKEN")
	if id == "" && sk == "" {
		return nil, fmt.Errorf("%w: no AWS credentials in this process; %s", ports.ErrBackendCredential, staticKeyRemedy)
	}
	if st == "" || !strings.HasPrefix(id, "ASIA") {
		// an allow-list: only a temporary key id (ASIA) comes with a session
		return nil, fmt.Errorf("%w: %s", ports.ErrBackendCredential, staticKeyRemedy)
	}
	if !awsKeyID.MatchString(id) || !printableToken([]byte(sk), 256) || !printableToken([]byte(st), 8192) {
		return nil, fmt.Errorf("%w: the AWS credentials in the environment are malformed", ports.ErrBackendCredential)
	}
	c := &awsCreds{keyID: id}
	var err error
	if c.secret, err = secret.Fill(len(sk), func(d []byte) error { copy(d, sk); return nil }); err != nil {
		return nil, err
	}
	if c.token, err = secret.Fill(len(st), func(d []byte) error { copy(d, st); return nil }); err != nil {
		c.destroy()
		return nil, err
	}
	k.creds = c
	return c, nil
}

// assumeRole is STS AssumeRoleWithWebIdentity (an unsigned call: the web
// identity token is the credential).
func (k *KMS) assumeRole(ctx context.Context, file, role string) (*awsCreds, error) {
	if !stsweb.ValidRoleARN(role) {
		return nil, fmt.Errorf("%w: the role is not an IAM role ARN", ports.ErrBackendCredential)
	}
	name := k.o.RoleSessionName
	if name == "" {
		name = k.o.Getenv("AWS_ROLE_SESSION_NAME")
	}
	if name == "" {
		name = "spo-unlock"
	}
	if !stsweb.ValidSessionName(name) {
		return nil, fmt.Errorf("%w: the role session name is 2 to 64 of [A-Za-z0-9_=,.@-]", ports.ErrBackendCredential)
	}
	sts, err := newConn(k.sts, k.stsCA, k.o.Timeout, k.stsHTTP)
	if err != nil {
		return nil, err
	}
	raw, err := readToken(file)
	if err != nil {
		return nil, fmt.Errorf("%w: the web identity token file %s %v", ports.ErrBackendCredential, file, err)
	}
	defer wipe(raw)
	jwt := trimLine(raw)
	if !printableToken(jwt, maxSecretFile) {
		return nil, fmt.Errorf("%w: the web identity token file %s does not hold a token", ports.ErrBackendCredential, file)
	}
	// one buffer of its final size, the token escaped by hand (platform/stsweb),
	// so no copy of it is left in a grown or discarded buffer
	b := stsweb.Request(role, name, 900, jwt)
	status, resp, err := sts.call(ctx, http.MethodPost, "/", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, b)
	wipe(b)
	if err != nil {
		return nil, err
	}
	defer wipe(resp)
	switch {
	case status == http.StatusOK:
	case status >= 500 || status == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: STS answered status %d", ports.ErrBackendUnavailable, status)
	default:
		return nil, fmt.Errorf("%w: STS refused the web identity (status %d)", ports.ErrBackendCredential, status)
	}
	return parseSTS(resp, k.o.Now())
}

// parseSTS reads the credentials of an AssumeRoleWithWebIdentity answer. They
// must be temporary (an ASIA key id, a session token) and not expired.
//
// The reading is platform/stsweb's (shared with the relay's provider): the
// secret key and the session token are spans of the answer's own bytes, each
// one element of plain text, the structure checked on a blanked copy. They are
// copied from the answer into guarded memory here.
func parseSTS(body []byte, now time.Time) (*awsCreds, error) {
	a, err := stsweb.Parse(body, now)
	switch {
	case errors.Is(err, stsweb.ErrNotXML):
		return nil, fmt.Errorf("%w: %v", ports.ErrBackendResponse, err)
	case err != nil:
		return nil, fmt.Errorf("%w: %v", ports.ErrBackendCredential, err)
	}
	ska, skz, sta, stz := a.Secret[0], a.Secret[1], a.Token[0], a.Token[1]
	out := &awsCreds{keyID: a.KeyID, expires: a.Expires}
	if out.secret, err = secret.Fill(skz-ska, func(d []byte) error { copy(d, body[ska:skz]); return nil }); err != nil {
		return nil, err
	}
	if out.token, err = secret.Fill(stz-sta, func(d []byte) error { copy(d, body[sta:stz]); return nil }); err != nil {
		out.destroy()
		return nil, err
	}
	return out, nil
}

// do signs and sends one KMS call.
func (k *KMS) do(ctx context.Context, target string, body []byte) (int, []byte, error) {
	c, err := k.credentials(ctx)
	if err != nil {
		return 0, nil, err
	}
	var tok string
	_ = c.token.Use(func(b []byte) error { tok = string(b); return nil }) // a header value: one transient copy
	hdr := map[string]string{"content-type": "application/x-amz-json-1.1", "x-amz-target": target}
	auth, date, err := sign(sigInput{Method: http.MethodPost, Host: k.host, Path: "/", Headers: hdr, Payload: body,
		Region: k.region, Service: "kms", Time: k.o.Now(), KeyID: c.keyID, Secret: c.secret, Token: tok})
	if err != nil {
		return 0, nil, fmt.Errorf("%w: the request could not be signed", ports.ErrBackendCredential)
	}
	h := http.Header{
		"Content-Type":         {hdr["content-type"]},
		"X-Amz-Target":         {target},
		"X-Amz-Date":           {date},
		"X-Amz-Security-Token": {tok},
		"Authorization":        {auth},
	}
	return k.c.call(ctx, http.MethodPost, "/", h, body)
}

// contextJSON is the encryption context as JSON, keys sorted.
func contextJSON(wc ports.WrapContext) ([]byte, error) {
	m, err := wc.KMSContext()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + key + `":"` + m[key] + `"`) // fixed names, hex values
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// Wrap implements ports.KeyWrapBackend: TrentService.Encrypt with the
// encryption context of decision 5.
func (k *KMS) Wrap(ctx context.Context, b *secret.Buffer, wc ports.WrapContext) ([]byte, error) {
	if b == nil || b.Len() != ports.BackendSecretSize {
		return nil, fmt.Errorf("%w: the factor secret must be %d bytes", ports.ErrBackendConfig, ports.BackendSecretSize)
	}
	ec, err := contextJSON(wc)
	if err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var body []byte
	if err := b.Use(func(p []byte) error {
		body = make([]byte, 0, 256+len(k.ref.Key))
		body = append(body, `{"EncryptionContext":`...)
		body = append(body, ec...)
		body = append(body, `,"KeyId":"`+k.ref.Key+`","Plaintext":"`...)
		body = base64.StdEncoding.AppendEncode(body, p)
		body = append(body, `"}`...)
		return nil
	}); err != nil {
		return nil, err
	}
	status, resp, err := k.do(ctx, "TrentService.Encrypt", body)
	wipe(body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, kmsStatusErr(status, resp)
	}
	return parseKMSEncrypt(resp, k.ref.Key)
}

// Unwrap implements ports.KeyWrapBackend: TrentService.Decrypt with the key
// ARN and the same encryption context; the answer must name the same key.
func (k *KMS) Unwrap(ctx context.Context, blob []byte, wc ports.WrapContext) (*secret.Buffer, error) {
	ec, err := contextJSON(wc)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 || len(blob) > ports.MaxWrappedBlob {
		return nil, fmt.Errorf("%w: the stored blob is empty or over %d bytes", ports.ErrBackendRefused, ports.MaxWrappedBlob)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	body := make([]byte, 0, 256+len(k.ref.Key)+base64.StdEncoding.EncodedLen(len(blob)))
	body = append(body, `{"CiphertextBlob":"`...)
	body = base64.StdEncoding.AppendEncode(body, blob)
	body = append(body, `","EncryptionAlgorithm":"SYMMETRIC_DEFAULT","EncryptionContext":`...)
	body = append(body, ec...)
	body = append(body, `,"KeyId":"`+k.ref.Key+`"}`...)
	status, resp, err := k.do(ctx, "TrentService.Decrypt", body)
	if err != nil {
		return nil, err
	}
	defer wipe(resp)
	if status != http.StatusOK {
		return nil, kmsStatusErr(status, resp)
	}
	return parseKMSDecrypt(resp, k.ref.Key)
}

// kmsStatusErr maps an error answer by its exception name only.
func kmsStatusErr(status int, body []byte) error {
	name := ""
	if f, err := scanJSON(body, "__type"); err == nil {
		if t, ok := f["__type"].plainString(body); ok && len(t) <= 256 {
			if i := bytes.LastIndexByte(t, '#'); i >= 0 {
				t = t[i+1:]
			}
			name = string(t) // compared with the fixed names below only
		}
	}
	switch name {
	case "InvalidCiphertextException", "IncorrectKeyException":
		return fmt.Errorf("%w: KMS refused to decrypt (%s)", ports.ErrBackendRefused, name)
	case "AccessDeniedException", "UnrecognizedClientException", "ExpiredTokenException", "InvalidSignatureException",
		"IncompleteSignature", "MissingAuthenticationToken", "InvalidClientTokenId", "SignatureDoesNotMatch":
		return fmt.Errorf("%w: KMS refused the credentials (%s)", ports.ErrBackendCredential, name)
	case "NotFoundException", "DisabledException", "KMSInvalidStateException", "InvalidKeyUsageException", "InvalidGrantTokenException", "ValidationException", "UnsupportedOperationException":
		return fmt.Errorf("%w: KMS cannot use this key for the call (%s)", ports.ErrBackendConfig, name)
	case "ThrottlingException", "LimitExceededException", "DependencyTimeoutException", "KMSInternalException", "KeyUnavailableException", "ServiceUnavailableException":
		return fmt.Errorf("%w: KMS is not available (%s)", ports.ErrBackendUnavailable, name)
	}
	if status >= 500 {
		return fmt.Errorf("%w: KMS answered status %d", ports.ErrBackendUnavailable, status)
	}
	return fmt.Errorf("%w: KMS answered status %d", ports.ErrBackendResponse, status)
}

// parseKMSEncrypt reads CiphertextBlob; KeyId must be the configured ARN and
// EncryptionAlgorithm SYMMETRIC_DEFAULT (an asymmetric key takes no context).
func parseKMSEncrypt(body []byte, wantKey string) ([]byte, error) {
	f, err := kmsAnswer(body, wantKey, "encrypt", "CiphertextBlob")
	if err != nil {
		return nil, err
	}
	c, ok := f["CiphertextBlob"].plainString(body)
	if !ok || len(c) > base64.StdEncoding.EncodedLen(ports.MaxWrappedBlob) {
		return nil, fmt.Errorf("%w: the answer has no ciphertext of at most %d bytes", ports.ErrBackendResponse, ports.MaxWrappedBlob)
	}
	blob := make([]byte, base64.StdEncoding.DecodedLen(len(c)))
	n, err := base64.StdEncoding.Strict().Decode(blob, c)
	if err != nil || n == 0 || n > ports.MaxWrappedBlob {
		return nil, fmt.Errorf("%w: the answer has no ciphertext of at most %d bytes", ports.ErrBackendResponse, ports.MaxWrappedBlob)
	}
	return blob[:n], nil
}

// parseKMSDecrypt reads Plaintext (the base64 of exactly 32 bytes) into
// guarded memory, from the answer's own bytes; KeyId must be the configured
// ARN.
func parseKMSDecrypt(body []byte, wantKey string) (*secret.Buffer, error) {
	f, err := kmsAnswer(body, wantKey, "decrypt", "Plaintext")
	if err != nil {
		return nil, err
	}
	return secretFromJSON(body, f["Plaintext"], ports.BackendSecretSize)
}

// kmsAnswer scans an Encrypt or Decrypt answer: KeyId must be the configured
// key ARN and EncryptionAlgorithm SYMMETRIC_DEFAULT (an asymmetric key takes
// no context), both plain strings.
func kmsAnswer(body []byte, wantKey, call, field string) (map[string]jsonValue, error) {
	f, err := scanJSON(body, "KeyId", "EncryptionAlgorithm", field)
	if err != nil {
		return nil, err
	}
	if k, ok := f["KeyId"].plainString(body); !ok || string(k) != wantKey {
		return nil, fmt.Errorf("%w: the answer names another key than the configured key ARN", ports.ErrBackendResponse)
	}
	if a, ok := f["EncryptionAlgorithm"].plainString(body); !ok || string(a) != "SYMMETRIC_DEFAULT" {
		return nil, fmt.Errorf("%w: the key did not %s with SYMMETRIC_DEFAULT", ports.ErrBackendResponse, call)
	}
	return f, nil
}
