package vaultkms

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// VaultOptions are the client side of a Vault Transit backend: how to reach it
// and which credential to use. The address, namespace and key are the
// reference (ports.BackendRef) the caller has checked against spo.toml.
type VaultOptions struct {
	// CAFile is a PEM file of the CA certificates that sign the server's
	// certificate; "" uses the system roots.
	CAFile string
	// Auth is "token" (the default: VAULT_TOKEN, else the token helper file) or
	// "jwt" (a JWT/OIDC login with the token in JWTFile).
	Auth string
	// TokenFile is the token helper file; "" is $HOME/.vault-token, where the
	// Vault command line keeps the token of `vault login`.
	TokenFile string
	// JWTMount, JWTRole and JWTFile configure the JWT login: the auth mount
	// (default "jwt"), the role, and the file that holds the JWT.
	JWTMount, JWTRole, JWTFile string
	// Timeout bounds each call (default DefaultTimeout).
	Timeout time.Duration
	// AllowLoopbackHTTP is allow_loopback_http of spo.toml: plain http to a
	// loopback IP address (a test server, a local Vault agent). Off by default;
	// a slot can never turn it on.
	AllowLoopbackHTTP bool
	// Getenv reads the environment (default os.Getenv).
	Getenv func(string) string
}

// Vault is a Vault Transit key used as a key-wrap backend.
type Vault struct {
	ref         ports.BackendRef
	c           *conn
	mount, name string
	o           VaultOptions

	mu      sync.Mutex
	token   *secret.Buffer
	checked bool
}

var (
	vaultSegment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	vaultCT      = regexp.MustCompile(`^vault:v[0-9]{1,10}:[A-Za-z0-9+/]+={0,2}$`)
)

// aeadKeyTypes are the Transit key types that take associated_data (decision 5).
var aeadKeyTypes = map[string]bool{"aes128-gcm96": true, "aes256-gcm96": true, "chacha20-poly1305": true}

// NewVault checks the reference and the options. It makes no call: the token is
// read and the key checked at the first Wrap or Unwrap.
func NewVault(ref ports.BackendRef, o VaultOptions) (*Vault, error) {
	if ref.Kind != ports.BackendVaultTransit {
		return nil, fmt.Errorf("%w: not a Vault Transit reference", ports.ErrBackendConfig)
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	i := strings.LastIndexByte(ref.Key, '/')
	if i <= 0 {
		return nil, fmt.Errorf("%w: the Vault key is <transit mount>/<key name>", ports.ErrBackendConfig)
	}
	mount, name := ref.Key[:i], ref.Key[i+1:]
	for _, seg := range append(strings.Split(mount, "/"), name) {
		if !vaultSegment.MatchString(seg) || seg == "." || seg == ".." {
			return nil, fmt.Errorf("%w: the Vault mount and key name are letters, digits, '.', '_' and '-'", ports.ErrBackendConfig)
		}
	}
	if ref.Namespace != "" {
		for _, seg := range strings.Split(strings.Trim(ref.Namespace, "/"), "/") {
			if !vaultSegment.MatchString(seg) || seg == "." || seg == ".." {
				return nil, fmt.Errorf("%w: the Vault namespace is letters, digits, '.', '_', '-' and '/'", ports.ErrBackendConfig)
			}
		}
	}
	switch o.Auth {
	case "", "token":
		o.Auth = "token"
	case "jwt":
		if o.JWTMount == "" {
			o.JWTMount = "jwt"
		}
		if o.JWTRole == "" || o.JWTFile == "" {
			return nil, fmt.Errorf("%w: a JWT login needs a role and a JWT file", ports.ErrBackendConfig)
		}
		for _, seg := range append(strings.Split(o.JWTMount, "/"), o.JWTRole) {
			if !vaultSegment.MatchString(seg) {
				return nil, fmt.Errorf("%w: the JWT mount and role are letters, digits, '.', '_' and '-'", ports.ErrBackendConfig)
			}
		}
	default:
		return nil, fmt.Errorf("%w: Vault auth %q: use token or jwt", ports.ErrBackendConfig, o.Auth)
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	c, err := newConn(ref.Address, o.CAFile, o.Timeout, o.AllowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	return &Vault{ref: ref, c: c, mount: mount, name: name, o: o}, nil
}

// Ref implements ports.KeyWrapBackend.
func (v *Vault) Ref() ports.BackendRef { return v.ref }

// Close destroys the token this client holds.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.token.Destroy()
	v.token = nil
}

// loadToken obtains the token once: from VAULT_TOKEN or the token helper file,
// or by a JWT login.
func (v *Vault) loadToken(ctx context.Context) error {
	if v.token != nil {
		return nil
	}
	var tok *secret.Buffer
	var err error
	switch v.o.Auth {
	case "jwt":
		tok, err = v.jwtLogin(ctx)
	default:
		tok, err = v.tokenFromClient()
	}
	if err != nil {
		return err
	}
	if err := v.checkToken(ctx, tok); err != nil {
		tok.Destroy()
		return err
	}
	v.token = tok
	return nil
}

const tokenRemedy = "use a token that expires (a periodic, service or batch token with a TTL, for example `vault token create -policy=<your unlock policy> -ttl=1h`, or `vault login` with your own auth method), or a JWT login (auth = \"jwt\"); a root token or a token without a TTL is refused"

// checkToken asks Vault about the token before it is used for anything else
// (GET /v1/auth/token/lookup-self) and refuses a token that never expires (ttl
// 0) and a token with the root policy. The answer is hostile input: ttl must
// be a whole number of at most ten digits, policies an array of at most 64
// plain strings.
func (v *Vault) checkToken(ctx context.Context, tok *secret.Buffer) error {
	h, err := v.headersWith(tok)
	if err != nil {
		return err
	}
	status, body, err := v.c.call(ctx, http.MethodGet, "/v1/auth/token/lookup-self", h, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return vaultStatusErr(status, false)
	}
	ttl, root, err := parseVaultLookup(body)
	if err != nil {
		return err
	}
	if ttl == 0 {
		return fmt.Errorf("%w: the Vault token never expires (ttl 0); %s", ports.ErrBackendCredential, tokenRemedy)
	}
	if root {
		return fmt.Errorf("%w: the Vault token has the root policy; %s", ports.ErrBackendCredential, tokenRemedy)
	}
	return nil
}

// parseVaultLookup reads data.ttl and data.policies of a lookup-self answer.
func parseVaultLookup(body []byte) (ttl uint64, root bool, err error) {
	f, err := scanJSON(body, "data", "data.ttl", "data.policies")
	if err != nil {
		return 0, false, err
	}
	if f["data"].kind != '{' {
		return 0, false, fmt.Errorf("%w: the token lookup has no data", ports.ErrBackendResponse)
	}
	ttl, ok := smallUint(body, f["data.ttl"])
	if !ok {
		return 0, false, fmt.Errorf("%w: the token lookup has no ttl that is a whole number", ports.ErrBackendResponse)
	}
	pol := f["data.policies"]
	if pol.kind != '[' || len(pol.elems) > 64 {
		return 0, false, fmt.Errorf("%w: the token lookup has no list of at most 64 policies", ports.ErrBackendResponse)
	}
	for _, e := range pol.elems {
		p, ok := e.plainString(body)
		if !ok || len(p) > 256 {
			return 0, false, fmt.Errorf("%w: a policy of the token lookup is not a short plain string", ports.ErrBackendResponse)
		}
		if string(p) == "root" {
			root = true
		}
	}
	return ttl, root, nil
}

func (v *Vault) tokenFromClient() (*secret.Buffer, error) {
	if t := v.o.Getenv("VAULT_TOKEN"); t != "" {
		if !printableToken([]byte(t), 4096) {
			return nil, fmt.Errorf("%w: VAULT_TOKEN is not a token (printable characters, no spaces)", ports.ErrBackendCredential)
		}
		return secret.Fill(len(t), func(d []byte) error { copy(d, t); return nil })
	}
	path := v.o.TokenFile
	if path == "" {
		home := v.o.Getenv("HOME")
		if home == "" {
			return nil, fmt.Errorf("%w: no Vault token: set VAULT_TOKEN, or log in with `vault login` (token helper file ~/.vault-token), or use auth = \"jwt\"", ports.ErrBackendCredential)
		}
		path = filepath.Join(home, ".vault-token")
	}
	b, err := readSmallFile(path, maxSecretFile, true)
	if errors.Is(err, errNoFile) {
		return nil, fmt.Errorf("%w: no Vault token: set VAULT_TOKEN, or log in with `vault login` (token helper file %s), or use auth = \"jwt\"", ports.ErrBackendCredential, path)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the token helper file %s %v", ports.ErrBackendCredential, path, err)
	}
	defer wipe(b)
	t := trimLine(b)
	if !printableToken(t, 4096) {
		return nil, fmt.Errorf("%w: the token helper file %s does not hold a token", ports.ErrBackendCredential, path)
	}
	return secret.Fill(len(t), func(d []byte) error { copy(d, t); return nil })
}

// jwtLogin exchanges the JWT for a Vault token: POST /v1/auth/<mount>/login.
func (v *Vault) jwtLogin(ctx context.Context) (*secret.Buffer, error) {
	raw, err := readSmallFile(v.o.JWTFile, maxSecretFile, true)
	if err != nil {
		return nil, fmt.Errorf("%w: the JWT file %s %v", ports.ErrBackendCredential, v.o.JWTFile, err)
	}
	defer wipe(raw)
	jwt := trimLine(raw)
	if !printableToken(jwt, maxSecretFile) {
		return nil, fmt.Errorf("%w: the JWT file %s does not hold a token", ports.ErrBackendCredential, v.o.JWTFile)
	}
	// built in one buffer of its final size, the JWT escaped by hand (printable
	// ASCII: only '"' and '\' are escaped), so no copy of it is left anywhere
	head, tail := `{"role":"`+v.o.JWTRole+`","jwt":"`, `"}`
	body := make([]byte, 0, len(head)+2*len(jwt)+len(tail))
	body = append(body, head...)
	for _, c := range jwt {
		if c == '"' || c == '\\' {
			body = append(body, '\\')
		}
		body = append(body, c)
	}
	body = append(body, tail...)
	hdr := http.Header{"Content-Type": {"application/json"}}
	if v.ref.Namespace != "" {
		hdr.Set("X-Vault-Namespace", v.ref.Namespace)
	}
	status, resp, err := v.c.call(ctx, http.MethodPost, "/v1/auth/"+v.o.JWTMount+"/login", hdr, body)
	wipe(body)
	if err != nil {
		return nil, err
	}
	defer wipe(resp)
	if status != http.StatusOK {
		if status == http.StatusBadRequest || status == http.StatusForbidden || status == http.StatusUnauthorized {
			return nil, fmt.Errorf("%w: the JWT login was refused (status %d)", ports.ErrBackendCredential, status)
		}
		return nil, vaultStatusErr(status, false)
	}
	return parseVaultLogin(resp)
}

func (v *Vault) headers(ctx context.Context) (http.Header, error) {
	if err := v.loadToken(ctx); err != nil {
		return nil, err
	}
	return v.headersWith(v.token)
}

func (v *Vault) headersWith(token *secret.Buffer) (http.Header, error) {
	var tok string
	_ = token.Use(func(b []byte) error { tok = string(b); return nil }) // net/http needs a string: a copy that cannot be zeroed (SPO-Xunlock-SEC-008)
	h := http.Header{"X-Vault-Token": {tok}, "Content-Type": {"application/json"}}
	if v.ref.Namespace != "" {
		h.Set("X-Vault-Namespace", v.ref.Namespace)
	}
	return h, nil
}

// checkKey reads the key's configuration once and refuses a key type without
// associated data and a derived key (decision 5: associated_data on a
// non-derived key, not context).
func (v *Vault) checkKey(ctx context.Context) error {
	if v.checked {
		return nil
	}
	h, err := v.headers(ctx)
	if err != nil {
		return err
	}
	status, body, err := v.c.call(ctx, http.MethodGet, "/v1/"+v.mount+"/keys/"+v.name, h, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return vaultStatusErr(status, false)
	}
	kt, derived, err := parseVaultKey(body)
	if err != nil {
		return err
	}
	if !aeadKeyTypes[kt] {
		return fmt.Errorf("%w: the Transit key type does not take associated data (aes128-gcm96, aes256-gcm96 or chacha20-poly1305 is needed)", ports.ErrBackendConfig)
	}
	if derived {
		return fmt.Errorf("%w: the Transit key is a derived key; decision 5 binds the context as associated data on a non-derived key", ports.ErrBackendConfig)
	}
	v.checked = true
	return nil
}

// Wrap implements ports.KeyWrapBackend: POST /v1/<mount>/encrypt/<key> with
// plaintext and associated_data.
func (v *Vault) Wrap(ctx context.Context, b *secret.Buffer, wc ports.WrapContext) ([]byte, error) {
	if b == nil || b.Len() != ports.BackendSecretSize {
		return nil, fmt.Errorf("%w: the factor secret must be %d bytes", ports.ErrBackendConfig, ports.BackendSecretSize)
	}
	ad, err := wc.Encode()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkKey(ctx); err != nil {
		return nil, err
	}
	h, err := v.headers(ctx)
	if err != nil {
		return nil, err
	}
	var body []byte
	if err := b.Use(func(p []byte) error {
		// one buffer of the final size: a grown buffer would leave a copy behind
		const head, mid, tail = `{"plaintext":"`, `","associated_data":"`, `"}`
		body = make([]byte, 0, len(head)+base64.StdEncoding.EncodedLen(len(p))+len(mid)+base64.StdEncoding.EncodedLen(len(ad))+len(tail))
		body = append(body, head...)
		body = base64.StdEncoding.AppendEncode(body, p)
		body = append(body, mid...)
		body = base64.StdEncoding.AppendEncode(body, ad)
		body = append(body, tail...)
		return nil
	}); err != nil {
		return nil, err
	}
	status, resp, err := v.c.call(ctx, http.MethodPost, "/v1/"+v.mount+"/encrypt/"+v.name, h, body)
	wipe(body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, vaultStatusErr(status, false)
	}
	return parseVaultEncrypt(resp)
}

// Unwrap implements ports.KeyWrapBackend: POST /v1/<mount>/decrypt/<key> with
// the ciphertext and the same associated_data.
func (v *Vault) Unwrap(ctx context.Context, blob []byte, wc ports.WrapContext) (*secret.Buffer, error) {
	ad, err := wc.Encode()
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 || len(blob) > ports.MaxWrappedBlob || !vaultCT.Match(blob) {
		return nil, fmt.Errorf("%w: the stored blob is not a Vault ciphertext", ports.ErrBackendRefused)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.checkKey(ctx); err != nil {
		return nil, err
	}
	h, err := v.headers(ctx)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(blob)+128)
	body = append(body, `{"ciphertext":"`...)
	body = append(body, blob...) // matched vaultCT: no character JSON escapes
	body = append(body, `","associated_data":"`...)
	body = base64.StdEncoding.AppendEncode(body, ad)
	body = append(body, `"}`...)
	status, resp, err := v.c.call(ctx, http.MethodPost, "/v1/"+v.mount+"/decrypt/"+v.name, h, body)
	if err != nil {
		return nil, err
	}
	defer wipe(resp)
	if status != http.StatusOK {
		return nil, vaultStatusErr(status, true)
	}
	return parseVaultDecrypt(resp)
}

// vaultStatusErr maps a status that is not 200. A 400 of a decrypt is the
// refusal of a wrong context or a changed ciphertext.
func vaultStatusErr(status int, decrypt bool) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: Vault refused the token (status %d)", ports.ErrBackendCredential, status)
	case status == http.StatusNotFound:
		return fmt.Errorf("%w: Vault has no such Transit key or mount (status 404)", ports.ErrBackendConfig)
	case status == http.StatusBadRequest && decrypt:
		return fmt.Errorf("%w: Vault refused to decrypt (status 400)", ports.ErrBackendRefused)
	case status == http.StatusBadRequest:
		return fmt.Errorf("%w: Vault refused the request (status 400)", ports.ErrBackendConfig)
	case status == http.StatusTooManyRequests || status >= 500:
		return fmt.Errorf("%w: Vault answered status %d", ports.ErrBackendUnavailable, status)
	}
	return fmt.Errorf("%w: Vault answered status %d", ports.ErrBackendResponse, status)
}

// vaultData scans a Vault answer for the fields under data (or auth) that the
// call reads. With noWarnings (encrypt and decrypt) it refuses an answer that
// carries warnings: Vault lists there a parameter it ignored (associated_data
// on a server that does not know it), and an ignored parameter here is a
// binding that was not made.
func vaultData(body []byte, noWarnings bool, top string, fields ...string) (map[string]jsonValue, error) {
	paths := []string{top, "warnings"}
	for _, f := range fields {
		paths = append(paths, top+"."+f)
	}
	got, err := scanJSON(body, paths...)
	if err != nil {
		return nil, err
	}
	if w, ok := got["warnings"]; noWarnings && ok && w.kind != 'z' && (w.kind != '[' || len(w.elems) != 0) {
		return nil, fmt.Errorf("%w: Vault answered with warnings (it may have ignored a parameter, such as associated_data on a server that is too old)", ports.ErrBackendResponse)
	}
	if got[top].kind != '{' {
		return nil, fmt.Errorf("%w: the answer has no %s object", ports.ErrBackendResponse, top)
	}
	return got, nil
}

// parseVaultKey reads the type and derived fields of a key read. Both must be
// there with their JSON types.
func parseVaultKey(body []byte) (keyType string, derived bool, err error) {
	f, err := vaultData(body, false, "data", "type", "derived")
	if err != nil {
		return "", false, err
	}
	t, ok := f["data.type"].plainString(body)
	d := f["data.derived"].kind
	if !ok || (d != 't' && d != 'f') {
		return "", false, fmt.Errorf("%w: the key read has no type or derived field", ports.ErrBackendResponse)
	}
	return string(t), d == 't', nil
}

// parseVaultEncrypt reads data.ciphertext: "vault:v<N>:<base64>", at most
// ports.MaxWrappedBlob bytes.
func parseVaultEncrypt(body []byte) ([]byte, error) {
	f, err := vaultData(body, true, "data", "ciphertext")
	if err != nil {
		return nil, err
	}
	c, ok := f["data.ciphertext"].plainString(body)
	if !ok {
		return nil, fmt.Errorf("%w: the encrypt answer has no ciphertext", ports.ErrBackendResponse)
	}
	if len(c) > ports.MaxWrappedBlob || !vaultCT.Match(c) {
		return nil, fmt.Errorf("%w: the encrypt answer is not a Vault ciphertext of at most %d bytes", ports.ErrBackendResponse, ports.MaxWrappedBlob)
	}
	return bytes.Clone(c), nil
}

// parseVaultDecrypt reads data.plaintext, which must be the base64 of exactly
// 32 bytes, into guarded memory, decoding from the answer's own bytes.
func parseVaultDecrypt(body []byte) (*secret.Buffer, error) {
	f, err := vaultData(body, true, "data", "plaintext")
	if err != nil {
		return nil, err
	}
	return secretFromJSON(body, f["data.plaintext"], ports.BackendSecretSize)
}

// parseVaultLogin reads auth.client_token into guarded memory.
func parseVaultLogin(body []byte) (*secret.Buffer, error) {
	f, err := vaultData(body, false, "auth", "client_token")
	if err != nil {
		return nil, err
	}
	in, ok := f["auth.client_token"].plainString(body)
	if !ok || !printableToken(in, 4096) {
		return nil, fmt.Errorf("%w: the login answer's token is not a token", ports.ErrBackendResponse)
	}
	return secret.Fill(len(in), func(d []byte) error { copy(d, in); return nil })
}

// secretFromJSON takes a scanned value that must be a string holding the
// standard base64 of exactly n bytes, with no escape, and decodes it from the
// answer's bytes into guarded memory (the caller zeroes the answer).
func secretFromJSON(body []byte, v jsonValue, n int) (*secret.Buffer, error) {
	in, ok := v.plainString(body)
	if !ok || len(in) != base64.StdEncoding.EncodedLen(n) {
		return nil, fmt.Errorf("%w: the secret in the answer is not the base64 of %d bytes", ports.ErrBackendResponse, n)
	}
	if n != ports.BackendSecretSize {
		return nil, errBadSecret
	}
	return secret.Fill(n, func(d []byte) error {
		// decoded into a fixed array that is zeroed (DecodedLen of the base64 of
		// 32 bytes is 33), then into the guarded buffer
		var tmp [ports.BackendSecretSize + 2]byte
		defer wipe(tmp[:])
		got, err := base64.StdEncoding.Strict().Decode(tmp[:], in)
		if err != nil || got != n {
			return errBadSecret
		}
		copy(d, tmp[:n])
		return nil
	})
}

var errBadSecret = fmt.Errorf("%w: the secret in the answer is not the base64 of %d bytes", ports.ErrBackendResponse, ports.BackendSecretSize)
