package vaultkms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

const testARN = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// refSign is a second, independent SigV4 signer written for the tests from the
// published description (canonical request, string to sign, HMAC chain). The
// fake KMS checks every request with it, so the adapter's signer must agree
// with it byte for byte.
func refSign(r *http.Request, body []byte, keyID, secretKey, region, service string) string {
	names := []string{}
	vals := map[string]string{}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "user-agent" || lk == "accept-encoding" || lk == "content-length" {
			continue
		}
		names = append(names, lk)
		vals[lk] = strings.Join(strings.Fields(strings.Join(v, ",")), " ")
	}
	names = append(names, "host")
	vals["host"] = r.Host
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + vals[n] + "\n")
	}
	ph := sha256.Sum256(body)
	cr := strings.Join([]string{r.Method, "/", "", ch.String(), strings.Join(names, ";"), hex.EncodeToString(ph[:])}, "\n")
	date := r.Header.Get("X-Amz-Date")
	scope := date[:8] + "/" + region + "/" + service + "/aws4_request"
	ch2 := sha256.Sum256([]byte(cr))
	sts := "AWS4-HMAC-SHA256\n" + date + "\n" + scope + "\n" + hex.EncodeToString(ch2[:])
	mac := func(k []byte, s string) []byte { m := hmac.New(sha256.New, k); m.Write([]byte(s)); return m.Sum(nil) }
	k := []byte("AWS4" + secretKey)
	for _, p := range []string{date[:8], region, service, "aws4_request"} {
		k = mac(k, p)
	}
	return "AWS4-HMAC-SHA256 Credential=" + keyID + "/" + scope + ", SignedHeaders=" + strings.Join(names, ";") + ", Signature=" + hex.EncodeToString(mac(k, sts))
}

type fakeKMS struct {
	keyID, secretKey, token string
	arn                     string
	answerKeyID             string // "" answers the true ARN
	key                     []byte
	hits                    atomic.Int32
	hook                    func(w http.ResponseWriter, r *http.Request, body []byte) bool
	badSig                  atomic.Int32
}

func newFakeKMS() *fakeKMS {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &fakeKMS{keyID: "ASIAEXAMPLETEMPKEY01", secretKey: "secretKEYexample/+abc", token: "SESSIONtoken//example==", arn: testARN, key: k}
}

func kmsErr(w http.ResponseWriter, code int, typ string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `{"__type":"com.amazonaws.kms#%s","message":"detail ZZZZ"}`, typ)
}

func (f *fakeKMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if f.hook != nil && f.hook(w, r, body) {
		return
	}
	if r.Header.Get("X-Amz-Security-Token") != f.token {
		kmsErr(w, 400, "UnrecognizedClientException")
		return
	}
	if r.Header.Get("Authorization") != refSign(r, body, f.keyID, f.secretKey, "eu-west-1", "kms") {
		f.badSig.Add(1)
		kmsErr(w, 400, "InvalidSignatureException")
		return
	}
	if r.Header.Get("Content-Type") != "application/x-amz-json-1.1" {
		kmsErr(w, 400, "ValidationException")
		return
	}
	var in struct {
		KeyID             string            `json:"KeyId"`
		Plaintext         []byte            `json:"Plaintext"`
		CiphertextBlob    []byte            `json:"CiphertextBlob"`
		EncryptionContext map[string]string `json:"EncryptionContext"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		kmsErr(w, 400, "SerializationException")
		return
	}
	if in.KeyID != f.arn {
		kmsErr(w, 400, "NotFoundException")
		return
	}
	ad, _ := json.Marshal(in.EncryptionContext)
	b, _ := aes.NewCipher(f.key)
	g, _ := cipher.NewGCM(b)
	answer := f.arn
	if f.answerKeyID != "" {
		answer = f.answerKeyID
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.Encrypt":
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		_ = json.NewEncoder(w).Encode(map[string]any{"CiphertextBlob": g.Seal(nonce, nonce, in.Plaintext, ad), "KeyId": answer, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
	case "TrentService.Decrypt":
		if len(in.CiphertextBlob) < 28 {
			kmsErr(w, 400, "InvalidCiphertextException")
			return
		}
		pt, err := g.Open(nil, in.CiphertextBlob[:12], in.CiphertextBlob[12:], ad)
		if err != nil {
			kmsErr(w, 400, "InvalidCiphertextException")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Plaintext": pt, "KeyId": answer, "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"})
	default:
		kmsErr(w, 400, "UnknownOperationException")
	}
}

func kmsRef(addr string) ports.BackendRef {
	return ports.BackendRef{Kind: ports.BackendAWSKMS, Address: addr, Key: testARN}
}

func envCreds(f *fakeKMS) func(string) string {
	return env("AWS_ACCESS_KEY_ID", f.keyID, "AWS_SECRET_ACCESS_KEY", f.secretKey, "AWS_SESSION_TOKEN", f.token)
}

func tlsKMS(t *testing.T, f *fakeKMS) (*httptest.Server, KMSOptions) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return srv, KMSOptions{PrivateEndpoint: srv.URL, PrivateCAFile: caFile(t, srv), Getenv: envCreds(f), Timeout: 5 * time.Second}
}

// spec: SPO-Xunlock-IF-010, SPO-Xunlock-IF-007, SPO-Xunlock-SEC-008
func TestKMSPassesTheContract(t *testing.T) {
	f := newFakeKMS()
	srv, o := tlsKMS(t, f)
	k, err := NewKMS(kmsRef(srv.URL), o)
	if err != nil {
		t.Fatal(err)
	}
	porttest.KeyWrapContract(t, porttest.KeyWrapSubject{Backend: k, Secrets: []string{f.secretKey, f.token}})
	if f.badSig.Load() != 0 {
		t.Errorf("%d requests failed the reference signature check", f.badSig.Load())
	}
}

// The encryption context KMS receives is decision 5's, and the request is
// signed as the reference signer signs it.
//
// spec: SPO-Xunlock-IF-010, SPO-Xunlock-IN-004
func TestKMSSendsTheEncryptionContext(t *testing.T) {
	f := newFakeKMS()
	var ctxSeen map[string]string
	inner := f.hook
	f.hook = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		var in struct {
			EncryptionContext map[string]string `json:"EncryptionContext"`
		}
		_ = json.Unmarshal(body, &in)
		ctxSeen = in.EncryptionContext
		return inner != nil && inner(w, r, body)
	}
	srv, o := tlsKMS(t, f)
	k, _ := NewKMS(kmsRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	if _, err := k.Wrap(context.Background(), b, wcA); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"spo-genesis": strings.Repeat("01", 16), "spo-slot": strings.Repeat("02", 16)}
	if fmt.Sprint(ctxSeen) != fmt.Sprint(want) {
		t.Errorf("context %v", ctxSeen)
	}
}

// Static long-lived keys are refused with the remedy; temporary keys with a
// session token are used.
//
// spec: SPO-Xunlock-PRE-040, SPO-Xunlock-SEC-009
func TestKMSRefusesStaticKeys(t *testing.T) {
	f := newFakeKMS()
	srv, o := tlsKMS(t, f)
	try := func(getenv func(string) string) error {
		o.Getenv = getenv
		k, err := NewKMS(kmsRef(srv.URL), o)
		if err != nil {
			return err
		}
		b := newB(t)
		defer b.Destroy()
		_, err = k.Wrap(context.Background(), b, wcA)
		return err
	}
	err := try(env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
	if !errors.Is(err, ports.ErrBackendCredential) || !strings.Contains(err.Error(), "AWS_SESSION_TOKEN") || !strings.Contains(err.Error(), "web identity") || strings.Contains(err.Error(), "wJalr") {
		t.Errorf("static keys: %v", err)
	}
	err = try(env("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY", "wJalr", "AWS_SESSION_TOKEN", "tok"))
	if !errors.Is(err, ports.ErrBackendCredential) {
		t.Errorf("a long-term key id with a session token: %v", err)
	}
	if err := try(env()); !errors.Is(err, ports.ErrBackendCredential) {
		t.Errorf("no credentials: %v", err)
	}
	if f.hits.Load() != 0 {
		t.Error("a refused credential reached the server")
	}
	if err := try(envCreds(f)); err != nil {
		t.Errorf("temporary credentials: %v", err)
	}
}

type fakeSTS struct {
	jwt, role string
	kms       *fakeKMS
	expires   time.Time
	keyID     string
	body      string // when set, the raw answer
	hits      atomic.Int32
}

func (s *fakeSTS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	if s.body != "" {
		_, _ = w.Write([]byte(s.body))
		return
	}
	_ = r.ParseForm()
	if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("WebIdentityToken") != s.jwt || r.Form.Get("RoleArn") != s.role || r.Form.Get("Version") != "2011-06-15" || r.Header.Get("Authorization") != "" {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`))
		return
	}
	kid := s.keyID
	if kid == "" {
		kid = s.kms.keyID
	}
	_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
		kid, s.kms.secretKey, s.kms.token, s.expires.UTC().Format(time.RFC3339))
}

// spec: SPO-Xunlock-IF-011, SPO-Xunlock-SEC-009
func TestKMSWebIdentityThroughSTS(t *testing.T) {
	f := newFakeKMS()
	srv, o := tlsKMS(t, f)
	s := &fakeSTS{jwt: "eyJ.web.identity", role: "arn:aws:iam::111122223333:role/spo-unlock", kms: f, expires: time.Now().Add(time.Hour)}
	ssrv := httptest.NewServer(s)
	defer ssrv.Close()
	tokFile := filepath.Join(t.TempDir(), "token")
	_ = os.WriteFile(tokFile, []byte(s.jwt), 0o600)
	o.Getenv = env()
	o.PrivateSTSEndpoint, o.AllowLoopbackHTTP = ssrv.URL, true
	o.WebIdentityTokenFile = tokFile
	o.RoleARN = s.role
	k, err := NewKMS(kmsRef(srv.URL), o)
	if err != nil {
		t.Fatal(err)
	}
	porttest.KeyWrapContract(t, porttest.KeyWrapSubject{Backend: k, Secrets: []string{f.secretKey, f.token, s.jwt}})
	if s.hits.Load() != 1 {
		t.Errorf("STS asked %d times; the credentials are cached until they expire", s.hits.Load())
	}
	// From the environment, as an EKS or GitHub Actions runner sets it.
	o.WebIdentityTokenFile, o.RoleARN = "", ""
	o.Getenv = env("AWS_WEB_IDENTITY_TOKEN_FILE", tokFile, "AWS_ROLE_ARN", s.role)
	k, _ = NewKMS(kmsRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	if _, err := k.Wrap(context.Background(), b, wcA); err != nil {
		t.Errorf("web identity from the environment: %v", err)
	}
	// Hostile or useless STS answers.
	for name, sts := range map[string]*fakeSTS{
		"expired":            {jwt: s.jwt, role: s.role, kms: f, expires: time.Now().Add(-time.Minute)},
		"long-term key id":   {jwt: s.jwt, role: s.role, kms: f, expires: time.Now().Add(time.Hour), keyID: "AKIAIOSFODNN7EXAMPLE"},
		"no session token":   {body: `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAEXAMPLETEMPKEY01</AccessKeyId><SecretAccessKey>x</SecretAccessKey><Expiration>2999-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`},
		"not xml":            {body: `{"Credentials":{}}`},
		"oversized":          {body: "<a>" + strings.Repeat("x", 200<<10) + "</a>"},
		"wrong root":         {body: `<Other><AssumeRoleWithWebIdentityResult/></Other>`},
		"refused":            {jwt: "other", role: s.role, kms: f, expires: time.Now().Add(time.Hour)},
		"nested entity bomb": {body: `<!DOCTYPE a [<!ENTITY x "xxxx">]><AssumeRoleWithWebIdentityResponse>&x;</AssumeRoleWithWebIdentityResponse>`},
	} {
		ss := httptest.NewServer(sts)
		kmsHits := f.hits.Load()
		o2 := o
		o2.Getenv = env()
		o2.PrivateSTSEndpoint, o2.WebIdentityTokenFile, o2.RoleARN = ss.URL, tokFile, s.role
		k, err := NewKMS(kmsRef(srv.URL), o2)
		if err == nil {
			b := newB(t)
			_, err = k.Wrap(context.Background(), b, wcA)
			b.Destroy()
		}
		ss.Close()
		if !errors.Is(err, ports.ErrBackendCredential) && !errors.Is(err, ports.ErrBackendResponse) {
			t.Errorf("%s: %v", name, err)
		}
		if f.hits.Load() != kmsHits {
			t.Errorf("%s: KMS was called with credentials STS should not have given", name)
		}
		if err != nil && (strings.Contains(err.Error(), f.secretKey) || strings.Contains(err.Error(), s.jwt)) {
			t.Errorf("%s: the error carries a credential: %v", name, err)
		}
	}
	// Only one of the two settings is a configuration error.
	o3 := o
	o3.Getenv, o3.RoleARN, o3.WebIdentityTokenFile = env(), "", tokFile
	if k, err := NewKMS(kmsRef(srv.URL), o3); err == nil {
		b := newB(t)
		_, err = k.Wrap(context.Background(), b, wcA)
		b.Destroy()
		if !errors.Is(err, ports.ErrBackendCredential) {
			t.Errorf("a token file with no role: %v", err)
		}
	}
}

// The key id of every answer must be the configured key ARN.
//
// spec: SPO-Xunlock-PRE-041
func TestKMSChecksTheKeyIDOfTheAnswer(t *testing.T) {
	f := newFakeKMS()
	srv, o := tlsKMS(t, f)
	k, _ := NewKMS(kmsRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	blob, err := k.Wrap(context.Background(), b, wcA)
	if err != nil {
		t.Fatal(err)
	}
	f.answerKeyID = "arn:aws:kms:eu-west-1:111122223333:key/ffffffff-12ab-34cd-56ef-1234567890ab"
	if out, err := k.Unwrap(context.Background(), blob, wcA); !errors.Is(err, ports.ErrBackendResponse) {
		if err == nil {
			out.Destroy()
		}
		t.Errorf("decrypt with another key id: %v", err)
	}
	if _, err := k.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendResponse) {
		t.Errorf("encrypt with another key id: %v", err)
	}
}

// spec: SPO-Xunlock-PRE-041, SPO-Xunlock-PRE-039
func TestKMSKeyAndEndpointShape(t *testing.T) {
	for _, arn := range []string{"alias/spo", "arn:aws:kms:eu-west-1:111122223333:alias/spo", "arn:aws:kms:eu-west-1:1111:key/x", "arn:aws:s3:::bucket", "1234abcd-12ab-34cd-56ef-1234567890ab", "arn:aws:kms:EU:111122223333:key/x"} {
		r := kmsRef("https://kms.eu-west-1.amazonaws.com")
		r.Key = arn
		if _, err := NewKMS(r, KMSOptions{Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%s: %v", arn, err)
		}
	}
	for _, a := range []string{"http://kms.eu-west-1.amazonaws.com", "https://kms.eu-west-1.amazonaws.com/x"} {
		if _, err := NewKMS(kmsRef(a), KMSOptions{Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if e, err := DefaultKMSEndpoint(testARN); err != nil || e != "https://kms.eu-west-1.amazonaws.com" {
		t.Errorf("default endpoint %q %v", e, err)
	}
	cn := "arn:aws-cn:kms:cn-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	if e, err := DefaultKMSEndpoint(cn); err != nil || e != "https://kms.cn-north-1.amazonaws.com.cn" {
		t.Errorf("china endpoint %q %v", e, err)
	}
}

// spec: SPO-Xunlock-SEC-010
func TestKMSTreatsTheAnswerAsHostile(t *testing.T) {
	cases := map[string]struct {
		hook func(w http.ResponseWriter, r *http.Request, body []byte) bool
		want error
	}{
		"plaintext of 31 bytes": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			_, _ = fmt.Fprintf(w, `{"KeyId":%q,"Plaintext":"%s","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`, testARN, base64.StdEncoding.EncodeToString(make([]byte, 31)))
			return true
		}, ports.ErrBackendResponse},
		"plaintext a list": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			_, _ = fmt.Fprintf(w, `{"KeyId":%q,"Plaintext":[1,2],"EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`, testARN)
			return true
		}, ports.ErrBackendResponse},
		"key id a number": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			_, _ = fmt.Fprintf(w, `{"KeyId":5,"Plaintext":"%s"}`, base64.StdEncoding.EncodeToString(make([]byte, 32)))
			return true
		}, ports.ErrBackendResponse},
		"key id missing": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			_, _ = fmt.Fprintf(w, `{"Plaintext":"%s","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`, base64.StdEncoding.EncodeToString(make([]byte, 32)))
			return true
		}, ports.ErrBackendResponse},
		"oversized": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool { stream(w, 4<<20); return true }, ports.ErrBackendResponse},
		"redirect": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			http.Redirect(w, r, "https://example.invalid/", http.StatusFound)
			return true
		}, ports.ErrBackendResponse},
		"refused": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 400, "InvalidCiphertextException")
			return true
		}, ports.ErrBackendRefused},
		"wrong key": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 400, "IncorrectKeyException")
			return true
		}, ports.ErrBackendRefused},
		"denied": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 400, "AccessDeniedException")
			return true
		}, ports.ErrBackendCredential},
		"expired": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 400, "ExpiredTokenException")
			return true
		}, ports.ErrBackendCredential},
		"disabled": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 400, "DisabledException")
			return true
		}, ports.ErrBackendConfig},
		"throttled": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 400, "ThrottlingException")
			return true
		}, ports.ErrBackendUnavailable},
		"internal": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			kmsErr(w, 500, "KMSInternalException")
			return true
		}, ports.ErrBackendUnavailable},
		"error junk": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			w.WriteHeader(400)
			_, _ = w.Write([]byte("ZZZZ"))
			return true
		}, ports.ErrBackendResponse},
		"asymmetric": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			_, _ = fmt.Fprintf(w, `{"KeyId":%q,"Plaintext":"%s","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"}`, testARN, base64.StdEncoding.EncodeToString(make([]byte, 32)))
			return true
		}, ports.ErrBackendResponse},
		"stall": {func(w http.ResponseWriter, r *http.Request, _ []byte) bool {
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
			return true
		}, ports.ErrBackendUnavailable},
	}
	for name, c := range cases {
		f := newFakeKMS()
		f.hook = c.hook
		srv, o := tlsKMS(t, f)
		o.Timeout = 500 * time.Millisecond
		k, _ := NewKMS(kmsRef(srv.URL), o)
		out, err := k.Unwrap(context.Background(), bytes.Repeat([]byte{9}, 60), wcA)
		if err == nil {
			out.Destroy()
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), "ZZZZ") || strings.Contains(err.Error(), f.token) || strings.Contains(err.Error(), f.secretKey)) {
			t.Errorf("%s: the error carries the answer or a credential: %v", name, err)
		}
	}
	// a wrap answer whose ciphertext is not base64, too long or missing
	for _, body := range []string{`{"KeyId":"` + testARN + `","CiphertextBlob":"!!","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`,
		`{"KeyId":"` + testARN + `","CiphertextBlob":"` + base64.StdEncoding.EncodeToString(make([]byte, 5000)) + `","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`,
		`{"KeyId":"` + testARN + `","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`} {
		f := newFakeKMS()
		body := body
		f.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool { _, _ = w.Write([]byte(body)); return true }
		srv, o := tlsKMS(t, f)
		k, _ := NewKMS(kmsRef(srv.URL), o)
		b := newB(t)
		if _, err := k.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendResponse) {
			t.Errorf("wrap answer %.60s: %v", body, err)
		}
		b.Destroy()
	}
}

// spec: SPO-Xunlock-SEC-010
func TestKMSBoundsTheAnswerBeforeAllocating(t *testing.T) {
	f := newFakeKMS()
	f.hook = func(w http.ResponseWriter, r *http.Request, _ []byte) bool { stream(w, 4<<20); return true }
	srv := httptest.NewServer(f)
	defer srv.Close()
	k, err := NewKMS(kmsRef(srv.URL), KMSOptions{Getenv: envCreds(f), Timeout: 5 * time.Second, PrivateEndpoint: srv.URL, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	var uerr error
	n := allocated(func() {
		out, err := k.Unwrap(context.Background(), bytes.Repeat([]byte{9}, 60), wcA)
		if err == nil {
			out.Destroy()
		}
		uerr = err
	})
	if !errors.Is(uerr, ports.ErrBackendResponse) || n > 1<<20 {
		t.Errorf("oversized: %v, %d bytes allocated", uerr, n)
	}
}
