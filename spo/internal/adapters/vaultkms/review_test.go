package vaultkms

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Plain http to a loopback address is an explicit opt-in of the local
// configuration; without it every address needs TLS.
//
// spec: SPO-Xunlock-PRE-039
func TestPlainHTTPToLoopbackNeedsTheOptIn(t *testing.T) {
	for _, a := range []string{"http://127.0.0.1:8200", "http://[::1]:8200"} {
		if _, err := NewVault(vaultRef(a), VaultOptions{Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%s without the opt-in: %v", a, err)
		}
	}
}

// The KMS address is the public endpoint of the key's region unless the
// configuration names a private endpoint.
//
// spec: SPO-Xunlock-PRE-039, SPO-Xunlock-PRE-046
func TestKMSAddressIsDerivedFromTheKeyARN(t *testing.T) {
	for _, a := range []string{"https://attacker.example", "https://kms.us-east-1.amazonaws.com"} {
		if _, err := NewKMS(kmsRef(a), KMSOptions{Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if _, err := NewKMS(kmsRef("https://kms.eu-west-1.amazonaws.com"), KMSOptions{Getenv: env()}); err != nil {
		t.Errorf("the public endpoint of the key's region: %v", err)
	}
}

// Environment credentials are accepted only with a temporary key id (ASIA): an
// allow-list, not a refusal of AKIA alone.
//
// spec: SPO-Xunlock-PRE-040
func TestKMSEnvironmentCredentialsMustBeTemporary(t *testing.T) {
	f := newFakeKMS()
	srv, o := tlsKMS(t, f)
	for _, id := range []string{"ABIAEXAMPLEKEY000001", "AROAEXAMPLEKEY000001", "AIDAEXAMPLEKEY000001"} {
		o.Getenv = env("AWS_ACCESS_KEY_ID", id, "AWS_SECRET_ACCESS_KEY", f.secretKey, "AWS_SESSION_TOKEN", f.token)
		k, err := NewKMS(kmsRef(srv.URL), o)
		if err == nil {
			b := newB(t)
			_, err = k.Wrap(context.Background(), b, wcA)
			b.Destroy()
		}
		if !errors.Is(err, ports.ErrBackendCredential) || f.hits.Load() != 0 {
			t.Errorf("key id %s: %v (%d requests reached KMS)", id, err, f.hits.Load())
		}
	}
}

// A duplicate key in an answer has two meanings; it is refused.
//
// spec: SPO-Xunlock-SEC-010
func TestAnswersWithADuplicateKeyAreRefused(t *testing.T) {
	a := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	z := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, body := range []string{
		`{"data":{"plaintext":"` + a + `","plaintext":"` + z + `"}}`,
		`{"data":{"plaintext":"` + a + `"},"data":{"plaintext":"` + z + `"}}`,
	} {
		if out, err := parseVaultDecrypt([]byte(body)); err == nil {
			out.Destroy()
			t.Errorf("accepted %s", body)
		}
	}
	if out, err := parseKMSDecrypt([]byte(`{"KeyId":"`+testARN+`","KeyId":"`+testARN+`","Plaintext":"`+a+`","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`), testARN); err == nil {
		out.Destroy()
		t.Error("a KMS answer with two key ids")
	}
}

// A Vault that does not know associated_data says so in "warnings" (it ignored
// a parameter); a warning on encrypt or decrypt is a failure.
//
// spec: SPO-Xunlock-PRE-047
func TestVaultWarningIsAFailure(t *testing.T) {
	f := newFakeVault()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:AAAA"},"warnings":["Endpoint ignored these unrecognized parameters: [associated_data]"]}`))
			return true
		}
		return false
	}
	srv, o := tlsVault(t, f)
	v, _ := NewVault(vaultRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	if _, err := v.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendResponse) {
		t.Errorf("a warning on encrypt: %v", err)
	}
}

// A secret file that is a symbolic link or a FIFO is refused, and the FIFO does
// not block the read.
//
// spec: SPO-Xunlock-PRE-048
func TestCredentialFilesAreOpenedSafely(t *testing.T) {
	f := newFakeVault()
	srv, o := tlsVault(t, f)
	dir := t.TempDir()
	real := filepath.Join(dir, "jwt-real")
	if err := os.WriteFile(real, []byte(f.jwt), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "jwt-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "jwt-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"symlink": link, "fifo": fifo} {
		o2 := o
		o2.Auth, o2.JWTRole, o2.JWTFile, o2.Getenv = "jwt", f.jwtRole, path, env()
		v, err := NewVault(vaultRef(srv.URL), o2)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			b := newB(t)
			defer b.Destroy()
			_, err := v.Wrap(context.Background(), b, wcA)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ports.ErrBackendCredential) {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the read blocked", name)
		}
	}
}

// A token that does not expire (ttl 0) or has the root policy is refused
// before it is used for anything else.
//
// spec: SPO-Xunlock-PRE-049
func TestVaultRefusesALongLivedOrRootToken(t *testing.T) {
	for name, c := range map[string]struct {
		lookup string
		want   error
	}{
		"ttl 0":                {`{"ttl":0,"policies":["default"]}`, ports.ErrBackendCredential},
		"root policy":          {`{"ttl":3600,"policies":["default","root"]}`, ports.ErrBackendCredential},
		"no ttl":               {`{"policies":["default"]}`, ports.ErrBackendResponse},
		"ttl a text":           {`{"ttl":"3600","policies":["default"]}`, ports.ErrBackendResponse},
		"ttl negative":         {`{"ttl":-1,"policies":["default"]}`, ports.ErrBackendResponse},
		"ttl a fraction":       {`{"ttl":1.5,"policies":["default"]}`, ports.ErrBackendResponse},
		"ttl of eleven digits": {`{"ttl":12345678901,"policies":["default"]}`, ports.ErrBackendResponse},
		"no policies":          {`{"ttl":3600}`, ports.ErrBackendResponse},
		"policies a text":      {`{"ttl":3600,"policies":"root"}`, ports.ErrBackendResponse},
		"an escaped root":      {`{"ttl":3600,"policies":["r` + "\\" + `u006fot"]}`, ports.ErrBackendResponse},
		"a policy a number":    {`{"ttl":3600,"policies":[7]}`, ports.ErrBackendResponse},
		"two ttls":             {`{"ttl":3600,"ttl":0,"policies":["default"]}`, ports.ErrBackendResponse},
		"too many policies":    {`{"ttl":3600,"policies":[` + strings.Repeat(`"p",`, 64) + `"p"]}`, ports.ErrBackendResponse},
	} {
		f := newFakeVault()
		f.lookup = c.lookup
		srv, o := tlsVault(t, f)
		v, _ := NewVault(vaultRef(srv.URL), o)
		b := newB(t)
		_, err := v.Wrap(context.Background(), b, wcA)
		b.Destroy()
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), f.token) {
			t.Errorf("%s: the error carries the token", name)
		}
		if len(f.seen) != 1 {
			t.Errorf("%s: %d requests; nothing is asked after a refused token lookup", name, len(f.seen))
		}
	}
	// the token of a JWT login is looked up too
	f := newFakeVault()
	f.lookup = `{"ttl":0,"policies":["default"]}`
	srv, o := tlsVault(t, f)
	jwtFile := filepath.Join(t.TempDir(), "jwt")
	_ = os.WriteFile(jwtFile, []byte(f.jwt), 0o600)
	o.Auth, o.JWTRole, o.JWTFile, o.Getenv = "jwt", f.jwtRole, jwtFile, env()
	v, _ := NewVault(vaultRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	if _, err := v.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendCredential) {
		t.Errorf("a JWT login that gives a token without a TTL: %v", err)
	}
}

// A secret file owned by another user, and a CA file that others can change,
// are refused; a CA file owned by root is accepted.
//
// spec: SPO-Xunlock-PRE-048
func TestCredentialFileOwnerAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("hvs.x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmallFile(p, maxSecretFile, true); err != nil {
		t.Fatalf("own file: %v", err)
	}
	me := processUID()
	processUID = func() int { return me + 1 }
	_, err := readSmallFile(p, maxSecretFile, true)
	processUID = os.Getuid
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("a secret file of another user: %v", err)
	}
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, []byte("x"), 0o644)
	if _, err := readSmallFile(ca, maxCAFile, false); err != nil {
		t.Errorf("a CA file others can read: %v", err)
	}
	_ = os.Chmod(ca, 0o666)
	if _, err := readSmallFile(ca, maxCAFile, false); err == nil {
		t.Error("a CA file others can change")
	}
	_ = os.Chmod(ca, 0o644)
	processUID = func() int { return me + 1 }
	_, err = readSmallFile(ca, maxCAFile, false)
	processUID = os.Getuid
	if me != 0 && err == nil {
		t.Error("a CA file of another user (not root)")
	}
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(big, make([]byte, maxSecretFile+1), 0o600)
	if _, err := readSmallFile(big, maxSecretFile, true); err == nil {
		t.Error("a file over the bound")
	}
	if _, err := readSmallFile(filepath.Join(dir, "none"), maxSecretFile, true); !errors.Is(err, errNoFile) {
		t.Errorf("a missing file: %v", err)
	}
}

// The STS endpoint is the public one of the key ARN's partition and region;
// another is an explicit opt-in, and plain http needs the loopback opt-in too.
//
// spec: SPO-Xunlock-PRE-046
func TestSTSEndpointIsDerivedUnlessPrivate(t *testing.T) {
	pub := "https://kms.eu-west-1.amazonaws.com"
	k, err := NewKMS(kmsRef(pub), KMSOptions{Getenv: env()})
	if err != nil || k.sts != "https://sts.eu-west-1.amazonaws.com" || k.stsCA != "" || k.stsHTTP {
		t.Fatalf("default STS: %+v %v", k, err)
	}
	cn := ports.BackendRef{Kind: ports.BackendAWSKMS, Address: "https://kms.cn-north-1.amazonaws.com.cn", Key: "arn:aws-cn:kms:cn-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"}
	if k, err := NewKMS(cn, KMSOptions{Getenv: env()}); err != nil || k.sts != "https://sts.cn-north-1.amazonaws.com.cn" {
		t.Errorf("china STS: %v", err)
	}
	if _, err := NewKMS(kmsRef(pub), KMSOptions{Getenv: env(), PrivateSTSEndpoint: "http://127.0.0.1:9"}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("a plain-http private STS without the loopback opt-in: %v", err)
	}
	if _, err := NewKMS(kmsRef(pub), KMSOptions{Getenv: env(), PrivateSTSEndpoint: "http://10.0.0.1:9", AllowLoopbackHTTP: true}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("a plain-http private STS that is not loopback: %v", err)
	}
	if _, err := NewKMS(kmsRef(pub), KMSOptions{Getenv: env(), PrivateSTSCAFile: "/x"}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("an STS CA without a private STS endpoint: %v", err)
	}
	if _, err := NewKMS(kmsRef(pub), KMSOptions{Getenv: env(), PrivateCAFile: "/x"}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("a KMS CA without a private endpoint: %v", err)
	}
	// a private KMS endpoint does not move STS
	if k, err := NewKMS(kmsRef("https://vpce.example"), KMSOptions{Getenv: env(), PrivateEndpoint: "https://vpce.example"}); err != nil || k.sts != "https://sts.eu-west-1.amazonaws.com" {
		t.Errorf("a private KMS endpoint: %v", err)
	}
	// the private CA is for the private endpoint only: the public endpoint uses the system roots
	if _, err := NewKMS(kmsRef(pub), KMSOptions{Getenv: env(), PrivateEndpoint: "https://vpce.example", PrivateCAFile: "/nonexistent"}); err != nil {
		t.Errorf("the public endpoint with a private CA configured: %v", err)
	}
}

// The STS secrets are taken from the answer's bytes only when each element
// occurs once, as plain text inside Credentials.
//
// spec: SPO-Xunlock-IF-011, SPO-Xunlock-SEC-008
func TestSTSSecretsAreTakenFromOneElementEach(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wrap := func(inner string) []byte {
		return []byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>` + inner + `</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
	}
	creds := func(sk, st string) string {
		return `<Credentials><AccessKeyId>ASIAEXAMPLETEMPKEY01</AccessKeyId><SecretAccessKey>` + sk + `</SecretAccessKey><SessionToken>` + st + `</SessionToken><Expiration>2999-01-01T00:00:00Z</Expiration></Credentials>`
	}
	c, err := parseSTS(wrap(creds("SeCrEt", "ToKeN")), now)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.secret.Use(func(p []byte) error {
		if string(p) != "SeCrEt" {
			t.Errorf("secret %q", p)
		}
		return nil
	})
	c.destroy()
	for name, body := range map[string][]byte{
		"two secrets":         wrap(creds("a", "b") + `<SecretAccessKey>c</SecretAccessKey>`),
		"one in a comment":    wrap(`<!--<SessionToken>z</SessionToken>-->` + creds("a", "b")),
		"outside Credentials": wrap(`<Credentials><AccessKeyId>ASIAEXAMPLETEMPKEY01</AccessKeyId><Expiration>2999-01-01T00:00:00Z</Expiration></Credentials><SecretAccessKey>a</SecretAccessKey><SessionToken>b</SessionToken>`),
		"an entity":           wrap(creds("a&amp;b", "t")),
		"CDATA":               wrap(creds("<![CDATA[a]]>", "t")),
		"an attribute":        []byte(strings.Replace(string(wrap(creds("a", "b"))), "<SecretAccessKey>", `<SecretAccessKey x="1">`, 1)),
	} {
		if c, err := parseSTS(body, now); err == nil {
			c.destroy()
			t.Errorf("%s: accepted", name)
		}
	}
}

// A declared length over the bound is refused before anything is read or
// allocated for it.
//
// spec: SPO-Xunlock-SEC-010
func TestADeclaredLengthOverTheBoundIsRefusedFirst(t *testing.T) {
	f := newFakeVault()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", "1073741824")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{}"))
		return true
	}
	srv, o := tlsVault(t, f)
	v, _ := NewVault(vaultRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	var err error
	n := allocated(func() { _, err = v.Wrap(context.Background(), b, wcA) })
	if !errors.Is(err, ports.ErrBackendResponse) || !strings.Contains(err.Error(), "1073741824") {
		t.Errorf("a declared length of 1 GiB: %v", err)
	}
	if n > 1<<20 {
		t.Errorf("allocated %d bytes", n)
	}
}

// A Vault that ignores associated_data and warns about it is refused at the
// first encrypt; one that ignores it silently passes here and is caught at
// enrolment by the store (an unwrap under another slot id must be refused).
//
// spec: SPO-Xunlock-PRE-047
func TestVaultThatIgnoresAssociatedData(t *testing.T) {
	f := newFakeVault()
	f.ignoreAD, f.warn = true, true
	srv, o := tlsVault(t, f)
	v, _ := NewVault(vaultRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	if _, err := v.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendResponse) || !strings.Contains(err.Error(), "warnings") {
		t.Errorf("a Vault that warns: %v", err)
	}
	f.warn = false
	blob, err := v.Wrap(context.Background(), b, wcA)
	if err != nil {
		t.Fatal(err)
	}
	other := wcA
	other.SlotID = []byte("another slot id!")
	if out, err := v.Unwrap(context.Background(), blob, other); err != nil {
		t.Fatalf("the silent fake should unwrap under any context: %v", err)
	} else {
		out.Destroy()
	}
}
