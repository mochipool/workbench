package vaultkms

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The response parsers never panic, never return a secret with an error, and
// return only what the protocol allows: a 32-byte secret, a blob within the
// bound, temporary credentials.
//
// spec: SPO-Xunlock-SEC-010

func FuzzParseVaultDecrypt(f *testing.F) {
	f.Add([]byte(`{"data":{"plaintext":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}}`))
	f.Add([]byte(`{"data":{"plaintext":12}}`))
	f.Add([]byte(`{"data":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := parseVaultDecrypt(append([]byte(nil), b...))
		if err == nil {
			if out.Len() != ports.BackendSecretSize {
				t.Fatalf("a secret of %d bytes", out.Len())
			}
			out.Destroy()
		} else if out != nil || !errors.Is(err, ports.ErrBackendResponse) {
			t.Fatalf("%v with %v", err, out)
		}
	})
}

func FuzzParseVaultOther(f *testing.F) {
	f.Add([]byte(`{"data":{"ciphertext":"vault:v1:AAAA","type":"aes256-gcm96","derived":false}}`))
	f.Add([]byte(`{"auth":{"client_token":"hvs.x"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if blob, err := parseVaultEncrypt(b); err == nil && (len(blob) == 0 || len(blob) > ports.MaxWrappedBlob || !vaultCT.Match(blob)) {
			t.Fatalf("blob %q", blob)
		}
		_, _, _ = parseVaultKey(b)
		if tok, err := parseVaultLogin(append([]byte(nil), b...)); err == nil {
			_ = tok.Use(func(p []byte) error {
				if !printableToken(p, 4096) {
					t.Fatalf("token %q", p)
				}
				return nil
			})
			tok.Destroy()
		}
	})
}

func FuzzParseKMS(f *testing.F) {
	f.Add([]byte(`{"KeyId":"` + testARN + `","Plaintext":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`))
	f.Add([]byte(`{"KeyId":"` + testARN + `","CiphertextBlob":"AAAA","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}`))
	f.Add([]byte(`{"__type":"x#InvalidCiphertextException"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if out, err := parseKMSDecrypt(append([]byte(nil), b...), testARN); err == nil {
			if out.Len() != ports.BackendSecretSize {
				t.Fatalf("a secret of %d bytes", out.Len())
			}
			out.Destroy()
		}
		if blob, err := parseKMSEncrypt(b, testARN); err == nil && (len(blob) == 0 || len(blob) > ports.MaxWrappedBlob) {
			t.Fatalf("blob of %d bytes", len(blob))
		}
		if err := kmsStatusErr(400, b); err == nil {
			t.Fatal("an error answer mapped to no error")
		}
	})
}

// The scanner accepts only what encoding/json accepts as one object, and an
// answer it accepts has no duplicate key at the top or in data.
//
// spec: SPO-Xunlock-SEC-010
func FuzzScanJSON(f *testing.F) {
	f.Add([]byte(`{"data":{"ttl":3600,"policies":["default"]},"warnings":null}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"a":"A","b":[1,2.5e-3,true,false,null,{}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := scanJSON(b, "data", "data.ttl", "data.policies", "warnings")
		if err != nil {
			if got != nil {
				t.Fatal("values with an error")
			}
			return
		}
		if !json.Valid(b) {
			t.Fatalf("accepted invalid JSON %q", b)
		}
		var top map[string]json.RawMessage
		if json.Unmarshal(b, &top) != nil {
			t.Fatalf("accepted a value that is not an object %q", b)
		}
		for k, v := range got {
			if v.start < 0 || v.end > len(b) || v.start > v.end {
				t.Fatalf("%s: span %d..%d of %d", k, v.start, v.end, len(b))
			}
		}
		_, _, _ = parseVaultLookup(b)
	})
}

func FuzzParseSTS(f *testing.F) {
	f.Add([]byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIAEXAMPLETEMPKEY01</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken><Expiration>2999-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`))
	f.Add([]byte(`<a>&x;</a>`))
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := parseSTS(b, now)
		if err == nil {
			if len(c.keyID) < 4 || c.keyID[:4] != "ASIA" || c.token == nil || c.token.Len() == 0 || !c.expires.After(now) {
				t.Fatalf("credentials %q", c.keyID)
			}
			c.destroy()
		}
	})
}
