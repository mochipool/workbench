package config

import (
	"strings"
	"testing"
)

// [vault] and [kms] are read, written back unchanged, and checked; a token or
// access key has no key to go in.
//
// spec: SPO-Xunlock-IF-012
func TestBackendSectionsRoundTrip(t *testing.T) {
	text := `network = "preview"
mode = "offline"

[vault]
address = "https://vault.example:8200"
namespace = "ops"
mount = "transit"
key = "spo-unlock"
ca_file = "/etc/spo/vault-ca.pem"
auth = "jwt"
jwt_mount = "jwt"
jwt_role = "spo"
jwt_file = "/run/user/1000/vault.jwt"
timeout_seconds = 20
allow_loopback_http = true

[kms]
key_arn = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
private_endpoint = "https://vpce-1.kms.eu-west-1.vpce.amazonaws.com"
private_ca_file = "/etc/spo/kms-ca.pem"
private_sts_endpoint = "https://vpce-2.sts.eu-west-1.vpce.amazonaws.com"
private_sts_ca_file = "/etc/spo/sts-ca.pem"
role_arn = "arn:aws:iam::111122223333:role/spo-unlock"
web_identity_token_file = "/run/user/1000/aws.jwt"
`
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if c.Vault == nil || c.Vault.Address != "https://vault.example:8200" || c.Vault.Auth != "jwt" || c.Vault.TimeoutSeconds != 20 || c.Vault.JWTFile != "/run/user/1000/vault.jwt" {
		t.Fatalf("vault %+v", c.Vault)
	}
	if c.KMS == nil || !strings.HasPrefix(c.KMS.KeyARN, "arn:aws:kms:") || c.KMS.WebIdentityTokenFile != "/run/user/1000/aws.jwt" ||
		c.KMS.PrivateSTSEndpoint == "" || c.KMS.PrivateSTSCAFile != "/etc/spo/sts-ca.pem" || c.KMS.AllowLoopbackHTTP {
		t.Fatalf("kms %+v", c.KMS)
	}
	if !c.Vault.AllowLoopbackHTTP {
		t.Fatal("allow_loopback_http was not read")
	}
	out, err := Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if *c2.Vault != *c.Vault || *c2.KMS != *c.KMS {
		t.Errorf("round trip:\n%s", out)
	}
	for name, bad := range map[string]string{
		"a token key":       "[vault]\ntoken = \"hvs.x\"\n",
		"an access key":     "[kms]\naccess_key_id = \"AKIA\"\n",
		"a secret key":      "[kms]\nsecret_access_key = \"x\"\n",
		"unknown auth":      "[vault]\nauth = \"approle\"\n",
		"timeout zero":      "[vault]\ntimeout_seconds = 0\n",
		"timeout too long":  "[kms]\ntimeout_seconds = 601\n",
		"timeout as text":   "[kms]\ntimeout_seconds = \"5\"\n",
		"address a number":  "[vault]\naddress = 5\n",
		"control character": "[vault]\naddress = \"https://x\\u001b\"\n",
		// one shared endpoint or CA no longer decides where a web identity goes
		"the old sts_endpoint":           "[kms]\nsts_endpoint = \"https://evil.example\"\n",
		"the old shared ca_file":         "[kms]\nca_file = \"/x\"\n",
		"the old endpoint":               "[kms]\nendpoint = \"https://evil.example\"\n",
		"an STS CA without the endpoint": "[kms]\nprivate_sts_ca_file = \"/x\"\n",
		"a KMS CA without the endpoint":  "[kms]\nprivate_ca_file = \"/x\"\n",
		"the opt-in as text":             "[vault]\nallow_loopback_http = \"true\"\n",
	} {
		if _, err := Parse([]byte("network = \"preview\"\nmode = \"offline\"\n" + bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Any [vault] or [kms] section that parses round-trips through Marshal
// unchanged, booleans included.
//
// spec: SPO-Xunlock-IF-012
func FuzzBackendSections(f *testing.F) {
	f.Add("[vault]\naddress = \"https://v\"\nallow_loopback_http = true\n")
	f.Add("[kms]\nkey_arn = \"a\"\nprivate_endpoint = \"https://p\"\nprivate_ca_file = \"/c\"\nallow_loopback_http = false\n")
	f.Add("[kms]\nprivate_sts_ca_file = \"/c\"\n")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := Parse([]byte("network = \"preview\"\nmode = \"offline\"\n" + s))
		if err != nil {
			return
		}
		out, err := Marshal(c)
		if err != nil {
			return
		}
		c2, err := Parse(out)
		if err != nil {
			t.Fatalf("a marshalled config does not parse: %v\n%s", err, out)
		}
		if (c.Vault == nil) != (c2.Vault == nil) || (c.Vault != nil && *c.Vault != *c2.Vault) ||
			(c.KMS == nil) != (c2.KMS == nil) || (c.KMS != nil && *c.KMS != *c2.KMS) {
			t.Fatalf("round trip changed a backend section:\n%s", out)
		}
	})
}
