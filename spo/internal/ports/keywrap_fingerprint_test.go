package ports

import (
	"regexp"
	"testing"
)

// The fingerprint covers every field of the reference and their boundaries: a
// change of any one, or a byte moved from one field to the next, changes it.
//
// spec: SPO-Xunlock-OUT-023
func TestBackendFingerprintCoversEveryField(t *testing.T) {
	base := BackendRef{Kind: BackendVaultTransit, Address: "https://vault.example:8200", Namespace: "ops", Key: "transit/spo"}
	fp := base.Fingerprint()
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fp) || base.Fingerprint() != fp {
		t.Fatalf("fingerprint %q", fp)
	}
	for name, r := range map[string]BackendRef{
		"kind":      {Kind: BackendAWSKMS, Address: base.Address, Namespace: base.Namespace, Key: base.Key},
		"address":   {Kind: base.Kind, Address: "https://vault.example:8201", Namespace: base.Namespace, Key: base.Key},
		"namespace": {Kind: base.Kind, Address: base.Address, Namespace: "op", Key: base.Key},
		"key":       {Kind: base.Kind, Address: base.Address, Namespace: base.Namespace, Key: "transit/spp"},
		"boundary":  {Kind: base.Kind, Address: base.Address, Namespace: "opst", Key: "ransit/spo"},
	} {
		if r.Fingerprint() == fp {
			t.Errorf("a change of the %s keeps the fingerprint", name)
		}
	}
}

// The fingerprint shown also covers the client-side settings that decide where
// a credential goes (a CA file, a token file, a private endpoint, plain http to
// loopback): a change of a name or a value, a setting added, or a byte moved
// between a name and its value changes it. With every setting at its default it
// is the fingerprint of the reference alone, so it reads the same as before.
//
// spec: SPO-Xunlock-OUT-023
func TestTheClientFingerprintCoversTheClientSettings(t *testing.T) {
	base := BackendRef{Kind: BackendVaultTransit, Address: "https://vault.example:8200", Key: "transit/spo"}
	if base.ClientFingerprint(nil) != base.Fingerprint() {
		t.Fatal("no client setting: not the reference's fingerprint")
	}
	set := []BackendSetting{{"ca_file", "/etc/spo/ca.pem"}, {"token_file", "/home/op/.vault-token"}}
	fp := base.ClientFingerprint(set)
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fp) || fp == base.Fingerprint() || base.ClientFingerprint(set) != fp {
		t.Fatalf("fingerprint %q", fp)
	}
	for name, s := range map[string][]BackendSetting{
		"value":    {{"ca_file", "/tmp/ca.pem"}, set[1]},
		"name":     {{"jwt_file", "/etc/spo/ca.pem"}, set[1]},
		"added":    {set[0], set[1], {"allow_loopback_http", "true"}},
		"dropped":  {set[0]},
		"boundary": {{"ca_file/", "etc/spo/ca.pem"}, set[1]},
	} {
		if base.ClientFingerprint(s) == fp {
			t.Errorf("a change of the %s keeps the fingerprint", name)
		}
	}
	// the settings never stand in for a field of the reference
	other := BackendRef{Kind: base.Kind, Address: base.Address, Key: "transit/sp"}
	if other.ClientFingerprint([]BackendSetting{{"o", ""}}) == base.Fingerprint() {
		t.Fatal("a setting reproduced another reference's fingerprint")
	}
}
