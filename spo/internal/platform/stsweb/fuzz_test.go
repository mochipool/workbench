package stsweb

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// Parse never panics, and what it accepts is one element each of plain text
// inside the body, a temporary key id and an expiry more than a minute ahead.
//
// spec: SPO-Xobjstore-SEC-301
func FuzzParse(f *testing.F) {
	f.Add(wrap(creds("ASIAEXAMPLETEMPKEY01", "SeCrEt", "ToKeN", "2026-01-01T00:15:00Z")))
	f.Add(wrap(`<!--<SessionToken>z</SessionToken>-->` + creds("ASIAEXAMPLETEMPKEY01", "a", "b", "2026-01-01T01:00:00Z")))
	f.Add(wrap(creds("ASIAEXAMPLETEMPKEY01", "<![CDATA[a]]>", "t", "2026-01-01T01:00:00Z")))
	f.Add([]byte("<AssumeRoleWithWebIdentityResponse>"))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 64<<10 {
			return
		}
		a, err := Parse(body, now)
		if err != nil {
			return
		}
		for _, sp := range [][2]int{a.Secret, a.Token} {
			if sp[0] < 0 || sp[1] > len(body) || sp[0] >= sp[1] {
				t.Fatalf("a span %v outside a body of %d", sp, len(body))
			}
			if txt := body[sp[0]:sp[1]]; !PrintableToken(txt, MaxTokenBytes) || bytes.ContainsAny(txt, "<&") {
				t.Fatalf("an accepted text that is not plain: %q", txt)
			}
		}
		if !strings.HasPrefix(a.KeyID, "ASIA") || !a.Expires.After(now.Add(time.Minute)) {
			t.Fatalf("accepted %v", a)
		}
	})
}
