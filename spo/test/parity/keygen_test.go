package parity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type envelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

// Keys generated in process must be keys the pinned cardano-cli accepts, and
// cardano-cli must derive the same verification key from the signing key
// (ADR 0007). The signing key reaches cardano-cli through a pipe.
//
// spec: SPO-04c-EXT-001, SPO-04c-OUT-004, SPO-Pfiles-OUT-012, SPO-Pfiles-OUT-013
func TestNativeKeysMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	cli, err := e.tc.Tool(ctx, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		generate     func(context.Context) (ports.KeyPair, error)
		vType, sType string
		vDesc, sDesc string
	}{
		{"kes", native.KeyGen{}.GenerateKES, "KesVerificationKey_ed25519_kes_2^6", "KesSigningKey_ed25519_kes_2^6", "KES Verification Key", "KES Signing Key"},
		{"vrf", native.KeyGen{}.GenerateVRF, "VrfVerificationKey_PraosVRF", "VrfSigningKey_PraosVRF", "VRF Verification Key", "VRF Signing Key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				pair, err := c.generate(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer pair.SKey.Destroy()

				var ours envelope
				if err := json.Unmarshal(pair.VKey, &ours); err != nil {
					t.Fatal(err)
				}
				if ours.Type != c.vType || ours.Description != c.vDesc {
					t.Fatalf("verification key envelope = %q / %q", ours.Type, ours.Description)
				}
				var sk envelope
				pair.SKey.Use(func(b []byte) error { return json.Unmarshal(b, &sk) })
				if sk.Type != c.sType || sk.Description != c.sDesc {
					t.Fatalf("signing key envelope = %q / %q", sk.Type, sk.Description)
				}

				res, err := execx.OS{}.Run(ctx, execx.Cmd{
					Path: cli.Path,
					Args: []execx.Arg{
						execx.Lit("latest"), execx.Lit("key"), execx.Lit("verification-key"),
						execx.Lit("--signing-key-file"), execx.SecretIn(pair.SKey),
						execx.Lit("--verification-key-file"), execx.Lit("/dev/stdout"),
					},
				})
				if err != nil {
					t.Fatalf("cardano-cli rejected the native signing key: %v\n%s", err, res.Stderr)
				}
				var theirs envelope
				if err := json.Unmarshal(res.Stdout, &theirs); err != nil {
					t.Fatalf("cardano-cli output: %v\n%s", err, res.Stdout)
				}
				// `key verification-key` writes an empty description, so compare
				// the type and the key bytes. Descriptions are compared with
				// what key-gen writes in TestKesKeyGeneration.
				if theirs.Type != ours.Type || theirs.CborHex != ours.CborHex {
					t.Fatalf("verification key differs\n  cardano-cli: %+v\n  native:      %+v", theirs, ours)
				}
			}
		})
	}
}
