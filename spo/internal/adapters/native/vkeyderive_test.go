package native

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/blinklabs-io/bursa"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func TestVKeyDeriverRoundTrip(t *testing.T) {
	ctx := context.Background()
	sk := SoftwareKeys{}
	mn, err := sk.GenerateMnemonic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mn.Destroy()

	type gen func() (ports.KeyPair, error)
	cases := map[string]gen{
		"cold":      func() (ports.KeyPair, error) { return sk.GenerateCold(ctx) },
		"payment":   func() (ports.KeyPair, error) { return sk.GeneratePayment(ctx) },
		"stake":     func() (ports.KeyPair, error) { return sk.GenerateStake(ctx) },
		"drep":      func() (ports.KeyPair, error) { return sk.GenerateDRep(ctx) },
		"cc-cold":   func() (ports.KeyPair, error) { return sk.GenerateCommitteeCold(ctx) },
		"cc-hot":    func() (ports.KeyPair, error) { return sk.GenerateCommitteeHot(ctx) },
		"drep-x":    func() (ports.KeyPair, error) { return sk.DeriveDRep(ctx, mn, 0, 1) },
		"cc-cold-x": func() (ports.KeyPair, error) { return sk.DeriveCommitteeCold(ctx, mn, 0, 2) },
		"cc-hot-x":  func() (ports.KeyPair, error) { return sk.DeriveCommitteeHot(ctx, mn, 0, 3) },
		"payment-x": func() (ports.KeyPair, error) {
			w, err := sk.DeriveWallet(ctx, mn, 0, 4)
			if err == nil {
				w.Stake.SKey.Destroy()
			}
			return w.Payment, err
		},
		"stake-x": func() (ports.KeyPair, error) {
			w, err := sk.DeriveWallet(ctx, mn, 0, 5)
			if err == nil {
				w.Payment.SKey.Destroy()
			}
			return w.Stake, err
		},
	}
	var d VKeyDeriver
	for name, g := range cases {
		t.Run(name, func(t *testing.T) {
			kp, err := g()
			if err != nil {
				t.Fatal(err)
			}
			defer kp.SKey.Destroy()
			got, err := d.DeriveVKeyEnvelope(ctx, kp.SKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, kp.VKey) {
				t.Fatalf("got %q want %q", got, kp.VKey)
			}
			raw, err := d.DeriveVerificationKey(ctx, kp.SKey)
			if err != nil || len(raw) != 32 {
				t.Fatalf("raw: %v len %d", err, len(raw))
			}
		})
	}
}

// Policy and Calidus keys, which have no generator here, derive from bursa's
// own derivation and equal bursa's verification key files.
func TestVKeyDeriverPolicyAndCalidus(t *testing.T) {
	ctx := context.Background()
	mn, err := SoftwareKeys{}.GenerateMnemonic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mn.Destroy()
	var root, acct, pol, cal []byte
	if err := mn.Use(func(b []byte) error {
		var err error
		root, err = bursa.GetRootKeyFromMnemonicBytes(b, "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if acct, err = bursa.GetAccountKey(root, 0); err != nil {
		t.Fatal(err)
	}
	if pol, err = bursa.GetPolicyKey(root, 0); err != nil {
		t.Fatal(err)
	}
	if cal, err = bursa.GetCalidusKey(acct, 0); err != nil {
		t.Fatal(err)
	}
	var d VKeyDeriver
	for name, c := range map[string]struct {
		k []byte
		v func([]byte) (bursa.KeyFile, error)
		s func([]byte) (bursa.KeyFile, error)
	}{
		"policy":  {pol, func(k []byte) (bursa.KeyFile, error) { return bursa.GetPolicyVKey(k) }, func(k []byte) (bursa.KeyFile, error) { return bursa.GetPolicySKey(k) }},
		"calidus": {cal, func(k []byte) (bursa.KeyFile, error) { return bursa.GetCalidusVKey(k) }, func(k []byte) (bursa.KeyFile, error) { return bursa.GetCalidusSKey(k) }},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := c.v(c.k)
			if err != nil {
				t.Fatal(err)
			}
			s, err := c.s(c.k)
			if err != nil {
				t.Fatal(err)
			}
			wantV, _ := envelopeIndent(v, "  ")
			sj, _ := envelopeIndent(s, "  ")
			got, err := d.DeriveVKeyEnvelope(ctx, secret.Take(sj))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, wantV) {
				t.Fatalf("got %q want %q", got, wantV)
			}
		})
	}
}

func TestVKeyDeriverUnsupportedAndMalformed(t *testing.T) {
	ctx := context.Background()
	var d VKeyDeriver
	for name, g := range map[string]func(context.Context) (ports.KeyPair, error){
		"kes": KeyGen{}.GenerateKES, "vrf": KeyGen{}.GenerateVRF,
	} {
		kp, err := g(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DeriveVerificationKey(ctx, kp.SKey); !errors.Is(err, ports.ErrKeyTypeUnsupported) {
			t.Fatalf("%s: %v", name, err)
		}
		kp.SKey.Destroy()
	}
	bls := secret.Take([]byte(`{"type":"BlsSigningKey_bls12-381-BLS-Signature-Minimal-Signature-Size","description":"x","cborHex":"5820` + string(bytes.Repeat([]byte("ab"), 32)) + `"}`))
	if _, err := d.DeriveVerificationKey(ctx, bls); !errors.Is(err, ports.ErrKeyTypeUnsupported) {
		t.Fatalf("bls: %v", err)
	}
	for _, bad := range []string{`not json`, `{"type":"PaymentSigningKeyShelley_ed25519","description":"x","cborHex":"5820ab"}`, `{"type":"PaymentSigningKeyShelley_ed25519","description":"x","cborHex":"zz"}`} {
		if _, err := d.DeriveVerificationKey(ctx, secret.Take([]byte(bad))); !errors.Is(err, ErrBadSigningKey) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	// An extended key whose public half does not match is refused.
	kp, _ := SoftwareKeys{}.GenerateMnemonic(ctx)
	w, err := SoftwareKeys{}.DeriveWallet(ctx, kp, 0, 0)
	kp.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	var env []byte
	_ = w.Payment.SKey.Use(func(b []byte) error { env = append([]byte(nil), b...); return nil })
	i := bytes.Index(env, []byte(`"cborHex": "5880`)) + len(`"cborHex": "5880`) + 128 + 2
	env[i] ^= 1 // flips a hex digit of the embedded public key
	if env[i] > 'f' || (env[i] > '9' && env[i] < 'a') {
		env[i] = '0'
	}
	if _, err := d.DeriveVerificationKey(ctx, secret.Take(env)); !errors.Is(err, ErrBadSigningKey) {
		t.Fatalf("mismatch: %v", err)
	}
}
