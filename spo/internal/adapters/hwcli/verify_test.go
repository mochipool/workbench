package hwcli_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// misbehave sets how the fake tool misbehaves from now on.
func (r *rig) misbehave(how string) {
	r.fake.Misbehave = how
	r.writeFake()
}

// The adapter does not trust what the tool wrote: each of its own checks has a
// test where the tool breaks it and the adapter refuses.

// spec: SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Chw-INV-002, SPO-Xidentity-SEC-004
func TestAWitnessThatDoesNotVerifyOverTheBodyIDIsRefused(t *testing.T) {
	for _, c := range []struct {
		how  string
		want error
	}{
		{"wrongkey", hwcli.ErrBadDeviceOutput},  // another key signed and is named: not the signing file's key
		{"badsig", hwcli.ErrBadDeviceOutput},    // the signature is over another body id
		{"truncated", hwcli.ErrBadDeviceOutput}, // half a file
		{"exitafter", hwcli.ErrToolFailed},      // the file is there, the tool failed
	} {
		r := newRig(t, "Ledger", "8.0.8")
		s := r.open()
		r.export(s, custody.RolePayment, "w", "1852H/1815H/0H/0/0")
		body := realBody(t, c.how)
		pay := hwKey(custody.RolePayment, "w")
		if _, err := s.Witness(context.Background(), pay, body); err != nil {
			t.Fatalf("%s: a correct tool: %v", c.how, err)
		}
		r.misbehave(c.how)
		w, err := s.Witness(context.Background(), pay, body)
		if !errors.Is(err, c.want) || w != (txbuild.Witness{}) {
			t.Errorf("%s: %v (witness %v)", c.how, err, w)
		}
	}
}

// spec: SPO-04d-EXT-004, SPO-04d-OUT-002, SPO-04d-PR-003, SPO-Chw-INV-002, SPO-Xidentity-SEC-002
func TestAnOpCertThatIsNotWhatWasAskedForIsRefused(t *testing.T) {
	kes := bytes.Repeat([]byte{0x42}, 32)
	req := ports.OpCertRequest{KesVKey: kes, Counter: 7, KesPeriod: 300}
	for _, c := range []struct {
		how  string
		want error
	}{
		{"counter", hwcli.ErrBadDeviceOutput},   // a certificate over another counter
		{"kes", hwcli.ErrBadDeviceOutput},       // over another KES key
		{"period", hwcli.ErrBadDeviceOutput},    // over another KES period
		{"coldkey", hwcli.ErrBadDeviceOutput},   // signed by a cold key that is not the pool's
		{"badsig", hwcli.ErrBadDeviceOutput},    // the cold signature does not verify
		{"truncated", hwcli.ErrBadDeviceOutput}, // half a file
		{"exitafter", hwcli.ErrToolFailed},      // written, then failed
	} {
		r := newRig(t, "Ledger", "8.0.8")
		s := r.open()
		r.export(s, custody.RolePoolCold, "p", "1853H/1815H/0H/0H")
		cold := mustAs[custody.PoolCold](t, hwKey(custody.RolePoolCold, "p"))
		if _, err := s.IssueOpCert(context.Background(), cold, req); err != nil {
			t.Fatalf("%s: a correct tool: %v", c.how, err)
		}
		r.misbehave(c.how)
		out, err := s.IssueOpCert(context.Background(), cold, req)
		if !errors.Is(err, c.want) || out != nil {
			t.Errorf("%s: %v (%d bytes)", c.how, err, len(out))
		}
	}
}

// spec: SPO-10-EXT-005
func TestAPolicyIDThatIsNotTheScriptsIsRefused(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	r.export(s, custody.RolePolicy, "pol", "1855H/1815H/0H")
	key := mustAs[custody.Policy](t, hwKey(custody.RolePolicy, "pol"))
	want, err := native.Ledger{}.PolicyID(policyScript)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.PolicyID(context.Background(), key, policyScript)
	if err != nil || got != hexOf(want[:]) {
		t.Fatalf("a correct tool: %q %v", got, err)
	}
	for _, how := range []string{"wrongpolicy", "truncated"} {
		r.misbehave(how)
		id, err := s.PolicyID(context.Background(), key, policyScript)
		if !errors.Is(err, hwcli.ErrBadDeviceOutput) || id != "" {
			t.Errorf("%s: %q %v", how, id, err)
		}
	}
}

// spec: SPO-02-EXT-003, SPO-03a-EXT-004, SPO-04a-EXT-004
func TestAKeyGenWhoseVerificationKeyIsNotTheSigningFilesIsRefused(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, _ *hwcli.Config) { f.Misbehave = "wrongvkey" })
	s := r.open()
	for _, role := range []custody.Role{custody.RolePayment, custody.RolePoolCold} {
		hk, err := s.ExportHardwareKey(context.Background(), hwKey(role, "o"), "1852H/1815H/0H/0/0")
		if !errors.Is(err, hwcli.ErrBadDeviceOutput) || hk.VKey != nil {
			t.Errorf("%s: %v", role, err)
		}
	}
}

// A body is converted once per session, however many keys witness it, and a body
// that conversion would change is never sent to the device.
//
// spec: SPO-Ctx-EXT-001, SPO-Ptx-EXT-005, SPO-Ptx-INV-009
func TestABodyIsCheckedForConversionOncePerSession(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8")
	s := r.open()
	r.export(s, custody.RolePayment, "w", "1852H/1815H/0H/0/0")
	r.export(s, custody.RoleStake, "w", "1852H/1815H/0H/2/0")
	body := realBody(t, "once")
	other := realBody(t, "another")
	ctx := context.Background()
	for _, k := range []custody.KeyRef{hwKey(custody.RolePayment, "w"), hwKey(custody.RoleStake, "w"), hwKey(custody.RolePayment, "w")} {
		if _, err := s.Witness(ctx, k, body); err != nil {
			t.Fatal(err)
		}
	}
	if n, w := r.called("transaction", "transform"), r.called("transaction", "witness"); n != 1 || w != 3 {
		t.Errorf("%d transforms and %d witnesses for one body and three witnesses", n, w)
	}
	// Another body is checked by itself.
	if _, err := s.Witness(ctx, hwKey(custody.RolePayment, "w"), other); err != nil {
		t.Fatal(err)
	}
	if n := r.called("transaction", "transform"); n != 2 {
		t.Errorf("%d transforms for two bodies", n)
	}
	// Canonicalising a canonical body is remembered too.
	third := realBody(t, "third")
	if _, changed, err := s.Canonicalize(ctx, third, ports.HardwareTxOptions{}); err != nil || changed {
		t.Fatal(changed, err)
	}
	if _, err := s.Witness(ctx, hwKey(custody.RolePayment, "w"), third); err != nil {
		t.Fatal(err)
	}
	if n := r.called("transaction", "transform"); n != 3 {
		t.Errorf("%d transforms: the witness repeated the one Canonicalize made", n)
	}
	// A body conversion would change is refused every time, and the device never sees it.
	legacy := legacyBody(t, "legacy")
	for i := 0; i < 2; i++ {
		var nc *ports.ErrNotHardwareCanonical
		if _, err := s.Witness(ctx, hwKey(custody.RolePayment, "w"), legacy); !errors.As(err, &nc) {
			t.Fatalf("%v", err)
		}
	}
	if n, w := r.called("transaction", "transform"), r.called("transaction", "witness"); n != 5 || w != 5 {
		t.Errorf("%d transforms, %d witnesses: a non-canonical body must be re-checked and never witnessed", n, w)
	}
	// Unrestricted mode is part of the check: a body found canonical without it is
	// checked again with it.
	if _, err := s.WitnessWith(ctx, hwKey(custody.RolePayment, "w"), body, ports.HardwareTxOptions{Unrestricted: true}); err != nil {
		t.Fatal(err)
	}
	if n := r.called("transaction", "transform"); n != 6 {
		t.Errorf("%d transforms", n)
	}
}

// A plan that the device's profile refuses calls the tool for nothing but one
// `device version`: no key generation, conversion, witness or certificate.
//
// spec: SPO-Chw-PRE-003, SPO-Chw-PRE-004, SPO-Chw-PR-001
func TestARefusedPlanOnlyProbesTheDeviceOnce(t *testing.T) {
	for _, c := range []struct {
		vendor, app string
		slot        custody.Slot
	}{
		{"Trezor", "2.7.2", custody.Slot{Label: "opcert", Key: hwKey(custody.RolePoolCold, "p"), Demand: custody.Demand{Role: custody.RolePoolCold, Operation: custody.OpIssueOpCert}}},
		{"Keystone", "1.7.7", custody.Slot{Label: "vote", Key: hwKey(custody.RoleDRep, "d"), Demand: custody.Demand{Role: custody.RoleDRep, Operation: custody.OpWitnessTx, Features: custody.NewFeatures(custody.FeatVote)}}},
		{"Ledger", "8.0.8", custody.Slot{Label: "calidus", Key: hwKey(custody.RoleCalidus, "c"), Demand: custody.Demand{Role: custody.RoleCalidus, Operation: custody.OpExportVKey}}},
	} {
		r := newRig(t, c.vendor, c.app)
		dir := native.Signers{Keys: hwIndex{}, Hardware: lazyFor(r)}
		for i := 0; i < 3; i++ { // a command plans more than once
			var ue *custody.UnsupportedError
			if _, err := ports.PlanSignatures(dir, []custody.Slot{c.slot}); !errors.As(err, &ue) {
				t.Fatalf("%s: %v", c.vendor, err)
			}
		}
		if n := r.called("device", "version"); n != 1 {
			t.Errorf("%s: `device version` ran %d times", c.vendor, n)
		}
		for _, cmd := range [][]string{{"address"}, {"node"}, {"transaction"}, {"message"}, {"vote"}} {
			if n := r.called(cmd...); n != 0 {
				t.Errorf("%s: a refused plan ran `%s` %d times", c.vendor, cmd[0], n)
			}
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
