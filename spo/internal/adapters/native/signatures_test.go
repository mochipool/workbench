package native

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

func envPub(t *testing.T, env []byte) string {
	t.Helper()
	var e struct{ CborHex string }
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	return e.CborHex[4:]
}

// The Calidus key of the public phrase is cardano-signer's: its verification
// key is the payment key 0/0 (cborHex 5820 63c5...), the envelope types and
// descriptions are the tool's, the voting key is at 1694H and has the CIP-36
// types and the `cvote_vk` text the tool prints. (The signing keys are compared
// byte for byte in spo/test/parity.)
//
// spec: SPO-15-INV-001, SPO-15-OUT-001, SPO-09a-OUT-001, SPO-09a-OUT-002
func TestCalidusAndVotingDerivationVectors(t *testing.T) {
	m := secret.Take([]byte(testPhrase))
	defer m.Destroy()
	cal, err := SoftwareKeys{}.DeriveCalidus(context.Background(), m, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cal.SKey.Destroy()
	if got := string(cal.VKey); !strings.Contains(got, `"PaymentVerificationKeyShelley_ed25519"`) || !strings.Contains(got, `"Calidus Pool Verification Key"`) ||
		envPub(t, cal.VKey) != "63c5d69570349e4233a0575811464f0e8a3fd329abe76e9bdc3d3f1b95982179" {
		t.Errorf("calidus vkey %s", got)
	}
	_ = cal.SKey.Use(func(b []byte) error {
		if !strings.Contains(string(b), `"PaymentExtendedSigningKeyShelley_ed25519_bip32"`) || !strings.Contains(string(b), `"Calidus Pool Signing Key"`) {
			t.Error("calidus skey type or description")
		}
		return nil
	})
	vote, pkey, err := SoftwareKeys{}.DeriveVoting(context.Background(), m, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer vote.SKey.Destroy()
	if pkey != "cvote_vk1693fwq7zfn9vmdky59786wwc8tf3a4pvx360tcp8ma2kfw0c233sg8y667" ||
		!strings.Contains(string(vote.VKey), `"CIP36VoteVerificationKey_ed25519"`) || envPub(t, vote.VKey) != "d1629703c24ccacdb6c4a17c7d39d83ad31ed42c3474f5e027df5564b9f85463" {
		t.Errorf("voting key %s %s", pkey, vote.VKey)
	}
	// Another account and index derive another key; a bad phrase is refused
	// without echoing it.
	other, _, err := SoftwareKeys{}.DeriveVoting(context.Background(), m, 3, 7)
	if err != nil || envPub(t, other.VKey) == envPub(t, vote.VKey) {
		t.Errorf("account/index ignored: %v", err)
	}
	other.SKey.Destroy()
	bad := secret.Take([]byte("not a phrase"))
	defer bad.Destroy()
	if _, _, err := (SoftwareKeys{}).DeriveVoting(context.Background(), bad, 0, 0); err != ports.ErrInvalidMnemonic {
		t.Errorf("bad phrase: %v", err)
	}
	if _, err := (SoftwareKeys{}).DeriveCalidus(context.Background(), bad, 0, 0); err != ports.ErrInvalidMnemonic {
		t.Errorf("bad phrase: %v", err)
	}
}

// The profile of the vault signer with signatures agrees with its interfaces
// (the conformance check), keeps the operations of VaultSigner, and refuses
// roles it cannot sign for.
func TestVaultSignaturesProfile(t *testing.T) {
	st, _ := plainstore.OpenTestnet(t.TempDir())
	s := VaultSignatures{VaultSigner{Vault: st.Anchor()}}
	if err := ports.CheckSignatureSigner(s); err != nil {
		t.Fatal(err)
	}
	if err := ports.CheckSigner(s); err != nil {
		t.Fatal(err)
	}
	p := s.Profile()
	for _, d := range []custody.Demand{
		{Role: custody.RolePoolCold, Operation: custody.OpSignCip88},
		{Role: custody.RoleStake, Operation: custody.OpSignCip36},
		{Role: custody.RoleStake, Operation: custody.OpSignMessage},
		{Role: custody.RolePayment, Operation: custody.OpSignMessage},
		{Role: custody.RolePoolCold, Operation: custody.OpIssueOpCert},
	} {
		if r := p.Check(d); r != "" {
			t.Errorf("%v: %s", d, r)
		}
	}
	for _, d := range []custody.Demand{
		{Role: custody.RolePayment, Operation: custody.OpSignCip36},
		{Role: custody.RolePayment, Operation: custody.OpSignCip88},
		{Role: custody.RoleDRep, Operation: custody.OpSignMessage},
	} {
		if p.Check(d) == "" {
			t.Errorf("%v is claimed", d)
		}
	}
	// A profile that claims more than the code does is caught.
	if err := ports.CheckSignatureSigner(onlyClaims{}); err == nil {
		t.Error("a signer claiming OpSignCip88 without the interface passed")
	}
	// The directory answers for the keys the vault holds and for no other.
	dir := NewSignatureSigners(st.Anchor())
	nobody, _ := identity.KeyHashOf(make([]byte, 32))
	if _, err := dir.SignerFor(custody.KeyRef{Role: custody.RoleStake, Identity: nobody}); err == nil {
		t.Error("a key nobody holds found a signer")
	}
}

type onlyClaims struct{}

func (onlyClaims) Profile() custody.Profile {
	return custody.NewProfile("liar").Allow(custody.RolePoolCold, custody.OpSignCip88)
}

// A message signed with a stored key verifies, the key must belong to the
// address, the role must be payment or stake, and a hashed payload is the
// 28-byte hash.
//
// spec: SPO-15-EXT-005
func TestVaultSignaturesSignMessage(t *testing.T) {
	st, _ := plainstore.OpenTestnet(t.TempDir())
	pair, err := SoftwareKeys{}.GenerateStake(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	if err := st.Update(context.Background(), func(w ports.NamedWriter) error {
		if err := w.Put(ports.NamedRef{Name: "w", Kind: ports.StakingVKey}, pair.VKey); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: "w", Kind: ports.StakingSKey}, pair.SKey)
	}); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(envPub(t, pair.VKey))
	h := cose.Blake2b224(pub)
	reward := append([]byte{0xe0}, h[:]...)
	s := VaultSignatures{VaultSigner{Vault: st.Anchor()}}
	ref := porttest.Key(t, st, custody.RoleStake, "w")
	for _, hashed := range []bool{false, true} {
		sm, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: ref, Address: reward, Payload: []byte("hi"), Hashed: hashed})
		if err != nil {
			t.Fatal(err)
		}
		v, err := s.VerifyMessage(context.Background(), sm.Sign1, sm.Key, []byte("hi"), true)
		if err != nil || v.Hashed != hashed {
			t.Errorf("hashed=%v: %v %+v", hashed, err, v)
		}
		if hashed != (len(v.Payload) == 28) {
			t.Errorf("payload length %d", len(v.Payload))
		}
	}
	otherAddr := append([]byte{0xe0}, make([]byte, 28)...)
	if _, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: ref, Address: otherAddr, Payload: []byte("hi")}); err != cose.ErrAddressMismatch {
		t.Errorf("foreign address: %v", err)
	}
	if _, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: custody.KeyRef{Role: custody.RoleDRep, Identity: ref.Identity}, Address: reward}); err == nil {
		t.Error("a drep key signed a message")
	}
	if _, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: ref, Payload: []byte("hi")}); err == nil {
		t.Error("a message without an address")
	}
	if _, err := s.SignMessage(context.Background(), ports.MessageRequest{Key: custody.KeyRef{Role: custody.RoleStake, Identity: nobodyID(t)}, Address: reward}); err == nil {
		t.Error("a missing key signed")
	}
	// A registration is not signed with the wrong key.
	var reg cose.Cip36
	reg.Delegations, reg.Address = []cose.Delegation{{Weight: 1}}, []byte{0x60, 1}
	k, _ := custody.As[custody.Stake](ref)
	if _, err := s.SignCip36(context.Background(), k, reg); err == nil || !strings.Contains(err.Error(), "not the registration's stake key") {
		t.Errorf("foreign stake key: %v", err)
	}
}

// nobodyID is an identity no test vault holds.
func nobodyID(t *testing.T) identity.Ref {
	t.Helper()
	id, err := identity.KeyHashOf(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
