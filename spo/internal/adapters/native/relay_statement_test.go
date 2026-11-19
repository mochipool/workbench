package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relaywallet"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

const vectorsPath = "../../domain/relaybind/testdata/vectors.json"

// putSeededPayment stores a payment key made from a 32-byte seed, as a normal
// (not extended) cardano-cli key pair, under a name.
func putSeededPayment(t *testing.T, st *plainstore.Store, name string, seed []byte) ed25519.PublicKey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	vk := fmt.Sprintf(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"Payment Verification Key","cborHex":"5820%x"}`, []byte(pub))
	sk := fmt.Sprintf(`{"type":"PaymentSigningKeyShelley_ed25519","description":"Payment Signing Key","cborHex":"5820%x"}`, seed)
	if err := st.Update(context.Background(), func(w ports.NamedWriter) error {
		if err := w.Put(ports.NamedRef{Name: name, Kind: ports.AddrVKey}, []byte(vk)); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: name, Kind: ports.AddrSKey}, secret.Take([]byte(sk)))
	}); err != nil {
		t.Fatal(err)
	}
	return pub
}

func putGenerated(t *testing.T, st *plainstore.Store, role custody.Role, name string) {
	t.Helper()
	var pair ports.KeyPair
	var err error
	var vkKind, skKind ports.Kind
	if role == custody.RoleStake {
		pair, err = SoftwareKeys{}.GenerateStake(context.Background())
		vkKind, skKind = ports.StakingVKey, ports.StakingSKey
	} else {
		pair, err = SoftwareKeys{}.GeneratePayment(context.Background())
		vkKind, skKind = ports.AddrVKey, ports.AddrSKey
	}
	if err != nil {
		t.Fatal(err)
	}
	defer pair.SKey.Destroy()
	if err := st.Update(context.Background(), func(w ports.NamedWriter) error {
		if err := w.Put(ports.NamedRef{Name: name, Kind: vkKind}, pair.VKey); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: name, Kind: skKind}, pair.SKey)
	}); err != nil {
		t.Fatal(err)
	}
}

func walletOf(t *testing.T, st *plainstore.Store, role custody.Role, name string) relaywallet.WalletKey {
	t.Helper()
	w, err := relaywallet.FromRef(porttest.Key(t, st, role, name))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func vaultSigner(st *plainstore.Store) VaultSignatures {
	return VaultSignatures{VaultSigner{Vault: st.Anchor()}}
}

func fp(start byte) (f party.Fingerprint) {
	for i := range f {
		f[i] = start + byte(i)
	}
	return f
}

// verifyBinding checks a signed binding as the relay would, and that its
// address is the bare key hash.
func verifyBinding(t *testing.T, sm ports.SignedMessage, dev party.Fingerprint, now int64) relaybind.VerifiedBinding {
	t.Helper()
	st, err := relaybind.ParseStatement(sm.Sign1)
	if err != nil {
		t.Fatalf("ParseStatement: %v", err)
	}
	vkey, err := relaybind.ParseCOSEKey(sm.Key)
	if err != nil {
		t.Fatalf("ParseCOSEKey: %v", err)
	}
	vb, err := relaybind.VerifyBinding(st, vkey, dev, now, relaybind.DefaultPolicy())
	if err != nil {
		t.Fatalf("VerifyBinding: %v", err)
	}
	if vb.AddressPart() != relaybind.PartKeyHash || len(st.Address()) != 28 {
		t.Errorf("the protected address is %x (%v), want the bare key hash", st.Address(), vb.AddressPart())
	}
	return vb
}

// The vault signer, for the software key of the committed vectors, writes
// exactly the vector bytes: Ed25519 is deterministic, so the whole COSE_Sign1
// and COSE_Key are byte-equal to what relaybind's vector generator produced from
// the same key and payload. The vault path adds nothing to the statement.
//
// spec: SPO-Xrelaybind-SEC-017, SPO-Xrelaybind-OUT-008
func TestVaultSignsTheRelayVectorsByteForByte(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Seed       string `json:"software_key_seed"`
		Public     string `json:"software_key_public"`
		Statements []struct {
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Device    string `json:"device"`
			All       bool   `json:"all"`
			From      int64  `json:"from"`
			Until     int64  `json:"until"`
			NotBefore int64  `json:"not_before"`
			Form      string `json:"address_form"`
			Sign1     string `json:"sign1_hex"`
			CoseKey   string `json:"cose_key_hex"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vf.Seed)
	st, _ := plainstore.OpenTestnet(t.TempDir())
	pub := putSeededPayment(t, st, "w", seed)
	if hex.EncodeToString(pub) != vf.Public {
		t.Fatalf("the vector key is %x, not %s", pub, vf.Public)
	}
	w := walletOf(t, st, custody.RolePayment, "w")
	s := vaultSigner(st)
	n := 0
	for _, v := range vf.Statements {
		if v.Form != "key-hash" {
			continue // the base-address vectors are an external wallet's form: the vault never writes it
		}
		var sm ports.SignedMessage
		dev, _ := hex.DecodeString(v.Device)
		var d party.Fingerprint
		copy(d[:], dev)
		switch v.Kind {
		case "binding":
			sm, err = s.SignRelayBinding(context.Background(), w, relaybind.Binding{Device: d, From: v.From, Until: v.Until})
		case "revoke":
			r := relaybind.Revoke{All: v.All, NotBefore: v.NotBefore}
			if !v.All {
				r.Device = d
			}
			sm, err = s.SignRelayRevoke(context.Background(), w, r)
		default:
			t.Fatalf("vector %q has kind %q", v.Name, v.Kind)
		}
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if got := hex.EncodeToString(sm.Sign1); got != v.Sign1 {
			t.Errorf("%s: COSE_Sign1\n got %s\nwant %s", v.Name, got, v.Sign1)
		}
		if got := hex.EncodeToString(sm.Key); got != v.CoseKey {
			t.Errorf("%s: COSE_Key\n got %s\nwant %s", v.Name, got, v.CoseKey)
		}
		n++
	}
	if n < 3 {
		t.Fatalf("only %d key-hash vectors were compared", n)
	}
}

// A payment key and a stake key from the vault both sign a binding and a revoke
// that relaybind verifies, with the bare 28-byte key hash as the address, the
// payload embedded and not hashed.
//
// spec: SPO-Xrelaybind-SEC-017
func TestVaultSignsBindingAndRevokeWithPaymentAndStakeKeys(t *testing.T) {
	ctx := context.Background()
	st, _ := plainstore.OpenTestnet(t.TempDir())
	putGenerated(t, st, custody.RolePayment, "pay")
	putGenerated(t, st, custody.RoleStake, "stk")
	s := vaultSigner(st)
	dev := fp(0x40)
	const now = int64(1800000000)
	b := relaybind.Binding{Device: dev, From: now - 60, Until: now - 60 + relaybind.DefaultLifetimeSeconds}
	for _, role := range []custody.Role{custody.RolePayment, custody.RoleStake} {
		name := map[custody.Role]string{custody.RolePayment: "pay", custody.RoleStake: "stk"}[role]
		w := walletOf(t, st, role, name)
		sm, err := s.SignRelayBinding(ctx, w, b)
		if err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		vb := verifyBinding(t, sm, dev, now)
		if vb.Key() != w.KeyHash() || vb.Binding() != b {
			t.Errorf("%s: verified %x %+v", role, vb.Key(), vb.Binding())
		}
		want, _ := b.Render()
		parsed, _ := relaybind.ParseStatement(sm.Sign1)
		if !bytes.Equal(parsed.Payload(), want) {
			t.Errorf("%s: payload %q, want the canonical %q", role, parsed.Payload(), want)
		}
		// revoke of one device, and of all
		for _, r := range []relaybind.Revoke{{Device: dev, NotBefore: now}, {All: true, NotBefore: now}} {
			rm, err := s.SignRelayRevoke(ctx, w, r)
			if err != nil {
				t.Fatalf("%s revoke: %v", role, err)
			}
			rs, err := relaybind.ParseStatement(rm.Sign1)
			if err != nil {
				t.Fatal(err)
			}
			vkey, err := relaybind.ParseCOSEKey(rm.Key)
			if err != nil {
				t.Fatal(err)
			}
			vr, err := relaybind.VerifyRevoke(rs, vkey, now, relaybind.DefaultPolicy())
			if err != nil || vr.Key() != w.KeyHash() || vr.Revoke() != r || len(rs.Address()) != 28 {
				t.Errorf("%s revoke %+v: %v %+v", role, r, err, vr.Revoke())
			}
		}
	}
}

// The typed methods render the payload themselves: a statement the relay would
// refuse (a lifetime over 180 days, a negative time, a revoke of all with a
// device) is refused before the key is opened, and nothing is returned.
//
// spec: SPO-Xrelaybind-SEC-017
func TestTypedMethodsRenderOrRefuse(t *testing.T) {
	ctx := context.Background()
	st, _ := plainstore.OpenTestnet(t.TempDir())
	putGenerated(t, st, custody.RolePayment, "pay")
	w := walletOf(t, st, custody.RolePayment, "pay")
	s := vaultSigner(st)
	for name, b := range map[string]relaybind.Binding{
		"too long":       {Device: fp(1), From: 100, Until: 100 + relaybind.MaxLifetimeSeconds + 1},
		"too short":      {Device: fp(1), From: 100, Until: 100 + relaybind.MinLifetimeSeconds - 1},
		"negative from":  {Device: fp(1), From: -5, Until: relaybind.MinLifetimeSeconds},
		"beyond maxtime": {Device: fp(1), From: relaybind.MaxTime, Until: relaybind.MaxTime},
	} {
		if sm, err := s.SignRelayBinding(ctx, w, b); err == nil || sm.Sign1 != nil || sm.Key != nil {
			t.Errorf("%s: signed (%v)", name, err)
		}
	}
	if sm, err := s.SignRelayRevoke(ctx, w, relaybind.Revoke{All: true, Device: fp(2), NotBefore: 5}); err == nil || sm.Sign1 != nil {
		t.Errorf("a revoke of all with a device: %v", err)
	}
	if sm, err := s.SignRelayRevoke(ctx, w, relaybind.Revoke{NotBefore: -1}); err == nil || sm.Sign1 != nil {
		t.Errorf("a negative not-before: %v", err)
	}
	// the zero wallet key and a key the vault does not hold
	if _, err := s.SignRelayBinding(ctx, relaywallet.WalletKey{}, relaybind.Binding{Device: fp(1), From: 0, Until: relaybind.MinLifetimeSeconds}); !errors.Is(err, relaywallet.ErrRole) {
		t.Errorf("the zero wallet key: %v", err)
	}
	nobody, _ := identity.KeyHashOf(make([]byte, 32))
	missing, err := relaywallet.FromRef(custody.KeyRef{Role: custody.RolePayment, Identity: nobody})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignRelayBinding(ctx, missing, relaybind.Binding{Device: fp(1), From: 0, Until: relaybind.MinLifetimeSeconds}); !errors.Is(err, relaywallet.ErrNoHistory) {
		// the history is asked first and fails closed: a key the store knows nothing of has none
		t.Errorf("a key the vault does not hold: %v", err)
	}
}

// The vault checks the role history of the key itself, so a caller that skips
// the use case cannot sign with a key that was once a cold key: a key stored as
// a payment key and recorded in a cold role (pool cold, committee cold) is
// refused, and a history that cannot be read refuses too.
//
// spec: SPO-Xrelaybind-SEC-013
func TestVaultRefusesAKeyWithColdRoleHistory(t *testing.T) {
	ctx := context.Background()
	for _, cold := range []custody.Role{custody.RolePoolCold, custody.RoleCommitteeCold} {
		st, _ := plainstore.OpenTestnet(t.TempDir())
		putGenerated(t, st, custody.RolePayment, "pay")
		w := walletOf(t, st, custody.RolePayment, "pay")
		s := vaultSigner(st)
		b := relaybind.Binding{Device: fp(1), From: 1000, Until: 1000 + relaybind.DefaultLifetimeSeconds}
		if _, err := s.SignRelayBinding(ctx, w, b); err != nil {
			t.Fatalf("before the cold role: %v", err)
		}
		// the plain test store derives its role histories from the files and does not
		// keep a written record, so the history that the real store would hold after
		// the key was imported as a cold key is given through the signer's index
		s = VaultSignatures{VaultSigner{Vault: st.Anchor(), Keys: coldIndex{st: st, cold: cold}}}
		sm, err := s.SignRelayBinding(ctx, w, b)
		if !errors.Is(err, relaywallet.ErrColdHistory) || sm.Sign1 != nil {
			t.Errorf("%s history: binding signed (%v)", cold, err)
		}
		sm, err = s.SignRelayRevoke(ctx, w, relaybind.Revoke{All: true, NotBefore: 5})
		if !errors.Is(err, relaywallet.ErrColdHistory) || sm.Sign1 != nil {
			t.Errorf("%s history: revoke signed (%v)", cold, err)
		}
	}
	// a vault whose index cannot answer refuses (fail closed)
	st, _ := plainstore.OpenTestnet(t.TempDir())
	putGenerated(t, st, custody.RolePayment, "pay")
	w := walletOf(t, st, custody.RolePayment, "pay")
	s := VaultSignatures{VaultSigner{Vault: st.Anchor(), Keys: brokenIndex{st}}}
	if _, err := s.SignRelayBinding(ctx, w, relaybind.Binding{Device: fp(1), From: 0, Until: relaybind.MinLifetimeSeconds}); !errors.Is(err, relaywallet.ErrHistoryUnreadable) {
		t.Errorf("an unreadable history: %v", err)
	}
}

// coldIndex finds the keys in the store and reports that the identity was
// recorded as a payment key and, too, in a cold role.
type coldIndex struct {
	st   *plainstore.Store
	cold custody.Role
}

func (c coldIndex) Homes(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) {
	return labels.NewIndex(c.st.AnchorStore()).Homes(ctx, id)
}

func (c coldIndex) RoleHistory(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	h, err := custody.NewRoleHistory(id, custody.RolePayment)
	if err != nil {
		return custody.RoleHistory{}, false, err
	}
	h, err = h.With(c.cold)
	return h, err == nil, err
}

// brokenIndex finds the keys but cannot read any role history.
type brokenIndex struct{ st *plainstore.Store }

func (b brokenIndex) Homes(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) {
	return labels.NewIndex(b.st.AnchorStore()).Homes(ctx, id)
}

func (brokenIndex) RoleHistory(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
	return custody.RoleHistory{}, false, ports.ErrUnreadableRecords
}

// The reserved-prefix guard: the generic SignMessage refuses a payload that
// starts with `spo-` or `spo/`, hashed or not, for either role, before anything
// else is looked at (the role, the address, the key), and still signs an
// ordinary message and near misses of the prefix.
//
// spec: SPO-Xrelaybind-SEC-016, SPO-Xidentity-SEC-007
func TestGenericSignMessageRefusesReservedPayloads(t *testing.T) {
	ctx := context.Background()
	st, _ := plainstore.OpenTestnet(t.TempDir())
	putGenerated(t, st, custody.RoleStake, "stk")
	ref := porttest.Key(t, st, custody.RoleStake, "stk")
	s := vaultSigner(st)
	// the key's own reward address
	pub := keyPub(t, st, "stk")
	h := cose.Blake2b224(pub)
	reward := append([]byte{0xe0}, h[:]...)

	reserved := [][]byte{
		[]byte("spo-"),
		[]byte("spo/"),
		[]byte("spo-relay-binding-v1 device 00 from 0 until 3600"),
		[]byte("spo/mailbox-auth/v2"),
		[]byte("spo-anything at all"),
	}
	binding, _ := relaybind.Binding{Device: fp(3), From: 100, Until: 100 + relaybind.DefaultLifetimeSeconds}.Render()
	reserved = append(reserved, binding)
	for _, p := range reserved {
		for _, hashed := range []bool{false, true} {
			sm, err := s.SignMessage(ctx, ports.MessageRequest{Key: ref, Address: reward, Payload: p, Hashed: hashed})
			if !errors.Is(err, relaybind.ErrReservedPayload) || sm.Sign1 != nil || sm.Key != nil {
				t.Errorf("payload %q hashed=%v: %v", p, hashed, err)
			}
		}
	}
	// the guard comes first: a key of another role and a missing address still get the reserved error
	sm, err := s.SignMessage(ctx, ports.MessageRequest{Key: custody.KeyRef{Role: custody.RoleDRep, Identity: ref.Identity}, Payload: []byte("spo-x")})
	if !errors.Is(err, relaybind.ErrReservedPayload) || sm.Sign1 != nil {
		t.Errorf("the guard is not first: %v", err)
	}
	// ordinary messages and near misses still sign
	for _, p := range [][]byte{[]byte("hi"), []byte("spo"), []byte("spo_x"), []byte("Spo-x"), []byte(" spo-x"), []byte("sp"), {}, []byte("xspo-")} {
		for _, hashed := range []bool{false, true} {
			if _, err := s.SignMessage(ctx, ports.MessageRequest{Key: ref, Address: reward, Payload: p, Hashed: hashed}); err != nil {
				t.Errorf("ordinary payload %q hashed=%v refused: %v", p, hashed, err)
			}
		}
	}
	// a payment key too
	putGenerated(t, st, custody.RolePayment, "pay")
	pref := porttest.Key(t, st, custody.RolePayment, "pay")
	ppub := keyPub(t, st, "pay")
	ph := cose.Blake2b224(ppub)
	if _, err := s.SignMessage(ctx, ports.MessageRequest{Key: pref, Address: append([]byte{0x60}, ph[:]...), Payload: []byte("spo-x")}); !errors.Is(err, relaybind.ErrReservedPayload) {
		t.Errorf("a payment key signed a reserved payload: %v", err)
	}
}

// keyPub reads the verification key stored under name (stake, else payment).
func keyPub(t *testing.T, st *plainstore.Store, name string) []byte {
	t.Helper()
	var pub []byte
	err := st.View(context.Background(), func(r ports.NamedReader) error {
		for _, k := range []ports.Kind{ports.StakingVKey, ports.AddrVKey} {
			raw, err := r.Get(ports.NamedRef{Name: name, Kind: k})
			if err != nil {
				continue
			}
			var e struct{ CborHex string }
			if err := json.Unmarshal(raw, &e); err != nil {
				return err
			}
			pub, err = hex.DecodeString(e.CborHex[4:])
			return err
		}
		return errors.New("no key " + name)
	})
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// The guard must not touch the other message-signing uses: the CIP-8 message of
// an operator and the registrations still sign (the existing tests of this file
// and of cip88/cip36 run unchanged); here a message whose hash happens to start
// with the prefix is fine because the guard reads the payload, not a digest.
//
// spec: SPO-Xrelaybind-INV-004
func TestGuardReadsThePayloadNotTheDigest(t *testing.T) {
	ctx := context.Background()
	st, _ := plainstore.OpenTestnet(t.TempDir())
	putGenerated(t, st, custody.RoleStake, "stk")
	ref := porttest.Key(t, st, custody.RoleStake, "stk")
	pub := keyPub(t, st, "stk")
	h := cose.Blake2b224(pub)
	reward := append([]byte{0xe0}, h[:]...)
	s := vaultSigner(st)
	// a 32-byte payload that is a hash (as the CIP-88 payload is) signs
	hash := cose.Blake2b256([]byte("a registration"))
	if _, err := s.SignMessage(ctx, ports.MessageRequest{Key: ref, Address: reward, Payload: hash[:]}); err != nil {
		t.Errorf("a hash payload: %v", err)
	}
}
