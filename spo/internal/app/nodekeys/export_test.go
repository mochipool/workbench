package nodekeys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/nodeage"
	"github.com/mochipool/workbench/spo/internal/app/nodekeys"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A workspace in memory: the use case runs against real keys, the real
// derivation and the real age sealer; only the store is a fake.
type memStore struct {
	files   map[ports.NamedRef][]byte
	secrets map[ports.NamedRef][]byte
}

func (m *memStore) View(_ context.Context, fn func(ports.NamedReader) error) error { return fn(m) }
func (m *memStore) Update(context.Context, func(ports.NamedWriter) error) error {
	return errors.New("read only")
}
func (m *memStore) Get(r ports.NamedRef) ([]byte, error) {
	if b, ok := m.files[r]; ok {
		return b, nil
	}
	return nil, ports.ErrNotFound
}
func (m *memStore) Exists(r ports.NamedRef) (bool, error) { _, ok := m.files[r]; return ok, nil }
func (m *memStore) Open(_ context.Context, r ports.NamedRef) (*secret.Buffer, error) {
	if b, ok := m.secrets[r]; ok {
		return secret.Take(append([]byte(nil), b...)), nil
	}
	return nil, ports.ErrNotFound
}

type auditLog struct {
	events []ports.AuditEvent
	fail   bool
}

func (a *auditLog) Record(_ context.Context, e ports.AuditEvent) error {
	if a.fail {
		return errors.New("audit down")
	}
	a.events = append(a.events, e)
	return nil
}

type rig struct {
	st                 *memStore
	kesS, vrfS         []byte
	kesV, vrfV, opcert []byte
	kesID, vrfID       identity.Ref
	hist               map[identity.Ref]custody.RoleHistory
	histErr            error
	audit              *auditLog
	identity           *age.X25519Identity
	counter            []byte
}

func raw(t *testing.T, env []byte) []byte {
	t.Helper()
	e, err := pool.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	k, err := e.Key32()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// signedOpcert is a certificate really signed by a test cold key.
func signedOpcert(kesVKey []byte, cold ed25519.PrivateKey, counter, period byte) []byte {
	signable := append(append([]byte(nil), kesVKey...), make([]byte, 16)...)
	signable[32+7], signable[40+7] = counter, period
	sig := ed25519.Sign(cold, signable)
	h := "8284" + "5820" + hex.EncodeToString(kesVKey) + hex.EncodeToString([]byte{counter}) + hex.EncodeToString([]byte{period}) + "5840" + hex.EncodeToString(sig) + "5820" + hex.EncodeToString(cold.Public().(ed25519.PublicKey))
	return []byte(`{"type":"NodeOperationalCertificate","description":"","cborHex":"` + h + `"}`)
}

func opcertFor(kesVKey []byte) []byte { return signedOpcert(kesVKey, testCold, 0, 0) }

var testCold = func() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5c}, 32)) }()

func coldFiles(c ed25519.PrivateKey, next uint64) (vk, counter []byte) {
	pub := c.Public().(ed25519.PublicKey)
	vk = []byte(`{"type":"StakePoolVerificationKey_ed25519","description":"","cborHex":"5820` + hex.EncodeToString(pub) + `"}`)
	ic := pool.IssueCounter{Next: next}
	copy(ic.ColdVKey[:], pub)
	return vk, ic.Envelope()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx := context.Background()
	kp, err := native.KeyGen{}.GenerateKES(ctx)
	if err != nil {
		t.Fatal(err)
	}
	vp, err := native.KeyGen{}.GenerateVRF(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{kesV: kp.VKey, vrfV: vp.VKey, audit: &auditLog{}, hist: map[identity.Ref]custody.RoleHistory{}}
	kp.SKey.Use(func(b []byte) error { r.kesS = append([]byte(nil), b...); return nil })
	vp.SKey.Use(func(b []byte) error { r.vrfS = append([]byte(nil), b...); return nil })
	r.opcert = opcertFor(raw(t, kp.VKey))
	if r.kesID, err = ports.IdentityOfVKey(custody.RoleKES, r.kesV); err != nil {
		t.Fatal(err)
	}
	if r.vrfID, err = ports.IdentityOfVKey(custody.RoleVRF, r.vrfV); err != nil {
		t.Fatal(err)
	}
	for id, role := range map[identity.Ref]custody.Role{r.kesID: custody.RoleKES, r.vrfID: custody.RoleVRF} {
		r.hist[id], _ = custody.NewRoleHistory(id, role)
	}
	if r.identity, err = age.GenerateX25519Identity(); err != nil {
		t.Fatal(err)
	}
	r.build()
	return r
}

func (r *rig) build() {
	n := func(k ports.Kind, num int) ports.NamedRef { return ports.NamedRef{Name: "p", Kind: k, Num: num} }
	coldVK, counterEnv := coldFiles(testCold, 1)
	if r.counter != nil {
		counterEnv = r.counter
	}
	r.st = &memStore{
		files: map[ports.NamedRef][]byte{
			n(ports.NodeVKey, 0): coldVK, n(ports.NodeCounter, 0): counterEnv,
			n(ports.KesVKey, 0): r.kesV, n(ports.VrfVKey, 0): r.vrfV, n(ports.OpCert, 0): r.opcert,
			n(ports.KesCounter, 0): []byte("000\n"), n(ports.KesCounterNext, 0): []byte("001\n"),
		},
		secrets: map[ports.NamedRef][]byte{n(ports.KesSKey, 0): r.kesS, n(ports.VrfSKey, 0): r.vrfS},
	}
}

func (r *rig) uc() nodekeys.Export {
	return nodekeys.Export{
		Store: r.st, Vault: r.st, Derive: native.HotKeyDeriver{}, Sealer: nodeage.Sealer{}, Auditor: r.audit,
		History: func(_ context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
			if r.histErr != nil {
				return custody.RoleHistory{}, false, r.histErr
			}
			h, ok := r.hist[id]
			return h, ok, nil
		},
	}
}

func (r *rig) req() nodekeys.Request {
	return nodekeys.Request{Pool: "p", Recipient: r.identity.Recipient().String()}
}

// spec: SPO-Xcustody-OUT-006, SPO-Xcustody-OUT-007, SPO-Xcustody-OUT-008
func TestExportSealsTheThreeFilesToTheRecipientOnly(t *testing.T) {
	r := newRig(t)
	res, err := r.uc().Run(context.Background(), r.req())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.audit.events) != 0 {
		t.Error("the delivery was recorded before the files were written")
	}
	if err := res.Record(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res.KESNumber != 0 || len(res.Files) != 3 {
		t.Fatalf("%+v", res)
	}
	want := map[string][]byte{"kes.skey.age": r.kesS, "vrf.skey.age": r.vrfS, "node.cert.age": r.opcert}
	other, _ := age.GenerateX25519Identity()
	for _, f := range res.Files {
		if bytes.Contains(f.Ciphertext, []byte("cborHex")) || bytes.Contains(f.Ciphertext, []byte("SigningKey")) {
			t.Errorf("%s holds plaintext", f.Name)
		}
		id, _ := nodeage.ParseIdentity(secret.Take([]byte(r.identity.String())))
		pt, err := id.Open(f.Ciphertext, 4096)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		pt.Use(func(b []byte) error {
			h, env, err := pool.UnframeDelivery(b)
			if err != nil || h.Kind+".age" != f.Name || h.KesNumber != 0 || h.Counter != 0 || len(h.PoolID) != 56 {
				t.Errorf("%s: header %+v %v", f.Name, h, err)
			}
			b = env
			if !bytes.Equal(b, want[f.Name]) {
				t.Errorf("%s: the decrypted bytes differ", f.Name)
			}
			return nil
		})
		oid, _ := nodeage.ParseIdentity(secret.Take([]byte(other.String())))
		if _, err := oid.Open(f.Ciphertext, 4096); !errors.Is(err, nodeage.ErrOpen) {
			t.Errorf("%s opens for another identity: %v", f.Name, err)
		}
	}
	if len(r.audit.events) != 1 || r.audit.events[0].Operation != "node-export" {
		t.Fatalf("audit %+v", r.audit.events)
	}
	d := strings.Join(r.audit.events[0].Detail, " ")
	for _, w := range []string{"kes=0", "recipient=" + res.RecipientID, "kes.skey.age,vrf.skey.age,node.cert.age"} {
		if !strings.Contains(d, w) {
			t.Errorf("audit detail %q lacks %q", d, w)
		}
	}
	if strings.Contains(d, r.identity.Recipient().String()) {
		t.Error("the audit record carries the whole recipient")
	}
}

// spec: SPO-Xcustody-PRE-007, SPO-Xcustody-PRE-008, SPO-Xcustody-PRE-009, SPO-Xcustody-PRE-011, SPO-Xcustody-PRE-016, SPO-Xcustody-PRE-017
func TestExportRefusals(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		mod  func(r *rig)
		want error
	}{
		{"a KES key recorded in a cold role", func(r *rig) { r.hist[r.kesID], _ = r.hist[r.kesID].With(custody.RolePoolCold) }, nodekeys.ErrColdRole},
		{"a VRF key recorded in a cold role", func(r *rig) { r.hist[r.vrfID], _ = r.hist[r.vrfID].With(custody.RoleCommitteeCold) }, nodekeys.ErrColdRole},
		{"no history for the KES key", func(r *rig) { delete(r.hist, r.kesID) }, nodekeys.ErrNoHistory},
		{"no history for the VRF key", func(r *rig) { delete(r.hist, r.vrfID) }, nodekeys.ErrNoHistory},
		{"a history that cannot be read", func(r *rig) { r.histErr = errors.New("corrupt") }, ports.ErrUnreadableRecords},
		{"a KES key whose history lacks the hot role", func(r *rig) { r.hist[r.kesID], _ = custody.NewRoleHistory(r.kesID, custody.RoleVRF) }, nodekeys.ErrWrongRole},
		{"a KES signing key of another pair", func(r *rig) {
			o, _ := native.KeyGen{}.GenerateKES(ctx)
			o.SKey.Use(func(b []byte) error { r.kesS = append([]byte(nil), b...); return nil })
		}, nodekeys.ErrMismatch},
		{"a VRF signing key of another pair", func(r *rig) {
			o, _ := native.KeyGen{}.GenerateVRF(ctx)
			o.SKey.Use(func(b []byte) error { r.vrfS = append([]byte(nil), b...); return nil })
		}, nodekeys.ErrMismatch},
		{"a certificate for another KES key", func(r *rig) {
			o, _ := native.KeyGen{}.GenerateKES(ctx)
			r.opcert = opcertFor(raw(t, o.VKey))
		}, nodekeys.ErrWrongOpCert},
		{"the VRF public key is a cold key's identity with history", func(r *rig) {
			id, _ := identity.KeyHashOf(raw(t, r.vrfV))
			r.hist[id], _ = custody.NewRoleHistory(id, custody.RolePoolCold)
		}, nodekeys.ErrColdRole},
		{"a certificate signed by another cold key", func(r *rig) {
			o := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
			r.opcert = signedOpcert(raw(t, r.kesV), o, 0, 0)
		}, nodekeys.ErrOpCertInvalid},
		{"a certificate with a damaged signature", func(r *rig) {
			i := bytes.Index(r.opcert, []byte("5840")) + 4
			if r.opcert[i] == '0' {
				r.opcert[i] = '1'
			} else {
				r.opcert[i] = '0'
			}
		}, nodekeys.ErrOpCertInvalid},
		{"a certificate older than the issue counter's last", func(r *rig) {
			_, c := coldFiles(testCold, 3)
			r.counter = c
		}, nodekeys.ErrOpCertInvalid},
		{"a cold key in the KES slot", func(r *rig) {
			r.kesS = []byte(`{"type":"StakePoolSigningKey_ed25519","description":"","cborHex":"5820` + strings.Repeat("11", 32) + `"}`)
		}, pool.ErrNotHot},
		{"a KES blob whose leaf seed is a cold key's", func(r *rig) {
			var e struct{ Type, Description, CborHex string }
			json.Unmarshal(r.kesS, &e)
			raw, _ := hex.DecodeString(e.CborHex)
			copy(raw[3:], bytes.Repeat([]byte{0x42}, 32))
			r.kesS, _ = json.Marshal(map[string]string{"type": e.Type, "description": e.Description, "cborHex": hex.EncodeToString(raw)})
		}, native.ErrBadHotKey},
		{"a KES envelope of the right type and 32 bytes", func(r *rig) {
			r.kesS = []byte(`{"type":"KesSigningKey_ed25519_kes_2^6","description":"","cborHex":"5820` + strings.Repeat("11", 32) + `"}`)
		}, pool.ErrNotHot},
		{"a missing certificate", func(r *rig) {}, nodekeys.ErrMissing},
	}
	for _, c := range cases {
		r := newRig(t)
		c.mod(r)
		r.build()
		if c.name == "a missing certificate" {
			delete(r.st.files, ports.NamedRef{Name: "p", Kind: ports.OpCert})
		}
		res, err := r.uc().Run(ctx, r.req())
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v (want %v)", c.name, err, c.want)
		}
		if res != nil || len(r.audit.events) != 0 {
			t.Errorf("%s: the refusal returned ciphertext or wrote an audit event", c.name)
		}
	}
}

// spec: SPO-Xcustody-OUT-006
func TestExportNeedsTheAuditRecordAndAGoodRecipient(t *testing.T) {
	r := newRig(t)
	r.audit.fail = true
	res, err := r.uc().Run(context.Background(), r.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Record(context.Background()); err == nil {
		t.Error("an unrecorded export was recorded")
	}
	r = newRig(t)
	for _, bad := range []string{"", "age1notakey", "AGE-SECRET-KEY-1QQQ", strings.ToUpper(r.identity.Recipient().String())} {
		req := r.req()
		req.Recipient = bad
		if res, err := r.uc().Run(context.Background(), req); err == nil || res != nil {
			t.Errorf("recipient %q: %v", bad, err)
		}
	}
	// a passphrase recipient is not a recipient
	if _, err := nodeage.ParseRecipientFile([]byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n")); err == nil {
		t.Error("a secret key was taken as a recipient file")
	}
}

func TestExportKesNumberDefaults(t *testing.T) {
	r := newRig(t)
	// counters: current 1, next 1 (a KES key without certificate): the newest key with a certificate is 0
	r.st.files[ports.NamedRef{Name: "p", Kind: ports.KesCounter}] = []byte("001\n")
	r.st.files[ports.NamedRef{Name: "p", Kind: ports.KesCounterNext}] = []byte("001\n")
	res, err := r.uc().Run(context.Background(), r.req())
	if err != nil || res.KESNumber != 0 {
		t.Errorf("%v %+v", err, res)
	}
	n := 7
	req := r.req()
	req.KES = &n
	if _, err := r.uc().Run(context.Background(), req); !errors.Is(err, nodekeys.ErrMissing) {
		t.Errorf("a number with no key: %v", err)
	}
}

// The audit event and the report say what the command cannot check about the
// producer's identity.
//
// spec: SPO-Xcustody-OUT-007, SPO-Xcustody-SEC-004
func TestExportRecordsWhetherTheIdentityIsTPMBound(t *testing.T) {
	r := newRig(t)
	res0, err := r.uc().Run(context.Background(), r.req())
	if err != nil {
		t.Fatal(err)
	}
	res0.Record(context.Background())
	if d := strings.Join(r.audit.events[0].Detail, " "); !strings.Contains(d, "tpm-identity=not verified") {
		t.Errorf("default: %q", d)
	}
	r = newRig(t)
	req := r.req()
	req.NoTPMIdentity = true
	res1, err := r.uc().Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	res1.Record(context.Background())
	if d := strings.Join(r.audit.events[0].Detail, " "); !strings.Contains(d, "tpm-identity=none") {
		t.Errorf("--no-tpm-identity: %q", d)
	}
}
