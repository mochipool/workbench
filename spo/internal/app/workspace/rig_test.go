package workspace

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// memStore is an in-memory ports.Store, ports.Vault and ports.SourceLister
// that enforces the secret-kind rules of the real stores.
type memStore struct {
	mu         sync.Mutex
	files      map[ports.Ref][]byte
	unknown    []ports.SourceUnknown
	updates    int
	failPut    error
	failUpdate error
}

func newMem() *memStore { return &memStore{files: map[ports.Ref][]byte{}} }

type memTx struct {
	s     *memStore
	stage map[ports.Ref][]byte
	del   map[ports.Ref]bool
}

func (t *memTx) cur(r ports.Ref) ([]byte, bool) {
	if t.del[r] {
		return nil, false
	}
	if b, ok := t.stage[r]; ok {
		return b, true
	}
	b, ok := t.s.files[r]
	return b, ok
}

func (t *memTx) Get(r ports.Ref) ([]byte, error) {
	if r.Kind.Secret() {
		return nil, ports.ErrSecretKind
	}
	b, ok := t.cur(r)
	if !ok {
		return nil, ports.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}
func (t *memTx) Exists(r ports.Ref) (bool, error) { _, ok := t.cur(r); return ok, nil }
func (t *memTx) Put(r ports.Ref, d []byte) error {
	if r.Kind.Secret() {
		return ports.ErrSecretKind
	}
	if t.s.failPut != nil {
		return t.s.failPut
	}
	t.stage[r] = append([]byte(nil), d...)
	return nil
}
func (t *memTx) PutSecret(r ports.Ref, b *secret.Buffer) error {
	if !r.Kind.Secret() {
		return ports.ErrInvalidRef
	}
	return b.Use(func(d []byte) error { t.stage[r] = append([]byte(nil), d...); return nil })
}
func (t *memTx) Delete(r ports.Ref) error { t.del[r] = true; return nil }

func (s *memStore) View(_ context.Context, fn func(ports.Reader) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&memTx{s: s, stage: map[ports.Ref][]byte{}, del: map[ports.Ref]bool{}})
}

func (s *memStore) Update(_ context.Context, fn func(ports.Writer) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &memTx{s: s, stage: map[ports.Ref][]byte{}, del: map[ports.Ref]bool{}}
	if err := fn(t); err != nil {
		return err
	}
	if s.failUpdate != nil {
		return s.failUpdate
	}
	for r := range t.del {
		delete(s.files, r)
	}
	for r, b := range t.stage {
		s.files[r] = b
	}
	s.updates++
	return nil
}

func (s *memStore) Open(_ context.Context, r ports.Ref) (*secret.Buffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[r]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return secret.Take(append([]byte(nil), b...)), nil
}

func (s *memStore) List(context.Context) (ports.SourceListing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var l ports.SourceListing
	for r := range s.files {
		l.Entries = append(l.Entries, ports.SourceEntry{Ref: r})
	}
	sort.Slice(l.Entries, func(i, j int) bool { return l.Entries[i].Ref.String() < l.Entries[j].Ref.String() })
	l.Unknown = s.unknown
	return l, nil
}

func (s *memStore) put(r ports.Ref, d []byte) { s.files[r] = d }

func (s *memStore) snapshot() map[ports.Ref]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[ports.Ref]string{}
	for r, b := range s.files {
		out[r] = string(b)
	}
	return out
}

// fakeGPG implements both gpg ports without gpg: the "ciphertext" is the key
// text behind a recognisable pad, bound to the exact password bytes.
type fakeGPG struct {
	mu       sync.Mutex
	decrypts int
	encrypts int
	seen     []string // every passphrase handed to Decrypt, for assertions
}

const fakePad = "0123456789abcdef0123456789abcdef"

func (g *fakeGPG) Encrypt(_ context.Context, cbor, pass *ports.Secret) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.encrypts++
	var out []byte
	err := cbor.Use(func(c []byte) error {
		return pass.Use(func(p []byte) error {
			out = []byte(hex.EncodeToString([]byte(fakePad + string(p) + "\x00" + string(c))))
			return nil
		})
	})
	return out, err
}

func (g *fakeGPG) Decrypt(_ context.Context, encrHex []byte, pass *ports.Secret) (*ports.Secret, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.decrypts++
	raw, err := hex.DecodeString(string(encrHex))
	if err != nil || !strings.HasPrefix(string(raw), fakePad) {
		return nil, ports.ErrMalformedCiphertext
	}
	body := strings.TrimPrefix(string(raw), fakePad)
	pw, cbor, ok := strings.Cut(body, "\x00")
	if !ok {
		return nil, ports.ErrMalformedCiphertext
	}
	var good bool
	_ = pass.Use(func(p []byte) error { g.seen = append(g.seen, string(p)); good = string(p) == pw; return nil })
	if !good {
		return nil, ports.ErrWrongPassphrase
	}
	return secret.Take([]byte(cbor)), nil
}

// edDeriver derives ed25519 verification keys from 32-byte seed keys.
type edDeriver struct{}

func (edDeriver) DeriveVerificationKey(_ context.Context, env *ports.Secret) ([]byte, error) {
	var out []byte
	err := env.Use(func(d []byte) error {
		span, err := keyfile.CborHexSpan(d)
		if err != nil {
			return err
		}
		raw, err := hex.DecodeString(string(span))
		if err != nil || len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
			return ports.ErrKeyTypeUnsupported
		}
		out = []byte(ed25519.NewKeyFromSeed(raw[2:]).Public().(ed25519.PublicKey))
		return nil
	})
	return out, err
}

// addrInspector maps "addr_<hex of key hash>" to its payment key hash,
// "addr_<payment hash>_<stake hash>" to a base address and "stake_<hex>" to a
// reward address.
type addrInspector struct{}

func hash28(h string) (*txbuild.KeyHash, bool) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 28 {
		return nil, false
	}
	var kh txbuild.KeyHash
	copy(kh[:], b)
	return &kh, true
}

func (addrInspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	if h, ok := strings.CutPrefix(string(a), "stake_"); ok {
		kh, ok := hash28(h)
		if !ok {
			return ports.AddressInfo{}, errors.New("not an address")
		}
		return ports.AddressInfo{Kind: ports.AddrReward, StakeKeyHash: kh}, nil
	}
	h, ok := strings.CutPrefix(string(a), "addr_")
	pay, stake, _ := strings.Cut(h, "_")
	kh, ok2 := hash28(pay)
	if !ok || !ok2 {
		return ports.AddressInfo{}, errors.New("not an address")
	}
	info := ports.AddressInfo{Kind: ports.AddrEnterprise, PaymentKeyHash: kh}
	if stake != "" {
		sh, ok := hash28(stake)
		if !ok {
			return ports.AddressInfo{}, errors.New("not an address")
		}
		info.Kind, info.StakeKeyHash = ports.AddrBase, sh
	}
	return info, nil
}

type auditLog struct {
	events []ports.AuditEvent
	err    error
	onRec  func()
}

func (a *auditLog) Record(_ context.Context, e ports.AuditEvent) error {
	if a.onRec != nil {
		a.onRec()
	}
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, e)
	return nil
}

// A key pair with real ed25519 keys; seed makes it deterministic.
type keyPair struct {
	skey, vkey []byte
	cbor       string
}

func pair(seed byte, skType, vkType, desc string) keyPair {
	s := make([]byte, 32)
	for i := range s {
		s[i] = seed + byte(i)
	}
	pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	cbor := "5820" + hex.EncodeToString(s)
	return keyPair{
		skey: keyfile.AppendPlainEnvelope(nil, skType, desc+" Signing Key", []byte(cbor), len(cbor), "    "),
		vkey: pool.MarshalEnvelope(pool.Envelope{Type: vkType, Description: desc + " Verification Key", CborHex: "5820" + hex.EncodeToString(pub)}),
		cbor: cbor,
	}
}

func payment(seed byte) keyPair {
	return pair(seed, "PaymentSigningKeyShelley_ed25519", "PaymentVerificationKeyShelley_ed25519", "Payment")
}
func cold(seed byte) keyPair {
	return pair(seed, "StakePoolSigningKey_ed25519", "StakePoolVerificationKey_ed25519", "Stake Pool Operator")
}

func keyHashOf(vkey []byte) txbuild.KeyHash {
	env, _ := pool.ParseEnvelope(vkey)
	k, _ := env.Key32()
	return txbuild.HashKey(k)
}

func addrOf(vkey []byte) []byte {
	h := keyHashOf(vkey)
	return []byte("addr_" + hex.EncodeToString(h[:]))
}

// encrypted wraps a plain key the way upstream does, with the fake cipher.
func encryptedOf(t *testing.T, kp keyPair, password string) []byte {
	t.Helper()
	g := &fakeGPG{}
	enc, err := g.Encrypt(context.Background(), secret.Take([]byte(kp.cbor)), secret.Take([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := keyfile.Classify(kp.skey)
	return keyfile.EncryptedEnvelope(info.Type, info.Description, enc)
}

func sec(s string) *ports.Secret { return secret.Take([]byte(s)) }

// workspaceFixture is a small realistic upstream directory: a wallet made by
// 03a (payment and stake accounts), a pool (cold, VRF, KES, opcert counters).
func workspaceFixture(t *testing.T) (*memStore, map[string]keyPair) {
	t.Helper()
	s := newMem()
	k := map[string]keyPair{
		"pay":   payment(1),
		"stake": pair(40, "StakeSigningKeyShelley_ed25519", "StakeVerificationKeyShelley_ed25519", "Stake"),
		"cold":  cold(80),
	}
	s.put(ports.Ref{Name: "w.payment", Kind: ports.AddrSKey}, k["pay"].skey)
	s.put(ports.Ref{Name: "w.payment", Kind: ports.AddrVKey}, k["pay"].vkey)
	s.put(ports.Ref{Name: "w.payment", Kind: ports.AddrFile}, addrOf(k["pay"].vkey))
	s.put(ports.Ref{Name: "w", Kind: ports.StakingSKey}, k["stake"].skey)
	s.put(ports.Ref{Name: "w", Kind: ports.StakingVKey}, k["stake"].vkey)
	s.put(ports.Ref{Name: "w", Kind: ports.PaymentMnemonics}, []byte("abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual\n"))
	s.put(ports.Ref{Name: "mypool", Kind: ports.NodeSKey}, k["cold"].skey)
	s.put(ports.Ref{Name: "mypool", Kind: ports.NodeVKey}, k["cold"].vkey)
	var vk [32]byte
	env, _ := pool.ParseEnvelope(k["cold"].vkey)
	kb, _ := env.Key32()
	copy(vk[:], kb)
	s.put(ports.Ref{Name: "mypool", Kind: ports.NodeCounter}, pool.IssueCounter{Next: 2, ColdVKey: vk}.Envelope())
	s.put(ports.Ref{Name: "mypool", Kind: ports.KesCounter}, pool.FormatCounter(1))
	s.put(ports.Ref{Name: "mypool", Kind: ports.KesCounterNext}, pool.FormatCounter(2))
	kes := []byte(`{"type":"KesSigningKey_ed25519_kes_2^6","description":"KES Signing Key","cborHex":"5860` + strings.Repeat("ab", 96) + `"}`)
	s.put(ports.Ref{Name: "mypool", Kind: ports.KesSKey, Num: 1}, kes)
	s.put(ports.Ref{Name: "mypool", Kind: ports.KesVKey, Num: 1}, pool.MarshalEnvelope(pool.Envelope{Type: "KesVerificationKey_ed25519_kes_2^6", Description: "KES Verification Key", CborHex: "5820" + strings.Repeat("cd", 32)}))
	s.put(ports.Ref{Name: "mypool", Kind: ports.OpCert, Num: 1}, pool.MarshalEnvelope(pool.Envelope{Type: "NodeOperationalCertificate", CborHex: "8400"}))
	return s, k
}
