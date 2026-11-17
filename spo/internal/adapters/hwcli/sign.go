package hwcli

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrAuxDataHashStale means the transformed body carries an auxiliary data hash
// that is not the hash of its (re-serialised) auxiliary data. Upstream patches
// the old hash with `sed` in a variant no script calls (SPO-Ctx-OUT-003); here
// the body is refused instead, because patching text in CBOR is not safe.
var ErrAuxDataHashStale = fmt.Errorf("%w: the transformed body's auxiliary data hash does not match its auxiliary data", ErrBadDeviceOutput)

const kesVKeyType = "KesVerificationKey_ed25519_kes_2^6"

// IssueOpCert implements ports.OpCertIssuer with `node issue-op-cert`. The
// counter is the caller's: cardano-hw-cli reads and advances a counter file, so
// it gets a private temporary file set to req.Counter, and the file is thrown
// away with the directory: nothing is consumed by a failed issue, and the
// advanced file is never read (SPO-04d-OUT-002 is the use case's, not the
// tool's, here). The certificate is verified against the signing file's public
// key before it is returned.
//
// spec: SPO-04d-EXT-004, SPO-04d-OUT-002, SPO-04d-PR-003
func (s *Session) IssueOpCert(ctx context.Context, cold custody.Key[custody.PoolCold], req ports.OpCertRequest) ([]byte, error) {
	if err := s.has(custody.RolePoolCold, custody.OpIssueOpCert); err != nil {
		return nil, err
	}
	if len(req.KesVKey) != 32 {
		return nil, fmt.Errorf("the KES verification key is %d bytes, not 32", len(req.KesVKey))
	}
	sc, err := s.scratch()
	if err != nil {
		return nil, err
	}
	defer sc.done()
	hws, hwsContent, err := s.signingFile(ctx, sc, cold.Ref())
	if err != nil {
		return nil, err
	}
	pub, ok := hwsfilePubKey(hwsContent)
	if !ok {
		return nil, fmt.Errorf("%w: the pool's hardware signing file has no public key", ErrBadDeviceOutput)
	}
	kes, err := sc.put("kes.vkey", pool.MarshalEnvelope(pool.Envelope{Type: kesVKeyType, Description: "", CborHex: "5820" + hex.EncodeToString(req.KesVKey)}))
	if err != nil {
		return nil, err
	}
	var vk [32]byte
	copy(vk[:], pub)
	counter, err := sc.put("cold.counter", pool.IssueCounter{Next: req.Counter, ColdVKey: vk}.Envelope())
	if err != nil {
		return nil, err
	}
	out := sc.path("node.opcert")
	if _, err := s.run(ctx, "node", "issue-op-cert",
		"--kes-verification-key-file", kes,
		"--kes-period", fmt.Sprint(req.KesPeriod),
		"--operational-certificate-issue-counter-file", counter,
		"--hw-signing-file", hws,
		"--out-file", out); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("%w: no certificate was written", ErrBadDeviceOutput)
	}
	oc, err := pool.ParseOpCert(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	coldID, err := wantID(cold.Ref(), pub)
	if err != nil {
		return nil, err
	}
	if err := custody.VerifyOpCert(custody.OpCert{KesVKey: oc.KesVKey, Counter: oc.Counter, KesPeriod: oc.KesPeriod,
		ColdVKey: oc.ColdVKey, Signature: oc.Signature},
		&custody.OpCertAsk{KesVKey: req.KesVKey, Counter: req.Counter, KesPeriod: req.KesPeriod}, coldID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	env, _ := pool.ParseEnvelope(raw)
	return pool.MarshalEnvelope(env), nil
}

// Witness implements ports.TxWitnesser with no options.
func (s *Session) Witness(ctx context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	return s.WitnessWith(ctx, key, body, ports.HardwareTxOptions{})
}

// WitnessWith implements ports.HardwareWitnesser: `transaction witness` with
// the key's signing file, after the body has been checked to be in hardware
// form. A body that `transaction transform` would change is refused with
// *ports.ErrNotHardwareCanonical, because a witness is over THIS body: the
// caller canonicalises first (ports.HardwareCanonicalizer), before the body is
// fixed and shown. The witness is verified against the signing file's public
// key and the body's id before it is returned.
//
// spec: SPO-Ptx-EXT-005, SPO-Ptx-INV-009, SPO-Ptx-PRE-005, SPO-01sendLovelaces-EXT-002, SPO-21b-PRE-009, SPO-21b-SEC-003
func (s *Session) WitnessWith(ctx context.Context, key custody.KeyRef, body txbuild.TxBody, opt ports.HardwareTxOptions) (txbuild.Witness, error) {
	ws, err := s.WitnessMany(ctx, []custody.KeyRef{key}, body, opt)
	if err != nil {
		return txbuild.Witness{}, err
	}
	return ws[0], nil
}

// WitnessMany implements ports.HardwareMultiWitnesser: one `transaction
// witness` call with one `--hw-signing-file` and one `--out-file` per key, the
// combined witness of 05c (SPO-05c-EXT-004). Every witness is verified against
// the body id and the public key of ITS signing file, in the order of the keys,
// so a tool that swaps or repeats a witness is refused. The same key twice is
// refused up front: the device would be asked to sign twice for nothing.
//
// spec: SPO-05c-EXT-004, SPO-Ptx-EXT-005
func (s *Session) WitnessMany(ctx context.Context, keys []custody.KeyRef, body txbuild.TxBody, opt ports.HardwareTxOptions) ([]txbuild.Witness, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key to witness with")
	}
	seen := map[custody.KeyRef]bool{}
	for _, key := range keys {
		if seen[key] {
			return nil, fmt.Errorf("%s is named twice in one witness call", key)
		}
		seen[key] = true
		if err := s.has(key.Role, custody.OpWitnessTx); err != nil {
			return nil, err
		}
	}
	return s.witnessKeys(ctx, keys, body, opt)
}

func (s *Session) witnessKeys(ctx context.Context, keys []custody.KeyRef, body txbuild.TxBody, opt ports.HardwareTxOptions) ([]txbuild.Witness, error) {
	if opt.Unrestricted {
		for _, key := range keys {
			if why := s.profile.Check(custody.Demand{Role: key.Role, Operation: custody.OpWitnessTx, Features: custody.NewFeatures(custody.FeatUnrestricted)}); why != "" {
				return nil, fmt.Errorf("%w: %s", ErrNotSupported, why)
			}
		}
	}
	net, err := s.cfg.Network.args()
	if err != nil {
		return nil, err
	}
	if s.cfg.TxID != nil {
		id, err := s.cfg.TxID(body.CBOR)
		if err != nil {
			return nil, fmt.Errorf("read the transaction body: %w", err)
		}
		if id != body.ID {
			return nil, fmt.Errorf("the body's id %s is not the id of its bytes (%s)", body.ID, id)
		}
	}
	sc, err := s.scratch()
	if err != nil {
		return nil, err
	}
	defer sc.done()
	txFile, err := sc.put("body.tx", pool.TxEnvelope(body.CBOR))
	if err != nil {
		return nil, err
	}
	// The signing files are read, and checked to hold the demanded keys, before
	// the device is asked anything (a wrong account is refused with no prompt).
	args := []string{"transaction", "witness", "--tx-file", txFile}
	contents := make([][]byte, len(keys))
	for i, key := range keys {
		hws, content, err := s.signingFile(ctx, sc, key)
		if err != nil {
			return nil, err
		}
		contents[i] = content
		args = append(args, "--hw-signing-file", hws)
	}
	// Conversion is checked once per body per session: the same body witnessed
	// by a payment and a stake key asks the tool to transform it once. Only a
	// body found canonical is remembered.
	ck := canonKey{hash: blake2b.Sum256(body.CBOR), unrestricted: opt.Unrestricted}
	if !s.knownCanonical(ck) {
		canon, err := s.transform(ctx, sc, txFile, opt.Unrestricted)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(canon, body.CBOR) {
			return nil, &ports.ErrNotHardwareCanonical{Canonical: canon}
		}
		s.markCanonical(ck)
	}
	for _, ck := range opt.ChangeKeys {
		p, _, err := s.signingFile(ctx, sc, ck)
		if err != nil {
			return nil, err
		}
		args = append(args, "--change-output-key-file", p)
	}
	if opt.Unrestricted {
		args = append(args, "--allow-unrestricted-mode")
	}
	outs := make([]string, len(keys))
	for i := range keys {
		outs[i] = sc.path(fmt.Sprintf("body%d.witness", i))
	}
	args = append(args, net...)
	for _, o := range outs {
		args = append(args, "--out-file", o)
	}
	if _, err := s.run(ctx, args...); err != nil {
		return nil, err
	}
	ws := make([]txbuild.Witness, len(keys))
	for i := range keys {
		raw, err := os.ReadFile(outs[i])
		if err != nil {
			return nil, fmt.Errorf("%w: no witness was written for the %s", ErrBadDeviceOutput, keys[i])
		}
		w, err := pool.ParseWitnessEnvelope(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
		}
		if pub, ok := hwsfilePubKey(contents[i]); ok {
			if _, err := wantID(keys[i], pub); err != nil {
				return nil, err
			}
			if err := txbuild.VerifyWitness(body, w, txbuild.HashKey(pub)); err != nil {
				return nil, fmt.Errorf("%w: %s: %v", ErrBadDeviceOutput, keys[i], err)
			}
		} else {
			// The adapter knows the key it asked for only through its signing
			// file's public key. With none, the witness cannot be checked
			// against the demanded identity, so it is not accepted.
			return nil, fmt.Errorf("%w: the signing file of %s has no public key, so its witness cannot be checked against the key demanded", ErrBadDeviceOutput, keys[i])
		}
		ws[i] = w
	}
	return ws, nil
}

func (s *Session) knownCanonical(k canonKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.canonical[k]
}

func (s *Session) markCanonical(k canonKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.canonical == nil {
		s.canonical = map[canonKey]bool{}
	}
	s.canonical[k] = true
}

// transform runs `transaction transform` and returns the CBOR it wrote.
//
// spec: SPO-Ctx-EXT-001, SPO-Ctx-PRE-003, SPO-Ctx-PRE-004
func (s *Session) transform(ctx context.Context, sc *scratch, txFile string, unrestricted bool) ([]byte, error) {
	sc.n++
	out := sc.path(fmt.Sprintf("canonical%d.tx", sc.n))
	args := []string{"transaction", "transform"}
	if unrestricted {
		args = append(args, "--allow-unrestricted-mode")
	}
	args = append(args, "--tx-file", txFile, "--out-file", out)
	if _, err := s.run(ctx, args...); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("%w: no transformed body was written", ErrBadDeviceOutput)
	}
	cbor, err := pool.ParseTxEnvelope(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	return cbor, nil
}

// Canonicalize implements ports.HardwareCanonicalizer with `transaction
// transform`. It needs no device. The new body's id is computed from its bytes
// (Config.TxID). When the body's auxiliary data is re-serialised so that the
// hash the body carries no longer matches, it is refused (ErrAuxDataHashStale).
//
// spec: SPO-Ctx-IF-001, SPO-Ctx-IF-002, SPO-Ctx-PRE-001, SPO-Ctx-PRE-002, SPO-Ctx-PRE-003, SPO-Ctx-PRE-004, SPO-Ctx-PRE-005, SPO-Ctx-EXT-001, SPO-Ctx-OUT-001, SPO-Ctx-OUT-002, SPO-Ctx-OUT-004, SPO-Ctx-IN-001, SPO-Ctx-IN-002, SPO-Ptx-EXT-005, SPO-Xparty-INV-012
func (s *Session) Canonicalize(ctx context.Context, body txbuild.TxBody, opt ports.HardwareTxOptions) (txbuild.TxBody, bool, error) {
	if s.cfg.TxID == nil {
		return txbuild.TxBody{}, false, fmt.Errorf("%w: no transaction id function is configured", ErrBadDeviceOutput)
	}
	if opt.Unrestricted {
		if why := s.profile.Check(custody.Demand{Role: custody.RolePayment, Operation: custody.OpWitnessTx, Features: custody.NewFeatures(custody.FeatUnrestricted)}); why != "" {
			return txbuild.TxBody{}, false, fmt.Errorf("%w: %s", ErrNotSupported, why)
		}
	}
	sc, err := s.scratch()
	if err != nil {
		return txbuild.TxBody{}, false, err
	}
	defer sc.done()
	txFile, err := sc.put("body.tx", pool.TxEnvelope(body.CBOR))
	if err != nil {
		return txbuild.TxBody{}, false, err
	}
	canon, err := s.transform(ctx, sc, txFile, opt.Unrestricted)
	if err != nil {
		return txbuild.TxBody{}, false, err
	}
	if bytes.Equal(canon, body.CBOR) {
		s.markCanonical(canonKey{hash: blake2b.Sum256(body.CBOR), unrestricted: opt.Unrestricted})
		return body, false, nil
	}
	if auxHashStale(canon) {
		return txbuild.TxBody{}, false, ErrAuxDataHashStale
	}
	id, err := s.cfg.TxID(canon)
	if err != nil {
		return txbuild.TxBody{}, false, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	return txbuild.TxBody{CBOR: canon, ID: chain.TxID(id)}, true, nil
}

// auxHashStale reports the situation of SPO-Ctx-IN-001 and SPO-Ctx-IN-002: the
// transaction ends in `f5 d90103 <auxiliary data>` (validity flag true and a
// tag-259 auxiliary data), and the blake2b-256 of those auxiliary data bytes does
// not occur in the body. A transaction without auxiliary data (f5 f6) is never
// stale, as upstream.
func auxHashStale(cbor []byte) bool {
	marker := []byte{0xf5, 0xd9, 0x01, 0x03}
	i := bytes.LastIndex(cbor, marker)
	if i < 0 {
		return false
	}
	aux := cbor[i+1:]
	h := blake2b.Sum256(aux)
	return !bytes.Contains(cbor[:i], h[:])
}

// PolicyID implements ports.HardwarePolicyIDer with `transaction policyid`; the
// device shows the script's expiry slot (SPO-10-EXT-005).
//
// spec: SPO-10-EXT-005
func (s *Session) PolicyID(ctx context.Context, key custody.Key[custody.Policy], script []byte) (string, error) {
	if err := s.has(custody.RolePolicy, custody.OpHardwarePolicyID); err != nil {
		return "", err
	}
	sc, err := s.scratch()
	if err != nil {
		return "", err
	}
	defer sc.done()
	hws, _, err := s.signingFile(ctx, sc, key.Ref())
	if err != nil {
		return "", err
	}
	sf, err := sc.put("policy.script", script)
	if err != nil {
		return "", err
	}
	text, err := s.run(ctx, "transaction", "policyid", "--script-file", sf, "--hw-signing-file", hws)
	if err != nil {
		return "", err
	}
	id := strings.ToLower(strings.TrimSpace(strings.SplitN(strings.TrimSpace(text), "\n", 2)[0]))
	if b, err := hex.DecodeString(id); err != nil || len(b) != 28 {
		return "", fmt.Errorf("%w: %q is not a policy id", ErrBadDeviceOutput, clip(id, 80))
	}
	if s.cfg.PolicyID != nil {
		want, err := s.cfg.PolicyID(script)
		if err != nil {
			return "", fmt.Errorf("read the policy script: %w", err)
		}
		if id != hex.EncodeToString(want[:]) {
			return "", fmt.Errorf("%w: the device's policy id %s is not the hash of the script (%x)", ErrBadDeviceOutput, id, want)
		}
	}
	return id, nil
}

var (
	_ ports.HardwareKeyExporter    = (*Session)(nil)
	_ ports.OpCertIssuer           = (*Session)(nil)
	_ ports.HardwareWitnesser      = (*Session)(nil)
	_ ports.HardwareMultiWitnesser = (*Session)(nil)
	_ ports.HardwareCanonicalizer  = (*Session)(nil)
	_ ports.HardwarePolicyIDer     = (*Session)(nil)
)
