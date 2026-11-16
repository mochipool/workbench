package hwcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// SignMessage implements ports.MessageSigner with `message sign` (CIP-8). The
// tool writes `COSE_Sign1_hex` and `COSE_Key_hex` (SPO-15-EXT-005). The device
// signs with the key of the hardware signing file; the profile offers it for
// the pool cold key on Ledger and Keystone (SPO-15-EXT-004). A raw address for
// the COSE header is not supported: the tool takes it as text, and no script
// gives one.
//
// spec: SPO-15-EXT-004, SPO-15-EXT-005, SPO-15-PR-001
func (s *Session) SignMessage(ctx context.Context, req ports.MessageRequest) (ports.SignedMessage, error) {
	if err := s.has(req.Key.Role, custody.OpSignMessage); err != nil {
		return ports.SignedMessage{}, err
	}
	if len(req.Address) != 0 {
		return ports.SignedMessage{}, fmt.Errorf("%w: a COSE header address cannot be given to cardano-hw-cli as raw bytes", ErrNotSupported)
	}
	sc, err := s.scratch()
	if err != nil {
		return ports.SignedMessage{}, err
	}
	defer sc.done()
	hws, hwsContent, err := s.signingFile(ctx, sc, req.Key)
	if err != nil {
		return ports.SignedMessage{}, err
	}
	out := sc.path("message.signed")
	args := []string{"message", "sign", "--message-hex", hex.EncodeToString(req.Payload), "--signing-path-hwsfile", hws}
	if req.Hashed {
		args = append(args, "--hashed")
	}
	args = append(args, "--out-file", out)
	if _, err := s.run(ctx, args...); err != nil {
		return ports.SignedMessage{}, err
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return ports.SignedMessage{}, fmt.Errorf("%w: no signed message was written", ErrBadDeviceOutput)
	}
	var j struct {
		Sign1 string `json:"COSE_Sign1_hex"`
		Key   string `json:"COSE_Key_hex"`
	}
	if json.Unmarshal(raw, &j) != nil {
		return ports.SignedMessage{}, fmt.Errorf("%w: the signed message is not JSON", ErrBadDeviceOutput)
	}
	sign1, err1 := hex.DecodeString(j.Sign1)
	key, err2 := hex.DecodeString(j.Key)
	if err1 != nil || err2 != nil || len(sign1) == 0 || len(key) == 0 {
		return ports.SignedMessage{}, fmt.Errorf("%w: COSE_Sign1_hex or COSE_Key_hex is missing", ErrBadDeviceOutput)
	}
	if pub, ok := hwsfilePubKey(hwsContent); ok && !bytes.Contains(key, pub) {
		return ports.SignedMessage{}, fmt.Errorf("%w: the COSE key is not the signing file's public key", ErrBadDeviceOutput)
	}
	return ports.SignedMessage{Sign1: sign1, Key: key}, nil
}

// SignCip36 implements ports.Cip36Signer with `vote registration-metadata`: the
// device signs the registration with the hardware stake key. The tool writes the
// metadata CBOR; it is returned only when it is exactly the registration that
// was asked for, with a signature that verifies under the stake key
// (SPO-09a-EXT-004, SPO-09a-INV-005).
//
// spec: SPO-09a-EXT-004, SPO-09a-INV-005
func (s *Session) SignCip36(ctx context.Context, key custody.Key[custody.Stake], reg cose.Cip36) (ports.Registration, error) {
	return s.SignCip36With(ctx, key, reg, ports.Cip36HardwareOptions{})
}

// SignCip36With is SignCip36 with the options of a device. With a RewardsKey
// the payment key's signing file is passed as
// `--payment-address-signing-key-hwsfile` (SPO-09a-INV-004), after the adapter
// has checked that its public key is the payment credential of the rewards
// address: a file that does not belong to the address is never handed over.
//
// spec: SPO-09a-EXT-004, SPO-09a-INV-004
func (s *Session) SignCip36With(ctx context.Context, key custody.Key[custody.Stake], reg cose.Cip36, opt ports.Cip36HardwareOptions) (ports.Registration, error) {
	if err := s.has(custody.RoleStake, custody.OpSignCip36); err != nil {
		return ports.Registration{}, err
	}
	if err := reg.Validate(); err != nil {
		return ports.Registration{}, err
	}
	net, err := s.cfg.Network.args()
	if err != nil {
		return ports.Registration{}, err
	}
	sc, err := s.scratch()
	if err != nil {
		return ports.Registration{}, err
	}
	defer sc.done()
	hws, hwsContent, err := s.signingFile(ctx, sc, key.Ref())
	if err != nil {
		return ports.Registration{}, err
	}
	if pub, ok := hwsfilePubKey(hwsContent); !ok || !bytes.Equal(pub, reg.StakePub[:]) {
		return ports.Registration{}, fmt.Errorf("the hardware stake key is not the registration's stake key")
	}
	hrp := "addr"
	if len(reg.Address) == 0 || reg.Address[0]&0x0f != 1 {
		hrp = "addr_test"
	}
	addr, err := chain.Bech32Encode(hrp, reg.Address)
	if err != nil {
		return ports.Registration{}, fmt.Errorf("the rewards address: %w", err)
	}
	out := sc.path("registration.cbor")
	args := []string{"vote", "registration-metadata"}
	for _, d := range reg.Delegations {
		vk, err := chain.Bech32Encode("cvote_vk", d.VotePub[:])
		if err != nil {
			return ports.Registration{}, err
		}
		args = append(args, "--vote-public-key-string", vk, "--vote-weight", fmt.Sprint(d.Weight))
	}
	args = append(args, "--stake-signing-key-hwsfile", hws, "--payment-address", addr, "--nonce", fmt.Sprint(reg.Nonce))
	if reg.Purpose != 0 {
		args = append(args, "--voting-purpose", fmt.Sprint(reg.Purpose))
	}
	if opt.RewardsKey != nil {
		if opt.RewardsKey.Role != custody.RolePayment {
			return ports.Registration{}, fmt.Errorf("the rewards key must be a payment key, not a %s key", opt.RewardsKey.Role)
		}
		pw, pwContent, err := s.signingFile(ctx, sc, *opt.RewardsKey)
		if err != nil {
			return ports.Registration{}, err
		}
		pub, ok := hwsfilePubKey(pwContent)
		h := cose.Blake2b224(pub)
		// The payment credential is the first 28 bytes after the header byte, in
		// every Shelley address that has one (base, pointer, enterprise).
		if !ok || len(reg.Address) < 29 || !bytes.Equal(reg.Address[1:29], h[:]) {
			return ports.Registration{}, fmt.Errorf("the hardware payment key %s is not the payment credential of the rewards address", opt.RewardsKey)
		}
		args = append(args, "--payment-address-signing-key-hwsfile", pw)
	}
	args = append(append(args, net...), "--metadata-cbor-out-file", out)
	if _, err := s.run(ctx, args...); err != nil {
		return ports.Registration{}, err
	}
	cbor, err := os.ReadFile(out)
	if err != nil || len(cbor) < 64 {
		return ports.Registration{}, fmt.Errorf("%w: no registration metadata was written", ErrBadDeviceOutput)
	}
	sig := cbor[len(cbor)-64:]
	h := reg.SigningHash()
	if !ed25519.Verify(reg.StakePub[:], h[:], sig) {
		return ports.Registration{}, fmt.Errorf("%w: the registration signature does not verify under the stake key", ErrBadDeviceOutput)
	}
	if !bytes.Equal(reg.Metadata(sig), cbor) {
		return ports.Registration{}, fmt.Errorf("%w: the registration the device signed differs from the one asked for", ErrBadDeviceOutput)
	}
	return ports.Registration{CBOR: cbor, JSON: reg.MetadataJSON(sig)}, nil
}

// SignCip88 implements ports.Cip88Signer: the Calidus registration signed by
// the pool cold key on the device (SPO-15-EXT-004, SPO-15-EXT-005). The message
// is the blake2b-256 of the payload (SPO-15-INV-006), signed with `message sign`
// and no `--hashed`. The tool's COSE_Sign1 is checked before anything is built
// from it: it must carry exactly this hash as its payload, its protected header
// must name the pool id as the address, and the signature must verify under the
// COSE key, which must be the signing file's key and hash to the pool id. The
// metadata then carries the device's own COSE_Sign1 (its protected header is the
// tool's), and cose.VerifyCip88 checks the finished metadata.
//
// ASSUMPTION a device can confirm (checklist item 6): that `message sign` over a
// pool cold key writes a protected header {1:-8, "address": <28-byte pool id>}.
// If it writes another address form, this refuses with ErrBadDeviceOutput and the
// registration is not built.
//
// spec: SPO-15-EXT-004, SPO-15-EXT-005, SPO-15-INV-005, SPO-15-INV-006, SPO-15-OUT-003
func (s *Session) SignCip88(ctx context.Context, key custody.Key[custody.PoolCold], reg cose.Cip88) (ports.Registration, error) {
	if err := s.has(custody.RolePoolCold, custody.OpSignCip88); err != nil {
		return ports.Registration{}, err
	}
	sc, err := s.scratch()
	if err != nil {
		return ports.Registration{}, err
	}
	_, content, err := s.signingFile(ctx, sc, key.Ref())
	sc.done()
	if err != nil {
		return ports.Registration{}, err
	}
	pub, ok := hwsfilePubKey(content)
	if !ok {
		return ports.Registration{}, fmt.Errorf("%w: the pool's hardware signing file has no public key", ErrBadDeviceOutput)
	}
	if h := cose.Blake2b224(pub); h != reg.PoolID {
		return ports.Registration{}, errors.New("the hardware cold key is not the pool's key: its hash is not the registration's pool id")
	}
	hash := reg.PayloadHash()
	msg, err := s.SignMessage(ctx, ports.MessageRequest{Key: key.Ref(), Payload: hash[:]})
	if err != nil {
		return ports.Registration{}, err
	}
	p, err := cose.ParseSign1(msg.Sign1)
	if err != nil {
		return ports.Registration{}, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	devPub, err := cose.ParseKey(msg.Key)
	if err != nil || !bytes.Equal(devPub, pub) {
		return ports.Registration{}, fmt.Errorf("%w: the COSE key is not the pool's cold key", ErrBadDeviceOutput)
	}
	if !p.HasPayload() || !bytes.Equal(p.Payload, hash[:]) || p.Hashed {
		return ports.Registration{}, fmt.Errorf("%w: the signed message is not the registration's payload hash", ErrBadDeviceOutput)
	}
	if !bytes.Equal(p.Address, reg.PoolID[:]) {
		return ports.Registration{}, fmt.Errorf("%w: the protected header's address is not the pool id", ErrBadDeviceOutput)
	}
	if !ed25519.Verify(pub, cose.SigStructure(p.Protected, p.Payload), p.Signature) {
		return ports.Registration{}, fmt.Errorf("%w: the signature does not verify under the pool's cold key", ErrBadDeviceOutput)
	}
	cbor := reg.MetadataFrom(pub, p.Sign1)
	if _, err := cose.VerifyCip88(cbor); err != nil {
		return ports.Registration{}, fmt.Errorf("%w: %v", ErrBadDeviceOutput, err)
	}
	return ports.Registration{CBOR: cbor, JSON: reg.MetadataJSONFrom(pub, p.Sign1)}, nil
}

var (
	_ ports.MessageSigner       = (*Session)(nil)
	_ ports.Cip36Signer         = (*Session)(nil)
	_ ports.HardwareCip36Signer = (*Session)(nil)
	_ ports.Cip88Signer         = (*Session)(nil)
)
