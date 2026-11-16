package hwcli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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

var (
	_ ports.MessageSigner = (*Session)(nil)
	_ ports.Cip36Signer   = (*Session)(nil)
)
