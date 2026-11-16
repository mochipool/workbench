package native

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/blinklabs-io/gouroboros/ledger/common"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Envelope type and descriptions of the certificates, as cardano-cli
// 11.2.3.0 `stake-address registration-certificate`, `deregistration-
// certificate`, `stake-delegation-certificate` and `vote-delegation-
// certificate` write them (checked against the real tool in spo/test/parity).
const certEnvelopeType = "Certificate"

var certDescriptions = map[stake.CertKind]string{
	stake.CertRegistration:   "Stake Address Registration Certificate",
	stake.CertDeregistration: "Stake Address Deregistration Certificate",
	stake.CertPoolDelegation: "Stake Delegation Certificate",
	stake.CertVoteDelegation: "Vote Delegation Certificate",
}

// ErrUnsupportedCertificate: a certificate this adapter does not read.
var ErrUnsupportedCertificate = errors.New("unsupported certificate")

// BuildCertificate implements ports.CertificateBuilder on gouroboros'
// certificate structs: the Conway registration and deregistration (types 7
// and 8, with the deposit), the stake delegation (type 2) and the vote
// delegation (type 9). The text envelope is the one cardano-cli writes:
// four-space indent, three fields, a trailing newline.
//
// spec: SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009,
// spec: SPO-03b-EXT-002, SPO-05b-EXT-001, SPO-08a-EXT-002, SPO-22a-EXT-001
func (Ledger) BuildCertificate(spec stake.Spec) (stake.Certificate, error) {
	if err := spec.Validate(); err != nil {
		return stake.Certificate{}, err
	}
	if spec.IsGovernance() {
		return buildGovCertificate(spec)
	}
	cred := common.Credential{CredType: common.CredentialTypeAddrKeyHash, Credential: common.CredentialHash(spec.Stake)}
	var cert any
	switch spec.Kind {
	case stake.CertRegistration:
		cert = &common.RegistrationCertificate{CertType: uint(common.CertificateTypeRegistration), StakeCredential: cred, Amount: uint64(spec.Deposit)}
	case stake.CertDeregistration:
		cert = &common.DeregistrationCertificate{CertType: uint(common.CertificateTypeDeregistration), StakeCredential: cred, Amount: uint64(spec.Deposit)}
	case stake.CertPoolDelegation:
		cert = &common.StakeDelegationCertificate{CertType: uint(common.CertificateTypeStakeDelegation), StakeCredential: &cred, PoolKeyHash: common.PoolKeyHash(spec.Pool)}
	case stake.CertVoteDelegation:
		d := common.Drep{}
		switch spec.DRep.Kind {
		case stake.DRepKey:
			d = common.Drep{Type: common.DrepTypeAddrKeyHash, Credential: spec.DRep.Hash[:]}
		case stake.DRepScript:
			d = common.Drep{Type: common.DrepTypeScriptHash, Credential: spec.DRep.Hash[:]}
		case stake.DRepAbstain:
			d = common.Drep{Type: common.DrepTypeAbstain}
		case stake.DRepNoConfidence:
			d = common.Drep{Type: common.DrepTypeNoConfidence}
		}
		cert = &common.VoteDelegationCertificate{CertType: uint(common.CertificateTypeVoteDelegation), StakeCredential: cred, Drep: d}
	}
	raw, err := cbor.Encode(cert)
	if err != nil {
		return stake.Certificate{}, fmt.Errorf("encode the certificate: %w", err)
	}
	env, err := certEnvelope(spec.Kind, raw)
	if err != nil {
		return stake.Certificate{}, err
	}
	out := stake.Certificate{Spec: spec, CBOR: raw, Envelope: env}
	// The encoding must read back as the spec it was made from.
	back, err := Ledger{}.DecodeCertificate(env)
	if err != nil {
		return stake.Certificate{}, fmt.Errorf("the encoded certificate does not read back: %w", err)
	}
	if back.Spec != spec {
		return stake.Certificate{}, errors.New("the encoded certificate reads back as another certificate")
	}
	return out, nil
}

func certEnvelope(kind stake.CertKind, raw []byte) ([]byte, error) {
	b, err := json.MarshalIndent(struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{certEnvelopeType, certDescriptions[kind], hex.EncodeToString(raw)}, "", "    ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeCertificate implements ports.CertificateDecoder. It decodes the
// CBOR with gouroboros, so the stake credential, the deposit, the pool and
// the DRep are read as fields, not by character offsets. The legacy
// registration and deregistration (types 0 and 1, which carry no deposit)
// are refused: the refund of a deregistration is the deposit in the
// certificate (SPO-08b-IN-002) and a legacy certificate has none.
//
// spec: SPO-06-IN-002, SPO-08b-IN-002, SPO-22b-IN-002
func (Ledger) DecodeCertificate(envelope []byte) (stake.Certificate, error) {
	var e struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(envelope, &e); err != nil || e.CborHex == "" {
		return stake.Certificate{}, errors.New("the file is not a text envelope with a cborHex")
	}
	if e.Type != certEnvelopeType {
		return stake.Certificate{}, fmt.Errorf("%w: the envelope type is %q, not %q", ErrUnsupportedCertificate, e.Type, certEnvelopeType)
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil {
		return stake.Certificate{}, errors.New("the certificate cborHex is not hex")
	}
	if c, ok, err := decodeGovCertificate(raw, envelope); ok {
		return c, err
	}
	var w common.CertificateWrapper
	if err := w.UnmarshalCBOR(raw); err != nil {
		return stake.Certificate{}, fmt.Errorf("%w: %v", ErrUnsupportedCertificate, err)
	}
	key := func(c common.Credential) (stake.KeyHash, error) {
		if c.CredType != common.CredentialTypeAddrKeyHash {
			return stake.KeyHash{}, fmt.Errorf("%w: the stake credential is a script hash, not a key", ErrUnsupportedCertificate)
		}
		return stake.KeyHash(c.Credential), nil
	}
	var spec stake.Spec
	switch c := w.Certificate.(type) {
	case *common.RegistrationCertificate:
		k, err := key(c.StakeCredential)
		if err != nil {
			return stake.Certificate{}, err
		}
		spec = stake.Spec{Kind: stake.CertRegistration, Stake: k, Deposit: chain.Lovelace(c.Amount)}
	case *common.DeregistrationCertificate:
		k, err := key(c.StakeCredential)
		if err != nil {
			return stake.Certificate{}, err
		}
		spec = stake.Spec{Kind: stake.CertDeregistration, Stake: k, Deposit: chain.Lovelace(c.Amount)}
	case *common.StakeDelegationCertificate:
		if c.StakeCredential == nil {
			return stake.Certificate{}, fmt.Errorf("%w: no stake credential", ErrUnsupportedCertificate)
		}
		k, err := key(*c.StakeCredential)
		if err != nil {
			return stake.Certificate{}, err
		}
		spec = stake.Spec{Kind: stake.CertPoolDelegation, Stake: k, Pool: chain.PoolID(c.PoolKeyHash)}
	case *common.VoteDelegationCertificate:
		k, err := key(c.StakeCredential)
		if err != nil {
			return stake.Certificate{}, err
		}
		spec = stake.Spec{Kind: stake.CertVoteDelegation, Stake: k}
		switch c.Drep.Type {
		case common.DrepTypeAddrKeyHash:
			spec.DRep = stake.DRep{Kind: stake.DRepKey}
			copy(spec.DRep.Hash[:], c.Drep.Credential)
		case common.DrepTypeScriptHash:
			spec.DRep = stake.DRep{Kind: stake.DRepScript}
			copy(spec.DRep.Hash[:], c.Drep.Credential)
		case common.DrepTypeAbstain:
			spec.DRep = stake.DRep{Kind: stake.DRepAbstain}
		case common.DrepTypeNoConfidence:
			spec.DRep = stake.DRep{Kind: stake.DRepNoConfidence}
		}
	case *common.StakeRegistrationCertificate, *common.StakeDeregistrationCertificate:
		return stake.Certificate{}, fmt.Errorf("%w: a pre-Conway registration or deregistration carries no deposit; make the certificate again", ErrUnsupportedCertificate)
	default:
		return stake.Certificate{}, fmt.Errorf("%w: certificate type %d", ErrUnsupportedCertificate, w.Type)
	}
	if err := spec.Validate(); err != nil {
		return stake.Certificate{}, err
	}
	return stake.Certificate{Spec: spec, CBOR: raw, Envelope: append([]byte(nil), envelope...)}, nil
}

var (
	_ ports.CertificateBuilder = Ledger{}
	_ ports.CertificateDecoder = Ledger{}
)
