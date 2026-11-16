package native

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// The DRep and committee certificates, as cardano-cli 11.2.3.0 `governance
// drep registration-certificate`, `update-certificate`, `retirement-certificate`
// and `governance committee create-hot-key-authorization-certificate`,
// `create-cold-key-resignation-certificate` write them. They are encoded by
// hand, as the stake certificates are in the Ledger methods:
//
//	registration  [16, credential, deposit, anchor / null]
//	retirement    [17, credential, deposit]
//	update        [18, credential, anchor / null]
//	authorisation [14, cold credential, hot credential]
//	resignation   [15, cold credential, anchor / null]
//
// A credential is [0, key hash]; only key credentials are issued.
var govCertDescriptions = map[stake.CertKind]string{
	stake.CertDRepRegistration:   "DRep Key Registration Certificate",
	stake.CertDRepUpdate:         "DRep Key Update Certificate",
	stake.CertDRepRetirement:     "DRep Key Retirement Certificate",
	stake.CertCommitteeAuthorize: "Constitutional Committee Hot Key Registration Certificate",
	stake.CertCommitteeResign:    "Constitutional Committee Cold Key Resignation Certificate",
}

const (
	certTagAuthHot    = 14
	certTagResignCold = 15
	certTagRegDRep    = 16
	certTagRetDRep    = 17
	certTagUpdDRep    = 18
)

// buildGovCertificate implements the governance kinds of BuildCertificate.
//
// spec: SPO-Pfiles-OUT-025, SPO-Pfiles-OUT-028, SPO-21b-EXT-005, SPO-21b-EXT-006, SPO-21b-INV-003, SPO-21d-EXT-002,
// spec: SPO-23c-EXT-003, SPO-23e-EXT-002
func buildGovCertificate(spec stake.Spec) (stake.Certificate, error) {
	anchor := func(b []byte) []byte { return gAnchor(b, spec.Anchor.URL, spec.Anchor.Hash, !spec.Anchor.IsZero()) }
	var raw []byte
	switch spec.Kind {
	case stake.CertDRepRegistration:
		raw = cborArray(raw, 4)
		raw = cborUint(raw, certTagRegDRep)
		raw = gCred(raw, false, spec.Stake[:])
		raw = cborUint(raw, uint64(spec.Deposit))
		raw = anchor(raw)
	case stake.CertDRepRetirement:
		raw = cborArray(raw, 3)
		raw = cborUint(raw, certTagRetDRep)
		raw = gCred(raw, false, spec.Stake[:])
		raw = cborUint(raw, uint64(spec.Deposit))
	case stake.CertDRepUpdate:
		raw = cborArray(raw, 3)
		raw = cborUint(raw, certTagUpdDRep)
		raw = gCred(raw, false, spec.Stake[:])
		raw = anchor(raw)
	case stake.CertCommitteeAuthorize:
		raw = cborArray(raw, 3)
		raw = cborUint(raw, certTagAuthHot)
		raw = gCred(raw, false, spec.Stake[:])
		raw = gCred(raw, false, spec.Hot[:])
	case stake.CertCommitteeResign:
		raw = cborArray(raw, 3)
		raw = cborUint(raw, certTagResignCold)
		raw = gCred(raw, false, spec.Stake[:])
		raw = anchor(raw)
	default:
		return stake.Certificate{}, fmt.Errorf("%w: kind %q is no governance certificate", ErrUnsupportedCertificate, spec.Kind)
	}
	env, err := certEnvelopeDesc(govCertDescriptions[spec.Kind], raw)
	if err != nil {
		return stake.Certificate{}, err
	}
	out := stake.Certificate{Spec: spec, CBOR: raw, Envelope: env}
	back, ok, err := decodeGovCertificate(raw, env)
	if err != nil || !ok || back.Spec != spec {
		return stake.Certificate{}, errors.New("the encoded certificate does not read back as the certificate it was made from")
	}
	return out, nil
}

// decodeGovCertificate reads a governance certificate; ok is false when the
// CBOR is another kind of certificate.
//
// spec: SPO-Pfiles-OUT-025, SPO-Pfiles-OUT-028
func decodeGovCertificate(raw, envelope []byte) (c stake.Certificate, ok bool, err error) {
	it, perr := gparseAll(raw)
	if perr != nil || it.major != 4 || len(it.arr) < 2 || it.arr[0].major != 0 {
		return stake.Certificate{}, false, nil
	}
	tag := it.arr[0].u
	if tag < certTagAuthHot || tag > certTagUpdDRep {
		return stake.Certificate{}, false, nil
	}
	bad := func(msg string) (stake.Certificate, bool, error) {
		return stake.Certificate{}, true, fmt.Errorf("%w: %s", ErrUnsupportedCertificate, msg)
	}
	cred := func(x gitem) (stake.KeyHash, bool, string) {
		if x.major != 4 || len(x.arr) != 2 || x.arr[0].major != 0 || x.arr[1].major != 2 || len(x.arr[1].b) != 28 {
			return stake.KeyHash{}, false, "a credential is not [type, 28-byte hash]"
		}
		if x.arr[0].u != 0 {
			return stake.KeyHash{}, false, "the credential is a script hash, not a key"
		}
		return stake.KeyHash(x.arr[1].b), true, ""
	}
	anchor := func(x gitem) (governance.Anchor, bool) {
		if x.isNull() {
			return governance.Anchor{}, true
		}
		if x.major != 4 || len(x.arr) != 2 || x.arr[0].major != 3 || x.arr[1].major != 2 || len(x.arr[1].b) != 32 {
			return governance.Anchor{}, false
		}
		a := governance.Anchor{URL: string(x.arr[0].b)}
		copy(a.Hash[:], x.arr[1].b)
		return a, true
	}
	var spec stake.Spec
	need := func(n int) bool { return len(it.arr) == n }
	switch tag {
	case certTagRegDRep:
		if !need(4) || it.arr[2].major != 0 {
			return bad("a DRep registration is [16, credential, deposit, anchor]")
		}
		k, kok, why := cred(it.arr[1])
		a, aok := anchor(it.arr[3])
		if !kok || !aok {
			return bad(orStr(why, "a malformed anchor"))
		}
		spec = stake.Spec{Kind: stake.CertDRepRegistration, Stake: k, Deposit: chain.Lovelace(it.arr[2].u), Anchor: a}
	case certTagRetDRep:
		if !need(3) || it.arr[2].major != 0 {
			return bad("a DRep retirement is [17, credential, deposit]")
		}
		k, kok, why := cred(it.arr[1])
		if !kok {
			return bad(why)
		}
		spec = stake.Spec{Kind: stake.CertDRepRetirement, Stake: k, Deposit: chain.Lovelace(it.arr[2].u)}
	case certTagUpdDRep:
		if !need(3) {
			return bad("a DRep update is [18, credential, anchor]")
		}
		k, kok, why := cred(it.arr[1])
		a, aok := anchor(it.arr[2])
		if !kok || !aok {
			return bad(orStr(why, "a malformed anchor"))
		}
		spec = stake.Spec{Kind: stake.CertDRepUpdate, Stake: k, Anchor: a}
	case certTagAuthHot:
		if !need(3) {
			return bad("a hot-key authorisation is [14, cold credential, hot credential]")
		}
		k, kok, why := cred(it.arr[1])
		h, hok, why2 := cred(it.arr[2])
		if !kok || !hok {
			return bad(orStr(why, why2))
		}
		spec = stake.Spec{Kind: stake.CertCommitteeAuthorize, Stake: k, Hot: h}
	case certTagResignCold:
		if !need(3) {
			return bad("a cold-key resignation is [15, cold credential, anchor]")
		}
		k, kok, why := cred(it.arr[1])
		a, aok := anchor(it.arr[2])
		if !kok || !aok {
			return bad(orStr(why, "a malformed anchor"))
		}
		spec = stake.Spec{Kind: stake.CertCommitteeResign, Stake: k, Anchor: a}
	}
	if err := spec.Validate(); err != nil {
		return stake.Certificate{}, true, err
	}
	return stake.Certificate{Spec: spec, CBOR: append([]byte(nil), raw...), Envelope: append([]byte(nil), envelope...)}, true, nil
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func certEnvelopeDesc(desc string, raw []byte) ([]byte, error) {
	return textEnvelope(certEnvelopeType, desc, hex.EncodeToString(raw), "    ")
}
