package stake

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// CertificateGenerated is the result of a certificate use case. The file
// content is the text envelope cardano-cli writes.
type CertificateGenerated struct {
	Name        string // the wallet the certificate is stored under
	Ref         ports.Ref
	Certificate stk.Certificate
}

// MinConwayMajor is the protocol major version from which the Conway
// certificates exist.
const MinConwayMajor = 9

// GenerateDelegationCertificate makes the certificate that delegates a stake
// key to a pool (upstream 05b). It never touches the chain: it does not check
// that the pool or the stake address is registered (SPO-05b-INV-001).
type GenerateDelegationCertificate struct {
	Store ports.Store
	Certs ports.CertificateBuilder
}

// DelegationRequest names the pool as the operator typed it (a hex or bech32
// pool id, or the name of a local pool whose `<pool>.node.vkey` is stored) and
// the delegator stake account.
type DelegationRequest struct {
	Pool      string
	Delegator string
}

// Run reads the stake and pool keys, builds the certificate and stores it as
// `<delegator>.deleg.cert`, replacing any earlier one (SPO-05b-OUT-001).
//
// spec: SPO-05b-IF-001, SPO-05b-IF-002, SPO-05b-IF-003, SPO-05b-IN-001, SPO-05b-IN-002, SPO-05b-PRE-001,
// spec: SPO-05b-EXT-001, SPO-05b-OUT-001, SPO-Pfiles-OUT-007
func (uc GenerateDelegationCertificate) Run(ctx context.Context, req DelegationRequest) (CertificateGenerated, error) {
	if req.Pool == "" || req.Delegator == "" {
		return CertificateGenerated{}, errors.New("a delegation certificate needs a pool and a delegator")
	}
	name, err := walletName(req.Delegator)
	if err != nil {
		return CertificateGenerated{}, fmt.Errorf("delegator: %w", err)
	}
	word, err := stk.ParsePoolWord(req.Pool)
	if err != nil {
		return CertificateGenerated{}, err
	}
	var spec stk.Spec
	err = uc.Store.View(ctx, func(r ports.Reader) error {
		vk, err := get(r, ports.Ref{Name: name, Kind: ports.StakingVKey})
		if err != nil {
			return err
		}
		h, err := vkeyHash(vk)
		if err != nil {
			return fmt.Errorf("%s.staking.vkey: %w", name, err)
		}
		spec = stk.Spec{Kind: stk.CertPoolDelegation, Stake: stk.KeyHash(h)}
		if word.IsID {
			spec.Pool = word.Pool
			return nil
		}
		cold, err := get(r, ports.Ref{Name: word.Name, Kind: ports.NodeVKey})
		if err != nil {
			return fmt.Errorf("the pool word %q is neither a pool id nor a stored pool: %w", req.Pool, err)
		}
		env, err := pool.ParseEnvelope(cold)
		if err != nil {
			return err
		}
		raw, err := env.Key32()
		if err != nil {
			return err
		}
		spec.Pool, err = chain.PoolIDOf(raw)
		return err
	})
	if err != nil {
		return CertificateGenerated{}, err
	}
	return store(ctx, uc.Store, uc.Certs, spec, ports.Ref{Name: name, Kind: ports.DelegCert})
}

// store builds a certificate and writes its envelope under ref in one update.
func store(ctx context.Context, st ports.Store, b ports.CertificateBuilder, spec stk.Spec, ref ports.Ref) (CertificateGenerated, error) {
	cert, err := b.BuildCertificate(spec)
	if err != nil {
		return CertificateGenerated{}, err
	}
	if err := st.Update(ctx, func(w ports.Writer) error { return w.Put(ref, cert.Envelope) }); err != nil {
		return CertificateGenerated{}, fmt.Errorf("store %s: %w", ref, err)
	}
	return CertificateGenerated{Name: ref.Name, Ref: ref, Certificate: cert}, nil
}

// GenerateVoteDelegationCertificate makes the certificate that delegates the
// votes of a stake key to a DRep, always-abstain or always-no-confidence
// (upstream 22a). It does not check that the DRep is registered.
type GenerateVoteDelegationCertificate struct {
	Store ports.Store
	Certs ports.CertificateBuilder
	// Params gives the era gate (SPO-22a-PRE-001). Nil skips it.
	Params ports.ProtocolParametersReader
}

// VoteDelegationRequest names the target word as typed (SPO-22a-IF-002) and
// the delegator stake account.
type VoteDelegationRequest struct {
	Target    string
	Delegator string
}

// Run classifies the target, builds the certificate and stores it as
// `<delegator>.vote-deleg.cert`.
//
// A pre-Conway era is refused with an error, where upstream exits 0 and
// creates nothing (SPO-22a-PRE-001).
//
// spec: SPO-22a-IF-001, SPO-22a-IF-002, SPO-22a-IN-001, SPO-22a-IN-002, SPO-22a-PRE-001, SPO-22a-PRE-002,
// spec: SPO-22a-EXT-001, SPO-22a-EXT-002, SPO-22a-EXT-003, SPO-22a-EXT-004, SPO-22a-EXT-005,
// spec: SPO-22a-OUT-001, SPO-Pfiles-OUT-008
func (uc GenerateVoteDelegationCertificate) Run(ctx context.Context, req VoteDelegationRequest) (CertificateGenerated, error) {
	if req.Target == "" || req.Delegator == "" {
		return CertificateGenerated{}, errors.New("a vote delegation certificate needs a target and a delegator")
	}
	name, err := walletName(req.Delegator)
	if err != nil {
		return CertificateGenerated{}, fmt.Errorf("delegator: %w", err)
	}
	word, err := stk.ParseDRepWord(req.Target)
	if err != nil {
		return CertificateGenerated{}, err
	}
	if uc.Params != nil {
		p, err := uc.Params.ProtocolParameters(ctx)
		if err != nil {
			return CertificateGenerated{}, fmt.Errorf("protocol parameters: %w", err)
		}
		if p.ProtocolMajor < MinConwayMajor {
			return CertificateGenerated{}, ErrProtocolTooOld
		}
	}
	var spec stk.Spec
	err = uc.Store.View(ctx, func(r ports.Reader) error {
		vk, err := get(r, ports.Ref{Name: name, Kind: ports.StakingVKey})
		if err != nil {
			return err
		}
		h, err := vkeyHash(vk)
		if err != nil {
			return fmt.Errorf("%s.staking.vkey: %w", name, err)
		}
		spec = stk.Spec{Kind: stk.CertVoteDelegation, Stake: stk.KeyHash(h)}
		if word.IsID {
			spec.DRep = word.DRep
			return nil
		}
		// A local DRep wins over the keywords (SPO-22a-IF-002, form 5).
		if word.Name != "" {
			dk, err := r.Get(ports.Ref{Name: word.Name, Kind: ports.DRepVKey})
			if err == nil {
				dh, err := vkeyHash(dk)
				if err != nil {
					return fmt.Errorf("%s.drep.vkey: %w", word.Name, err)
				}
				spec.DRep = stk.DRep{Kind: stk.DRepKey, Hash: dh}
				return nil
			}
			if !errors.Is(err, ports.ErrNotFound) {
				return err
			}
		}
		if word.Keyword == "" {
			return fmt.Errorf("%w: %q is not a DRep id, a stored DRep (%s.drep.vkey), always-abstain or always-no-confidence", ErrBadWord, req.Target, word.Name)
		}
		spec.DRep = stk.DRep{Kind: word.Keyword}
		return nil
	})
	if err != nil {
		return CertificateGenerated{}, err
	}
	return store(ctx, uc.Store, uc.Certs, spec, ports.Ref{Name: name, Kind: ports.VoteDelegCert})
}

// GenerateDeregistrationCertificate makes the certificate that retires a
// stake address (upstream 08a). The account must be registered on chain,
// hold no rewards and have no open governance-action deposit, and the
// certificate carries the key deposit the chain holds for it, so the refund
// of 08b matches (SPO-08a-EXT-002).
type GenerateDeregistrationCertificate struct {
	Store     ports.Store
	Addresses ports.AddressInspector
	Certs     ports.CertificateBuilder
	// Account is where the account state comes from: the node, Koios or the
	// offline snapshot. CrossCheck is an optional second independent source.
	Account    ports.RewardAccountReader
	CrossCheck ports.RewardAccountReader
	// Sources decides what happens when only one source answers.
	Sources   SourcePolicy
	NetworkID uint8
}

// DeregistrationCertificateResult adds what the operator is told.
type DeregistrationCertificateResult struct {
	CertificateGenerated
	Sources      []chain.Source
	SingleSource bool
}

// Run reads the account, checks it can be retired and stores
// `<name>.staking.dereg-cert`. Nothing is written when a check fails.
//
// Both refusals of an account with rewards and governance deposits are
// reported together (SPO-08a-PRE-005). The deposit comes from the chain
// state, never from the protocol parameters, and an unknown deposit is
// refused instead of defaulted to 2000000 (SPO-Clight-OUT-011).
//
// spec: SPO-08a-IF-001, SPO-08a-IN-001, SPO-08a-IN-002, SPO-08a-PRE-001, SPO-08a-PRE-002, SPO-08a-PRE-003,
// spec: SPO-08a-PRE-004, SPO-08a-PRE-005, SPO-08a-EXT-001, SPO-08a-EXT-002, SPO-08a-OUT-001, SPO-08a-MODE-001, SPO-Pfiles-OUT-009
func (uc GenerateDeregistrationCertificate) Run(ctx context.Context, name string) (DeregistrationCertificateResult, error) {
	if name == "" {
		return DeregistrationCertificateResult{}, errors.New("a deregistration certificate needs the stake account name")
	}
	w, err := walletName(name)
	if err != nil {
		return DeregistrationCertificateResult{}, err
	}
	var addr chain.StakeAddress
	err = uc.Store.View(ctx, func(r ports.Reader) error {
		b, err := get(r, ports.Ref{Name: w, Kind: ports.StakingAddr})
		if err != nil {
			return err
		}
		addr = chain.StakeAddress(firstLine(b))
		return nil
	})
	if err != nil {
		return DeregistrationCertificateResult{}, err
	}
	base := Base{Addresses: uc.Addresses, NetworkID: uc.NetworkID}
	key, err := base.checkStakeAddress(addr)
	if err != nil {
		return DeregistrationCertificateResult{}, err
	}
	ans, err := accountReads{Primary: uc.Account, CrossCheck: uc.CrossCheck, Policy: uc.Sources}.read(ctx, addr, true)
	if err != nil {
		return DeregistrationCertificateResult{}, err
	}
	deposit, err := refundOf(ans)
	if err != nil {
		return DeregistrationCertificateResult{}, err
	}
	spec := stk.Spec{Kind: stk.CertDeregistration, Stake: key, Deposit: deposit}
	if _, err := ans.Account.Apply(spec); err != nil {
		return DeregistrationCertificateResult{}, err
	}
	gen, err := store(ctx, uc.Store, uc.Certs, spec, ports.Ref{Name: w, Kind: ports.StakingDeregCert})
	if err != nil {
		return DeregistrationCertificateResult{}, err
	}
	return DeregistrationCertificateResult{CertificateGenerated: gen, Sources: ans.Sources, SingleSource: ans.Single}, nil
}

// refundOf checks that the account state a deregistration rests on is
// complete: the deposit and the governance deposits are stated, not guessed.
func refundOf(ans accountAnswer) (chain.Lovelace, error) {
	if ans.Account.State == stk.Unregistered {
		return 0, stk.ErrNotRegistered
	}
	if !ans.Known.Deposit {
		return 0, fmt.Errorf("%w: the source did not state the key deposit of the stake address", stk.ErrUnknown)
	}
	if !ans.Known.Gov {
		return 0, fmt.Errorf("%w: the source did not state the governance-action deposits of the stake address", stk.ErrUnknown)
	}
	return ans.Account.Deposit, nil
}
