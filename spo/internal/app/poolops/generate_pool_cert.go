package poolops

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of GeneratePoolCertificate beyond those of domain/pool.
var (
	// ErrAdditionalMetadataCreated: extended metadata was asked for and the
	// operator had no `<pool>.additional-metadata.json`: a dummy was written
	// and the run stops, as the script's message says (SPO-05a-OUT-003). The
	// dummy is the only thing written.
	ErrAdditionalMetadataCreated = errors.New("<pool>.additional-metadata.json did not exist: a dummy was created; edit it and run again")
	// ErrITNUnsupported: ITN witness signing is not ported (SPO-05a-EXT-003).
	ErrITNUnsupported = errors.New("the pool has Incentivized Testnet keys (.itn.skey and .itn.vkey): signing the ITN witness is not ported; move the keys away or use the upstream script")
	// ErrDuplicateOwner: an owner is listed twice.
	ErrDuplicateOwner = errors.New("an owner is listed more than once in poolOwner")
)

// GeneratePoolCertificate turns the descriptor `<pool>.pool.json` into the
// published metadata, the pool id files and the registration certificate
// (upstream 05a_genStakepoolCert). It builds no transaction and talks to no
// chain service but the protocol parameters. Everything is written in one
// store transaction, after every check passed: a refusal writes nothing
// (upstream leaves the ids and a half-updated descriptor behind,
// SPO-05a-OUT-001).
type GeneratePoolCertificate struct {
	Store  ports.NamedStore
	Params ports.ProtocolParametersReader
	Certs  ports.PoolCertificateBuilder
	Hasher ports.PoolMetadataHasher
	Clock  ports.Clock
	// NetworkID goes into the reward account of the certificate.
	NetworkID uint8
	// Choices are the answers to the two prompts of 05a; both default to No.
	Choices pool.Choices
}

// GenerateRequest names the pool as typed and carries the optional
// registration protection key (SPO-05a-IF-002).
type GenerateRequest struct {
	Pool string
	// ProtectionKey is recorded in the descriptor for 05c and the offline
	// entry (SPO-05a-OUT-012). It is never sent to any service (hazard H6)
	// and never in a result or a log line (SPO-05a-SEC-001).
	ProtectionKey string
}

// GeneratedPool is what was made. It holds no key and no protection key.
type GeneratedPool struct {
	PoolID      chain.PoolID
	PoolIDHex   string
	PoolIDBech  string
	MetaHash    string // hex
	Certificate pool.Certificate
	// Corrections are the descriptor fields the checks rewrote.
	Corrections []pool.Correction
	Warnings    []string
	// Decisions records where the port departs from upstream.
	Decisions []string
}

// Run generates the certificate.
//
// spec: SPO-05a-IF-001, SPO-05a-IF-002, SPO-05a-IF-003, SPO-05a-IN-001, SPO-05a-IN-002, SPO-05a-IN-003, SPO-05a-IN-004,
// spec: SPO-05a-IN-005, SPO-05a-IN-006, SPO-05a-PRE-001, SPO-05a-PRE-002, SPO-05a-PRE-003, SPO-05a-PRE-004,
// spec: SPO-05a-PRE-012, SPO-05a-PRE-013, SPO-05a-EXT-002, SPO-05a-EXT-004, SPO-05a-EXT-005, SPO-05a-OUT-001,
// spec: SPO-05a-OUT-008, SPO-05a-OUT-009, SPO-05a-OUT-011, SPO-05a-OUT-012, SPO-05a-OUT-013, SPO-05a-INV-001,
// spec: SPO-05a-MODE-001, SPO-05a-SEC-001, SPO-05a-SEC-003, SPO-Pfiles-OUT-017, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019,
// spec: SPO-Pfiles-OUT-021
func (uc GeneratePoolCertificate) Run(ctx context.Context, req GenerateRequest) (GeneratedPool, error) {
	name, err := poolName(req.Pool)
	if err != nil {
		return GeneratedPool{}, err
	}
	params, err := uc.Params.ProtocolParameters(ctx)
	if err != nil {
		return GeneratedPool{}, fmt.Errorf("protocol parameters: %w", err)
	}
	// Protocol 12 and above (SPO-05a-INV-001): refuse before reading files,
	// the BLS key cannot be put into a certificate here.
	if params.ProtocolMajor >= 12 {
		return GeneratedPool{}, ErrBLSRequired
	}
	minCost, err := minPoolCost(params)
	if err != nil {
		return GeneratedPool{}, err
	}

	var (
		d                          *pool.Descriptor
		coldEnv, vrfEnv, rewardEnv []byte
		ownerKeys                  []stake.KeyHash
		additional                 []byte
		haveAdditional, itn        bool
	)
	reg := pool.Registration{}
	err = uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if d, err = readDescriptor(r, name); err != nil {
			return err
		}
		if err = d.CheckName(name); err != nil {
			return err
		}
		if err = d.Require(pool.FieldRewards); err != nil {
			return err
		}
		rewards := d.Text(pool.FieldRewards)
		if coldEnv, err = get(r, ports.NamedRef{Name: name, Kind: ports.NodeVKey}); err != nil {
			return err
		}
		if vrfEnv, err = get(r, ports.NamedRef{Name: name, Kind: ports.VrfVKey}); err != nil {
			return err
		}
		if rewardEnv, err = get(r, ports.NamedRef{Name: rewards, Kind: ports.StakingVKey}); err != nil {
			return err
		}
		if reg, err = d.Check(minCost, uc.Choices); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, o := range reg.Owners {
			if seen[o.Name] {
				return fmt.Errorf("%w: %s", ErrDuplicateOwner, o.Name)
			}
			seen[o.Name] = true
			env, err := get(r, ports.NamedRef{Name: o.Name, Kind: ports.StakingVKey})
			if err != nil {
				return err
			}
			_, h, err := keyOf(env)
			if err != nil {
				return fmt.Errorf("%s.staking.vkey: %w", o.Name, err)
			}
			ownerKeys = append(ownerKeys, stake.KeyHash(h))
		}
		s, e1 := r.Exists(ports.NamedRef{Name: name, Kind: ports.PoolItnSKey})
		v, e2 := r.Exists(ports.NamedRef{Name: name, Kind: ports.PoolItnVKey})
		if e1 != nil || e2 != nil {
			return errors.Join(e1, e2)
		}
		itn = s && v
		if reg.ExtendedURL != "" {
			a, err := r.Get(ports.NamedRef{Name: name, Kind: ports.PoolAdditionalMetadata})
			switch {
			case err == nil:
				additional, haveAdditional = a, true
			case errors.Is(err, ports.ErrNotFound):
			default:
				return err
			}
		}
		return nil
	})
	if err != nil {
		return GeneratedPool{}, err
	}
	if itn {
		return GeneratedPool{}, ErrITNUnsupported
	}

	coldRaw, _, err := keyOf(coldEnv)
	if err != nil {
		return GeneratedPool{}, fmt.Errorf("%s.node.vkey: %w", name, err)
	}
	poolID, err := chain.PoolIDOf(coldRaw)
	if err != nil {
		return GeneratedPool{}, err
	}
	idHex := hex.EncodeToString(poolID[:])
	idBech := poolID.Bech32()

	var extended []byte
	if reg.ExtendedURL != "" {
		if !haveAdditional {
			// The only artefact written: the operator edits it and runs again.
			if err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
				return w.Put(ports.NamedRef{Name: name, Kind: ports.PoolAdditionalMetadata}, pool.AdditionalMetadataTemplate(idHex))
			}); err != nil {
				return GeneratedPool{}, err
			}
			return GeneratedPool{}, ErrAdditionalMetadataCreated
		}
		if extended, err = pool.MergeExtended(additional); err != nil {
			return GeneratedPool{}, err
		}
		reg.Meta.Extended = reg.ExtendedURL
	}
	meta := reg.Meta.Render()
	if err := pool.CheckMetadataSize(meta); err != nil {
		return GeneratedPool{}, err
	}
	hash, err := uc.Hasher.MetadataHash(meta)
	if err != nil {
		return GeneratedPool{}, fmt.Errorf("metadata hash: %w", err)
	}

	vrfRaw, _, err := keyOf(vrfEnv)
	if err != nil {
		return GeneratedPool{}, fmt.Errorf("%s.vrf.vkey: %w", name, err)
	}
	_, rewardHash, err := keyOf(rewardEnv)
	if err != nil {
		return GeneratedPool{}, fmt.Errorf("%s.staking.vkey: %w", reg.Rewards, err)
	}
	cert, err := uc.Certs.BuildPoolRegistration(pool.RegistrationSpec{
		Operator: poolID, VrfKeyHash: pool.VrfHash(vrfRaw), Pledge: reg.Pledge, Cost: reg.Cost, Margin: reg.Margin,
		RewardAccount: stake.KeyHash(rewardHash), NetworkID: uc.NetworkID, Owners: ownerKeys, Relays: reg.Relays,
		MetaURL: reg.MetaURL, MetaHash: hash,
	})
	if err != nil {
		return GeneratedPool{}, err
	}

	d.Apply(reg.Corrections)
	d.NormalizeOwners(reg.Owners)
	d.RecordGeneration(idHex, idBech, hex.EncodeToString(hash[:]), rfc5322(uc.Clock.Now()), name+".pool.cert", req.ProtectionKey)

	if err := uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		puts := []struct {
			k ports.Kind
			b []byte
		}{
			{ports.PoolIDFile, []byte(idHex + "\n")},
			{ports.PoolIDBechFile, []byte(idBech + "\n")},
			{ports.PoolMetadata, meta},
			{ports.PoolCert, cert.Envelope},
			{ports.PoolDescriptor, d.Render()},
		}
		if extended != nil {
			puts = append(puts, struct {
				k ports.Kind
				b []byte
			}{ports.PoolExtendedMetadata, extended})
		}
		for _, p := range puts {
			if err := w.Put(ports.NamedRef{Name: name, Kind: p.k}, p.b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return GeneratedPool{}, err
	}
	out := GeneratedPool{PoolID: poolID, PoolIDHex: idHex, PoolIDBech: idBech, MetaHash: hex.EncodeToString(hash[:]),
		Certificate: cert, Corrections: reg.Corrections, Warnings: reg.Warnings}
	out.Decisions = append(out.Decisions,
		"the registration protection key is recorded in the descriptor and never sent to a service or shown (SPO-05c-SEC-002, SPO-05a-SEC-001, hazard H6)",
		"every artefact is written in one store transaction after all checks passed, where upstream persists the ids before the metadata checks (SPO-05a-OUT-001)",
		"a multi-owner re-run keeps regWitness, regEpoch and regSubmitted: the descriptor is edited, not rebuilt (SPO-05a-OUT-013)")
	return out, nil
}
