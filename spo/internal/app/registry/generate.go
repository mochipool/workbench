package registry

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/app/assets"
	dassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the registry use cases.
var (
	// ErrMisconfigured: the composition lacks a port (a programming error).
	ErrMisconfigured = errors.New("the registry use case is not wired correctly")
	// ErrPolicyFiles: a policy artefact is missing (SPO-12a-IN-002).
	ErrPolicyFiles = errors.New("the policy is incomplete")
	// ErrNoSigner: the signer for the policy key cannot sign a registry entry.
	ErrNoSigner = errors.New("the signer for the policy key cannot sign a token-registry entry")
	// ErrBadSequence: the record's sequenceNumber is not a decimal number.
	ErrBadSequence = errors.New("the asset record's sequenceNumber is not a whole decimal number")
	// ErrNoLogoSource: the record names a logo file and no reader is wired.
	ErrNoLogoSource = errors.New("the asset record names a logo file, and no file reader is wired")
	// ErrLogoFile: the logo file cannot be read (SPO-12a-PRE-006).
	ErrLogoFile = errors.New("the logo file cannot be read")
)

// GenerateTokenMetadata builds the CIP-26 registry entry of an asset, signs it
// with the policy key and stores it as `<subject>.json` (upstream
// 12a_genAssetMeta, with `token-metadata-creator` replaced by
// domain/tokenmeta).
//
// The record `<policy>.<asset>.asset` is the input, as upstream has it: the
// operator edits its `meta*` fields and runs again. The first run only creates
// the record. A hardware policy is refused by the signing plan before the
// store is read or written (SPO-12a-IN-002); a policy whose key a registry
// signer holds is signed in the signer.
type GenerateTokenMetadata struct {
	Store   ports.Store
	Signers ports.SignerDirectory
	Clock   ports.Clock
	// Logos reads the file `metaLogoPNG` names; nil refuses a record that
	// names one.
	Logos ports.LogoFileReader
}

// GenerateRequest names the asset: `<policy>.<asset>`, a trailing `.asset`
// dropped (SPO-12a-IF-001).
type GenerateRequest struct {
	Asset string
}

// Generated is the result. Nothing in it is secret.
type Generated struct {
	// Created: the record did not exist, it was created and nothing else was
	// done (SPO-12a-OUT-001). The operator fills in the meta fields and runs
	// again.
	Created bool
	Record  ports.Ref
	Subject string
	// Sequence is the sequence number of the new entry (the record's number
	// plus one); zero when Created.
	Sequence uint64
	Entry    tokenmeta.Entry
	// File is the stored submission file; the zero Ref when Created.
	File ports.Ref
}

// recordFields lists the keys of the record in the order a first run writes
// them (SPO-12a-OUT-001), with the values that do not depend on the asset.
func firstRun(id chain.AssetID, name dassets.Name, validBefore string, now time.Time) dassets.Record {
	r, _ := dassets.ParseRecord(nil)
	display := dassets.DisplayName(id.Name)
	if utf8.RuneCountInString(display) > tokenmeta.MaxName {
		display = string([]rune(display)[:tokenmeta.MaxName])
	}
	hexName := ""
	if name.HexTyped {
		hexName = hex.EncodeToString(id.Name)
	}
	for _, kv := range [][2]string{
		{"metaName", display}, {"metaDescription", ""}, {"metaDecimals", ""}, {"metaTicker", ""},
		{"metaUrl", ""}, {"metaLogoPNG", ""},
		{"---", "--- Optional additional info ---"}, {"===", "--- DO NOT EDIT BELOW THIS LINE !!! ---"},
		{"minted", "0"}, {"name", display}, {"hexname", hexName},
		{"bechName", dassets.Fingerprint(id)},
		{"policyID", hex.EncodeToString(id.Policy[:])}, {"policyValidBeforeSlot", validBefore},
		{"subject", dassets.Subject(id)}, {"sequenceNumber", "0"},
		{"lastUpdate", now.Format(time.RFC1123Z)}, {"lastAction", "created Asset-File"},
	} {
		r.Set(kv[0], kv[1])
	}
	return r
}

// normalise merges the record over the skeleton of SPO-12a-OUT-002: a key the
// record has wins and keeps its place, a missing key is added with the
// skeleton's value.
func normalise(r dassets.Record, id chain.AssetID, now time.Time) dassets.Record {
	have := map[string]bool{}
	for _, k := range r.Keys() {
		have[k] = true
	}
	for _, kv := range [][2]string{
		{"metaName", hex.EncodeToString(id.Name)}, {"metaDescription", ""}, {"metaDecimals", "0"},
		{"metaTicker", ""}, {"metaUrl", ""}, {"metaLogoPNG", ""}, {"minted", "0"},
		{"name", dassets.DisplayName(id.Name)}, {"hexname", ""}, {"bechName", dassets.Fingerprint(id)},
		{"policyID", hex.EncodeToString(id.Policy[:])}, {"policyValidBeforeSlot", ""},
		{"subject", dassets.Subject(id)}, {"sequenceNumber", "0"},
		{"lastUpdate", now.Format(time.RFC1123Z)}, {"lastAction", "update Asset-File"},
	} {
		if !have[kv[0]] {
			r.Set(kv[0], kv[1])
		}
	}
	return r
}

// Run generates the entry.
//
// Decisions: upstream locks the record before the fields are validated, so a
// mistake leaves a locked file the operator must unlock; here nothing is
// written until the entry is built and signed, and the record and the
// submission file are written together (SPO-12a-OUT-002, SPO-12a-OUT-003). The
// unused TTL query of SPO-12a-IN-004 is not made.
//
// spec: SPO-12a-IF-001, SPO-12a-IF-002, SPO-12a-IN-002, SPO-12a-IN-003, SPO-12a-IN-004, SPO-12a-OUT-001, SPO-12a-OUT-002
// spec: SPO-12a-OUT-003, SPO-12a-OUT-004, SPO-12a-INV-001, SPO-12a-INV-002, SPO-12a-SEC-001, SPO-12a-SEC-002
func (uc GenerateTokenMetadata) Run(ctx context.Context, req GenerateRequest) (Generated, error) {
	if uc.Store == nil || uc.Signers == nil || uc.Clock == nil {
		return Generated{}, fmt.Errorf("%w: a store, a signer directory and a clock are needed", ErrMisconfigured)
	}
	ref, err := dassets.ParseRef(req.Asset)
	if err != nil {
		return Generated{}, err
	}
	name, err := dassets.ParseName(ref.Asset)
	if err != nil {
		return Generated{}, err
	}
	policyName, err := assets.PolicyName(ref.Policy)
	if err != nil {
		return Generated{}, err
	}
	recRef := ports.Ref{Name: dassets.RecordName(ref.Policy, ref.Asset), Kind: ports.AssetFile}

	var script []byte
	var idHex string
	var recBytes []byte
	var haveRec, hws bool
	if err := uc.Store.View(ctx, func(r ports.Reader) error {
		// The hardware file is looked at before the signing key (SPO-12a-IN-002).
		var err error
		if hws, err = r.Exists(ports.Ref{Name: policyName, Kind: ports.PolicyHwsFile}); err != nil {
			return err
		}
		get := func(k ports.Kind) ([]byte, error) {
			v, err := r.Get(ports.Ref{Name: policyName, Kind: k})
			if errors.Is(err, ports.ErrNotFound) {
				return nil, fmt.Errorf("%w: %s.%s is missing", ErrPolicyFiles, policyName, k)
			}
			return v, err
		}
		id, err := get(ports.PolicyID)
		if err != nil {
			return err
		}
		idHex = strings.TrimSpace(string(id))
		if script, err = get(ports.PolicyScript); err != nil {
			return err
		}
		if !hws {
			ok, err := r.Exists(ports.Ref{Name: policyName, Kind: ports.PolicySKey})
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: %s.policy.skey is missing", ErrPolicyFiles, policyName)
			}
		}
		recBytes, err = r.Get(recRef)
		switch {
		case err == nil:
			haveRec = true
		case errors.Is(err, ports.ErrNotFound):
			err = nil
		}
		return err
	}); err != nil {
		return Generated{}, err
	}

	// The holder is the device when a hardware file exists (SPO-Pfiles-INV-002).
	holder := custody.HolderVault
	if hws {
		holder = custody.HolderHardware
	}
	keyRef := custody.KeyRef{Role: custody.RolePolicy, Holder: holder, Owner: policyName}
	if _, err := ports.PlanSignatures(uc.Signers, []custody.Slot{{
		Label: "sign the token-registry entry", Key: keyRef,
		Demand: custody.Demand{Role: custody.RolePolicy, Operation: custody.OpSignRegistryEntry},
	}}); err != nil {
		return Generated{}, err
	}

	var asset chain.AssetID
	pid, err := hex.DecodeString(idHex)
	if err != nil || len(pid) != 28 {
		return Generated{}, fmt.Errorf("%w: %s.policy.id is not a 56-digit policy id", ErrPolicyFiles, policyName)
	}
	copy(asset.Policy[:], pid)
	asset.Name = name.Bytes
	now := uc.Clock.Now()

	// First run: create the record and stop (SPO-12a-OUT-001).
	if !haveRec {
		validBefore := dassets.ValidBefore(dassets.Expiry(script))
		rec := firstRun(asset, name, validBefore, now)
		if err := uc.Store.Update(ctx, func(w ports.Writer) error {
			if ok, err := w.Exists(recRef); err != nil || ok {
				if err == nil {
					err = ports.ErrConflict
				}
				return err
			}
			return w.Put(recRef, rec.Marshal())
		}); err != nil {
			return Generated{}, err
		}
		return Generated{Created: true, Record: recRef, Subject: dassets.Subject(asset)}, nil
	}

	rec, err := dassets.ParseRecord(recBytes)
	if err != nil {
		return Generated{}, fmt.Errorf("%s: %w", recRef, err)
	}
	rec = normalise(rec, asset, now)

	// The subject and the sequence number are the record's (SPO-12a-INV-001).
	subject := rec.Get("subject")
	if err := tokenmeta.CheckSubject(subject); err != nil {
		return Generated{}, fmt.Errorf("%s: the record's subject: %w", recRef, err)
	}
	seqText := rec.Get("sequenceNumber")
	if seqText == "" || strings.Trim(seqText, "0123456789") != "" {
		return Generated{}, fmt.Errorf("%w: %q", ErrBadSequence, seqText)
	}
	prev, err := strconv.ParseUint(seqText, 10, 63)
	if err != nil {
		return Generated{}, fmt.Errorf("%w: %q", ErrBadSequence, seqText)
	}
	seq := prev + 1

	f := tokenmeta.Fields{
		Name: rec.Get("metaName"), Description: rec.Get("metaDescription"),
		Ticker: rec.Get("metaTicker"), URL: rec.Get("metaUrl"), Decimals: rec.Get("metaDecimals"),
	}
	if path := rec.Get("metaLogoPNG"); path != "" {
		if uc.Logos == nil {
			return Generated{}, ErrNoLogoSource
		}
		png, err := uc.Logos.ReadLogoFile(path)
		if err != nil {
			return Generated{}, fmt.Errorf("%w: %v", ErrLogoFile, err)
		}
		f.Logo = png
	}
	if err := f.Validate(); err != nil {
		return Generated{}, err
	}

	sg, err := uc.Signers.SignerFor(keyRef)
	if err != nil {
		return Generated{}, err
	}
	signer, ok := sg.(ports.RegistrySigner)
	if !ok {
		return Generated{}, ErrNoSigner
	}
	key, err := custody.As[custody.Policy](keyRef)
	if err != nil {
		return Generated{}, err
	}
	entry, err := tokenmeta.Build(ctx, subject, script, f, seq, func(ctx context.Context, msgs [][32]byte) ([]tokenmeta.Attestation, error) {
		got, err := signer.SignRegistryMessages(ctx, key, msgs)
		if err != nil {
			return nil, fmt.Errorf("sign the registry entry: %w", err)
		}
		out := make([]tokenmeta.Attestation, len(got))
		for i, a := range got {
			out[i] = tokenmeta.Attestation{PublicKey: a.PublicKey, Signature: a.Signature}
		}
		return out, nil
	})
	if err != nil {
		return Generated{}, err
	}

	rec.Set("sequenceNumber", strconv.FormatUint(seq, 10))
	rec.Set("lastUpdate", now.Format(time.RFC1123Z))
	rec.Set("lastAction", "created Token-Registry-JSON")
	file := ports.Ref{Name: subject, Kind: ports.TokenRegistration}
	if err := uc.Store.Update(ctx, func(w ports.Writer) error {
		if err := w.Put(recRef, rec.Marshal()); err != nil {
			return err
		}
		return w.Put(file, entry.JSON())
	}); err != nil {
		return Generated{}, err
	}
	return Generated{Record: recRef, Subject: subject, Sequence: seq, Entry: entry, File: file}, nil
}
