package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	dassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of CheckTokenMetadata.
var (
	// ErrNoRegistry: no registry reader is wired. In offline mode there is none
	// (SPO-12b-PRE-001: upstream refuses offline mode; light mode is allowed and
	// uses the registry only).
	ErrNoRegistry = errors.New("no token registry is reachable in this mode (offline mode has none)")
	// ErrNoSuchAsset: the argument is neither an asset record nor a subject
	// (SPO-12b-IF-002).
	ErrNoSuchAsset = errors.New("the argument is neither an asset record nor a subject of 56 to 120 hex digits")
	// ErrNoSubject: the record has no valid subject (SPO-12b-IN-001).
	ErrNoSubject = errors.New("the asset record has no valid subject; run the metadata generation first")
)

// CheckTokenMetadata looks up the registry entry of an asset on the registry
// server and compares it with the local record (upstream
// 12b_checkAssetMetaServer, with the checks its port notes ask for). It reads
// the store and the registry, and writes nothing.
type CheckTokenMetadata struct {
	Store    ports.Store
	Registry ports.TokenRegistryReader
	// Logos reads the file the record's metaLogoPNG names, to compare it with
	// the registry's logo; nil leaves the logo uncompared.
	Logos ports.LogoFileReader
}

// CheckRequest is the one argument of the command: `<policy>.<asset>` (a
// trailing `.asset` dropped) or a subject.
type CheckRequest struct{ Argument string }

// Status says where the submission stands.
type Status string

// The statuses (SPO-12b port notes: "published", "behind" or "not found").
const (
	// StatusNotFound: the registry has no entry for the subject.
	StatusNotFound Status = "not found"
	// StatusPublished: the registry serves the record's sequence number.
	StatusPublished Status = "published"
	// StatusBehind: the registry serves a lower number than the record's, so
	// the submission is not published yet.
	StatusBehind Status = "behind"
	// StatusAhead: the registry serves a higher number than the record's.
	StatusAhead Status = "ahead"
	// StatusUnlinked: the subject was given directly, or the record has no
	// submission yet (sequenceNumber 0), so there is nothing to compare with.
	StatusUnlinked Status = "not compared"
)

// PropertyCheck compares one property.
type PropertyCheck struct {
	Property tokenmeta.Property
	// Registry is the registry's value and sequence number; Present is false
	// when the entry has no such property (upstream shows it empty,
	// SPO-12b-OUT-001).
	Present  bool
	Value    tokenmeta.Value
	Sequence uint64
	// Local is the record's value ("" when it has none); Compared is false when
	// there is no record, or no way to read the local logo.
	Local    string
	Compared bool
	Match    bool
}

// Checked is the result.
type Checked struct {
	Subject string
	// Record is the record read, empty when the argument was a subject.
	Record string
	// RecordSequence is the record's sequenceNumber; HasRecord false for a
	// subject argument.
	RecordSequence uint64
	HasRecord      bool
	Registry       string
	Found          bool
	Entry          tokenmeta.Entry
	// RegistrySequence is the highest sequence number of the entry.
	RegistrySequence uint64
	Status           Status
	Verification     tokenmeta.Verification
	Properties       []PropertyCheck
	// Logo is the decoded logo of the entry (nil when it has none); LogoIsPNG
	// says whether it is a PNG within the registry's size limit. The caller
	// writes it to a file of its own, if it wants one (SPO-12b-OUT-002).
	Logo      []byte
	LogoIsPNG bool
}

var hexRE = func(s string) bool { return strings.Trim(s, "0123456789abcdefABCDEF") == "" }

// Run checks.
//
// spec: SPO-12b-IF-001, SPO-12b-IF-002, SPO-12b-IN-001, SPO-12b-PRE-001, SPO-12b-PRE-002, SPO-12b-EXT-001
// spec: SPO-12b-OUT-001, SPO-12b-OUT-002, SPO-12b-OUT-003, SPO-12b-INV-001, SPO-12b-MODE-001
func (uc CheckTokenMetadata) Run(ctx context.Context, req CheckRequest) (Checked, error) {
	if uc.Registry == nil {
		return Checked{}, ErrNoRegistry
	}
	if uc.Store == nil {
		return Checked{}, fmt.Errorf("%w: a store is needed", ErrMisconfigured)
	}
	arg := strings.TrimSpace(req.Argument)
	if arg == "" {
		return Checked{}, ErrNoSuchAsset
	}
	// The record is tried first; only when there is none is the argument a
	// subject (SPO-12b-IF-002).
	var res Checked
	var rec dassets.Record
	if ref, err := dassets.ParseRef(arg); err == nil {
		name := ports.Ref{Name: dassets.RecordName(ref.Policy, ref.Asset), Kind: ports.AssetFile}
		var b []byte
		var found bool
		if name.Validate() == nil {
			if err := uc.Store.View(ctx, func(r ports.Reader) error {
				v, err := r.Get(name)
				switch {
				case err == nil:
					b, found = v, true
				case errors.Is(err, ports.ErrNotFound):
					return nil
				}
				return err
			}); err != nil {
				return Checked{}, err
			}
		}
		if found {
			if rec, err = dassets.ParseRecord(b); err != nil {
				return Checked{}, fmt.Errorf("%s: %w", name, err)
			}
			res.Record, res.HasRecord = name.Name, true
			res.Subject = rec.Get("subject")
			if tokenmeta.CheckSubject(res.Subject) != nil {
				return Checked{}, fmt.Errorf("%w: %s", ErrNoSubject, name)
			}
			res.Subject = strings.ToLower(res.Subject)
			if s := rec.Get("sequenceNumber"); s != "" {
				n, err := strconv.ParseUint(s, 10, 63)
				if err != nil {
					return Checked{}, fmt.Errorf("%w: %q", ErrBadSequence, s)
				}
				res.RecordSequence = n
			}
		}
	}
	if !res.HasRecord {
		if tokenmeta.CheckSubject(arg) != nil || !hexRE(arg) {
			return Checked{}, fmt.Errorf("%w: %q", ErrNoSuchAsset, arg)
		}
		res.Subject = strings.ToLower(arg)
	}
	res.Registry = uc.Registry.Registry()

	entry, err := uc.Registry.TokenMetadata(ctx, res.Subject)
	switch {
	case errors.Is(err, ports.ErrTokenNotFound):
		res.Status = StatusNotFound
		return res, nil
	case err != nil:
		return Checked{}, err
	}
	if !strings.EqualFold(entry.Subject, res.Subject) {
		return Checked{}, fmt.Errorf("%w: the answer is for subject %s", ports.ErrRegistryAnswer, entry.Subject)
	}
	res.Found, res.Entry = true, entry
	res.RegistrySequence, _ = entry.Sequence()
	res.Verification = entry.Verify()

	switch {
	case !res.HasRecord || res.RecordSequence == 0:
		res.Status = StatusUnlinked
	case res.RegistrySequence == res.RecordSequence:
		res.Status = StatusPublished
	case res.RegistrySequence < res.RecordSequence:
		res.Status = StatusBehind
	default:
		res.Status = StatusAhead
	}

	localKey := map[tokenmeta.Property]string{
		tokenmeta.PropName: "metaName", tokenmeta.PropDescription: "metaDescription", tokenmeta.PropTicker: "metaTicker",
		tokenmeta.PropURL: "metaUrl", tokenmeta.PropDecimals: "metaDecimals", tokenmeta.PropLogo: "metaLogoPNG",
	}
	for _, p := range []tokenmeta.Property{tokenmeta.PropName, tokenmeta.PropDescription, tokenmeta.PropTicker, tokenmeta.PropURL, tokenmeta.PropDecimals, tokenmeta.PropLogo} {
		pc := PropertyCheck{Property: p}
		a, ok := entry.Props[p]
		if ok {
			pc.Present, pc.Value, pc.Sequence = true, a.Value, a.Sequence
		}
		if res.HasRecord {
			pc.Local = rec.Get(localKey[p])
			switch p {
			case tokenmeta.PropLogo:
				if uc.Logos != nil && pc.Local != "" && ok {
					if png, err := uc.Logos.ReadLogoFile(pc.Local); err == nil {
						pc.Compared, pc.Match = true, bytes.Equal(png, a.Value.Bytes())
					}
				} else if pc.Local == "" {
					pc.Compared, pc.Match = true, !ok
				}
			default:
				pc.Compared = true
				pc.Match = (!ok && pc.Local == "") || (ok && a.Value.String() == pc.Local)
			}
		}
		res.Properties = append(res.Properties, pc)
	}
	if a, ok := entry.Props[tokenmeta.PropLogo]; ok {
		res.Logo = a.Value.Bytes()
		res.LogoIsPNG = tokenmeta.CheckLogo(res.Logo) == nil
	}
	return res, nil
}
