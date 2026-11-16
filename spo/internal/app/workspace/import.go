package workspace

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ImportWorkspace reads an upstream script directory and writes what it
// recognises into the destination store, sealing every secret on the way.
//
// The source is only read: nothing in it is modified, locked or deleted. The
// destination is written once per owner (a pool or a wallet) in one atomic
// Update, so a failed owner leaves no trace and a good one is complete.
//
// Decision (E9): keys that upstream encrypted are decrypted with the
// operator's password and sealed like any other key. The password is tried
// as typed and as upstream's prompt would have stored it (keyfile.UpstreamRead).
// With no password, an owner holding an encrypted key fails with
// ErrPasswordRequired, unless KeepEncrypted is set: then the key is stored
// still gpg-wrapped as an opaque UpstreamEncryptedSKey record that no signer
// reads, and a later import or export can open it. Decrypt-and-seal is the
// recommended path: a kept key is protected only by its password and cannot
// sign.
type ImportWorkspace struct {
	// Source, SourceVault and Lister read the upstream directory
	// (fsstore.Store implements all three).
	Source      ports.Store
	SourceVault ports.Vault
	Lister      ports.SourceLister
	// Dest is the sealed store.
	Dest ports.Store
	// Decryptor opens upstream-encrypted keys (the gpg adapter). May be nil
	// when the directory has none.
	Decryptor ports.KeyDecryptor
	// Deriver and Addresses enable the consistency checks (native
	// adapters). When nil the checks are skipped and the report says so.
	Deriver   ports.VerificationKeyDeriver
	Addresses ports.AddressInspector
}

// ImportOptions selects and shapes an import.
type ImportOptions struct {
	// Owners names the pools and wallets to import; empty means everything
	// found.
	Owners []string
	// Password opens upstream-encrypted keys. The caller owns and destroys it.
	Password *ports.Secret
	// KeepEncrypted imports an encrypted key as it is when there is no
	// Password.
	KeepEncrypted bool
	// Overwrite replaces artefacts the destination already holds. Without it
	// an owner with any artefact already in the destination is not imported.
	Overwrite bool
}

type planned struct {
	dst  ports.Ref
	data []byte
	sec  *ports.Secret
}

// Run imports. It returns an error only when nothing could be attempted
// (listing failed, an owner asked for does not exist, the context ended); a
// failed owner is in the report.
//
// spec: SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-003, SPO-Pfiles-OUT-004, SPO-Pfiles-OUT-005, SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009
// spec: SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-012, SPO-Pfiles-OUT-013, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-015, SPO-Pfiles-OUT-016, SPO-Pfiles-OUT-017, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019, SPO-Pfiles-OUT-020
// spec: SPO-Pfiles-OUT-021, SPO-Pfiles-OUT-022, SPO-Pfiles-OUT-023, SPO-Pfiles-OUT-024, SPO-Pfiles-OUT-025, SPO-Pfiles-OUT-026, SPO-Pfiles-OUT-027, SPO-Pfiles-OUT-028, SPO-Pfiles-OUT-029, SPO-Pfiles-OUT-030
// spec: SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032, SPO-Pfiles-OUT-033, SPO-Pfiles-OUT-034, SPO-Pfiles-OUT-035, SPO-Pfiles-OUT-036, SPO-Pfiles-SEC-001, SPO-Pfiles-IN-003
// spec: SPO-Ckey-IN-001, SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-007, SPO-Ckey-PRE-010, SPO-Ckey-OUT-003, SPO-Ckey-PR-002, SPO-Ckey-PR-003, SPO-Ckey-EXT-002, SPO-Ckey-OUT-002
func (u ImportWorkspace) Run(ctx context.Context, opts ImportOptions) (*Report, error) {
	listing, err := u.Lister.List(ctx)
	if err != nil {
		return nil, err
	}
	byOwner := map[string][]ports.Ref{}
	for _, e := range listing.Entries {
		o := OwnerOf(e.Ref)
		byOwner[o] = append(byOwner[o], e.Ref)
	}
	owners := make([]string, 0, len(byOwner))
	if len(opts.Owners) == 0 {
		for o := range byOwner {
			owners = append(owners, o)
		}
	} else {
		for _, o := range opts.Owners {
			if _, ok := byOwner[o]; !ok {
				return nil, fmt.Errorf("%w: %q", ErrNoSuchOwner, o)
			}
			owners = append(owners, o)
		}
	}
	sort.Strings(owners)

	pw, err := newPasswordSet(opts.Password)
	if err != nil {
		return nil, err
	}
	defer pw.destroy()

	rep := &Report{Operation: "import", Unknown: listing.Unknown}
	if u.Deriver == nil {
		rep.Warnings = append(rep.Warnings, "signing keys were not checked against their verification key files: no deriver wired")
	}
	for _, o := range owners {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		rep.Owners = append(rep.Owners, u.importOwner(ctx, o, byOwner[o], opts, pw, rep))
	}
	return rep, nil
}

func (u ImportWorkspace) importOwner(ctx context.Context, owner string, refs []ports.Ref, opts ImportOptions, pw *passwordSet, rep *Report) OwnerReport {
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	results := map[ports.Ref]*ArtefactReport{}
	for _, r := range refs {
		results[r] = &ArtefactReport{Ref: r, Status: StatusDone}
	}
	failed := false
	fail := func(r ports.Ref, why string) {
		results[r].Status, results[r].Reason = StatusFailed, why
		failed = true
	}

	data := ownerData{open: map[ports.Ref][]byte{}, skey: map[ports.Ref]*ports.Secret{}}
	var plan []planned
	var toDestroy []*ports.Secret
	defer func() {
		for _, s := range toDestroy {
			s.Destroy()
		}
	}()

	for _, r := range refs {
		switch {
		case r.Kind == ports.PoolDescriptor || !r.Kind.Secret():
			b, err := u.read(ctx, r)
			if err != nil {
				fail(r, "could not be read")
				continue
			}
			if ok := validateOpen(r.Kind, b); !ok {
				fail(r, "malformed content")
				continue
			}
			if r.Kind == ports.PoolDescriptor && keyfile.HasField(b, "regProtectionKey") {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("the descriptor of %s holds regProtectionKey, a secret (ADR 0004), but its kind is not classified secret: it is stored as an ordinary record", owner))
			}
			data.open[r] = b
			plan = append(plan, planned{dst: r, data: b})
		case r.Kind.IsSigningKey():
			buf, err := u.SourceVault.Open(ctx, r)
			if err != nil {
				fail(r, "could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			info, cerr := classifyBuf(buf)
			switch {
			case cerr != nil && errors.Is(cerr, keyfile.ErrMalformedEncrypted):
				fail(r, "the encrypted key file is damaged")
			case cerr != nil:
				fail(r, "not a signing key envelope")
			case info.Form == keyfile.FormPlain:
				data.skey[r] = buf
				plan = append(plan, planned{dst: r, sec: buf})
			case info.Form == keyfile.FormEncrypted:
				dec, note, derr := u.openEncrypted(ctx, r, buf, opts, pw)
				if derr != "" {
					fail(r, derr)
					break
				}
				if note != "" {
					results[r].Note = note
					stem, _ := KeyStem(r)
					dst := ports.Ref{Name: stem, Kind: ports.UpstreamEncryptedSKey}
					plan = append(plan, planned{dst: dst, sec: buf})
					break
				}
				toDestroy = append(toDestroy, dec)
				data.skey[r] = dec
				plan = append(plan, planned{dst: r, sec: dec})
			default:
				fail(r, "a hardware signing file under a signing key name")
			}
		default: // mnemonics, QR codes: secret, opaque
			buf, err := u.SourceVault.Open(ctx, r)
			if err != nil {
				fail(r, "could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			if buf.Len() == 0 {
				fail(r, "empty")
				continue
			}
			plan = append(plan, planned{dst: r, sec: buf})
		}
	}

	if !failed {
		fails, notes := checker{deriver: u.Deriver, addresses: u.Addresses}.check(ctx, data)
		for r, why := range fails {
			fail(r, why)
		}
		for r, n := range notes {
			if results[r].Note == "" {
				results[r].Note = n
			}
		}
	}

	out := OwnerReport{Owner: owner}
	if !failed {
		if err := u.commit(ctx, plan, opts.Overwrite); err != nil {
			out.Reason = commitReason(err)
			for _, r := range refs {
				results[r].Status, results[r].Reason = StatusSkipped, "the owner was not imported: "+out.Reason
			}
		} else {
			out.Written = true
		}
	} else {
		out.Reason = "an artefact failed; nothing of this owner was imported"
		for _, r := range refs {
			if results[r].Status != StatusFailed {
				results[r].Status, results[r].Reason = StatusSkipped, "the owner was not imported: another artefact failed"
			}
		}
	}
	for _, r := range refs {
		out.Artefacts = append(out.Artefacts, *results[r])
	}
	return out
}

var errConflict = errors.New("destination conflict")

func commitReason(err error) string {
	if errors.Is(err, errConflict) {
		return "the destination already holds artefacts of this owner (use Overwrite)"
	}
	return "the destination could not be written"
}

func (u ImportWorkspace) commit(ctx context.Context, plan []planned, overwrite bool) error {
	return u.Dest.Update(ctx, func(w ports.Writer) error {
		if !overwrite {
			for _, p := range plan {
				ok, err := w.Exists(p.dst)
				if err != nil {
					return err
				}
				if ok {
					return errConflict
				}
			}
		}
		for _, p := range plan {
			var err error
			if p.sec != nil {
				err = w.PutSecret(p.dst, p.sec)
			} else {
				err = w.Put(p.dst, p.data)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (u ImportWorkspace) read(ctx context.Context, r ports.Ref) ([]byte, error) {
	var b []byte
	err := u.Source.View(ctx, func(rd ports.Reader) error {
		var e error
		b, e = rd.Get(r)
		return e
	})
	return b, err
}

// openEncrypted decrypts an upstream-encrypted key. When no password is
// given and KeepEncrypted is set it returns a note instead and keeps the
// opaque form. A non-empty string is a failure reason.
//
// spec: SPO-Ckey-PRE-006, SPO-Ckey-PRE-010, SPO-Ckey-PRE-007, SPO-Ckey-PR-002
func (u ImportWorkspace) openEncrypted(ctx context.Context, r ports.Ref, buf *ports.Secret, opts ImportOptions, pw *passwordSet) (dec *ports.Secret, note, failure string) {
	var enc keyfile.Encrypted
	var perr error
	_ = buf.Use(func(b []byte) error { enc, perr = keyfile.ParseEncrypted(b); return nil })
	if perr != nil {
		return nil, "", "the encrypted key file is damaged"
	}
	if pw == nil {
		if opts.KeepEncrypted {
			return nil, "kept in upstream's encrypted form (upstream-encrypted record)", ""
		}
		return nil, "", ErrPasswordRequired.Error()
	}
	if u.Decryptor == nil {
		return nil, "", "no decryptor wired"
	}
	cbor, err := pw.open(ctx, u.Decryptor, enc.EncrHex)
	switch {
	case errors.Is(err, ports.ErrWrongPassphrase):
		return nil, "", "the password does not open this key"
	case errors.Is(err, ports.ErrMalformedCiphertext):
		return nil, "", "the encrypted key is not a valid gpg message"
	case err != nil:
		return nil, "", "the key could not be decrypted"
	}
	defer cbor.Destroy()
	plain, err := plainFromDecrypted(enc, cbor, "    ")
	if err != nil {
		return nil, "", "the decrypted key is not usable"
	}
	return plain, "", ""
}

// validateOpen applies the cheap structural checks to non-secret artefacts
// that have one: hardware signing files are JSON, an address file is text.
func validateOpen(k ports.Kind, b []byte) bool {
	for _, hk := range ports.HardwareFileKinds() {
		if k == hk {
			return keyfile.ValidObject(b)
		}
	}
	switch k {
	case ports.AddrFile, ports.StakingAddr:
		return len(b) > 0
	}
	return true
}
