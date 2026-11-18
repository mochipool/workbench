package workspace

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ExportWorkspace writes the artefacts of the sealed store into a directory in
// the upstream layout, for upstream's scripts. Signing keys leave the sealed
// store only in upstream's encrypted form: a Password is required, every
// signing key is encrypted with it (the strong-password rule applies), and the
// destination refuses anything else (SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003;
// ADR 0011 (proposed)). Each run is recorded through the Auditor before any
// secret is written.
//
// Artefacts with no encrypted form (mnemonics, the Catalyst QR code) and the
// records of keys kept in upstream's encrypted form are never written: they are
// left out and the report says so. Nothing of the source changes.
type ExportWorkspace struct {
	// Source, SourceVault and Lister read the sealed store.
	Source      ports.NamedStore
	SourceVault ports.NamedVault
	Lister      ports.SourceLister
	// Dest is the destination directory (exportdir). It must refuse a
	// secret that is not an encrypted signing key.
	Dest ports.NamedStore
	// Encryptor makes upstream's encrypted form; required.
	// Decryptor, when set, checks that each encrypted key opens again with
	// the password before it is written (SPO-01protectKey-INV-001).
	Encryptor ports.KeyEncryptor
	Decryptor ports.KeyDecryptor
	// Auditor records the operation; required.
	Auditor ports.WorkspaceAuditor
}

// ExportOptions chooses what leaves the store and in which form.
type ExportOptions struct {
	// Owners names the pools and wallets to export; empty means everything.
	Owners []string
	// Password encrypts the signing keys (upstream form). Required; the
	// caller destroys it.
	Password *ports.Secret
	// Overwrite replaces files the destination already holds.
	Overwrite bool
}

// Run exports. Options are checked before anything is read or written.
//
// spec: SPO-Pfiles-SEC-001, SPO-Pfiles-INV-003, SPO-Pfiles-OUT-003, SPO-Ckey-OUT-001, SPO-Ckey-INV-001, SPO-Ckey-EXT-001, SPO-Ckey-SEC-002, SPO-Xcustody-INV-001, SPO-Xcustody-OUT-003, SPO-Xcustody-PRE-003
func (u ExportWorkspace) Run(ctx context.Context, opts ExportOptions) (*Report, error) {
	if u.Auditor == nil {
		return nil, ErrNoAuditor
	}
	if opts.Password == nil {
		return nil, ErrExportPasswordRequired
	}
	if u.Encryptor == nil {
		return nil, errors.New("no encryptor wired")
	}
	pwForm, err := upstreamForm(opts.Password) // the password as it is used to encrypt
	if err != nil {
		return nil, err
	}
	defer pwForm.Destroy()
	listing, err := u.Lister.List(ctx)
	if err != nil {
		return nil, err
	}
	byOwner := map[string][]ports.NamedRef{}
	for _, e := range listing.Entries {
		if !ports.IsWorkspaceKind(e.Ref.Kind) {
			continue
		}
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

	rep := &Report{Operation: "export"}
	for _, o := range owners {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		rep.Owners = append(rep.Owners, u.exportOwner(ctx, o, byOwner[o], opts, pwForm, rep))
	}
	return rep, nil
}

// upstreamForm is the password as upstream's prompt would have produced it,
// so the operator can type the same characters into upstream's scripts. It
// must be strong in that form (SPO-Ckey-INV-001) and at least 20 characters
// long (SPO-Xcustody-PRE-003).
func upstreamForm(pw *ports.Secret) (*ports.Secret, error) {
	var out *ports.Secret
	err := pw.Use(func(b []byte) error {
		u := keyfile.UpstreamRead(b)
		if !keyfile.IsStrongPassword(u) {
			clear(u)
			return ErrWeakPassword
		}
		if !keyfile.IsLongExportPassword(b) {
			clear(u)
			return ErrShortExportPassword
		}
		b2, terr := ports.TakeSecret(u)
		if terr != nil {
			return terr
		}
		out = b2
		return nil
	})
	return out, err
}

func (u ExportWorkspace) exportOwner(ctx context.Context, owner string, refs []ports.NamedRef, opts ExportOptions, pw *ports.Secret, rep *Report) OwnerReport {
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	results := map[ports.NamedRef]*ArtefactReport{}
	var plan []planned
	var toDestroy []*ports.Secret
	defer func() {
		for _, s := range toDestroy {
			s.Destroy()
		}
	}()
	failed := false
	var protected int
	for _, r := range refs {
		res := &ArtefactReport{Ref: r, Status: StatusDone}
		results[r] = res
		fail := func(why string) { res.Status, res.Reason, failed = StatusFailed, why, true }
		skip := func(why string) { res.Status, res.Reason = StatusSkipped, why }
		switch {
		case !r.Kind.Secret():
			var b []byte
			err := u.Source.View(ctx, func(rd ports.NamedReader) error {
				var e error
				b, e = rd.Get(r)
				return e
			})
			if err != nil {
				fail("could not be read")
				continue
			}
			if r.Kind == ports.PoolDescriptor {
				b = u.descriptorWithNames(ctx, b)
			}
			plan = append(plan, planned{dst: r, data: b})
		case r.Kind == ports.UpstreamEncryptedSKey:
			// Never written out (SPO-Xcustody-OUT-003): convert it into a
			// sealed key first (spo key convert), then export that.
			skip("a key kept in upstream's encrypted form is never written out: convert it into a sealed key with `spo key convert`, then export")
			continue
		case r.Kind.IsSigningKey():
			buf, err := u.SourceVault.Open(ctx, r)
			if err != nil {
				fail("could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			info, cerr := classifyBuf(buf)
			if cerr != nil {
				fail("not a signing key envelope")
				continue
			}
			switch info.Form {
			case keyfile.FormEncrypted:
				plan = append(plan, planned{dst: r, sec: buf})
				protected++
			case keyfile.FormPlain:
				env, eerr := u.protect(ctx, buf, info, pw)
				if eerr != nil {
					fail(eerr.Error())
					break
				}
				toDestroy = append(toDestroy, env)
				plan = append(plan, planned{dst: r, sec: env})
				protected++
			default:
				fail("not a signing key envelope")
			}
		default: // mnemonics, QR codes: no encrypted form, so never written
			skip("has no encrypted form and is never written in clear (SPO-Xcustody-OUT-003)")
			continue
		}
	}

	out := OwnerReport{Owner: owner}
	finish := func(reason string) OwnerReport {
		out.Reason = reason
		for _, r := range refs {
			if results[r].Status == StatusDone {
				results[r].Status, results[r].Reason = StatusSkipped, "the owner was not exported: "+reason
			}
		}
		for _, r := range refs {
			out.Artefacts = append(out.Artefacts, *results[r])
		}
		return out
	}
	if failed {
		return finish("an artefact failed; nothing of this owner was exported")
	}
	// Record before the first secret is written; a failed record stops the owner.
	if protected > 0 {
		ev := ports.AuditEvent{Operation: "export-workspace", Owners: []string{owner}, ProtectedKeys: protected, Protected: true}
		if err := u.Auditor.Record(ctx, ev); err != nil {
			return finish("the audit record could not be made")
		}
	}
	if err := u.commit(ctx, plan, opts.Overwrite); err != nil {
		return finish(commitReason(err))
	}
	out.Written = true
	for _, r := range refs {
		out.Artefacts = append(out.Artefacts, *results[r])
	}
	return out
}

// protect makes upstream's encrypted envelope of a plain key and checks it
// decrypts back to the same key text before it is used (SPO-01protectKey-INV-001).
func (u ExportWorkspace) protect(ctx context.Context, plain *ports.Secret, info keyfile.Info, pw *ports.Secret) (*ports.Secret, error) {
	return encryptEnvelope(ctx, u.Encryptor, u.Decryptor, plain, info, pw)
}

func (u ExportWorkspace) commit(ctx context.Context, plan []planned, overwrite bool) error {
	return ImportWorkspace{Dest: u.Dest}.commit(ctx, plan, overwrite)
}

// encryptEnvelope encrypts the cborHex of a plain envelope and returns the
// encrypted envelope in guarded memory. With a decryptor it verifies the round
// trip first.
func encryptEnvelope(ctx context.Context, enc ports.KeyEncryptor, dec ports.KeyDecryptor, plain *ports.Secret, info keyfile.Info, pw *ports.Secret) (*ports.Secret, error) {
	var cbor *ports.Secret
	err := plain.Use(func(d []byte) error {
		span, err := keyfile.CborHexSpan(d)
		if err != nil {
			return err
		}
		c, terr := ports.TakeSecret(append([]byte(nil), span...))
		cbor = c
		return terr
	})
	if err != nil {
		return nil, ErrNotAKeyFile
	}
	defer cbor.Destroy()
	encrHex, err := enc.Encrypt(ctx, cbor, pw)
	if err != nil {
		return nil, errors.New("the key could not be encrypted")
	}
	if dec != nil {
		back, derr := dec.Decrypt(ctx, encrHex, pw)
		if derr != nil {
			return nil, ErrVerifyFailed
		}
		defer back.Destroy()
		same := false
		_ = back.Use(func(b []byte) error {
			return cbor.Use(func(c []byte) error { same = string(b) == string(c); return nil })
		})
		if !same {
			return nil, ErrVerifyFailed
		}
	}
	return ports.TakeSecret(keyfile.EncryptedEnvelope(info.Type, info.Description, encrHex))
}

// descriptorWithNames writes the labels back into a pool descriptor: a descriptor
// of the workspace refers to its owners, its reward account and the payer of an
// open registration by key hash (ADR 0010 decision 2), and the upstream scripts
// read names. Each reference that is an identity is replaced by the label of the
// owner that lists it (`<label>.payment` for the payment account of a wallet that
// has one); a reference that is a name, or whose owner has no label, is left as it
// is.
func (u ExportWorkspace) descriptorWithNames(ctx context.Context, b []byte) []byte {
	d, err := pool.ParseDescriptor(b)
	if err != nil {
		return b
	}
	out := b
	_ = u.Source.View(ctx, func(rd ports.NamedReader) error {
		lab, ok := rd.(ports.OwnerLabeler)
		if !ok {
			return nil
		}
		changed, err := d.MapRefs(func(place, old string) (string, error) {
			if _, isID := ports.IdentityName(old); !isID {
				return old, nil
			}
			name, stem, err := lab.LabelOfIdentity(identity.OwnerWallet, old)
			if err != nil {
				return old, nil
			}
			if place == pool.RefPayer && stem {
				name += ".payment"
			}
			return name, nil
		})
		if err == nil && changed {
			out = d.Render()
		}
		return nil
	})
	return out
}
