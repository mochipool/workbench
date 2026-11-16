package workspace

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ExportWorkspace writes the artefacts of the sealed store into a directory in
// the upstream layout. It is a dangerous operation: signing keys leave the
// sealed store. Each run is recorded through the Auditor before any secret is
// written, and it needs an explicit choice:
//
//   - a Password protects every signing key in upstream's encrypted form
//     (the strong-password rule applies); this is the default whenever a
//     password is given;
//   - PlaintextAcknowledged writes signing keys as upstream's default
//     plaintext files (SPO-Pfiles-SEC-002), mode 0400.
//
// Artefacts with no protected form (mnemonics, the Catalyst QR code) are
// written only with PlaintextAcknowledged, whatever else is chosen; without it
// they are left out and the report says so. Nothing of the source changes.
type ExportWorkspace struct {
	// Source, SourceVault and Lister read the sealed store.
	Source      ports.Store
	SourceVault ports.Vault
	Lister      ports.SourceLister
	// Dest is the upstream-layout store (fsstore).
	Dest ports.Store
	// Encryptor makes upstream's encrypted form; needed with a password.
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
	// Password protects signing keys (upstream form). The caller destroys it.
	Password *ports.Secret
	// PlaintextAcknowledged is the operator's explicit acceptance that
	// secrets are written in clear.
	PlaintextAcknowledged bool
	// Overwrite replaces files the destination already holds.
	Overwrite bool
}

// Run exports. Options are checked before anything is read or written.
//
// spec: SPO-Pfiles-SEC-001, SPO-Pfiles-SEC-002, SPO-Pfiles-INV-003, SPO-Pfiles-OUT-003, SPO-Ckey-OUT-001, SPO-Ckey-INV-001, SPO-Ckey-EXT-001, SPO-Ckey-SEC-002, SPO-01protectKey-OUT-001, SPO-01protectKey-SEC-001
func (u ExportWorkspace) Run(ctx context.Context, opts ExportOptions) (*Report, error) {
	if u.Auditor == nil {
		return nil, ErrNoAuditor
	}
	protect := opts.Password != nil
	var pwForm *ports.Secret // the password as it is used to encrypt
	if protect {
		if u.Encryptor == nil {
			return nil, errors.New("no encryptor wired")
		}
		var err error
		if pwForm, err = upstreamForm(opts.Password); err != nil {
			return nil, err
		}
		defer pwForm.Destroy()
	}
	listing, err := u.Lister.List(ctx)
	if err != nil {
		return nil, err
	}
	byOwner := map[string][]ports.Ref{}
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

	// Without a password a plaintext export must be acknowledged, and it is
	// refused before anything is read when the selection has a secret.
	if !protect && !opts.PlaintextAcknowledged {
		for _, o := range owners {
			for _, r := range byOwner[o] {
				if r.Kind.Secret() && r.Kind != ports.UpstreamEncryptedSKey {
					return nil, ErrPlaintextNotAcknowledged
				}
			}
		}
	}

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
// must be strong in that form (SPO-Ckey-INV-001).
func upstreamForm(pw *ports.Secret) (*ports.Secret, error) {
	var out *ports.Secret
	err := pw.Use(func(b []byte) error {
		u := keyfile.UpstreamRead(b)
		if !keyfile.IsStrongPassword(u) {
			clear(u)
			return ErrWeakPassword
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

func (u ExportWorkspace) exportOwner(ctx context.Context, owner string, refs []ports.Ref, opts ExportOptions, pw *ports.Secret, rep *Report) OwnerReport {
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	results := map[ports.Ref]*ArtefactReport{}
	var plan []planned
	var toDestroy []*ports.Secret
	defer func() {
		for _, s := range toDestroy {
			s.Destroy()
		}
	}()
	failed := false
	var plaintext, protected int
	for _, r := range refs {
		res := &ArtefactReport{Ref: r, Status: StatusDone}
		results[r] = res
		fail := func(why string) { res.Status, res.Reason, failed = StatusFailed, why, true }
		skip := func(why string) { res.Status, res.Reason = StatusSkipped, why }
		switch {
		case !r.Kind.Secret():
			var b []byte
			err := u.Source.View(ctx, func(rd ports.Reader) error {
				var e error
				b, e = rd.Get(r)
				return e
			})
			if err != nil {
				fail("could not be read")
				continue
			}
			plan = append(plan, planned{dst: r, data: b})
		case r.Kind == ports.UpstreamEncryptedSKey:
			dst, ok := SKeyRefFromStem(r.Name)
			buf, err := u.SourceVault.Open(ctx, r)
			if err != nil || !ok {
				fail("could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			plan = append(plan, planned{dst: dst, sec: buf})
			res.Note = "written back in upstream's encrypted form as it was imported"
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
				if pw == nil {
					plan = append(plan, planned{dst: r, sec: buf})
					plaintext++
					break
				}
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
		default: // mnemonics, QR codes: no protected form
			if !opts.PlaintextAcknowledged {
				skip("has no protected form: written only with PlaintextAcknowledged")
				continue
			}
			buf, err := u.SourceVault.Open(ctx, r)
			if err != nil {
				fail("could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			plan = append(plan, planned{dst: r, sec: buf})
			plaintext++
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
	if plaintext+protected > 0 {
		ev := ports.AuditEvent{Operation: "export-workspace", Owners: []string{owner}, PlaintextKeys: plaintext, ProtectedKeys: protected,
			Protected: pw != nil, Acknowledged: opts.PlaintextAcknowledged}
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
