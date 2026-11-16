package workspace

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ProtectKey converts one plaintext signing key file of an upstream-layout
// store to upstream's encrypted form, in place (`01_protectKey enc`).
//
// On the sealed store this is meaningless, because every key there is
// already protected: set Sealed and Run returns ErrSealedStore.
type ProtectKey struct {
	Store     ports.Store
	Vault     ports.Vault
	Encryptor ports.KeyEncryptor
	// Decryptor checks that the new envelope opens again before the file is
	// replaced (the check upstream lacks, SPO-01protectKey-INV-001).
	Decryptor ports.KeyDecryptor
	// Sealed is true when Store is the sealed store.
	Sealed bool
}

// Run protects the key at ref with the password as the operator typed it. The
// password is used as upstream's prompt would have stored it, so the same
// keystrokes open the file in upstream's scripts, and it must be strong in
// that form. The file is replaced atomically and ends at mode 0400.
//
// spec: SPO-01protectKey-IF-003, SPO-01protectKey-IN-001, SPO-01protectKey-PRE-001, SPO-01protectKey-PRE-003, SPO-01protectKey-PR-002
// spec: SPO-01protectKey-EXT-001, SPO-01protectKey-INV-001, SPO-01protectKey-OUT-001, SPO-01protectKey-PRE-005, SPO-01protectKey-SEC-001, SPO-01protectKey-SEC-006, SPO-01protectKey-SEC-007, SPO-01protectKey-SEC-003
// spec: SPO-Ckey-INV-001, SPO-Ckey-INV-002, SPO-Ckey-PRE-002, SPO-Ckey-PRE-003, SPO-Ckey-PRE-004, SPO-Ckey-EXT-001, SPO-Ckey-OUT-001
func (u ProtectKey) Run(ctx context.Context, ref ports.Ref, password *ports.Secret) error {
	if u.Sealed {
		return ErrSealedStore
	}
	if !ref.Kind.IsSigningKey() {
		return ErrNotSigningKey
	}
	pw, err := upstreamForm(password)
	if err != nil {
		return err
	}
	defer pw.Destroy()
	buf, err := u.Vault.Open(ctx, ref)
	if err != nil {
		return err
	}
	defer buf.Destroy()
	info, cerr := classifyBuf(buf)
	switch {
	case cerr != nil:
		return ErrNotAKeyFile
	case info.Form == keyfile.FormEncrypted:
		return ErrAlreadyEncrypted
	case info.Form != keyfile.FormPlain:
		return ErrNotAKeyFile
	}
	env, err := encryptEnvelope(ctx, u.Encryptor, u.Decryptor, buf, info, pw)
	if err != nil {
		return err
	}
	defer env.Destroy()
	return u.Store.Update(ctx, func(w ports.Writer) error { return w.PutSecret(ref, env) })
}

// UnprotectKey converts one encrypted signing key file back to plaintext, in
// place (`01_protectKey dec`). It writes a secret in clear and is audited.
type UnprotectKey struct {
	Store     ports.Store
	Vault     ports.Vault
	Decryptor ports.KeyDecryptor
	Auditor   ports.WorkspaceAuditor
	Sealed    bool
}

// Run decrypts the key at ref. acknowledged is the operator's explicit
// acceptance that the key is written in clear. The password is tried as typed
// and as upstream's prompt would have stored it; a wrong password is
// ports.ErrWrongPassphrase, with no retry. The plain envelope is written as
// upstream's decrypt formats it (two-space indent).
//
// spec: SPO-01protectKey-PRE-004, SPO-01protectKey-EXT-002, SPO-01protectKey-OUT-002, SPO-01protectKey-PR-005, SPO-01protectKey-SEC-004, SPO-01protectKey-SEC-005, SPO-01protectKey-PRE-006
// spec: SPO-Ckey-PRE-005, SPO-Ckey-PRE-006, SPO-Ckey-PRE-007, SPO-Ckey-EXT-002, SPO-Ckey-OUT-002, SPO-Ckey-PR-002
func (u UnprotectKey) Run(ctx context.Context, ref ports.Ref, password *ports.Secret, acknowledged bool) error {
	if u.Sealed {
		return ErrSealedStore
	}
	if !ref.Kind.IsSigningKey() {
		return ErrNotSigningKey
	}
	if !acknowledged {
		return ErrPlaintextNotAcknowledged
	}
	if u.Auditor == nil {
		return ErrNoAuditor
	}
	pws, err := newPasswordSet(password)
	if err != nil {
		return err
	}
	defer pws.destroy()
	buf, err := u.Vault.Open(ctx, ref)
	if err != nil {
		return err
	}
	defer buf.Destroy()
	info, cerr := classifyBuf(buf)
	switch {
	case errors.Is(cerr, keyfile.ErrMalformedEncrypted):
		return cerr
	case cerr != nil:
		return ErrNotAKeyFile
	case info.Form == keyfile.FormPlain:
		return ErrNotEncrypted
	case info.Form != keyfile.FormEncrypted:
		return ErrNotAKeyFile
	}
	var enc keyfile.Encrypted
	var perr error
	_ = buf.Use(func(b []byte) error { enc, perr = keyfile.ParseEncrypted(b); return nil })
	if perr != nil {
		return perr
	}
	cbor, err := pws.open(ctx, u.Decryptor, enc.EncrHex)
	if err != nil {
		return err
	}
	defer cbor.Destroy()
	plain, err := plainFromDecrypted(enc, cbor, "  ")
	if err != nil {
		return err
	}
	defer plain.Destroy()
	if err := u.Auditor.Record(ctx, ports.AuditEvent{Operation: "unprotect-key", Owners: []string{OwnerOf(ref)}, PlaintextKeys: 1, Acknowledged: true}); err != nil {
		return errors.New("the audit record could not be made; nothing was written")
	}
	return u.Store.Update(ctx, func(w ports.Writer) error { return w.PutSecret(ref, plain) })
}
