package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of ConvertKey.
var (
	ErrNoKeptKey          = errors.New("no key kept in upstream's encrypted form has this name")
	ErrConvertNoVKey      = errors.New("the verification key of this key is not in the workspace, so the decrypted key cannot be checked against it: import the .vkey file and convert again")
	ErrConvertType        = errors.New("a key of this type (KES, VRF, BLS) cannot be checked against its verification key here, so it is not converted: import it again from the upstream directory with its password (spo workspace import --password-fd)")
	ErrConvertUnverified  = errors.New("the decrypted key could not be checked against its verification key")
	ErrConvertMismatch    = errors.New("the decrypted key does not belong to the verification key in the workspace; nothing was changed")
	ErrConvertDestination = errors.New("a sealed signing key of this name already exists; nothing was changed")
)

// ConvertKey turns a key kept in upstream's password-encrypted form (an
// UpstreamEncryptedSKey record, made by an import with --keep-encrypted) into
// an ordinary sealed signing key that can sign.
//
// It decrypts with the operator's upstream password, checks the key against the
// verification key in the workspace, then stores the sealed key and removes the
// kept record in ONE transaction: either both happen or the record is as it was.
// The decrypted key lives only in guarded memory and is never written in clear
// anywhere (SPO-Xcustody-INV-001, SPO-Xcustody-PR-001).
type ConvertKey struct {
	Store     ports.Store
	Vault     ports.Vault
	Decryptor ports.KeyDecryptor
	Deriver   ports.VerificationKeyDeriver
}

// Run converts the record named by name: the stem of the key file, with or
// without its `.skey` (`mypool.node`, `mywallet.payment.skey`). It returns the
// reference of the sealed key.
//
// spec: SPO-Xcustody-PR-001, SPO-Ckey-PRE-005, SPO-Ckey-PRE-006, SPO-Ckey-EXT-002
func (u ConvertKey) Run(ctx context.Context, name string, password *ports.Secret) (ports.Ref, error) {
	stem := strings.TrimSuffix(name, ".skey")
	rec := ports.Ref{Name: stem, Kind: ports.UpstreamEncryptedSKey}
	if rec.Validate() != nil {
		return ports.Ref{}, ErrNoKeptKey
	}
	dst, ok := SKeyRefFromStem(stem)
	if !ok {
		return ports.Ref{}, ErrNoKeptKey
	}
	if u.Decryptor == nil {
		return ports.Ref{}, errors.New("no decryptor wired")
	}
	if u.Deriver == nil {
		return ports.Ref{}, ErrConvertUnverified
	}
	role := ports.SigningKeyKinds()[dst.Kind]
	if role.VKey == "" {
		return ports.Ref{}, ErrConvertNoVKey
	}
	var vdata []byte
	var taken bool
	if err := u.Store.View(ctx, func(r ports.Reader) error {
		var e error
		if taken, e = r.Exists(dst); e != nil || taken {
			return e
		}
		vdata, e = r.Get(ports.Ref{Name: dst.Name, Kind: role.VKey, Num: dst.Num})
		if errors.Is(e, ports.ErrNotFound) {
			vdata, e = nil, nil
		}
		return e
	}); err != nil {
		return ports.Ref{}, err
	}
	if taken {
		return ports.Ref{}, ErrConvertDestination
	}
	pws, err := newPasswordSet(password)
	if err != nil {
		return ports.Ref{}, err
	}
	defer pws.destroy()
	buf, err := u.Vault.Open(ctx, rec)
	if errors.Is(err, ports.ErrNotFound) {
		return ports.Ref{}, ErrNoKeptKey
	}
	if err != nil {
		return ports.Ref{}, err
	}
	defer buf.Destroy()
	info, cerr := classifyBuf(buf)
	if cerr != nil || info.Form != keyfile.FormEncrypted {
		return ports.Ref{}, ErrNotAKeyFile
	}
	var enc keyfile.Encrypted
	var perr error
	_ = buf.Use(func(b []byte) error { enc, perr = keyfile.ParseEncrypted(b); return nil })
	if perr != nil {
		return ports.Ref{}, perr
	}
	cbor, err := pws.open(ctx, u.Decryptor, enc.EncrHex)
	if err != nil {
		return ports.Ref{}, err
	}
	defer cbor.Destroy()
	plain, err := plainFromDecrypted(enc, cbor, "    ")
	if err != nil {
		return ports.Ref{}, fmt.Errorf("the decrypted key is not usable: %w", err)
	}
	defer plain.Destroy()
	if len(vdata) == 0 {
		return ports.Ref{}, ErrConvertNoVKey
	}
	raw, err := u.Deriver.DeriveVerificationKey(ctx, plain)
	if errors.Is(err, ports.ErrKeyTypeUnsupported) {
		return ports.Ref{}, ErrConvertType
	}
	if err != nil {
		return ports.Ref{}, ErrConvertUnverified
	}
	env, perr := pool.ParseEnvelope(vdata)
	stored, kerr := env.Key32()
	if perr != nil || kerr != nil {
		return ports.Ref{}, ErrConvertUnverified
	}
	if !bytes.Equal(raw, stored) {
		return ports.Ref{}, ErrConvertMismatch
	}
	err = u.Store.Update(ctx, func(w ports.Writer) error {
		// The checks above ran in a View, before the password was tried and the
		// key decrypted: the workspace may have changed since. Look again in
		// this transaction, at what the decision rested on.
		if exists, e := w.Exists(dst); e != nil {
			return e
		} else if exists {
			return ErrConvertDestination
		}
		if kept, e := w.Exists(rec); e != nil {
			return e
		} else if !kept {
			return fmt.Errorf("%w: the kept key is gone", ports.ErrConflict)
		}
		if now, e := w.Get(ports.Ref{Name: dst.Name, Kind: role.VKey, Num: dst.Num}); e != nil || !bytes.Equal(now, vdata) {
			return fmt.Errorf("%w: the verification key the check used has changed", ports.ErrConflict)
		}
		if err := w.PutSecret(dst, plain); err != nil {
			return err
		}
		return w.Delete(rec)
	})
	if err != nil {
		return ports.Ref{}, err
	}
	return dst, nil
}
