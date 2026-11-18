package labels

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ADR 0011 decision 6, "Cold-role sub-keys": the sub-key applies by identity,
// not by record. The store classifies a signing-key record at put time from the
// role history of the key identity the record holds, which it finds through the
// verification key stored beside it (the same anchor, number and role).

var (
	// ErrNoKeyIdentity means a signing key record has no verification key beside
	// it, so the key has no identity and no role history can be found for it.
	ErrNoKeyIdentity = errors.New("a signing key has no verification key stored with it, so its key identity and role history cannot be found")
	// ErrNoRoleHistory means the key identity of a signing key has no role
	// history. The store fails closed: it never seals such a key as a hot key.
	ErrNoRoleHistory = errors.New("the key identity of this signing key has no role history, so it cannot be told whether it is a cold key")
)

type skeyRole struct {
	vkey ports.Kind
	role custody.Role
	// mnemonic marks the mnemonic record of a cold role: the words derive the
	// signing key, so the record is a cold record whatever the role history says,
	// and it is bound to the identity of the verification key beside it.
	mnemonic bool
}

// coldMnemonics are the mnemonic kinds from which a key with a cold role can be
// derived by this program: the committee cold key (path role 4). There is no pool
// cold mnemonic kind (a pool cold key is generated or comes from a device); the
// payment, DRep, committee hot, Calidus and Catalyst voting mnemonics derive
// keys of other roles only (ADR 0011 decision 6, "Cold-role sub-keys").
var coldMnemonics = map[ports.Kind]ports.Kind{ports.CCColdMnemonics: ports.CCColdVKey}

var skeyRoles = func() map[ports.Kind]skeyRole {
	m := map[ports.Kind]skeyRole{ports.KesSKey: {vkey: ports.KesVKey, role: custody.RoleKES}}
	for _, r := range custody.Roles() {
		if k, ok := ports.KeyKindsOf(r); ok && k.SKey != "" {
			m[k.SKey] = skeyRole{vkey: k.VKey, role: r}
		}
	}
	for mk, vk := range coldMnemonics {
		for _, r := range custody.Roles() {
			if k, ok := ports.KeyKindsOf(r); ok && k.VKey == vk && r.IsCold() {
				m[mk] = skeyRole{vkey: vk, role: r, mnemonic: true}
			}
		}
	}
	return m
}()

// IsKeySecret reports whether the kind is the signing key of a role: a record
// whose secret is a key with an identity, or the mnemonic of a cold role (the
// other secrets, such as a provider token, a party key or the mnemonic of a hot
// role, are not).
func IsKeySecret(k ports.Kind) bool {
	_, ok := skeyRoles[k]
	return ok || k == ports.UpstreamEncryptedSKey
}

// IdentityUncheckable reports whether the plaintext of a record of the kind is
// not a signing key from which the key identity can be derived (the words of a
// mnemonic, a key still wrapped by gpg), so a recovery that opens it without its
// sub-key factor cannot check that the secret belongs to the record's identity.
func IdentityUncheckable(k ports.Kind) bool {
	return IsColdMnemonic(k) || k == ports.UpstreamEncryptedSKey
}

// RoleOfKind is the role of the key a signing-key (or cold mnemonic) kind holds.
func RoleOfKind(k ports.Kind) (custody.Role, bool) { r, ok := skeyRoles[k]; return r.role, ok }

// IsColdMnemonic reports whether the kind is the mnemonic record of a cold role.
func IsColdMnemonic(k ports.Kind) bool { r, ok := skeyRoles[k]; return ok && r.mnemonic }

// KeyClass is what ClassifyKeyRecord finds.
type KeyClass struct {
	// IsKey is false for a secret that is not the signing key of a role.
	IsKey bool
	// Identity is the key identity the record's verification key hashes to.
	Identity identity.Ref
	// Cold is true when the identity's role history holds a cold role.
	Cold bool
}

// ClassifyKeyRecord classifies the signing-key record ref from inside a
// transaction. A signing key whose verification key is missing, or whose key
// identity has no role history, is an error (ErrNoKeyIdentity, ErrNoRoleHistory):
// the caller refuses the record.
func ClassifyKeyRecord(r ports.Reader, ref ports.Ref) (KeyClass, error) {
	if ref.Kind == ports.UpstreamEncryptedSKey {
		// keyed by the identity of the verification key beside it (ADR 0010
		// decision 4)
		id := ref.Anchor
		if id.IsZero() || id.Is(identity.KindNamedRecord) {
			// quarantined: the label layer has refused every stem of a cold role
			// that has no sibling, so what is left is not a cold-role key
			return KeyClass{}, nil
		}
		h, ok, err := readHistory(r, id)
		if err != nil {
			return KeyClass{IsKey: true, Identity: id}, err
		}
		if !ok {
			return KeyClass{IsKey: true, Identity: id}, ErrNoRoleHistory
		}
		return KeyClass{IsKey: true, Identity: id, Cold: h.HasColdRole()}, nil
	}
	info, ok := skeyRoles[ref.Kind]
	if !ok {
		return KeyClass{}, nil
	}
	vk, err := r.Get(ports.Ref{Anchor: ref.Anchor, Kind: info.vkey, Num: ref.Num})
	if errors.Is(err, ports.ErrNotFound) {
		return KeyClass{IsKey: true}, ErrNoKeyIdentity
	}
	if err != nil {
		return KeyClass{IsKey: true}, err
	}
	id, err := ports.IdentityOfVKey(info.role, vk)
	if err != nil {
		return KeyClass{IsKey: true}, fmt.Errorf("%w: %v", ErrNoKeyIdentity, err)
	}
	h, ok, err := readHistory(r, id)
	if err != nil {
		return KeyClass{IsKey: true, Identity: id}, err
	}
	if !ok {
		return KeyClass{IsKey: true, Identity: id}, ErrNoRoleHistory
	}
	return KeyClass{IsKey: true, Identity: id, Cold: h.HasColdRole() || info.mnemonic}, nil
}

// KeyRecordsOf lists the signing-key records of the verification keys whose
// identity is id: the secret references a role history change can reclassify.
// It scans the verification keys of every role.
func KeyRecordsOf(r ports.Reader, l ports.RecordLister, id identity.Ref) ([]ports.Ref, error) {
	var out []ports.Ref
	if encs, err := l.Records(ports.UpstreamEncryptedSKey); err == nil {
		for _, er := range encs {
			if er.Anchor == id {
				out = append(out, er)
			}
		}
	}
	for sk, info := range skeyRoles {
		vks, err := l.Records(info.vkey)
		if err != nil {
			return nil, err
		}
		for _, vr := range vks {
			b, err := r.Get(vr)
			if err != nil {
				continue
			}
			got, err := ports.IdentityOfVKey(info.role, b)
			if err != nil || got != id {
				continue
			}
			sref := ports.Ref{Anchor: vr.Anchor, Kind: sk, Num: vr.Num}
			if ok, err := r.Exists(sref); err == nil && ok {
				out = append(out, sref)
			}
		}
	}
	return out, nil
}

// ParseHistory reads a stored role-history record.
func ParseHistory(b []byte) (custody.RoleHistory, error) { return custody.ParseRoleHistory(b) }
