package ports

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrEnvelopeKind means the type of a signing-key text envelope does not match the
// record kind it is to be stored under: a key of a cold role under another kind
// (under a hot kind it would be sealed hot).
var ErrEnvelopeKind = errors.New("the envelope type of this signing key does not match the kind of record it is stored under")

// coldEnvelopeKinds maps the envelope types of the signing keys of the cold roles
// (pool cold, committee cold) to the one record kind that may hold them.
var coldEnvelopeKinds = map[string]Kind{
	"StakePoolSigningKey_ed25519":                                 NodeSKey,
	"StakePoolExtendedSigningKey_ed25519_bip32":                   NodeSKey,
	"ConstitutionalCommitteeColdSigningKey_ed25519":               CCColdSKey,
	"ConstitutionalCommitteeColdExtendedSigningKey_ed25519_bip32": CCColdSKey,
	"CommitteeColdSigningKeyShelley_ed25519":                      CCColdSKey,
}

// CheckEnvelopeKind refuses a signing-key envelope whose type belongs to a cold
// role but which is to be stored under another kind. (An envelope of another type
// under a cold kind is not refused: the record is sealed cold by its kind, and the
// upstream envelope types of the other roles are not all known.) A payload that is not an envelope (a key in another
// form, a mnemonic) is not judged here. The type is read from the clear member
// "type" of the text envelope; no key material is parsed.
func CheckEnvelopeKind(kind Kind, payload []byte) error {
	var env struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(payload, &env) != nil || env.Type == "" {
		return nil
	}
	if want, cold := coldEnvelopeKinds[env.Type]; cold {
		if want != kind {
			return fmt.Errorf("%w: a %s envelope belongs under %s, not %s", ErrEnvelopeKind, env.Type, want, kind)
		}
		return nil
	}
	return nil
}
