package porttest

import (
	"context"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// Key returns the key reference of the role's key stored under a name in a
// store: the name is resolved once, to the identity of the stored verification
// key, as the use cases do (ADR 0010). A test that has to build a reference
// uses it instead of naming an owner or a holder, which a reference no longer
// carries.
func Key(t testing.TB, st ports.NamedStore, role custody.Role, name string) custody.KeyRef {
	t.Helper()
	kinds, ok := ports.KeyKindsOf(role)
	if !ok {
		t.Fatalf("a %s key has no stored form", role)
	}
	var ref custody.KeyRef
	err := st.View(context.Background(), func(r ports.NamedReader) error {
		raw, err := r.Get(ports.NamedRef{Name: name, Kind: kinds.VKey})
		if err != nil {
			return err
		}
		id, err := ports.IdentityOfVKey(role, raw)
		ref = custody.KeyRef{Role: role, Identity: id}
		return err
	})
	if err != nil {
		t.Fatalf("the %s key of %q: %v", role, name, err)
	}
	return ref
}

// VaultOnly is a SignerDirectory of one signer that answers for every key whose
// signing key is stored in the store, as a build with no device does: a key
// that only has a hardware signing file has no signer. The store is the
// anchor-level store: its keys are found by identity through the labels.
func VaultOnly(named ports.NamedStore, s ports.Signer) ports.SignerDirectory {
	var idx ports.KeyIndex
	if st, ok := labels.AnchorOf(named); ok {
		idx = labels.NewIndex(st)
	} else {
		idx = namedIndex{named}
	}
	return ports.SignerFunc(func(k custody.KeyRef) (ports.Signer, error) {
		homes, err := idx.Homes(context.Background(), k.Identity)
		if err != nil {
			return nil, err
		}
		// the hardware file wins when both exist (SPO-Pfiles-INV-002), and no
		// device is connected here
		if _, ok := ports.HardwareHome(homes, k.Role); ok {
			return nil, errNoSigner
		}
		if _, ok := ports.SecretHome(homes, k.Role); ok {
			return s, nil
		}
		return nil, errNoSigner
	})
}

// namedIndex is the key index of a name-level test store that has no anchor
// level (an in-memory fake): it finds the keys of an identity from the store's
// listing of names. It says whether a signing key or a hardware file is held,
// which is all a test directory needs; its homes carry no anchor.
type namedIndex struct{ st ports.NamedStore }

func (x namedIndex) Homes(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) {
	lister, ok := x.st.(ports.SourceLister)
	if !ok {
		return nil, errors.New("porttest: the store lists nothing, so its keys cannot be found by identity")
	}
	listing, err := lister.List(ctx)
	if err != nil {
		return nil, err
	}
	byV := map[ports.Kind]custody.Role{}
	for _, role := range custody.Roles() {
		if k, ok := ports.KeyKindsOf(role); ok {
			byV[k.VKey] = role
		}
	}
	var out []ports.KeyHome
	err = x.st.View(ctx, func(r ports.NamedReader) error {
		for _, e := range listing.Entries {
			role, ok := byV[e.Ref.Kind]
			if !ok {
				continue
			}
			raw, err := r.Get(e.Ref)
			if err != nil {
				continue
			}
			got, err := ports.IdentityOfVKey(role, raw)
			if err != nil || got != id {
				continue
			}
			kk, _ := ports.KeyKindsOf(role)
			h := ports.KeyHome{Role: role, Identity: id}
			h.HasSecret, _ = r.Exists(ports.NamedRef{Name: e.Ref.Name, Kind: kk.SKey})
			if kk.Hws != "" {
				h.HasHardware, _ = r.Exists(ports.NamedRef{Name: e.Ref.Name, Kind: kk.Hws})
			}
			out = append(out, h)
		}
		return nil
	})
	return out, err
}

func (x namedIndex) RoleHistory(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	homes, err := x.Homes(ctx, id)
	if err != nil || len(homes) == 0 {
		return custody.RoleHistory{}, false, err
	}
	h, err := custody.NewRoleHistory(id, homes[0].Role)
	for _, home := range homes[1:] {
		if err == nil {
			h, err = h.With(home.Role)
		}
	}
	return h, err == nil, err
}

var errNoSigner = ports.ErrNoHardwareSigner
