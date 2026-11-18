package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// keptFixture is a sealed store that holds a payment key only in upstream's
// encrypted form (a record of an older import), with its verification key.
func keptFixture(t *testing.T) (*memStore, keyPair, ConvertKey) {
	t.Helper()
	src, keys := workspaceFixture(t)
	src.put(ref("w.payment", ports.AddrSKey), encryptedOf(t, keys["pay"], "Str0ng-Passw0rd!-And-Long"))
	// the record an older import made (no new import creates one)
	mid := newMem()
	for r, b := range src.snapshot() {
		if OwnerOf(r) == "w" && r != ref("w.payment", ports.AddrSKey) {
			mid.put(r, []byte(b))
		}
	}
	mid.put(ref("w.payment", ports.UpstreamEncryptedSKey), encryptedOf(t, keys["pay"], "Str0ng-Passw0rd!-And-Long"))
	if _, ok := mid.files[ref("w.payment", ports.UpstreamEncryptedSKey)]; !ok {
		t.Fatalf("the key was not kept encrypted: %v", mid.snapshot())
	}
	g := &fakeGPG{}
	return mid, keys["pay"], ConvertKey{Store: mid, Vault: mid, Decryptor: g, Deriver: edDeriver{}}
}

// A kept key becomes a sealed signing key that holds the same key, and the kept
// record is gone, in one transaction.
//
// spec: SPO-Xcustody-PR-001, SPO-Xcustody-OUT-001, SPO-Ckey-PRE-005, SPO-Ckey-EXT-002
func TestConvertKeyMakesASealedKeyAndRemovesTheRecord(t *testing.T) {
	mid, kp, u := keptFixture(t)
	dst, err := u.Run(context.Background(), "w.payment.skey", sec("Str0ng-Passw0rd!-And-Long"))
	if err != nil {
		t.Fatal(err)
	}
	if dst != ref("w.payment", ports.AddrSKey) {
		t.Errorf("destination %v", dst)
	}
	if _, ok := mid.files[ref("w.payment", ports.UpstreamEncryptedSKey)]; ok {
		t.Error("the kept record is still there")
	}
	info, cerr := keyfile.Classify(mid.files[dst])
	if cerr != nil || info.Form != keyfile.FormPlain {
		t.Fatalf("the sealed key is not a plain envelope: %v", cerr)
	}
	if string(mid.files[dst]) != string(kp.skey) {
		t.Errorf("sealed key:\n%s\nwant\n%s", mid.files[dst], kp.skey)
	}
}

// The destination, the kept record and the verification key are checked again
// inside the transaction that writes: a sealed key that appears (or a kept
// record or verification key that goes or changes) after the first look and
// before the write stops the conversion, and nothing is replaced or removed.
//
// spec: SPO-Xcustody-OUT-001, SPO-Xcustody-PRE-002
func TestConvertKeyRechecksInsideTheTransaction(t *testing.T) {
	ctx := context.Background()
	rec := ref("w.payment", ports.UpstreamEncryptedSKey)
	dst := ref("w.payment", ports.AddrSKey)
	for name, tc := range map[string]struct {
		change func(m *memStore)
		want   error
	}{
		"a sealed key appears": {func(m *memStore) { m.put(dst, []byte(`{"type":"x","description":"","cborHex":"5820aa"}`)) }, ErrConvertDestination},
		"the kept record goes": {func(m *memStore) { delete(m.files, rec) }, ports.ErrConflict},
		"the verification key changes": {func(m *memStore) {
			m.put(ref("w.payment", ports.AddrVKey), []byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820`+strings.Repeat("00", 32)+`"}`))
		}, ports.ErrConflict},
	} {
		t.Run(name, func(t *testing.T) {
			mid, _, u := keptFixture(t)
			u.Deriver = hookDeriver{edDeriver{}, func() { tc.change(mid) }}
			before := mid.snapshot()
			if _, err := u.Run(ctx, "w.payment", sec("Str0ng-Passw0rd!-And-Long")); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			after := mid.snapshot()
			if name == "a sealed key appears" {
				if after[dst] == before[dst] {
					t.Error("the sealed key that appeared was replaced")
				}
				if _, ok := after[rec]; !ok {
					t.Error("the kept record was removed")
				}
			}
		})
	}
}

// hookDeriver runs a hook between the first look at the workspace and the write.
type hookDeriver struct {
	ports.VerificationKeyDeriver
	hook func()
}

func (h hookDeriver) DeriveVerificationKey(ctx context.Context, k *ports.Secret) ([]byte, error) {
	h.hook()
	return h.VerificationKeyDeriver.DeriveVerificationKey(ctx, k)
}

// Nothing changes when the password is wrong, the key does not match its
// verification key, the verification key is missing, the key is of a type that
// cannot be checked, or the write fails.
//
// spec: SPO-Xcustody-PRE-002, SPO-Xcustody-OUT-001
func TestConvertKeyRefusesAndChangesNothing(t *testing.T) {
	ctx := context.Background()
	rec := ref("w.payment", ports.UpstreamEncryptedSKey)
	unchanged := func(t *testing.T, mid *memStore, before map[ports.NamedRef]string) {
		t.Helper()
		after := mid.snapshot()
		if len(after) != len(before) {
			t.Errorf("the store changed: %d artefacts, was %d", len(after), len(before))
		}
		if _, ok := after[rec]; !ok {
			t.Error("the kept record is gone")
		}
		if _, ok := after[ref("w.payment", ports.AddrSKey)]; ok {
			t.Error("a sealed key was written")
		}
	}
	t.Run("wrong password", func(t *testing.T) {
		mid, _, u := keptFixture(t)
		before := mid.snapshot()
		if _, err := u.Run(ctx, "w.payment", sec("Wrong-Passw0rd!x")); !errors.Is(err, ports.ErrWrongPassphrase) {
			t.Errorf("got %v", err)
		}
		unchanged(t, mid, before)
	})
	t.Run("key of another pair", func(t *testing.T) {
		mid, kp, u := keptFixture(t)
		other := payment(9)
		if other.cbor == kp.cbor {
			t.Fatal("fixture")
		}
		mid.put(ref("w.payment", ports.AddrVKey), other.vkey)
		before := mid.snapshot()
		if _, err := u.Run(ctx, "w.payment", sec("Str0ng-Passw0rd!-And-Long")); !errors.Is(err, ErrConvertMismatch) {
			t.Errorf("got %v", err)
		}
		unchanged(t, mid, before)
	})
	t.Run("no verification key", func(t *testing.T) {
		mid, _, u := keptFixture(t)
		delete(mid.files, ref("w.payment", ports.AddrVKey))
		before := mid.snapshot()
		if _, err := u.Run(ctx, "w.payment", sec("Str0ng-Passw0rd!-And-Long")); !errors.Is(err, ErrConvertNoVKey) {
			t.Errorf("got %v", err)
		}
		unchanged(t, mid, before)
	})
	t.Run("write fails", func(t *testing.T) {
		mid, _, u := keptFixture(t)
		before := mid.snapshot()
		mid.failUpdate = errors.New("disk full")
		if _, err := u.Run(ctx, "w.payment", sec("Str0ng-Passw0rd!-And-Long")); err == nil {
			t.Error("a failed write was not reported")
		}
		mid.failUpdate = nil
		unchanged(t, mid, before)
	})
	t.Run("a type that cannot be checked", func(t *testing.T) {
		mid, _, u := keptFixture(t)
		u.Deriver = unsupportedDeriver{}
		before := mid.snapshot()
		if _, err := u.Run(ctx, "w.payment", sec("Str0ng-Passw0rd!-And-Long")); !errors.Is(err, ErrConvertType) {
			t.Errorf("got %v", err)
		}
		unchanged(t, mid, before)
	})
	t.Run("no such record", func(t *testing.T) {
		mid, _, u := keptFixture(t)
		if _, err := u.Run(ctx, "nobody.payment", sec("Str0ng-Passw0rd!-And-Long")); !errors.Is(err, ErrNoKeptKey) {
			t.Errorf("got %v", err)
		}
		_ = mid
	})
	t.Run("sealed key exists", func(t *testing.T) {
		mid, kp, u := keptFixture(t)
		mid.put(ref("w.payment", ports.AddrSKey), kp.skey)
		if _, err := u.Run(ctx, "w.payment", sec("Str0ng-Passw0rd!-And-Long")); !errors.Is(err, ErrConvertDestination) {
			t.Errorf("got %v", err)
		}
	})
}

type unsupportedDeriver struct{}

func (unsupportedDeriver) DeriveVerificationKey(context.Context, *ports.Secret) ([]byte, error) {
	return nil, ports.ErrKeyTypeUnsupported
}
