package governance

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fakeGen struct{ n int }

func (g *fakeGen) pair(typ string) (ports.KeyPair, error) {
	g.n++
	pub, _, _ := ed25519.GenerateKey(nil)
	v := fmt.Sprintf(`{"type": %q, "description": "d", "cborHex": "5820%x"}`+"\n", typ, []byte(pub))
	return ports.KeyPair{VKey: []byte(v), SKey: secret.Take([]byte(`{"type":"s","cborHex":"5820aa"}`))}, nil
}
func (g *fakeGen) GenerateDRep(context.Context) (ports.KeyPair, error) {
	return g.pair("DRepVerificationKey_ed25519")
}
func (g *fakeGen) GenerateCommitteeCold(context.Context) (ports.KeyPair, error) {
	return g.pair("ConstitutionalCommitteeColdVerificationKey_ed25519")
}
func (g *fakeGen) GenerateCommitteeHot(context.Context) (ports.KeyPair, error) {
	return g.pair("ConstitutionalCommitteeHotVerificationKey_ed25519")
}
func (g *fakeGen) DeriveDRep(_ context.Context, m *secret.Buffer, a, i uint32) (ports.KeyPair, error) {
	return g.pair(fmt.Sprintf("derived-3-%d-%d", a, i))
}
func (g *fakeGen) DeriveCommitteeCold(_ context.Context, m *secret.Buffer, a, i uint32) (ports.KeyPair, error) {
	return g.pair(fmt.Sprintf("derived-4-%d-%d", a, i))
}
func (g *fakeGen) DeriveCommitteeHot(_ context.Context, m *secret.Buffer, a, i uint32) (ports.KeyPair, error) {
	return g.pair(fmt.Sprintf("derived-5-%d-%d", a, i))
}
func (g *fakeGen) GenerateMnemonic(context.Context) (*secret.Buffer, error) {
	return secret.Take([]byte(strings.TrimSpace(strings.Repeat("abandon ", 23)) + " art")), nil
}

func emptyStore() *memStore {
	l := &log{}
	return &memStore{l: l, files: map[ports.Ref][]byte{}, secrets: map[ports.Ref][]byte{}}
}

// A random DRep key pair is stored with its id: the vkey, the sealed skey and
// the id file hold the legacy id, as cardano-cli prints it; the result has
// the three spellings.
//
// spec: SPO-21a-EXT-001, SPO-21a-EXT-005, SPO-21a-INV-003, SPO-21a-IF-001, SPO-Pfiles-OUT-024
// spec: SPO-21a-IN-001
func TestGenerateDRepKeysRandom(t *testing.T) {
	st := emptyStore()
	g := &fakeGen{}
	res, err := GenerateDRepKeys{Store: st, Keys: g}.Run(context.Background(), GenerateKeysRequest{Name: "./x.id", Source: KeysRandom})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "x" || !strings.HasPrefix(res.IDs.Legacy, "drep1") || len(res.IDs.Legacy) != 56 || len(res.IDs.CIP129) != 58 {
		t.Fatalf("result %+v", res)
	}
	if string(st.files[ports.Ref{Name: "x", Kind: ports.DRepID}]) != res.IDs.Legacy {
		t.Error("the id file holds another form than the legacy id")
	}
	if _, ok := st.secrets[ports.Ref{Name: "x", Kind: ports.DRepSKey}]; !ok {
		t.Error("the signing key is not stored as a secret")
	}
	if _, ok := st.files[ports.Ref{Name: "x", Kind: ports.DRepMnemonics}]; ok || res.MnemonicStored {
		t.Error("a random key has no mnemonics")
	}
}

// A mnemonic key uses the path of its role (3, 4, 5), stores the phrase with
// a newline as a secret, and never returns it.
//
// spec: SPO-21a-INV-002, SPO-21a-OUT-002, SPO-23a-INV-002, SPO-23a-OUT-002, SPO-23b-INV-002, SPO-23b-OUT-002, SPO-21a-IF-004
func TestGenerateGovernanceKeysMnemonic(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		run  func(st ports.Store, g *fakeGen) (ports.Kind, error)
	}{
		{"drep", func(st ports.Store, g *fakeGen) (ports.Kind, error) {
			_, err := GenerateDRepKeys{Store: st, Deriver: g, Mnemonics: g}.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysMnemonic, Account: 1, Index: 2})
			return ports.DRepMnemonics, err
		}},
		{"cold", func(st ports.Store, g *fakeGen) (ports.Kind, error) {
			_, err := GenerateCommitteeColdKeys{Store: st, Deriver: g, Mnemonics: g}.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysMnemonic, Account: 1, Index: 2})
			return ports.CCColdMnemonics, err
		}},
		{"hot", func(st ports.Store, g *fakeGen) (ports.Kind, error) {
			_, err := GenerateCommitteeHotKeys{Store: st, Deriver: g, Mnemonics: g}.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysMnemonic, Account: 1, Index: 2})
			return ports.CCHotMnemonics, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := emptyStore()
			kind, err := tc.run(st, &fakeGen{})
			if err != nil {
				t.Fatal(err)
			}
			m := st.secrets[ports.Ref{Name: "x", Kind: kind}]
			if !strings.HasSuffix(string(m), " art\n") {
				t.Errorf("mnemonics file %q", m)
			}
		})
	}
	// Given words are normalised (case, spaces) and need 24 of them.
	st := emptyStore()
	words := secret.Take([]byte("ABANDON   " + strings.Repeat("abandon ", 22) + "art"))
	if _, err := (GenerateDRepKeys{Store: st, Deriver: &fakeGen{}}).Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysMnemonic, Mnemonic: words}); err != nil {
		t.Fatal(err)
	}
	short := secret.Take([]byte("abandon abandon"))
	if _, err := (GenerateDRepKeys{Store: emptyStore(), Deriver: &fakeGen{}}).Run(ctx, GenerateKeysRequest{Name: "y", Source: KeysMnemonic, Mnemonic: short}); err == nil {
		t.Error("two words are not a mnemonic")
	}
}

// Every existing artefact refuses the generation and nothing is written;
// options of the other key source are refused; a hardware holder is refused
// up front.
//
// spec: SPO-21a-PRE-004, SPO-21a-PRE-005, SPO-21a-PRE-006, SPO-21a-PRE-007, SPO-21a-PRE-001, SPO-21a-IF-004, SPO-23a-PRE-003, SPO-23a-PRE-004
// spec: SPO-21a-PRE-002
func TestGenerateDRepKeysRefusals(t *testing.T) {
	ctx := context.Background()
	for _, k := range []ports.Kind{ports.DRepVKey, ports.DRepSKey, ports.DRepHwsFile, ports.DRepID} {
		st := emptyStore()
		st.files[ports.Ref{Name: "x", Kind: k}] = []byte("x")
		_, err := GenerateDRepKeys{Store: st, Keys: &fakeGen{}}.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysRandom})
		if !errors.Is(err, ErrExists) || st.writes != 0 {
			t.Errorf("%s: %v writes=%d", k, err, st.writes)
		}
	}
	// The mnemonics file counts for the mnemonic source only.
	st := emptyStore()
	st.files[ports.Ref{Name: "x", Kind: ports.DRepMnemonics}] = []byte("x")
	if _, err := (GenerateDRepKeys{Store: st, Keys: &fakeGen{}}).Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysRandom}); err != nil {
		t.Errorf("a random key ignores the mnemonics file: %v", err)
	}
	st = emptyStore()
	st.files[ports.Ref{Name: "x", Kind: ports.DRepMnemonics}] = []byte("x")
	if _, err := (GenerateDRepKeys{Store: st, Deriver: &fakeGen{}, Mnemonics: &fakeGen{}}).Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysMnemonic}); !errors.Is(err, ErrExists) || st.writes != 0 {
		t.Errorf("mnemonics file: %v", err)
	}
	st = emptyStore()
	uc := GenerateDRepKeys{Store: st, Keys: &fakeGen{}, Deriver: &fakeGen{}, Mnemonics: &fakeGen{}}
	if _, err := uc.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysRandom, Account: 1}); !errors.Is(err, ErrOptionNotUsed) {
		t.Errorf("account with a random key: %v", err)
	}
	if _, err := uc.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysMnemonic, Index: MaxDerivationIndex + 1}); !errors.Is(err, ErrDerivationRange) {
		t.Errorf("range: %v", err)
	}
	if _, err := uc.Run(ctx, GenerateKeysRequest{Name: "x", Source: KeysRandom, Holder: custody.HolderHardware}); err == nil {
		t.Errorf("hardware: %v", err)
	}
	if _, err := uc.Run(ctx, GenerateKeysRequest{Name: "a/b", Source: KeysRandom}); !errors.Is(err, ErrBadWord) {
		t.Errorf("directory part: %v", err)
	}
	if st.writes != 0 {
		t.Errorf("a refusal wrote %d artefacts", st.writes)
	}
}

// The era gate is an error where upstream exits 0.
//
// spec: SPO-21a-PRE-003, SPO-23a-PRE-002, SPO-23b-PRE-002
// spec: SPO-23a-PRE-001, SPO-23b-PRE-001, SPO-23b-PRE-003
func TestGenerateKeysEraGate(t *testing.T) {
	r := newRig(t)
	r.chain.params.ProtocolMajor = 8
	st := emptyStore()
	if _, err := (GenerateDRepKeys{Store: st, Keys: &fakeGen{}, Params: r.chain}).Run(context.Background(), GenerateKeysRequest{Name: "x", Source: KeysRandom}); !errors.Is(err, ErrProtocolTooOld) || st.writes != 0 {
		t.Fatalf("got %v", err)
	}
}

// Committee cold and hot keys write the hash file with a newline, as
// `governance committee key-hash` prints it, and the ids in both forms.
//
// spec: SPO-23a-EXT-005, SPO-23a-INV-003, SPO-23b-EXT-005, SPO-23b-INV-003, SPO-Pfiles-OUT-027
// spec: SPO-23a-IF-001, SPO-23b-IF-001
func TestGenerateCommitteeKeysWriteHash(t *testing.T) {
	ctx := context.Background()
	st := emptyStore()
	cold, err := GenerateCommitteeColdKeys{Store: st, Keys: &fakeGen{}}.Run(ctx, GenerateKeysRequest{Name: "m.hash", Source: KeysRandom})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(st.files[ports.Ref{Name: "m", Kind: ports.CCColdHash}]); got != cold.IDs.Hex+"\n" || !strings.HasPrefix(cold.IDs.Legacy, "cc_cold1") {
		t.Errorf("hash file %q, ids %+v", got, cold.IDs)
	}
	hot, err := GenerateCommitteeHotKeys{Store: st, Keys: &fakeGen{}}.Run(ctx, GenerateKeysRequest{Name: "m", Source: KeysRandom})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hot.IDs.Legacy, "cc_hot1") || len(hot.IDs.CIP129) != 60 {
		t.Errorf("hot ids %+v", hot.IDs)
	}
}

// An existing hot key is replaced only on request, and the replacement removes
// the signing key too (upstream's replace removes the vkey twice and leaves
// the skey, SPO-23b-PR-001).
//
// spec: SPO-23b-PR-001, SPO-23b-SEC-004
func TestGenerateCommitteeHotKeysReplace(t *testing.T) {
	ctx := context.Background()
	st := emptyStore()
	for _, k := range []ports.Kind{ports.CCHotVKey, ports.CCHotHash, ports.CCHotHwsFile} {
		st.files[ports.Ref{Name: "m", Kind: k}] = []byte("old")
	}
	st.secrets[ports.Ref{Name: "m", Kind: ports.CCHotSKey}] = []byte("old")
	uc := GenerateCommitteeHotKeys{Store: st, Keys: &fakeGen{}}
	if _, err := uc.Run(ctx, GenerateKeysRequest{Name: "m", Source: KeysRandom}); !errors.Is(err, ErrExists) || st.writes != 0 {
		t.Fatalf("without Replace: %v writes=%d", err, st.writes)
	}
	if _, err := uc.Run(ctx, GenerateKeysRequest{Name: "m", Source: KeysRandom, Replace: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.files[ports.Ref{Name: "m", Kind: ports.CCHotHwsFile}]; ok {
		t.Error("the old hardware file survived")
	}
	if string(st.secrets[ports.Ref{Name: "m", Kind: ports.CCHotSKey}]) == "old" {
		t.Error("the old signing key survived")
	}
	// Replace is for the hot key only.
	if _, err := (GenerateCommitteeColdKeys{Store: emptyStore(), Keys: &fakeGen{}}).Run(ctx, GenerateKeysRequest{Name: "m", Source: KeysRandom, Replace: true}); !errors.Is(err, ErrOptionNotUsed) {
		t.Errorf("replace a cold key: %v", err)
	}
}
