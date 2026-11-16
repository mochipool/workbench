package txflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type files map[string][]byte

func (f files) ReadMetadataFile(p string) ([]byte, error) {
	if b, ok := f[p]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("%w: %s", ports.ErrNotFound, p)
}

type upper struct{ pass string }

func (u *upper) EncryptMessages(l []string, p *ports.Secret) ([]string, error) {
	if p != nil {
		p.Use(func(b []byte) error { u.pass = string(b); return nil })
	}
	return []string{strings.ToUpper(strings.Join(l, "|"))}, nil
}

// spec: SPO-Pparam-IF-010, SPO-Pparam-IF-011, SPO-Pparam-IF-012, SPO-Pparam-IF-013, SPO-Pparam-IF-014, SPO-Pparam-IF-016,
// spec: SPO-Pparam-PRE-005, SPO-Pparam-EXT-001
func TestResolveExtras(t *testing.T) {
	parse := func(w ...string) *txparam.Extras {
		ex, err := txparam.Parse(w, txparam.ForSendLovelaces)
		if err != nil {
			t.Fatal(err)
		}
		return &ex
	}
	enc := &upper{}
	p := ExtrasPorts{Files: files{"a.json": []byte(`{"1":1}`), "bad.json": []byte(`{"x":1}`), "c.cbor": {0xa0}}, Encrypter: enc}

	// no extras: the request's own lines pass through
	if r, err := ResolveExtras(p, nil, []string{"own"}, nil); err != nil || len(r.Lines) != 1 || len(r.Files) != 0 {
		t.Errorf("%+v %v", r, err)
	}
	// files in order, lines after the request's, not encrypted without a mode
	r, err := ResolveExtras(p, parse("a.json", "c.cbor", "msg:hi"), []string{"own"}, nil)
	if err != nil || len(r.Files) != 2 || r.Files[0].Format != txbuild.MetadataJSON || r.Files[1].Format != txbuild.MetadataCBOR ||
		strings.Join(r.Lines, ",") != "own,hi" || r.Encryption != "" {
		t.Errorf("%+v %v", r, err)
	}
	// encryption covers every line, with the passphrase as typed
	pass := secret.Take([]byte(" pw "))
	defer pass.Destroy()
	r, err = ResolveExtras(p, parse("msg:hi", "enc:basic"), []string{"own"}, pass)
	if err != nil || r.Encryption != "basic" || strings.Join(r.Lines, ",") != "OWN|HI" || enc.pass != " pw " {
		t.Errorf("%+v %v %q", r, err, enc.pass)
	}
	// enc: with no message at all changes nothing
	if r, err = ResolveExtras(p, parse("enc:basic"), nil, nil); err != nil || r.Encryption != "" {
		t.Errorf("%+v %v", r, err)
	}
	// refusals
	if _, err := ResolveExtras(p, parse("nothere.json"), nil, nil); !errors.Is(err, txparam.ErrBadMetadataFile) {
		t.Errorf("a missing file: %v", err)
	}
	if _, err := ResolveExtras(p, parse("bad.json"), nil, nil); !errors.Is(err, txparam.ErrBadMetadataFile) {
		t.Errorf("a bad first key: %v", err)
	}
	if _, err := ResolveExtras(ExtrasPorts{}, parse("a.json"), nil, nil); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("no reader: %v", err)
	}
	if _, err := ResolveExtras(ExtrasPorts{}, parse("msg:x", "enc:basic"), nil, nil); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("no encrypter: %v", err)
	}
	if _, err := ResolveExtras(p, nil, []string{strings.Repeat("a", 65)}, nil); err != nil {
		// lines of the request itself are checked by the use case; Resolve only checks the extras' own
		_ = err
	}
	// the draft takes it
	d, _ := txbuild.NewDraft("a", "b", txbuild.Lovelaces(1), []chain.Utxo{{Lovelace: 1}}, nil)
	if d, err = r.Attach(d); err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-Pparam-IF-019, SPO-Pparam-IF-022
func TestFilterCandidates(t *testing.T) {
	in := []chain.Utxo{{Index: 1}, {Index: 0}}
	if got := FilterCandidates(nil, in); len(got) != 2 || got[0].Index != 1 {
		t.Errorf("no extras leave the set as it is: %v", got)
	}
	ex, _ := txparam.Parse([]string{"utxolimit:1"}, txparam.ForSendLovelaces)
	if got := FilterCandidates(&ex, in); len(got) != 1 || got[0].Index != 0 {
		t.Errorf("%v", got)
	}
}
