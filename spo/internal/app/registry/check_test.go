package registry

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fakeRegistry struct {
	entry tokenmeta.Entry
	err   error
	asked []string
}

func (f *fakeRegistry) Registry() string { return "registry.test" }
func (f *fakeRegistry) TokenMetadata(_ context.Context, subject string) (tokenmeta.Entry, error) {
	f.asked = append(f.asked, subject)
	return f.entry, f.err
}

// published makes a world with a generated and filled asset and returns what a registry that
// serves the generated file would answer.
func published(t *testing.T) (*world, *fakeRegistry, Generated) {
	t.Helper()
	w := newWorld(t)
	w.policy("tok", 0)
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"}); err != nil {
		t.Fatal(err)
	}
	w.fill("tok.MYTOKEN")
	w.logos["logo.png"] = png
	w.edit("tok.MYTOKEN", map[string]string{"metaLogoPNG": "logo.png"})
	g, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := w.read(g.File)
	e, err := tokenmeta.ParseEntry(b)
	if err != nil {
		t.Fatal(err)
	}
	return w, &fakeRegistry{entry: e}, g
}

func (w *world) check(reg ports.TokenRegistryReader) CheckTokenMetadata {
	return CheckTokenMetadata{Store: w.store, Registry: reg, Logos: w.logos}
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			out[p] = string(b)
		}
		return nil
	})
	return out
}

// spec: SPO-12b-IF-001, SPO-12b-IF-002, SPO-12b-IN-001, SPO-12b-EXT-001, SPO-12b-OUT-001, SPO-12b-OUT-002, SPO-12b-OUT-003, SPO-12b-INV-001
// What 12a generated and a registry serves compares equal: published, signatures verified, no
// property differs, and nothing in the workspace changes.
func TestPublishedEntryMatchesTheRecord(t *testing.T) {
	w, reg, g := published(t)
	before := snapshot(t, w.dir)
	res, err := w.check(reg).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN.asset"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusPublished || !res.Found || !res.HasRecord || res.Subject != g.Subject || res.RegistrySequence != 1 || res.RecordSequence != 1 {
		t.Fatalf("result: %+v", res)
	}
	if !res.Verification.OK {
		t.Errorf("verification: %+v", res.Verification)
	}
	for _, p := range res.Properties {
		if !p.Present || !p.Compared || !p.Match {
			t.Errorf("%s: %+v", p.Property, p)
		}
	}
	if !bytes.Equal(res.Logo, png) || !res.LogoIsPNG {
		t.Error("logo")
	}
	if len(reg.asked) != 1 || reg.asked[0] != g.Subject {
		t.Errorf("asked %v", reg.asked)
	}
	if after := snapshot(t, w.dir); len(after) != len(before) {
		t.Error("the workspace changed")
	} else {
		for k, v := range before {
			if after[k] != v {
				t.Errorf("%s changed", k)
			}
		}
	}
}

// spec: SPO-12b-IF-002, SPO-12b-IN-001
func TestArgumentIsARecordFirstThenASubject(t *testing.T) {
	w, reg, g := published(t)
	res, err := w.check(reg).Run(context.Background(), CheckRequest{Argument: strings.ToUpper(g.Subject)})
	if err != nil {
		t.Fatal(err)
	}
	if res.HasRecord || res.Status != StatusUnlinked || res.Subject != g.Subject || reg.asked[0] != g.Subject {
		t.Errorf("subject argument: %+v", res)
	}
	for _, a := range []string{"", "nothing.here", "zz", g.Subject[:55], g.Subject + strings.Repeat("00", 40), "tok.MYTOKEN.extra.asset"} {
		if _, err := w.check(reg).Run(context.Background(), CheckRequest{Argument: a}); !errors.Is(err, ErrNoSuchAsset) {
			t.Errorf("%q: %v", a, err)
		}
	}
	// A record with no valid subject says to run the generation first.
	w.edit("tok.MYTOKEN", map[string]string{"subject": "nothex"})
	if _, err := w.check(reg).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"}); !errors.Is(err, ErrNoSubject) {
		t.Errorf("bad subject: %v", err)
	}
}

// spec: SPO-12b-PRE-001, SPO-12b-MODE-001
// Offline mode has no registry capability, so the use case refuses before it looks at the
// argument; online and light modes wire the same reader.
func TestNoRegistryRefusesFirst(t *testing.T) {
	w := newWorld(t)
	if _, err := w.check(nil).Run(context.Background(), CheckRequest{Argument: "garbage"}); !errors.Is(err, ErrNoRegistry) {
		t.Errorf("%v", err)
	}
}

// spec: SPO-12b-PRE-002, SPO-12b-EXT-001
func TestNotFoundBehindAheadAndFailure(t *testing.T) {
	w, reg, g := published(t)
	nf := &fakeRegistry{err: ports.ErrTokenNotFound}
	res, err := w.check(nf).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	if err != nil || res.Status != StatusNotFound || res.Found {
		t.Errorf("not found: %v %+v", err, res)
	}
	// The registry is behind: the record was generated again (sequence 2) and not submitted.
	if _, err := w.gen().Run(context.Background(), GenerateRequest{Asset: "tok.MYTOKEN"}); err != nil {
		t.Fatal(err)
	}
	res, err = w.check(reg).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	if err != nil || res.Status != StatusBehind || res.RecordSequence != 2 || res.RegistrySequence != 1 {
		t.Errorf("behind: %v %+v", err, res.Status)
	}
	// The registry is ahead: the record was reset.
	w.edit("tok.MYTOKEN", map[string]string{"sequenceNumber": "0"})
	res, _ = w.check(reg).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	if res.Status != StatusUnlinked {
		t.Errorf("sequence 0: %s", res.Status)
	}
	w.edit("tok.MYTOKEN", map[string]string{"sequenceNumber": "1"})
	e := reg.entry
	for p, a := range e.Props {
		a.Sequence = 5
		e.Props[p] = a
	}
	res, _ = w.check(&fakeRegistry{entry: e}).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	if res.Status != StatusAhead {
		t.Errorf("ahead: %s", res.Status)
	}
	if res.Verification.OK {
		t.Error("an entry whose sequence numbers were changed verified")
	}
	// A failure is an error, never "not found".
	down := &fakeRegistry{err: errors.New("connection refused")}
	if _, err := w.check(down).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"}); err == nil || errors.Is(err, ports.ErrTokenNotFound) {
		t.Errorf("failure: %v", err)
	}
	// An answer for another subject is refused.
	other := reg.entry
	other.Subject = strings.Repeat("cd", 28)
	if _, err := w.check(&fakeRegistry{entry: other}).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"}); !errors.Is(err, ports.ErrRegistryAnswer) {
		t.Errorf("other subject: %v", err)
	}
	_ = g
}

// spec: SPO-12b-OUT-001, SPO-12b-INV-001
// A property that differs from the record is reported; a property the entry lacks shows as absent.
func TestDifferingAndMissingProperties(t *testing.T) {
	w, reg, _ := published(t)
	w.edit("tok.MYTOKEN", map[string]string{"metaName": "Changed", "metaTicker": ""})
	res, err := w.check(reg).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	by := map[tokenmeta.Property]PropertyCheck{}
	for _, p := range res.Properties {
		by[p.Property] = p
	}
	if by[tokenmeta.PropName].Match || by[tokenmeta.PropTicker].Match || !by[tokenmeta.PropURL].Match {
		t.Errorf("%+v", by)
	}
	e := reg.entry
	delete(e.Props, tokenmeta.PropURL)
	res, _ = w.check(&fakeRegistry{entry: e}).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	for _, p := range res.Properties {
		if p.Property == tokenmeta.PropURL && (p.Present || p.Match) {
			t.Errorf("absent url: %+v", p)
		}
	}
	// The logo of the entry is not a PNG: reported, not hidden.
	e = reg.entry
	a := e.Props[tokenmeta.PropLogo]
	a.Value = tokenmeta.Bytes([]byte("GIF89a"))
	e.Props[tokenmeta.PropLogo] = a
	res, _ = w.check(&fakeRegistry{entry: e}).Run(context.Background(), CheckRequest{Argument: "tok.MYTOKEN"})
	if res.LogoIsPNG {
		t.Error("a GIF passed as a PNG")
	}
}
