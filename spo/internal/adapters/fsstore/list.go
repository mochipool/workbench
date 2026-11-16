package fsstore

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// File names and modes of the artefact families that other files of this
// package do not name: BLS keys, minting policies and assets, Catalyst voting
// keys, Calidus keys, and the upstream-encrypted key record.
//
// spec: SPO-Pfiles-OUT-016, SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032, SPO-Pfiles-OUT-033, SPO-Pfiles-OUT-034, SPO-Pfiles-OUT-035, SPO-Pfiles-OUT-036, SPO-Pfiles-INV-004
func init() {
	for k, ext := range map[ports.Kind]string{
		ports.BLSVKey: ".bls.vkey", ports.BLSSKey: ".bls.skey",
		ports.PolicyVKey: ".policy.vkey", ports.PolicySKey: ".policy.skey", ports.PolicyHwsFile: ".policy.hwsfile",
		ports.PolicyScript: ".policy.script", ports.PolicyID: ".policy.id", ports.AssetFile: ".asset",
		ports.TokenRegistration: ".json",
		ports.VotingVKey:        ".voting.vkey", ports.VotingSKey: ".voting.skey", ports.VotingHwsFile: ".voting.hwsfile",
		ports.VotingPKey: ".voting.pkey", ports.VotingMnemonics: ".voting.mnemonics",
		ports.CatalystQRCode: ".catalyst-qrcode.png", ports.VoteRegistration: ".vote-registration.cbor",
		ports.CalidusVKey: ".calidus.vkey", ports.CalidusSKey: ".calidus.skey", ports.CalidusHwsFile: ".calidus.hwsfile",
		ports.CalidusMnemonics: ".calidus.mnemonics", ports.CalidusID: ".calidus.id",
		ports.CalidusRegistration:   ".calidus-registration.json",
		ports.UpstreamEncryptedSKey: ".upstream-encrypted.skey",
	} {
		ext := ext
		layout[k] = func(r ports.Ref) string { return r.Name + ext }
	}
	// The Catalyst QR code is secret and so is written by PutSecret at 0400,
	// stricter than upstream's default mode (SPO-Pfiles-INV-004) on purpose.
	for _, k := range []ports.Kind{ports.VoteRegistration, ports.CalidusRegistration, ports.TokenRegistration} {
		modes[k] = 0o644
	}
}

// notUpstream are layout entries that belong to this program's own records,
// not to an upstream workspace; a listing leaves them out.
var notUpstream = map[ports.Kind]bool{
	ports.PartyKeys: true, ports.PartyIdentity: true, ports.PartyRecords: true, ports.PartyReplay: true,
	ports.TailcatNodeKey: true, ports.TailcatPSK: true, ports.TailcatAddr: true,
	ports.MultisigCoordinator: true, ports.MultisigSigner: true, ports.MultisigOutbox: true,
	ports.MultisigEvents: true, ports.MultisigCollection: true, ports.MultisigSubmitted: true,
	ports.UpstreamEncryptedSKey: false,
}

var subjectName = regexp.MustCompile(`^[0-9a-f]{56,}$`)

type pattern struct {
	kind     ports.Kind
	re       *regexp.Regexp
	numbered bool
	literal  int // length of the fixed part of the file name; longer is more specific
}

var (
	patternsOnce sync.Once
	patterns     []pattern
)

func buildPatterns() {
	const nameMark, numMark = "@NAME@", 424242
	for k, fn := range layout {
		if notUpstream[k] {
			continue
		}
		sample := fn(ports.Ref{Name: nameMark, Kind: k, Num: numMark})
		q := regexp.QuoteMeta(sample)
		q = strings.Replace(q, regexp.QuoteMeta(nameMark), `(.+)`, 1)
		numbered := k.Numbered()
		if numbered {
			q = strings.Replace(q, strconv.Itoa(numMark), `(\d+)`, 1)
		}
		lit := len(sample) - len(nameMark)
		if numbered {
			lit -= len(strconv.Itoa(numMark))
		}
		patterns = append(patterns, pattern{kind: k, re: regexp.MustCompile("^" + q + "$"), numbered: numbered, literal: lit})
	}
	sort.Slice(patterns, func(i, j int) bool {
		if patterns[i].literal != patterns[j].literal {
			return patterns[i].literal > patterns[j].literal
		}
		return patterns[i].kind < patterns[j].kind
	})
}

// RefOf maps an upstream file name to the artefact it holds. The most
// specific name pattern wins (`w.node.skey` is a node key, not a payment key
// named `w.node`); a name that does not render back to the same file name, or
// that Ref.Validate refuses, is not an artefact.
//
// spec: SPO-Pfiles-IN-001, SPO-Pfiles-IN-003
func RefOf(file string) (ports.Ref, bool) {
	patternsOnce.Do(buildPatterns)
	for _, p := range patterns {
		m := p.re.FindStringSubmatch(file)
		if m == nil {
			continue
		}
		ref := ports.Ref{Name: m[1], Kind: p.kind}
		if p.numbered {
			n, err := strconv.Atoi(m[2])
			if err != nil {
				continue
			}
			ref.Num = n
		}
		if p.kind == ports.TokenRegistration && !subjectName.MatchString(ref.Name) {
			continue
		}
		if ref.Validate() != nil || layout[p.kind](ref) != file {
			continue
		}
		return ref, true
	}
	return ports.Ref{}, false
}

// reasonFor explains why a file is not an artefact, when it is a file the
// catalogue knows of but a workspace does not hold.
func reasonFor(file string) string {
	switch {
	case file == ".spo-workspace-audit.json" || file == "spo-workspace-audit.json":
		return "this program's own audit log of the directory (spo key unprotect), not an artefact"
	case file == "offlineTransfer.json":
		return "the offline transfer bag (Ptransfer), not part of a workspace"
	case strings.HasSuffix(file, ".witness"), strings.HasSuffix(file, ".txbody"), strings.HasSuffix(file, ".tx"), strings.HasSuffix(file, ".txwitness"):
		return "a transaction or witness file that is not in the catalogue of a workspace"
	}
	return "not an artefact of the upstream catalogue"
}

// List implements ports.SourceLister: every regular file of the directory
// that the name mapping recognises, and the rest as unknown. Directories,
// symbolic links and special files are never followed; this program's own
// temporary files are skipped.
func (s *Store) List(ctx context.Context) (ports.SourceListing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return ports.SourceListing{}, err
	}
	var out ports.SourceListing
	for _, e := range ents {
		if err := ctx.Err(); err != nil {
			return ports.SourceListing{}, err
		}
		name := e.Name()
		if strings.HasPrefix(name, ".spo-tmp-") {
			continue
		}
		switch {
		case e.Type()&os.ModeSymlink != 0:
			out.Unknown = append(out.Unknown, ports.SourceUnknown{File: name, Reason: "a symbolic link is never followed"})
			continue
		case e.IsDir():
			out.Unknown = append(out.Unknown, ports.SourceUnknown{File: name, Reason: "a directory"})
			continue
		case !e.Type().IsRegular():
			out.Unknown = append(out.Unknown, ports.SourceUnknown{File: name, Reason: "not a regular file"})
			continue
		}
		ref, ok := RefOf(name)
		if !ok {
			out.Unknown = append(out.Unknown, ports.SourceUnknown{File: name, Reason: reasonFor(name)})
			continue
		}
		out.Entries = append(out.Entries, ports.SourceEntry{Ref: ref})
	}
	return out, nil
}

// FileName returns the upstream file name of a reference, for reports and
// for tests that compare directories.
func FileName(r ports.Ref) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	fn, ok := layout[r.Kind]
	if !ok {
		return "", fmt.Errorf("%w: %s has no upstream file name", ports.ErrInvalidRef, r.Kind)
	}
	return fn(r), nil
}

var _ ports.SourceLister = (*Store)(nil)
