// Package workspace moves an operator between an upstream script directory
// and the sealed store: ImportWorkspace reads a directory in the layout of
// spec/upstream/patterns/Pfiles.md and seals every artefact it recognises;
// ExportWorkspace is the reverse and is a dangerous, audited operation;
// ProtectKey and UnprotectKey convert one signing key file between upstream's
// plaintext and gpg-wrapped forms (01_protectKey).
//
// Secret material stays in guarded memory from the moment it is read; no
// report, error or audit record holds any of it.
package workspace

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Errors a caller can test for. None names a key or a password.
var (
	ErrPasswordRequired       = errors.New("an encrypted key needs the password (or keep it encrypted)")
	ErrWeakPassword           = errors.New("the password is not strong: at least 10 characters with a lower-case letter, an upper-case letter, a digit and a special character")
	ErrShortExportPassword    = errors.New("the export password is too short: an export needs at least 20 characters (and the strength rule), because gpg's key derivation is not memory-hard; use --generate-password")
	ErrExportPasswordRequired = errors.New("an export writes signing keys in upstream's encrypted form only and needs the password to encrypt them")
	ErrNoSuchOwner            = errors.New("no such pool or wallet in the source")
	ErrNoAuditor              = errors.New("an audit sink is required for a dangerous operation")
	ErrNotAKeyFile            = errors.New("the file is not a signing key envelope")
	ErrVerifyFailed           = errors.New("the encrypted key did not decrypt back to the original; nothing was written")
)

// Status of one artefact in a report.
type Status string

const (
	// StatusDone means the artefact was written to the destination.
	StatusDone Status = "done"
	// StatusSkipped means it was left out, with the reason given.
	StatusSkipped Status = "skipped"
	// StatusFailed means it could not be processed; its owner was not written.
	StatusFailed Status = "failed"
	// StatusPlanned means a dry run found it would be written.
	StatusPlanned Status = "planned"
)

// ArtefactReport is the outcome for one artefact. Reason and Note are fixed
// phrases of this package, never content of a file.
type ArtefactReport struct {
	Ref    ports.NamedRef
	Status Status
	Reason string
	// Note carries a remark on a done artefact: a check that could not be
	// made, or that the key was kept in upstream's encrypted form.
	Note string
	// To is the reference the artefact is stored under when the owner is
	// imported under another name; zero when it is the same as Ref.
	To ports.NamedRef
}

// OwnerReport is the outcome for one pool or wallet. A destination is
// written for all of an owner's artefacts or none of them.
type OwnerReport struct {
	Owner     string
	Written   bool
	Reason    string // why nothing was written, when it was not
	Artefacts []ArtefactReport

	// The fields below are set by a selective import (ImportWorkspace.Import).
	// Kind is "pool", "wallet" or "other"; Dir the source directory; Final the
	// name the owner is stored under; Would reports, in a dry run, that the
	// owner would be written. Rewrites lists the descriptor fields changed
	// (SPO-Xmulti-OUT-003). The strings are taken from the source: print them
	// through a text-safe writer.
	Kind     OwnerKind
	Dir      string
	Final    string
	Would    bool
	Rewrites []Rewrite
	// Collision: refused because another selected owner has the same stored
	// name.
	Collision bool
}

// Rewrite is one field of a pool descriptor changed on import.
type Rewrite struct {
	Pool  string // the pool, by its final name
	Field string
	Old   string
	New   string
}

// FoundOwner is an owner discovered in a source directory and not selected.
type FoundOwner struct {
	Kind      OwnerKind
	Name, Dir string
	Artefacts []ports.NamedRef
}

// Report is the result of an import or an export.
type Report struct {
	Operation string // "import" or "export"
	Owners    []OwnerReport
	// Unknown lists files the source holds that are no artefact of the
	// catalogue. They are never imported.
	Unknown []ports.SourceUnknown
	// Warnings are remarks about the run as a whole.
	Warnings []string
	// DryRun: nothing was written; Owners say what would be.
	DryRun bool
	// Extended: the request was a selective import, so a table shows the
	// source directory and the stored name.
	Extended bool
	// Found lists the owners discovered and not selected.
	Found []FoundOwner
}

// Failed counts the owners that were not written.
func (r *Report) Failed() int {
	n := 0
	for _, o := range r.Owners {
		if !o.Written && !(r.DryRun && o.Would) {
			n++
		}
	}
	return n
}

// Done counts the artefacts written.
func (r *Report) Done() int {
	n := 0
	for _, o := range r.Owners {
		if !o.Written && !(r.DryRun && o.Would) {
			continue
		}
		for _, a := range o.Artefacts {
			if a.Status == StatusDone || a.Status == StatusPlanned {
				n++
			}
		}
	}
	return n
}

var (
	reTimestamp = regexp.MustCompile(`_\d{12}$`)
)

// OwnerOf names the pool, wallet or other owner an artefact belongs to, so
// everything of one owner is written together. A wallet made by 03a has its
// payment account under `<w>.payment` and its stake account under `<w>`: both
// belong to `<w>`.
//
// spec: SPO-Pfiles-IN-003
func OwnerOf(r ports.NamedRef) string {
	n := r.Name
	switch r.Kind {
	case ports.AddrFile, ports.AddrVKey, ports.AddrSKey, ports.AddrHwsFile:
		return strings.TrimSuffix(n, ".payment")
	case ports.PoolWitnessFile:
		// <pool>_<slot>_<witnessId>
		for i := 0; i < 2; i++ {
			if k := strings.LastIndex(n, "_"); k > 0 {
				n = n[:k]
			}
		}
		return n
	case ports.VoteDRepFile, ports.VoteCCHotFile, ports.VotePoolFile, ports.GovActionFile, ports.VoteRegistration, ports.CalidusRegistration:
		if reTimestamp.MatchString(n) {
			if k := strings.Index(n, "_"); k > 0 {
				return n[:k]
			}
		}
		return n
	case ports.AssetFile:
		if k := strings.Index(n, "."); k > 0 {
			return n[:k]
		}
	case ports.UpstreamEncryptedSKey:
		if ref, ok := SKeyRefFromStem(n); ok {
			return OwnerOf(ref)
		}
	}
	return n
}

// KeyStem is the file name of a signing key without its `.skey`, which names
// an upstream-encrypted record: `<pool>.node`, `<wallet>.payment`.
func KeyStem(r ports.NamedRef) (string, bool) {
	role, ok := ports.SigningKeyKinds()[r.Kind]
	if !ok {
		return "", false
	}
	if r.Kind.Numbered() {
		return r.Name + fmt.Sprintf(role.Role, r.Num), true
	}
	return r.Name + role.Role, true
}

var reKesStem = regexp.MustCompile(`^(.+)\.kes-(\d+)$`)

// SKeyRefFromStem is the reverse of KeyStem. A stem with no known role is a
// plain payment key.
func SKeyRefFromStem(stem string) (ports.NamedRef, bool) {
	if m := reKesStem.FindStringSubmatch(stem); m != nil {
		var n int
		if _, err := fmt.Sscanf(m[2], "%d", &n); err == nil {
			r := ports.NamedRef{Name: m[1], Kind: ports.KesSKey, Num: n}
			return r, r.Validate() == nil
		}
	}
	type cand struct {
		kind ports.Kind
		role string
	}
	var cands []cand
	for k, role := range ports.SigningKeyKinds() {
		if role.Role != "" && !k.Numbered() {
			cands = append(cands, cand{k, role.Role})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return len(cands[i].role) > len(cands[j].role) })
	for _, c := range cands {
		if name, ok := strings.CutSuffix(stem, c.role); ok && name != "" {
			r := ports.NamedRef{Name: name, Kind: c.kind}
			return r, r.Validate() == nil
		}
	}
	r := ports.NamedRef{Name: stem, Kind: ports.AddrSKey}
	return r, r.Validate() == nil
}

// passwordSet holds the candidates of one operator password in guarded
// memory and remembers which one opened a key, so one password that opens
// many keys is found at the first try after the first key.
type passwordSet struct {
	cands []*ports.Secret
	good  int
}

func newPasswordSet(pw *ports.Secret) (*passwordSet, error) {
	if pw == nil {
		return nil, nil
	}
	set := &passwordSet{}
	err := pw.Use(func(b []byte) error {
		for _, c := range keyfile.PasswordCandidates(b) {
			buf, err := ports.TakeSecret(c)
			if err != nil {
				return err
			}
			set.cands = append(set.cands, buf)
		}
		return nil
	})
	if err != nil {
		set.destroy()
		return nil, ErrPasswordRequired
	}
	return set, nil
}

func (p *passwordSet) destroy() {
	if p == nil {
		return
	}
	for _, c := range p.cands {
		c.Destroy()
	}
}

// open decrypts with the candidates in turn, the one that worked last first.
// A wrong passphrase moves on to the next candidate; anything else stops.
func (p *passwordSet) open(ctx context.Context, dec ports.KeyDecryptor, encrHex []byte) (*ports.Secret, error) {
	if p == nil || len(p.cands) == 0 {
		return nil, ErrPasswordRequired
	}
	order := make([]int, 0, len(p.cands))
	order = append(order, p.good)
	for i := range p.cands {
		if i != p.good {
			order = append(order, i)
		}
	}
	for _, i := range order {
		out, err := dec.Decrypt(ctx, encrHex, p.cands[i])
		if err == nil {
			p.good = i
			return out, nil
		}
		if !errors.Is(err, ports.ErrWrongPassphrase) {
			return nil, err
		}
	}
	return nil, ports.ErrWrongPassphrase
}

// plainFromDecrypted builds the cardano-cli style plain envelope of a
// decrypted key in guarded memory.
func plainFromDecrypted(enc keyfile.Encrypted, cbor *ports.Secret, indent string) (*ports.Secret, error) {
	desc := keyfile.PlainDescription(enc.Description)
	n := cbor.Len()
	size := keyfile.PlainEnvelopeLen(enc.Type, desc, n, indent)
	return ports.FillSecret(size, func(dst []byte) error {
		return cbor.Use(func(h []byte) error {
			out := keyfile.AppendPlainEnvelope(dst[:0], enc.Type, desc, h, n, indent)
			if len(out) != size {
				return errors.New("internal: envelope size")
			}
			return nil
		})
	})
}

// classifyBuf classifies a key file held in guarded memory.
func classifyBuf(b *ports.Secret) (keyfile.Info, error) {
	var info keyfile.Info
	var cerr error
	err := b.Use(func(d []byte) error {
		info, cerr = keyfile.Classify(d)
		return nil
	})
	if err != nil {
		return keyfile.Info{}, err
	}
	return info, cerr
}
