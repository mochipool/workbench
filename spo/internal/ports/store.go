package ports

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Kind names a type of artefact. The catalogue is spec/upstream/patterns/Pfiles.md;
// kinds are added here as use cases need them.
type Kind string

// Pool artefacts (SPO-Pfiles-OUT-010 to OUT-015).
const (
	NodeVKey       Kind = "node.vkey"
	NodeSKey       Kind = "node.skey"
	NodeCounter    Kind = "node.counter"
	NodeHwsFile    Kind = "node.hwsfile" // hardware signing file of the cold key; not secret (SPO-Pfiles-OUT-010)
	VrfVKey        Kind = "vrf.vkey"
	VrfSKey        Kind = "vrf.skey"
	KesVKey        Kind = "kes.vkey"         // numbered
	KesSKey        Kind = "kes.skey"         // numbered
	KesCounter     Kind = "kes.counter"      // newest generated KES key number
	KesCounterNext Kind = "kes.counter-next" // number the next KES key must have
	OpCert         Kind = "node.opcert"      // numbered
	KesExpire      Kind = "kes-expire.json"
)

type kindInfo struct {
	secret   bool
	numbered bool
}

var kinds = map[Kind]kindInfo{
	NodeVKey: {}, NodeSKey: {secret: true}, NodeCounter: {}, NodeHwsFile: {},
	VrfVKey: {}, VrfSKey: {secret: true},
	KesVKey: {numbered: true}, KesSKey: {secret: true, numbered: true},
	KesCounter: {}, KesCounterNext: {},
	OpCert: {numbered: true}, KesExpire: {},
}

// Known reports whether k is in the catalogue.
func (k Kind) Known() bool { _, ok := kinds[k]; return ok }

// Secret reports whether artefacts of this kind hold secret material
// (SPO-Pfiles-SEC-001). Secret artefacts are written with PutSecret and read
// only through Vault.
func (k Kind) Secret() bool { return kinds[k].secret }

// Numbered reports whether artefacts of this kind carry a sequence number.
func (k Kind) Numbered() bool { return kinds[k].numbered }

// Ref identifies one artefact: the operator's name for its owner (a pool, a
// wallet), the kind, and a sequence number for numbered kinds.
type Ref struct {
	Name string
	Kind Kind
	Num  int
}

func (r Ref) String() string {
	if r.Kind.Numbered() {
		return fmt.Sprintf("%s/%s#%d", r.Name, r.Kind, r.Num)
	}
	return fmt.Sprintf("%s/%s", r.Name, r.Kind)
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)*$`)

// Validate checks a reference before it reaches any adapter. A name is a
// plain label: no path separators, no leading dot, no shell or jq syntax
// (hazard H7).
func (r Ref) Validate() error {
	if !r.Kind.Known() {
		return fmt.Errorf("%w: unknown artefact kind %q", ErrInvalidRef, r.Kind)
	}
	if len(r.Name) > 128 || !nameRE.MatchString(r.Name) {
		return fmt.Errorf("%w: name %q must be letters, digits, '-', '_' and single dots", ErrInvalidRef, r.Name)
	}
	if r.Num < 0 || (!r.Kind.Numbered() && r.Num != 0) {
		return fmt.Errorf("%w: bad sequence number %d for %s", ErrInvalidRef, r.Num, r.Kind)
	}
	return nil
}

// Errors of the Store and Vault ports.
var (
	ErrNotFound   = errors.New("artefact not found")
	ErrInvalidRef = errors.New("invalid artefact reference")
	ErrSecretKind = errors.New("secret artefacts are read through the vault and written with PutSecret")
	ErrConflict   = errors.New("the workspace changed during the operation")
)

// Reader reads artefacts inside a View or Update.
type Reader interface {
	// Get returns a non-secret artefact, or ErrNotFound.
	Get(ref Ref) ([]byte, error)
	// Exists reports whether an artefact of any kind is present.
	Exists(ref Ref) (bool, error)
}

// Writer changes artefacts inside an Update. Nothing is visible to others
// until Update returns nil.
type Writer interface {
	Reader
	Put(ref Ref, data []byte) error
	// PutSecret stores secret material. The buffer stays owned by the caller.
	PutSecret(ref Ref, s *secret.Buffer) error
	Delete(ref Ref) error
}

// Store persists artefacts. An Update commits all of its writes or none
// (hazard H10; upstream leaves orphans, SPO-04c-PRE-004).
type Store interface {
	View(ctx context.Context, fn func(Reader) error) error
	Update(ctx context.Context, fn func(Writer) error) error
}

// Vault releases secret material to the adapters that sign or export. Use
// cases never call it: they pass references to a Signer.
type Vault interface {
	// Open returns the secret in guarded memory. The caller destroys it.
	Open(ctx context.Context, ref Ref) (*secret.Buffer, error)
}
