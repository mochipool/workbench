// Package plainstore is a writable store over a directory in the upstream file
// layout (spec/upstream/patterns/Pfiles.md). It is TEST-ONLY.
//
// Signing keys are written as upstream writes them, in clear at mode 0400
// (SPO-Pfiles-SEC-002). The release binary must be unable to do that
// (SPO-Xcustody-INV-001; ADR 0011 (proposed)), so this package lives under
// spo/test, and internal/archtest refuses an import of it from any package that
// is not a test, and from cmd/spo outside a file built with the `plainlayout`
// tag. Open opens a directory only when its spo.toml exists, parses and names a
// network that is not mainnet; absence, an unreadable file and mainnet are all
// refused, and OpenNetwork also refuses the mainnet network magic: no key in
// clear is ever written for real funds.
//
// The store is keyed by anchor identity like the sealed one (ports.Store), and
// the directory stays name-based: an anchor is mapped to a file name at this
// edge. The map is not stored. Each transaction derives the owners of the
// directory from its key files (labels.Derive: the label of an owner is its stem,
// its anchor follows from the keys), and the label, owner, manifest and role
// history records of that view are served as records; those a transaction writes
// are kept for the length of the transaction and not written as files, because
// the files themselves are what a later transaction derives them from. A rename
// moves the files. Use the name-level view with labels.Named(store).
//
// An Update stages every write in memory and applies it on success: each
// file is written to a temporary name and renamed into place. A crash in the
// middle of applying can leave some files updated and others not; a plain
// directory cannot do better. The sealed store commits atomically.
package plainstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/mochipool/workbench/spo/internal/adapters/config"
	"github.com/mochipool/workbench/spo/internal/adapters/upstreamdir"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// MainnetMagic is the network magic of mainnet.
const MainnetMagic = 764824073

// ErrMainnet is the refusal to hold keys in clear for mainnet.
var ErrMainnet = errors.New("plainstore: refused: this directory is for mainnet, and keys in clear are never written there")

// ErrNoNetwork is the refusal of a directory whose network is unknown: it has
// no spo.toml, or one that cannot be read.
var ErrNoNetwork = errors.New("plainstore: refused: the directory has no spo.toml that can be read, so its network is unknown")

// Store is a workspace directory. It is a ports.NamedStore (and NamedVault and
// SourceLister): the commands and use cases of the tests address it by name,
// through the label resolver over the anchor-level store below. Anchor returns
// that store, for the signers and the key index.
type Store struct {
	*labels.Store
	a   *anchored
	src *upstreamdir.Source
}

// Anchor is the anchor-level store of the directory.
func (s *Store) Anchor() Anchored { return s.a }

// AnchorStore implements the optional interface labels.AnchorOf looks for.
func (s *Store) AnchorStore() ports.Store { return s.a }

// Anchored is the anchor-level store of a plain directory: a ports.Store that
// is also a vault.
type Anchored interface {
	ports.Store
	ports.Vault
}

// Subdirs implements ports.SourceTree.
func (s *Store) Subdirs(ctx context.Context) ([]string, error) { return s.src.Subdirs(ctx) }

// Dir is the absolute path of the directory.
func (s *Store) Dir() string { return s.a.dir }

// anchored is the anchor-level store over the directory.
type anchored struct {
	*upstreamdir.Source // the name-level List and Subdirs; View and Open are redefined below
	dir                 string
	mu                  sync.Mutex
}

// OpenNetwork is Open for a caller that also knows the network magic of the
// directory; mainnet's magic is refused here as well, and the directory's own
// spo.toml is checked as in Open.
func OpenNetwork(dir string, magic uint32) (*Store, error) {
	if magic == MainnetMagic {
		return nil, ErrMainnet
	}
	return Open(dir)
}

// OpenTestnet is the test helper for a bare directory. When dir has no
// spo.toml it writes one that names a test network (preview), opens the
// directory through Open, and removes the file it wrote, so a test that lists
// the directory sees only the artefacts. A directory that has an spo.toml is
// opened as it is, so a mainnet one is still refused.
func OpenTestnet(dir string) (*Store, error) {
	if _, err := config.Load(dir); errors.Is(err, os.ErrNotExist) {
		if err := config.Create(dir, config.Config{Network: "preview", Mode: "offline"}); err != nil {
			return nil, err
		}
		defer os.Remove(config.Path(dir))
	}
	return Open(dir)
}

// Open returns a Store over an existing directory. It is the one constructor,
// and it checks the network unconditionally (SPO-Xcustody-SEC-002): the
// directory must hold an spo.toml that can be read and names a network that is
// not mainnet. A missing file, one that cannot be read and one that names
// mainnet are all refused, because the network is then unknown or is the one
// where keys in clear are never written.
func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("plainstore: %s is not a directory", abs)
	}
	c, err := config.Load(abs)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNoNetwork, abs, err)
	}
	if p, ok := config.PresetFor(c.Network); c.Network == "mainnet" || !ok || p.Magic == "mainnet" {
		return nil, ErrMainnet
	}
	src, err := upstreamdir.Open(abs)
	if err != nil {
		return nil, err
	}
	a := &anchored{Source: src, dir: abs}
	return &Store{Store: labels.Named(a), a: a, src: src}, nil
}

func (s *anchored) path(r ports.NamedRef) (string, error) {
	name, err := upstreamdir.FileName(r)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.dir, name), nil
}

type ownerKey struct {
	kind identity.OwnerKind
	name string
}

// snap is the identity-layer view of the directory at the start of a
// transaction.
type snap struct {
	owners      map[identity.Ref]labels.DerivedOwner
	byName      map[ownerKey]identity.Ref
	quarantined map[identity.Ref]string         // anchor of an upstream-encrypted key with no sibling -> its stem
	prov        map[identity.Ref]labels.Label   // provisional anchor -> the label of an owner with no anchoring key
	named       map[identity.Ref]ports.NamedRef // anchor of a named record -> its kind and name
	virtual     map[ports.Ref][]byte
	entries     []ports.SourceEntry
}

func virtualKind(k ports.Kind) bool {
	switch k {
	case ports.Label, ports.OwnerRecord, ports.OwnerManifest, ports.RoleHistory:
		return true
	}
	return false
}

// snapshot reads the directory and derives its owners and labels.
func (s *anchored) snapshot(ctx context.Context) (*snap, error) {
	listing, err := upstreamdir.ListAll(ctx, s.Source)
	if err != nil {
		return nil, err
	}
	var d *labels.Derived
	if err := s.Source.View(ctx, func(r ports.NamedReader) error {
		var e error
		d, e = labels.Derive(r, listing.Entries)
		return e
	}); err != nil {
		return nil, err
	}
	if len(d.Conflicts) > 0 {
		return nil, fmt.Errorf("plainstore: %s holds names that the identity rules refuse: %v", s.dir, d.Texts())
	}
	sn := &snap{owners: map[identity.Ref]labels.DerivedOwner{}, byName: map[ownerKey]identity.Ref{},
		named: map[identity.Ref]ports.NamedRef{}, quarantined: map[identity.Ref]string{}, prov: map[identity.Ref]labels.Label{}, virtual: map[ports.Ref][]byte{}, entries: listing.Entries}
	hist := map[identity.Ref]custody.RoleHistory{}
	for _, o := range d.Owners {
		sn.owners[o.Anchor] = o
		sn.byName[ownerKey{o.Kind, o.Name}] = o.Anchor
		lab := labels.Label{Group: string(o.Kind), Name: o.Name, Anchor: o.Anchor, PaymentStem: o.PaymentStem}
		if err := sn.putLabel(lab); err != nil {
			return nil, err
		}
		m, err := o.Manifest()
		if err != nil {
			return nil, err
		}
		id, err := m.ID()
		if err != nil {
			return nil, err
		}
		mb, err := m.Canonical()
		if err != nil {
			return nil, err
		}
		sn.virtual[ports.Ref{Anchor: id, Kind: ports.OwnerManifest}] = mb
		rb, err := labels.OwnerRec{Kind: o.Kind, Manifest: id}.Encode()
		if err != nil {
			return nil, err
		}
		sn.virtual[ports.Ref{Anchor: o.Anchor, Kind: ports.OwnerRecord}] = rb
		for _, mem := range o.Members {
			if role, ok := labels.RoleOfMember(o.Kind, mem.Role); ok {
				if h, ok := hist[mem.Identity]; ok {
					hist[mem.Identity], _ = h.With(role)
				} else if h, err := custody.NewRoleHistory(mem.Identity, role); err == nil {
					hist[mem.Identity] = h
				}
			}
		}
	}
	for id, h := range hist {
		b, err := h.Canonical()
		if err != nil {
			return nil, err
		}
		sn.virtual[ports.Ref{Anchor: id, Kind: ports.RoleHistory}] = b
	}
	for _, u := range d.Unresolved {
		// a name with records but no key that anchors it is a provisional owner
		prov, err := labels.ProvisionalAnchor(u.Kind, u.Name)
		if err != nil {
			return nil, err
		}
		stem := false
		for _, r := range u.Records {
			if labels.IsPaymentKind(r.Kind) && r.Name != u.Name {
				stem = true
			}
		}
		sn.byName[ownerKey{u.Kind, u.Name}] = prov
		sn.prov[prov] = labels.Label{Group: string(u.Kind), Name: u.Name, Anchor: prov, PaymentStem: stem}
		if err := sn.putLabel(sn.prov[prov]); err != nil {
			return nil, err
		}
	}
	for _, n := range d.Named {
		a, err := identity.NamedAnchor(labels.GroupOf(n.Kind), n.Name)
		if err != nil {
			return nil, err
		}
		sn.named[a] = n
		if err := sn.putLabel(labels.Label{Group: labels.GroupOf(n.Kind), Name: n.Name, Anchor: a}); err != nil {
			return nil, err
		}
	}
	for _, e := range listing.Entries {
		if e.Ref.Kind != ports.UpstreamEncryptedSKey {
			continue
		}
		if _, ok := sn.siblingIdentity(e.Ref); ok {
			continue
		}
		a, err := identity.NamedAnchor(string(ports.UpstreamEncryptedSKey), e.Ref.Name)
		if err != nil {
			return nil, err
		}
		sn.quarantined[a] = e.Ref.Name
	}
	return sn, nil
}

// siblingIdentity is the identity of the verification key an upstream-encrypted
// key pairs with, when the directory has it.
func (sn *snap) siblingIdentity(n ports.NamedRef) (identity.Ref, bool) {
	vk := labels.EncryptedSibling(n.Name)
	p := labels.PlacementOf(vk.Kind)
	a, ok := sn.byName[ownerKey{p.Owner, labels.OwnerName(vk.Kind, vk.Name)}]
	if !ok {
		return identity.Ref{}, false
	}
	role, _ := labels.MemberKind(vk.Kind)
	for _, m := range sn.owners[a].Members {
		if m.Role == role && m.Num == uint64(vk.Num) {
			return m.Identity, true
		}
	}
	return identity.Ref{}, false
}

func (sn *snap) putLabel(l labels.Label) error {
	ref, err := l.Record()
	if err != nil {
		return err
	}
	b, err := l.Encode()
	if err != nil {
		return err
	}
	sn.virtual[ref] = b
	return nil
}

type staged struct {
	path   string
	ref    ports.Ref
	data   []byte         // non-secret content
	secret *secret.Buffer // secret content (a private copy)
	delete bool
	mode   os.FileMode // 0 means upstreamdir.ModeLocked
}

type tx struct {
	s        *anchored
	sn       *snap
	writable bool
	virt     map[ports.Ref][]byte // identity-layer records written by this transaction; nil data is a delete
	ops      map[string]*staged
	order    []string
}

var errUnsupported = errors.New("plainstore: the plain directory layout has no place for this kind of record")

// labelsOf returns the labels this transaction can see: those it wrote, and
// those of the directory the transaction did not delete.
func (t *tx) ownerLabel(anchor identity.Ref, owner identity.OwnerKind) (labels.Label, bool) {
	for ref, b := range t.virt {
		if ref.Kind != ports.Label || b == nil {
			continue
		}
		if l, err := labels.ParseLabel(b); err == nil && l.Anchor == anchor && l.Group == string(owner) {
			return l, true
		}
	}
	if l, ok := t.sn.prov[anchor]; ok && l.Group == string(owner) {
		if _, gone := t.virt[mustLabelRef(l.Group, l.Name)]; !gone {
			return l, true
		}
	}
	if o, ok := t.sn.owners[anchor]; ok && o.Kind == owner {
		if _, gone := t.virt[mustLabelRef(string(owner), o.Name)]; !gone {
			return labels.Label{Group: string(owner), Name: o.Name, Anchor: anchor, PaymentStem: o.PaymentStem}, true
		}
	}
	return labels.Label{}, false
}

func mustLabelRef(group, name string) ports.Ref {
	r, err := (labels.Label{Group: group, Name: name, Anchor: identity.Ref{}}).Record()
	if err != nil {
		panic(err)
	}
	return r
}

func (t *tx) namedOf(anchor identity.Ref, kind ports.Kind) (ports.NamedRef, bool) {
	for ref, b := range t.virt {
		if ref.Kind != ports.Label || b == nil {
			continue
		}
		if l, err := labels.ParseLabel(b); err == nil && l.Anchor == anchor && l.Group == labels.GroupOf(kind) {
			return ports.NamedRef{Name: l.Name, Kind: kind}, true
		}
	}
	if n, ok := t.sn.named[anchor]; ok && labels.GroupOf(n.Kind) == labels.GroupOf(kind) {
		return ports.NamedRef{Name: n.Name, Kind: kind}, true
	}
	return ports.NamedRef{}, false
}

// nameOf maps a reference to the file stem it is kept under: the plain
// directory is name-based, and this is where the anchor becomes a name.
func (t *tx) nameOf(r ports.Ref) (ports.NamedRef, error) {
	if err := r.Validate(); err != nil {
		return ports.NamedRef{}, err
	}
	if r.Kind == ports.UpstreamEncryptedSKey {
		if r.Anchor.Is(identity.KindNamedRecord) { // quarantined: no sibling key
			l, ok := t.namedLabel(r.Anchor, string(r.Kind))
			if !ok {
				return ports.NamedRef{}, fmt.Errorf("%w: no label names this record", ports.ErrNotFound)
			}
			return ports.NamedRef{Name: l, Kind: r.Kind, Num: r.Num}, nil
		}
		return t.encryptedName(r)
	}
	p := labels.PlacementOf(r.Kind)
	if p.Class == labels.ClassNamed {
		n, ok := t.namedOf(r.Anchor, r.Kind)
		if !ok {
			return ports.NamedRef{}, fmt.Errorf("%w: no label names this record", ports.ErrNotFound)
		}
		n.Num = r.Num
		return n, nil
	}
	l, ok := t.ownerLabel(r.Anchor, p.Owner)
	if !ok {
		return ports.NamedRef{}, fmt.Errorf("%w: no label names this owner", ports.ErrNotFound)
	}
	stem := l.Name
	if labels.IsPaymentKind(r.Kind) {
		stem = labels.PaymentStem(l.Name, l.PaymentStem)
	}
	return ports.NamedRef{Name: stem, Kind: r.Kind, Num: r.Num}, nil
}

// namedLabel is the name a label of a group gives an anchor.
func (t *tx) namedLabel(anchor identity.Ref, group string) (string, bool) {
	for ref, b := range t.virt {
		if ref.Kind != ports.Label || b == nil {
			continue
		}
		if l, err := labels.ParseLabel(b); err == nil && l.Anchor == anchor && l.Group == group {
			return l.Name, true
		}
	}
	if n, ok := t.sn.quarantined[anchor]; ok {
		return n, true
	}
	return "", false
}

// encryptedName is the stem of an upstream-encrypted signing key: the key is
// keyed by the identity of its verification key, which an owner lists.
func (t *tx) encryptedName(r ports.Ref) (ports.NamedRef, error) {
	notFound := fmt.Errorf("%w: no owner lists the verification key", ports.ErrNotFound)
	for _, o := range t.sn.owners {
		for _, m := range o.Members {
			if m.Identity != r.Anchor {
				continue
			}
			l, ok := t.ownerLabel(o.Anchor, o.Kind)
			if !ok {
				return ports.NamedRef{}, notFound
			}
			stem, ok := labels.EncryptedStemOf(o.Kind, l.Name, l.PaymentStem, m)
			if !ok {
				return ports.NamedRef{}, notFound
			}
			return ports.NamedRef{Name: stem, Kind: r.Kind}, nil
		}
	}
	// an owner created by this transaction
	for ref, b := range t.virt {
		if ref.Kind != ports.OwnerManifest || b == nil {
			continue
		}
		m, err := identity.ParseManifest(b)
		if err != nil {
			continue
		}
		for _, mem := range m.Members() {
			if mem.Identity != r.Anchor {
				continue
			}
			l, ok := t.ownerLabel(m.Anchor(), m.Owner())
			if !ok {
				return ports.NamedRef{}, notFound
			}
			stem, ok := labels.EncryptedStemOf(m.Owner(), l.Name, l.PaymentStem, mem)
			if !ok {
				return ports.NamedRef{}, notFound
			}
			return ports.NamedRef{Name: stem, Kind: r.Kind}, nil
		}
	}
	return ports.NamedRef{}, notFound
}

func (t *tx) lookup(r ports.Ref) (string, *staged, error) {
	n, err := t.nameOf(r)
	if err != nil {
		return "", nil, err
	}
	p, err := t.s.path(n)
	if err != nil {
		return "", nil, err
	}
	return p, t.ops[p], nil
}

func (t *tx) virtGet(r ports.Ref) ([]byte, bool) {
	if b, ok := t.virt[r]; ok {
		return b, b != nil
	}
	b, ok := t.sn.virtual[r]
	return b, ok
}

func (t *tx) Get(r ports.Ref) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if virtualKind(r.Kind) {
		b, ok := t.virtGet(r)
		if !ok {
			return nil, ports.ErrNotFound
		}
		return append([]byte(nil), b...), nil
	}
	if r.Kind.Secret() {
		return nil, ports.ErrSecretKind
	}
	p, st, err := t.lookup(r)
	if err != nil {
		return nil, err
	}
	if st != nil {
		if st.delete {
			return nil, ports.ErrNotFound
		}
		return append([]byte(nil), st.data...), nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	return b, err
}

func (t *tx) Exists(r ports.Ref) (bool, error) {
	if err := r.Validate(); err != nil {
		return false, err
	}
	if virtualKind(r.Kind) {
		_, ok := t.virtGet(r)
		return ok, nil
	}
	p, st, err := t.lookup(r)
	if errors.Is(err, ports.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if st != nil {
		return !st.delete, nil
	}
	_, err = os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func (t *tx) stage(p string, st *staged) {
	if old, ok := t.ops[p]; ok {
		old.secret.Destroy()
	} else {
		t.order = append(t.order, p)
	}
	st.path = p
	t.ops[p] = st
}

func (t *tx) Put(r ports.Ref, data []byte) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if virtualKind(r.Kind) {
		t.virt[r] = append([]byte{}, data...)
		return nil
	}
	if r.Kind.Secret() {
		return ports.ErrSecretKind
	}
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{ref: r, data: append([]byte(nil), data...), mode: upstreamdir.ModeOf(r.Kind)})
	return nil
}

func (t *tx) PutSecret(r ports.Ref, sec *secret.Buffer) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !r.Kind.Secret() {
		return fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, r.Kind)
	}
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	var cp *secret.Buffer
	if err := sec.Use(func(b []byte) error {
		cp = secret.Take(append([]byte(nil), b...))
		return nil
	}); err != nil {
		return err
	}
	t.stage(p, &staged{ref: r, secret: cp})
	return nil
}

func (t *tx) Delete(r ports.Ref) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if virtualKind(r.Kind) {
		t.virt[r] = nil
		return nil
	}
	p, _, err := t.lookup(r)
	if errors.Is(err, ports.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	t.stage(p, &staged{ref: r, delete: true})
	return nil
}

// OpenSecret implements ports.SecretOpener: the transaction's view of a secret
// file, in guarded memory.
func (t *tx) OpenSecret(r ports.Ref) (*secret.Buffer, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	p, st, err := t.lookup(r)
	if err != nil {
		return nil, err
	}
	if st != nil {
		if st.delete || st.secret == nil {
			return nil, ports.ErrNotFound
		}
		var out *secret.Buffer
		err := st.secret.Use(func(b []byte) error { out = secret.Take(append([]byte(nil), b...)); return nil })
		return out, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return secret.Read(f)
}

// Records implements ports.RecordLister.
func (t *tx) Records(kind ports.Kind) ([]ports.Ref, error) {
	set := map[ports.Ref]bool{}
	if virtualKind(kind) {
		for ref := range t.sn.virtual {
			if ref.Kind == kind {
				set[ref] = true
			}
		}
		for ref, b := range t.virt {
			if ref.Kind != kind {
				continue
			}
			if b == nil {
				delete(set, ref)
			} else {
				set[ref] = true
			}
		}
	} else {
		for _, e := range t.sn.entries {
			if e.Ref.Kind != kind {
				continue
			}
			ref, ok := t.refOfEntry(e.Ref)
			if ok {
				set[ref] = true
			}
		}
		for _, st := range t.ops {
			if st.ref.Kind != kind {
				continue
			}
			if st.delete {
				delete(set, st.ref)
			} else {
				set[st.ref] = true
			}
		}
	}
	out := make([]ports.Ref, 0, len(set))
	for ref := range set {
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Anchor.Compare(out[j].Anchor); c != 0 {
			return c < 0
		}
		return out[i].Num < out[j].Num
	})
	return out, nil
}

func (t *tx) refOfEntry(n ports.NamedRef) (ports.Ref, bool) {
	if n.Kind == ports.UpstreamEncryptedSKey {
		if id, ok := t.sn.siblingIdentity(n); ok {
			return ports.Ref{Anchor: id, Kind: n.Kind, Num: n.Num}, true
		}
		a, err := identity.NamedAnchor(string(n.Kind), n.Name)
		return ports.Ref{Anchor: a, Kind: n.Kind, Num: n.Num}, err == nil
	}
	p := labels.PlacementOf(n.Kind)
	if p.Class == labels.ClassNamed {
		a, err := identity.NamedAnchor(labels.GroupOf(n.Kind), n.Name)
		return ports.Ref{Anchor: a, Kind: n.Kind, Num: n.Num}, err == nil
	}
	a, ok := t.sn.byName[ownerKey{p.Owner, labels.OwnerName(n.Kind, n.Name)}]
	return ports.Ref{Anchor: a, Kind: n.Kind, Num: n.Num}, ok
}

func (t *tx) discard() {
	for _, st := range t.ops {
		st.secret.Destroy()
	}
}

func (s *anchored) begin(ctx context.Context, writable bool) (*tx, error) {
	sn, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	return &tx{s: s, sn: sn, writable: writable, virt: map[ports.Ref][]byte{}, ops: map[string]*staged{}}, nil
}

// View implements ports.Store.
func (s *anchored) View(ctx context.Context, fn func(ports.Reader) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	return fn(t)
}

// renames moves the files of an owner whose label changed in the transaction.
func (t *tx) renames() ([][2]string, error) {
	var out [][2]string
	for ref, b := range t.virt {
		if ref.Kind != ports.Label || b == nil {
			continue
		}
		l, err := labels.ParseLabel(b)
		if err != nil {
			continue
		}
		old, ok := t.sn.owners[l.Anchor]
		if !ok || old.Name == l.Name || string(old.Kind) != l.Group {
			continue
		}
		for _, rec := range old.Records {
			ns := l.Name + strings.TrimPrefix(rec.Name, old.Name)
			from, err := upstreamdir.FileName(rec)
			if err != nil {
				continue
			}
			to, err := upstreamdir.FileName(ports.NamedRef{Name: ns, Kind: rec.Kind, Num: rec.Num})
			if err != nil {
				continue
			}
			out = append(out, [2]string{filepath.Join(t.s.dir, from), filepath.Join(t.s.dir, to)})
		}
	}
	return out, nil
}

// Update implements ports.Store.
func (s *anchored) Update(ctx context.Context, fn func(ports.Writer) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.begin(ctx, true)
	if err != nil {
		return err
	}
	defer t.discard()
	if err := fn(t); err != nil {
		return err
	}
	moves, err := t.renames()
	if err != nil {
		return err
	}
	// Stage every file under a temporary name first, so a failure here
	// leaves the workspace untouched.
	var temps []string
	cleanup := func() {
		for _, tmp := range temps {
			os.Remove(tmp)
		}
	}
	tmpOf := map[string]string{}
	for _, p := range t.order {
		st := t.ops[p]
		if st.delete {
			continue
		}
		tmp, err := writeTemp(p, st)
		if err != nil {
			cleanup()
			return err
		}
		temps = append(temps, tmp)
		tmpOf[p] = tmp
	}
	for _, m := range moves {
		if _, err := os.Lstat(m[0]); err == nil {
			if err := os.Rename(m[0], m[1]); err != nil {
				cleanup()
				return err
			}
		}
	}
	for _, p := range t.order {
		st := t.ops[p]
		if st.delete {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				cleanup()
				return err
			}
			continue
		}
		if err := os.Rename(tmpOf[p], p); err != nil {
			cleanup()
			return err
		}
	}
	return nil
}

func (st *staged) fileMode() os.FileMode {
	if st.mode != 0 {
		return st.mode
	}
	return upstreamdir.ModeLocked
}

// writeTemp writes the staged content beside its destination with the
// locked mode already set, so the rename publishes a finished file.
func writeTemp(dest string, st *staged) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(dest), ".spo-tmp-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if st.secret != nil {
		if _, err := st.secret.WriteTo(f); err != nil {
			return fail(err)
		}
	} else if _, err := f.Write(st.data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Chmod(st.fileMode()); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// Open implements ports.Vault: it reads a signing key file into guarded
// memory.
func (s *anchored) Open(ctx context.Context, r ports.Ref) (*secret.Buffer, error) {
	if !r.Kind.Secret() {
		return nil, fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, r.Kind)
	}
	s.mu.Lock()
	t, err := s.begin(ctx, false)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	n, err := t.nameOf(r)
	if err != nil {
		return nil, err
	}
	p, err := s.path(n)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return secret.Read(f)
}

var (
	_ ports.Store        = (*anchored)(nil)
	_ ports.Vault        = (*anchored)(nil)
	_ ports.RecordLister = (*tx)(nil)
	_ ports.SecretOpener = (*tx)(nil)
	_ ports.NamedStore   = (*Store)(nil)
	_ ports.NamedVault   = (*Store)(nil)
	_ ports.SourceLister = (*Store)(nil)
	_ ports.SourceTree   = (*Store)(nil)
)

// Upstream is OpenTestnet as a cli.Deps.OpenUpstream wants it: the anchor-level
// store of the directory.
func Upstream(dir string) (ports.Store, error) {
	s, err := OpenTestnet(dir)
	if err != nil {
		return nil, err
	}
	return s.Anchor(), nil
}

// List implements ports.SourceLister by the file names of the directory, with the
// files that are no artefact reported as unknown (the name-level view of the
// upstream layout, not a listing of labels).
func (s *Store) List(ctx context.Context) (ports.SourceListing, error) { return s.src.List(ctx) }
