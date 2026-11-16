// Package fsstore implements ports.Store and ports.Vault over a directory in
// the upstream file layout (spec/upstream/patterns/Pfiles.md).
//
// It exists for parity tests, import and export (concern S4). Signing keys
// are stored as upstream stores them, in plaintext at mode 0400
// (SPO-Pfiles-SEC-002), so the composition root offers this adapter only
// behind an explicit flag.
//
// An Update stages every write in memory and applies it on success: each
// file is written to a temporary name and renamed into place. A crash in the
// middle of applying can leave some files updated and others not; a plain
// directory cannot do better. The sealed store commits atomically.
package fsstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// modeLocked is upstream's file_lock mode. A rewrite replaces the file by
// rename, so no unlock step is needed (SPO-Pfiles-INV-003).
const modeLocked = 0o400

// layout maps a kind to its upstream file name.
// spec: SPO-Pfiles-OUT-010 to SPO-Pfiles-OUT-015, SPO-04c-INV-001
var layout = map[ports.Kind]func(r ports.Ref) string{
	ports.NodeVKey:       func(r ports.Ref) string { return r.Name + ".node.vkey" },
	ports.NodeSKey:       func(r ports.Ref) string { return r.Name + ".node.skey" },
	ports.NodeCounter:    func(r ports.Ref) string { return r.Name + ".node.counter" },
	ports.NodeHwsFile:    func(r ports.Ref) string { return r.Name + ".node.hwsfile" },
	ports.VrfVKey:        func(r ports.Ref) string { return r.Name + ".vrf.vkey" },
	ports.VrfSKey:        func(r ports.Ref) string { return r.Name + ".vrf.skey" },
	ports.KesVKey:        func(r ports.Ref) string { return fmt.Sprintf("%s.kes-%03d.vkey", r.Name, r.Num) },
	ports.KesSKey:        func(r ports.Ref) string { return fmt.Sprintf("%s.kes-%03d.skey", r.Name, r.Num) },
	ports.KesCounter:     func(r ports.Ref) string { return r.Name + ".kes.counter" },
	ports.KesCounterNext: func(r ports.Ref) string { return r.Name + ".kes.counter-next" },
	ports.OpCert:         func(r ports.Ref) string { return fmt.Sprintf("%s.node-%03d.opcert", r.Name, r.Num) },
	ports.KesExpire:      func(r ports.Ref) string { return r.Name + ".kes-expire.json" },

	// spec: SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-004
	ports.AddrFile:       func(r ports.Ref) string { return r.Name + ".addr" },
	ports.AddrVKey:       func(r ports.Ref) string { return r.Name + ".vkey" },
	ports.AddrSKey:       func(r ports.Ref) string { return r.Name + ".skey" },
	ports.AddrHwsFile:    func(r ports.Ref) string { return r.Name + ".hwsfile" },
	ports.StakingAddr:    func(r ports.Ref) string { return r.Name + ".staking.addr" },
	ports.StakingVKey:    func(r ports.Ref) string { return r.Name + ".staking.vkey" },
	ports.StakingSKey:    func(r ports.Ref) string { return r.Name + ".staking.skey" },
	ports.StakingHwsFile: func(r ports.Ref) string { return r.Name + ".staking.hwsfile" },
	ports.StakingCert:    func(r ports.Ref) string { return r.Name + ".staking.cert" },
	// spec: SPO-Pfiles-OUT-006 to SPO-Pfiles-OUT-009 (certificates), SPO-22a-IN-002 (DRep key)
	ports.DelegCert:        func(r ports.Ref) string { return r.Name + ".deleg.cert" },
	ports.VoteDelegCert:    func(r ports.Ref) string { return r.Name + ".vote-deleg.cert" },
	ports.StakingDeregCert: func(r ports.Ref) string { return r.Name + ".staking.dereg-cert" },
	ports.DRepVKey:         func(r ports.Ref) string { return r.Name + ".drep.vkey" },
	// spec: SPO-Pfiles-OUT-005
	ports.PaymentMnemonics: func(r ports.Ref) string { return r.Name + ".payment.mnemonics" },

	// spec: SPO-Pfiles-OUT-017 to SPO-Pfiles-OUT-023 (the pool descriptor, ids, certificates, metadata, witness transfer files)
	ports.PoolDescriptor:         func(r ports.Ref) string { return r.Name + ".pool.json" },
	ports.PoolIDFile:             func(r ports.Ref) string { return r.Name + ".pool.id" },
	ports.PoolIDBechFile:         func(r ports.Ref) string { return r.Name + ".pool.id-bech" },
	ports.PoolCert:               func(r ports.Ref) string { return r.Name + ".pool.cert" },
	ports.PoolDeregCert:          func(r ports.Ref) string { return r.Name + ".pool.dereg-cert" },
	ports.PoolMetadata:           func(r ports.Ref) string { return r.Name + ".metadata.json" },
	ports.PoolExtendedMetadata:   func(r ports.Ref) string { return r.Name + ".extended-metadata.json" },
	ports.PoolAdditionalMetadata: func(r ports.Ref) string { return r.Name + ".additional-metadata.json" },
	ports.PoolItnSKey:            func(r ports.Ref) string { return r.Name + ".itn.skey" },
	ports.PoolItnVKey:            func(r ports.Ref) string { return r.Name + ".itn.vkey" },
	ports.PoolWitnessFile:        func(r ports.Ref) string { return r.Name + ".witness" },

	// spec: SPO-Xparty-INV-001, SPO-Xparty-INV-003, SPO-Xparty-OUT-001, SPO-Xparty-INV-007, SPO-Xparty-SEC-001
	ports.PartyKeys:      func(r ports.Ref) string { return r.Name + ".party.keys" },
	ports.PartyIdentity:  func(r ports.Ref) string { return r.Name + ".party.identity" },
	ports.PartyRecords:   func(r ports.Ref) string { return r.Name + ".party.records" },
	ports.PartyReplay:    func(r ports.Ref) string { return r.Name + ".party.replay" },
	ports.TailcatNodeKey: func(r ports.Ref) string { return r.Name + ".tailcat.nodekey" },
	ports.TailcatPSK:     func(r ports.Ref) string { return r.Name + ".tailcat.psk" },
	ports.TailcatAddr:    func(r ports.Ref) string { return r.Name + ".tailcat.addr" },
	// spec: SPO-Xparty-SEC-003, SPO-Xparty-OUT-004
	ports.MultisigCoordinator: func(r ports.Ref) string { return r.Name + ".multisig.coordinator" },
	ports.MultisigSigner:      func(r ports.Ref) string { return r.Name + ".multisig.signer" },
	ports.MultisigOutbox:      func(r ports.Ref) string { return r.Name + ".multisig.outbox" },
	ports.MultisigEvents:      func(r ports.Ref) string { return r.Name + ".multisig.events" },
	ports.MultisigCollection:  func(r ports.Ref) string { return r.Name + ".multisig.collection" },
	ports.MultisigSubmitted:   func(r ports.Ref) string { return r.Name + ".multisig.submitted" },
}

// modes of the kinds that are not locked at 0400: the published metadata is
// 0444 so it can be copied to a web server (SPO-05a-OUT-006, OUT-007), the
// additional metadata and the witness transfer files keep the default mode
// because the operator edits the first and `05d sign` rewrites the second in
// place (SPO-05a-OUT-003, SPO-05d-OUT-001).
var modes = map[ports.Kind]os.FileMode{
	ports.PoolMetadata:           0o444,
	ports.PoolExtendedMetadata:   0o444,
	ports.PoolAdditionalMetadata: 0o644,
	ports.PoolWitnessFile:        0o644,
}

func modeOf(k ports.Kind) os.FileMode {
	if m, ok := modes[k]; ok {
		return m
	}
	return modeLocked
}

// Store is a workspace directory.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open returns a Store over an existing directory.
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
		return nil, fmt.Errorf("fsstore: %s is not a directory", abs)
	}
	return &Store{dir: abs}, nil
}

func (s *Store) path(r ports.Ref) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	name, ok := layout[r.Kind]
	if !ok {
		return "", fmt.Errorf("%w: %s has no upstream file name", ports.ErrInvalidRef, r.Kind)
	}
	return filepath.Join(s.dir, name(r)), nil
}

type staged struct {
	path   string
	data   []byte         // non-secret content
	secret *secret.Buffer // secret content (a private copy)
	delete bool
	mode   os.FileMode // 0 means modeLocked
}

type tx struct {
	s        *Store
	writable bool
	ops      map[string]*staged
	order    []string
}

func (t *tx) lookup(r ports.Ref) (string, *staged, error) {
	p, err := t.s.path(r)
	if err != nil {
		return "", nil, err
	}
	return p, t.ops[p], nil
}

func (t *tx) Get(r ports.Ref) ([]byte, error) {
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
	p, st, err := t.lookup(r)
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
	if r.Kind.Secret() {
		return ports.ErrSecretKind
	}
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{data: append([]byte(nil), data...), mode: modeOf(r.Kind)})
	return nil
}

func (t *tx) PutSecret(r ports.Ref, sec *secret.Buffer) error {
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
	t.stage(p, &staged{secret: cp})
	return nil
}

func (t *tx) Delete(r ports.Ref) error {
	p, _, err := t.lookup(r)
	if err != nil {
		return err
	}
	t.stage(p, &staged{delete: true})
	return nil
}

func (t *tx) discard() {
	for _, st := range t.ops {
		st.secret.Destroy()
	}
}

// View implements ports.Store.
func (s *Store) View(_ context.Context, fn func(ports.Reader) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&tx{s: s, ops: map[string]*staged{}})
}

// Update implements ports.Store.
func (s *Store) Update(_ context.Context, fn func(ports.Writer) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &tx{s: s, writable: true, ops: map[string]*staged{}}
	defer t.discard()
	if err := fn(t); err != nil {
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
	return modeLocked
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
func (s *Store) Open(_ context.Context, r ports.Ref) (*secret.Buffer, error) {
	if !r.Kind.Secret() {
		return nil, fmt.Errorf("%w: %s is not a secret kind", ports.ErrInvalidRef, r.Kind)
	}
	p, err := s.path(r)
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
	_ ports.Store = (*Store)(nil)
	_ ports.Vault = (*Store)(nil)
)
