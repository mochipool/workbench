// Package layoutfix is a synthetic workspace and an in-memory layout directory
// for tests of the layout reader (app/layoutread) and the importer. It writes a
// layout with the real exporter use case, so what the reader reads is what the
// exporter writes, and it offers the means to build hostile variants of it. The
// keys are real (seal.Keys and its object sealer); the owner blobs, slot tables
// and audit MACs are synthetic, and the opener it hands out is a fake that knows
// how they are made. Real-store tests live in the store package and in cmd/spo.
package layoutfix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakesk"
)

// MemDir is an in-memory layout directory.
type MemDir struct {
	mu   sync.Mutex
	Objs map[string][]byte
	// GetHook, when set, may change the bytes a Get returns (a directory that
	// changes while it is read).
	GetHook func(name string, b []byte) []byte
	// GetErr, when set, makes a Get of that name fail with the error.
	GetErr map[string]error
	Gets   atomic.Int64
	// MaxLive is the highest number of reads open at once.
	live, MaxLive int64
}

func NewMemDir() *MemDir { return &MemDir{Objs: map[string][]byte{}, GetErr: map[string]error{}} }

func (d *MemDir) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if err := ports.ValidObjectName(name); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if old, ok := d.Objs[name]; ok {
		if !bytes.Equal(old, b) {
			return ports.ErrObjectExists
		}
		return nil
	}
	d.Objs[name] = b
	return nil
}

type trackedReader struct {
	io.Reader
	d    *MemDir
	done bool
}

func (t *trackedReader) Close() error {
	if !t.done {
		t.done = true
		t.d.mu.Lock()
		t.d.live--
		t.d.mu.Unlock()
	}
	return nil
}

func (d *MemDir) Get(_ context.Context, name string) (io.ReadCloser, error) {
	d.Gets.Add(1)
	d.mu.Lock()
	b, ok := d.Objs[name]
	hook := d.GetHook
	gerr := d.GetErr[name]
	d.live++
	if d.live > d.MaxLive {
		d.MaxLive = d.live
	}
	d.mu.Unlock()
	if gerr != nil || !ok {
		d.mu.Lock()
		d.live--
		d.mu.Unlock()
		if gerr != nil {
			return nil, gerr
		}
		return nil, ports.ErrObjectNotFound
	}
	if hook != nil {
		b = hook(name, append([]byte(nil), b...))
	}
	return &trackedReader{Reader: bytes.NewReader(b), d: d}, nil
}

func (d *MemDir) Has(_ context.Context, name string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.Objs[name]
	return ok, nil
}

func (d *MemDir) List(_ context.Context, prefix string) ([]ports.ObjectInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []ports.ObjectInfo
	for n, b := range d.Objs {
		if strings.HasPrefix(n, prefix) {
			out = append(out, ports.ObjectInfo{Name: n, Size: int64(len(b))})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Names are the names under prefix, sorted.
func (d *MemDir) Names(prefix string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for n := range d.Objs {
		if strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Clone is an independent copy of the directory.
func (d *MemDir) Clone() *MemDir {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := NewMemDir()
	for n, b := range d.Objs {
		c.Objs[n] = append([]byte(nil), b...)
	}
	return c
}

// Set replaces the bytes of a name (a hostile edit).
func (d *MemDir) Set(name string, b []byte) {
	d.mu.Lock()
	d.Objs[name] = b
	d.mu.Unlock()
}

// Delete removes a name (a hostile edit).
func (d *MemDir) Delete(name string) {
	d.mu.Lock()
	delete(d.Objs, name)
	d.mu.Unlock()
}

// Lock and Pins are the exporter's single-writer lock and local pin, in memory.
type Lock struct {
	mu   sync.Mutex
	held bool
}
type heldLock struct{ l *Lock }

func (l *Lock) Lock(context.Context) (ports.LayoutLock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return nil, ports.ErrLayoutLocked
	}
	l.held = true
	return heldLock{l}, nil
}
func (h heldLock) Check() error { return nil }
func (h heldLock) Release() error {
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	h.l.held = false
	return nil
}

type Pins struct {
	mu  sync.Mutex
	Pin *ports.LayoutPin
}

func (p *Pins) Load() (ports.LayoutPin, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Pin == nil {
		return ports.LayoutPin{}, false, nil
	}
	return *p.Pin, true, nil
}
func (p *Pins) Advance(pin ports.LayoutPin) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.Pin != nil {
		if p.Pin.Sequence == pin.Sequence && bytes.Equal(p.Pin.HeadHash, pin.HeadHash) {
			return nil
		}
		if p.Pin.Sequence >= pin.Sequence {
			return ports.ErrLayoutPinBackwards
		}
	}
	c := pin
	p.Pin = &c
	return nil
}

type sealer struct {
	s     *seal.ObjectSealer
	epoch []byte
	ws    []byte
}

func (t *sealer) Epoch() []byte       { return t.epoch }
func (t *sealer) WorkspaceID() []byte { return t.ws }
func (t *sealer) Seal(b []byte) ([]byte, error) {
	return t.s.Seal(t.epoch, t.ws, b)
}
func (t *sealer) Close() { t.s.Close() }

// Pat is n bytes that depend on seed.
func Pat(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

func sha(b ...[]byte) []byte {
	h := sha256.New()
	for _, x := range b {
		h.Write(x)
	}
	return h.Sum(nil)
}

func i64(v int64) *int64 { return &v }

// Rule is the store's kind-to-class rule.
func Rule(kind string) (string, bool) {
	k := ports.Kind(kind)
	if !k.Known() {
		return "", false
	}
	if k.Secret() {
		return "secret", true
	}
	return "sensitive", true
}

var kinds = []string{"node.skey", "kes.vkey", "vrf.skey", "addr.vkey"}

// World is a synthetic workspace, its layout directory and the means to export it.
type World struct {
	T      *testing.T
	WS     []byte
	Policy string
	Epoch  []byte
	Keys   *seal.Keys

	Records []ports.SnapshotRecord
	Refs    []ports.RecordRef
	Audit   []ports.SnapshotAudit
	Slots   []ports.SnapshotSlot
	Meta    ports.SnapshotMeta

	Dir   *MemDir
	Lock  *Lock
	Pins  *Pins
	Clock time.Time

	Signing *backupsink.Signing
	KeyRec  *checkpoint.KeyRecord
	SK      *fakesk.Source
}

// NewWorld builds a workspace of nrec records and the audit chain of their
// creation.
func NewWorld(t *testing.T, policy string, nrec int) *World {
	t.Helper()
	m, err := seal.NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := seal.DeriveKeys(m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Destroy)
	w := &World{T: t, WS: Pat(0x20, 16), Policy: policy, Epoch: Pat(0xf0, 16), Keys: k,
		Dir: NewMemDir(), Lock: &Lock{}, Pins: &Pins{}, Clock: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)}
	w.buildSlots()
	for i := 0; i < nrec; i++ {
		w.AddRecord(i, kinds[i%len(kinds)])
	}
	w.appendAudit("slots")
	for i := 0; i < nrec; i++ {
		w.appendAudit("update")
	}
	return w
}

func (w *World) buildSlots() {
	pub := Pat(0x90, 32)
	w.Meta = ports.SnapshotMeta{SchemaVersion: 3, WorkspaceID: w.WS, FormatVersion: 3, CreatedAt: 1700000000, KeyEpoch: w.Epoch,
		EpochMAC: w.EpochMAC(), Policy: w.Policy, RecoveryPub: pub}
	switch w.Policy {
	case "standard":
		w.Slots = []ports.SnapshotSlot{
			{ID: Pat(0x30, 16), Kind: "passphrase", KDFMemoryKiB: i64(65536), KDFPasses: i64(3), KDFLanes: i64(1), Salt: Pat(0x70, 16), KeyCommit: Pat(1, 32), Nonce: Pat(2, 24), WrappedKey: Pat(3, 48), Bound: 1, RecHash: sha(pub)},
			{ID: Pat(0x40, 16), Kind: "recovery", Salt: []byte{}, KeyCommit: Pat(4, 32), Nonce: Pat(5, 24), WrappedKey: Pat(6, 48), Bound: 1, RecHash: sha(pub)},
		}
	case "hardware":
		w.Slots = []ports.SnapshotSlot{
			{ID: Pat(0x31, 16), Kind: "fido2-hmac", KeyCommit: Pat(1, 32), Nonce: Pat(2, 24), WrappedKey: Pat(3, 48), Bound: 1, RecHash: sha(pub), Factors: Pat(0xc0, 120)},
			{ID: Pat(0x41, 16), Kind: "composite", KeyCommit: Pat(4, 32), Nonce: Pat(5, 24), WrappedKey: Pat(6, 48), Bound: 1, RecHash: sha(pub), Factors: Pat(0xd0, 300)},
		}
	default:
		w.Meta.RecoveryPub = nil
		w.Slots = []ports.SnapshotSlot{
			{ID: Pat(0x32, 16), Kind: "fido2-hmac", KeyCommit: Pat(1, 32), Nonce: Pat(2, 24), WrappedKey: Pat(3, 48), Bound: 1, Factors: Pat(0xc0, 120)},
			{ID: Pat(0x33, 16), Kind: "fido2-hmac", KeyCommit: Pat(7, 32), Nonce: Pat(8, 24), WrappedKey: Pat(9, 48), Bound: 1, Factors: Pat(0xc8, 120)},
		}
	}
}

// EpochMAC is the epoch MAC this world's fake opener accepts.
func (w *World) EpochMAC() []byte { return sha([]byte("epoch-mac"), w.WS, w.Epoch) }

// RecID is the id of record i.
func RecID(i int) []byte {
	id := make([]byte, 16)
	id[0], id[1] = byte(i>>8), byte(i)
	copy(id[2:], Pat(0xa0, 14))
	return id
}

// OwnerBlob is the owner blob the fake opener accepts for a record.
func OwnerBlob(ws, id []byte, kind string, anchor []byte, num uint64) []byte {
	return ownerBlob(ws, id, kind, anchor, num)
}

func ownerBlob(ws, id []byte, kind string, anchor []byte, num uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], num)
	mac := sha([]byte("owner"), ws, id, []byte(kind), anchor, n[:])[:8]
	return append(append(append([]byte(nil), anchor...), n[:]...), mac...)
}

func lookupTag(anchor []byte, kind string, num uint64) []byte {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], num)
	return sha([]byte("tag"), anchor, []byte(kind), n[:])
}

// AddRecord appends record i of the kind to the workspace (not to the audit).
func (w *World) AddRecord(i int, kind string) {
	class, _ := Rule(kind)
	anchor := append([]byte{0}, Pat(byte(50+i), 28)...)
	id := RecID(i)
	r := ports.SnapshotRecord{
		ID: id, LookupTag: lookupTag(anchor, kind, uint64(i)), Kind: kind, Version: 1,
		Nonce: Pat(byte(10+i), 24), WrappedKey: Pat(byte(20+i), 72), OwnerSealed: ownerBlob(w.WS, id, kind, anchor, uint64(i)),
		Ciphertext: Pat(byte(40+i), 300+i), UpdatedAt: 1700000000 + int64(i),
	}
	w.Records = append(w.Records, r)
	w.Refs = append(w.Refs, ports.RecordRef{Anchor: anchor, Num: uint64(i), Class: class})
}

func (w *World) appendAudit(kind string) {
	seq := int64(len(w.Audit) + 1)
	prev := make([]byte, 32)
	if n := len(w.Audit); n > 0 {
		prev = w.Audit[n-1].MAC
	}
	a := ports.SnapshotAudit{Seq: seq, At: 1700000000 + seq, Kind: kind, Event: Pat(byte(seq), 80), Touched: Pat(byte(seq+1), 40), SlotSet: []byte{}, MAC: sha(prev, []byte{byte(seq), byte(seq >> 8)}), PrevMAC: prev}
	if kind == "slots" || kind == "rollover" {
		a.SlotSet = w.SlotSet()
	}
	w.Audit = append(w.Audit, a)
}

// AppendAudit adds n audit rows of kind update.
func (w *World) AppendAudit(n int) {
	for i := 0; i < n; i++ {
		w.appendAudit("update")
	}
}

// LayoutSlots is the slot table as the slots object carries it.
func (w *World) LayoutSlots() []layout.Slot {
	var out []layout.Slot
	for _, s := range w.Slots {
		out = append(out, layout.Slot{ID: s.ID, Kind: s.Kind, KDFMemoryKiB: s.KDFMemoryKiB, KDFPasses: s.KDFPasses, KDFLanes: s.KDFLanes,
			Salt: s.Salt, KeyCommit: s.KeyCommit, Nonce: s.Nonce, WrappedKey: s.WrappedKey, Bound: s.Bound, RecHash: s.RecHash, Factors: s.Factors})
	}
	return out
}

// SlotSet is the slot-set hash of the slot table.
func (w *World) SlotSet() []byte {
	h, err := layout.SlotSetHash(w.Policy, w.LayoutSlots())
	if err != nil {
		w.T.Fatal(err)
	}
	return h
}

// Change makes record i newer, as a store write would.
func (w *World) Change(i int) {
	r := &w.Records[i]
	r.Version++
	r.Nonce = Pat(byte(100+i)+byte(r.Version), 24)
	r.Ciphertext = Pat(byte(110+i)+byte(r.Version), len(r.Ciphertext))
	r.UpdatedAt += 100
	w.appendAudit("update")
}

func (w *World) copySnapshot() (ports.Snapshot, []ports.RecordRef) {
	cp := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte{}, b...)
	}
	snap := ports.Snapshot{Meta: w.Meta}
	snap.Meta.WorkspaceID, snap.Meta.KeyEpoch, snap.Meta.EpochMAC, snap.Meta.RecoveryPub = cp(w.Meta.WorkspaceID), cp(w.Meta.KeyEpoch), cp(w.Meta.EpochMAC), cp(w.Meta.RecoveryPub)
	for _, s := range w.Slots {
		s.ID, s.Salt, s.KeyCommit, s.Nonce, s.WrappedKey, s.RecHash, s.Factors = cp(s.ID), cp(s.Salt), cp(s.KeyCommit), cp(s.Nonce), cp(s.WrappedKey), cp(s.RecHash), cp(s.Factors)
		snap.Slots = append(snap.Slots, s)
	}
	for _, r := range w.Records {
		r.ID, r.LookupTag, r.Nonce, r.WrappedKey, r.OwnerSealed, r.Ciphertext = cp(r.ID), cp(r.LookupTag), cp(r.Nonce), cp(r.WrappedKey), cp(r.OwnerSealed), cp(r.Ciphertext)
		snap.Records = append(snap.Records, r)
	}
	for _, a := range w.Audit {
		a.Event, a.Touched, a.SlotSet, a.MAC, a.PrevMAC = cp(a.Event), cp(a.Touched), cp(a.SlotSet), cp(a.MAC), cp(a.PrevMAC)
		snap.Audit = append(snap.Audit, a)
	}
	refs := append([]ports.RecordRef(nil), w.Refs...)
	return snap, refs
}

// Snapshot is a copy of the rows of the workspace.
func (w *World) Snapshot() ports.Snapshot { s, _ := w.copySnapshot(); return s }

// Sealer makes a sealer for the workspace's keys.
func (w *World) Sealer() ports.ObjectSealer {
	s, err := w.Keys.ObjectSealer()
	if err != nil {
		w.T.Fatal(err)
	}
	return &sealer{s: s, epoch: w.Epoch, ws: w.WS}
}

// ExportInput is the exporter's input for this world.
func (w *World) ExportInput() layoutexport.Input {
	return layoutexport.Input{
		Dir: layoutexport.Dir{Writer: w.Dir, Reader: w.Dir, Lister: w.Dir, Locker: w.Lock, Pins: w.Pins}, WorkspaceID: w.WS,
		Now: func() time.Time { return w.Clock },
		Unlock: func(context.Context) (layoutexport.Material, error) {
			snap, refs := w.copySnapshot()
			s := w.Sealer()
			return layoutexport.Material{Snapshot: snap, Refs: refs, Sealer: s, Signing: w.Signing, KeyRecord: w.KeyRec, Close: s.Close}, nil
		},
	}
}

// Export runs the exporter, a minute after the last run.
func (w *World) Export() (layoutexport.Result, error) {
	w.Clock = w.Clock.Add(time.Minute)
	return layoutexport.Run(context.Background(), w.ExportInput())
}

// MustExport is Export that fails the test on an error.
func (w *World) MustExport() layoutexport.Result {
	w.T.Helper()
	res, err := w.Export()
	if err != nil {
		w.T.Fatalf("export: %v", err)
	}
	return res
}

// WithKey enrols a checkpoint key on a fake authenticator and signs heads with it.
func (w *World) WithKey() {
	const dev, pin = "/dev/sk0", "2468"
	w.SK = fakesk.New(map[string]string{dev: pin})
	p, _ := ports.TakeSecret([]byte(pin))
	en, err := w.SK.EnrolSigner(context.Background(), ports.SignerEnrolRequest{Device: dev, RPID: checkpoint.Application, PIN: p})
	if err != nil {
		w.T.Fatal(err)
	}
	rec := checkpoint.KeyRecord{Key: sshsig.Key{Q: en.PublicKey, Application: checkpoint.Application}, CredentialID: en.CredentialID, Enrolled: w.Clock}
	w.KeyRec = &rec
	w.Signing = &backupsink.Signing{Record: rec, Source: w.SK, Device: dev,
		PIN: func(context.Context) (*ports.Secret, error) { return ports.TakeSecret([]byte(pin)) }}
}

// SignWith signs text under the head namespace with this world's checkpoint key.
func (w *World) SignWith(note []byte) []byte {
	b, err := w.Signing.Sign(context.Background(), layout.NamespaceHead, note)
	if err != nil {
		w.T.Fatal(err)
	}
	return b
}

// Pin is the exact pin of the head with the sequence number, read from the
// directory.
func (w *World) Pin(seq uint64) string {
	return fmt.Sprintf("%x:layout:%d:%x", w.WS, seq, layout.HeadHash(w.Dir.Objs[layout.HeadPath(seq)]))
}

// LongPin is the key pin of the world's checkpoint key.
func (w *World) LongPin() string {
	return checkpoint.LongPin{WorkspaceID: w.WS, KeyHash: w.KeyRec.Hash()}.String()
}

// Head reads and parses head seq of the directory.
func (w *World) Head(seq uint64) layout.Head {
	h, err := layout.ParseHead(w.Dir.Objs[layout.HeadPath(seq)])
	if err != nil {
		w.T.Fatal(err)
	}
	return h
}

// ---- hostile building ----

// SealObject seals an object of this workspace and returns the stored bytes.
func (w *World) SealObject(o layout.Object) []byte {
	w.T.Helper()
	body, err := layout.EncodeBody(o)
	if err != nil {
		w.T.Fatal(err)
	}
	s := w.Sealer()
	defer s.Close()
	stored, err := s.Seal(body)
	if err != nil {
		w.T.Fatal(err)
	}
	return stored
}

// OpenStored opens and decodes a stored sealed object with the workspace keys.
func (w *World) OpenStored(stored []byte) layout.Object {
	w.T.Helper()
	body, err := w.Keys.OpenObject(stored, w.WS, stored[1:17])
	if err != nil {
		w.T.Fatal(err)
	}
	o, err := layout.DecodeBody(body, Rule)
	if err != nil {
		w.T.Fatal(err)
	}
	return o
}

// ObjectOf reads the stored object with the hash from the directory.
func (w *World) ObjectOf(hash []byte) []byte {
	p, _ := layout.ObjectPath(fmt.Sprintf("%x", hash))
	b, ok := w.Dir.Objs[p]
	if !ok {
		w.T.Fatalf("object %x is not in the directory", hash[:6])
	}
	return b
}

// PutObject stores bytes under their own name and returns the hash.
func (w *World) PutObject(stored []byte) []byte {
	p, _ := layout.ObjectPath(layout.ObjectName(stored))
	w.Dir.Set(p, stored)
	return layout.ObjectHash(stored)
}

// Root returns the manifest root of head seq.
func (w *World) Root(seq uint64) layout.Root {
	return w.OpenStored(w.ObjectOf(w.Head(seq).Manifest)).(layout.Root)
}

// RePutHead writes a head note (and removes any signature), the way an attacker
// with write access to the directory would.
func (w *World) RePutHead(h layout.Head) []byte {
	note, err := h.Encode()
	if err != nil {
		w.T.Fatal(err)
	}
	w.Dir.Set(layout.HeadPath(h.Sequence), note)
	w.Dir.Delete(layout.HeadPath(h.Sequence) + ".sig")
	return note
}

// ---- the fake opener and checker ----

// Opener is the fake key opener of a world: the real object envelope under the
// world's keys, and the synthetic owner blobs and tags of the fixture.
type Opener struct {
	W *World
	// Err makes OpenLayoutKeys fail.
	Err error
	// Opens counts the unlocks; Closed the closed openers.
	Opens, Closed atomic.Int32
	// BadEpochMAC makes EpochMACValid report false.
	BadEpochMAC bool
	// TagErr makes LookupTag fail; WrongEpoch and WrongWorkspace make the opener
	// report another key epoch or workspace id than the head's.
	TagErr                     error
	WrongEpoch, WrongWorkspace bool
}

var _ ports.LayoutKeyOpener = (*Opener)(nil)

func (w *World) Opener() *Opener { return &Opener{W: w} }

type opener struct {
	o *Opener
	s *seal.ObjectSealer
}

func (o *Opener) OpenLayoutKeys(_ context.Context, meta ports.SnapshotMeta, _ []ports.SnapshotSlot) (ports.ObjectOpener, error) {
	o.Opens.Add(1)
	if o.Err != nil {
		return nil, o.Err
	}
	s, err := o.W.Keys.ObjectSealer()
	if err != nil {
		return nil, err
	}
	return &opener{o: o, s: s}, nil
}

func (p *opener) Epoch() []byte {
	if p.o.WrongEpoch {
		return Pat(0x01, 16)
	}
	return p.o.W.Epoch
}
func (p *opener) WorkspaceID() []byte {
	if p.o.WrongWorkspace {
		return Pat(0x02, 16)
	}
	return p.o.W.WS
}
func (p *opener) EpochMACValid(ws, epoch, mac []byte) (bool, error) {
	if p.o.BadEpochMAC {
		return false, nil
	}
	return bytes.Equal(mac, sha([]byte("epoch-mac"), ws, epoch)), nil
}
func (p *opener) Open(stored []byte) ([]byte, error) {
	return p.s.Open(stored, p.o.W.WS, p.o.W.Epoch)
}
func (p *opener) OwnerRef(id []byte, kind string, owner []byte) ([]byte, uint64, error) {
	if len(owner) < 16 {
		return nil, 0, errors.New("owner blob too short")
	}
	anchor := owner[:len(owner)-16]
	num := binary.BigEndian.Uint64(owner[len(owner)-16 : len(owner)-8])
	if !bytes.Equal(owner, ownerBlob(p.o.W.WS, id, kind, anchor, num)) {
		return nil, 0, errors.New("owner blob does not authenticate")
	}
	return anchor, num, nil
}
func (p *opener) LookupTag(anchor []byte, kind string, num uint64) ([]byte, error) {
	if p.o.TagErr != nil {
		return nil, p.o.TagErr
	}
	return lookupTag(anchor, kind, num), nil
}
func (p *opener) Close() { p.s.Close(); p.o.Closed.Add(1) }

// Tables is the fake slot-table check: a table needs a daily slot (a passphrase
// or a fido2-hmac slot).
type Tables struct {
	Calls atomic.Int32
	// Reject, when set, makes the check refuse a table it returns true for (the
	// store's own checks, such as the RP id of a FIDO2 slot).
	Reject func(slots []ports.SnapshotSlot) bool
}

func (t *Tables) CheckSlotTable(_ ports.SnapshotMeta, slots []ports.SnapshotSlot) error {
	t.Calls.Add(1)
	if t.Reject != nil && t.Reject(slots) {
		return errors.New("the store refuses the slot table")
	}
	for _, s := range slots {
		if s.Kind == "passphrase" || s.Kind == "fido2-hmac" {
			return nil
		}
	}
	return errors.New("the slot table has no daily slot")
}

// ---- forging a next head (an attacker or a buggy exporter that holds the keys) ----

// Parts are the manifest of a head, opened, for a test to change.
type Parts struct {
	RecordPages []layout.RecordPage
	AuditPages  []layout.AuditPage
	Root        layout.Root
	// SlotsStored is the stored slots object the head names.
	SlotsStored []byte
	// KeepPageHashes keeps Root.RecordPages and Root.AuditPages as they are
	// instead of naming the (changed) pages.
	KeepPageHashes bool
	// Head is the head note to write; Forge fills it in before mutate runs.
	Head layout.Head
}

// Forge writes head newest+1 (unsigned). pre changes the parts before the pages
// are sealed and named by the root; post changes the root and the head after
// that (either may be nil). The new pages, root and slots object are put in the
// directory. It returns the head.
func (w *World) Forge(pre, post func(p *Parts)) layout.Head {
	w.T.Helper()
	var seq uint64 = 1
	for _, n := range w.Dir.Names("heads/") {
		if !strings.HasSuffix(n, ".sig") {
			var s uint64
			fmt.Sscanf(n, "heads/%d", &s)
			seq = s
		}
	}
	prev := w.Head(seq)
	prevNote := w.Dir.Objs[layout.HeadPath(seq)]
	root := w.Root(seq)
	p := &Parts{Root: root, SlotsStored: w.ObjectOf(prev.Slots)}
	for _, h := range root.RecordPages {
		p.RecordPages = append(p.RecordPages, w.OpenStored(w.ObjectOf(h)).(layout.RecordPage))
	}
	for _, h := range root.AuditPages {
		p.AuditPages = append(p.AuditPages, w.OpenStored(w.ObjectOf(h)).(layout.AuditPage))
	}
	w.Clock = w.Clock.Add(time.Minute)
	p.Head = layout.Head{Workspace: w.WS, Sequence: seq + 1, Previous: layout.HeadHash(prevNote), AuditSeq: prev.AuditSeq,
		AuditMAC: prev.AuditMAC, RecoveryKey: prev.RecoveryKey, Epoch: prev.Epoch, Time: w.Clock.UTC().Truncate(time.Second)}
	if pre != nil {
		pre(p)
	}
	if !p.KeepPageHashes {
		p.Root.RecordPages, p.Root.AuditPages = nil, nil
		for _, pg := range p.RecordPages {
			p.Root.RecordPages = append(p.Root.RecordPages, w.PutObject(w.SealObject(pg)))
		}
		for _, pg := range p.AuditPages {
			p.Root.AuditPages = append(p.Root.AuditPages, w.PutObject(w.SealObject(pg)))
		}
	}
	slotsHash := w.PutObject(p.SlotsStored)
	if p.Root.Slots == nil || bytes.Equal(p.Root.Slots, prev.Slots) {
		p.Root.Slots = slotsHash
	}
	p.Root.Parent = layout.Parent{Format: layout.ParentFormat, Seq: seq + 1, PreviousHead: layout.HeadHash(prevNote)}
	if post != nil {
		post(p)
	}
	p.Head.Manifest = w.PutObject(w.SealObject(p.Root))
	if p.Head.Slots == nil {
		p.Head.Slots = slotsHash
	}
	note, err := p.Head.Encode()
	if err != nil {
		w.T.Fatal(err)
	}
	w.Dir.Set(layout.HeadPath(p.Head.Sequence), note)
	return p.Head
}

// Sha is SHA-256.
func Sha(b []byte) []byte { return sha(b) }

// Rekey changes the slot table (a new nonce in the first slot) and records it in
// a new audit row of kind rollover, so that the newest slot-table row is not the
// first one.
func (w *World) Rekey() {
	w.Slots[0].Nonce = Pat(0x5a, len(w.Slots[0].Nonce))
	w.appendAudit("rollover")
}

// CBORClaiming is the start of a canonical CBOR array of n items followed by
// nothing: the header of a structure that claims n entries and holds none.
func CBORClaiming(n uint32) []byte {
	return []byte{0x9a, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// SealRaw seals raw CBOR (framed as a body) and puts it in the directory, for
// a hostile object the encoder would refuse to make. It returns the hash.
func (w *World) SealRaw(cbor []byte) []byte {
	w.T.Helper()
	body, err := layout.FrameBody(cbor)
	if err != nil {
		w.T.Fatal(err)
	}
	s := w.Sealer()
	defer s.Close()
	stored, err := s.Seal(body)
	if err != nil {
		w.T.Fatal(err)
	}
	return w.PutObject(stored)
}
