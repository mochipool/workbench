package layoutexport_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
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

// ---- in-memory directory with fault injection ----

type memDir struct {
	mu   sync.Mutex
	objs map[string][]byte
	// puts counts calls of Put (including ones that found the object).
	puts []string
	// hooks
	putHook  func(n int, name string) error // called before the n-th Put (1-based); an error fails it
	getHook  func(name string, b []byte) []byte
	afterPut func(n int, name string)
	extra    map[string]int64 // listing entries that are not objects (a file in the directory)
}

func newMemDir() *memDir { return &memDir{objs: map[string][]byte{}} }

func (d *memDir) Put(ctx context.Context, name string, r io.Reader, size int64) error {
	if err := ports.ValidObjectName(name); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if int64(len(b)) != size {
		return errors.New("size mismatch")
	}
	d.mu.Lock()
	d.puts = append(d.puts, name)
	n := len(d.puts)
	hook, after := d.putHook, d.afterPut
	d.mu.Unlock()
	if hook != nil {
		if err := hook(n, name); err != nil {
			return err
		}
	}
	d.mu.Lock()
	if old, ok := d.objs[name]; ok {
		d.mu.Unlock()
		if !bytes.Equal(old, b) {
			return ports.ErrObjectExists
		}
		return nil
	}
	d.objs[name] = b
	d.mu.Unlock()
	if after != nil {
		after(n, name)
	}
	return nil
}

func (d *memDir) Get(_ context.Context, name string) (io.ReadCloser, error) {
	d.mu.Lock()
	b, ok := d.objs[name]
	hook := d.getHook
	d.mu.Unlock()
	if !ok {
		return nil, ports.ErrObjectNotFound
	}
	if hook != nil {
		b = hook(name, append([]byte(nil), b...))
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (d *memDir) Has(_ context.Context, name string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.objs[name]
	return ok, nil
}

func (d *memDir) List(_ context.Context, prefix string) ([]ports.ObjectInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []ports.ObjectInfo
	for n, b := range d.objs {
		if strings.HasPrefix(n, prefix) {
			out = append(out, ports.ObjectInfo{Name: n, Size: int64(len(b))})
		}
	}
	for n, sz := range d.extra {
		if strings.HasPrefix(n, prefix) {
			out = append(out, ports.ObjectInfo{Name: n, Size: sz})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (d *memDir) putCount() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.puts) }

func (d *memDir) resetPuts() { d.mu.Lock(); d.puts = nil; d.mu.Unlock() }

func (d *memDir) names(prefix string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for n := range d.objs {
		if strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func (d *memDir) snapshotNames() map[string]bool {
	m := map[string]bool{}
	for _, n := range d.names("") {
		m[n] = true
	}
	return m
}

// ---- lock and pins ----

type memLock struct {
	mu       sync.Mutex
	held     bool
	checkErr error
	released int
}

type heldLock struct{ l *memLock }

func (l *memLock) Lock(context.Context) (ports.LayoutLock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return nil, ports.ErrLayoutLocked
	}
	l.held = true
	return heldLock{l}, nil
}

func (h heldLock) Check() error {
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	return h.l.checkErr
}

func (h heldLock) Release() error {
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	h.l.held = false
	h.l.released++
	return nil
}

type memPins struct {
	mu       sync.Mutex
	pin      *ports.LayoutPin
	loadErr  error
	writes   int
	advances int
}

func (p *memPins) Load() (ports.LayoutPin, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loadErr != nil {
		return ports.LayoutPin{}, false, p.loadErr
	}
	if p.pin == nil {
		return ports.LayoutPin{}, false, nil
	}
	return *p.pin, true, nil
}

func (p *memPins) Advance(pin ports.LayoutPin) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.advances++
	if p.pin != nil {
		if p.pin.Sequence == pin.Sequence && bytes.Equal(p.pin.HeadHash, pin.HeadHash) {
			return nil
		}
		if p.pin.Sequence >= pin.Sequence {
			return ports.ErrLayoutPinBackwards
		}
	}
	c := pin
	p.pin = &c
	p.writes++
	return nil
}

// ---- sealer ----

type testSealer struct {
	s      *seal.ObjectSealer
	epoch  []byte
	ws     []byte
	closed int
}

func (t *testSealer) Epoch() []byte       { return t.epoch }
func (t *testSealer) WorkspaceID() []byte { return t.ws }
func (t *testSealer) Seal(b []byte) ([]byte, error) {
	return t.s.Seal(t.epoch, t.ws, b)
}
func (t *testSealer) Close() { t.closed++; t.s.Close() }

// ---- the world: a synthetic workspace ----

func pat(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

type world struct {
	t      *testing.T
	ws     []byte
	policy string
	epoch  []byte
	keys   *seal.Keys
	// the rows
	records []ports.SnapshotRecord
	refs    []ports.RecordRef
	audit   []ports.SnapshotAudit
	slots   []ports.SnapshotSlot
	meta    ports.SnapshotMeta

	dir   *memDir
	lock  *memLock
	pins  *memPins
	clock time.Time

	unlocks int
	signing *backupsink.Signing
	keyRec  *checkpoint.KeyRecord
	notify  func(string)
	adopt   bool
	sk      *fakesk.Source
	sealers []*testSealer
	notices []string
}

func newKeys(t *testing.T) *seal.Keys {
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
	return k
}

var kindsInUse = []string{"node.skey", "kes.vkey", "vrf.skey", "addr.vkey"}

func ruleOf(kind string) (string, bool) {
	k := ports.Kind(kind)
	if !k.Known() {
		return "", false
	}
	if k.Secret() {
		return "secret", true
	}
	return "sensitive", true
}

// newWorld builds a workspace of nrec records and an audit chain.
func newWorld(t *testing.T, policy string, nrec int) *world {
	t.Helper()
	w := &world{t: t, ws: pat(0x20, 16), policy: policy, epoch: pat(0xf0, 16), keys: newKeys(t),
		dir: newMemDir(), lock: &memLock{}, pins: &memPins{}, clock: time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)}
	w.buildSlots()
	for i := 0; i < nrec; i++ {
		w.addRecord(i, kindsInUse[i%len(kindsInUse)])
	}
	w.audit = nil
	w.appendAudit("slots")
	for i := 0; i < nrec; i++ {
		w.appendAudit("update")
	}
	return w
}

func i64(v int64) *int64 { return &v }

func (w *world) buildSlots() {
	pub := pat(0x90, 32)
	w.meta = ports.SnapshotMeta{SchemaVersion: 3, WorkspaceID: w.ws, FormatVersion: 3, CreatedAt: 1700000000, KeyEpoch: w.epoch,
		EpochMAC: pat(0x01, 32), Policy: w.policy, RecoveryPub: pub}
	switch w.policy {
	case "standard":
		w.slots = []ports.SnapshotSlot{
			{ID: pat(0x30, 16), Kind: "passphrase", KDFMemoryKiB: i64(65536), KDFPasses: i64(3), KDFLanes: i64(1), Salt: pat(0x70, 16), KeyCommit: pat(1, 32), Nonce: pat(2, 24), WrappedKey: pat(3, 48), Bound: 1, RecHash: sha(pub)},
			{ID: pat(0x40, 16), Kind: "recovery", Salt: []byte{}, KeyCommit: pat(4, 32), Nonce: pat(5, 24), WrappedKey: pat(6, 48), Bound: 1, RecHash: sha(pub)},
		}
	case "hardware":
		w.slots = []ports.SnapshotSlot{
			{ID: pat(0x31, 16), Kind: "fido2-hmac", KeyCommit: pat(1, 32), Nonce: pat(2, 24), WrappedKey: pat(3, 48), Bound: 1, RecHash: sha(pub), Factors: pat(0xc0, 120)},
			{ID: pat(0x41, 16), Kind: "composite", KeyCommit: pat(4, 32), Nonce: pat(5, 24), WrappedKey: pat(6, 48), Bound: 1, RecHash: sha(pub), Factors: pat(0xd0, 300)},
		}
	default:
		w.meta.RecoveryPub = nil
		w.slots = []ports.SnapshotSlot{
			{ID: pat(0x32, 16), Kind: "fido2-hmac", KeyCommit: pat(1, 32), Nonce: pat(2, 24), WrappedKey: pat(3, 48), Bound: 1, Factors: pat(0xc0, 120)},
			{ID: pat(0x33, 16), Kind: "fido2-hmac", KeyCommit: pat(7, 32), Nonce: pat(8, 24), WrappedKey: pat(9, 48), Bound: 1, Factors: pat(0xc8, 120)},
		}
	}
}

func sha(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func recID(i int) []byte {
	id := make([]byte, 16)
	id[0], id[1] = byte(i>>8), byte(i)
	copy(id[2:], pat(0xa0, 14))
	return id
}

func (w *world) addRecord(i int, kind string) {
	class, _ := ruleOf(kind)
	r := ports.SnapshotRecord{
		ID: recID(i), LookupTag: pat(byte(i), 32), Kind: kind, Version: 1,
		Nonce: pat(byte(10+i), 24), WrappedKey: pat(byte(20+i), 72), OwnerSealed: pat(byte(30+i), 200), Ciphertext: pat(byte(40+i), 300+i), UpdatedAt: 1700000000 + int64(i),
	}
	r.LookupTag[0], r.LookupTag[1] = byte(i>>8), byte(i)
	w.records = append(w.records, r)
	w.refs = append(w.refs, ports.RecordRef{Anchor: append([]byte{0}, pat(byte(50+i), 28)...), Num: uint64(i), Class: class})
}

func (w *world) appendAudit(kind string) {
	seq := int64(len(w.audit) + 1)
	prev := make([]byte, 32)
	if n := len(w.audit); n > 0 {
		prev = w.audit[n-1].MAC
	}
	a := ports.SnapshotAudit{Seq: seq, At: 1700000000 + seq, Kind: kind, Event: pat(byte(seq), 80), Touched: pat(byte(seq+1), 40), MAC: sha(append(prev, byte(seq))), PrevMAC: prev}
	if kind == "slots" {
		a.SlotSet = w.slotSet()
	}
	w.audit = append(w.audit, a)
}

func (w *world) slotSet() []byte {
	h, err := layout.SlotSetHash(w.policy, w.layoutSlots())
	if err != nil {
		w.t.Fatal(err)
	}
	return h
}

func (w *world) layoutSlots() []layout.Slot {
	var out []layout.Slot
	for _, s := range w.slots {
		out = append(out, layout.Slot{ID: s.ID, Kind: s.Kind, KDFMemoryKiB: s.KDFMemoryKiB, KDFPasses: s.KDFPasses, KDFLanes: s.KDFLanes,
			Salt: s.Salt, KeyCommit: s.KeyCommit, Nonce: s.Nonce, WrappedKey: s.WrappedKey, Bound: s.Bound, RecHash: s.RecHash, Factors: s.Factors})
	}
	return out
}

// change makes one record newer, as a store write would: a new version, new sealed
// bytes, and a new audit row.
func (w *world) change(i int) {
	r := &w.records[i]
	r.Version++
	r.Nonce = pat(byte(100+i)+byte(r.Version), 24)
	r.Ciphertext = pat(byte(110+i)+byte(r.Version), len(r.Ciphertext))
	r.UpdatedAt += 100
	w.appendAudit("update")
}

func (w *world) newSealer(epoch []byte) *testSealer {
	s, err := w.keys.ObjectSealer()
	if err != nil {
		w.t.Fatal(err)
	}
	ts := &testSealer{s: s, epoch: epoch, ws: w.ws}
	w.sealers = append(w.sealers, ts)
	return ts
}

// copySnapshot is what the store would hand over: fresh slices every time.
func (w *world) copySnapshot() (ports.Snapshot, []ports.RecordRef) {
	cp := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte{}, b...)
	}
	snap := ports.Snapshot{Meta: w.meta}
	snap.Meta.WorkspaceID, snap.Meta.KeyEpoch, snap.Meta.EpochMAC, snap.Meta.RecoveryPub = cp(w.meta.WorkspaceID), cp(w.meta.KeyEpoch), cp(w.meta.EpochMAC), cp(w.meta.RecoveryPub)
	for _, s := range w.slots {
		s.ID, s.Salt, s.KeyCommit, s.Nonce, s.WrappedKey, s.RecHash, s.Factors = cp(s.ID), cp(s.Salt), cp(s.KeyCommit), cp(s.Nonce), cp(s.WrappedKey), cp(s.RecHash), cp(s.Factors)
		snap.Slots = append(snap.Slots, s)
	}
	for _, r := range w.records {
		r.ID, r.LookupTag, r.Nonce, r.WrappedKey, r.OwnerSealed, r.Ciphertext = cp(r.ID), cp(r.LookupTag), cp(r.Nonce), cp(r.WrappedKey), cp(r.OwnerSealed), cp(r.Ciphertext)
		snap.Records = append(snap.Records, r)
	}
	for _, a := range w.audit {
		a.Event, a.Touched, a.SlotSet, a.MAC, a.PrevMAC = cp(a.Event), cp(a.Touched), cp(a.SlotSet), cp(a.MAC), cp(a.PrevMAC)
		snap.Audit = append(snap.Audit, a)
	}
	refs := append([]ports.RecordRef(nil), w.refs...)
	return snap, refs
}

func (w *world) input() layoutexport.Input {
	return layoutexport.Input{
		Dir: layoutexport.Dir{Writer: w.dir, Reader: w.dir, Lister: w.dir, Locker: w.lock, Pins: w.pins}, WorkspaceID: w.ws,
		Now: func() time.Time { return w.clock }, AdoptLayout: w.adopt, Notify: w.notify,
		Unlock: func(context.Context) (layoutexport.Material, error) {
			w.unlocks++
			snap, refs := w.copySnapshot()
			s := w.newSealer(w.epoch)
			return layoutexport.Material{Snapshot: snap, Refs: refs, Sealer: s, Notices: w.notices, Signing: w.signing, KeyRecord: w.keyRec, Close: s.Close}, nil
		},
	}
}

func (w *world) run() (layoutexport.Result, error) {
	w.clock = w.clock.Add(time.Minute)
	return layoutexport.Run(context.Background(), w.input())
}

func (w *world) mustRun() layoutexport.Result {
	w.t.Helper()
	res, err := w.run()
	if err != nil {
		w.t.Fatalf("export: %v", err)
	}
	return res
}

// withKey enrols a checkpoint key on a fake authenticator and signs with it.
func (w *world) withKey() {
	const dev, pin = "/dev/sk0", "2468"
	w.sk = fakesk.New(map[string]string{dev: pin})
	p, _ := ports.TakeSecret([]byte(pin))
	en, err := w.sk.EnrolSigner(context.Background(), ports.SignerEnrolRequest{Device: dev, RPID: checkpoint.Application, PIN: p})
	if err != nil {
		w.t.Fatal(err)
	}
	rec := checkpoint.KeyRecord{Key: sshsig.Key{Q: en.PublicKey, Application: checkpoint.Application}, CredentialID: en.CredentialID, Enrolled: w.clock}
	w.keyRec = &rec
	w.signing = &backupsink.Signing{Record: rec, Source: w.sk, Device: dev,
		PIN: func(context.Context) (*ports.Secret, error) { return ports.TakeSecret([]byte(pin)) }}
}

// ---- reading a layout back with the keys (tests only) ----

type opened struct {
	records map[string]layout.Record // by object name
	audit   map[string]layout.Audit
	rpages  map[string]layout.RecordPage
	apages  map[string]layout.AuditPage
	roots   map[string]layout.Root
	slots   map[string]layout.SlotsObject
	sizes   map[string]int
}

// openAll opens every object of the directory with the keys.
func (w *world) openAll(d *memDir, epoch []byte) *opened {
	w.t.Helper()
	o := &opened{records: map[string]layout.Record{}, audit: map[string]layout.Audit{}, rpages: map[string]layout.RecordPage{},
		apages: map[string]layout.AuditPage{}, roots: map[string]layout.Root{}, slots: map[string]layout.SlotsObject{}, sizes: map[string]int{}}
	for _, p := range d.names("objects/") {
		name := p[len("objects/xx/"):]
		stored := d.objs[p]
		o.sizes[name] = len(stored)
		if layout.ObjectName(stored) != name {
			w.t.Fatalf("object %s is not named by its hash", name)
		}
		if stored[0] == layout.FormatSlots {
			_, so, err := layout.ParseSlotsObject(stored)
			if err != nil {
				w.t.Fatal(err)
			}
			o.slots[name] = so
			continue
		}
		body, err := w.keys.OpenObject(stored, w.ws, stored[1:17])
		if err != nil {
			w.t.Fatalf("object %s does not open: %v", name, err)
		}
		obj, err := layout.DecodeBody(body, ruleOf)
		if err != nil {
			w.t.Fatalf("object %s: %v", name, err)
		}
		switch x := obj.(type) {
		case layout.Record:
			o.records[name] = x
		case layout.Audit:
			o.audit[name] = x
		case layout.RecordPage:
			o.rpages[name] = x
		case layout.AuditPage:
			o.apages[name] = x
		case layout.Root:
			o.roots[name] = x
		}
	}
	return o
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

// newestHead reads the newest head of the directory.
func newestHead(t *testing.T, d *memDir) (layout.Head, []byte) {
	t.Helper()
	var best string
	for _, n := range d.names("heads/") {
		if !strings.HasSuffix(n, ".sig") {
			best = n
		}
	}
	if best == "" {
		t.Fatal("no head in the directory")
	}
	h, err := layout.ParseHead(d.objs[best])
	if err != nil {
		t.Fatal(err)
	}
	return h, d.objs[best]
}

// satisfiable is the crash-safety invariant: the newest valid head, if any, has
// its manifest, every page, every record and audit object and its slots object in
// the directory, and the manifest verifies against its pages. It returns the head
// sequence number (0 for no head).
func satisfiable(t *testing.T, w *world, d *memDir) uint64 {
	t.Helper()
	var heads []string
	for _, n := range d.names("heads/") {
		if !strings.HasSuffix(n, ".sig") {
			heads = append(heads, n)
		}
	}
	if len(heads) == 0 {
		return 0
	}
	hb := d.objs[heads[len(heads)-1]]
	h, err := layout.ParseHead(hb)
	if err != nil {
		t.Fatalf("the newest head does not parse: %v", err)
	}
	get := func(hash []byte) []byte {
		p, _ := layout.ObjectPath(hexOf(hash))
		b, ok := d.objs[p]
		if !ok {
			t.Fatalf("the newest head (sequence %d) names %x, which is not in the directory", h.Sequence, hash[:6])
		}
		return b
	}
	slots := get(h.Slots)
	if _, _, err := layout.ParseSlotsObject(slots); err != nil {
		t.Fatal(err)
	}
	openBody := func(stored []byte) layout.Object {
		body, err := w.keys.OpenObject(stored, w.ws, stored[1:17])
		if err != nil {
			t.Fatal(err)
		}
		o, err := layout.DecodeBody(body, ruleOf)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	root, ok := openBody(get(h.Manifest)).(layout.Root)
	if !ok {
		t.Fatal("the manifest is not a root")
	}
	var rp []layout.RecordPage
	var ap []layout.AuditPage
	for _, ph := range root.RecordPages {
		p := openBody(get(ph)).(layout.RecordPage)
		rp = append(rp, p)
		for _, e := range p.Entries {
			get(e.Hash)
		}
	}
	for _, ph := range root.AuditPages {
		p := openBody(get(ph)).(layout.AuditPage)
		ap = append(ap, p)
		for _, e := range p.Entries {
			get(e.Hash)
		}
	}
	if err := layout.VerifyManifest(root, rp, ap); err != nil {
		t.Fatalf("the manifest of the newest head does not verify: %v", err)
	}
	return h.Sequence
}

// fork is a second workspace of the same history: the same keys, records and audit
// chain (copied), and a directory and pins of its own.
func (w *world) fork() *world {
	x := newWorld(w.t, w.policy, 0)
	x.ws, x.epoch, x.keys, x.meta = w.ws, w.epoch, w.keys, w.meta
	x.records = append([]ports.SnapshotRecord(nil), w.records...)
	x.refs = append([]ports.RecordRef(nil), w.refs...)
	x.audit = append([]ports.SnapshotAudit(nil), w.audit...)
	x.slots = w.slots
	x.keyRec, x.signing, x.sk, x.clock = w.keyRec, w.signing, w.sk, w.clock
	return x
}
