package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ImportWorkspace reads an upstream script directory and writes what it
// recognises into the destination store, sealing every secret on the way.
//
// The source is only read: nothing in it is modified, locked or deleted. The
// destination is written once per owner (a pool or a wallet) in one atomic
// Update, so a failed owner leaves no trace and a good one is complete.
//
// Decision (E9): keys that upstream encrypted are decrypted with the
// operator's password and sealed like any other key. The password is tried
// as typed and as upstream's prompt would have stored it (keyfile.UpstreamRead).
// With no password, an owner holding an encrypted key fails with
// ErrPasswordRequired. With DeferEncrypted the encrypted key file is not
// imported at all (ADR 0011 decision 2): it stays in the source, the report
// says so, and its owner is not counted as imported. No UpstreamEncryptedSKey
// record is created any more; one an older workspace holds is read by
// ConvertKey only.
type ImportWorkspace struct {
	// Source, SourceVault and Lister read the upstream directory
	// (upstreamdir.Source implements all three).
	Source      ports.NamedReadStore
	SourceVault ports.NamedVault
	Lister      ports.SourceLister
	// Dest is the sealed store.
	Dest ports.NamedStore
	// Decryptor opens upstream-encrypted keys (the gpg adapter). May be nil
	// when the directory has none.
	Decryptor ports.KeyDecryptor
	// Deriver and Addresses enable the consistency checks (native
	// adapters). When nil the checks are skipped and the report says so.
	Deriver   ports.VerificationKeyDeriver
	Addresses ports.AddressInspector
	// Open opens a source directory by path for a selective import
	// (Import). Run does not use it.
	Open func(dir string) (Source, error)
	// History and Homes read the destination's role histories and the owners
	// that list a key identity. When set, a VRF or KES verification key whose
	// Ed25519 identity has any role history, or is a member of an owner in a
	// role other than KES or VRF, is refused: a cold key relabelled as a hot
	// one (the check the node export makes, applied at import by stem).
	// HotDeriver derives the KES leaf from a KES signing key, so the relabel
	// check looks at the key the signing key really holds and not only at the
	// root the verification key file declares. May be nil (the check then covers
	// the declared key only).
	HotDeriver ports.HotVKeyDeriver
	History    func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error)
	Homes      func(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error)
}

// ErrRelabelledHotKey means a verification key imported as a VRF or KES key is
// the public key of a key the workspace knows in another role.
var ErrRelabelledHotKey = errors.New("the public key of this hot key is also a recorded key of the workspace in another role")

// checkHotRelabel refuses the verification key envelope b of a VRF or KES key
// when its Ed25519 identity has a role history or a non-hot home.
func (u ImportWorkspace) checkHotRelabel(ctx context.Context, b []byte) error {
	env, err := pool.ParseEnvelope(b)
	if err != nil {
		return nil // malformed content is refused elsewhere
	}
	pub, err := identity.PublicKeyOfCborHex(env.CborHex)
	if err != nil {
		return nil
	}
	return u.checkRelabelPub(ctx, pub, false)
}

// checkRelabelPub refuses a 32-byte public key that the workspace already knows
// as another role's key. For a hot key (VRF, KES) any role history, or a home
// other than KES or VRF, refuses it; for a Calidus or Catalyst voting key only a
// cold role (a role history with a cold role, or a cold home) does.
func (u ImportWorkspace) checkRelabelPub(ctx context.Context, pub []byte, coldOnly bool) error {
	if u.History == nil && u.Homes == nil {
		return nil
	}
	eid, err := identity.KeyHashOf(pub)
	if err != nil {
		return nil
	}
	if u.History != nil {
		h, ok, herr := u.History(ctx, eid)
		switch {
		case herr != nil:
			return fmt.Errorf("%w: %v", ports.ErrUnreadableRecords, herr)
		case ok && !coldOnly && len(h.Roles()) > 0:
			return fmt.Errorf("%w: the workspace records it with roles", ErrRelabelledHotKey)
		case ok && coldOnly && h.HasColdRole():
			return fmt.Errorf("%w: the workspace records it as a cold key", ErrRelabelledHotKey)
		}
	}
	if u.Homes != nil {
		hs, herr := u.Homes(ctx, eid)
		if herr != nil {
			return fmt.Errorf("%w: %v", ports.ErrUnreadableRecords, herr)
		}
		for _, h := range hs {
			if coldOnly && h.Role.IsCold() || !coldOnly && h.Role != custody.RoleKES && h.Role != custody.RoleVRF {
				return fmt.Errorf("%w: it is a member of an owner as a %s key", ErrRelabelledHotKey, h.Role)
			}
		}
	}
	return nil
}

// ImportOptions selects and shapes an import.
type ImportOptions struct {
	// Owners names the pools and wallets to import; empty means everything
	// found.
	Owners []string
	// Password opens upstream-encrypted keys. The caller owns and destroys it.
	Password *ports.Secret
	// DeferEncrypted leaves every upstream-encrypted key file in the source: it
	// is listed in the report as left there, and its owner is not imported. No
	// password is asked for.
	DeferEncrypted bool
	// Overwrite replaces artefacts the destination already holds. Without it
	// an owner with any artefact already in the destination is not imported.
	Overwrite bool
}

type planned struct {
	src  ports.NamedRef
	dst  ports.NamedRef
	data []byte
	sec  *ports.Secret
}

// Run imports. It returns an error only when nothing could be attempted
// (listing failed, an owner asked for does not exist, the context ended); a
// failed owner is in the report.
//
// spec: SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-003, SPO-Pfiles-OUT-004, SPO-Pfiles-OUT-005, SPO-Pfiles-OUT-006, SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009
// spec: SPO-Pfiles-OUT-010, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-012, SPO-Pfiles-OUT-013, SPO-Pfiles-OUT-014, SPO-Pfiles-OUT-015, SPO-Pfiles-OUT-016, SPO-Pfiles-OUT-017, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019, SPO-Pfiles-OUT-020
// spec: SPO-Pfiles-OUT-021, SPO-Pfiles-OUT-022, SPO-Pfiles-OUT-023, SPO-Pfiles-OUT-024, SPO-Pfiles-OUT-025, SPO-Pfiles-OUT-026, SPO-Pfiles-OUT-027, SPO-Pfiles-OUT-028, SPO-Pfiles-OUT-029, SPO-Pfiles-OUT-030
// spec: SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032, SPO-Pfiles-OUT-033, SPO-Pfiles-OUT-034, SPO-Pfiles-OUT-035, SPO-Pfiles-OUT-036, SPO-Pfiles-SEC-001, SPO-Pfiles-IN-003
// spec: SPO-Ckey-IN-001, SPO-Ckey-PRE-003, SPO-Ckey-PRE-006, SPO-Ckey-PRE-007, SPO-Ckey-PRE-010, SPO-Ckey-OUT-003, SPO-Ckey-PR-002, SPO-Ckey-PR-003, SPO-Ckey-EXT-002, SPO-Ckey-OUT-002
func (u ImportWorkspace) Run(ctx context.Context, opts ImportOptions) (*Report, error) {
	req := ImportRequest{ImportOptions: opts, legacy: true}
	for _, o := range opts.Owners {
		req.Only = append(req.Only, Selector{Name: o})
	}
	req.All = len(opts.Owners) == 0
	return u.importRepeating(ctx, req, []srcDir{{dir: "/", store: u.Source, vault: u.SourceVault, lister: u.Lister}})
}

// prepared is one owner after the plan phase: every check that can refuse it
// has run, nothing has been written. Its secrets stay in guarded memory until
// release.
type prepared struct {
	owner   string
	refs    []ports.NamedRef
	results map[ports.NamedRef]*ArtefactReport
	plan    []planned
	final   string
	rewrite []Rewrite
	failed  bool
	// refusal is a plan-phase refusal that is not the failure of one
	// artefact: a conflict with the workspace, a refused dependency.
	refusal string
	// conflictOnly: the only reason for the refusal is that the workspace
	// already holds artefacts of this owner.
	conflictOnly bool
	// deps are the selected owners the descriptor was bound to; the owner is
	// written only if each of them is stored.
	deps    []*found
	cleanup func()
	// legacyCheck: the plain form checks conflicts against the destination
	// itself in a dry run.
	legacyCheck bool
	// state of the owner in the run
	started, done, written bool
	// fixed: decided before preparation (a name collision, a workspace rule);
	// out is its report.
	fixed     bool
	out       OwnerReport
	reasonOut string
}

func (p *prepared) ok() bool { return !p.failed && p.refusal == "" }

// why is the reason a planned owner is refused, for a row that names it.
func (p *prepared) why() string {
	if p.refusal != "" {
		return p.refusal
	}
	if p.out.Reason != "" && !p.failed {
		return p.out.Reason
	}
	for _, r := range sortedRefs(p.results) {
		if a := p.results[r]; a.Status == StatusFailed {
			return fmt.Sprintf("%s %s", r.String(), a.Reason)
		}
	}
	return "an artefact failed"
}

func sortedRefs(m map[ports.NamedRef]*ArtefactReport) []ports.NamedRef {
	var rs []ports.NamedRef
	for r := range m {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].String() < rs[j].String() })
	return rs
}

// prepareOwner is the plan phase of one owner: it reads, decrypts, checks and
// decides, and writes nothing (SPO-Xmulti-INV-003).
func (u ImportWorkspace) prepareOwner(ctx context.Context, src srcDir, owner string, refs []ports.NamedRef, opts ImportOptions, pw *passwordSet, rep *Report, xf *ownerXform, dry bool) *prepared {
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	results := map[ports.NamedRef]*ArtefactReport{}
	for _, r := range refs {
		results[r] = &ArtefactReport{Ref: r, Status: StatusDone}
	}
	failed := false
	fail := func(r ports.NamedRef, why string) {
		results[r].Status, results[r].Reason = StatusFailed, why
		failed = true
	}

	data := ownerData{open: map[ports.NamedRef][]byte{}, skey: map[ports.NamedRef]*ports.Secret{}}
	var plan []planned
	var toDestroy []*ports.Secret
	cleanup := func() {
		for _, s := range toDestroy {
			s.Destroy()
		}
	}

	for _, r := range refs {
		switch {
		case r.Kind == ports.PoolDescriptor || !r.Kind.Secret():
			b, err := u.read(ctx, src, r)
			if err != nil {
				fail(r, "could not be read")
				continue
			}
			if ok := validateOpen(r.Kind, b); !ok {
				fail(r, "malformed content")
				continue
			}
			if r.Kind == ports.PoolDescriptor && keyfile.HasField(b, "regProtectionKey") {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("the descriptor of %s holds regProtectionKey, which ADR 0004 classes as Sensitive, not Secret: it is stored in the descriptor, an ordinary record that is sealed like every record", owner))
			}
			data.open[r] = b
			plan = append(plan, planned{src: r, dst: r, data: b})
		case r.Kind.IsSigningKey():
			buf, err := src.vault.Open(ctx, r)
			if err != nil {
				fail(r, "could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			info, cerr := classifyBuf(buf)
			switch {
			case cerr != nil && errors.Is(cerr, keyfile.ErrMalformedEncrypted):
				fail(r, "the encrypted key file is damaged")
			case cerr != nil:
				fail(r, "not a signing key envelope")
			case info.Form == keyfile.FormPlain:
				var kerr error
				_ = buf.Use(func(b []byte) error { kerr = ports.CheckEnvelopeKind(r.Kind, b); return nil })
				if kerr != nil {
					fail(r, "the key's envelope type does not match its file kind: it would be sealed under the wrong class")
					break
				}
				data.skey[r] = buf
				plan = append(plan, planned{src: r, dst: r, sec: buf})
			case info.Form == keyfile.FormEncrypted:
				if opts.DeferEncrypted {
					fail(r, ReasonDeferred)
					break
				}
				dec, derr := u.openEncrypted(ctx, r, buf, pw)
				if derr != "" {
					fail(r, derr)
					break
				}
				toDestroy = append(toDestroy, dec)
				data.skey[r] = dec
				plan = append(plan, planned{src: r, dst: r, sec: dec})
			default:
				fail(r, "a hardware signing file under a signing key name")
			}
		default: // mnemonics, QR codes: secret, opaque
			buf, err := src.vault.Open(ctx, r)
			if err != nil {
				fail(r, "could not be read")
				continue
			}
			toDestroy = append(toDestroy, buf)
			if buf.Len() == 0 {
				fail(r, "empty")
				continue
			}
			plan = append(plan, planned{src: r, dst: r, sec: buf})
		}
	}

	if !failed {
		fails, notes := checker{deriver: u.Deriver, addresses: u.Addresses}.check(ctx, data)
		for r, why := range fails {
			fail(r, why)
		}
		for r, n := range notes {
			if results[r].Note == "" {
				results[r].Note = n
			}
		}
	}

	if !failed {
		for _, p := range plan {
			if p.sec == nil && (p.dst.Kind == ports.VrfVKey || p.dst.Kind == ports.KesVKey) {
				if err := u.checkHotRelabel(ctx, p.data); err != nil {
					fail(p.src, err.Error())
				}
			}
			// a Calidus or Catalyst voting key that is a known cold key
			if p.sec == nil && (p.dst.Kind == ports.CalidusVKey || p.dst.Kind == ports.VotingVKey) {
				if env, perr := pool.ParseEnvelope(p.data); perr == nil {
					if pub, kerr := identity.PublicKeyOfCborHex(env.CborHex); kerr == nil {
						if err := u.checkRelabelPub(ctx, pub, true); err != nil {
							fail(p.src, err.Error())
						}
					}
				}
			}
			// a KES signing key: the leaf it holds, not the root a file declares
			if p.sec != nil && p.dst.Kind == ports.KesSKey && u.HotDeriver != nil {
				if leaf, lerr := u.HotDeriver.DeriveKESLeaf(ctx, p.sec); lerr == nil {
					if err := u.checkRelabelPub(ctx, leaf, false); err != nil {
						fail(p.src, err.Error())
					}
				}
			}
		}
	}

	final := owner
	var rewrites []Rewrite
	if !failed && xf != nil {
		final = xf.final
		for i := range plan {
			p := &plan[i]
			if p.dst.Kind != ports.PoolDescriptor || p.sec != nil || xf.descriptor == nil {
				continue
			}
			nd, rw, notes, refuse := xf.descriptor(p.data)
			if refuse != "" {
				fail(p.src, refuse)
				break
			}
			p.data, rewrites = nd, rw
			if len(notes) > 0 {
				results[p.src].Note = strings.Join(notes, "; ")
			}
		}
		if !failed && final != owner {
			for i := range plan {
				plan[i].dst = renameRef(plan[i].dst, owner, final)
			}
		}
		for _, p := range plan {
			if p.dst != p.src {
				results[p.src].To = p.dst
			}
		}
		if !failed && xf.ws != nil && !xf.legacy {
			fails, general := u.checkUnion(ctx, xf.ws, final, plan)
			for r, why := range fails {
				fail(r, why)
			}
			if general != "" && !failed && len(plan) > 0 {
				fail(plan[0].src, general)
			}
		}
		if !failed && xf.ws != nil && opts.Overwrite {
			verb := "replaces"
			if dry {
				verb = "would replace"
			}
			for _, p := range plan {
				if xf.ws.has(p.dst) {
					results[p.src].Note = joinNotes(results[p.src].Note, verb+" the workspace's existing "+p.dst.String())
				}
			}
			for r, n := range coldKeyNotes(xf.ws, final, plan, verb) {
				results[r].Note = joinNotes(results[r].Note, n)
			}
		}
	}

	// Gate A: whenever the stored name is one the workspace already holds, the
	// owner that would result is checked as a whole, with or without
	// --overwrite. Without it an exact clash is the conflict refusal below.
	var leftoverWhy, mergeNote string
	if !failed && xf != nil && xf.ws != nil && !xf.legacy && xf.ws.owner(final) != nil && (opts.Overwrite || !xf.ws.conflicts(plan)) {
		leftoverWhy, mergeNote = u.checkCoherence(ctx, xf.ws, final, plan)
		if leftoverWhy == "" && mergeNote != "" && len(plan) > 0 {
			results[plan[0].src].Note = joinNotes(results[plan[0].src].Note, mergeNote)
		}
	}
	pr := &prepared{legacyCheck: xf == nil || xf.ws == nil || xf.legacy, owner: owner, refs: refs, results: results, plan: plan, final: final, rewrite: rewrites, failed: failed, cleanup: cleanup}
	// A conflict with the workspace is decided here, from the snapshot the run
	// took before it wrote anything, so that the owners that depend on this one
	// know its outcome before they are decided. The plain form leaves it to
	// the commit, as it always did.
	if leftoverWhy != "" {
		pr.refusal = leftoverWhy
	}
	if !failed && !opts.Overwrite && xf != nil && xf.ws != nil && !xf.legacy && xf.ws.conflicts(plan) {
		pr.refusal, pr.conflictOnly = commitReason(errConflict), true
	}
	return pr
}

// coldKeyNotes says, for an incoming cold verification key or issue counter
// that replaces artefacts of a workspace pool holding a different cold key,
// that it does. Notes only: the key pair and counter checks decide refusals.
func coldKeyNotes(ws *wsSnapshot, final string, plan []planned, verb string) map[ports.NamedRef]string {
	out := map[ports.NamedRef]string{}
	cold := func(get func(ports.NamedRef) ([]byte, bool), name string) []byte {
		if b, ok := get(ports.NamedRef{Name: name, Kind: ports.NodeVKey}); ok {
			if env, err := pool.ParseEnvelope(b); err == nil {
				if k, err := env.Key32(); err == nil {
					return k
				}
			}
		}
		if b, ok := get(ports.NamedRef{Name: name, Kind: ports.NodeCounter}); ok {
			if c, err := pool.ParseIssueCounter(b); err == nil {
				return c.ColdVKey[:]
			}
		}
		return nil
	}
	existing := cold(ws.get, final)
	if existing == nil {
		return out
	}
	inc := map[ports.NamedRef][]byte{}
	for _, p := range plan {
		if p.sec == nil {
			inc[p.dst] = p.data
		}
	}
	incoming := cold(func(r ports.NamedRef) ([]byte, bool) { b, ok := inc[r]; return b, ok }, final)
	if incoming == nil || bytes.Equal(incoming, existing) {
		return out
	}
	for _, p := range plan {
		if p.sec == nil && (p.dst.Kind == ports.NodeVKey || p.dst.Kind == ports.NodeCounter) && ws.has(p.dst) {
			out[p.src] = fmt.Sprintf("%s the cold key of the workspace pool %q: the workspace's cold verification key is %x, the incoming one is %x", verb, final, existing, incoming)
		}
	}
	return out
}

// finishOwner writes a prepared owner, or reports what the plan decided.
func (u ImportWorkspace) finishOwner(ctx context.Context, p *prepared, opts ImportOptions, dry bool) OwnerReport {
	out := OwnerReport{Owner: p.owner, Final: p.final, Rewrites: p.rewrite}
	refs, results := p.refs, p.results
	switch {
	case p.refusal != "":
		out.Reason = p.refusal
		for _, r := range refs {
			results[r].Status, results[r].Reason = StatusSkipped, "the owner is not imported: "+p.refusal
		}
	case !p.failed && dry:
		if !opts.Overwrite && p.legacyCheck {
			c, err := u.conflicts(ctx, p.plan)
			if err != nil || c {
				out.Reason = commitReason(errConflict)
				if err != nil {
					out.Reason = commitReason(err)
				}
				for _, r := range refs {
					results[r].Status, results[r].Reason = StatusSkipped, "the owner would not be imported: "+out.Reason
				}
				break
			}
		}
		out.Would = true
		p.written = true
		for _, r := range refs {
			if results[r].Status == StatusDone {
				results[r].Status = StatusPlanned
			}
		}
	case !p.failed:
		if err := u.commit(ctx, p.plan, opts.Overwrite); err != nil {
			out.Reason = commitReason(err)
			for _, r := range refs {
				results[r].Status, results[r].Reason = StatusSkipped, "the owner was not imported: "+out.Reason
			}
		} else {
			out.Written, p.written = true, true
		}
	default:
		out.Reason = "an artefact failed; nothing of this owner was imported"
		for _, r := range refs {
			if results[r].Status != StatusFailed {
				results[r].Status, results[r].Reason = StatusSkipped, "the owner was not imported: another artefact failed"
			}
		}
	}
	for _, r := range refs {
		out.Artefacts = append(out.Artefacts, *results[r])
	}
	return out
}

var errConflict = errors.New("destination conflict")

func commitReason(err error) string {
	if errors.Is(err, errConflict) {
		return "the destination already holds artefacts of this owner (use Overwrite)"
	}
	return "the destination could not be written: " + err.Error()
}

func (u ImportWorkspace) commit(ctx context.Context, plan []planned, overwrite bool) error {
	return u.Dest.Update(ctx, func(w ports.NamedWriter) error {
		if !overwrite {
			for _, p := range plan {
				ok, err := w.Exists(p.dst)
				if err != nil {
					return err
				}
				if ok {
					return errConflict
				}
			}
		}
		for _, p := range plan {
			var err error
			if p.sec != nil {
				err = w.PutSecret(p.dst, p.sec)
			} else {
				err = w.Put(p.dst, p.data)
			}
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// conflicts reports whether the destination holds any artefact of the plan.
func (u ImportWorkspace) conflicts(ctx context.Context, plan []planned) (bool, error) {
	found := false
	err := u.Dest.View(ctx, func(r ports.NamedReader) error {
		for _, p := range plan {
			ok, err := r.Exists(p.dst)
			if err != nil {
				return err
			}
			if ok {
				found = true
			}
		}
		return nil
	})
	return found, err
}

func (u ImportWorkspace) read(ctx context.Context, src srcDir, r ports.NamedRef) ([]byte, error) {
	var b []byte
	err := src.store.View(ctx, func(rd ports.NamedReader) error {
		var e error
		b, e = rd.Get(r)
		return e
	})
	return b, err
}

// ReasonDeferred is the reason shown for an upstream-encrypted key file that an
// import with DeferEncrypted left in the source.
const ReasonDeferred = "left in the source: encrypted by upstream, not imported (--defer-encrypted); its owner is not imported"

// openEncrypted decrypts an upstream-encrypted key. A non-empty string is a
// failure reason.
//
// spec: SPO-Ckey-PRE-006, SPO-Ckey-PRE-010, SPO-Ckey-PRE-007, SPO-Ckey-PR-002
func (u ImportWorkspace) openEncrypted(ctx context.Context, r ports.NamedRef, buf *ports.Secret, pw *passwordSet) (dec *ports.Secret, failure string) {
	var enc keyfile.Encrypted
	var perr error
	_ = buf.Use(func(b []byte) error { enc, perr = keyfile.ParseEncrypted(b); return nil })
	if perr != nil {
		return nil, "the encrypted key file is damaged"
	}
	if pw == nil {
		return nil, ErrPasswordRequired.Error()
	}
	if u.Decryptor == nil {
		return nil, "no decryptor wired"
	}
	cbor, err := pw.open(ctx, u.Decryptor, enc.EncrHex)
	switch {
	case errors.Is(err, ports.ErrWrongPassphrase):
		return nil, "the password does not open this key"
	case errors.Is(err, ports.ErrMalformedCiphertext):
		return nil, "the encrypted key is not a valid gpg message"
	case err != nil:
		return nil, "the key could not be decrypted"
	}
	defer cbor.Destroy()
	plain, err := plainFromDecrypted(enc, cbor, "    ")
	if err != nil {
		return nil, "the decrypted key is not usable"
	}
	return plain, ""
}

// validateOpen applies the cheap structural checks to non-secret artefacts
// that have one: hardware signing files are JSON, an address file is text.
func validateOpen(k ports.Kind, b []byte) bool {
	for _, hk := range ports.HardwareFileKinds() {
		if k == hk {
			return keyfile.ValidObject(b)
		}
	}
	switch k {
	case ports.AddrFile, ports.StakingAddr:
		return len(b) > 0
	}
	return true
}
