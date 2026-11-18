// Package nodekeys is `spo node export`: the delivery of a pool's hot keys to
// its block producer (ADR 0011 decision 2). It reads the KES signing key, the
// VRF signing key and the operational certificate from the workspace, checks
// them, and returns age ciphertext sealed to the recipient the operator named.
// It has no way to write a file and no plaintext leaves it: the only plaintext
// writer of the release is the producer's start-up helper (adapters/nodefiles),
// which never opens a workspace.
package nodekeys

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals. None names key material.
var (
	ErrNotConfigured = errors.New("node export is not wired in this build")
	ErrNoHistory     = errors.New("the workspace has no role history for the key, so it cannot be told that the key was never a cold key: refused (fail closed)")
	ErrWrongRole     = errors.New("the role history of the key does not contain the hot role of its kind")
	ErrColdRole      = errors.New("the key has been recorded in a cold role: a cold key is never delivered to a block producer")
	ErrMismatch      = errors.New("the signing key does not derive the verification key stored with it")
	ErrWrongOpCert   = errors.New("the operational certificate does not name this KES key")
	ErrNoKesNumber   = errors.New("no KES key number could be determined: name one with --kes")
	ErrMissing       = errors.New("an artefact the delivery needs is missing")
	ErrOpCertInvalid = errors.New("the operational certificate is not valid for this pool: its cold signature does not verify, its cold key is not the pool's, its period is not sane, or it is not the newest certificate the issue counter has made")
)

// Export is the use case.
type Export struct {
	Store ports.NamedStore
	Vault ports.NamedVault
	// History returns the recorded roles of a key identity (ports.RoleHistoryOf
	// over the workspace's key index). A history that cannot be read is an error.
	History func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error)
	// Homes, when set, lists the owners that hold a key identity; an Ed25519
	// identity that is a member of an owner in a role other than KES or VRF is
	// refused. History alone cannot see an identity that no record names.
	Homes   func(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error)
	Derive  ports.HotVKeyDeriver
	Sealer  ports.HotSealer
	Auditor ports.WorkspaceAuditor
	// Now gives the export time recorded in each file's header; nil is time.Now.
	Now func() time.Time
}

// Request is one delivery.
type Request struct {
	// Pool is the name of the pool whose hot keys are delivered.
	Pool string
	// KES is the number of the KES key; nil takes the newest key that has a
	// certificate.
	KES *int
	// Recipient is the age X25519 public key of the block producer.
	Recipient string
	// NoTPMIdentity records that the producer's identity is not held in a TPM
	// bound credential (the operator said so).
	NoTPMIdentity bool
}

// File is one sealed file of a delivery.
type File struct {
	Kind pool.HotKind
	// Name is the file name of the ciphertext, kes.skey.age and so on.
	Name       string
	Ciphertext []byte
}

// Result is what the command writes and reports.
type Result struct {
	KESNumber   int
	RecipientID string
	Files       []File
	record      func(ctx context.Context) error
}

// Record writes the audit event of the delivery. The caller writes the files
// under temporary names first, calls Record, and only then gives them their
// names, so there is no audit row without files and no named file without an
// audit row, except in a crash between Record and the renames (an audit row, the
// files still under temporary names).
func (r *Result) Record(ctx context.Context) error {
	if r == nil || r.record == nil {
		return errors.New("nothing to record")
	}
	return r.record(ctx)
}

// Run checks the three hot files and seals them in memory. Everything is checked
// before anything is sealed. The delivery is recorded by Result.Record, which the
// caller calls after the files exist under temporary names.
//
// spec: SPO-Xcustody-IF-005, SPO-Xcustody-PRE-007, SPO-Xcustody-PRE-008, SPO-Xcustody-PRE-009, SPO-Xcustody-PRE-010, SPO-Xcustody-PRE-011, SPO-Xcustody-OUT-006, SPO-Xcustody-OUT-007
func (u Export) Run(ctx context.Context, req Request) (*Result, error) {
	if u.Store == nil || u.Vault == nil || u.History == nil || u.Derive == nil || u.Sealer == nil || u.Auditor == nil {
		return nil, ErrNotConfigured
	}
	rid, err := u.Sealer.CheckRecipient(req.Recipient)
	if err != nil {
		return nil, err
	}

	// The non-secret artefacts, by name.
	var (
		coldV, counterFile []byte
		num                int
		kesV, vrfV, opcert []byte
		kesVKey32, vrfVKey []byte
		kesID, vrfID       identity.Ref
	)
	err = u.Store.View(ctx, func(r ports.NamedReader) error {
		var verr error
		if num, verr = kesNumber(r, req); verr != nil {
			return verr
		}
		get := func(k ports.Kind, n int) ([]byte, error) {
			b, err := r.Get(ports.NamedRef{Name: req.Pool, Kind: k, Num: n})
			if errors.Is(err, ports.ErrNotFound) {
				return nil, fmt.Errorf("%w: %s", ErrMissing, ports.NamedRef{Name: req.Pool, Kind: k, Num: n})
			}
			return b, err
		}
		if kesV, verr = get(ports.KesVKey, num); verr != nil {
			return verr
		}
		if vrfV, verr = get(ports.VrfVKey, 0); verr != nil {
			return verr
		}
		if opcert, verr = get(ports.OpCert, num); verr != nil {
			return verr
		}
		if coldV, verr = get(ports.NodeVKey, 0); verr != nil {
			return verr
		}
		counterFile, verr = get(ports.NodeCounter, 0)
		return verr
	})
	if err != nil {
		return nil, err
	}
	if kesID, err = ports.IdentityOfVKey(custody.RoleKES, kesV); err != nil {
		return nil, fmt.Errorf("the KES verification key: %w", err)
	}
	if vrfID, err = ports.IdentityOfVKey(custody.RoleVRF, vrfV); err != nil {
		return nil, fmt.Errorf("the VRF verification key: %w", err)
	}
	if kesVKey32, err = raw32(kesV); err != nil {
		return nil, err
	}
	if vrfVKey, err = raw32(vrfV); err != nil {
		return nil, err
	}

	// Role history: fail closed.
	for _, c := range []struct {
		id   identity.Ref
		role custody.Role
	}{{kesID, custody.RoleKES}, {vrfID, custody.RoleVRF}} {
		h, ok, herr := u.History(ctx, c.id)
		switch {
		case herr != nil:
			return nil, fmt.Errorf("%w: %v", ports.ErrUnreadableRecords, herr)
		case !ok:
			return nil, fmt.Errorf("%w (%s key)", ErrNoHistory, c.role)
		case h.HasColdRole():
			return nil, fmt.Errorf("%w (%s key)", ErrColdRole, c.role)
		case !h.Has(c.role):
			return nil, fmt.Errorf("%w (%s key)", ErrWrongRole, c.role)
		}
	}

	// An Ed25519 key relabelled as a hot key: the Ed25519 identity of the VRF public
	// key and of the KES leaf must have no history and no non-hot home.
	kesLeafProbe, lerr := u.leaf(ctx, req.Pool, num)
	if lerr != nil {
		return nil, lerr
	}
	for _, pub := range [][]byte{vrfVKey, kesLeafProbe} {
		eid, ierr := identity.KeyHashOf(pub)
		if ierr != nil {
			return nil, ierr
		}
		if h, ok, herr := u.History(ctx, eid); herr != nil {
			return nil, fmt.Errorf("%w: %v", ports.ErrUnreadableRecords, herr)
		} else if ok && len(h.Roles()) > 0 {
			return nil, fmt.Errorf("%w: the public key of a hot key is also recorded as an Ed25519 key with roles", ErrColdRole)
		}
		if u.Homes != nil {
			hs, herr := u.Homes(ctx, eid)
			if herr != nil {
				return nil, fmt.Errorf("%w: %v", ports.ErrUnreadableRecords, herr)
			}
			for _, h := range hs {
				if h.Role != custody.RoleKES && h.Role != custody.RoleVRF {
					return nil, fmt.Errorf("%w: the public key of a hot key is a member of an owner as a %s key", ErrColdRole, h.Role)
				}
			}
		}
	}

	// The certificate names this KES key.
	if err := pool.ValidateHot(pool.HotOpCert, opcert); err != nil {
		return nil, err
	}
	oc, err := pool.ParseOpCert(opcert)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(oc.KesVKey[:], kesVKey32) {
		return nil, ErrWrongOpCert
	}
	// Whose certificate: signed by the pool's own cold key, the newest the issue
	// counter has made (an older one is a rollback), with a sane period.
	cold32, cerr := raw32(coldV)
	ic, ierr := pool.ParseIssueCounter(counterFile)
	if cerr != nil || ierr != nil || !bytes.Equal(oc.ColdVKey[:], cold32) || !bytes.Equal(ic.ColdVKey[:], cold32) ||
		custody.VerifyOpCertOwnKey(custody.OpCert{KesVKey: oc.KesVKey, Counter: oc.Counter, KesPeriod: oc.KesPeriod, ColdVKey: oc.ColdVKey, Signature: oc.Signature}, pool.MaxSaneKesPeriod) != nil || oc.Counter+1 != ic.Next {
		return nil, ErrOpCertInvalid
	}

	// The signing keys: exact form, and the verification key derived from each
	// is the stored one.
	kesS, err := u.Vault.Open(ctx, ports.NamedRef{Name: req.Pool, Kind: ports.KesSKey, Num: num})
	if err != nil {
		return nil, fmt.Errorf("the KES signing key: %w", err)
	}
	defer kesS.Destroy()
	vrfS, err := u.Vault.Open(ctx, ports.NamedRef{Name: req.Pool, Kind: ports.VrfSKey})
	if err != nil {
		return nil, fmt.Errorf("the VRF signing key: %w", err)
	}
	defer vrfS.Destroy()
	for _, c := range []struct {
		kind  pool.HotKind
		s     *ports.Secret
		want  []byte
		deriv func(context.Context, *ports.Secret) ([]byte, error)
	}{{pool.HotKES, kesS, kesVKey32, u.Derive.DeriveKES}, {pool.HotVRF, vrfS, vrfVKey, u.Derive.DeriveVRF}} {
		if err := c.s.Use(func(b []byte) error { return pool.ValidateHot(c.kind, b) }); err != nil {
			return nil, err
		}
		got, err := c.deriv(ctx, c.s)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, c.want) {
			return nil, ErrMismatch
		}
	}

	// Seal, then record, then return.
	opS, err := ports.TakeSecret(append([]byte(nil), opcert...))
	if err != nil {
		return nil, err
	}
	defer opS.Destroy()
	pid, perr := chain.PoolIDOf(oc.ColdVKey[:])
	if perr != nil {
		return nil, perr
	}
	now := time.Now
	if u.Now != nil {
		now = u.Now
	}
	hdr := pool.DeliveryHeader{PoolID: hex.EncodeToString(pid[:]), KesNumber: num, Counter: oc.Counter, ExportedAt: now().Unix()}
	res := &Result{KESNumber: num, RecipientID: rid}
	var names []string
	for _, c := range []struct {
		kind pool.HotKind
		s    *ports.Secret
	}{{pool.HotKES, kesS}, {pool.HotVRF, vrfS}, {pool.HotOpCert, opS}} {
		spec, _ := c.kind.Spec()
		framed, err := u.frame(c.kind, spec, c.s, hdr)
		if err != nil {
			return nil, err
		}
		ct, err := u.Sealer.Seal(ctx, req.Recipient, framed)
		framed.Destroy()
		if err != nil {
			return nil, err
		}
		res.Files = append(res.Files, File{Kind: c.kind, Name: spec.CipherFile(), Ciphertext: ct})
		names = append(names, spec.CipherFile())
	}
	tpm := "tpm-identity=not verified (the producer's credential is not visible from here)"
	if req.NoTPMIdentity {
		tpm = "tpm-identity=none (the operator stated the producer's identity is not TPM-bound)"
	}
	ev := ports.AuditEvent{Operation: "node-export", Owners: []string{req.Pool}, Protected: true,
		Detail: []string{fmt.Sprintf("kes=%d", num), "recipient=" + rid, "files=" + joinNames(names), tpm}}
	res.record = func(ctx context.Context) error {
		if err := u.Auditor.Record(ctx, ev); err != nil {
			return fmt.Errorf("the delivery cannot be recorded in the audit log, so no file was given its name: %w", err)
		}
		return nil
	}
	return res, nil
}

func joinNames(n []string) string {
	var b bytes.Buffer
	for i, s := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s)
	}
	return b.String()
}

func raw32(vkeyEnvelope []byte) ([]byte, error) {
	e, err := pool.ParseEnvelope(vkeyEnvelope)
	if err != nil {
		return nil, err
	}
	return e.Key32()
}

// kesNumber is the number the operator gave or the newest key that has a
// certificate: after `issue` the next counter is the issued number plus one.
func kesNumber(r ports.NamedReader, req Request) (int, error) {
	if req.KES != nil {
		if *req.KES < 0 {
			return 0, ErrNoKesNumber
		}
		return *req.KES, nil
	}
	read := func(k ports.Kind) (*int, error) {
		b, err := r.Get(ports.NamedRef{Name: req.Pool, Kind: k})
		if errors.Is(err, ports.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		n, err := pool.ParseCounter(b)
		if err != nil {
			return nil, err
		}
		return &n, nil
	}
	cur, err := read(ports.KesCounter)
	if err != nil {
		return 0, err
	}
	next, err := read(ports.KesCounterNext)
	if err != nil {
		return 0, err
	}
	if cur == nil {
		return 0, ErrNoKesNumber
	}
	if next != nil && *next == *cur+1 {
		return *cur, nil // the newest key has its certificate
	}
	if *cur == 0 {
		return 0, ErrNoKesNumber
	}
	return *cur - 1, nil
}

// leaf opens the KES key once for its leaf public key.
func (u Export) leaf(ctx context.Context, name string, num int) ([]byte, error) {
	k, err := u.Vault.Open(ctx, ports.NamedRef{Name: name, Kind: ports.KesSKey, Num: num})
	if err != nil {
		return nil, fmt.Errorf("the KES signing key: %w", err)
	}
	defer k.Destroy()
	if err := k.Use(func(b []byte) error { return pool.ValidateHot(pool.HotKES, b) }); err != nil {
		return nil, err
	}
	return u.Derive.DeriveKESLeaf(ctx, k)
}

// frame wraps a plaintext file with the delivery header of its kind.
func (u Export) frame(kind pool.HotKind, spec pool.HotSpec, plain *ports.Secret, h pool.DeliveryHeader) (*ports.Secret, error) {
	h.Kind = spec.File
	var out *ports.Secret
	err := plain.Use(func(b []byte) error {
		f, err := pool.FrameDelivery(h, b)
		if err != nil {
			return err
		}
		out, err = ports.TakeSecret(f)
		return err
	})
	return out, err
}
