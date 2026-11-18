package layoutread

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/domain/sshsig"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ChainError names the head that stopped the check. Heads below it may still be
// valid; the operator may use one of them with --at, and the pin still has to
// accept it.
type ChainError struct {
	Seq uint64
	Why error
	// Is is the refusal this is (ErrChain, ErrSignature, ErrWorkspace, ...).
	Is error
	// LastGood is the newest head below Seq that verified; 0 for none.
	LastGood uint64
	// AtAllowed says --at LastGood would be accepted by the pin.
	AtAllowed bool
}

func (e *ChainError) Error() string {
	msg := fmt.Sprintf("%s does not verify: %v", layout.HeadPath(e.Seq), e.Why)
	if e.LastGood > 0 && e.AtAllowed {
		msg += fmt.Sprintf(". The heads below it may still be valid: the newest of them that verified is head %d. This check does not skip a head that fails; if you accept the state of head %d, run it again with --at %d (the pin still has to accept it)", e.LastGood, e.LastGood, e.LastGood)
	}
	return msg
}
func (e *ChainError) Unwrap() []error { return []error{e.Is, e.Why} }

// CheckLocked is the locked pass: everything that needs no credential. It checks
// the pin, walks and verifies the chain of heads, and fetches the slots object and
// the manifest root of the head it settles on, by hash, and checks what can be
// checked without a key.
func CheckLocked(ctx context.Context, in LockedInput) (*Locked, error) {
	if in.Reader == nil || in.Tables == nil {
		return nil, errors.New("layoutread: the reader or the slot table check is missing")
	}
	pin := in.Pin
	if pin.Kind != PinExact && pin.Kind != PinKey {
		return nil, ErrNoPin
	}
	if len(pin.WorkspaceID) != layout.EpochSize {
		return nil, fmt.Errorf("%w: no workspace id", ErrBadPin)
	}
	lr := &Locked{Pin: pin}
	c := &chain{in: in, lr: lr}
	if err := c.walk(ctx); err != nil {
		return nil, err
	}
	if err := c.objects(ctx); err != nil {
		return nil, err
	}
	c.report()
	return lr, nil
}

type chain struct {
	in LockedInput
	lr *Locked
	// pinnedKey is the checkpoint key the pinned head of an exact pin names;
	// pinned is the pinned head itself.
	pinnedKey []byte
	pinned    *HeadInfo
}

func (c *chain) pinKind() PinKind { return c.in.Pin.Kind }

// start is the first head the walk reads: the pinned head, or the first head of
// the chain for a key pin.
func (c *chain) start() uint64 {
	if c.pinKind() == PinExact {
		return c.in.Pin.Sequence
	}
	return 1
}

func (c *chain) floor() uint64 {
	if c.pinKind() == PinExact {
		return c.in.Pin.Sequence
	}
	if c.in.Pin.HasMin {
		return c.in.Pin.MinSeq
	}
	return 1
}

func (c *chain) walk(ctx context.Context) error {
	pin, opt := c.in.Pin, c.in.Opt
	start := c.start()
	if opt.HasAt && opt.At < c.floor() {
		return fmt.Errorf("%w: --at %d is below the pin, which names head %d or a later one; an older head is not accepted", ErrRolledBack, opt.At, c.floor())
	}
	if opt.HasAt && opt.At > MaxSequence {
		return fmt.Errorf("%w: --at %d is not a head sequence number", ErrBadPin, opt.At)
	}
	var prev *HeadInfo
	count := 0
	for seq := start; ; seq++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count >= MaxHeads {
			// a head past the limit exists only if it can be read
			if _, err := readAll(ctx, c.in.Reader, layout.HeadPath(seq), layout.MaxHeadSize); err == nil || !errors.Is(err, ports.ErrObjectNotFound) {
				return fmt.Errorf("%w: more than %d heads from sequence %d; a layout of this tool's holds far fewer. Use --at to name a head, or a pin of a later head", ErrLimit, MaxHeads, start)
			}
			c.lr.Newest = true
			break
		}
		hi, err := c.readHead(ctx, seq)
		if errors.Is(err, ports.ErrObjectNotFound) {
			if prev == nil {
				return fmt.Errorf("%w: the directory has no %s, the head the pin names (or its first head): the directory was rolled back or replaced, or it is not this workspace's layout", ErrRolledBack, layout.HeadPath(seq))
			}
			if opt.HasAt {
				return fmt.Errorf("%w: --at %d names %s, which is not in the directory (the chain of heads ends at %s)", ErrNoHead, opt.At, layout.HeadPath(opt.At), layout.HeadPath(seq-1))
			}
			c.lr.Newest = true
			break
		}
		if err == nil {
			err = c.verifyHead(ctx, hi, prev)
		}
		if err != nil {
			return c.fail(seq, err, prev)
		}
		c.lr.Chain = append(c.lr.Chain, *hi)
		prev = &c.lr.Chain[len(c.lr.Chain)-1]
		count++
		if opt.HasAt && seq == opt.At {
			break
		}
	}
	c.lr.Used = *prev
	if pin.Kind == PinKey && pin.HasMin && prev.Head.Sequence < pin.MinSeq {
		return fmt.Errorf("%w: the newest head of the directory is %d and the pin refuses anything below %d: the directory was rolled back, or this is an older copy", ErrRolledBack, prev.Head.Sequence, pin.MinSeq)
	}
	return nil
}

// fail turns the error of one head into the refusal that names it.
func (c *chain) fail(seq uint64, err error, prev *HeadInfo) error {
	var te *typedErr
	if !errors.As(err, &te) {
		te = &typedErr{is: ErrChain, err: err}
	}
	ce := &ChainError{Seq: seq, Why: te.err, Is: te.is}
	if prev != nil {
		ce.LastGood = prev.Head.Sequence
		ce.AtAllowed = ce.LastGood >= c.floor()
	}
	return ce
}

type typedErr struct {
	is  error
	err error
}

func (e *typedErr) Error() string { return e.err.Error() }
func (e *typedErr) Unwrap() error { return e.err }

func terr(is error, f string, a ...any) error {
	return &typedErr{is: is, err: fmt.Errorf(f, a...)}
}

func (c *chain) readHead(ctx context.Context, seq uint64) (*HeadInfo, error) {
	b, err := readAll(ctx, c.in.Reader, layout.HeadPath(seq), layout.MaxHeadSize)
	if err != nil {
		if errors.Is(err, ports.ErrObjectNotFound) {
			return nil, err
		}
		return nil, terr(ErrChain, "it could not be read: %v", err)
	}
	h, perr := layout.ParseHead(b)
	if perr != nil {
		return nil, terr(ErrChain, "it is not a valid head note: %v", perr)
	}
	if h.Sequence != seq {
		return nil, terr(ErrChain, "the note says sequence %d under the name of sequence %d", h.Sequence, seq)
	}
	return &HeadInfo{Head: h, Note: b, Hash: layout.HeadHash(b)}, nil
}

// verifyHead applies the rules of the pin to one head, given the head before it.
func (c *chain) verifyHead(ctx context.Context, hi *HeadInfo, prev *HeadInfo) error {
	pin := c.in.Pin
	h := hi.Head
	if !bytes.Equal(h.Workspace, pin.WorkspaceID) {
		return terr(ErrWorkspace, "it names workspace %x, not the pinned workspace %x", h.Workspace, pin.WorkspaceID)
	}
	if prev != nil && !bytes.Equal(h.Previous, prev.Hash) {
		return terr(ErrChain, "its previous hash is not the hash of %s", layout.HeadPath(prev.Head.Sequence))
	}
	if prev == nil && pin.Kind == PinExact && !bytes.Equal(hi.Hash, pin.HeadHash) {
		return terr(ErrPinHash, "%s is not the head the pin names (its hash is %x, the pin's %x): the directory was replaced or rolled back", layout.HeadPath(h.Sequence), hi.Hash, pin.HeadHash)
	}
	want := c.wantKey(h, prev)
	signed, by, serr := c.signature(ctx, hi, want)
	hi.Signed, hi.SignedBy = signed, by
	switch {
	case pin.Kind == PinKey:
		if serr != nil {
			return terr(ErrSignature, "its signature does not verify against the pinned key %x: %v", pin.KeyHash, serr)
		}
		if !signed {
			return terr(ErrSignature, "it has no signature, and the pin is a checkpoint key: every head the used head depends on must carry a signature of that key")
		}
		if !bytes.Equal(h.CheckpointKey, pin.KeyHash) {
			return terr(ErrSignature, "it names another checkpoint key (%s) than the pinned one", keyName(h.CheckpointKey))
		}
	case prev == nil:
		// the pinned head: the pin vouches for it; a signature is information
		c.pinnedKey = h.CheckpointKey
		c.pinned = hi
		if serr != nil {
			c.lr.Notices = append(c.lr.Notices, fmt.Sprintf("%s.sig does not verify (%v); it is not counted as a signature", layout.HeadPath(h.Sequence), serr))
		}
	case c.pinnedKey != nil:
		// a head above an exact pin: the pinned head named a key, and this one must
		// name the same key and carry its signature, or anyone who can write the
		// directory could append it
		if !bytes.Equal(h.CheckpointKey, c.pinnedKey) {
			return terr(ErrSignature, "it names another checkpoint key (%s) than the pinned head's (%x)", keyName(h.CheckpointKey), c.pinnedKey)
		}
		if serr != nil {
			return terr(ErrSignature, "its signature does not verify against the key the pinned head names (%x): %v", c.pinnedKey, serr)
		}
		if !signed {
			return terr(ErrSignature, "it has no signature, and the pinned head names the checkpoint key %x: a head above the pin must be signed by it", c.pinnedKey)
		}
	default:
		// a head above an exact pin that named no key: chained by hash only. A key
		// cannot appear after the pin without the pin vouching for it: the note's key
		// and time are not bound by the manifest, so a head that names a key here is
		// one anyone who can write the directory could have made.
		if h.CheckpointKey != nil {
			return terr(ErrSignature, "it names a checkpoint key (%x), but the pinned head names none: a key cannot appear after the pin without the pin vouching for it. Use a newer exact pin of a head that names it, or the key pin", h.CheckpointKey)
		}
		if serr != nil {
			c.lr.Notices = append(c.lr.Notices, fmt.Sprintf("%s.sig does not verify (%v); it is not counted as a signature", layout.HeadPath(h.Sequence), serr))
		}
	}
	return nil
}

func keyName(k []byte) string {
	if k == nil {
		return "none"
	}
	return fmt.Sprintf("%x", k)
}

// wantKey is the key hash a signature of this head must have: the pinned key, the
// key the pinned head names, or, for a head with no authority above it, the key
// the head names itself.
func (c *chain) wantKey(h layout.Head, prev *HeadInfo) []byte {
	switch {
	case c.pinKind() == PinKey:
		return c.in.Pin.KeyHash
	case prev != nil && c.pinnedKey != nil:
		return c.pinnedKey
	}
	return h.CheckpointKey
}

// signature reads and verifies heads/<seq>.sig against the key hash want (the key
// of the signature itself when want is nil there is nothing to verify against
// and the file is not counted). No file is (false, nil, nil).
func (c *chain) signature(ctx context.Context, hi *HeadInfo, want []byte) (bool, []byte, error) {
	b, err := readAll(ctx, c.in.Reader, layout.HeadPath(hi.Head.Sequence)+".sig", maxSigBytes)
	if errors.Is(err, ports.ErrObjectNotFound) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if want == nil {
		return false, nil, errors.New("the pin does not vouch for any key to check it with, and the head names none")
	}
	blob, err := sshsig.Dearmor(b)
	if err != nil {
		return false, nil, err
	}
	res, err := sshsig.Verify(blob, hi.Note, layout.NamespaceHead, want, checkpoint.Application)
	if err != nil {
		return false, nil, err
	}
	return true, res.Key.Hash(), nil
}

// slotsOf fetches the slots object a head names, by hash and within its bound, and
// checks what needs no key: it parses strictly, is of the head's key epoch and the
// pinned workspace, binds the recovery key the head names, and its slot table
// passes the store's unlock-policy check (which also refuses a FIDO2 slot naming
// an RP id that is not the workspace's own).
func (c *chain) slotsOf(ctx context.Context, h layout.Head) ([]byte, layout.SlotsObject, error) {
	stored, err := fetchBounded(ctx, c.in.Reader, h.Slots, "the slots object", layout.MaxSlotsObject)
	if err != nil {
		return nil, layout.SlotsObject{}, err
	}
	epoch, so, err := layout.ParseSlotsObject(stored)
	if err != nil {
		return nil, so, fmt.Errorf("%w: %v", ErrSlots, err)
	}
	if !bytes.Equal(epoch, h.Epoch) {
		return nil, so, fmt.Errorf("%w: the key epoch of the slots object (%x) is not the key epoch the head names (%x): it is another epoch's slot table", ErrSlots, epoch, h.Epoch)
	}
	if !bytes.Equal(so.Meta.WorkspaceID, c.in.Pin.WorkspaceID) {
		return nil, so, fmt.Errorf("%w: the slots object is of another workspace (%x)", ErrSlots, so.Meta.WorkspaceID)
	}
	if !bytes.Equal(so.Meta.RecoveryPubHash, h.RecoveryKey) {
		return nil, so, fmt.Errorf("%w: the recovery key of the slots object is not the one the head names (%s)", ErrSlots, keyName(h.RecoveryKey))
	}
	meta, slots := SnapshotOf(so)
	if err := c.in.Tables.CheckSlotTable(meta, slots); err != nil {
		return nil, so, fmt.Errorf("%w: the slot table breaks its unlock policy (%s): %v", ErrSlots, so.Meta.Policy, err)
	}
	return stored, so, nil
}

// objects fetches the slots object and the manifest root of the head used and
// checks what needs no key. The slot table decides which credential is asked for
// and what the authenticator is asked, so it must be one the pin vouches for: with
// a key pin the head, and so the hash of the table, is signed; with an exact pin
// the table is the pinned head's, or that of a later head that is not weaker,
// binds the same recovery key and passes the store's own check.
func (c *chain) objects(ctx context.Context) error {
	h := c.lr.Used.Head
	stored, so, err := c.slotsOf(ctx, h)
	if err != nil {
		return err
	}
	c.lr.Vouched = so.Meta.Policy
	if c.pinned != nil && !bytes.Equal(c.pinned.Head.Slots, h.Slots) {
		_, pso, err := c.slotsOf(ctx, c.pinned.Head)
		if err != nil {
			return fmt.Errorf("the pinned head's own slots object: %w", err)
		}
		c.lr.Vouched = pso.Meta.Policy
		remedy := fmt.Sprintf("this check will not ask for a credential on the word of a table the pin does not vouch for. Pin a head that carries it (a newer exact pin), use a key pin, or use --at %d", c.pinned.Head.Sequence)
		if unlock.Weakens(unlock.Policy(pso.Meta.Policy), unlock.Policy(so.Meta.Policy)) {
			return fmt.Errorf("%w: %s names a slot table of policy %s, which is weaker than the pinned head's (%s); %s", ErrSlots, layout.HeadPath(h.Sequence), so.Meta.Policy, pso.Meta.Policy, remedy)
		}
		if !bytes.Equal(so.Meta.RecoveryPubHash, pso.Meta.RecoveryPubHash) {
			return fmt.Errorf("%w: %s names a slot table with another recovery key (%s) than the pinned head's (%s); %s", ErrSlots, layout.HeadPath(h.Sequence), keyName(so.Meta.RecoveryPubHash), keyName(pso.Meta.RecoveryPubHash), remedy)
		}
	}
	mstored, err := fetchObject(ctx, c.in.Reader, h.Manifest, "the manifest root")
	if err != nil {
		return err
	}
	hd, err := layout.ParseHeader(mstored)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if hd.Format != layout.FormatSealed {
		return fmt.Errorf("%w: the manifest root is not a sealed object", ErrManifest)
	}
	if !bytes.Equal(hd.Epoch, h.Epoch) {
		return fmt.Errorf("%w: the manifest root is sealed under key epoch %x, not the head's %x: it belongs to another export", ErrManifest, hd.Epoch, h.Epoch)
	}
	c.lr.Slots, c.lr.ManifestStored = so, mstored
	c.lr.SlotsBytes, c.lr.ManifestBytes = len(stored), len(mstored)
	return nil
}

func (c *chain) report() {
	lr, pin := c.lr, c.in.Pin
	u := lr.Used
	switch {
	case u.Signed:
		lr.Established = append(lr.Established, fmt.Sprintf("head %d is signed by checkpoint key %x (user presence and verification set)", u.Head.Sequence, u.SignedBy))
	default:
		lr.Notices = append(lr.Notices, fmt.Sprintf("head %d is not signed: it is protected against accidents (a half-written or damaged directory), not against forgery. Whoever can write to the directory can write a head of their own; only the pin you brought, and the chain of hashes down to it, tie this head to a state you trust", u.Head.Sequence))
	}
	switch pin.Kind {
	case PinExact:
		lr.Notices = append(lr.Notices, fmt.Sprintf("head %d is the newest head this directory offers, not necessarily the newest that exists: a head above the pin that was deleted cannot be detected. Only a key pin with a minimum sequence, or a newer exact pin, says what the newest is", u.Head.Sequence))
		lr.Established = append(lr.Established, fmt.Sprintf("head %d is the head the pin names, or chains from it by hash, with %d head(s) examined and no gap", c.start(), len(lr.Chain)))
		if above := len(lr.Chain) - 1; above > 0 && c.pinnedKey == nil {
			lr.Notices = append(lr.Notices, fmt.Sprintf("%d head(s) above the pinned head chain from it by hash only: the pinned head names no checkpoint key, so nothing authenticates them. Anyone who could write to the directory could have added them; --at %d uses only the pinned head", above, pin.Sequence))
		}
	case PinKey:
		lr.Established = append(lr.Established, fmt.Sprintf("every one of the %d head(s) from 1 to %d carries a signature of the pinned checkpoint key", len(lr.Chain), u.Head.Sequence))
		if !pin.HasMin {
			lr.Notices = append(lr.Notices, fmt.Sprintf("this pin has no minimum sequence: it proves head %d is authentic, not that it is the newest head the key ever signed. Add :<sequence> to the pin to refuse anything older", u.Head.Sequence))
		}
	}
	if !lr.Newest {
		lr.Notices = append(lr.Notices, fmt.Sprintf("head %d was chosen or is the last one this check examined; the directory may hold newer heads that were not examined (heads are looked up by number, not listed)", u.Head.Sequence))
	}
	lr.Established = append(lr.Established,
		fmt.Sprintf("the slots object (%d bytes) and the manifest root (%d bytes) are in the directory, hash to their names, are of a bucket size, and belong to workspace %x and key epoch %x", lr.SlotsBytes, lr.ManifestBytes, pin.WorkspaceID, u.Head.Epoch),
		fmt.Sprintf("the slot table (policy %s) satisfies its unlock policy, and is one the pin vouches for (the credential asked for follows from the pinned table's policy, %s)", lr.Slots.Meta.Policy, lr.Vouched))
	lr.Cannot = append(lr.Cannot,
		"a locked check cannot open any sealed object: it does not know whether the manifest root, its pages or the records and audit rows are what the head says, or whether they can be decrypted",
		"it cannot check the audit chain, the record hashes the chain recorded, or the epoch MAC: those need the workspace keys",
		"it cannot tell that the records are the ones you expect; run the check again without --locked, with the credential of the workspace, to open the objects")
}
