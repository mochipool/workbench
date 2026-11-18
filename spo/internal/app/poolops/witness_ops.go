package poolops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/hwkeys"
	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of the witness subcommands.
var (
	// ErrWitnessExpired: the transfer file's or the collection's window is
	// over (SPO-05d-PRE-003, SPO-05d-PRE-013).
	ErrWitnessExpired = errors.New("the transaction window of the witness collection is over; clear it and start again")
	// ErrAlreadySigned: a witness is signed once (SPO-05d-PRE-004).
	ErrAlreadySigned = errors.New("the witness transfer file is already signed")
	// ErrWrongSigningKey: the key's verification key is not the file's
	// signing-vkey (SPO-05d-PRE-006).
	ErrWrongSigningKey = errors.New("wrong signing key: its verification key is not the one the witness was requested for")
	// ErrSigningNotApproved: the signer did not approve what the body does.
	ErrSigningNotApproved = errors.New("the signer did not approve the transaction")
	// ErrNoApprover: a witness is never made without showing the body to the
	// signer (SPO-05d-INV-008).
	ErrNoApprover = errors.New("no way to show the transaction to the signer: refusing to sign it unseen")
	// ErrBodyNotDisplayable: the body has parts the signer cannot be shown in
	// full (SPO-05d-SEC-002).
	ErrBodyNotDisplayable = errors.New("the transaction has parts that cannot be displayed in full; refusing to sign it")
)

// SignWitnessFile signs a witness transfer file with the owner's staking key
// (upstream 05d `sign`). It runs on the signer's machine with only the file
// and the signer's keys: no descriptor is read or written
// (SPO-05d-OUT-002). Unlike upstream it decodes the transaction body
// through the viewer, refuses a body it cannot display in full, and signs
// only after the signer approves what it shows (SPO-05d-INV-008,
// SPO-05d-SEC-002).
type SignWitnessFile struct {
	Store    ports.NamedStore
	Tip      ports.TipReader
	Clock    ports.Clock
	Viewer   ports.TxViewer
	TxIDs    ports.TxIDCalculator
	Signers  ports.SignerDirectory
	Approver ports.SigningApprover
	// NetworkMagic is the network the signer works on: a body for another
	// network is refused.
	NetworkMagic uint32
}

// SignRequest names the transfer file's content and the signing key.
type SignRequest struct {
	File []byte
	// Key is the signing key name; `.staking` is appended unless it is there
	// (SPO-05d-IF-003).
	Key string
}

// SignResult is the signed file and what the signer was shown.
type SignResult struct {
	// File is the transfer file with `signedWitness` and `date-signed`
	// set, to be written back in place.
	File []byte
	// View is the decoded body.
	View party.TxView
	// Tip is the slot the window was checked against.
	Tip uint64
	// NameMismatch is set when the file's signing-name differs from the key
	// name: a warning, the vkey comparison decides (SPO-05d-PRE-005).
	NameMismatch bool
	// Hardware is true when the key is held by a hardware wallet.
	Hardware bool
}

// SigningKeyName normalises a signing key argument: a leading `./` is
// dropped and the name ends in `.staking`, once (SPO-05d-IF-003).
func SigningKeyName(arg string) string {
	arg = strings.TrimPrefix(arg, "./")
	return strings.TrimSuffix(arg, ".staking") + ".staking"
}

// WitnessFileName normalises a witness file argument: `.witness` is appended
// unless it is there (SPO-05d-IF-003, SPO-05d-IF-004).
func WitnessFileName(arg string) string {
	arg = strings.TrimPrefix(arg, "./")
	if strings.HasSuffix(arg, ".witness") {
		return arg
	}
	return arg + ".witness"
}

// Run signs the file. The checks are upstream's, in order: valid JSON, the
// window, not signed yet, the key; then the body is decoded and shown.
//
// spec: SPO-05d-IF-003, SPO-05d-PRE-001, SPO-05d-PRE-002, SPO-05d-PRE-003, SPO-05d-PRE-004, SPO-05d-PRE-005, SPO-05d-PRE-006, SPO-05d-EXT-002, SPO-05d-OUT-001, SPO-05d-OUT-002, SPO-05d-IN-003, SPO-05d-IN-004, SPO-05d-INV-007, SPO-05d-INV-008, SPO-05d-MODE-001
func (uc SignWitnessFile) Run(ctx context.Context, req SignRequest) (SignResult, error) {
	tf, err := pool.ParseTransferFile(req.File)
	if err != nil {
		return SignResult{}, err
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return SignResult{}, fmt.Errorf("current slot: %w", err)
	}
	if tf.TTL <= tip.Slot {
		return SignResult{}, fmt.Errorf("%w: ttl %d, tip %d", ErrWitnessExpired, tf.TTL, tip.Slot)
	}
	if tf.Signed() {
		return SignResult{}, ErrAlreadySigned
	}
	keyName := SigningKeyName(req.Key)
	owner := strings.TrimSuffix(keyName, ".staking")
	if owner == "" || strings.ContainsAny(owner, "/\\") {
		return SignResult{}, fmt.Errorf("%w: %q", ErrBadPoolName, req.Key)
	}
	res := SignResult{Tip: tip.Slot, NameMismatch: tf.SigningName != keyName}

	vkeyRef := ports.NamedRef{Name: owner, Kind: ports.StakingVKey}
	var vkey []byte
	var key custody.KeyRef
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		if vkey, err = r.Get(vkeyRef); err != nil {
			return fmt.Errorf("%s: %w", vkeyRef, err)
		}
		key, err = keyring.Held(r, custody.RoleStake, owner, ErrNoSigningKey)
		return err
	}); err != nil {
		return SignResult{}, err
	}
	if !sameJSON(vkey, tf.SigningVKey) {
		return SignResult{}, ErrWrongSigningKey
	}
	// Which signer answers is the directory's decision, taken now: a key
	// that no connected signer holds fails here, before anything is shown or
	// any prompt (ADR 0010 decision 3). The result says whether it is a device.
	s, err := uc.Signers.SignerFor(key)
	if err != nil {
		return SignResult{}, err
	}
	w, ok := s.(ports.TxWitnesser)
	if !ok {
		return SignResult{}, fmt.Errorf("the signer of %s cannot make witnesses", key)
	}
	res.Hardware = hwkeys.IsHardware(s)

	// Decode and show the body: the signer never approves what it cannot read.
	cbor, err := pool.ParseTxEnvelope(tf.TxBody)
	if err != nil {
		return SignResult{}, fmt.Errorf("the transaction body: %w", err)
	}
	id, err := uc.TxIDs.TransactionID(cbor)
	if err != nil {
		return SignResult{}, fmt.Errorf("the transaction body: %w", err)
	}
	body, err := uc.Viewer.BodyOf(cbor)
	if err != nil {
		return SignResult{}, fmt.Errorf("the transaction body: %w", err)
	}
	view, err := uc.Viewer.View(body)
	if err != nil {
		return SignResult{}, fmt.Errorf("%w: %v", ErrBodyNotDisplayable, err)
	}
	if view.TTL == nil || *view.TTL != tf.TTL {
		return SignResult{}, fmt.Errorf("%w: the file's ttl is not the body's", ErrBodyNotDisplayable)
	}
	if err := view.CheckNetwork(party.NetworkIDOf(uc.NetworkMagic)); err != nil {
		return SignResult{}, err
	}
	if u := view.Undisplayable(); len(u) > 0 {
		return SignResult{}, fmt.Errorf("%w: %s", ErrBodyNotDisplayable, strings.Join(u, "; "))
	}
	res.View = view
	if uc.Approver == nil {
		return SignResult{}, ErrNoApprover
	}
	ok, err = uc.Approver.ApproveSigning(ctx, tf.SigningName, view)
	if err != nil {
		return SignResult{}, err
	}
	if !ok {
		return SignResult{}, ErrSigningNotApproved
	}

	wit, err := w.Witness(ctx, key, txbuild.TxBody{CBOR: cbor, ID: id})
	if err != nil {
		return SignResult{}, err
	}
	// The answer is verified against the demanded key before it is written.
	idArr := [32]byte(id)
	if err := custody.VerifyTxWitnessOverTx(cbor, &idArr, wit.VKey, wit.Signature, key.Identity); err != nil {
		return SignResult{}, fmt.Errorf("the signer's witness does not verify: %w", err)
	}
	tf.SignedWitness = pool.WitnessEnvelope(wit)
	tf.DateSigned = rfc5322(uc.Clock.Now())
	res.File = tf.Render()
	return res, nil
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ca, _ := json.Marshal(x)
	cb, _ := json.Marshal(y)
	return bytes.Equal(ca, cb)
}

// ---- info ----------------------------------------------------------------------

// WitnessInfo reports the collection of a pool (upstream 05d `info`).
type WitnessInfo struct {
	Store ports.NamedStore
	Tip   ports.TipReader
	TxIDs ports.TxIDCalculator
}

// SlotInfo is one slot of the report.
type SlotInfo struct {
	Name  string
	Ready bool
	// FileName is the transfer file name upstream's report prints for a
	// missing slot, `<pool>.<slot basename>.witness`. It is not the name 05c
	// writes (SPO-05d-INV-002): display only.
	FileName string
}

// InfoResult is the report.
type InfoResult struct {
	// Present is false when the pool has no collection (upstream: "no
	// witnesses", exit 0).
	Present       bool
	ID            uint64
	Type          pool.RegistrationType
	TTL, Tip      uint64
	Ticker        string
	PayName       string
	MetadataFiles string
	State         pool.CollectionState
	Slots         []SlotInfo
}

// Run reads the collection. An expired collection is reported in full and
// the error says so (upstream cuts the report off at the TTL and exits 1,
// SPO-05d-PRE-013). The chain tip is read in the work mode of the
// composition, offline from the genesis files and the clock
// (SPO-05d-MODE-001).
//
// spec: SPO-05d-IF-005, SPO-05d-IN-002, SPO-05d-IN-004, SPO-05d-PRE-012, SPO-05d-PRE-013, SPO-05d-INV-002, SPO-05d-MODE-001
func (uc WitnessInfo) Run(ctx context.Context, poolArg string) (InfoResult, error) {
	name, err := poolName(poolArg)
	if err != nil {
		return InfoResult{}, err
	}
	var d *pool.Descriptor
	if err := uc.Store.View(ctx, func(r ports.NamedReader) error {
		var err error
		d, err = readDescriptor(r, name)
		return err
	}); err != nil {
		return InfoResult{}, err
	}
	coll, err := d.Collection(uc.TxIDs.TransactionID)
	if err != nil {
		return InfoResult{}, err
	}
	if coll == nil {
		return InfoResult{}, nil
	}
	tip, err := uc.Tip.Tip(ctx)
	if err != nil {
		return InfoResult{}, fmt.Errorf("current slot: %w", err)
	}
	res := InfoResult{Present: true, ID: coll.ID, Type: coll.Type, TTL: coll.TTL, Tip: tip.Slot, Ticker: d.Text(pool.FieldMetaTicker),
		PayName: coll.PayName, MetadataFiles: coll.MetadataFiles, State: coll.State(tip.Slot)}
	for _, s := range coll.Slots {
		si := SlotInfo{Name: s.Name, Ready: s.Filled()}
		if !si.Ready {
			si.FileName = name + "." + path.Base(strings.TrimSuffix(s.Name, ".staking")) + ".witness"
		}
		res.Slots = append(res.Slots, si)
	}
	if res.State == pool.CollectionExpired {
		return res, fmt.Errorf("%w: ttl %d, tip %d", ErrWitnessExpired, coll.TTL, tip.Slot)
	}
	return res, nil
}

// ---- clear ---------------------------------------------------------------------

// ClearWitnesses discards the collection of a pool (upstream 05d `clear`).
type ClearWitnesses struct {
	Store ports.NamedStore
	TxIDs ports.TxIDCalculator
}

// ClearRequest names the pool and says whether the operator confirmed.
type ClearRequest struct {
	Pool string
	// Confirmed is the answer to "do you really want to delete the witness
	// collection?" (default No, SPO-05d-PR-001). Without it nothing is
	// removed.
	Confirmed bool
}

// ClearResult says what happened.
type ClearResult struct {
	Present bool
	Cleared bool
}

// Run removes `regWitness` from the descriptor when confirmed. Without a
// collection it does nothing and says so; a declined clear is not an error
// (upstream exits 0 in every case). The descriptor is rewritten as every
// store write is, locked at 0400; upstream leaves it at 0600
// (SPO-05d-OUT-005, decision: not reproduced). Witness transfer files are not
// touched. Unlike upstream's, the removal is one store transaction.
//
// spec: SPO-05d-PR-001, SPO-05d-OUT-005, SPO-05d-INV-001, SPO-05d-IF-005
func (uc ClearWitnesses) Run(ctx context.Context, req ClearRequest) (ClearResult, error) {
	name, err := poolName(req.Pool)
	if err != nil {
		return ClearResult{}, err
	}
	var res ClearResult
	err = uc.Store.Update(ctx, func(w ports.NamedWriter) error {
		d, err := readDescriptor(w, name)
		if err != nil {
			return err
		}
		coll, err := d.Collection(uc.TxIDs.TransactionID)
		if err != nil {
			return err
		}
		if coll == nil {
			return nil
		}
		res.Present = true
		if !req.Confirmed {
			return nil
		}
		d.ClearCollection()
		res.Cleared = true
		return w.Put(ports.NamedRef{Name: name, Kind: ports.PoolDescriptor}, d.Render())
	})
	return res, err
}
