package poll

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/keyring"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals of SubmitPollAnswer (spec/upstream/scripts/13b_sendSpoPoll.md).
var (
	// ErrNoAnswer: the transaction carries no metadata file (SPO-13b-PRE-001).
	ErrNoAnswer = errors.New("please attach your SPO-Poll-Answer metadata file: a message given with `msg:` does not count")
	// ErrNoColdKey: `<pool>.node.skey` is missing (SPO-13b-IN-001).
	ErrNoColdKey = errors.New("the pool has no cold signing key (.node.skey)")
	// ErrHardwareColdKey: a hardware cold key is not supported by 13b
	// (SPO-13b-IN-001): only the key-file form is accepted.
	ErrHardwareColdKey = errors.New("a hardware-wallet cold key (.node.hwsfile) is not supported for a poll answer: only the key-file form is accepted")
	// ErrColdKeyMismatch: the stored cold verification key is not the one of the
	// signing key; the witness would not verify (SPO-13b-EXT-001).
	ErrColdKeyMismatch = errors.New("the pool's cold verification key does not belong to its cold signing key")
)

// SubmitPollAnswer sends the transaction that carries an SPO poll answer
// (13a's metadata) and that the pool's cold key also signs (13b): a payment as
// 01_sendLovelaces makes it, with the cold key's hash in the body's required
// signers (body key 14), the fee estimated for two witnesses and a second
// witness from the cold key. It is the shared payment pipeline with a second
// signature, not a second pipeline; the composition decides whether the signed
// transaction is submitted or queued (SPO-13b-MODE-001) and which signer holds
// the paying key (key file or hardware, SPO-13b-EXT-003, SPO-13b-EXT-004).
type SubmitPollAnswer struct {
	// Send is the wired payment use case. Its Store reads the cold key's files.
	Send wallet.SendLovelaces
}

// SubmitRequest is one answer. Payer, Destination and Amount are 13b's first
// three words as typed (the amount keywords of SPO-01sendLovelaces-IF-002), Pool
// the fourth.
type SubmitRequest struct {
	Payer, Destination, Amount string
	// Pool is the pool name as typed: an optional `.skey` and then `.node` are
	// dropped (SPO-13b-IF-002).
	Pool    string
	Message []string
	// Extras are the extra parameters from the fifth word on
	// (txparam.ForSendLovelaces, SPO-13b-IF-003). The answer is a metadata file
	// among them, or Answer.
	Extras     *txparam.Extras
	Passphrase *ports.Secret
	// Answer is the answer 13a built, handed over by the use case instead of a
	// file (the port note of 13b). Optional when Extras names a metadata file.
	Answer *Answer
}

// SubmitResult is what happened.
type SubmitResult struct {
	wallet.SendResult
	// PoolID is the pool id the answer is attributable to: the hash of the cold
	// verification key, shown as "Pool-ID" (SPO-13b-EXT-001, SPO-13b-SEC-003).
	PoolID    chain.PoolID
	SignerHex string
}

// PoolStem applies SPO-13b-IF-002: `.skey` is removed, then `.node`, so
// `mypool`, `mypool.node` and `mypool.node.skey` name the same pool.
//
// spec: SPO-13b-IF-002
func PoolStem(s string) string {
	s = strings.TrimSuffix(s, ".skey")
	return strings.TrimSuffix(s, ".node")
}

// Run sends the answer.
//
// spec: SPO-13b-IF-001, SPO-13b-IF-002, SPO-13b-IF-003, SPO-13b-IN-001, SPO-13b-IN-002, SPO-13b-PRE-001, SPO-13b-EXT-001,
// spec: SPO-13b-EXT-002, SPO-13b-EXT-003, SPO-13b-EXT-004, SPO-13b-INV-001, SPO-13b-INV-002, SPO-13b-INV-003, SPO-13b-INV-008,
// spec: SPO-13b-INV-010, SPO-13b-INV-011, SPO-13b-MODE-001
func (uc SubmitPollAnswer) Run(ctx context.Context, req SubmitRequest) (SubmitResult, error) {
	// SPO-13b-IF-001: the four words.
	if req.Payer == "" || req.Destination == "" || req.Amount == "" || req.Pool == "" {
		return SubmitResult{}, errors.New("a poll answer needs a paying address, a destination, an amount and a pool name")
	}
	// SPO-13b-PRE-001, before any chain query (the port note): at least one
	// metadata file or the answer; a message does not count.
	files := 0
	if req.Extras != nil {
		files = len(req.Extras.MetadataFiles)
	}
	if files == 0 && req.Answer == nil {
		return SubmitResult{}, ErrNoAnswer
	}
	stem := PoolStem(strings.TrimPrefix(req.Pool, "./"))
	if stem == "" || strings.ContainsAny(stem, "/\\") {
		return SubmitResult{}, fmt.Errorf("the pool name %q is not a plain name", req.Pool)
	}

	// SPO-13b-IN-001, SPO-13b-IN-002: the cold key. The paying key's files are
	// checked by the payment use case. A key held on a hardware wallet is
	// refused; the verification key gives the hash the body lists.
	var coldHash txbuild.KeyHash
	var coldKey custody.KeyRef
	var poolID chain.PoolID
	if err := uc.Send.Store.View(ctx, func(r ports.Reader) error {
		hws, err := r.Exists(ports.Ref{Name: stem, Kind: ports.NodeHwsFile})
		if err != nil {
			return err
		}
		skey, err := r.Exists(ports.Ref{Name: stem, Kind: ports.NodeSKey})
		if err != nil {
			return err
		}
		if !skey {
			if hws {
				return ErrHardwareColdKey
			}
			return fmt.Errorf("%w: %s.node.skey", ErrNoColdKey, stem)
		}
		vk, err := r.Get(ports.Ref{Name: stem, Kind: ports.NodeVKey})
		if err != nil {
			return fmt.Errorf("the cold verification key %s.node.vkey: %w", stem, err)
		}
		env, err := parseVKey(vk)
		if err != nil {
			return err
		}
		coldHash = txbuild.HashKey(env)
		if coldKey, err = keyring.Resolve(r, custody.RolePoolCold, stem); err != nil {
			return err
		}
		poolID, err = chain.PoolIDOf(env)
		return err
	}); err != nil {
		return SubmitResult{}, err
	}

	sr := wallet.SendRequest{Source: req.Payer, Destination: req.Destination, Amount: req.Amount,
		Message: req.Message, Extras: req.Extras, Passphrase: req.Passphrase,
		CoSign: &wallet.CoSigner{Label: "pool cold key", Key: coldKey,
			Hash: coldHash, RequiredSigner: true}}
	if req.Answer != nil {
		sr.ExtraFiles = []txbuild.MetadataFile{{Name: req.Answer.FileName, Format: txbuild.MetadataCBOR, Data: req.Answer.CBOR}}
	}
	res, err := uc.Send.Run(ctx, sr)
	if err != nil {
		return SubmitResult{}, err
	}
	return SubmitResult{SendResult: res, PoolID: poolID, SignerHex: fmt.Sprintf("%x", coldHash[:])}, nil
}

func parseVKey(envelope []byte) ([]byte, error) {
	env, err := pool.ParseEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return env.Key32()
}
