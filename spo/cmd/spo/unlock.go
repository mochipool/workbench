package main

import (
	"context"
	"errors"
	"strings"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/unlock"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// factorInputs turns what a command can present into what the store asks for.
// The recovery key arrives as typed (grouped text) and goes to the store as its
// 32 raw bytes.
func factorInputs(in cli.FactorOpen) sqlitestore.FactorInputs {
	out := sqlitestore.FactorInputs{Source: in.Source, Device: in.Device, PIN: in.PIN, Passphrase: in.Passphrase, Notify: in.Notify}
	if in.Recovery != nil {
		out.Recovery = func(ctx context.Context) (*secret.Buffer, error) {
			text, err := in.Recovery(ctx)
			if err != nil {
				return nil, err
			}
			defer text.Destroy()
			return seal.DecodeRecoveryKey(text)
		}
	}
	return out
}

// coldSource turns what a command can present of the cold sub-key factor into
// what the store asks for.
func coldSource(c cli.ColdOpen) *sqlitestore.ColdSource {
	out := &sqlitestore.ColdSource{Passphrase: c.Passphrase, Deriver: native.VKeyDeriver{}, Mnemonic: native.SoftwareKeys{}, LeaveUnreachable: c.LeaveUnreachable}
	if c.Factors != nil {
		f := factorInputs(*c.Factors)
		out.Factors = &f
	}
	return out
}

// ChangePassphraseRekeyCold is the recovery rekey that re-establishes the cold
// records under the new cold factor.
func (w sealedStore) ChangePassphraseRekeyCold(ctx context.Context, np *secret.Buffer, c cli.ColdOpen) (*secret.Buffer, error) {
	k, err := w.s.ChangePassphraseRekeyCold(ctx, np, &sqlitestore.ColdSource{Passphrase: c.Passphrase, Deriver: native.VKeyDeriver{}, Mnemonic: native.SoftwareKeys{}, LeaveUnreachable: c.LeaveUnreachable})
	return k, mapStoreErr(err)
}

// DiscardRecovery drops a recovery presentation that was not used.
func (w sealedStore) DiscardRecovery() { w.s.DiscardRecovery() }

// ColdWithoutWrap counts the cold-role records and those with no recovery wrap.
func (w sealedStore) ColdWithoutWrap(ctx context.Context) (int, int, error) {
	c, n, err := w.s.ColdWithoutWrap(ctx)
	return c, n, mapStoreErr(err)
}

// ColdProblems names the cold-role records that are out of step with the workspace.
func (w sealedStore) ColdProblems(ctx context.Context) ([]string, error) {
	st, err := w.s.ColdStatus(ctx)
	if err != nil {
		return nil, mapStoreErr(err)
	}
	var out []string
	for _, p := range st.Problems {
		out = append(out, p.Record+": "+p.Why)
	}
	return out, nil
}

// VerifyColdPayloads opens every cold-role record with the factor, read-only.
func (w sealedStore) VerifyColdPayloads(ctx context.Context) (int, error) {
	n, err := w.s.VerifyColdPayloads(ctx)
	return n, mapStoreErr(err)
}

// SetColdSource wires the cold sub-key factor of this handle.
func (w sealedStore) SetColdSource(c cli.ColdOpen) { w.s.SetColdSource(coldSource(c)) }

func describe(path string) (cli.WorkspaceInfo, error) {
	pol, slots, err := sqlitestore.Describe(path)
	if err != nil {
		return cli.WorkspaceInfo{}, mapStoreErr(err)
	}
	info := cli.WorkspaceInfo{Policy: string(pol)}
	if c, err := sqlitestore.Inspect(path); err == nil {
		info.ID, info.Records, info.AuditRows = c.WorkspaceID, c.Records, c.AuditRows
	}
	for _, x := range slots {
		s := cli.Slot{ID: x.ID, Kind: x.Kind, Legacy: x.Legacy}
		for _, f := range x.Factors {
			s.Factors = append(s.Factors, f.Kind)
			touch := ""
			if f.Kind == "fido2" {
				touch = ports.TouchProbe(f.Touch).String()
			}
			s.Touch = append(s.Touch, touch)
		}
		info.Slots = append(info.Slots, s)
	}
	return info, nil
}

func openFactors(path string, in cli.FactorOpen, o cli.OpenOptions) (cli.SealedStore, error) {
	s, err := sqlitestore.OpenWithFactors(path, factorInputs(in), sqlitestore.OpenOptions{AcceptRollback: o.AcceptRollback})
	if err != nil {
		if errors.Is(err, sqlitestore.ErrNoFactorSlot) {
			return nil, cli.ErrWrongPassphrase // the command says what was presented (cli.openSealed)
		}
		return nil, mapStoreErr(err)
	}
	return sealedStore{s}, nil
}

func (w sealedStore) Policy(ctx context.Context) (string, error) {
	p, err := w.s.Policy(ctx)
	return string(p), err
}

func (w sealedStore) AddFIDO2Slot(ctx context.Context, in cli.FactorOpen) ([]byte, error) {
	id, err := w.s.EnrolAndAddFIDO2(ctx, factorInputs(in))
	return id, mapStoreErr(err)
}

// Reauthenticate asks the authenticator again and checks the answer against the
// slot this session opened through (the approval gate of a factor session).
func (w sealedStore) Reauthenticate(ctx context.Context, in cli.FactorOpen) error {
	return mapStoreErr(w.s.Reauthenticate(ctx, factorInputs(in)))
}

func verifyFileFactors(path string, in cli.FactorOpen, deep bool) (cli.VerifyReport, error) {
	r, err := sqlitestore.VerifyFileFactors(path, factorInputs(in), deep)
	return cli.VerifyReport{Head: toHead(r.Head), Notices: r.Notices}, mapStoreErr(err)
}

// Rotate presents the current recovery credential first (the store refuses a
// rotation without it, and presenting after enrolling would leave credentials
// behind when it fails), checks the PIN of every authenticator before any
// credential is made, and only then enrols.
func (w sealedStore) Rotate(ctx context.Context, req cli.RotateRequest) (*secret.Buffer, string, error) {
	plan := sqlitestore.RotatePlan{Policy: unlock.Policy(req.Policy), KeepCopy: req.KeepCopy}
	cur, err := w.s.Policy(ctx)
	if err != nil {
		return nil, "", mapStoreErr(err)
	}
	if cur == unlock.Strict {
		plan.ConfirmRemoved = map[string]bool{}
		for _, id := range req.YesRemove {
			plan.ConfirmRemoved[strings.ToLower(id)] = true
		}
	}
	switch plan.Policy {
	case unlock.Standard:
		if req.Passphrase == nil {
			return nil, "", errors.New("a standard rotation needs the new passphrase")
		}
	case unlock.Hardware, unlock.Strict:
	default:
		return nil, "", errors.New("unknown policy")
	}
	// 1. every PIN that will be used, verified before anything is created
	var pre []sqlitestore.FactorInputs
	if plan.Policy != unlock.Standard {
		pre = append(pre, factorInputs(req.Daily))
	}
	if plan.Policy == unlock.Hardware {
		pre = append(pre, factorInputs(req.Recovery))
	}
	if cur == unlock.Hardware {
		pre = append(pre, factorInputs(req.CurrentRecovery))
	}
	if len(pre) > 0 {
		if err := sqlitestore.PreflightFactors(ctx, pre...); err != nil {
			return nil, "", mapStoreErr(err)
		}
	}
	// 2. the current recovery credential
	if cur != unlock.Strict {
		proof, err := w.s.PresentRecovery(ctx, factorInputs(req.CurrentRecovery))
		if err != nil {
			return nil, "", mapStoreErr(err)
		}
		plan.Proof = proof
		// every exit from here on, an enrolment that fails included, drops the
		// presentation (a rotation that ran has consumed it already)
		defer w.s.DiscardRecovery()
	}
	// the sub-key factor of the new table, for the cold-role records
	plan.ColdNew = &sqlitestore.ColdSource{Passphrase: req.ColdPassphrase, Deriver: native.VKeyDeriver{}, Mnemonic: native.SoftwareKeys{}, LeaveUnreachable: req.LeaveUnreachable}
	if plan.Policy != unlock.Standard {
		d := factorInputs(req.Daily)
		plan.ColdNew.Factors = &d
	}
	// 3. enrolment
	switch plan.Policy {
	case unlock.Standard:
		plan.Slots = []sqlitestore.SlotPlan{{Kind: seal.SlotPassphrase, Passphrase: req.Passphrase}, {Kind: seal.SlotRecovery}}
	case unlock.Hardware, unlock.Strict:
		daily, _, err := sqlitestore.EnrolFactor(ctx, factorInputs(req.Daily), w.s.WorkspaceNonce(), nil)
		defer daily.Output.Destroy()
		if err != nil {
			return nil, "", mapStoreErr(err)
		}
		plan.Slots = []sqlitestore.SlotPlan{{Kind: seal.SlotFIDO2HMAC, Factors: []sqlitestore.FactorPlan{daily}}}
		if plan.Policy == unlock.Hardware {
			if req.Recovery.Notify != nil {
				req.Recovery.Notify("now connect the SECOND authenticator (the recovery one)")
			}
			rec, _, err := sqlitestore.EnrolFactor(ctx, factorInputs(req.Recovery), w.s.WorkspaceNonce(), nil)
			defer rec.Output.Destroy()
			if err != nil {
				return nil, "", mapStoreErr(err)
			}
			plan.Slots = append(plan.Slots, sqlitestore.SlotPlan{Kind: seal.SlotComposite,
				Factors: []sqlitestore.FactorPlan{{Params: seal.FactorParams{Kind: seal.FactorRecovery}}, rec}})
		}
	}
	text, backup, err := w.s.Rotate(ctx, plan)
	return text, backup, mapStoreErr(err)
}

// RemoveSlot presents the current recovery credential, then removes the slot by
// a rotation that re-creates the others with their factors present.
func (w sealedStore) RemoveSlot(ctx context.Context, req cli.RemoveSlotRequest) (*secret.Buffer, string, error) {
	cur, err := w.s.Policy(ctx)
	if err != nil {
		return nil, "", mapStoreErr(err)
	}
	r := sqlitestore.RemoveRequest{SlotID: req.ID, KeepCopy: req.KeepCopy, Daily: factorInputs(req.Daily)}
	if cur != unlock.Strict {
		rin := factorInputs(req.CurrentRecovery)
		if cur == unlock.Hardware {
			if err := sqlitestore.PreflightFactors(ctx, factorInputs(req.Daily), rin); err != nil {
				return nil, "", mapStoreErr(err)
			}
		}
		var drop func()
		rin.Recovery, drop = cachedRecovery(rin.Recovery)
		defer drop()
		proof, err := w.s.PresentRecovery(ctx, rin)
		if err != nil {
			return nil, "", mapStoreErr(err)
		}
		defer w.s.DiscardRecovery()
		r.Proof = proof
		r.Recovery = rin // its recovery key is read once and cached: the store checks the kept slots with it
	}
	text, backup, err := w.s.RemoveSlotByRotation(ctx, r)
	return text, backup, mapStoreErr(err)
}

func (w sealedStore) PresentRecovery(ctx context.Context, in cli.FactorOpen) error {
	_, err := w.s.PresentRecovery(ctx, factorInputs(in))
	return mapStoreErr(err)
}

func (w sealedStore) ChangePassphraseKeepRecovery(ctx context.Context, np, text *secret.Buffer) error {
	raw, err := seal.DecodeRecoveryKey(text)
	if err != nil {
		return err
	}
	defer raw.Destroy()
	err = w.s.RekeyKeepRecovery(ctx, np, raw)
	if err == nil {
		_ = w.s.Cleanup(ctx) // a failure is retried at Close
	}
	return mapStoreErr(err)
}

// cachedRecovery reads the raw recovery key on first use and hands out copies, so
// the store can use it more than once from a descriptor that is read once.
func cachedRecovery(f func(context.Context) (*secret.Buffer, error)) (func(context.Context) (*secret.Buffer, error), func()) {
	if f == nil {
		return nil, func() {}
	}
	var raw *secret.Buffer
	get := func(ctx context.Context) (*secret.Buffer, error) {
		if raw == nil {
			b, err := f(ctx)
			if err != nil {
				return nil, err
			}
			raw = b
		}
		return secret.Fill(raw.Len(), func(dst []byte) error { return raw.Use(func(x []byte) error { copy(dst, x); return nil }) })
	}
	return get, func() {
		if raw != nil {
			raw.Destroy()
		}
	}
}
