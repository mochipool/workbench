package workspace

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ownerData is what the checks see of one owner: the non-secret artefacts by
// reference, and the signing keys in plain form (guarded memory), whether
// they were plain in the source or decrypted on the way in.
type ownerData struct {
	open map[ports.Ref][]byte
	skey map[ports.Ref]*ports.Secret
}

type checker struct {
	deriver   ports.VerificationKeyDeriver
	addresses ports.AddressInspector
}

// check runs the consistency checks of an owner. It returns, per artefact, a
// failure reason, and notes for checks that could not be made. Nothing is
// written before this has passed.
//
// spec: SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-011, SPO-Pfiles-OUT-013, SPO-04c-IN-001, SPO-04c-IN-002
func (c checker) check(ctx context.Context, d ownerData) (fail map[ports.Ref]string, notes map[ports.Ref]string) {
	fail, notes = map[ports.Ref]string{}, map[ports.Ref]string{}
	c.checkKeyPairs(ctx, d, fail, notes)
	c.checkAddresses(d, fail, notes)
	checkNodeCounter(d, fail, notes)
	checkKesCounters(d, fail, notes)
	return fail, notes
}

func rawVKey(d ownerData, ref ports.Ref) ([]byte, bool) {
	data, ok := d.open[ref]
	if !ok {
		return nil, false
	}
	env, err := pool.ParseEnvelope(data)
	if err != nil {
		return nil, false
	}
	k, err := env.Key32()
	if err != nil {
		return nil, false
	}
	return k, true
}

// checkKeyPairs: a signing key's verification key matches the stored `.vkey`.
func (c checker) checkKeyPairs(ctx context.Context, d ownerData, fail, notes map[ports.Ref]string) {
	for ref, sk := range d.skey {
		role := ports.SigningKeyKinds()[ref.Kind]
		vref := ports.Ref{Name: ref.Name, Kind: role.VKey, Num: ref.Num}
		if role.VKey == "" {
			continue
		}
		vdata, have := d.open[vref]
		if !have {
			notes[ref] = "no verification key file to check against"
			continue
		}
		if c.deriver == nil {
			notes[ref] = "verification key not checked: no deriver wired"
			continue
		}
		raw, err := c.deriver.DeriveVerificationKey(ctx, sk)
		switch {
		case errors.Is(err, ports.ErrKeyTypeUnsupported):
			notes[ref] = "verification key not derivable for this key type: not checked"
			continue
		case err != nil:
			fail[ref] = "the verification key could not be derived from the signing key"
			continue
		}
		env, perr := pool.ParseEnvelope(vdata)
		stored, kerr := env.Key32()
		if perr != nil || kerr != nil {
			notes[ref] = "the verification key file is not a 32-byte key: not checked"
			continue
		}
		if !bytes.Equal(raw, stored) {
			fail[ref] = "the signing key does not belong to the verification key file"
		}
	}
}

// checkAddresses: an address file belongs to the keys of its name.
func (c checker) checkAddresses(d ownerData, fail, notes map[ports.Ref]string) {
	for ref, data := range d.open {
		if ref.Kind != ports.AddrFile {
			continue
		}
		if c.addresses == nil {
			continue
		}
		pay, havePay := rawVKey(d, ports.Ref{Name: ref.Name, Kind: ports.AddrVKey})
		if !havePay {
			continue
		}
		info, err := c.addresses.InspectAddress(chain.Address(strings.TrimSpace(string(data))))
		if err != nil {
			fail[ref] = "the address file does not hold an address"
			continue
		}
		if info.PaymentKeyHash != nil && *info.PaymentKeyHash != txbuild.HashKey(pay) {
			fail[ref] = "the address does not belong to the payment verification key of the same name"
			continue
		}
		if info.StakeKeyHash != nil {
			stakeName := strings.TrimSuffix(ref.Name, ".payment")
			if st, ok := rawVKey(d, ports.Ref{Name: stakeName, Kind: ports.StakingVKey}); ok && *info.StakeKeyHash != txbuild.HashKey(st) {
				fail[ref] = "the address does not belong to the stake verification key of the same wallet"
			}
		}
	}
}

// checkNodeCounter: the issue counter belongs to the cold verification key.
func checkNodeCounter(d ownerData, fail, notes map[ports.Ref]string) {
	for ref, data := range d.open {
		if ref.Kind != ports.NodeCounter {
			continue
		}
		c, err := pool.ParseIssueCounter(data)
		if err != nil {
			fail[ref] = "the operational certificate issue counter is malformed"
			continue
		}
		cold, ok := rawVKey(d, ports.Ref{Name: ref.Name, Kind: ports.NodeVKey})
		if !ok {
			notes[ref] = "no cold verification key to check the counter against"
			continue
		}
		if !bytes.Equal(cold, c.ColdVKey[:]) {
			fail[ref] = "the issue counter belongs to another cold key"
		}
	}
}

// checkKesCounters: the two KES counters are numbers and agree with the
// rotation rule (next is current, or current plus one).
func checkKesCounters(d ownerData, fail, notes map[ports.Ref]string) {
	var curRef, nextRef *ports.Ref
	for ref := range d.open {
		r := ref
		switch ref.Kind {
		case ports.KesCounter:
			curRef = &r
		case ports.KesCounterNext:
			nextRef = &r
		}
	}
	if curRef == nil && nextRef == nil {
		return
	}
	var cur, next *int
	bad := false
	if curRef != nil {
		n, err := pool.ParseCounter(d.open[*curRef])
		if err != nil {
			fail[*curRef] = "the KES counter is not a number"
			bad = true
		} else {
			cur = &n
		}
	}
	if nextRef != nil {
		n, err := pool.ParseCounter(d.open[*nextRef])
		if err != nil {
			fail[*nextRef] = "the next KES counter is not a number"
			bad = true
		} else {
			next = &n
		}
	}
	if bad {
		return
	}
	st := pool.NewKesState(cur, next)
	switch {
	case cur == nil && next != nil:
		fail[*nextRef] = "the next KES counter exists without the KES counter"
	case cur != nil && next != nil && *next != *cur && *next != *cur+1:
		fail[*nextRef] = "the KES counters disagree: next is not the current number or the one after it"
	default:
		if n, ok := st.Current(); ok {
			name := ports.Ref{}.Name
			if curRef != nil {
				name = curRef.Name
			}
			if _, have := d.open[ports.Ref{Name: name, Kind: ports.KesVKey, Num: n}]; !have {
				notes[*curRef] = "the KES key named by the counter has no verification key file"
			}
		}
	}
}
