package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Action files, as cardano-cli 11.2.3.0 `governance action create-*` writes
// them: a text envelope of type "Governance proposal" whose cborHex is the
// proposal procedure
//
//	[deposit, reward account, governance action, anchor]
//
// with the governance action
//
//	info                [6]
//	no confidence       [3, previous id / null]
//	hard fork           [1, previous id / null, [major, minor]]
//	new constitution    [5, previous id / null, [[url, hash], guardrails script / null]]
//	update committee    [4, previous id / null, {removed credentials}, {added credential: end epoch}, threshold]
//	treasury withdrawal [2, {reward account: lovelace}, guardrails script / null]
//	parameter change    [0, previous id / null, {parameter number: value}, guardrails script / null] (govparams.go)
//
// where the committee sets and maps are ordered as the ledger orders credentials
// (script before key, then by hash) and the threshold is a tag-30 rational.
const actionEnvelopeType = "Governance proposal"

var actionDescriptions = map[governance.ActionKind]string{
	governance.InfoAction:          "Info proposal",
	governance.NoConfidenceAction:  "Motion of no confidence proposal",
	governance.HardForkInitiation:  "Hardfork initiation proposal",
	governance.NewConstitution:     "Update to the Constitution or policy proposal",
	governance.UpdateCommittee:     "New constitutional committee and/or threshold and/or terms proposal",
	governance.TreasuryWithdrawals: "Treasury withdrawal proposal",
	governance.ParameterChange:     "Update protocol parameters proposal",
}

const (
	actTagHardFork     = 1
	actTagTreasury     = 2
	actTagNoConfidence = 3
	actTagCommittee    = 4
	actTagConstitution = 5
	actTagInfo         = 6
)

func gPrev(b []byte, p *governance.ActionID) []byte {
	if p == nil {
		return append(b, 0xf6)
	}
	b = cborArray(b, 2)
	b = cborBytes(b, p.TxID[:])
	return cborUint(b, uint64(p.Index))
}

func gScript(b []byte, s *[28]byte) []byte {
	if s == nil {
		return append(b, 0xf6)
	}
	return cborBytes(b, s[:])
}

// rewardAccount is the 29 bytes of a stake address: the header byte and the
// credential hash.
func rewardAccount(a chain.StakeAddress) ([]byte, error) {
	hrp, data, err := chain.Bech32Decode(string(a))
	if err != nil {
		return nil, fmt.Errorf("stake address %q: %w", a, err)
	}
	if (hrp != "stake" && hrp != "stake_test") || len(data) != 29 {
		return nil, fmt.Errorf("%q is not a stake address", a)
	}
	return data, nil
}

// credOrder orders credentials as the ledger does: script before key, then
// by hash.
func credLess(aScript bool, ah []byte, bScript bool, bh []byte) bool {
	if aScript != bScript {
		return aScript
	}
	return bytes.Compare(ah, bh) < 0
}

// BuildActionFile implements ports.ActionFileBuilder.
//
// spec: SPO-25a-EXT-005, SPO-25a-EXT-006, SPO-25a-EXT-007, SPO-25a-EXT-008, SPO-25a-EXT-009, SPO-25a-EXT-010,
// spec: SPO-25a-EXT-012, SPO-25a-EXT-013, SPO-25a-OUT-002, SPO-Pfiles-OUT-030
func (Ledger) BuildActionFile(a governance.Action) (ports.ActionFile, error) {
	if err := a.Validate(); err != nil {
		return ports.ActionFile{}, err
	}
	if a.Kind == governance.ParameterChange {
		// The canonical set, in the ledger's order.
		params, err := governance.CheckParams(a.Params)
		if err != nil {
			return ports.ActionFile{}, err
		}
		a.Params = params
	}
	b, err := encodeAction(a)
	if err != nil {
		return ports.ActionFile{}, err
	}
	env, err := textEnvelope(actionEnvelopeType, actionDescriptions[a.Kind], hex.EncodeToString(b), "    ")
	if err != nil {
		return ports.ActionFile{}, err
	}
	out := ports.ActionFile{Action: a, CBOR: b, Envelope: env}
	back, err := Ledger{}.DecodeActionFile(env)
	if err != nil {
		return ports.ActionFile{}, fmt.Errorf("the encoded action does not read back: %w", err)
	}
	if !sameAction(a, back.Action) {
		return ports.ActionFile{}, errors.New("the encoded action reads back as another action")
	}
	return out, nil
}

// encodeAction writes the proposal procedure of an action in the form
// cardano-cli writes. DecodeActionFile requires a file to equal it.
func encodeAction(a governance.Action) ([]byte, error) {
	ret, err := rewardAccount(a.Return)
	if err != nil {
		return nil, fmt.Errorf("deposit return: %w", err)
	}
	var b []byte
	b = cborArray(b, 4)
	b = cborUint(b, uint64(a.Deposit))
	b = cborBytes(b, ret)
	switch a.Kind {
	case governance.InfoAction:
		b = cborArray(b, 1)
		b = cborUint(b, actTagInfo)
	case governance.NoConfidenceAction:
		b = cborArray(b, 2)
		b = cborUint(b, actTagNoConfidence)
		b = gPrev(b, a.Prev)
	case governance.HardForkInitiation:
		b = cborArray(b, 3)
		b = cborUint(b, actTagHardFork)
		b = gPrev(b, a.Prev)
		b = cborArray(b, 2)
		b = cborUint(b, a.Version.Major)
		b = cborUint(b, a.Version.Minor)
	case governance.NewConstitution:
		b = cborArray(b, 3)
		b = cborUint(b, actTagConstitution)
		b = gPrev(b, a.Prev)
		b = cborArray(b, 2)
		b = gAnchor(b, a.Constitution.URL, a.Constitution.Hash, true)
		b = gScript(b, a.Guardrails)
	case governance.TreasuryWithdrawals:
		type wd struct {
			acct []byte
			amt  chain.Lovelace
		}
		ws := make([]wd, len(a.Withdrawals))
		for i, w := range a.Withdrawals {
			acct, err := rewardAccount(w.Account)
			if err != nil {
				return nil, fmt.Errorf("withdrawal %d: %w", i, err)
			}
			ws[i] = wd{acct, w.Amount}
		}
		sort.SliceStable(ws, func(i, j int) bool { return rewardAccountLess(ws[i].acct, ws[j].acct) })
		for i := 1; i < len(ws); i++ {
			if bytes.Equal(ws[i].acct, ws[i-1].acct) {
				return nil, errors.New("a treasury withdrawal names the same account twice")
			}
		}
		b = cborArray(b, 3)
		b = cborUint(b, actTagTreasury)
		b = cborMap(b, len(ws))
		for _, w := range ws {
			b = cborBytes(b, w.acct)
			b = cborUint(b, uint64(w.amt))
		}
		b = gScript(b, a.Guardrails)
	case governance.ParameterChange:
		b = cborArray(b, 4)
		b = cborUint(b, actTagParameters)
		b = gPrev(b, a.Prev)
		var err error
		if b, err = encodeParamUpdate(b, a.Params); err != nil {
			return nil, err
		}
		b = gScript(b, a.Guardrails)
	case governance.UpdateCommittee:
		rem := append([]governance.Credential(nil), a.Remove...)
		sort.SliceStable(rem, func(i, j int) bool { return credLess(rem[i].Script, rem[i].Hash[:], rem[j].Script, rem[j].Hash[:]) })
		add := append([]governance.CommitteeAdd(nil), a.Add...)
		sort.SliceStable(add, func(i, j int) bool {
			return credLess(add[i].Cold.Script, add[i].Cold.Hash[:], add[j].Cold.Script, add[j].Cold.Hash[:])
		})
		b = cborArray(b, 5)
		b = cborUint(b, actTagCommittee)
		b = gPrev(b, a.Prev)
		b = cborTag(b, 258)
		b = cborArray(b, len(rem))
		for _, c := range rem {
			b = gCred(b, c.Script, c.Hash[:])
		}
		b = cborMap(b, len(add))
		for _, m := range add {
			b = gCred(b, m.Cold.Script, m.Cold.Hash[:])
			b = cborUint(b, m.Epoch)
		}
		b = cborTag(b, 30)
		b = cborArray(b, 2)
		b = cborUint(b, a.Threshold.Num)
		b = cborUint(b, a.Threshold.Den)
	default:
		return nil, fmt.Errorf("%w: %q", governance.ErrActionKind, a.Kind)
	}
	return gAnchor(b, a.Anchor.URL, a.Anchor.Hash, true), nil
}

// sameAction compares what an action file carries (the deposit-return address
// is compared by credential and network, not by spelling).
func sameAction(a, b governance.Action) bool {
	norm := func(x governance.Action) governance.Action {
		x.Return, x.ReturnKey = "", governance.Credential{}
		x.Withdrawals = append([]governance.Withdrawal(nil), x.Withdrawals...)
		sort.SliceStable(x.Withdrawals, func(i, j int) bool { return x.Withdrawals[i].Account < x.Withdrawals[j].Account })
		x.Add = append([]governance.CommitteeAdd(nil), x.Add...)
		sort.SliceStable(x.Add, func(i, j int) bool {
			return credLess(x.Add[i].Cold.Script, x.Add[i].Cold.Hash[:], x.Add[j].Cold.Script, x.Add[j].Cold.Hash[:])
		})
		x.Remove = append([]governance.Credential(nil), x.Remove...)
		sort.SliceStable(x.Remove, func(i, j int) bool {
			return credLess(x.Remove[i].Script, x.Remove[i].Hash[:], x.Remove[j].Script, x.Remove[j].Hash[:])
		})
		return x
	}
	na, nb := norm(a), norm(b)
	ja, _ := json.Marshal(na)
	jb, _ := json.Marshal(nb)
	if !bytes.Equal(ja, jb) {
		// A caller's order of members and withdrawals is not the file's.
		return false
	}
	ra, e1 := rewardAccount(a.Return)
	rb, e2 := rewardAccount(b.Return)
	return e1 == nil && e2 == nil && bytes.Equal(ra, rb)
}

func stakeAddressOf(raw []byte) (chain.StakeAddress, governance.Credential, error) {
	if len(raw) != 29 {
		return "", governance.Credential{}, errors.New("a reward account is 29 bytes")
	}
	var c governance.Credential
	copy(c.Hash[:], raw[1:])
	hdr := raw[0]
	switch hdr >> 4 {
	case 0xe:
	case 0xf:
		c.Script = true
	default:
		return "", c, fmt.Errorf("reward account header %#02x", hdr)
	}
	hrp := "stake_test"
	switch hdr & 0xf {
	case 0:
	case 1:
		hrp = "stake"
	default:
		return "", c, fmt.Errorf("reward account network %d", hdr&0xf)
	}
	s, err := chain.Bech32Encode(hrp, raw)
	return chain.StakeAddress(s), c, err
}

// DecodeActionFile implements ports.ActionFileBuilder. A tag it does not read
// is an error.
//
// spec: SPO-25b-IN-002, SPO-25b-PRE-004, SPO-25b-PRE-005, SPO-25b-PRE-006
func (Ledger) DecodeActionFile(envelope []byte) (ports.ActionFile, error) {
	var e struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(envelope, &e); err != nil || e.CborHex == "" {
		return ports.ActionFile{}, errors.New("the file is not a text envelope with a cborHex")
	}
	if e.Type != actionEnvelopeType {
		return ports.ActionFile{}, fmt.Errorf("the envelope type is %q, not %q: not an action file", e.Type, actionEnvelopeType)
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil {
		return ports.ActionFile{}, errors.New("the action cborHex is not hex")
	}
	// The indefinite-length arrays of cardano-cli's cost models are the one
	// leniency; the comparison with the builder's bytes at the end makes it
	// exact: an indefinite array anywhere else cannot equal what is built.
	it, err := gparseAllIndefinite(raw)
	if err != nil {
		return ports.ActionFile{}, fmt.Errorf("the action: %w", err)
	}
	bad := func(msg string) (ports.ActionFile, error) {
		return ports.ActionFile{}, fmt.Errorf("the action file is not a proposal procedure: %s", msg)
	}
	if it.major != 4 || len(it.arr) != 4 || it.arr[0].major != 0 || it.arr[1].major != 2 || it.arr[2].major != 4 || len(it.arr[2].arr) == 0 {
		return bad("want [deposit, reward account, action, anchor]")
	}
	var a governance.Action
	a.Deposit = chain.Lovelace(it.arr[0].u)
	if a.Return, a.ReturnKey, err = stakeAddressOf(it.arr[1].b); err != nil {
		return bad(err.Error())
	}
	anc := it.arr[3]
	if anc.major != 4 || len(anc.arr) != 2 || anc.arr[0].major != 3 || anc.arr[1].major != 2 || len(anc.arr[1].b) != 32 {
		return bad("the anchor is not [url, hash]")
	}
	a.Anchor.URL = string(anc.arr[0].b)
	copy(a.Anchor.Hash[:], anc.arr[1].b)

	g := it.arr[2].arr
	prev := func(x gitem) (*governance.ActionID, bool) {
		if x.isNull() {
			return nil, true
		}
		if x.major != 4 || len(x.arr) != 2 || x.arr[0].major != 2 || len(x.arr[0].b) != 32 || x.arr[1].major != 0 {
			return nil, false
		}
		id := &governance.ActionID{Index: uint32(x.arr[1].u)}
		copy(id.TxID[:], x.arr[0].b)
		return id, true
	}
	script := func(x gitem) (*[28]byte, bool) {
		if x.isNull() {
			return nil, true
		}
		if x.major != 2 || len(x.b) != 28 {
			return nil, false
		}
		var s [28]byte
		copy(s[:], x.b)
		return &s, true
	}
	cred := func(x gitem) (governance.Credential, bool) {
		var c governance.Credential
		if x.major != 4 || len(x.arr) != 2 || x.arr[0].major != 0 || x.arr[1].major != 2 || len(x.arr[1].b) != 28 {
			return c, false
		}
		c.Script = x.arr[0].u == 1
		copy(c.Hash[:], x.arr[1].b)
		return c, true
	}
	if g[0].major != 0 {
		return bad("the governance action tag is not an unsigned integer")
	}
	ok := true
	switch g[0].u {
	case actTagInfo:
		a.Kind = governance.InfoAction
		ok = len(g) == 1
	case actTagNoConfidence:
		a.Kind = governance.NoConfidenceAction
		ok = len(g) == 2
		if ok {
			a.Prev, ok = prev(g[1])
		}
	case actTagHardFork:
		a.Kind = governance.HardForkInitiation
		ok = len(g) == 3 && g[2].major == 4 && len(g[2].arr) == 2 && g[2].arr[0].major == 0 && g[2].arr[1].major == 0
		if ok {
			a.Prev, ok = prev(g[1])
			a.Version = governance.Version{Major: g[2].arr[0].u, Minor: g[2].arr[1].u}
		}
	case actTagConstitution:
		a.Kind = governance.NewConstitution
		ok = len(g) == 3 && g[2].major == 4 && len(g[2].arr) == 2
		if ok {
			a.Prev, ok = prev(g[1])
			c := g[2].arr[0]
			if ok && (c.major != 4 || len(c.arr) != 2 || c.arr[0].major != 3 || c.arr[1].major != 2 || len(c.arr[1].b) != 32) {
				ok = false
			}
			if ok {
				a.Constitution.URL = string(c.arr[0].b)
				copy(a.Constitution.Hash[:], c.arr[1].b)
				a.Guardrails, ok = script(g[2].arr[1])
			}
		}
	case actTagTreasury:
		a.Kind = governance.TreasuryWithdrawals
		ok = len(g) == 3 && g[1].major == 5
		if ok {
			seenAcct := map[string]bool{}
			for i, k := range g[1].keys {
				addr, key, err := stakeAddressOf(k.b)
				if k.major != 2 || err != nil || g[1].vals[i].major != 0 {
					ok = false
					break
				}
				if seenAcct[string(addr)] {
					return bad(fmt.Sprintf("the treasury withdrawal names the account %s twice", addr))
				}
				seenAcct[string(addr)] = true
				a.Withdrawals = append(a.Withdrawals, governance.Withdrawal{Account: addr, Key: key, Amount: chain.Lovelace(g[1].vals[i].u)})
			}
			if ok {
				a.Guardrails, ok = script(g[2])
			}
		}
	case actTagCommittee:
		a.Kind = governance.UpdateCommittee
		ok = len(g) == 5 && g[2].major == 6 && g[2].inner != nil && g[2].inner.major == 4 && g[3].major == 5 &&
			g[4].major == 6 && g[4].u == 30 && g[4].inner != nil && len(g[4].inner.arr) == 2 &&
			g[4].inner.arr[0].major == 0 && g[4].inner.arr[1].major == 0
		if ok {
			a.Prev, ok = prev(g[1])
		}
		if ok {
			for _, r := range g[2].inner.arr {
				c, cok := cred(r)
				if !cok {
					ok = false
					break
				}
				a.Remove = append(a.Remove, c)
			}
			for i, k := range g[3].keys {
				c, cok := cred(k)
				if !cok || g[3].vals[i].major != 0 {
					ok = false
					break
				}
				a.Add = append(a.Add, governance.CommitteeAdd{Cold: c, Epoch: g[3].vals[i].u})
			}
			a.Threshold = chain.Rational{Num: g[4].inner.arr[0].u, Den: g[4].inner.arr[1].u}
		}
	case actTagParameters:
		a.Kind = governance.ParameterChange
		ok = len(g) == 4 && g[2].major == 5
		if ok {
			a.Prev, ok = prev(g[1])
		}
		if ok {
			var perr error
			if a.Params, perr = decodeParamUpdate(g[2]); perr != nil {
				return bad(perr.Error())
			}
			a.Guardrails, ok = script(g[3])
		}
	default:
		return bad(fmt.Sprintf("the governance action tag %d is not one this adapter reads", g[0].u))
	}
	if !ok {
		return bad(fmt.Sprintf("the governance action of tag %d is malformed", g[0].u))
	}
	// What is shown is what is carried: the file must be what the builder writes
	// for the action it was read as. A non-minimal integer, a duplicate map key,
	// an unsorted set or an indefinite array outside the cost models cannot be.
	if want, err := encodeAction(a); err != nil {
		return bad(err.Error())
	} else if !bytes.Equal(want, raw) {
		return ports.ActionFile{}, errors.New("the action file is not in the canonical encoding (a non-minimal integer, an unsorted or repeated set or map entry, or an indefinite-length item other than a cost model): refusing to display what may not be what it carries")
	}
	return ports.ActionFile{Action: a, CBOR: raw, Envelope: append([]byte(nil), envelope...)}, nil
}

// encodeProposals writes the proposal-procedure set of body key 20: tag 258
// over the proposals in the order given (the ledger's ordered set keeps the
// order; the oracle compares both orders of two files).
func encodeProposals(b []byte, props [][]byte) []byte {
	b = cborTag(b, 258)
	b = cborArray(b, len(props))
	for _, p := range props {
		b = append(b, p...)
	}
	return b
}

var _ ports.ActionFileBuilder = Ledger{}

// rewardAccountLess is the ledger's order of reward accounts, the order of the
// treasury-withdrawal map that cardano-cli writes whatever the order of its
// flags: the network id first (testnet before mainnet), then the credential
// with a script before a key (the ledger's Credential has ScriptHashObj first),
// then the hash. The raw bytes do not sort this way: the header byte of a key
// account (0xe0 or 0xe1) is below that of a script account (0xf0 or 0xf1).
// Observed with cardano-cli: a script account precedes a key account.
func rewardAccountLess(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return bytes.Compare(a, b) < 0
	}
	if na, nb := a[0]&0x0f, b[0]&0x0f; na != nb {
		return na < nb
	}
	if sa, sb := a[0]&0x10 != 0, b[0]&0x10 != 0; sa != sb {
		return sa
	}
	return bytes.Compare(a[1:], b[1:]) < 0
}
