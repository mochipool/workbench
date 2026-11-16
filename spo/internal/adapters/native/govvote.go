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
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Vote files and the voting procedures of a body, as cardano-cli 11.2.3.0
// writes them.
//
// A vote file is a text envelope of type "Governance voting procedures"
// whose cborHex is a one-voter, one-action voting-procedures map:
//
//	{ [voter type, hash] => { [tx id, index] => [decision, anchor / null] } }
//
// with the voter type 0 (committee hot key), 1 (committee hot script), 2 (DRep
// key), 3 (DRep script), 4 (pool) and the decision 0 (no), 1 (yes), 2 (abstain).
const voteEnvelopeType = "Governance voting procedures"

func voterTag(v governance.Voter) (byte, error) {
	switch v.Role {
	case governance.RoleCommitteeHot:
		if v.Cred.Script {
			return 1, nil
		}
		return 0, nil
	case governance.RoleDRep:
		if v.Cred.Script {
			return 3, nil
		}
		return 2, nil
	case governance.RolePool:
		if v.Cred.Script {
			return 0, errors.New("a pool voter has a key credential")
		}
		return 4, nil
	}
	return 0, fmt.Errorf("unknown voter role %q", v.Role)
}

func decisionCode(d governance.Decision) (uint64, error) {
	switch d {
	case governance.No:
		return 0, nil
	case governance.Yes:
		return 1, nil
	case governance.Abstain:
		return 2, nil
	}
	return 0, fmt.Errorf("unknown decision %q", d)
}

// SanitizeVoteDescription is governance.SanitizeDescription.
func SanitizeVoteDescription(title string) string { return governance.SanitizeDescription(title) }

// BuildVoteFile implements ports.VoteFileBuilder. CLIEnvelope is the file
// `cardano-cli governance vote create` writes (four-space indent, empty
// description); Envelope is what 24a stores: the same with the description
// injected and jq's two-space indent.
//
// spec: SPO-24a-EXT-004, SPO-24a-OUT-001, SPO-Pfiles-OUT-029
func (Ledger) BuildVoteFile(v governance.Vote, description string) (ports.VoteFile, error) {
	if err := v.Validate(); err != nil {
		return ports.VoteFile{}, err
	}
	tag, err := voterTag(v.Voter)
	if err != nil {
		return ports.VoteFile{}, err
	}
	code, err := decisionCode(v.Decision)
	if err != nil {
		return ports.VoteFile{}, err
	}
	var b []byte
	b = cborMap(b, 1)
	b = cborArray(b, 2)
	b = cborUint(b, uint64(tag))
	b = cborBytes(b, v.Voter.Cred.Hash[:])
	b = cborMap(b, 1)
	b = cborArray(b, 2)
	b = cborBytes(b, v.Action.TxID[:])
	b = cborUint(b, uint64(v.Action.Index))
	b = cborArray(b, 2)
	b = cborUint(b, code)
	b = gAnchor(b, v.Anchor.URL, v.Anchor.Hash, !v.Anchor.IsZero())
	cli, err := textEnvelope(voteEnvelopeType, "", hex.EncodeToString(b), "    ")
	if err != nil {
		return ports.VoteFile{}, err
	}
	env, err := textEnvelope(voteEnvelopeType, description, hex.EncodeToString(b), "  ")
	if err != nil {
		return ports.VoteFile{}, err
	}
	out := ports.VoteFile{Vote: v, CBOR: b, Envelope: env, CLIEnvelope: cli, Description: description}
	back, err := Ledger{}.DecodeVoteFile(env)
	if err != nil || back.Vote != v {
		return ports.VoteFile{}, errors.New("the encoded vote does not read back as the vote it was made from")
	}
	return out, nil
}

// DecodeVoteFile implements ports.VoteFileBuilder. A file with more than one
// voter or one action is refused (upstream examines the first entry only).
//
// spec: SPO-24b-IF-005, SPO-24b-PRE-003
func (Ledger) DecodeVoteFile(envelope []byte) (ports.VoteFile, error) {
	var e struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}
	if err := json.Unmarshal(envelope, &e); err != nil || e.CborHex == "" {
		return ports.VoteFile{}, errors.New("the file is not a text envelope with a cborHex")
	}
	if e.Type != voteEnvelopeType {
		return ports.VoteFile{}, fmt.Errorf("the envelope type is %q, not %q: not a vote file", e.Type, voteEnvelopeType)
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil {
		return ports.VoteFile{}, errors.New("the vote cborHex is not hex")
	}
	v, err := decodeVotingProcedures(raw)
	if err != nil {
		return ports.VoteFile{}, err
	}
	return ports.VoteFile{Vote: v, CBOR: raw, Envelope: append([]byte(nil), envelope...), Description: e.Description}, nil
}

func decodeVotingProcedures(raw []byte) (governance.Vote, error) {
	it, err := gparseAll(raw)
	if err != nil {
		return governance.Vote{}, fmt.Errorf("the vote: %w", err)
	}
	if it.major != 5 || len(it.keys) != 1 {
		return governance.Vote{}, errors.New("the vote file must hold exactly one voter")
	}
	voter, inner := it.keys[0], it.vals[0]
	if voter.major != 4 || len(voter.arr) != 2 || voter.arr[0].major != 0 || voter.arr[1].major != 2 || len(voter.arr[1].b) != 28 {
		return governance.Vote{}, errors.New("the voter is not [type, 28-byte hash]")
	}
	var v governance.Vote
	copy(v.Voter.Cred.Hash[:], voter.arr[1].b)
	switch voter.arr[0].u {
	case 0:
		v.Voter.Role = governance.RoleCommitteeHot
	case 1:
		v.Voter.Role, v.Voter.Cred.Script = governance.RoleCommitteeHot, true
	case 2:
		v.Voter.Role = governance.RoleDRep
	case 3:
		v.Voter.Role, v.Voter.Cred.Script = governance.RoleDRep, true
	case 4:
		v.Voter.Role = governance.RolePool
	default:
		return governance.Vote{}, fmt.Errorf("unknown voter type %d", voter.arr[0].u)
	}
	if inner.major != 5 || len(inner.keys) != 1 {
		return governance.Vote{}, errors.New("the vote file must hold exactly one governance action")
	}
	id, proc := inner.keys[0], inner.vals[0]
	if id.major != 4 || len(id.arr) != 2 || id.arr[0].major != 2 || len(id.arr[0].b) != 32 || id.arr[1].major != 0 {
		return governance.Vote{}, errors.New("the action id is not [tx id, index]")
	}
	copy(v.Action.TxID[:], id.arr[0].b)
	v.Action.Index = uint32(id.arr[1].u)
	if proc.major != 4 || len(proc.arr) != 2 || proc.arr[0].major != 0 {
		return governance.Vote{}, errors.New("the voting procedure is not [vote, anchor]")
	}
	switch proc.arr[0].u {
	case 0:
		v.Decision = governance.No
	case 1:
		v.Decision = governance.Yes
	case 2:
		v.Decision = governance.Abstain
	default:
		return governance.Vote{}, fmt.Errorf("unknown vote %d", proc.arr[0].u)
	}
	a := proc.arr[1]
	if !a.isNull() {
		if a.major != 4 || len(a.arr) != 2 || a.arr[0].major != 3 || a.arr[1].major != 2 || len(a.arr[1].b) != 32 {
			return governance.Vote{}, errors.New("the anchor is not [url, hash]")
		}
		v.Anchor.URL = string(a.arr[0].b)
		copy(v.Anchor.Hash[:], a.arr[1].b)
	}
	return v, nil
}

// encodeVotingProcedures merges the vote files of a body into the one
// voting-procedures map of body key 19: voters in the ledger's order
// (committee hot, DRep, pool; script before key within a role; then by hash),
// each voter's actions by transaction id then index. cardano-cli writes this
// order; the oracle compares it for key voters of the three roles. A voter and
// action that occur twice are refused.
//
// spec: SPO-24b-IF-005, SPO-24b-PRE-005, SPO-24b-OUT-001
func encodeVotingProcedures(votes []txbuild.VoteAttachment) ([]byte, error) {
	type entry struct {
		id   [33 + 4]byte // tx id, index (4 bytes) for ordering
		idb  []byte
		proc []byte
	}
	type voterEntry struct {
		raw     []byte
		group   int
		script  bool
		hash    []byte
		entries []entry
	}
	var voters []*voterEntry
	for _, va := range votes {
		it, err := gparseAll(va.CBOR)
		if err != nil || it.major != 5 {
			return nil, errors.New("a vote has no voting-procedure encoding")
		}
		for i, voter := range it.keys {
			if voter.major != 4 || len(voter.arr) != 2 {
				return nil, errors.New("a voter is not [type, hash]")
			}
			t := voter.arr[0].u
			ve := &voterEntry{raw: voter.raw, group: int(t) / 2, script: t%2 == 1, hash: voter.arr[1].b}
			if t == 4 {
				ve.group, ve.script = 2, false
			}
			var found *voterEntry
			for _, x := range voters {
				if bytes.Equal(x.raw, ve.raw) {
					found = x
				}
			}
			if found == nil {
				voters = append(voters, ve)
				found = ve
			}
			inner := it.vals[i]
			for j, id := range inner.keys {
				if id.major != 4 || len(id.arr) != 2 || id.arr[0].major != 2 || len(id.arr[0].b) != 32 {
					return nil, errors.New("an action id is not [tx id, index]")
				}
				var e entry
				copy(e.id[:32], id.arr[0].b)
				ix := id.arr[1].u
				e.id[33], e.id[34], e.id[35], e.id[36] = byte(ix>>24), byte(ix>>16), byte(ix>>8), byte(ix)
				e.idb, e.proc = id.raw, inner.vals[j].raw
				for _, other := range found.entries {
					if other.id == e.id {
						return nil, fmt.Errorf("the voter votes twice on the action %x#%d", id.arr[0].b, ix)
					}
				}
				found.entries = append(found.entries, e)
			}
		}
	}
	sort.SliceStable(voters, func(i, j int) bool {
		a, b := voters[i], voters[j]
		if a.group != b.group {
			return a.group < b.group
		}
		if a.script != b.script {
			return a.script
		}
		return bytes.Compare(a.hash, b.hash) < 0
	})
	var out []byte
	out = cborMap(out, len(voters))
	for _, v := range voters {
		sort.SliceStable(v.entries, func(i, j int) bool { return bytes.Compare(v.entries[i].id[:], v.entries[j].id[:]) < 0 })
		out = append(out, v.raw...)
		out = cborMap(out, len(v.entries))
		for _, e := range v.entries {
			out = append(out, e.idb...)
			out = append(out, e.proc...)
		}
	}
	return out, nil
}

var _ = chain.TxID{}

var (
	_ ports.VoteFileBuilder = Ledger{}
)
