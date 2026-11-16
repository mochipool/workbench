// Package partystore implements ports.PartyRegistry and ports.ReplayLog over
// ports.Store records. It keeps no state of its own: every method takes the
// Reader or Writer of the caller's transaction, so a registry change or a
// replay entry commits together with the effect it belongs to
// (SPO-Xparty-INV-007).
//
// Both are one blob each (kinds PartyRecords and PartyReplay, name "all" and
// "log"), because the Store port has no listing and one blob commits
// atomically. The registry is read whole, which is fine for the tens of
// parties an operator enrols; the replay log is capped (MaxReplayEntries).
package partystore

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	recordsRef = ports.Ref{Name: "all", Kind: ports.PartyRecords}
	replayRef  = ports.Ref{Name: "log", Kind: ports.PartyReplay}
)

// ErrCorrupt: a stored record does not parse or does not match itself.
var ErrCorrupt = errors.New("partystore: stored record is corrupt")

// Registry is the party registry over Store records.
type Registry struct{}

var _ ports.PartyRegistry = Registry{}

// partyJSON is the stored form of one party. Keys are hex.
type partyJSON struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Ed25519     string   `json:"ed25519"`
	X25519      string   `json:"x25519"`
	Node        string   `json:"node,omitempty"`
	Created     int64    `json:"created"`
	Fingerprint string   `json:"fingerprint"`
	Roles       []string `json:"roles"`
	Pools       []string `json:"pools"`
	State       string   `json:"state"`
	EnrolledAt  int64    `json:"enrolled_at"`
}

func toJSON(p party.Party) partyJSON {
	j := partyJSON{Name: p.Name, Label: p.Identity.Label, Ed25519: hex.EncodeToString(p.Identity.Ed25519[:]),
		X25519: hex.EncodeToString(p.Identity.X25519[:]), Created: p.Identity.Created.Unix(),
		Fingerprint: hex.EncodeToString(p.Fingerprint[:]), Pools: p.Pools, State: string(p.State), EnrolledAt: p.EnrolledAt.Unix()}
	if p.Identity.Node != nil {
		j.Node = hex.EncodeToString(p.Identity.Node[:])
	}
	for _, r := range p.Roles {
		j.Roles = append(j.Roles, string(r))
	}
	return j
}

func unhex(dst []byte, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(dst) {
		return ErrCorrupt
	}
	copy(dst, b)
	return nil
}

func fromJSON(j partyJSON) (party.Party, error) {
	id := party.Identity{Label: j.Label, Created: time.Unix(j.Created, 0).UTC()}
	var fp party.Fingerprint
	if err := errors.Join(unhex(id.Ed25519[:], j.Ed25519), unhex(id.X25519[:], j.X25519), unhex(fp[:], j.Fingerprint)); err != nil {
		return party.Party{}, ErrCorrupt
	}
	if j.Node != "" {
		id.Node = new(party.NodeKey)
		if err := unhex(id.Node[:], j.Node); err != nil {
			return party.Party{}, err
		}
	}
	// The fingerprint is derived, never trusted from the record.
	if id.Fingerprint() != fp {
		return party.Party{}, fmt.Errorf("%w: fingerprint does not match keys", ErrCorrupt)
	}
	p := party.Party{Identity: id, Fingerprint: fp, Name: j.Name, Pools: j.Pools, State: party.State(j.State),
		EnrolledAt: time.Unix(j.EnrolledAt, 0).UTC()}
	for _, r := range j.Roles {
		p.Roles = append(p.Roles, party.Role(r))
	}
	if p.State != party.StateActive && p.State != party.StateRevoked {
		return party.Party{}, fmt.Errorf("%w: state %q", ErrCorrupt, j.State)
	}
	return p, nil
}

func load(r ports.Reader) ([]party.Party, error) {
	b, err := r.Get(recordsRef)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var js []partyJSON
	if err := json.Unmarshal(b, &js); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	out := make([]party.Party, 0, len(js))
	for _, j := range js {
		p, err := fromJSON(j)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func store(w ports.Writer, ps []party.Party) error {
	slices.SortFunc(ps, func(a, b party.Party) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	js := make([]partyJSON, 0, len(ps))
	for _, p := range ps {
		js = append(js, toJSON(p))
	}
	b, err := json.Marshal(js)
	if err != nil {
		return err
	}
	return w.Put(recordsRef, b)
}

func (Registry) List(r ports.Reader) ([]party.Party, error) { return load(r) }

func (Registry) ByFingerprint(r ports.Reader, fp party.Fingerprint) (party.Party, error) {
	ps, err := load(r)
	if err != nil {
		return party.Party{}, err
	}
	for _, p := range ps {
		if p.Fingerprint == fp {
			return p, nil
		}
	}
	return party.Party{}, ports.ErrNotFound
}

func (Registry) ByName(r ports.Reader, name string) (party.Party, error) {
	ps, err := load(r)
	if err != nil {
		return party.Party{}, err
	}
	for _, p := range ps {
		if p.Name == name {
			return p, nil
		}
	}
	return party.Party{}, ports.ErrNotFound
}

// Put adds p. It refuses a name or fingerprint already present, so enrolling
// the same identity twice or reusing a name changes nothing.
func (Registry) Put(w ports.Writer, p party.Party) error {
	ps, err := load(w)
	if err != nil {
		return err
	}
	for _, q := range ps {
		if q.Fingerprint == p.Fingerprint {
			return party.ErrAlreadyEnrolled
		}
		if q.Name == p.Name {
			return party.ErrNameTaken
		}
	}
	return store(w, append(ps, p))
}

// Revoke sets the named party to revoked and returns it.
func (Registry) Revoke(w ports.Writer, name string) (party.Party, error) {
	ps, err := load(w)
	if err != nil {
		return party.Party{}, err
	}
	for i, p := range ps {
		if p.Name != name {
			continue
		}
		r, err := party.Revoke(p)
		if err != nil {
			return p, err
		}
		ps[i] = r
		return r, store(w, ps)
	}
	return party.Party{}, ports.ErrNotFound
}

// MaxReplayEntries caps the replay log (24 bytes each, about 800 KB). A full
// log refuses new messages, never forgets an unexpired id.
const MaxReplayEntries = 32768

const entryLen = 16 + 8

// Replay is the replay log over Store records.
type Replay struct{}

var _ ports.ReplayLog = Replay{}

type entry struct {
	id      party.MessageID
	expires int64
}

func loadReplay(r ports.Reader, now time.Time) ([]entry, error) {
	b, err := r.Get(replayRef)
	if errors.Is(err, ports.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b)%entryLen != 0 {
		return nil, fmt.Errorf("%w: replay log length", ErrCorrupt)
	}
	var out []entry
	for ; len(b) > 0; b = b[entryLen:] {
		e := entry{expires: int64(binary.BigEndian.Uint64(b[16:entryLen]))}
		copy(e.id[:], b[:16])
		if e.expires >= now.Unix() { // an id is kept until its expiry has passed
			out = append(out, e)
		}
	}
	return out, nil
}

func (Replay) Seen(r ports.Reader, id party.MessageID, now time.Time) (bool, error) {
	es, err := loadReplay(r, now)
	if err != nil {
		return false, err
	}
	for _, e := range es {
		if e.id == id {
			return true, nil
		}
	}
	return false, nil
}

// Record adds id until expires and drops expired entries in the same write.
func (Replay) Record(w ports.Writer, id party.MessageID, expires, now time.Time) error {
	es, err := loadReplay(w, now)
	if err != nil {
		return err
	}
	for _, e := range es {
		if e.id == id {
			return ports.ErrReplay
		}
	}
	if len(es) >= MaxReplayEntries {
		return ports.ErrReplayFull
	}
	es = append(es, entry{id: id, expires: expires.Unix()})
	b := make([]byte, 0, len(es)*entryLen)
	for _, e := range es {
		b = append(b, e.id[:]...)
		b = binary.BigEndian.AppendUint64(b, uint64(e.expires))
	}
	return w.Put(replayRef, b)
}
