package poolkey

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

func hexString(b []byte) string { return hex.EncodeToString(b) }

// QueryCalidus lists the Calidus keys registered on chain (upstream 15 `query`).
// The subject is classified in upstream's order (SPO-15-IF-005); the provider
// behind Reader answers for registered pools only.
type QueryCalidus struct {
	Store ports.Store
	// Reader is nil in offline mode, which has no provider (SPO-15-PRE-006).
	Reader ports.CalidusKeyReader
}

// CalidusQueryResult is what the provider answered. An empty list is an empty
// answer, not an error (the port note of SPO-15-PRE-007).
type CalidusQueryResult struct {
	Filter  ports.CalidusFilter
	Entries []ports.CalidusEntry // oldest first, as the provider ordered them
	// UniqueIDs is the number of distinct Calidus ids in Entries.
	UniqueIDs int
}

// Run classifies the subject and reads the keys.
func (uc QueryCalidus) Run(ctx context.Context, subject string) (CalidusQueryResult, error) {
	var res CalidusQueryResult
	if uc.Reader == nil {
		return res, ErrNoReader
	}
	f, err := uc.classify(ctx, subject)
	if err != nil {
		return res, err
	}
	entries, err := uc.Reader.CalidusKeys(ctx, f)
	if err != nil {
		return res, fmt.Errorf("read the Calidus keys: %w", err)
	}
	res.Filter, res.Entries = f, entries
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.IDBech] = true
	}
	res.UniqueIDs = len(seen)
	return res, nil
}

func validCalidusID(s string) bool {
	_, err := cose.ParseCalidusID(strings.TrimSpace(s))
	return err == nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// classify is SPO-15-IF-005: the first match wins.
func (uc QueryCalidus) classify(ctx context.Context, s string) (ports.CalidusFilter, error) {
	s = trimDir(s)
	// (1) a Calidus id.
	if len(s) == 61 && strings.HasPrefix(s, "calidus1") {
		if !validCalidusID(s) {
			return ports.CalidusFilter{}, fmt.Errorf("%w: %q is not a valid Calidus id", ErrBadSubject, s)
		}
		return ports.CalidusFilter{IDBech: s}, nil
	}
	var out ports.CalidusFilter
	var found bool
	var ferr error
	err := uc.Store.View(ctx, func(r ports.Reader) error {
		get := func(k ports.Kind) ([]byte, bool) {
			if !validName(s, k) {
				return nil, false
			}
			b, err := r.Get(ports.Ref{Name: s, Kind: k})
			return b, err == nil
		}
		pubOf := func(b []byte) (string, bool) {
			pub, err := cose.VKeyFromEnvelope(b)
			if err != nil {
				ferr = fmt.Errorf("%w: %v", ErrBadSubject, err)
				return "", false
			}
			return hex.EncodeToString(pub[:]), true
		}
		poolOf := func(raw []byte) {
			bech, err := chain.Bech32Encode("pool", raw)
			if err != nil {
				ferr = err
				return
			}
			out, found = ports.CalidusFilter{PoolBech: bech}, true
		}
		// (2) <s>.calidus.id
		if b, ok := get(ports.CalidusID); ok {
			if id := strings.TrimSpace(string(b)); validCalidusID(id) {
				out, found = ports.CalidusFilter{IDBech: id}, true
			} else {
				ferr = fmt.Errorf("%w: %s holds no valid Calidus id", ErrBadSubject, ports.Ref{Name: s, Kind: ports.CalidusID})
			}
			return nil
		}
		// (3) 64 hex digits: a Calidus public key.
		if isHex(s, 64) {
			out, found = ports.CalidusFilter{PubKeyHex: strings.ToLower(s)}, true
			return nil
		}
		// (4) <s>.calidus.vkey
		if b, ok := get(ports.CalidusVKey); ok {
			if h, ok := pubOf(b); ok {
				out, found = ports.CalidusFilter{PubKeyHex: h}, true
			}
			return nil
		}
		// (5) a pool id.
		if len(s) == 56 && strings.HasPrefix(s, "pool1") {
			if _, err := chain.ParsePoolBech32(s); err != nil {
				ferr = fmt.Errorf("%w: %q is not a valid pool id", ErrBadSubject, s)
				return nil
			}
			out, found = ports.CalidusFilter{PoolBech: s}, true
			return nil
		}
		// (6) <s>.pool.id: 56 hex digits.
		if b, ok := get(ports.PoolIDFile); ok {
			if h := strings.TrimSpace(string(b)); isHex(h, 56) {
				raw, _ := hex.DecodeString(h)
				poolOf(raw)
				return nil
			}
		}
		// (7) <s>.node.vkey: the pool id is the key's hash.
		if b, ok := get(ports.NodeVKey); ok {
			if _, ok := pubOf(b); ok {
				pub, _ := cose.VKeyFromEnvelope(b)
				h := cose.Blake2b224(pub[:])
				poolOf(h[:])
			}
		}
		return nil
	})
	if err != nil {
		return ports.CalidusFilter{}, err
	}
	if ferr != nil {
		return ports.CalidusFilter{}, ferr
	}
	if found {
		return out, nil
	}
	// (8) the word all.
	if strings.EqualFold(s, "all") {
		return ports.CalidusFilter{}, nil
	}
	return ports.CalidusFilter{}, fmt.Errorf("%w: %q", ErrBadSubject, s)
}

func validName(s string, k ports.Kind) bool { return (ports.Ref{Name: s, Kind: k}).Validate() == nil }
