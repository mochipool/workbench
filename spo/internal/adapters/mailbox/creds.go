package mailbox

import (
	"errors"
	"fmt"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// defaultRenewMargin is how close to its end the binding may come before the
// client says so (ADR 0014 decision 3: a reminder 14 days before `until`).
const defaultRenewMargin = 14 * 24 * time.Hour

// creds is what the next connection presents: the binding and the canonical
// expected-sender list with their hashes. It is guarded by Client.credMu; a value
// is never changed once it is published, only replaced.
type creds struct {
	binding     Binding
	from, until int64 // of the binding, unix seconds
	bindingHash [wire.HashSize]byte
	senders     []wire.WalletKey // sorted, unique, at most wire.MaxSenders
	sendersHash [wire.HashSize]byte
}

// checkBinding is the client's own check of a binding, the one the relay makes
// (ADR 0014 decision 3, rules 1 to 7): it parses, it verifies, it is for this
// device, it is inside its window on the client's clock and its lifetime is inside
// the policy. A client never dials with a binding the relay would refuse. It
// returns the pieces the client keeps.
//
// spec: SPO-Xmailbox-PRE-057
func checkBinding(b Binding, device party.Fingerprint, now int64, pol relaybind.Policy) (from, until int64, hash [wire.HashSize]byte, err error) {
	if len(b.Statement) == 0 || len(b.Key) == 0 {
		return 0, 0, hash, fmt.Errorf("%w: the statement and the key are both required", ErrBindingInvalid)
	}
	st, err := relaybind.ParseStatement(b.Statement)
	if err != nil {
		return 0, 0, hash, fmt.Errorf("%w: %w", ErrBindingInvalid, err)
	}
	vkey, err := relaybind.ParseCOSEKey(b.Key)
	if err != nil {
		return 0, 0, hash, fmt.Errorf("%w: %w", ErrBindingInvalid, err)
	}
	vb, err := relaybind.VerifyBinding(st, vkey, device, now, pol)
	if err != nil {
		return 0, 0, hash, fmt.Errorf("%w: %w", ErrBindingInvalid, err)
	}
	bb := vb.Binding()
	return bb.From, bb.Until, vb.FullHash(), nil
}

// canonSenders is the client's rule for the expected-sender list: the first
// wire.MaxSenders distinct keys in the caller's own order are kept (the caller
// puts the keys that matter most first), the rest are dropped, and the kept keys
// are sorted so that one set has one encoding and one hash. dropped is how many
// distinct keys were left out.
//
// spec: SPO-Xmailbox-OUT-095
func canonSenders(in []wire.WalletKey) (out []wire.WalletKey, hash [wire.HashSize]byte, dropped int, err error) {
	seen := make(map[wire.WalletKey]struct{}, min(len(in), wire.MaxSenders+1))
	kept := make([]wire.WalletKey, 0, min(len(in), wire.MaxSenders))
	for _, k := range in {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if len(kept) < wire.MaxSenders {
			kept = append(kept, k)
		} else {
			dropped++
		}
	}
	out, err = wire.CanonicalSenders(kept)
	if err != nil {
		return nil, hash, 0, err
	}
	hash, err = wire.SendersHash(out)
	return out, hash, dropped, err
}

func (c *Client) policy() relaybind.Policy {
	if c.cfg.Policy == (relaybind.Policy{}) {
		return relaybind.DefaultPolicy()
	}
	return c.cfg.Policy
}

// snapshot is the credentials the next connection presents.
func (c *Client) snapshot() *creds {
	c.credMu.Lock()
	defer c.credMu.Unlock()
	return c.cr
}

// SetBinding gives the client a new binding to present: a renewal (ADR 0014
// decision 3: signed again before the old one ends), or the answer to
// ErrBindingRefused. It is checked as New checks the first one, and a binding
// whose `from` is earlier than the one held is refused too (the relay refuses an
// older binding of the same key and device). The wallet key is not compared: a
// binding of this device under another wallet key is taken when its `from` is not
// earlier (the relay moves the device to that key, within its own budget of key
// changes), and refused when it is, which is stricter than the relay. A binding
// with the same `from` and an earlier `until` is taken and moves BindingUntil
// back. Nothing changes when it fails. The
// next connection presents it; the connection that is open is not touched, and a
// wait caused by a refused binding ends, so the next operation dials at once
// (bounded by the dial limiter). The client signs nothing with a wallet key: the
// binding is bytes the caller got from its signing path. After Close it returns
// ports.ErrClosed.
//
// spec: SPO-Xmailbox-OUT-094
func (c *Client) SetBinding(b Binding) error {
	if c.isClosed() {
		return ports.ErrClosed
	}
	from, until, hash, err := checkBinding(b, c.cfg.Self, c.cfg.Clock.Now().Unix(), c.policy())
	if err != nil {
		return err
	}
	c.credMu.Lock()
	defer c.credMu.Unlock()
	if from < c.cr.from {
		return fmt.Errorf("%w: it starts at %d, before the binding held (%d)", ErrBindingInvalid, from, c.cr.from)
	}
	n := *c.cr
	n.binding = Binding{Statement: append([]byte(nil), b.Statement...), Key: append([]byte(nil), b.Key...)}
	n.from, n.until, n.bindingHash = from, until, hash
	c.cr = &n
	c.identityReset.Store(true)
	return nil
}

// BindingUntil is the end of the binding the next connection presents (unix
// seconds), so that the caller can renew in time.
func (c *Client) BindingUntil() int64 {
	return c.snapshot().until
}

// SetSenders gives the client the wallet keys of the parties this device
// expects mail from: the new list is presented at the next login. The relay
// fixes the list for the connection that presented it, so when the canonical set
// differs from the one the open connection presented, the client authenticates
// again at the next safe point: the start of its next operation, or the next
// fetch of a Receive that is waiting, bounded by the dial limiter like every
// connection (ADR 0014 decision 5; obligation 9). The same set again, in any
// order and with repeats, changes nothing. A list of more than 64 distinct keys
// is cut by canonSenders's rule and an event says how many were dropped.
//
// spec: SPO-Xmailbox-OUT-093, SPO-Xmailbox-OUT-095
func (c *Client) SetSenders(list []wire.WalletKey) {
	out, hash, dropped, err := canonSenders(list)
	if err != nil { // unreachable: canonSenders keeps at most wire.MaxSenders
		return
	}
	if dropped > 0 {
		c.emit(Event{Kind: EventSenders, Reason: ReasonLimit, Count: dropped})
	}
	c.credMu.Lock()
	defer c.credMu.Unlock()
	if hash == c.cr.sendersHash {
		return
	}
	n := *c.cr
	n.senders, n.sendersHash = out, hash
	c.cr = &n
}

// bindingUsable is the client's check, before it dials, that the binding it
// holds is inside its window on its own clock: the relay would refuse one that
// has expired or that is not valid yet, and a client does not ask. It is the
// ErrBindingRefused of a binding that must be renewed.
//
// spec: SPO-Xmailbox-OUT-094
func (c *Client) bindingUsable(cr *creds) error {
	now := c.cfg.Clock.Now().Unix()
	switch {
	case now > cr.until:
		return newErr(ReasonBindingExpired, errors.New("the binding has ended"), ErrBindingRefused)
	case now < cr.from-c.policy().Skew:
		return newErr(ReasonBinding, errors.New("the binding is not valid yet by this clock"), ErrBindingRefused)
	}
	return nil
}

// noteRenewal says so when the binding in use is within the renewal margin of
// its end: the caller should sign a new one and give it to SetBinding.
func (c *Client) noteRenewal(cr *creds) {
	if cr.until-c.cfg.Clock.Now().Unix() <= int64(c.margin/time.Second) {
		c.emit(Event{Kind: EventRenew, Reason: ReasonBinding, Until: cr.until})
	}
}
