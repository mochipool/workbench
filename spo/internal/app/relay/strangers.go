package relay

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// The stranger book is the session layer's accounting of ADR 0014 decision 5:
// for each recipient device, which of the entries in its queue were put by a
// sender that was NOT on the recipient's expected-sender list when the put was
// made. The 16 entries and 1 MiB that strangers share are counted from it.
//
// WHERE IT LIVES, AND WHY. The ADR's keep/change/remove table keeps the
// mailbox store keyed by the device fingerprint and says that the counters per
// wallet key are kept by the registry, not the store; it adds one thing to the
// store (deleting a device's queue on a revoke) and nothing else. So the class
// of an entry is not stored with it. The book keeps it in memory, per recipient,
// one record for each entry (sender, mid, size, class), bounded by what the
// store holds (256 entries a queue). It is released by exactly the events that
// remove an entry: an ack (the session removes every copy of the mid), a
// retraction (the session's own), a purge on revoke (the session drops the
// recipient), and the retention sweep, which the session does not see: the book
// compares itself with the store's own pair counters (Usage) at each admission
// and drops, oldest first, what the store no longer holds.
//
// After a restart the book is empty. The first admission for a recipient
// rebuilds it from a listing of its queue and counts every entry as a
// stranger's, because the class it was put under is not stored. That is an
// approximation for entries put before the restart and it errs toward stranger
// only: it can make a stranger wait for an ack, never let strangers pass their
// allowance. A
// sender whose every entry is a second copy of an id (the listing shows the
// first copy of an id only) is not seen by the rebuild; envelopes are sealed to
// one recipient with a fresh key, so two senders do not put identical bytes
// unless one replays the other's envelope, and the store's own bounds (queue,
// pair) still apply to every such copy.
//
// spec: SPO-Xmailbox-OUT-056 (obligation 4 of "What a session must still do in
// version 2")

type heldEntry struct {
	sender   party.Fingerprint
	mid      mailbox.Hash
	size     uint32
	stranger bool
}

type rcptBook struct {
	built bool
	held  []heldEntry // in put order, oldest first
	// reserved are the strangers' entries and bytes of puts that were admitted
	// and have not ended.
	resE, resB uint64
}

func (r *rcptBook) strangers() (entries, bytes uint64) {
	entries, bytes = r.resE, r.resB
	for _, h := range r.held {
		if h.stranger {
			entries++
			bytes += uint64(h.size)
		}
	}
	return entries, bytes
}

// The book's lock is a one-place channel, not a sync.Mutex, so that a session that
// waits for it can give up at its own deadline (lockCtx). Admission reads the
// store while it holds the lock (the rebuild, the usage counters, the devices of
// the wallet key), and a store read can wait behind the store's fsyncs: THE
// RESIDUAL is that on a slow disk admission is serialised relay-wide behind that
// read. It is bounded as follows and no further. Every read under the lock is
// given the session's context with the deadline of the put (admitPut's caller:
// the earliest of BodyTimeout, the end of the connection and the end of the
// device's binding), so a store that honours its context returns at that
// deadline, and the lock is released then; a store that ignores its context is
// bounded only by its own I/O, and until it returns the lock stays held, but every
// other session waiting for it gives up at its own deadline and answers
// `unavailable`. The releases that are bookkeeping (forget, forgetMid,
// forgetRecipient) give up at their own deadline too and are repaired by reconcile.
// finish, which must release a reservation, and strangerUsage read no store and
// wait for the lock without a deadline: they wait for at most the holder's. The
// design is kept; nothing is restructured.
//
// spec: SPO-Xmailbox-INV-037
type book struct {
	sem chan struct{}
	r   map[party.Fingerprint]*rcptBook
	// keyRes are the bytes of the puts of each wallet key that were admitted and
	// whose store call has not ended: the store does not count them yet, so the key's
	// total as a sender (summed over its devices, read from the store) would miss
	// them. They are reserved under mu with the stranger counters, so two puts of one
	// key at once cannot both pass the bound (obligation 4, OUT-086). Between the
	// store's commit and finish an entry is in both figures: the error is toward
	// refusing.
	keyRes map[relaybind.KeyHash]uint64
}

func newBook() *book {
	return &book{sem: make(chan struct{}, 1), r: map[party.Fingerprint]*rcptBook{}, keyRes: map[relaybind.KeyHash]uint64{}}
}

// lock waits for the lock without a bound: for the sections that read no store.
func (b *book) lock() { b.sem <- struct{}{} }

// lockCtx waits for the lock until ctx ends, and then gives up with its error.
func (b *book) lockCtx(ctx context.Context) error {
	select { // a free lock is taken whatever the context says
	case b.sem <- struct{}{}:
		return nil
	default:
	}
	select {
	case b.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *book) unlock() { <-b.sem }

// a token is what an admitted put holds until its store call ends.
type token struct {
	rcpt     party.Fingerprint
	sender   party.Fingerprint
	key      relaybind.KeyHash
	mid      mailbox.Hash
	size     uint32
	stranger bool
	reserved bool // the stranger allowance is reserved
	keyHeld  bool // the wallet key's bytes are reserved
}

// admitPut decides one put with ValidOpenQuota.Admit, from the usage of the store,
// the wallet key's total as a sender (the sum over its devices) and the
// recipient's stranger counters, and reserves the stranger allowance for it when
// the sender is a stranger. listed is decided by the caller from the session's
// bound wallet key against the recipient's stored list, never from a frame. It
// returns the status the put would get, and a token that finish must be given
// when that is StatusStored.
func (s *Server) admitPut(ctx context.Context, rcpt, sender party.Fingerprint, key relaybind.KeyHash, mid mailbox.Hash, size uint32, listed bool) (mailbox.Status, *token, error) {
	b := s.book
	if err := b.lockCtx(ctx); err != nil {
		return 0, nil, err
	}
	defer b.unlock()
	rb := b.r[rcpt]
	if rb == nil {
		rb = &rcptBook{}
		b.r[rcpt] = rb
	}
	if err := s.reconcile(ctx, rcpt, rb); err != nil {
		b.tidy(rcpt, rb)
		return 0, nil, err
	}
	tok := &token{rcpt: rcpt, sender: sender, key: key, mid: mid, size: size, stranger: !listed}
	for _, h := range rb.held {
		if h.sender == sender && h.mid == mid {
			// a retry of a put the store holds: the store answers duplicate and it
			// costs nothing, so it is not counted again
			return mailbox.StatusStored, tok, nil
		}
	}
	u, err := s.usage.Usage(ctx, rcpt, sender)
	if err != nil {
		return 0, nil, err
	}
	// the sender figure counts the wallet key, summed over its devices
	devs, err := s.reg.Devices(ctx, key)
	if err != nil {
		return 0, nil, err
	}
	var total uint64
	seen := false
	for _, d := range devs {
		du, err := s.usage.Usage(ctx, rcpt, d.Device)
		if err != nil {
			return 0, nil, err
		}
		total += du.SenderBytes
		if d.Device == sender {
			seen = true
		}
	}
	if !seen {
		total += u.SenderBytes
	}
	u.SenderBytes = total + b.keyRes[key] // what the key has in flight counts too
	se, sb := rb.strangers()
	st := s.quota.Admit(mailbox.OpenUsage{Usage: u, StrangerEntries: se, StrangerBytes: sb}, uint64(size), listed)
	if st != mailbox.StatusStored {
		b.tidy(rcpt, rb)
		return st, nil, nil
	}
	if !listed {
		rb.resE++
		rb.resB += uint64(size)
		tok.reserved = true
	}
	b.keyRes[key] += uint64(size)
	tok.keyHeld = true
	return mailbox.StatusStored, tok, nil
}

// finish ends the put that admit admitted: the reservation is released, and when
// the store stored the entry it is recorded with the class it was admitted under.
func (s *Server) finish(tok *token, stored bool) {
	if tok == nil {
		return
	}
	b := s.book
	b.lock()
	defer b.unlock()
	rb := b.r[tok.rcpt]
	if rb == nil {
		rb = &rcptBook{}
		b.r[tok.rcpt] = rb
	}
	if tok.reserved {
		rb.resE--
		rb.resB -= uint64(tok.size)
	}
	if tok.keyHeld {
		if b.keyRes[tok.key] -= uint64(tok.size); b.keyRes[tok.key] == 0 {
			delete(b.keyRes, tok.key)
		}
	}
	if stored {
		rb.held = append(rb.held, heldEntry{sender: tok.sender, mid: tok.mid, size: tok.size, stranger: tok.stranger})
	}
	b.tidy(tok.rcpt, rb)
}

// forget removes what a retraction took back: this sender's copy of the id.
//
// forget, forgetMid and forgetRecipient wait for the lock only until ctx ends and
// then do nothing: the book compares itself with the store's own pair counters at
// the next admission for the recipient and drops what the store no longer holds
// (reconcile), so a skipped release repairs itself, and a session is never held by
// a stalled admission for a bookkeeping step.
func (s *Server) forget(ctx context.Context, rcpt, sender party.Fingerprint, mid mailbox.Hash) {
	b := s.book
	if b.lockCtx(ctx) != nil {
		return
	}
	defer b.unlock()
	rb := b.r[rcpt]
	if rb == nil {
		return
	}
	rb.held = filterHeld(rb.held, func(h heldEntry) bool { return h.sender == sender && h.mid == mid })
	b.tidy(rcpt, rb)
}

// forgetMid removes every copy of an id: an ack removes them all.
func (s *Server) forgetMid(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) {
	b := s.book
	if b.lockCtx(ctx) != nil {
		return
	}
	defer b.unlock()
	rb := b.r[rcpt]
	if rb == nil {
		return
	}
	rb.held = filterHeld(rb.held, func(h heldEntry) bool { return h.mid == mid })
	b.tidy(rcpt, rb)
}

// forgetRecipient drops a recipient's book: its mailbox was purged.
func (s *Server) forgetRecipient(ctx context.Context, rcpt party.Fingerprint) {
	b := s.book
	if b.lockCtx(ctx) != nil {
		return
	}
	defer b.unlock()
	if rb := b.r[rcpt]; rb != nil {
		rb.held = nil
		rb.built = false
		b.tidy(rcpt, rb)
	}
}

func filterHeld(h []heldEntry, drop func(heldEntry) bool) []heldEntry {
	out := h[:0]
	for _, e := range h {
		if !drop(e) {
			out = append(out, e)
		}
	}
	return out
}

// tidy deletes the book of a recipient that holds nothing; it is rebuilt from the
// store at its next admission.
func (b *book) tidy(rcpt party.Fingerprint, rb *rcptBook) {
	if len(rb.held) == 0 && rb.resE == 0 && rb.resB == 0 {
		delete(b.r, rcpt)
	}
}

// reconcile makes the book agree with the store: a book that was never built (a
// restart, or a purge) is built from a listing; otherwise, for each sender the
// book holds, what the store counts for that pair is the most the book may hold
// for it, and the oldest records above it are dropped (the retention sweep, or
// any other removal the session did not see, removed them). The book mutex is
// held.
func (s *Server) reconcile(ctx context.Context, rcpt party.Fingerprint, rb *rcptBook) error {
	if !rb.built {
		if err := s.rebuild(ctx, rcpt, rb); err != nil {
			return err
		}
		rb.built = true
		return nil
	}
	senders := map[party.Fingerprint]struct{}{}
	for _, h := range rb.held {
		senders[h.sender] = struct{}{}
	}
	for sender := range senders {
		u, err := s.usage.Usage(ctx, rcpt, sender)
		if err != nil {
			return err
		}
		var n, bytes uint64
		for _, h := range rb.held {
			if h.sender == sender {
				n++
				bytes += uint64(h.size)
			}
		}
		for (n > u.PairEntries || bytes > u.PairBytes) && n > 0 {
			for i, h := range rb.held {
				if h.sender == sender {
					n--
					bytes -= uint64(h.size)
					rb.held = append(rb.held[:i], rb.held[i+1:]...)
					break
				}
			}
		}
	}
	return nil
}

// rebuild fills the book of rcpt from a listing of its queue. The class an entry
// was put under is not stored, so every entry is counted as a stranger's: the one
// error the rebuild can make is toward counting too many strangers (a stranger is
// refused `full` for a while, until the recipient acks), never toward letting
// strangers hold more than the allowance because the relay forgot. A listed
// sender is not limited by these counters.
func (s *Server) rebuild(ctx context.Context, rcpt party.Fingerprint, rb *rcptBook) error {
	entries, _, err := s.rd.List(ctx, rcpt, nil, mailbox.MaxMailboxEntries)
	if err != nil {
		return err
	}
	rb.held = rb.held[:0]
	for _, e := range entries {
		rb.held = append(rb.held, heldEntry{sender: e.Sender, mid: e.Mid, size: e.Size, stranger: true})
	}
	return nil
}

// onList reports whether key is on the strictly ascending list.
func onList(list []mailbox.WalletKey, key mailbox.WalletKey) bool {
	lo, hi := 0, len(list)
	for lo < hi {
		m := (lo + hi) / 2
		switch c := compareKey(list[m], key); {
		case c == 0:
			return true
		case c < 0:
			lo = m + 1
		default:
			hi = m
		}
	}
	return false
}

func compareKey(a, b mailbox.WalletKey) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// strangerUsage reports the stranger counters of a recipient (a test and the log
// read it).
func (s *Server) strangerUsage(rcpt party.Fingerprint) (entries, bytes uint64) {
	s.book.lock()
	defer s.book.unlock()
	if rb := s.book.r[rcpt]; rb != nil {
		return rb.strangers()
	}
	return 0, 0
}
