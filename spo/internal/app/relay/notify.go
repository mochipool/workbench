package relay

import (
	"sync"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// notifier wakes the long-polls of one recipient when a put to that mailbox
// has stored. It is in-process, holds no goroutine and no timer, and is
// bounded: at most max waiters in all (a session waits on one fetch at a
// time, so the bound is the number of connections).
//
// spec: SPO-Xmailbox-INV-014
type notifier struct {
	mu  sync.Mutex
	max int
	n   int
	m   map[party.Fingerprint]map[*waiter]struct{}
}

// waiter is one long-poll's slot. ch holds at most one pending wake: a second
// wake before the first is taken adds nothing, because the waiter re-reads the
// mailbox either way.
type waiter struct {
	fp party.Fingerprint
	ch chan struct{}
}

func newNotifier(max int) *notifier {
	return &notifier{max: max, m: map[party.Fingerprint]map[*waiter]struct{}{}}
}

// subscribe makes a slot for fp, or returns nil when the bound is reached. The
// caller subscribes before it reads the mailbox, so a put between the read and
// the wait is not missed.
func (n *notifier) subscribe(fp party.Fingerprint) *waiter {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.n >= n.max {
		return nil
	}
	w := &waiter{fp: fp, ch: make(chan struct{}, 1)}
	set := n.m[fp]
	if set == nil {
		set = map[*waiter]struct{}{}
		n.m[fp] = set
	}
	set[w] = struct{}{}
	n.n++
	return w
}

// unsubscribe frees the slot; it is idempotent.
func (n *notifier) unsubscribe(w *waiter) {
	n.mu.Lock()
	defer n.mu.Unlock()
	set := n.m[w.fp]
	if _, ok := set[w]; !ok {
		return
	}
	delete(set, w)
	if len(set) == 0 {
		delete(n.m, w.fp)
	}
	n.n--
}

// wake signals every waiter of fp, without blocking.
func (n *notifier) wake(fp party.Fingerprint) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for w := range n.m[fp] {
		select {
		case w.ch <- struct{}{}:
		default:
		}
	}
}

func (n *notifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.n
}
