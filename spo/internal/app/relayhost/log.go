package relayhost

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// logger writes the operator log: one line per event of the session, with the
// public keys and the fixed classes of relay.Event and nothing else (no envelope
// byte, no statement byte, no text a peer chose; SPO-Xmailbox-SEC-068). The
// notes of the stores at open are the stores' own fixed texts.
type logger struct {
	mu sync.Mutex
	w  io.Writer
}

func newLogger(w io.Writer) *logger { return &logger{w: w} }

func (l *logger) line(s string) {
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "spo-relay: %s %s\n", time.Now().UTC().Format(time.RFC3339), s)
}

// maxTunnelLine bounds one line of the tunnel adapter in the log.
const maxTunnelLine = 512

// tunnelPrefix starts every line the tunnel adapter writes itself.
const tunnelPrefix = "tailcat stream:"

// tunnelf is the tunnel adapter's Logf (SPO-Xmailbox-OUT-113): its own lines
// (they start with tunnelPrefix) go to the log as one line each, every control
// or unprintable character replaced by '?' so that what the line carries (an
// error of the tunnel library) cannot forge a line or drive a terminal, and cut
// at maxTunnelLine bytes. Every other line is the tunnel library's own chatter,
// which can carry what a peer sent, and is dropped.
func (l *logger) tunnelf(format string, args ...any) {
	if !strings.HasPrefix(format, tunnelPrefix) {
		return
	}
	s := fmt.Sprintf(format, args...)
	if len(s) > maxTunnelLine {
		s = s[:maxTunnelLine]
	}
	s = strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	l.line(s)
}

func (l *logger) notes(what string, notes []string) {
	for _, n := range notes {
		l.line(what + ": " + n)
	}
}

// event is the server's and the sweeper's relay.EventSink.
func (l *logger) event(e relay.Event) {
	if l == nil || l.w == nil {
		return
	}
	var b strings.Builder
	b.WriteString(string(e.Kind))
	if e.Reason != relay.ReasonNone {
		fmt.Fprintf(&b, " reason=%s", e.Reason)
	}
	if e.Node != (party.NodeKey{}) {
		fmt.Fprintf(&b, " node=%s", hex.EncodeToString(e.Node[:]))
	}
	if e.Party != (party.Fingerprint{}) {
		fmt.Fprintf(&b, " device=%s", e.Party)
	}
	if e.Key != (relaybind.KeyHash{}) {
		fmt.Fprintf(&b, " key=%s", hex.EncodeToString(e.Key[:]))
	}
	if e.Recipient != (party.Fingerprint{}) {
		fmt.Fprintf(&b, " to=%s", e.Recipient)
	}
	if e.HasCode {
		fmt.Fprintf(&b, " code=%d", e.Code)
	}
	if e.Count != 0 {
		fmt.Fprintf(&b, " count=%d", e.Count)
	}
	l.line(b.String())
}
