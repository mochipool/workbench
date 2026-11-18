package relay_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// New refuses a configuration with a missing piece.
//
// spec: SPO-Xmailbox-IF-005
func TestNewRefusesAMissingPiece(t *testing.T) {
	r := newRig(t)
	good := r.config()
	if _, err := relay.New(good); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(c *relay.Config){
		"writer":     func(c *relay.Config) { c.Writer = nil },
		"reader":     func(c *relay.Config) { c.Reader = nil },
		"acker":      func(c *relay.Config) { c.Acker = nil },
		"retractor":  func(c *relay.Config) { c.Retractor = nil },
		"usage":      func(c *relay.Config) { c.Usage = nil },
		"access":     func(c *relay.Config) { c.Access = nil },
		"clock":      func(c *relay.Config) { c.Clock = nil },
		"rand":       func(c *relay.Config) { c.Rand = nil },
		"relay key":  func(c *relay.Config) { c.RelayKey = [32]byte{} },
		"quota":      func(c *relay.Config) { c.Quota = mailbox.ValidQuota{} },
		"limits":     func(c *relay.Config) { c.Limits = relay.ValidLimits{} },
		"empty list": func(c *relay.Config) { c.Access = newAccess() },
	} {
		c := good
		mut(&c)
		if _, err := relay.New(c); err == nil {
			t.Errorf("New accepted a configuration without %s", name)
		}
	}
	// a nil sink is fine
	c := good
	c.Events = nil
	if _, err := relay.New(c); err != nil {
		t.Errorf("a nil event sink: %v", err)
	}
}

// Every limit has a ceiling in the table and a floor above zero: the ceiling is
// allowed, one more is refused, zero is refused.
//
// spec: SPO-Xmailbox-IF-005, SPO-Xmailbox-INV-012
func TestLimitsMayOnlyTighten(t *testing.T) {
	if _, err := relay.DefaultLimits().Validated(); err != nil {
		t.Fatal(err)
	}
	type field struct {
		name string
		set  func(l *relay.Limits, over bool, zero bool)
	}
	u := func(f func(l *relay.Limits) *uint, max uint) func(*relay.Limits, bool, bool) {
		return func(l *relay.Limits, over, zero bool) {
			switch {
			case zero:
				*f(l) = 0
			case over:
				*f(l) = max + 1
			}
		}
	}
	n := func(f func(l *relay.Limits) *int, max int) func(*relay.Limits, bool, bool) {
		return func(l *relay.Limits, over, zero bool) {
			switch {
			case zero:
				*f(l) = 0
			case over:
				*f(l) = max + 1
			}
		}
	}
	d := func(f func(l *relay.Limits) *time.Duration, max time.Duration) func(*relay.Limits, bool, bool) {
		return func(l *relay.Limits, over, zero bool) {
			switch {
			case zero:
				*f(l) = 0
			case over:
				*f(l) = max + 1
			}
		}
	}
	fields := []field{
		{"envelope", func(l *relay.Limits, over, zero bool) {
			if zero {
				l.MaxEnvelope = 0
			} else if over {
				l.MaxEnvelope = mailbox.MaxEnvelopeBytes + 1
			}
		}},
		{"items", u(func(l *relay.Limits) *uint { return &l.MaxItems }, mailbox.MaxItemsPerFetch)},
		{"ack", u(func(l *relay.Limits) *uint { return &l.MaxAck }, mailbox.MaxAckHashes)},
		{"connections", n(func(l *relay.Limits) *int { return &l.MaxConnections }, mailbox.MaxConnections)},
		{"per key", n(func(l *relay.Limits) *int { return &l.MaxConnsPerKey }, mailbox.MaxConnsPerKey)},
		{"new per minute", n(func(l *relay.Limits) *int { return &l.MaxNewConnsPerMinute }, mailbox.MaxNewConnsPerKeyPerMinute)},
		{"requests", n(func(l *relay.Limits) *int { return &l.MaxRequests }, mailbox.MaxRequestsPerConn)},
		{"puts per minute", n(func(l *relay.Limits) *int { return &l.MaxPutsPerMinute }, mailbox.MaxPutsPerPartyPerMinute)},
		{"concurrent puts", n(func(l *relay.Limits) *int { return &l.MaxConcurrentPuts }, mailbox.MaxConnsPerKey)},
		{"lifetime", d(func(l *relay.Limits) *time.Duration { return &l.ConnLifetime }, mailbox.ConnLifetime)},
		{"idle", d(func(l *relay.Limits) *time.Duration { return &l.IdleTimeout }, mailbox.IdleTimeout)},
		{"handshake", d(func(l *relay.Limits) *time.Duration { return &l.HandshakeTimeout }, mailbox.HandshakeTimeout)},
		{"body", d(func(l *relay.Limits) *time.Duration { return &l.BodyTimeout }, mailbox.IdleTimeout)},
		{"write", d(func(l *relay.Limits) *time.Duration { return &l.WriteTimeout }, mailbox.IdleTimeout)},
		{"bytes", func(l *relay.Limits, over, zero bool) {
			if zero {
				l.MaxBytes = 0
			} else if over {
				l.MaxBytes = mailbox.MaxBytesPerConn + 1
			}
		}},
		{"bytes sent", func(l *relay.Limits, over, zero bool) {
			if zero {
				l.MaxBytesSent = 0
			} else if over {
				l.MaxBytesSent = mailbox.MaxBytesSentPerConn + 1
			}
		}},
		{"wait", func(l *relay.Limits, over, zero bool) {
			if over {
				l.MaxWaitSeconds = mailbox.MaxFetchWaitSeconds + 1
			}
		}},
		{"retention", func(l *relay.Limits, over, zero bool) {
			if zero {
				l.RetentionSeconds = 0
			} else if over {
				l.RetentionSeconds = mailbox.MaxRetentionSeconds + 1
			}
		}},
	}
	for _, f := range fields {
		over := relay.DefaultLimits()
		f.set(&over, true, false)
		if _, err := over.Validated(); err == nil {
			t.Errorf("%s one over the ceiling was accepted", f.name)
		}
		if f.name == "wait" {
			z := relay.DefaultLimits()
			z.MaxWaitSeconds = 0 // long-poll off is a tightening
			if _, err := z.Validated(); err != nil {
				t.Errorf("a wait of 0: %v", err)
			}
			continue
		}
		zero := relay.DefaultLimits()
		f.set(&zero, false, true)
		if _, err := zero.Validated(); err == nil {
			t.Errorf("%s of zero was accepted", f.name)
		}
	}
	if !(relay.ValidLimits{}).IsZero() {
		t.Error("the zero ValidLimits is not zero")
	}
	// the ceiling itself is the default
	l := relay.DefaultLimits()
	v, _ := l.Validated()
	if v.IsZero() || v.Limits() != l {
		t.Error("Validated changed the limits")
	}
}

// The server holds narrow capabilities: no field of its configuration can
// delete a mailbox, sweep or close the store, and the source of the package
// (apart from the sweeper) never names those capabilities.
//
// spec: SPO-Xmailbox-IF-005, SPO-Xmailbox-SEC-024
func TestServerHoldsNoRevokerNoExpirerNoFullStore(t *testing.T) {
	ct := reflect.TypeFor[relay.Config]()
	banned := []string{"RemoveMailbox", "Sweep", "Close"}
	for i := range ct.NumField() {
		f := ct.Field(i)
		if f.Type.Kind() != reflect.Interface {
			continue
		}
		for _, m := range banned {
			if _, ok := f.Type.MethodByName(m); ok {
				t.Errorf("Config.%s (%s) has the method %s", f.Name, f.Type, m)
			}
		}
	}
	if _, ok := reflect.TypeFor[relay.Server]().MethodByName("Remove"); ok {
		t.Error("Server exposes Remove")
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range files {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		src, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), fn, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			switch id.Name {
			case "RemoveMailbox", "MailboxRevoker", "MailboxStore":
				t.Errorf("%s names %s", fn, id.Name)
			case "MailboxExpirer", "Sweep":
				if fn != "sweeper.go" {
					t.Errorf("%s names %s", fn, id.Name)
				}
			}
			return true
		})
	}
}

// The package imports the standard library, domain/mailbox, domain/party and
// ports/relayport and nothing else of this module.
//
// spec: SPO-Xmailbox-SEC-009
func TestImportsAreTheRelayPortsOnly(t *testing.T) {
	allowed := map[string]bool{
		"github.com/mochipool/workbench/spo/internal/domain/mailbox":  true,
		"github.com/mochipool/workbench/spo/internal/domain/party":    true,
		"github.com/mochipool/workbench/spo/internal/ports/relayport": true,
	}
	files, _ := filepath.Glob("*.go")
	for _, fn := range files {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), fn, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") && !allowed[p] {
				t.Errorf("%s imports %s", fn, p)
			}
			switch p {
			case "os", "net", "os/exec", "unsafe", "crypto/rand", "math/rand":
				t.Errorf("%s imports %s", fn, p)
			}
		}
	}
}

// The store double with nothing armed is a store: it passes the contract
// every implementation passes.
//
// spec: SPO-Xmailbox-IF-001
func TestFaultStoreIsAStore(t *testing.T) {
	relayporttest.RunMailboxStore(t, func(t *testing.T, clock relayport.Clock) relayporttest.MailboxFixture {
		dir := t.TempDir()
		s, _, err := mailboxstore.Open(dir, clock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		cur := &faultStore{MailboxStore: s}
		return relayporttest.MailboxFixture{
			Store: cur,
			Reopen: func(t *testing.T) relayport.MailboxStore {
				s.Close()
				n, _, err := mailboxstore.Open(dir, clock)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { n.Close() })
				s = n
				cur = &faultStore{MailboxStore: n}
				return cur
			},
		}
	})
}
