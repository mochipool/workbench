package relayconfig_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

type member struct {
	label string
	doc   []byte
	id    party.Identity
	fp    party.Fingerprint
	node  party.NodeKey
	b64   string
}

var seed uint64

// newMember makes a real identity and its signed document. node nil: a party
// with no node key.
func newMember(t *testing.T, label string, node *party.NodeKey) member {
	t.Helper()
	seed++
	rnd := rand.NewChaCha8([32]byte{byte(seed), byte(seed >> 8), 1})
	p, err := envelope.Generate(label, node, time.Unix(1_700_000_000, 0), rnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Destroy)
	doc, err := envelope.EncodeDocument(p)
	if err != nil {
		t.Fatal(err)
	}
	m := member{label: label, doc: doc, id: p.Identity(), fp: p.Fingerprint(), b64: base64.StdEncoding.EncodeToString(doc)}
	if node != nil {
		m.node = *node
	}
	return m
}

func nk(b byte) *party.NodeKey { k := party.NodeKey{b, 0x55}; return &k }

func hexfp(f party.Fingerprint) string { return fmt.Sprintf("%x", f[:]) }

func partyBlock(m member, extra ...string) string {
	s := "[[party]]\nlabel = \"" + m.label + "\"\ndocument = \"" + m.b64 + "\"\n"
	for _, e := range extra {
		s += e + "\n"
	}
	return s
}

func parse(t *testing.T, text string) (*relayconfig.Config, error) {
	t.Helper()
	return relayconfig.Parse([]byte(text), envelope.ParseDocument)
}

func mustParse(t *testing.T, text string) *relayconfig.Config {
	t.Helper()
	c, err := parse(t, text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c
}

func wantErr(t *testing.T, text, contains string) {
	t.Helper()
	c, err := parse(t, text)
	if err == nil {
		t.Fatalf("a configuration that must be refused was accepted (%d entries); wanted an error with %q", len(c.Entries), contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("error %q does not say %q", err, contains)
	}
}

// spec: SPO-Xmailbox-OUT-016
// spec: SPO-Xmailbox-IF-002
func TestLoadsPartiesAndDerivesTheAllowList(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	c := mustParse(t, "[relay]\nretention_seconds = 86400\n\n# parties\n"+partyBlock(a, "send_to = [\""+hexfp(b.fp)+"\"]")+"\n"+partyBlock(b))
	if len(c.Entries) != 2 || c.RetentionSeconds != 86400 {
		t.Fatalf("%d entries, retention %d", len(c.Entries), c.RetentionSeconds)
	}
	l := c.AccessList()
	ea, ok := l.Lookup(a.fp)
	if !ok || ea.Label != "alice" || ea.Node != a.node || ea.Fingerprint != a.fp || ea.Document.Identity.Ed25519 != a.id.Ed25519 {
		t.Fatalf("alice = %+v, %v", ea, ok)
	}
	if !ea.MaySendTo(b.fp) || ea.MaySendTo(a.fp) {
		t.Fatalf("alice's send_to = %v", ea.SendTo())
	}
	if got, ok := l.LookupNode(b.node); !ok || got.Fingerprint != b.fp {
		t.Fatalf("lookup by node key: %+v %v", got, ok)
	}
	if _, ok := l.Lookup(party.Fingerprint{1}); ok {
		t.Fatal("an unknown fingerprint was found")
	}
	if _, ok := l.LookupNode(party.NodeKey{9}); ok {
		t.Fatal("an unknown node key was found")
	}
	// the tunnel allow-list is exactly the node keys of the access list
	got := l.NodeKeys()
	want := []party.NodeKey{a.node, b.node}
	slices.SortFunc(got, func(x, y party.NodeKey) int { return slices.Compare(x[:], y[:]) })
	slices.SortFunc(want, func(x, y party.NodeKey) int { return slices.Compare(x[:], y[:]) })
	if !slices.Equal(got, want) {
		t.Fatalf("NodeKeys = %x, want exactly %x", got, want)
	}
}

// spec: SPO-Xmailbox-SEC-011
func TestSendToDefaultsToNothing(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	c := mustParse(t, partyBlock(a)+partyBlock(b))
	for _, e := range c.Entries {
		if len(e.SendTo()) != 0 || e.MaySendTo(a.fp) || e.MaySendTo(b.fp) {
			t.Fatalf("%s may send to %v by default", e.Label, e.SendTo())
		}
	}
	c = mustParse(t, partyBlock(a, "send_to = []")+partyBlock(b))
	if len(c.Entries[0].SendTo()) != 0 {
		t.Fatal("an empty send_to is not empty")
	}
}

func TestLabelDefaultsToTheDocumentsAndIsChecked(t *testing.T) {
	a := newMember(t, "from-the-document", nk(1))
	c := mustParse(t, "[[party]]\ndocument = \""+a.b64+"\"\n")
	if c.Entries[0].Label != "from-the-document" {
		t.Fatalf("label = %q", c.Entries[0].Label)
	}
	wantErr(t, "[[party]]\nlabel = \""+strings.Repeat("x", 65)+"\"\ndocument = \""+a.b64+"\"\n", "label")
	// a format character is not a control character but is as bad (a bidi
	// override): the parser refuses it anywhere in the file
	wantErr(t, "[[party]]\nlabel = \"evil\u202etxt\"\ndocument = \""+a.b64+"\"\n", "bidirectional")
	// 64 bytes is the limit and is accepted
	c = mustParse(t, "[[party]]\nlabel = \""+strings.Repeat("x", 64)+"\"\ndocument = \""+a.b64+"\"\n")
	if len(c.Entries[0].Label) != 64 {
		t.Fatal("a label of 64 bytes was not kept")
	}
}

// spec: SPO-Xmailbox-SEC-010
func TestADocumentWithNoNodeKeyIsRefused(t *testing.T) {
	m := newMember(t, "nonode", nil)
	wantErr(t, partyBlock(m), "node key")
}

// spec: SPO-Xmailbox-SEC-010
func TestASelfSignatureThatFailsIsRefused(t *testing.T) {
	m := newMember(t, "forged", nk(3))
	bad := slices.Clone(m.doc)
	bad[len(bad)-1] ^= 0x01 // the last byte is in the signature
	wantErr(t, "[[party]]\nlabel = \"forged\"\ndocument = \""+base64.StdEncoding.EncodeToString(bad)+"\"\n", "signature")
	// another party's signature over this content
	other := newMember(t, "other", nk(4))
	spliced := slices.Clone(m.doc)
	copy(spliced[len(spliced)-64:], other.doc[len(other.doc)-64:])
	wantErr(t, "[[party]]\ndocument = \""+base64.StdEncoding.EncodeToString(spliced)+"\"\n", "signature")
}

// spec: SPO-Xmailbox-PRE-012
func TestDuplicatesAreRefused(t *testing.T) {
	a := newMember(t, "alice", nk(1))
	wantErr(t, partyBlock(a)+partyBlock(a), "fingerprint")
	b := newMember(t, "bob", nk(1)) // another identity on the same node key
	wantErr(t, partyBlock(a)+partyBlock(b), "node key")
}

// spec: SPO-Xmailbox-PRE-012
func TestAnEmptyListIsRefused(t *testing.T) {
	wantErr(t, "", "part")
	wantErr(t, "# nothing\n", "part")
	wantErr(t, "[relay]\nretention_seconds = 1000\n", "part")
}

// spec: SPO-Xmailbox-PRE-012
func TestMoreThanTheLimitOfPartiesIsRefusedByCountBeforeDecoding(t *testing.T) {
	var sb strings.Builder
	for range mailbox.MaxAccessListParties + 1 {
		sb.WriteString("[[party]]\ndocument = \"AAAA\"\n")
	}
	wantErr(t, sb.String(), fmt.Sprint(mailbox.MaxAccessListParties))
	// at the limit the refusal is about the document, not the count
	sb.Reset()
	for range mailbox.MaxAccessListParties {
		sb.WriteString("[[party]]\ndocument = \"AAAA\"\n")
	}
	if _, err := parse(t, sb.String()); err == nil || strings.Contains(err.Error(), "at most") {
		t.Fatalf("1024 parties: %v", err)
	}
}

// spec: SPO-Xmailbox-PRE-013
func TestQuotasAreValidated(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	parties := partyBlock(a) + partyBlock(b)
	// two parties at 64 MiB each need 128 MiB
	wantErr(t, "[relay]\nglobal_bytes = 134217727\n"+parties, "global")
	if c := mustParse(t, "[relay]\nglobal_bytes = 134217728\n"+parties); c.Quota.GlobalBytes != 134217728 {
		t.Fatal("the exact cover was refused or not applied")
	}
	wantErr(t, "[relay]\nsender_bytes = 67108864\nglobal_bytes = 1000\n"+parties, "global")
	// a tighter per-sender total lowers what the global quota must cover
	mustParse(t, "[relay]\nsender_bytes = 1000\nglobal_bytes = 2000\n"+parties)
	wantErr(t, "[relay]\nsender_bytes = 1000\nglobal_bytes = 1999\n"+parties, "global")
	// nothing looser than the table, nothing zero
	wantErr(t, "[relay]\nmailbox_bytes = 99999999999999999999999\n"+parties, "out of range")
	for _, kv := range []string{"mailbox_entries = 257", "mailbox_bytes = 67108865", "pair_entries = 65", "pair_bytes = 8388609", "sender_bytes = 67108865",
		"mailbox_entries = 0", "pair_bytes = 0"} {
		wantErr(t, "[relay]\n"+kv+"\n"+parties, strings.ReplaceAll(strings.Fields(kv)[0], "_", " "))
	}
	wantErr(t, "[relay]\nglobal_bytes = 0\n"+parties, "global")
	// the defaults are the table
	c := mustParse(t, parties)
	if c.Quota != mailbox.DefaultQuota() || c.Limits.IsZero() || c.Limits.Quota() != mailbox.DefaultQuota() || c.RetentionSeconds != mailbox.DefaultRetentionSeconds {
		t.Fatalf("defaults = %+v, %d", c.Quota, c.RetentionSeconds)
	}
	// retention: 1 to the maximum
	wantErr(t, "[relay]\nretention_seconds = 0\n"+parties, "retention")
	wantErr(t, fmt.Sprintf("[relay]\nretention_seconds = %d\n%s", mailbox.MaxRetentionSeconds+1, parties), "retention")
	if c := mustParse(t, fmt.Sprintf("[relay]\nretention_seconds = %d\n%s", mailbox.MaxRetentionSeconds, parties)); c.RetentionSeconds != mailbox.MaxRetentionSeconds {
		t.Fatal("the maximum retention was refused")
	}
	// the global default covers 64 parties at 64 MiB: 4 GiB / 64 MiB; 65 would not, but 1024 limit is by count
}

// spec: SPO-Xmailbox-PRE-012
func TestUnknownKeysAndTablesAreRefused(t *testing.T) {
	a := newMember(t, "alice", nk(1))
	p := "[[party]]\nlabel = \"x\"\ndocument = \"" + a.b64 + "\"\n"
	for name, text := range map[string]string{
		"a top-level key":                 "retention_seconds = 5\n" + p,
		"an unknown relay key":            "[relay]\nretension_seconds = 5\n" + p,
		"an unknown party key":            strings.Replace(p, "label", "lable", 1),
		"an unknown table":                "[other]\nx = 1\n" + p,
		"a plain party table":             strings.Replace(p, "[[party]]", "[party]", 1),
		"relay twice":                     "[relay]\n[relay]\n" + p,
		"a repeated key":                  "[relay]\nretention_seconds = 5\nretention_seconds = 6\n" + p,
		"a repeated party key":            p + "label = \"again\"\n",
		"a dotted key":                    "[relay]\nx.y = 1\n" + p,
		"a send_to that is text":          strings.Replace(p, "document", "send_to = \"x\"\ndocument", 1),
		"a number as a document":          "[[party]]\ndocument = 5\n",
		"a string as a number":            "[relay]\nretention_seconds = \"5\"\n" + p,
		"a negative number":               "[relay]\nretention_seconds = -5\n" + p,
		"a number with an underscore":     "[relay]\nretention_seconds = 1_000\n" + p,
		"a hex number":                    "[relay]\nretention_seconds = 0x10\n" + p,
		"a leading zero":                  "[relay]\nretention_seconds = 0100\n" + p,
		"a number too large":              "[relay]\nmailbox_bytes = 99999999999999999999999\n" + p,
		"an unclosed string":              strings.Replace(p, "label = \"x\"", "label = \"abc", 1),
		"a bad escape":                    strings.Replace(p, "label = \"x\"", "label = \"a\\nb\"", 1),
		"a tab in a string":               strings.Replace(p, "label = \"x\"", "label = \"a\tb\"", 1),
		"an escape character in a string": strings.Replace(p, "label = \"x\"", "label = \"a\x1bb\"", 1),
		"a delete character in a string":  strings.Replace(p, "label = \"x\"", "label = \"a\x7fb\"", 1),
		"text after the value":            "[relay]\nretention_seconds = 5 extra\n" + p,
		"text after a string":             strings.Replace(p, "label = \"x\"", "label = \"x\" extra", 1),
		"no equals":                       "[relay]\nretention_seconds\n" + p,
		"a literal string":                strings.Replace(p, "label = \"x\"", "label = 'x'", 1),
		"a multi-line array":              strings.Replace(p, "document", "send_to = [\n\"a\"]\ndocument", 1),
		"an array of numbers":             strings.Replace(p, "document", "send_to = [1]\ndocument", 1),
		"an unclosed array":               strings.Replace(p, "document", "send_to = [\"a\"\ndocument", 1),
		"a trailing comma":                strings.Replace(p, "document", "send_to = [\"a\",]\ndocument", 1),
		"invalid UTF-8":                   strings.Replace(p, "label = \"x\"", "label = \"\xff\"", 1),
		"text after the party header":     strings.Replace(p, "[[party]]", "[[party]] extra", 1),
		"text after the relay header":     "[relay] extra\n" + p,
		"a key with a space":              "[relay]\nretention seconds = 5\n" + p,
		"a key with a dot":                "[relay]\nretention.seconds = 5\n" + p,
	} {
		t.Run(name, func(t *testing.T) {
			if c, err := parse(t, text); err == nil {
				t.Fatalf("accepted (%d entries)", len(c.Entries))
			}
		})
	}
	// a key and comments are fine
	mustParse(t, "# c\n[relay]   # c\nretention_seconds = 5 # c\n"+p)
}

// spec: SPO-Xmailbox-PRE-012
func TestSendToIsChecked(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	ok := hexfp(b.fp)
	for name, send := range map[string]string{
		"an unknown fingerprint": `["` + strings.Repeat("ab", 20) + `"]`,
		"upper case":             `["` + strings.ToUpper(ok) + `"]`,
		"too short":              `["` + ok[:38] + `"]`,
		"not hex":                `["` + strings.Repeat("zz", 20) + `"]`,
		"a repeat":               `["` + ok + `", "` + ok + `"]`,
		"too long":               `["` + ok + `00"]`,
		"with a prefix":          `["00` + ok + `"]`,
	} {
		t.Run(name, func(t *testing.T) {
			wantErr(t, partyBlock(a, "send_to = "+send)+partyBlock(b), "send_to")
		})
	}
	// more entries than there can be parties
	many := make([]string, mailbox.MaxAccessListParties+1)
	for i := range many {
		many[i] = fmt.Sprintf(`"%040x"`, i)
	}
	wantErr(t, partyBlock(a, "send_to = ["+strings.Join(many, ",")+"]")+partyBlock(b), "at most 1024")
	// 1024 entries pass the count (they are refused for naming unknown parties)
	if _, err := parse(t, partyBlock(a, "send_to = ["+strings.Join(many[:mailbox.MaxAccessListParties], ",")+"]")+partyBlock(b)); err == nil || strings.Contains(err.Error(), "at most") {
		t.Fatalf("1024 send_to entries: %v", err)
	}
	// a party may name itself and others, in any order in the file
	mustParse(t, partyBlock(a, `send_to = ["`+hexfp(a.fp)+`", "`+ok+`"]`)+partyBlock(b))
}

// spec: SPO-Xmailbox-PRE-012
func TestDocumentsAreBoundedBeforeDecoding(t *testing.T) {
	// the document parser is a probe: it says which stage a document reached
	reached := false
	probe := func([]byte) (party.Document, error) {
		reached = true
		return party.Document{}, errors.New("probe: reached the parser")
	}
	parseWith := func(doc string) error {
		reached = false
		_, err := relayconfig.Parse([]byte("[[party]]\ndocument = \""+doc+"\"\n"), probe)
		return err
	}
	limit := base64.StdEncoding.EncodedLen(relayconfig.MaxDocumentBytes)
	// exactly the bound reaches the parser; one more character does not
	if err := parseWith(strings.Repeat("A", limit)); !reached || err == nil || !strings.Contains(err.Error(), "probe") {
		t.Fatalf("a document of exactly the bound did not reach the parser: %v", err)
	}
	if err := parseWith(strings.Repeat("A", limit+4)); reached || err == nil || !strings.Contains(err.Error(), "over 4096 bytes") {
		t.Fatalf("a document over the bound: reached %v, %v", reached, err)
	}
	if err := parseWith(strings.Repeat("A", 20000)); reached || err == nil || !strings.Contains(err.Error(), "over 4096 bytes") {
		t.Fatalf("a huge document: reached %v, %v", reached, err)
	}
	// base64 is strict: non-zero padding bits are refused
	if err := parseWith("QQ=="); !reached {
		t.Fatalf("a canonical base64 string did not reach the parser: %v", err)
	}
	if err := parseWith("QR=="); reached || err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("non-canonical base64: reached %v, %v", reached, err)
	}
	if err := parseWith("!!!!"); reached || err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("not base64: reached %v, %v", reached, err)
	}
	if err := parseWith(""); reached || err == nil || !strings.Contains(err.Error(), "no document") {
		t.Fatalf("an empty document: reached %v, %v", reached, err)
	}
	wantErr(t, "[[party]]\nlabel = \"x\"\n", "no document")
	wantErr(t, "[[party]]\ndocument = \"AAAA\"\n", "does not parse") // not a document
	if _, err := relayconfig.Parse([]byte(partyBlock(newMember(t, "x", nk(1)))), nil); err == nil {
		t.Fatal("a nil document parser was accepted")
	}
	boom := errors.New("parser says no")
	_, err := relayconfig.Parse([]byte(partyBlock(newMember(t, "x", nk(1)))), func([]byte) (party.Document, error) { return party.Document{}, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("the parser's error is lost: %v", err)
	}
}

// A document whose parse is trusted but that carries a zero node key is refused
// too: the injected parser is not what enforces that.
//
// spec: SPO-Xmailbox-SEC-010
func TestAZeroNodeKeyFromAnInjectedParserIsRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	content := []byte("an identity")
	var doc party.Document
	copy(doc.Identity.Ed25519[:], pub)
	doc.Identity.X25519 = party.X25519Public{1}
	doc.Identity.Label = "zero"
	doc.Content = content
	copy(doc.Signature[:], ed25519.Sign(priv, party.DocumentMessage(content)))
	text := "[[party]]\ndocument = \"QQ==\"\n"
	parse := func(node *party.NodeKey) relayconfig.DocumentParser {
		return func([]byte) (party.Document, error) { d := doc; d.Identity.Node = node; return d, nil }
	}
	zero := party.NodeKey{}
	if _, err := relayconfig.Parse([]byte(text), parse(&zero)); err == nil || !strings.Contains(err.Error(), "node key") {
		t.Fatalf("a zero node key: %v", err)
	}
	if _, err := relayconfig.Parse([]byte(text), parse(nil)); err == nil || !strings.Contains(err.Error(), "node key") {
		t.Fatalf("no node key: %v", err)
	}
	good := party.NodeKey{7}
	if c, err := relayconfig.Parse([]byte(text), parse(&good)); err != nil || len(c.Entries) != 1 || c.Entries[0].Node != good {
		t.Fatalf("a good node key: %v", err)
	}
}

// spec: SPO-Xmailbox-PRE-012
func TestFileSizeIsBoundedBeforeReading(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "relay.toml")
	f, _ := os.Create(p)
	f.Truncate(int64(relayconfig.MaxFileBytes) + 1) // sparse
	f.Close()
	os.Chmod(p, 0o600)
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	_, err := relayconfig.Load(p, envelope.ParseDocument)
	runtime.ReadMemStats(&m1)
	if err == nil || !strings.Contains(err.Error(), "bytes; the limit is") {
		t.Fatalf("Load = %v", err)
	}
	if d := m1.TotalAlloc - m0.TotalAlloc; d > 1<<20 {
		t.Fatalf("an oversize file allocated %d bytes before it was refused", d)
	}
	if _, err := relayconfig.Parse(make([]byte, relayconfig.MaxFileBytes+1), envelope.ParseDocument); err == nil || !strings.Contains(err.Error(), "bytes; the limit is") {
		t.Fatalf("Parse of an oversize input = %v", err)
	}
	// exactly the bound is not a size error (it is refused for what it holds)
	if _, err := relayconfig.Parse(make([]byte, relayconfig.MaxFileBytes), envelope.ParseDocument); err == nil || strings.Contains(err.Error(), "bytes; the limit is") {
		t.Fatalf("Parse of an input of exactly the bound = %v", err)
	}
	g, _ := os.Create(filepath.Join(dir, "exact.toml"))
	g.Truncate(int64(relayconfig.MaxFileBytes))
	g.Close()
	os.Chmod(filepath.Join(dir, "exact.toml"), 0o600)
	if _, err := relayconfig.Load(filepath.Join(dir, "exact.toml"), envelope.ParseDocument); err == nil || strings.Contains(err.Error(), "bytes; the limit is") {
		t.Fatalf("Load of a file of exactly the bound = %v", err)
	}
	// a file claiming to be small but growing is read only up to the bound
}

// spec: SPO-Xmailbox-PRE-012
func TestFileChecks(t *testing.T) {
	a := newMember(t, "alice", nk(1))
	dir := t.TempDir()
	p := filepath.Join(dir, "relay.toml")
	os.WriteFile(p, []byte(partyBlock(a)), 0o600)
	if _, err := relayconfig.Load(p, envelope.ParseDocument); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0o620)
	if _, err := relayconfig.Load(p, envelope.ParseDocument); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("a group-writable file: %v", err)
	}
	os.Chmod(p, 0o602)
	if _, err := relayconfig.Load(p, envelope.ParseDocument); err == nil {
		t.Fatal("a world-writable file was accepted")
	}
	if _, err := relayconfig.Load(dir, envelope.ParseDocument); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory: %v", err)
	}
	os.Chmod(p, 0o000)
	if _, err := relayconfig.Load(p, envelope.ParseDocument); err == nil && os.Geteuid() != 0 {
		t.Fatal("an unreadable file was accepted")
	}
	os.Chmod(p, 0o600)
	if _, err := relayconfig.Load(filepath.Join(dir, "missing.toml"), envelope.ParseDocument); err == nil {
		t.Fatal("a missing file was accepted")
	}
	// a symbolic link to a good file is followed (a store path is one)
	os.Chmod(p, 0o600)
	ln := filepath.Join(dir, "link.toml")
	os.Symlink(p, ln)
	if _, err := relayconfig.Load(ln, envelope.ParseDocument); err != nil {
		t.Fatalf("a link to a good file: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.toml")
	if err := mkfifo(fifo); err == nil {
		done := make(chan error, 1)
		go func() { _, err := relayconfig.Load(fifo, envelope.ParseDocument); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("a FIFO: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Load blocked on a FIFO")
		}
	}
}

// spec: SPO-Xmailbox-PRE-014
func TestAFailedReloadKeepsTheOldList(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	p := filepath.Join(t.TempDir(), "relay.toml")
	os.WriteFile(p, []byte(partyBlock(a)), 0o600)
	r, err := relayconfig.OpenReloadable(p, envelope.ParseDocument)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(a.fp); !ok || len(r.NodeKeys()) != 1 {
		t.Fatal("the first load")
	}
	for name, text := range map[string]string{"empty": "", "bad": partyBlock(a) + "nonsense\n", "no node": partyBlock(newMember(t, "n", nil))} {
		os.WriteFile(p, []byte(text), 0o600)
		if err := r.Reload(); err == nil {
			t.Fatalf("%s: Reload succeeded", name)
		}
		if _, ok := r.Lookup(a.fp); !ok || len(r.NodeKeys()) != 1 {
			t.Fatalf("%s: a failed reload lost the old list", name)
		}
	}
	os.WriteFile(p, []byte(partyBlock(b)), 0o600)
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(a.fp); ok {
		t.Fatal("alice stayed after she was removed")
	}
	if got, ok := r.LookupNode(b.node); !ok || got.Label != "bob" || len(r.NodeKeys()) != 1 {
		t.Fatal("bob is not there after the reload")
	}
	// the list that first loads must be good
	os.WriteFile(p, []byte(""), 0o600)
	if _, err := relayconfig.OpenReloadable(p, envelope.ParseDocument); err == nil {
		t.Fatal("an empty list started")
	}
	var _ relayport.AccessList = r
}

// spec: SPO-Xmailbox-PRE-012
func TestLinesAndStringsAreBoundedAndChecked(t *testing.T) {
	a := newMember(t, "l", nk(1))
	doc := "document = \"" + a.b64 + "\"\n"
	// a line over the bound; exactly at it, the line is accepted (and refused for its label)
	wantErr(t, "[[party]]\nlabel = \""+strings.Repeat("x", 70000)+"\"\n"+doc, "line limit")
	pad := relayconfig.MaxLineBytes - len("label = \"\"")
	if _, err := parse(t, "[[party]]\nlabel = \""+strings.Repeat("x", pad)+"\"\n"+doc); err == nil || strings.Contains(err.Error(), "line limit") {
		t.Fatalf("a line of exactly the bound: %v", err)
	}
	if _, err := parse(t, "[[party]]\nlabel = \""+strings.Repeat("x", pad+1)+"\"\n"+doc); err == nil || !strings.Contains(err.Error(), "line limit") {
		t.Fatalf("a line one over the bound: %v", err)
	}
	// the parser itself refuses control characters in a string, with its own message
	wantErr(t, "[[party]]\nlabel = \"a\tb\"\n"+doc, "in a string")
	for _, c := range []string{"\x1b", "\x7f"} {
		wantErr(t, "[[party]]\nlabel = \"a"+c+"b\"\n"+doc, "control character")
	}
	// and a file that is not UTF-8 anywhere, even in a comment
	wantErr(t, "# \xff\n[[party]]\n"+doc, "UTF-8")
}

// A control character in the file is refused wherever it is: a bare carriage
// return in a comment hides the next key from a reader of the file while the
// parser reads it as a line of its own.
//
// spec: SPO-Xmailbox-SEC-019
func TestControlCharactersAreRefused(t *testing.T) {
	a := newMember(t, "alice", nk(1))
	p := partyBlock(a)
	for name, text := range map[string]string{
		"a bare CR in a comment":        "[relay]\n# old\rretention_seconds = 60\n" + p,
		"a bare CR after a value":       "[relay]\nretention_seconds = 5\rmailbox_entries = 1\n" + p,
		"a bare CR after a header":      "[relay]\r# x\n" + p,
		"a CR at the end of the file":   p + "# end\r",
		"a CR followed by a CR":         "# a\r\r\n" + p,
		"NUL in a comment":              "# a\x00b\n" + p,
		"ESC in a comment":              "# \x1b[2K\n" + p,
		"DEL in a comment":              "# a\x7fb\n" + p,
		"a C1 control character":        "# a\u0085b\n" + p,
		"a vertical tab":                "# a\vb\n" + p,
		"a form feed between key and =": "[relay]\nretention_seconds\f= 5\n" + p,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(t, text); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// a CRLF file with tabs as whitespace is the same file as its LF form
	crlf := strings.ReplaceAll("[relay]\nretention_seconds\t=\t5 # c\n"+p, "\n", "\r\n")
	c := mustParse(t, crlf)
	if c.RetentionSeconds != 5 || len(c.Entries) != 1 {
		t.Fatalf("a CRLF file read as %+v", c)
	}
}

// Labels are shown to the operator and name a party in every refusal, so an
// empty label or two parties with one label are refused.
//
// spec: SPO-Xmailbox-PRE-019
func TestLabelsAreNonEmptyAndUnique(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	blank := newMember(t, "", nk(3))
	wantErr(t, "[[party]]\nlabel = \"\"\ndocument = \""+a.b64+"\"\n", "label")
	wantErr(t, "[[party]]\nlabel = \"   \"\ndocument = \""+a.b64+"\"\n", "label")
	wantErr(t, "[[party]]\ndocument = \""+blank.b64+"\"\n", "label") // none given and the document's is empty
	// two parties, one label: given, or taken from the documents
	wantErr(t, "[[party]]\nlabel = \"same\"\ndocument = \""+a.b64+"\"\n[[party]]\nlabel = \"same\"\ndocument = \""+b.b64+"\"\n", "same")
	wantErr(t, "[[party]]\nlabel = \"bob\"\ndocument = \""+a.b64+"\"\n[[party]]\ndocument = \""+b.b64+"\"\n", "label")
	// different labels are fine, and the empty-label document is fine with a given label
	mustParse(t, "[[party]]\nlabel = \"x\"\ndocument = \""+a.b64+"\"\n[[party]]\nlabel = \"y\"\ndocument = \""+blank.b64+"\"\n")
}

// The file must belong to the user running the relay or to root: anyone else
// who owns it can add a party to the access list.
//
// spec: SPO-Xmailbox-SEC-018
func TestTheFileMustBeOwnedByTheEffectiveUserOrRoot(t *testing.T) {
	a := newMember(t, "alice", nk(1))
	p := filepath.Join(t.TempDir(), "relay.toml")
	os.WriteFile(p, []byte(partyBlock(a)), 0o600)
	owner := os.Getuid()
	if owner == 0 {
		t.Skip("a file of root is accepted by every effective uid")
	}
	if _, err := relayconfig.Load(p, envelope.ParseDocument); err != nil {
		t.Fatalf("a file of the running user: %v", err)
	}
	defer relayconfig.SetEuid(func() int { return owner + 1 })()
	if _, err := relayconfig.Load(p, envelope.ParseDocument); err == nil || !strings.Contains(err.Error(), "owned") {
		t.Fatalf("a file owned by another user than the effective one: %v", err)
	}
}

// spec: SPO-Xmailbox-SEC-018
func TestOwnerRule(t *testing.T) {
	for _, c := range []struct {
		uid, euid int
		ok        bool
	}{
		{1000, 1000, true},  // the running user
		{0, 1000, true},     // root, for a user's relay
		{0, 0, true},        // root's own
		{1001, 1000, false}, // someone else
		{1000, 0, false},    // a user's file for a relay running as root
		{-1, 1000, false},   // an owner that cannot be read is nobody
	} {
		if got := relayconfig.OwnerOK(c.uid, c.euid); got != c.ok {
			t.Errorf("a file of uid %d for effective uid %d: %v, want %v", c.uid, c.euid, got, c.ok)
		}
	}
}

// A caller cannot change the list through an entry it looked up: the send_to of
// an entry is not a slice shared with the list.
//
// spec: SPO-Xmailbox-SEC-011
func TestALookedUpEntryCannotChangeTheList(t *testing.T) {
	a, b := newMember(t, "alice", nk(1)), newMember(t, "bob", nk(2))
	c := mustParse(t, partyBlock(a, "send_to = [\""+hexfp(b.fp)+"\"]")+partyBlock(b))
	l := c.AccessList()
	ea, _ := l.Lookup(a.fp)
	got := ea.SendTo()
	for i := range got {
		got[i] = a.fp
	}
	if again, _ := l.Lookup(a.fp); !again.MaySendTo(b.fp) || again.MaySendTo(a.fp) {
		t.Fatal("a caller changed the access list through a looked-up entry")
	}
}
