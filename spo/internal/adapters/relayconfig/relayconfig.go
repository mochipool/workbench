// Package relayconfig reads the relay's configuration file: its limits and the
// access list (ADR 0013 decisions 2 and 3, work package 4).
//
// An access-list entry is a party's signed identity document. This package
// verifies the document's self-signature with party.Document.Verify and refuses
// a document with no node key. It parses the document through a function the
// caller injects (DocumentParser), because the real parser lives in
// adapters/envelope, which links age, and the relay binary must not (ADR 0013
// decision 1). The wiring passes envelope.ParseDocument. The injected parser is
// trusted to return an Identity that is the decoding of Content, as
// party.Document documents; the fingerprint is recomputed from those keys and
// never read from the file.
//
// The file is a small subset of TOML (see parse.go) read by
// internal/platform/tomlsubset, the parser that adapters/config uses too, with
// arrays of tables and lists of strings switched on. Unknown keys and tables
// are refused, and so is every control character but tab.
//
// The tunnel allow-list is exactly the node keys of the access list.
package relayconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// geteuid is the effective uid the file's owner is compared with; a variable so
// that a test can change it.
var geteuid = os.Geteuid

// Bounds on the file, checked before anything of that size is read or built.
const (
	// MaxFileBytes is the largest configuration file: 1024 parties with a
	// document of 4 KiB each and a send_to of some size would still fit.
	MaxFileBytes = 4 << 20
	// MaxLineBytes is the longest line: a send_to of 1024 fingerprints is about 45 KiB.
	MaxLineBytes = 64 << 10
	// MaxDocumentBytes is the largest identity document, decoded. A real one is
	// a few hundred bytes.
	MaxDocumentBytes = 4 << 10
)

// DocumentParser decodes an identity document. It does not verify it.
type DocumentParser func([]byte) (party.Document, error)

// Config is a validated configuration.
type Config struct {
	Quota mailbox.Quota
	// Limits is Quota after Validated(len(Entries)): the value to hand to a
	// store, which refuses an unvalidated quota.
	Limits           mailbox.ValidQuota
	RetentionSeconds uint64
	Entries          []relayport.AccessEntry
}

// AccessList is the list of the configuration.
func (c *Config) AccessList() *List { return NewList(c.Entries) }

// Parse validates the text of a configuration file.
func Parse(data []byte, parse DocumentParser) (*Config, error) {
	if parse == nil {
		return nil, errors.New("no document parser was given")
	}
	raw, err := parseFile(data)
	if err != nil {
		return nil, err
	}
	c := &Config{Quota: mailbox.DefaultQuota(), RetentionSeconds: mailbox.DefaultRetentionSeconds}
	if err := raw.applyRelay(c); err != nil {
		return nil, err
	}
	seenFP := map[party.Fingerprint]int{}
	seenNode := map[party.NodeKey]int{}
	seenLabel := map[string]int{}
	for i, rp := range raw.parties {
		who := fmt.Sprintf("party %d (line %d)", i+1, rp.line)
		e, err := rp.entry(parse)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", who, err)
		}
		who = fmt.Sprintf("party %d (%s)", i+1, e.Label)
		if j, dup := seenFP[e.Fingerprint]; dup {
			return nil, fmt.Errorf("%s: the same fingerprint as party %d", who, j)
		}
		if j, dup := seenNode[e.Node]; dup {
			return nil, fmt.Errorf("%s: the same node key as party %d", who, j)
		}
		if j, dup := seenLabel[e.Label]; dup {
			return nil, fmt.Errorf("%s: the same label as party %d; labels name parties in every message and must differ", who, j)
		}
		seenFP[e.Fingerprint], seenNode[e.Node], seenLabel[e.Label] = i+1, i+1, i+1
		c.Entries = append(c.Entries, e)
	}
	for i, rp := range raw.parties {
		listed := map[party.Fingerprint]bool{}
		var to []party.Fingerprint
		for _, s := range rp.sendTo {
			fp, err := parseFingerprint(s)
			if err != nil {
				return nil, fmt.Errorf("party %d (%s): send_to: %w", i+1, c.Entries[i].Label, err)
			}
			if _, ok := seenFP[fp]; !ok {
				return nil, fmt.Errorf("party %d (%s): send_to names %s, which is not in the access list", i+1, c.Entries[i].Label, s)
			}
			if listed[fp] {
				return nil, fmt.Errorf("party %d (%s): send_to names %s twice", i+1, c.Entries[i].Label, s)
			}
			listed[fp] = true
			to = append(to, fp)
		}
		c.Entries[i] = c.Entries[i].WithSendTo(to)
	}
	limits, err := c.Quota.Validated(len(c.Entries))
	if err != nil {
		return nil, fmt.Errorf("[relay]: %w", err)
	}
	c.Limits = limits
	return c, nil
}

func (rp *rawParty) entry(parse DocumentParser) (relayport.AccessEntry, error) {
	var e relayport.AccessEntry
	if rp.document == "" {
		return e, errors.New("there is no document")
	}
	if len(rp.document) > base64.StdEncoding.EncodedLen(MaxDocumentBytes) {
		return e, fmt.Errorf("the document is over %d bytes", MaxDocumentBytes)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(rp.document)
	if err != nil {
		return e, fmt.Errorf("the document is not base64: %w", err)
	}
	doc, err := parse(b)
	if err != nil {
		return e, fmt.Errorf("the document does not parse: %w", err)
	}
	if err := doc.Verify(); err != nil {
		return e, fmt.Errorf("the document's self-signature does not verify: %w", err)
	}
	if doc.Identity.Node == nil || *doc.Identity.Node == (party.NodeKey{}) {
		return e, errors.New("the document has no node key; the relay admits a party only by its tunnel node key")
	}
	label := rp.label
	if !rp.hasLabel {
		label = doc.Identity.Label
	}
	if len(label) > party.MaxLabelBytes || !cleanText(label) {
		return e, fmt.Errorf("the label is over %d bytes or has a control character", party.MaxLabelBytes)
	}
	if strings.TrimSpace(label) == "" {
		return e, errors.New("the label is empty (give a label, or use a document that has one)")
	}
	return relayport.AccessEntry{
		Label:       label,
		Document:    doc,
		Fingerprint: doc.Identity.Fingerprint(),
		Node:        *doc.Identity.Node,
	}, nil
}

func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// Load reads and validates the file at path. The file must be a regular file
// owned by the effective user or by root (by fstat on the opened descriptor),
// that its group and others cannot write, of at most MaxFileBytes; the size is
// checked before a byte is read. A link is followed (a store path is one) and a
// FIFO is refused without being waited on.
func Load(path string, parse DocumentParser) (*Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case !st.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", path)
	case !ownerOK(st, geteuid()):
		return nil, fmt.Errorf("%s is owned by uid %d; it must belong to the user running the relay (uid %d) or to root, or its owner could add a party to the access list", path, fileUid(st), geteuid())
	case st.Mode().Perm()&0o022 != 0:
		return nil, fmt.Errorf("%s is writable by its group or by everyone (mode %o); another user could add a party to the access list. Run: chmod 600 %s", path, st.Mode().Perm(), path)
	case st.Size() > MaxFileBytes:
		return nil, fmt.Errorf("%s is %d bytes; the limit is %d", path, st.Size(), MaxFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	c, err := Parse(b, parse)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// ownerOK reports whether the file's owner may write the access list: the
// effective user, or root.
func ownerOK(st os.FileInfo, euid int) bool {
	uid := fileUid(st)
	return uid == euid || uid == 0
}

func fileUid(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1 // not a unix stat: nobody
}

// ---- the list ----

// List is an access list in memory. It implements relayport.AccessList.
type List struct {
	entries []relayport.AccessEntry
	byFP    map[party.Fingerprint]int
	byNode  map[party.NodeKey]int
}

var _ relayport.AccessList = (*List)(nil)

// NewList indexes entries. It trusts them: Parse is what validates.
func NewList(entries []relayport.AccessEntry) *List {
	l := &List{entries: slices.Clone(entries), byFP: map[party.Fingerprint]int{}, byNode: map[party.NodeKey]int{}}
	for i, e := range l.entries {
		l.byFP[e.Fingerprint] = i
		l.byNode[e.Node] = i
	}
	return l
}

// Lookup implements relayport.AccessList.
func (l *List) Lookup(fp party.Fingerprint) (relayport.AccessEntry, bool) {
	i, ok := l.byFP[fp]
	if !ok {
		return relayport.AccessEntry{}, false
	}
	return l.entries[i], true
}

// LookupNode implements relayport.AccessList.
func (l *List) LookupNode(k party.NodeKey) (relayport.AccessEntry, bool) {
	i, ok := l.byNode[k]
	if !ok {
		return relayport.AccessEntry{}, false
	}
	return l.entries[i], true
}

// NodeKeys implements relayport.AccessList: exactly the node keys of the entries.
func (l *List) NodeKeys() []party.NodeKey {
	out := make([]party.NodeKey, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e.Node)
	}
	return out
}

// ---- reload ----

// Reloadable is the access list of a file that can be loaded again (SIGHUP). A
// reload that fails keeps the list that was there.
type Reloadable struct {
	path  string
	parse DocumentParser
	cur   atomic.Pointer[state]
}

type state struct {
	cfg  *Config
	list *List
}

var _ relayport.AccessList = (*Reloadable)(nil)

// OpenReloadable loads the file; a file that does not validate is an error.
func OpenReloadable(path string, parse DocumentParser) (*Reloadable, error) {
	r := &Reloadable{path: path, parse: parse}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload loads the file again. On an error the old configuration stays.
func (r *Reloadable) Reload() error {
	c, err := Load(r.path, r.parse)
	if err != nil {
		return err
	}
	r.cur.Store(&state{cfg: c, list: c.AccessList()})
	return nil
}

// Config is the configuration now in force.
func (r *Reloadable) Config() *Config { return r.cur.Load().cfg }

// Lookup implements relayport.AccessList.
func (r *Reloadable) Lookup(fp party.Fingerprint) (relayport.AccessEntry, bool) {
	return r.cur.Load().list.Lookup(fp)
}

// LookupNode implements relayport.AccessList.
func (r *Reloadable) LookupNode(k party.NodeKey) (relayport.AccessEntry, bool) {
	return r.cur.Load().list.LookupNode(k)
}

// NodeKeys implements relayport.AccessList.
func (r *Reloadable) NodeKeys() []party.NodeKey { return r.cur.Load().list.NodeKeys() }
