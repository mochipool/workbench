package relayconfig

import (
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/tomlsubset"
)

// The file is the subset of TOML of internal/platform/tomlsubset, with arrays
// of tables, single-line lists of strings and unsigned integers:
//
//   - blank lines and '#' comments, a whole line or after a value
//   - a [relay] table, at most once, and any number of [[party]] tables
//   - key = value with bare keys (letters, digits, '-', '_')
//   - values: a basic string in double quotes with the escapes \" and \\, a
//     decimal integer with no sign, no underscore and no leading zero, and a
//     single-line array of strings
//   - no control character but tab anywhere, and a CR only in a CRLF ending
//
// Anything else, including every key and table not named below, is an error.
//
//	[relay]    retention_seconds mailbox_entries mailbox_bytes pair_entries
//	           pair_bytes sender_bytes global_bytes
//	[[party]]  label document send_to

type kind = tomlsubset.Kind

const (
	kString = tomlsubset.String
	kInt    = tomlsubset.Int
	kList   = tomlsubset.List
)

type rawParty struct {
	line     int
	label    string
	hasLabel bool
	document string
	sendTo   []string
}

type rawFile struct {
	relayLine int
	relay     map[string]uint64
	parties   []rawParty
}

var (
	relayKeys = map[string]kind{
		"retention_seconds": kInt, "mailbox_entries": kInt, "mailbox_bytes": kInt,
		"pair_entries": kInt, "pair_bytes": kInt, "sender_bytes": kInt, "global_bytes": kInt,
	}
	partyKeys = map[string]kind{"label": kString, "document": kString, "send_to": kList}
	fpRE      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func parseFingerprint(s string) (party.Fingerprint, error) {
	var fp party.Fingerprint
	if !fpRE.MatchString(s) {
		return fp, fmt.Errorf("%q is not a fingerprint (40 lower-case hex digits)", s)
	}
	b, _ := hex.DecodeString(s)
	copy(fp[:], b)
	return fp, nil
}

func parseFile(data []byte) (*rawFile, error) {
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("the configuration is %d bytes; the limit is %d", len(data), MaxFileBytes)
	}
	doc, err := tomlsubset.Parse(data, tomlsubset.Options{
		ArrayTables:    true,
		Lists:          true,
		Unsigned:       true,
		MaxLineBytes:   MaxLineBytes,
		MaxArrayTables: mailbox.MaxAccessListParties,
		MaxListItems:   mailbox.MaxAccessListParties,
	})
	if err != nil {
		return nil, err
	}
	f := &rawFile{relay: map[string]uint64{}}
	for i, t := range doc.Tables {
		if i == 0 {
			if len(t.Entries) > 0 {
				return nil, fmt.Errorf("line %d: a key outside a table (start with [relay] or [[party]])", t.Entries[0].Val.Line)
			}
			continue
		}
		var schema map[string]kind
		switch {
		case t.Name == "relay" && !t.Array:
			f.relayLine, schema = t.Line, relayKeys
		case t.Name == "party" && t.Array:
			f.parties = append(f.parties, rawParty{line: t.Line})
			schema = partyKeys
		default:
			return nil, fmt.Errorf("line %d: %q is not a table of this file (only [relay] and [[party]])", t.Line, t.Name)
		}
		for _, e := range t.Entries {
			n := e.Val.Line
			want, known := schema[e.Key]
			if !known {
				return nil, fmt.Errorf("line %d: unknown key %q", n, e.Key)
			}
			if e.Val.Kind != want {
				return nil, fmt.Errorf("line %d: key %q has the wrong kind of value", n, e.Key)
			}
			if t.Name == "relay" {
				f.relay[e.Key] = e.Val.Uint
				continue
			}
			p := &f.parties[len(f.parties)-1]
			switch e.Key {
			case "label":
				p.label, p.hasLabel = e.Val.Str, true
			case "document":
				p.document = e.Val.Str
			case "send_to":
				p.sendTo = e.Val.List
			}
		}
	}
	return f, nil
}

// applyRelay applies the [relay] table to c, refusing a retention outside
// 1 to the maximum.
func (f *rawFile) applyRelay(c *Config) error {
	for k, v := range f.relay {
		switch k {
		case "retention_seconds":
			if v == 0 || v > mailbox.MaxRetentionSeconds {
				return fmt.Errorf("[relay] retention_seconds is %d; retention is 1 to %d seconds (30 days) and never beyond", v, mailbox.MaxRetentionSeconds)
			}
			c.RetentionSeconds = v
		case "mailbox_entries":
			c.Quota.MailboxEntries = v
		case "mailbox_bytes":
			c.Quota.MailboxBytes = v
		case "pair_entries":
			c.Quota.PairEntries = v
		case "pair_bytes":
			c.Quota.PairBytes = v
		case "sender_bytes":
			c.Quota.SenderBytes = v
		case "global_bytes":
			c.Quota.GlobalBytes = v
		}
	}
	return nil
}
