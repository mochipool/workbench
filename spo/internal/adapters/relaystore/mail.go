package relaystore

import (
	"context"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

type objInfo = s3client.ObjectInfo

// maxListedKeys bounds the keys a report names for each class of finding.
const maxListedKeys = 32

// maxListedRecipients bounds the mailboxes a report describes one by one;
// the rest are counted.
const maxListedRecipients = 1024

// Recipient is one mailbox as a load would see it.
type Recipient struct {
	Recipient party.Fingerprint
	// Objects and Bytes count every object of the mailbox; Entries those a
	// load serves; Senders the distinct senders of those.
	Objects, Entries, Senders int
	Bytes                     int64
	// Duplicates are later objects of one sender and id, OverBound objects
	// past the 256 entries of the mailbox: a load dooms both (counts them,
	// lists neither, and its sweep deletes them). The lists hold the first
	// maxListedKeys; the counts are DuplicatesN and OverBoundN.
	Duplicates, OverBound   []string
	DuplicatesN, OverBoundN int
}

// MailboxView is the version-free view of the mailbox prefix.
type MailboxView struct {
	Objects int
	Bytes   int64
	// Recipients are the first maxListedRecipients mailboxes; RecipientsN
	// counts them all.
	Recipients  []Recipient
	RecipientsN int
	// Unparsable are keys under mailbox/ that are not entry keys, BadSize keys
	// whose size is not 1 B to 1 MiB, and TooMany recipients holding more than
	// objmailbox.MaxNamesPerMailbox objects: each makes a load refuse.
	Unparsable, BadSize []string
	TooMany             []party.Fingerprint
	// UnparsableN, BadSizeN and TooManyN count them (the lists are cut at
	// maxListedKeys).
	UnparsableN, BadSizeN, TooManyN int
}

// mailClass is a class of mailbox object repair deletes.
type mailClass int

const (
	mailServed mailClass = iota
	mailDuplicate
	mailOverBound
	mailUnparsable
	mailBadSize
)

// mailScan is a classification of the objects for repair: the keys of each
// class repair deletes, at most keep of them in all (more counts the rest).
type mailScan struct {
	view    MailboxView
	classes map[string]mailClass
	keys    []string // in listing order
	more    int
}

// scanMailbox lists the mailbox prefix page by page, at most maxObjects
// objects (objmailbox.MaxObjects by default), and classifies every key as
// objmailbox's load does: unparsable or badly sized keys refuse a load; of one
// sender and id the earlier is the entry and the later doomed; past 256
// entries of a mailbox doomed. It keeps counts, the first keys of each class
// for the report, and, for repair, at most keep keys of the classes repair
// deletes (changed after the review of work package 9: it kept every key).
func (s *session) scanMailbox(ctx context.Context, maxObjects, keep int) (mailScan, error) {
	if maxObjects <= 0 {
		maxObjects = objmailbox.MaxObjects
	}
	ms := mailScan{classes: map[string]mailClass{}}
	mprefix := s.prefix + pathMailbox
	var cur Recipient
	have := false
	var seen map[[2]string]bool
	var senders map[party.Fingerprint]bool
	flush := func() {
		if have && len(ms.view.Recipients) < maxListedRecipients {
			ms.view.Recipients = append(ms.view.Recipients, cur)
		}
	}
	class := func(rel string, c mailClass) {
		if len(ms.keys) >= keep {
			ms.more++
			return
		}
		ms.classes[rel] = c
		ms.keys = append(ms.keys, rel)
	}
	listed := func(list *[]string, n *int, rel string) {
		if *n++; len(*list) < maxListedKeys {
			*list = append(*list, rel)
		}
	}
	err := s.listObjects(ctx, s.wc, mprefix, maxObjects, func(o objInfo) error {
		ms.view.Objects++
		ms.view.Bytes += o.Size
		rel := strings.TrimPrefix(o.Key, s.prefix)
		k, err := parseEntry(mprefix, o.Key)
		if err != nil {
			listed(&ms.view.Unparsable, &ms.view.UnparsableN, rel)
			class(rel, mailUnparsable)
			return nil
		}
		if o.Size < 1 || o.Size > mailbox.MaxEnvelopeBytes {
			listed(&ms.view.BadSize, &ms.view.BadSizeN, rel)
			class(rel, mailBadSize)
			return nil
		}
		if !have || cur.Recipient != k.Recipient {
			flush()
			cur, have = Recipient{Recipient: k.Recipient}, true
			ms.view.RecipientsN++
			seen, senders = map[[2]string]bool{}, map[party.Fingerprint]bool{}
		}
		cur.Objects++
		cur.Bytes += o.Size
		if cur.Objects == objmailbox.MaxNamesPerMailbox+1 {
			if ms.view.TooManyN++; len(ms.view.TooMany) < maxListedKeys {
				ms.view.TooMany = append(ms.view.TooMany, k.Recipient)
			}
		}
		id := [2]string{fp(k.Sender), k.Mid.String()}
		switch {
		case seen[id]:
			listed(&cur.Duplicates, &cur.DuplicatesN, rel)
			class(rel, mailDuplicate)
		case cur.Entries >= mailbox.MaxMailboxEntries:
			listed(&cur.OverBound, &cur.OverBoundN, rel)
			class(rel, mailOverBound)
		default:
			// at most MaxMailboxEntries ids and senders a mailbox
			seen[id] = true
			cur.Entries++
			if !senders[k.Sender] {
				senders[k.Sender] = true
				cur.Senders++
			}
		}
		return nil
	})
	flush()
	if err != nil {
		return ms, fmt.Errorf("the mailbox listing: %w", err)
	}
	return ms, nil
}
