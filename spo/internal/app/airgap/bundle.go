package airgap

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// InspectBundle shows the bundle (upstream `01_workOffline info` and
// showOfflineFileInfo): general information, the addresses with their
// balances, the queued transactions, the history and the attached files by
// name and size. It never writes, and runs in every mode.
type InspectBundle struct {
	Bundle ports.BundleReader
}

// InfoResult is the read model.
type InfoResult struct {
	// Found is false for a missing file, which is shown as an empty bundle
	// (SPO-01workOffline-INV-004).
	Found bool
	transfer.Info
}

// PendingTransactions is the number of queued transactions: the notice
// `info` ends with (SPO-01workOffline-INV-004).
func (r InfoResult) PendingTransactions() int { return len(r.Transactions) }

// AttachedFiles is the number of attached files.
func (r InfoResult) AttachedFiles() int { return len(r.Files) }

// Run reads the bundle. A file that is not JSON is an error
// (SPO-01workOffline-PRE-003); a bundle that readOfflineFile would refuse is
// reported in Usable, not as an error.
//
// spec: SPO-01workOffline-INV-004, SPO-01workOffline-IF-008, SPO-01workOffline-PRE-003, SPO-Coffline-IF-001,
// spec: SPO-Coffline-IN-002, SPO-Coffline-IN-003, SPO-Coffline-IN-004, SPO-Coffline-IN-005, SPO-Coffline-IN-006,
// spec: SPO-Coffline-IN-007, SPO-Coffline-IN-008, SPO-Coffline-IN-009, SPO-Coffline-IN-010, SPO-Coffline-IN-011,
// spec: SPO-Coffline-PRE-001, SPO-Coffline-PRE-002, SPO-Coffline-PRE-003, SPO-Coffline-PRE-004, SPO-Coffline-OUT-001,
// spec: SPO-Ptransfer-IN-002
func (uc InspectBundle) Run(ctx context.Context) (InfoResult, error) {
	if uc.Bundle == nil {
		return InfoResult{}, fmt.Errorf("%w: a bundle reader is needed", ErrMisconfigured)
	}
	b, found, err := uc.Bundle.ReadBundle(ctx)
	if err != nil {
		return InfoResult{}, err
	}
	info, err := b.Info()
	if err != nil {
		return InfoResult{}, err
	}
	if !found {
		info.Usable = transfer.ErrNoFile
	}
	return InfoResult{Found: found, Info: info}, nil
}

// RequireUsable reads the bundle and applies the checks of upstream's
// readOfflineFile: it exists, is JSON, is not empty and has protocol
// parameters (SPO-Coffline-PRE-001 to SPO-Coffline-PRE-004). The offline
// use cases that serve the snapshot call it through their reader; `attach`
// calls it here.
func RequireUsable(ctx context.Context, r ports.BundleReader) error {
	b, found, err := r.ReadBundle(ctx)
	if err != nil {
		return err
	}
	if !found {
		return transfer.ErrNoFile
	}
	return b.Usable()
}

// ClearPart says which part of the bundle a Clear removes.
type ClearPart int

// The parts.
const (
	ClearTransactions ClearPart = iota
	ClearHistory
	ClearFiles
)

// Clear empties a part of the bundle (upstream `cleartx`, `clearhistory`,
// `clearfiles`): the queue without submitting anything, the history, or the
// attached files. Each appends its own history entry and changes no other
// key. Upstream asks no confirmation and neither does this; a caller that
// wants one asks before (the port note of 01_workOffline). It works on
// whatever the file contains and on a missing file, which then holds only
// the history entry (SPO-Ptransfer-IN-002).
type Clear struct {
	Bundle ports.BundleMutator
	Clock  ports.Clock
}

// Run clears one part.
//
// spec: SPO-01workOffline-OUT-001, SPO-01workOffline-OUT-002, SPO-01workOffline-OUT-003, SPO-01workOffline-INV-002,
// spec: SPO-Ptransfer-OUT-015, SPO-Ptransfer-OUT-016, SPO-Ptransfer-OUT-020, SPO-Ptransfer-IN-002
func (uc Clear) Run(ctx context.Context, part ClearPart) error {
	if uc.Bundle == nil {
		return fmt.Errorf("%w: a bundle is needed", ErrMisconfigured)
	}
	date := now(uc.Clock)
	return uc.Bundle.MutateBundle(ctx, func(b *transfer.Bundle) error {
		switch part {
		case ClearTransactions:
			return b.ClearTransactions(date)
		case ClearHistory:
			return b.ClearHistory(date)
		case ClearFiles:
			return b.ClearFiles(date)
		}
		return fmt.Errorf("%w: unknown part to clear", ErrMisconfigured)
	})
}

// DefaultMaxAttachBytes bounds an attachment when Attach.MaxBytes is zero.
// Upstream's limit is an accident of the kernel's argument size (about
// 96 KB, SPO-01workOffline-OUT-013's quirk) and ends in a refusal with no
// explanation; this one is stated.
const DefaultMaxAttachBytes = 1 << 20

// ErrTooLarge: the file is larger than the limit.
var ErrTooLarge = errors.New("the file is too large to attach")

// Attach stores a file in the bundle (upstream `attach`). It needs a usable
// bundle (SPO-01workOffline-PRE-008) and works in every mode. The caller
// reads the file; the name is the key stored, as given, and must be a plain
// file name (a leading `./` is kept as upstream stores it). A path with a
// directory part is refused: extraction would refuse it too
// (SPO-Ptransfer-SEC-001).
type Attach struct {
	Bundle   ports.BundleStore
	Clock    ports.Clock
	MaxBytes int
}

// Run attaches content under name.
//
// spec: SPO-01workOffline-IF-007, SPO-01workOffline-PRE-008, SPO-01workOffline-OUT-013, SPO-01workOffline-MODE-001,
// spec: SPO-Ptransfer-OUT-017
func (uc Attach) Run(ctx context.Context, name string, content []byte) error {
	if uc.Bundle == nil {
		return fmt.Errorf("%w: a bundle is needed", ErrMisconfigured)
	}
	if name == "" {
		return errors.New("attach needs a file")
	}
	limit := uc.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxAttachBytes
	}
	if len(content) > limit {
		return fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, len(content), limit)
	}
	if _, err := transfer.SafeName(name); err != nil {
		return err
	}
	if err := RequireUsable(ctx, uc.Bundle); err != nil {
		return err
	}
	date := now(uc.Clock)
	return uc.Bundle.MutateBundle(ctx, func(b *transfer.Bundle) error {
		if err := b.Usable(); err != nil {
			return err
		}
		return b.Attach(name, content, date)
	})
}

// ExtractStatus is what became of one attachment.
type ExtractStatus string

// The statuses.
const (
	// Extracted: written, the entry removed and the history entry added.
	Extracted ExtractStatus = "extracted"
	// Skipped: a file of that name exists and overwriting was not asked for;
	// the entry stays (SPO-01workOffline-OUT-014).
	Skipped ExtractStatus = "skipped"
	// Refused: the name is not a plain file name; the entry stays.
	Refused ExtractStatus = "refused"
	// Failed: the content could not be decoded or written; the entry stays.
	Failed ExtractStatus = "failed"
)

// ExtractEntry is the outcome for one attachment.
type ExtractEntry struct {
	Key    string
	Status ExtractStatus
	Err    error
}

// ExtractResult lists the outcomes, in key order, and how many attachments
// remain.
type ExtractResult struct {
	Entries   []ExtractEntry
	Remaining int
}

// ErrExtractIncomplete: some attachments were refused or failed. Upstream
// ends with exit 0 (SPO-01workOffline-INV-005).
var ErrExtractIncomplete = errors.New("some attached files were not extracted")

// Extract writes the attached files to a directory (upstream `extract`).
//
// It differs from upstream where upstream is unsafe: a stored key is never a
// path. The destination is the sink's directory joined with the key as a
// plain file name; a key with a separator, an absolute path or `..` is
// refused and its entry stays (SPO-Ptransfer-SEC-001, SPO-01workOffline-SEC-001,
// SPO-01workOffline-SEC-004: the fix). An existing file is skipped unless
// Overwrite is set. The entry is removed from the bundle and the bundle
// rewritten after each file, so an interrupted run loses nothing.
type Extract struct {
	Bundle ports.BundleStore
	Sink   ports.FileSink
	Clock  ports.Clock
	// Overwrite replaces an existing regular file. It is explicit; upstream
	// has no such option.
	Overwrite bool
}

// Run extracts every attachment it can and returns the outcomes. The error is
// ErrExtractIncomplete (wrapping each cause) when an attachment was refused
// or failed; skipped files are not an error.
//
// spec: SPO-01workOffline-OUT-014, SPO-01workOffline-INV-005, SPO-01workOffline-SEC-001, SPO-01workOffline-SEC-004,
// spec: SPO-01workOffline-MODE-001, SPO-Ptransfer-OUT-019, SPO-Ptransfer-SEC-001, SPO-Ptransfer-IN-002
func (uc Extract) Run(ctx context.Context) (ExtractResult, error) {
	if uc.Bundle == nil || uc.Sink == nil {
		return ExtractResult{}, fmt.Errorf("%w: a bundle and a file sink are needed", ErrMisconfigured)
	}
	b, _, err := uc.Bundle.ReadBundle(ctx)
	if err != nil {
		return ExtractResult{}, err
	}
	files, err := b.Files()
	if err != nil {
		return ExtractResult{}, err
	}
	var res ExtractResult
	var problems []error
	for _, f := range files {
		e := ExtractEntry{Key: f.Key}
		name, err := transfer.SafeName(f.Key)
		var content []byte
		if err == nil {
			content, err = b.FileContent(f.Key)
		}
		if err != nil {
			e.Status, e.Err = Refused, err
			if !errors.Is(err, transfer.ErrUnsafeName) {
				e.Status = Failed
			}
		} else if written, werr := uc.Sink.WriteFile(ctx, name, content, uc.Overwrite); werr != nil {
			e.Status, e.Err = Failed, werr
		} else if !written {
			e.Status = Skipped
		} else {
			date := now(uc.Clock)
			key := f.Key
			if merr := uc.Bundle.MutateBundle(ctx, func(nb *transfer.Bundle) error { return nb.MarkExtracted(key, date) }); merr != nil {
				e.Status, e.Err = Failed, fmt.Errorf("%s was written but the bundle could not record it: %w", name, merr)
			} else {
				e.Status = Extracted
			}
		}
		if e.Err != nil {
			problems = append(problems, fmt.Errorf("%q: %w", f.Key, e.Err))
		}
		res.Entries = append(res.Entries, e)
		if e.Status != Extracted {
			res.Remaining++
		}
	}
	if len(problems) > 0 {
		return res, fmt.Errorf("%w: %w", ErrExtractIncomplete, errors.Join(problems...))
	}
	return res, nil
}
