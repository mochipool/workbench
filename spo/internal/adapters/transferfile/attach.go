package transferfile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Attach implements ports.TransferAttacher: it stores a file inside the
// transfer file as `files."<name>"` with `date`, `size` (bytes, as a string)
// and `base64` (the whole file), appends the history entry `attached file
// '<name>'` and rewrites the file atomically. Attaching the same name again
// replaces that entry. The pool use cases attach the metadata files after a
// transaction was queued and the witness transfer files of open slots
// (SPO-05c-PR-005, SPO-05c-PR-006, SPO-05c-PR-007, SPO-05d-PR-003).
//
// spec: SPO-Ptransfer-OUT-017, SPO-Ptransfer-OUT-018
func (f *File) Attach(_ context.Context, name string, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return err
	}
	date := rfc5322(f.now())
	files := &ordered{vals: map[string]json.RawMessage{}}
	if raw, ok := doc.vals["files"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if files, err = parseOrdered(raw); err != nil {
			return fmt.Errorf("%w: files: %v", ErrInvalidFile, err)
		}
	}
	entry, _ := json.Marshal(struct {
		Date   string `json:"date"`
		Size   string `json:"size"`
		Base64 string `json:"base64"`
	}{date, strconv.Itoa(len(content)), base64.StdEncoding.EncodeToString(content)})
	files.set(name, entry)
	fb, err := files.marshalCompact()
	if err != nil {
		return err
	}
	doc.set("files", fb)

	var hist []json.RawMessage
	if raw, ok := doc.vals["history"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &hist); err != nil {
			return fmt.Errorf("%w: history is not an array", ErrInvalidFile)
		}
	}
	h, _ := json.Marshal(struct {
		Date   string `json:"date"`
		Action string `json:"action"`
	}{date, "attached file '" + name + "'"})
	hb, _ := json.Marshal(append(hist, h))
	doc.set("history", hb)

	out, err := doc.marshal()
	if err != nil {
		return err
	}
	return writeAtomic(f.Path, out)
}

var _ ports.TransferAttacher = (*File)(nil)
