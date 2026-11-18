package plainstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/mochipool/workbench/spo/internal/adapters/storeaudit"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// AuditFileName is the audit log of a plain directory: that layout has no
// record for it, so it is one dotfile next to the files. It holds names the
// operator gave, counts and a reason, never key material. It is not part of
// the upstream layout, so an import lists it as an unknown file.
const AuditFileName = ".spo-workspace-audit.json"

// legacyAuditFileName is the name before the file became a dotfile.
const legacyAuditFileName = "spo-workspace-audit.json"

// AuditStore is the record store of the audit log of a plain directory: it
// holds the one record storeaudit keeps, in AuditFileName.
func AuditStore(dir string) ports.NamedStore { return auditFile{dir: dir} }

// IsPlain reports whether store is a plain store.
func IsPlain(store ports.Store) bool { _, ok := store.(*anchored); return ok }

type auditFile struct{ dir string }

func (a auditFile) path() string { return filepath.Join(a.dir, AuditFileName) }

func (a auditFile) View(_ context.Context, fn func(ports.NamedReader) error) error {
	return fn(auditTx{a})
}

func (a auditFile) Update(_ context.Context, fn func(ports.NamedWriter) error) error {
	return fn(auditTx{a})
}

type auditTx struct{ a auditFile }

var errAuditOnly = errors.New("this record store holds the audit log only")

func (t auditTx) Get(ref ports.NamedRef) ([]byte, error) {
	if ref != storeaudit.Ref {
		return nil, errAuditOnly
	}
	b, err := os.ReadFile(t.a.path())
	if errors.Is(err, os.ErrNotExist) {
		b, err = os.ReadFile(filepath.Join(t.a.dir, legacyAuditFileName))
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, ports.ErrNotFound
	}
	return b, err
}

func (t auditTx) Exists(ref ports.NamedRef) (bool, error) {
	_, err := t.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (t auditTx) Put(ref ports.NamedRef, data []byte) error {
	if ref != storeaudit.Ref {
		return errAuditOnly
	}
	tmp, err := os.CreateTemp(t.a.dir, ".audit-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), t.a.path()); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(t.a.dir, legacyAuditFileName))
	return nil
}

func (t auditTx) PutSecret(ports.NamedRef, *secret.Buffer) error { return errAuditOnly }
func (t auditTx) Delete(ports.NamedRef) error                    { return errAuditOnly }
