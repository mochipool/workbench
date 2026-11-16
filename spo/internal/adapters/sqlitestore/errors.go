package sqlitestore

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Errors. None of them contains an operator-chosen name (pool, wallet): those
// are Sensitive (ADR 0004). Errors about one artefact are a *RefError.
var (
	// ErrWrongCredential: no slot of the requested kind opens with the given
	// passphrase or recovery key (or the file's slots were modified). It is
	// never returned because of audit rows or records: damage there is a
	// verification error (ErrVerify).
	ErrWrongCredential = errors.New("sqlitestore: wrong passphrase or recovery key")
	// ErrCorrupt: a record failed to authenticate.
	ErrCorrupt = errors.New("sqlitestore: a record failed authentication; the file is damaged or was tampered with")
	// ErrNotWorkspace: the file has no workspace schema.
	ErrNotWorkspace = errors.New("sqlitestore: not a workspace file")
	// ErrExists: the destination already holds a workspace.
	ErrExists = errors.New("sqlitestore: destination already exists")
	// ErrLastSlot: the operation would leave the workspace without a
	// passphrase slot or without a recovery slot (at least one of each is
	// always kept).
	ErrLastSlot = errors.New("sqlitestore: a workspace must keep at least one passphrase slot and one recovery slot")
	// ErrReentrant: an operation gave up waiting for the Store handle because
	// its context ended. The usual cause is a call to the same Store from
	// inside its own View or Update callback, which waits for itself until the
	// context ends (there is no other timeout: a call with context.Background
	// would wait forever). Use the Reader or Writer you were given instead (a
	// Writer also offers OpenSecret). The error also wraps the context's own
	// error.
	ErrReentrant = errors.New("sqlitestore: gave up waiting for the store; a call made from inside a View or Update callback of the same store waits for itself")
	// ErrStaleHandle: the workspace's key epoch is no longer the one this
	// handle unlocked: another process rekeyed the workspace and this handle
	// holds revoked keys, or the meta row was modified. Nothing was done; close
	// the handle and open the workspace again (a modified meta row then fails
	// verification).
	ErrStaleHandle = errors.New("sqlitestore: the workspace was rekeyed by another process or its meta row was modified; close and reopen")
	// ErrKeyEpoch: a slot opened with the credential, but the master key in it
	// does not belong to the key epoch the meta row records: the slot row
	// comes from before a rekey (put back from an old copy), or the meta row
	// (key epoch, epoch MAC) was modified.
	ErrKeyEpoch = errors.New("sqlitestore: this credential belongs to an earlier key epoch of the workspace, or the workspace's meta row was modified")
	// ErrSchema: the database holds objects (triggers, views, tables,
	// indexes) or column definitions that the schema of its version does not
	// have, or lacks ones it has. It is always wrapped in ErrVerify; the
	// message names the type and name of the object, never record data.
	ErrSchema = errors.New("sqlitestore: the database schema is not the one this version creates")
	// ErrLockLost: a lock upgrade or downgrade failed and left this handle
	// without its shared file lock, so another process may now replace or
	// rekey the file. Every later operation except Close returns it.
	ErrLockLost = errors.New("sqlitestore: this handle lost its file lock; close it and open the workspace again")
	// ErrRolledBack: the workspace file is older than the last state recorded
	// in its head file (see OpenOptions.AcceptRollback).
	ErrRolledBack = errors.New("sqlitestore: the workspace file is older than the last recorded state; it may have been replaced by an older copy. If you restored an older backup on purpose, open it with AcceptRollback")
	// ErrHeadMismatch: the head file belongs to another workspace or cannot
	// be read.
	ErrHeadMismatch = errors.New("sqlitestore: the head file does not belong to this workspace or is unreadable")
	// ErrUseRekey: removing or replacing a key slot does not revoke it unless
	// the master key changes; use Rekey.
	ErrUseRekey = errors.New("sqlitestore: removing or replacing a slot revokes nothing unless the master key changes; use Rekey (or ChangePassphraseRekey)")
	// ErrRekeyCredentials: Rekey needs exactly one passphrase credential.
	ErrRekeyCredentials = errors.New("sqlitestore: rekey needs exactly one passphrase credential")
	// ErrLocked: another process or handle holds the workspace in a way that
	// conflicts (a restore and a rekey need it exclusively: every other handle,
	// in this process or another, must be closed).
	ErrLocked = errors.New("sqlitestore: the workspace is open elsewhere or is being replaced")
	// ErrOtherWorkspace: a restore would replace a workspace with a backup of
	// a different workspace.
	ErrOtherWorkspace = errors.New("sqlitestore: the backup is of a different workspace than the destination")
	// ErrOlderBackup: a restore would replace a workspace with a backup that
	// is older than, or has diverged from, the destination.
	ErrOlderBackup = errors.New("sqlitestore: the backup is older than the destination or has diverged from it")
)

// RefError is an error about one artefact. Error prints the kind and the
// cause but not the name: the name is Sensitive, so callers decide whether to
// show Ref.
type RefError struct {
	Ref ports.Ref
	Err error
}

func (e *RefError) Error() string { return fmt.Sprintf("%s record: %v", e.Ref.Kind, e.Err) }
func (e *RefError) Unwrap() error { return e.Err }
