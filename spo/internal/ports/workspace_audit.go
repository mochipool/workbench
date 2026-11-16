package ports

// WorkspaceAuditLog is the record of dangerous workspace operations (export,
// unprotect, import): one blob under the name "workspace", kept in the store
// the operations run against, so that in the sealed store each append is a
// write of the MAC-chained audit log like any other. It holds names the
// operator gave, counts and a reason, never secret material or file contents.
// Sensitive, not secret; this program's own record, not part of an upstream
// workspace (IsWorkspaceKind must refuse it).
const WorkspaceAuditLog Kind = "workspace.audit"

func init() { kinds[WorkspaceAuditLog] = kindInfo{} }
