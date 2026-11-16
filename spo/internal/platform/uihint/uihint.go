// Package uihint names the cobra annotations the command tree uses to tell
// an interactive driver (the TUI, ADR 0009) what a flag or a command is. The
// annotations change nothing in the command line; they only describe.
package uihint

const (
	// SecretFD marks an integer flag that names an inherited file descriptor
	// carrying a secret. Its value is SecretIn (the command reads a secret
	// from it) or SecretOut (the command writes a secret to it).
	SecretFD  = "spo.ui/secret-fd"
	SecretIn  = "in"
	SecretOut = "out"

	// SensitiveOutput marks a command whose output can hold a secret (a
	// recovery key shown once): an interactive driver clears what it kept of
	// that output when the operator leaves the command.
	SensitiveOutput = "spo.ui/sensitive-output"

	// Global marks a persistent flag of the root that the driver fixes for
	// its whole session (the workspace directory, the layout), so it is not
	// offered again in each command's form.
	Global = "spo.ui/global"
)
