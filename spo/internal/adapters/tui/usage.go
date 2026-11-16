package tui

import "github.com/mochipool/workbench/spo/internal/platform/uihint"

// positional is one positional argument named in a command's Use line; the
// parser is shared with the shell completion (uihint.Positionals).
type positional struct {
	name     string
	optional bool
	repeat   bool
}

func parseUse(use string) []positional {
	var out []positional
	for _, p := range uihint.Positionals(use) {
		out = append(out, positional{name: p.Name, optional: p.Optional, repeat: p.Repeat})
	}
	return out
}
