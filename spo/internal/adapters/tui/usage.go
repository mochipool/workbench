package tui

import "strings"

// positional is one positional argument named in a command's Use line.
type positional struct {
	name     string
	optional bool
	repeat   bool
}

// parseUse extracts the positional arguments from a cobra Use string:
//
//	send <from> <to> <amount> [--message TEXT]... [--yes]  -> from, to, amount
//	export <dir> (--password-fd N | --plaintext) [--yes]   -> dir
//	vote <txhash> [index]                                   -> txhash, [index]
//	init --network <mainnet|preprod>                        -> none (a flag value)
//
// Bracketed groups that begin with a dash are flags; an angle group right
// after a bare --flag word is that flag's value; parentheses are skipped.
func parseUse(use string) []positional {
	fields := strings.SplitN(strings.TrimSpace(use), " ", 2)
	if len(fields) < 2 {
		return nil
	}
	s := fields[1]
	var out []positional
	prevFlag := false // the previous top-level token was a bare --flag
	i := 0
	for i < len(s) {
		switch c := s[i]; {
		case c == ' ' || c == '|':
			i++
		case c == '<' || c == '[' || c == '(':
			closer := map[byte]byte{'<': '>', '[': ']', '(': ')'}[c]
			depth, j := 0, i
			for ; j < len(s); j++ {
				if s[j] == c {
					depth++
				} else if s[j] == closer {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if j >= len(s) {
				return out
			}
			body := s[i+1 : j]
			i = j + 1
			repeat := strings.HasPrefix(s[i:], "...")
			if repeat {
				i += 3
			}
			switch {
			case c == '(' || (c == '[' && strings.HasPrefix(body, "-")):
				prevFlag = false
			case c == '<' && prevFlag:
				prevFlag = false // the value of the flag before it
			default:
				out = append(out, positional{name: strings.TrimSpace(body), optional: c == '[', repeat: repeat})
				prevFlag = false
			}
		default:
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			word := s[i:j]
			i = j
			prevFlag = strings.HasPrefix(word, "--")
		}
	}
	return out
}
