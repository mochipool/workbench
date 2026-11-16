package uihint

import "strings"

// Positional is one positional argument named in a command's usage line.
type Positional struct {
	Name     string // the text between the brackets, or the bare word
	Optional bool
	Repeat   bool
}

// capsPositional recognises a bare upper-case word (`FILE`, `ID`, `FILE|DIR...`)
// as a required positional: usage lines that do not use angle brackets name
// their arguments that way. A word after a flag is that flag's value and is
// not asked about here.
func capsPositional(word string) (name string, repeat, ok bool) {
	word = strings.TrimSpace(word)
	if repeat = strings.HasSuffix(word, "..."); repeat {
		word = strings.TrimSuffix(word, "...")
	}
	if word == "" || word[0] < 'A' || word[0] > 'Z' {
		return "", false, false
	}
	for _, c := range word {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '|' || c == '-') {
			return "", false, false
		}
	}
	return word, repeat, true
}

// Positionals extracts the positional arguments from a cobra Use string:
//
//	send <from> <to> <amount> [--message TEXT]... [--yes]  -> from, to, amount
//	export <dir> (--password-fd N | --plaintext) [--yes]   -> dir
//	vote <txhash> [index]                                   -> txhash, [index]
//	init --network <mainnet|preprod>                        -> none (a flag value)
//
// Bracketed groups that begin with a dash are flags; an angle group right
// after a bare --flag word is that flag's value; parentheses are skipped.
func Positionals(use string) []Positional {
	fields := strings.SplitN(strings.TrimSpace(use), " ", 2)
	if len(fields) < 2 {
		return nil
	}
	s := fields[1]
	var out []Positional
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
				body = strings.TrimSpace(body)
				if c == '[' && strings.HasPrefix(body, "<") && strings.HasSuffix(body, ">") {
					body = body[1 : len(body)-1] // an optional <name>
				}
				out = append(out, Positional{Name: body, Optional: c == '[', Repeat: repeat})
				prevFlag = false
			}
		default:
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			word := s[i:j]
			i = j
			wasFlag := prevFlag
			prevFlag = strings.HasPrefix(word, "--")
			if !wasFlag && !prevFlag {
				if name, repeat, ok := capsPositional(word); ok {
					out = append(out, Positional{Name: name, Repeat: repeat})
				}
			}
		}
	}
	return out
}
