package tui

import (
	"strings"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// maxSecret bounds what the masked input takes, as the CLI's terminal does.
const maxSecret = 4096

// lineInput is a one-line text input that edits at its end.
type lineInput struct {
	runes []rune
}

func (l *lineInput) String() string { return string(l.runes) }
func (l *lineInput) empty() bool    { return len(l.runes) == 0 }
func (l *lineInput) reset()         { l.runes = nil }
func (l *lineInput) set(s string)   { l.runes = []rune(CleanLine(s)) }

// handle applies an editing key; it reports whether the key was consumed.
func (l *lineInput) handle(k keyInput) bool {
	switch {
	case k.text != "":
		l.insert(k.text)
		return true
	case k.name == "backspace":
		if n := len(l.runes); n > 0 {
			l.runes = l.runes[:n-1]
		}
		return true
	case k.name == "ctrl+u":
		l.runes = nil
		return true
	}
	return false
}

// insert adds typed or pasted text, dropping control characters.
func (l *lineInput) insert(s string) {
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && !(r >= 0x80 && r <= 0x9f) {
			l.runes = append(l.runes, r)
		}
	}
}

func (l *lineInput) view() string { return CleanLine(string(l.runes)) }

// maskedInput holds a secret as it is typed: bytes in a slice of fixed
// capacity (no reallocation that would leave copies), drawn as bullets, wiped
// by clear and handed on only by take. It is the interactive twin of what the
// CLI's terminal does with a password read from the tty.
type maskedInput struct {
	buf []byte
}

func (m *maskedInput) n() int      { return utf8.RuneCount(m.buf) }
func (m *maskedInput) empty() bool { return len(m.buf) == 0 }

func (m *maskedInput) handle(k keyInput) bool {
	switch {
	case k.text != "":
		m.insert(k.text)
		return true
	case k.name == "backspace":
		if len(m.buf) > 0 {
			_, size := utf8.DecodeLastRune(m.buf)
			for i := len(m.buf) - size; i < len(m.buf); i++ {
				m.buf[i] = 0
			}
			m.buf = m.buf[:len(m.buf)-size]
		}
		return true
	case k.name == "ctrl+u":
		m.clear()
		return true
	}
	return false
}

// insert adds typed or pasted text, dropping control characters.
func (m *maskedInput) insert(s string) {
	if m.buf == nil {
		m.buf = make([]byte, 0, maxSecret)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || len(m.buf)+utf8.RuneLen(r) > cap(m.buf) {
			continue
		}
		m.buf = utf8.AppendRune(m.buf, r)
	}
}

// clear wipes what was typed.
func (m *maskedInput) clear() {
	b := m.buf[:cap(m.buf)]
	for i := range b {
		b[i] = 0
	}
	m.buf = nil
}

// take moves the secret into guarded memory (which wipes the slice) and
// leaves the input empty; nil when nothing was typed.
func (m *maskedInput) take() *secret.Buffer {
	if len(m.buf) == 0 {
		return nil
	}
	b := m.buf
	m.buf = nil
	return secret.Take(b)
}

func (m *maskedInput) view() string { return strings.Repeat("•", m.n()) }
