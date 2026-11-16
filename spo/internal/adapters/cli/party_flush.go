package cli

import "golang.org/x/sys/unix"

// inputFlusher is a terminal that can throw away what was typed before a
// prompt was shown. It is optional: a Terminal that does not implement it is
// used as it is.
type inputFlusher interface{ FlushInput() }

// flushTypedAhead discards typed-ahead input (a pasted "y", a stray Enter)
// before a yes/no or a passphrase is asked, so that nothing typed before the
// review was shown can answer the question.
func flushTypedAhead(t Terminal) {
	if f, ok := t.(inputFlusher); ok {
		f.FlushInput()
	}
}

// FlushInput is TCIFLUSH on the terminal descriptor: it drops the unread input.
// It does nothing when the descriptor is not a terminal.
func (t ttyTerminal) FlushInput() {
	if _, ok := t.isTTY(); !ok {
		return
	}
	_ = unix.IoctlSetInt(t.fd, unix.TCFLSH, unix.TCIFLUSH)
}
