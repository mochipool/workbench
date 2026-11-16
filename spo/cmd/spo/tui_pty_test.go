//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests run the real `spo tui` on a real pseudo-terminal and drive it
// with key bytes, as a person at a terminal would. The program under test is
// this test binary re-executed as spo (SPO_PTY_CHILD=1 makes init run the
// binary's own run() and exit), so it is the same code path as the shipped
// command, including secret.Init, process hardening and bubbletea on a tty.
//
// They need /dev/ptmx and permission to open a pty slave. Where that is not
// available (a Nix build sandbox, a container without devpts) each test skips
// with the reason "no pseudo-terminal"; a CI run should count those skips.

func init() {
	if os.Getenv("SPO_PTY_CHILD") == "1" {
		os.Exit(run())
	}
}

const (
	altOn       = "\x1b[?1049h"
	altOff      = "\x1b[?1049l"
	cursorShow  = "\x1b[?25h"
	ptyWait     = 30 * time.Second
	keyEnter    = "\r"
	keyCtrlC    = "\x03"
	keyEsc      = "\x1b"
	keyTab      = "\t"
	keyUp       = "\x1b[A"
	keyDown     = "\x1b[B"
	keyCtrlN    = "\x0e"
	keyCtrlO    = "\x0f"
	keyCtrlR    = "\x12"
	rows, cols  = 30, 160
	markerSecre = "xyzzy-marker-passphrase"
)

type ptyTUI struct {
	t      *testing.T
	master *os.File
	proc   *os.Process

	mu   sync.Mutex
	raw  bytes.Buffer
	exit chan struct{}
	st   *os.ProcessState
	scr  *vt
	// frames holds the text of every distinct screen the terminal showed. A
	// renderer that redraws only what changed never writes a typed string
	// contiguously, so a search of the raw bytes alone can miss what a person
	// saw; the frames are what was on the screen.
	frames   []string
	frameLen int
}

const maxFrameBytes = 32 << 20

// startTUI opens a pty of the given size and starts `spo -C dir tui` on it.
func startTUI(t *testing.T, dir string, r, c uint16, extraArgs ...string) *ptyTUI {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal in this environment: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("no pseudo-terminal in this environment: TIOCGPTN: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("no pseudo-terminal in this environment: unlockpt: %v", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal in this environment: opening the slave: %v", err)
	}
	defer slave.Close()
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: r, Col: c}); err != nil {
		t.Skipf("no pseudo-terminal in this environment: window size: %v", err)
	}
	p := &ptyTUI{t: t, master: master, exit: make(chan struct{}), scr: newVT(int(r), int(c))}
	args := append([]string{os.Args[0], "-C", dir}, extraArgs...)
	args = append(args, "tui")
	proc, err := os.StartProcess(os.Args[0], args, &os.ProcAttr{
		Env:   append(os.Environ(), "SPO_PTY_CHILD=1", "TERM=xterm-256color"),
		Files: []*os.File{slave, slave, slave},
		Sys:   &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	})
	if err != nil {
		t.Skipf("no pseudo-terminal in this environment: cannot start a session on it: %v", err)
	}
	p.proc = proc
	t.Cleanup(func() { proc.Kill() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				p.mu.Lock()
				p.raw.Write(buf[:n])
				p.scr.Write(buf[:n])
				if f := p.scr.String(); (len(p.frames) == 0 || p.frames[len(p.frames)-1] != f) && p.frameLen < maxFrameBytes {
					p.frames = append(p.frames, f)
					p.frameLen += len(f)
				}
				p.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		st, _ := proc.Wait()
		p.mu.Lock()
		p.st = st
		p.mu.Unlock()
		close(p.exit)
	}()
	return p
}

var (
	csiRE = regexp.MustCompile(`\x1b\[[0-9;?<>=:]*[ -/]*[@-~]`)
	oscRE = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	escRE = regexp.MustCompile(`\x1b[()#]?[@-~0-9]`)
)

// text is what the terminal received, with control sequences removed.
func stripCtl(b []byte) string {
	s := oscRE.ReplaceAllString(string(b), "")
	s = csiRE.ReplaceAllString(s, "")
	s = escRE.ReplaceAllString(s, "")
	return strings.ReplaceAll(s, "\r", "")
}

func (p *ptyTUI) bytes() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.raw.Bytes()...)
}

// send types bytes into the terminal, like keys.
func (p *ptyTUI) send(s string) {
	p.t.Helper()
	if _, err := p.master.Write([]byte(s)); err != nil {
		p.t.Fatalf("writing keys: %v", err)
	}
	if s == keyEsc {
		// A lone Esc is told from the start of a sequence by a pause, as for
		// a person at a keyboard.
		time.Sleep(200 * time.Millisecond)
	}
}

// typeSlowly sends text one rune at a time, as typing is.
func (p *ptyTUI) typeText(s string) {
	for _, r := range s {
		if _, err := p.master.Write([]byte(string(r))); err != nil {
			p.t.Fatalf("typing: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// screen is what the terminal shows now.
func (p *ptyTUI) screen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.scr.String()
}

// wait blocks until the text is on the screen. The screen is rebuilt from the
// bytes the program wrote (see vt), so a renderer that redraws only what
// changed is read as a person would see it.
func (p *ptyTUI) wait(what string) {
	p.t.Helper()
	deadline := time.Now().Add(ptyWait)
	for time.Now().Before(deadline) {
		if strings.Contains(p.screen(), what) {
			return
		}
		select {
		case <-p.exit:
			if strings.Contains(p.screen(), what) {
				return
			}
			p.t.Fatalf("spo exited while waiting for %q; the screen was:\n%s", what, p.screen())
		case <-time.After(20 * time.Millisecond):
		}
	}
	p.t.Fatalf("timed out waiting for %q; the screen is:\n%s", what, p.screen())
}

func (p *ptyTUI) resize(r, c uint16) {
	p.t.Helper()
	p.mu.Lock()
	p.scr.resize(int(r), int(c))
	p.mu.Unlock()
	if err := unix.IoctlSetWinsize(int(p.master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: r, Col: c}); err != nil {
		p.t.Fatal(err)
	}
}

// exited waits for the process to end and returns its status.
func (p *ptyTUI) exited() *os.ProcessState {
	p.t.Helper()
	select {
	case <-p.exit:
	case <-time.After(ptyWait):
		p.t.Fatalf("spo did not exit; the screen is:\n%s", p.screen())
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.st
}

// checkRestored asserts that the terminal was given back: the alternate
// screen was entered and left, and the cursor was shown again after the last
// time it could have been hidden.
func (p *ptyTUI) checkRestored() {
	p.t.Helper()
	b := string(p.bytes())
	on, off := strings.LastIndex(b, altOn), strings.LastIndex(b, altOff)
	if on < 0 {
		p.t.Error("the TUI never entered the alternate screen")
	}
	if off < on {
		p.t.Error("the alternate screen was not left on exit: the terminal's scrollback would hold the screen")
	}
	if hide := strings.LastIndex(b, "\x1b[?25l"); hide >= 0 && strings.LastIndex(b, cursorShow) < hide {
		p.t.Error("the cursor was hidden and not shown again")
	}
}

// leaked lists the strings that reached the terminal in any form (echo, a
// redraw, the scrollback), in the raw bytes or with control sequences removed.
func (p *ptyTUI) leaked(secrets ...string) []string {
	p.t.Helper()
	raw := string(p.bytes())
	plain := stripCtl(p.bytes())
	p.mu.Lock()
	frames := strings.Join(p.frames, "\n")
	p.mu.Unlock()
	var out []string
	for _, s := range secrets {
		if strings.Contains(raw, s) || strings.Contains(plain, s) || strings.Contains(frames, s) {
			out = append(out, s)
		}
	}
	return out
}

// noSecretAnywhere asserts that none of the strings reached the terminal in
// any form (echo, a redraw, the scrollback).
func (p *ptyTUI) noSecretAnywhere(secrets ...string) {
	p.t.Helper()
	for _, s := range p.leaked(secrets...) {
		p.t.Errorf("the secret %q reached the terminal", s)
	}
}

func ptyWorkspace(t *testing.T) (dir, addr string) {
	t.Helper()
	dir = copyWorkspace(t)
	_, addr = importWallet(t, dir)
	writeTransferFile(t, filepath.Join(dir, "offlineTransfer.json"), addr)
	return dir, addr
}

// Open the TUI, find a command by search, complete a wallet name (listing the
// names asks the passphrase once, in a hidden modal), pick a file, run the
// command (it asks the passphrase again), read its output, leave and quit.
func TestPTYFormNamesFilePickerRunAndQuit(t *testing.T) {
	dir, addr := ptyWorkspace(t)
	p := startTUI(t, dir, rows, cols)
	p.wait("up/down move")

	p.send("/")
	p.typeText("address")
	p.wait("address")
	p.send(keyEnter)
	p.wait("name|address")

	// The workspace is sealed: names stay locked until asked for.
	p.wait("ctrl+n asks the passphrase once")
	p.send(keyCtrlN)
	p.wait("Passphrase (used once, to list names")
	p.typeText(testPass)
	p.send(keyEnter)
	p.wait("tab completes: " + walletName)
	p.typeText("wall")
	p.send(keyTab)
	p.wait("$ spo address -- " + walletName)

	// The transfer file is the last field: shift-tab to Run, then up.
	p.send("\x1b[Z")
	p.send(keyUp)
	p.send(keyCtrlO)
	p.wait("choose or name a file")
	p.wait("offlineTransfer.json")
	p.send(keyDown)
	p.send(keyEnter)
	p.wait("--transfer-file=" + filepath.Join(dir, "offlineTransfer.json"))

	p.send(keyCtrlR)
	p.wait("Passphrase:")
	p.typeText(testPass)
	p.send(keyEnter)
	p.wait(addr)
	p.wait("done")

	p.send(keyEsc) // back to the menu, still searching
	p.send(keyEsc) // end the search
	p.send("q")
	if st := p.exited(); !st.Success() {
		t.Fatalf("spo tui exited with %v", st)
	}
	p.checkRestored()
	p.noSecretAnywhere(testPass, "battery staple")
}

// A terminal below the minimum gets a notice, not a broken screen; growing it
// brings the menu back.
func TestPTYTerminalNarrowerThanTheMinimum(t *testing.T) {
	dir, _ := ptyWorkspace(t)
	p := startTUI(t, dir, 24, 30)
	p.wait("40x10")
	p.resize(rows, cols)
	p.wait("up/down move")
	p.resize(24, 20)
	p.wait("40x10")
	p.send(keyCtrlC)
	if st := p.exited(); !st.Success() {
		t.Fatalf("exit %v", st)
	}
	p.checkRestored()
}

// Resize while a passphrase modal is open: the prompt survives, what was typed
// is neither drawn nor lost, and Esc cancels.
func TestPTYResizeDuringAPassphrasePrompt(t *testing.T) {
	dir, _ := ptyWorkspace(t)
	p := startTUI(t, dir, rows, cols)
	p.wait("commands")
	p.send("/")
	p.typeText("store slots")
	p.send(keyEnter)
	p.wait("spo store slots")
	p.send(keyCtrlR)
	p.wait("Passphrase:")
	p.typeText(markerSecre)
	p.resize(12, 50)
	p.wait("Passphrase:")
	p.resize(8, 30) // below the minimum, with the modal open
	p.wait("40x10")
	p.resize(rows, cols)
	p.wait("Passphrase:")
	p.send(keyEsc) // cancel the command
	p.wait("cancelled")
	p.send("q")
	if st := p.exited(); !st.Success() {
		t.Fatalf("exit %v", st)
	}
	p.checkRestored()
	p.noSecretAnywhere(markerSecre)
}

// Ctrl-C at a prompt cancels the command and leaves no secret on the screen; a
// second Ctrl-C quits and the terminal is given back.
func TestPTYCtrlCAtAPromptLeavesNoSecretAndRestoresTheTerminal(t *testing.T) {
	dir, _ := ptyWorkspace(t)
	before, _ := os.ReadFile(filepath.Join(dir, "workspace.spo"))
	p := startTUI(t, dir, rows, cols)
	p.wait("commands")
	p.send("/")
	p.typeText("store slots")
	p.send(keyEnter)
	p.wait("spo store slots")
	p.send(keyCtrlR)
	p.wait("Passphrase:")
	p.typeText(markerSecre)
	p.send(keyCtrlC)
	p.wait("cancelled")
	p.send(keyCtrlC)
	st := p.exited()
	if !st.Success() {
		t.Fatalf("exit %v", st)
	}
	p.checkRestored()
	p.noSecretAnywhere(markerSecre)
	// The bytes between leaving the alternate screen and exit are what stays
	// in the scrollback: nothing of the form or the prompt.
	b := string(p.bytes())
	tail := b[strings.LastIndex(b, altOff)+len(altOff):]
	if strings.Contains(stripCtl([]byte(tail)), "Passphrase") {
		t.Errorf("the prompt is in what follows the alternate screen: %q", tail)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "workspace.spo"))
	if !bytes.Equal(before, after) {
		t.Error("a cancelled command changed the workspace file")
	}
}

// Typing a passphrase into the TUI: the terminal never echoes it (the tty is
// in raw mode with echo off) and the screen shows bullets only.
func TestPTYPassphraseIsNeverEchoed(t *testing.T) {
	dir, _ := ptyWorkspace(t)
	p := startTUI(t, dir, rows, cols)
	p.wait("commands")
	p.send("/")
	p.typeText("store slots")
	p.send(keyEnter)
	p.wait("spo store slots")
	p.send(keyCtrlR)
	p.wait("Passphrase:")
	p.typeText(testPass)
	p.wait("•")
	p.send(keyEnter)
	p.wait("done")
	p.send("q")
	if st := p.exited(); !st.Success() {
		t.Fatalf("exit %v", st)
	}
	p.noSecretAnywhere(testPass, "battery staple")
}

// Positive control for the secret-leak tests above: a deliberately echoing path
// (text typed into the command filter is drawn, as a plain field would be) makes
// the detector fire, so those tests cannot pass because the detector sees
// nothing. The masked passphrase path, in contrast, leaves it silent.
func TestPTYLeakDetectorFiresOnADeliberatelyEchoingPath(t *testing.T) {
	dir, _ := ptyWorkspace(t)
	p := startTUI(t, dir, rows, cols)
	p.wait("commands")
	if l := p.leaked(markerSecre); len(l) != 0 {
		t.Fatalf("the marker was on the terminal before it was typed anywhere: %v", l)
	}
	p.send("/")
	p.typeText(markerSecre) // the filter shows what is typed
	p.wait(markerSecre)
	if l := p.leaked(markerSecre); len(l) != 1 || l[0] != markerSecre {
		t.Fatalf("the detector did not fire on a visibly echoed string: %v", l)
	}
	// The same marker typed at a masked prompt is not echoed: the detector is not
	// simply always firing.
	p.send(keyEsc)
	p.send("q")
	p.exited()
	q := startTUI(t, dir, rows, cols)
	q.wait("commands")
	q.send("/")
	q.typeText("store slots")
	q.send(keyEnter)
	q.wait("spo store slots")
	q.send(keyCtrlR)
	q.wait("Passphrase:")
	q.typeText(markerSecre)
	q.wait("•")
	if l := q.leaked(markerSecre); len(l) != 0 {
		t.Errorf("a masked prompt echoed: %v", l)
	}
	q.send(keyCtrlC)
	q.wait("cancelled")
	q.send(keyCtrlC)
	q.exited()
}
