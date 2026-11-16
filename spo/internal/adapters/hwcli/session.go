// Package hwcli is the hardware-wallet signer: one adapter over the pinned
// cardano-hw-cli (a Node tool; concern X6) with its own capability profile.
// No use case knows it exists: a use case asks the signer directory for the
// signer of a key, and for a key held on a device it gets this one (ADR 0008).
//
// The tool prompts on the device, not on a terminal, and writes progress on
// stderr. Every call here is an argument vector run through execx with an
// explicit environment; its non-secret files (body, signing-file copies,
// outputs) live in a private 0700 directory that is removed afterwards
// (concern X2). A signing file holds no private key but identifies the
// account, so it is read from the store and never from an operator path.
package hwcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/version"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Default minimum app and firmware versions (spec: SPO-Chw-IN-002).
const (
	DefaultMinLedger   = "8.0.8"
	DefaultMinTrezor   = "2.7.2"
	DefaultMinKeystone = "1.7.7"
)

// Network says which network a transaction or registration is for. Exactly one
// field is set: `--mainnet`, or `--testnet-magic <n>`.
type Network struct {
	Mainnet bool
	Magic   uint32
}

func (n Network) args() ([]string, error) {
	switch {
	case n.Mainnet && n.Magic == 0:
		return []string{"--mainnet"}, nil
	case !n.Mainnet && n.Magic != 0:
		return []string{"--testnet-magic", fmt.Sprint(n.Magic)}, nil
	}
	return nil, ErrBadNetwork
}

// Wait is what the wait-for-device hook is told after an attempt that got no
// device (SPO-Chw-PR-001): show it to the operator, with the instruction to
// connect and unlock the device and open the Cardano app.
type Wait struct {
	Attempt   int
	Elapsed   time.Duration
	Remaining time.Duration
	// Message is the first 64 characters of the tool's answer, with `General
	// error` replaced by "Cardano App not opened?".
	Message string
}

// SigningFiles reads the hardware signing file of a key from the store.
type SigningFiles interface {
	HardwareSigningFile(ctx context.Context, key custody.KeyRef) ([]byte, error)
}

// Config configures a session. Only Toolchain, Runner and Network are
// required; the rest has the defaults of the spec.
type Config struct {
	Toolchain ports.Toolchain
	Runner    execx.Runner
	Files     SigningFiles // needed to witness, issue and sign; not to export keys
	// TxID computes a transaction's id from its CBOR (native.Ledger.TransactionID).
	// It is needed to canonicalise a body; a witness checks the body's id with it
	// when it is set.
	TxID func(cbor []byte) (chain.TxID, error)
	// PolicyID computes a native script's policy id (native.Ledger.PolicyID).
	// When it is set, the id the device prints is checked against it.
	PolicyID func(scriptJSON []byte) ([28]byte, error)
	Network  Network

	// Timeout bounds the wait for the device (default 60s); Poll is the pause
	// between attempts (default 6s, as upstream); Attempt bounds one `device
	// version` call (default 20s). OnWait is told after each failed attempt.
	Timeout time.Duration
	Poll    time.Duration
	Attempt time.Duration
	OnWait  func(Wait)
	// OnWarning receives the tool's WARNING output, which does not stop signing
	// (SPO-Ptx-PRE-005).
	OnWarning func(string)

	// Minimum app or firmware versions; empty selects the default
	// (SPO-Chw-IF-001, SPO-Chw-IN-002). The Ledger minimum is also what
	// ENV_MINLEDGERCARDANOAPPVERSION overrides upstream; 09a lowers it to 6.0.3.
	MinLedger, MinTrezor, MinKeystone string

	// TempRoot is where the private working directories go (default os.TempDir()).
	TempRoot string
	// Env is the complete environment of the tool. Nil selects PATH, HOME, LANG,
	// LC_ALL and XDG_RUNTIME_DIR from this process; nothing else is inherited.
	Env []string
}

func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.Poll <= 0 {
		c.Poll = 6 * time.Second
	}
	if c.Attempt <= 0 {
		c.Attempt = 20 * time.Second
	}
	if c.MinLedger == "" {
		c.MinLedger = DefaultMinLedger
	}
	if c.MinTrezor == "" {
		c.MinTrezor = DefaultMinTrezor
	}
	if c.MinKeystone == "" {
		c.MinKeystone = DefaultMinKeystone
	}
	if c.Env == nil {
		for _, k := range []string{"PATH", "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR"} {
			if v, ok := os.LookupEnv(k); ok {
				c.Env = append(c.Env, k+"="+v)
			}
		}
		if c.Env == nil {
			c.Env = []string{}
		}
	}
	return c
}

// Session is an open hardware wallet: a located tool and a device that answered
// and passed the version gates. It is a signer (ports.Signer) with the profile
// of that vendor and version, and it implements the capabilities of the profile.
type Session struct {
	cfg     Config
	tool    ports.Tool
	Vendor  custody.Vendor
	Version string // the device's app or firmware version
	profile custody.Profile

	// canonical remembers the bodies `transaction transform` left unchanged
	// (by hash of their bytes, and whether unrestricted mode was on), so a
	// body witnessed by several keys is checked once per session.
	mu        sync.Mutex
	canonical map[canonKey]bool
}

type canonKey struct {
	hash         [32]byte
	unrestricted bool
}

// Open starts a session: locate the tool (version gate in the toolchain), wait
// for a device, identify it, and apply the vendor's minimum version.
//
// spec: SPO-Chw-PRE-001, SPO-Chw-PRE-002, SPO-Chw-EXT-001, SPO-Chw-EXT-002, SPO-Chw-EXT-003, SPO-Chw-PR-001, SPO-Chw-IN-001, SPO-Chw-IN-002, SPO-Chw-PRE-004, SPO-Chw-PRE-005, SPO-Chw-INV-001, SPO-Chw-INV-002, SPO-Chw-OUT-001
func Open(ctx context.Context, cfg Config) (*Session, error) {
	cfg = cfg.withDefaults()
	if cfg.Toolchain == nil || cfg.Runner == nil {
		return nil, fmt.Errorf("%w: no toolchain or runner configured", ports.ErrNoHardwareSigner)
	}
	if _, err := cfg.Network.args(); err != nil {
		return nil, err
	}
	tool, err := cfg.Toolchain.Tool(ctx, ports.CardanoHWCLI)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrToolUnavailable, err)
	}
	s := &Session{cfg: cfg, tool: tool}
	text, err := s.waitForDevice(ctx)
	if err != nil {
		return nil, err
	}
	vendor, ver, err := parseDeviceVersion(text)
	if err != nil {
		return nil, err
	}
	var min string
	switch vendor {
	case custody.VendorLedger:
		min = cfg.MinLedger
	case custody.VendorTrezor:
		min = cfg.MinTrezor
	case custody.VendorKeystone:
		min = cfg.MinKeystone
	}
	if !version.AtLeast(ver, min) {
		return nil, fmt.Errorf("%w: %s app or firmware %s is older than the minimum %s", ErrDeviceTooOld, vendor, ver, min)
	}
	s.Vendor, s.Version = vendor, ver
	s.profile = custody.HardwareProfile(vendor, ver, version.AtLeast)
	return s, nil
}

// Profile implements ports.Signer.
func (s *Session) Profile() custody.Profile { return s.profile }

// Tool returns the located cardano-hw-cli.
func (s *Session) Tool() ports.Tool { return s.tool }

func (s *Session) waitForDevice(ctx context.Context) (string, error) {
	start := time.Now()
	deadline := start.Add(s.cfg.Timeout)
	var last string
	for attempt := 1; ; attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", fmt.Errorf("%w (waited %s; last answer: %q)", ErrNoDevice, s.cfg.Timeout.Round(time.Millisecond), clip(last, 200))
		}
		per := s.cfg.Attempt
		if remaining < per {
			per = remaining
		}
		actx, cancel := context.WithTimeout(ctx, per)
		res, err := s.cfg.Runner.Run(actx, execx.Cmd{Path: s.tool.Path, Args: execx.Lits("device", "version"), Env: s.cfg.Env})
		timedOut := actx.Err() != nil
		cancel()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		var ee *execx.ExitError
		if err != nil && !errors.As(err, &ee) && !timedOut {
			return "", fmt.Errorf("%w: %v", ErrToolUnavailable, err)
		}
		if ee != nil {
			res = ee.Result
		}
		text := mergeOutput(res)
		if strings.Contains(text, "app version") && !strings.Contains(text, "undefined") {
			return text, nil
		}
		last = text
		if s.cfg.OnWait != nil {
			s.cfg.OnWait(Wait{Attempt: attempt, Elapsed: time.Since(start), Remaining: time.Until(deadline), Message: waitMessage(text)})
		}
		pause := s.cfg.Poll
		if r := time.Until(deadline); r < pause {
			pause = r
		}
		if pause > 0 {
			t := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				t.Stop()
				return "", ctx.Err()
			case <-t.C:
			}
		}
	}
}

func waitMessage(text string) string {
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, "General error", "Cardano App not opened?")
	text = strings.ReplaceAll(text, "\n", " ")
	return clip(text, 64)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

var versionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*`)

// parseDeviceVersion reads the answer of `device version`: the first line holds
// the vendor as its first word and the app or firmware version as its fourth
// (`<vendor> app version <x>`, SPO-Chw-EXT-003). A line that has no such fourth
// word, or whose fourth word is not a version, fails: an unreadable version must
// not pass (the fix of the upstream quirk of SPO-Chw-INV-001).
func parseDeviceVersion(text string) (custody.Vendor, string, error) {
	line := ""
	for i, l := range strings.Split(text, "\n") {
		if i == 0 {
			line = l
		}
		if strings.Contains(l, "app version") && !strings.Contains(line, "app version") {
			line = l
		}
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", "", fmt.Errorf("%w: the answer is empty", ErrUnreadableVersion)
	}
	vendor, ok := custody.ParseVendor(f[0])
	if !ok {
		return "", "", fmt.Errorf("%w: %q (cardano-hw-cli supports Ledger, Trezor and Keystone)", ErrUnsupportedVendor, f[0])
	}
	if len(f) < 4 || !versionRE.MatchString(f[3]) {
		return "", "", fmt.Errorf("%w: %q", ErrUnreadableVersion, clip(line, 80))
	}
	return vendor, f[3], nil
}

func mergeOutput(r execx.Result) string {
	out, errOut := strings.TrimRight(string(r.Stdout), "\n"), strings.TrimRight(string(r.Stderr), "\n")
	switch {
	case out == "":
		return errOut
	case errOut == "":
		return out
	}
	return out + "\n" + errOut
}
