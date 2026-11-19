package hwcli

import (
	"context"
	"fmt"
	"sync"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Lazy is the hardware signer a command wires: it opens the session the first
// time anything needs the device (at plan time, for its Profile) and keeps it
// for the rest of the command. A software-only run never opens it. If opening
// fails, Profile offers nothing and names the cause, so the plan refuses with
// the reason (no device, tool too old, ...); Err gives the typed error.
type Lazy struct {
	ctx  context.Context
	cfg  Config
	once sync.Once
	s    *Session
	err  error
}

// NewLazy returns a Lazy over a configuration. ctx is the command's context,
// used where a method has none (Profile).
func NewLazy(ctx context.Context, cfg Config) *Lazy { return &Lazy{ctx: ctx, cfg: cfg} }

// Session opens the session once and returns it, or the error that stopped it.
func (l *Lazy) Session(ctx context.Context) (*Session, error) {
	l.once.Do(func() {
		if ctx == nil {
			ctx = l.ctx
		}
		l.s, l.err = Open(ctx, l.cfg)
	})
	return l.s, l.err
}

// Err is the error of opening the session, nil before it is tried and after it worked.
func (l *Lazy) Err() error { return l.err }

// Profile implements ports.Signer. It opens the session.
func (l *Lazy) Profile() custody.Profile {
	s, err := l.Session(l.ctx)
	if err != nil {
		return custody.NewProfile(fmt.Sprintf("hardware wallet unavailable (%v)", err))
	}
	return s.Profile()
}

func (l *Lazy) ExportHardwareKey(ctx context.Context, key custody.KeyRef, path string) (ports.HardwareKey, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return ports.HardwareKey{}, err
	}
	return s.ExportHardwareKey(ctx, key, path)
}

func (l *Lazy) IssueOpCert(ctx context.Context, cold custody.Key[custody.PoolCold], req ports.OpCertRequest) ([]byte, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return nil, err
	}
	return s.IssueOpCert(ctx, cold, req)
}

func (l *Lazy) Witness(ctx context.Context, key custody.KeyRef, body txbuild.TxBody) (txbuild.Witness, error) {
	return l.WitnessWith(ctx, key, body, ports.HardwareTxOptions{})
}

func (l *Lazy) WitnessWith(ctx context.Context, key custody.KeyRef, body txbuild.TxBody, opt ports.HardwareTxOptions) (txbuild.Witness, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return txbuild.Witness{}, err
	}
	return s.WitnessWith(ctx, key, body, opt)
}

func (l *Lazy) Canonicalize(ctx context.Context, body txbuild.TxBody, opt ports.HardwareTxOptions) (txbuild.TxBody, bool, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return txbuild.TxBody{}, false, err
	}
	return s.Canonicalize(ctx, body, opt)
}

// SignMessage refuses a reserved payload (`spo-`, `spo/`) before the session is
// opened, so the device is not even looked for (SPO-Xrelaybind-SEC-016).
func (l *Lazy) SignMessage(ctx context.Context, req ports.MessageRequest) (ports.SignedMessage, error) {
	if relaybind.IsReserved(req.Payload) {
		return ports.SignedMessage{}, relaybind.ErrReservedPayload
	}
	s, err := l.Session(ctx)
	if err != nil {
		return ports.SignedMessage{}, err
	}
	return s.SignMessage(ctx, req)
}

func (l *Lazy) SignCip36(ctx context.Context, key custody.Key[custody.Stake], reg cose.Cip36) (ports.Registration, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return ports.Registration{}, err
	}
	return s.SignCip36(ctx, key, reg)
}

func (l *Lazy) SignCip36With(ctx context.Context, key custody.Key[custody.Stake], reg cose.Cip36, opt ports.Cip36HardwareOptions) (ports.Registration, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return ports.Registration{}, err
	}
	return s.SignCip36With(ctx, key, reg, opt)
}

func (l *Lazy) SignCip88(ctx context.Context, key custody.Key[custody.PoolCold], reg cose.Cip88) (ports.Registration, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return ports.Registration{}, err
	}
	return s.SignCip88(ctx, key, reg)
}

func (l *Lazy) WitnessMany(ctx context.Context, keys []custody.KeyRef, body txbuild.TxBody, opt ports.HardwareTxOptions) ([]txbuild.Witness, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return nil, err
	}
	return s.WitnessMany(ctx, keys, body, opt)
}

func (l *Lazy) PolicyID(ctx context.Context, key custody.Key[custody.Policy], script []byte) (string, error) {
	s, err := l.Session(ctx)
	if err != nil {
		return "", err
	}
	return s.PolicyID(ctx, key, script)
}

var (
	_ ports.Signer                 = (*Lazy)(nil)
	_ ports.HardwareKeyExporter    = (*Lazy)(nil)
	_ ports.OpCertIssuer           = (*Lazy)(nil)
	_ ports.HardwareWitnesser      = (*Lazy)(nil)
	_ ports.HardwareCanonicalizer  = (*Lazy)(nil)
	_ ports.HardwarePolicyIDer     = (*Lazy)(nil)
	_ ports.MessageSigner          = (*Lazy)(nil)
	_ ports.Cip36Signer            = (*Lazy)(nil)
	_ ports.HardwareCip36Signer    = (*Lazy)(nil)
	_ ports.Cip88Signer            = (*Lazy)(nil)
	_ ports.HardwareMultiWitnesser = (*Lazy)(nil)
)
