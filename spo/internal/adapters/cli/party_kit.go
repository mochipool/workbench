package cli

import (
	"context"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// PartyKit is the multi-party stack as the composition root builds it
// (spec/extensions/Xparty.md, ADR 0005): the envelope kit, the registry, the
// replay log, the file transport and the tailcat transport. This package
// imports none of the adapters; cmd/spo supplies them.
type PartyKit struct {
	Kit      ports.IdentityKit
	Registry ports.PartyRegistry
	// SetScope changes the scope recorded for a party inside the Update the
	// caller runs (partystore.Registry.SetScope).
	SetScope func(w ports.NamedWriter, name string, scope party.Scope) (party.Party, error)
	Replay   ports.ReplayLog
	// Addresses is the ledger's address inspector, always: a signer's
	// classification of inputs and outputs by credential depends on it. It is
	// NOT taken from Env.AddressInspector, so a build that leaves the
	// environment's inspector out cannot turn the signer's off. Nil makes
	// every signer command refuse with a configuration error (ADR 0005,
	// obligation 1).
	Addresses ports.AddressInspector

	// OpenInbox opens the file transport on an INBOX directory: the adapter
	// refuses a directory that is a link, not owned by the operator or
	// writable by anyone else (obligation 5). OpenOutput opens a directory
	// that is only written to (an export target).
	OpenInbox  func(dir string) (FileBag, error)
	OpenOutput func(dir string) (FileBag, error)

	// CheckAncestors refuses a path with a directory above it that others can
	// replace (filebag.CheckAncestors): the same rule as for an inbox, applied
	// to an --own-snapshot file. Nil refuses every snapshot.
	CheckAncestors func(path string) error

	Tailcat TailcatOps
}

// BagRejection is a file the file transport refused to deliver.
type BagRejection struct{ Name, Reason string }

// FileBag is the file transport on one directory.
type FileBag interface {
	ports.EnvelopeAcker
	// Transport is the bag as the sending side of multisig; its kind is a file.
	Transport() ports.Transport
	Write(name string, envelope []byte) error
	// SetNamer gives the files of Send the spec's names.
	SetNamer(func(envelope []byte) string)
	SetPoll(time.Duration)
	Rejected() []BagRejection
	Close() error
}

// TailcatOps builds the tailcat transport.
type TailcatOps struct {
	NewNodeKey func() (*secret.Buffer, error)
	NodePublic func(*secret.Buffer) (party.NodeKey, error)
	NewServer  func(TailcatServerConfig) (TailcatServer, error)
	NewClient  func(TailcatClientConfig) (TailcatClient, error)
}

// TailcatServerConfig is what a coordinator's server needs. The server takes
// ownership of the key buffers.
type TailcatServerConfig struct {
	NodeKey, PSK *secret.Buffer
	Allowed      []party.NodeKey
	Admit        func(envelope []byte, peer party.NodeKey) (party.Fingerprint, error)
	Port         uint16
	DERPMapURL   string
}

// TailcatServer is the coordinator side (tailcat.Server).
type TailcatServer interface {
	ports.EnvelopeSender
	ports.EnvelopeReceiver
	Transport() ports.Transport
	Start(ctx context.Context) error
	Address() (*secret.Buffer, error)
	Keys() (nodeKey, psk *secret.Buffer)
	Allow(party.NodeKey)
	Revoke(party.NodeKey)
	Peers() []party.Fingerprint
	Close() error
}

// TailcatClientConfig is what a signer's client needs. The client takes
// ownership of the buffers.
type TailcatClientConfig struct {
	Address         *secret.Buffer
	NodeKey         *secret.Buffer
	Coordinator     party.Fingerprint
	Hello           func(ctx context.Context) ([]byte, error)
	ExpectServerKey party.NodeKey
	Port            uint16
	DERPMapURL      string
}

// TailcatClient is the signer side (tailcat.Client).
type TailcatClient interface {
	ports.EnvelopeReceiver
	Transport() ports.Transport
	Connect(ctx context.Context) error
	Disconnect()
	Close() error
}

// liveServers are the tailcat servers running in this process, so that
// revoking a party (here, or from a screen of the same process) closes its
// live connections and stops serving its node key at once. A server started in
// another process notices the change when it next reads the registry.
var live struct {
	mu sync.Mutex
	s  map[TailcatServer]struct{}
}

func registerLive(s TailcatServer) (unregister func()) {
	live.mu.Lock()
	if live.s == nil {
		live.s = map[TailcatServer]struct{}{}
	}
	live.s[s] = struct{}{}
	live.mu.Unlock()
	return func() { live.mu.Lock(); delete(live.s, s); live.mu.Unlock() }
}

// revokeLive stops serving a party's node key on every server of this process
// (tailcat.Server.Revoke).
func revokeLive(p party.Party) {
	if p.Identity.Node == nil {
		return
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	for s := range live.s {
		s.Revoke(*p.Identity.Node)
	}
}

// allowLive adds an enrolled node key to every server of this process.
func allowLive(p party.Party) {
	if p.Identity.Node == nil || !p.Active() || !(p.HasRole(party.RoleSigner) || p.HasRole(party.RoleMachine)) {
		return
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	for s := range live.s {
		s.Allow(*p.Identity.Node)
	}
}
