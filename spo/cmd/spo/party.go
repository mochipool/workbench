package main

import (
	"context"
	"errors"

	"tailscale.com/tailcfg"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// derpRegion is a self-hosted relay region for the tailcat server. It is nil in
// the program, where tailcat finds its relay from the DERP map URL ([tailcat]
// derp_map_url, else tailcat's default); a test sets it to an in-process relay.
var derpRegion *tailcfg.DERPRegion

// bagAdapter is a filebag.Bag as the command tree's FileBag.
type bagAdapter struct{ *filebag.Bag }

func (b bagAdapter) Rejected() []cli.BagRejection {
	var out []cli.BagRejection
	for _, r := range b.Bag.Rejected() {
		out = append(out, cli.BagRejection{Name: r.Name, Reason: r.Reason})
	}
	return out
}

func openBag(open func(string) (*filebag.Bag, error)) func(string) (cli.FileBag, error) {
	return func(dir string) (cli.FileBag, error) {
		b, err := open(dir)
		if err != nil {
			return nil, err
		}
		return bagAdapter{b}, nil
	}
}

// partyAddresses is the address inspector of the party stack: the ledger's,
// always (ADR 0005, obligation 1). It is not read from the environment.
func partyAddresses() ports.AddressInspector { return native.Ledger{} }

// relayOps is the relay-identity stack (ADR 0014 work package 8): the vault's
// relay statement signer (the only implementation of
// ports.RelayStatementSigner) inside relaybinding, and the device-signed revoke
// through the typed method of the local identity. No relay is wired yet (work
// packages 9 and 10), so revokes are stored and not sent.
func relayOps(vault ports.Vault) cli.RelayOps {
	var signer ports.RelayStatementSigner = native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: vault}}
	return cli.RelayOps{
		Signing: func(clock ports.Clock, history func(context.Context, identity.Ref) (custody.RoleHistory, bool, error)) relaybinding.Service {
			return relaybinding.Service{Signer: signer, Clock: clock, History: history}
		},
		SignDeviceRevoke: func(ctx context.Context, svc relaybinding.Service, local ports.LocalIdentity, nb int64) (relaybinding.DeviceRevokeResult, error) {
			dev, ok := local.(relayport.DeviceRevokeSigner)
			if !ok {
				return relaybinding.DeviceRevokeResult{}, errors.New("the local identity cannot sign a device revoke")
			}
			return svc.SignDeviceRevoke(ctx, dev, nb)
		},
	}
}

// wireParty gives the Env the multi-party stack over the workspace's store
// (nil in the probe that only inspects what a command needs).
func wireParty(env *cli.Env, store ports.Store) {
	var named ports.NamedStore
	var vault ports.NamedVault
	if store != nil {
		ns := labels.Named(store)
		named = ns
		if _, ok := store.(ports.Vault); ok {
			vault = ns
		}
	}
	reg := partystore.Registry{}
	var keys ports.Vault
	if store != nil {
		keys, _ = store.(ports.Vault)
	}
	env.Party = &cli.PartyKit{
		Kit:            envelope.Kit{Store: named, Vault: vault},
		Registry:       reg,
		SetScope:       reg.SetScope,
		SetRelay:       reg.SetRelay,
		Relay:          relayOps(keys),
		Replay:         partystore.Replay{},
		Addresses:      partyAddresses(),
		CheckAncestors: filebag.CheckAncestors,
		OpenInbox:      openBag(filebag.Open),
		OpenOutput:     openBag(filebag.OpenOutput),
		Tailcat: cli.TailcatOps{
			NewNodeKey: tailcat.NewKey,
			NodePublic: tailcat.PublicKey,
			NewServer: func(c cli.TailcatServerConfig) (cli.TailcatServer, error) {
				s, err := tailcat.NewServer(tailcat.ServerConfig{NodeKey: c.NodeKey, PSK: c.PSK, Allowed: c.Allowed, Admit: c.Admit,
					Port: c.Port, Region: derpRegion, DERPMapURL: c.DERPMapURL})
				if err != nil {
					return nil, err
				}
				return s, nil
			},
			NewClient: func(c cli.TailcatClientConfig) (cli.TailcatClient, error) {
				key := c.ExpectServerKey
				cl, err := tailcat.NewClient(tailcat.ClientConfig{Address: c.Address, NodeKey: c.NodeKey, Coordinator: c.Coordinator, Hello: c.Hello,
					ExpectServerKey: &key, Port: c.Port, DERPMapURL: c.DERPMapURL})
				if err != nil {
					return nil, err
				}
				return cl, nil
			},
		},
	}
	// An offline snapshot is read from the path the operator names with
	// --own-snapshot, after the command tree has judged the path.
	env.SnapshotResolver = func(path string) ports.UtxoResolver { return &transferfile.File{Path: path} }
}
