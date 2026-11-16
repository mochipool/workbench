package main

import (
	"tailscale.com/tailcfg"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/ports"
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

// wireParty gives the Env the multi-party stack over the workspace's store
// (nil in the probe that only inspects what a command needs).
func wireParty(env *cli.Env, store ports.Store) {
	var vault ports.Vault
	if store != nil {
		vault, _ = store.(ports.Vault)
	}
	reg := partystore.Registry{}
	env.Party = &cli.PartyKit{
		Kit:            envelope.Kit{Store: store, Vault: vault},
		Registry:       reg,
		SetScope:       reg.SetScope,
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
