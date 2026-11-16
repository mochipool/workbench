package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/genesisfile"
	"github.com/mochipool/workbench/spo/internal/adapters/gpg"
	"github.com/mochipool/workbench/spo/internal/adapters/httpfetch"
	"github.com/mochipool/workbench/spo/internal/adapters/koios"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/offline"
	"github.com/mochipool/workbench/spo/internal/adapters/systemclock"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// chainCaps are the capabilities that depend on the mode.
var chainCaps = []cli.Cap{cli.CapTip, cli.CapSync, cli.CapOpCertCount, cli.CapParams, cli.CapUtxos, cli.CapRewards, cli.CapPools, cli.CapDReps, cli.CapCrossCheck, cli.CapSubmit, cli.CapQueue, cli.CapCalidusRead, cli.CapAdaHandle, cli.CapPollQuestion}

func init() { chainCaps = append(chainCaps, cli.GovernanceChainCaps...) }

// noCalidusReader is why `pool calidus status` is unavailable: no provider
// adapter reads CIP-88 registrations yet.
const noCalidusReader = "no chain provider reads the Calidus keys registered on chain (CIP-88) yet; the Koios adapter has no reader for them"

// signatureDirectory hands out the vault signer with the signature
// capabilities for a key held in the vault, and leaves every other holder to
// the directory of the build.
type signatureDirectory struct {
	vault ports.Vault
	other ports.SignerDirectory
}

// SignerFor implements ports.SignerDirectory.
func (d signatureDirectory) SignerFor(key custody.KeyRef) (ports.Signer, error) {
	if key.Holder == custody.HolderVault {
		return native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: d.vault}}, nil
	}
	return d.other.SignerFor(key)
}

// anchorLimit is the most bytes of an anchor document that is downloaded.
const anchorLimit = 1 << 20

// governanceReaders sets each governance chain reader that src implements
// (type assertions, so an adapter that gains a port is picked up without more
// wiring) and records why for those it does not.
func governanceReaders(env *cli.Env, src any, why string) {
	if r, ok := src.(ports.CommitteeStateReader); ok {
		env.Committee = r
	}
	if r, ok := src.(ports.GovActionReader); ok {
		env.GovActions = r
	}
	if r, ok := src.(ports.ConstitutionReader); ok {
		env.Constitution = r
	}
	if r, ok := src.(ports.LastEnactedReader); ok {
		env.LastEnacted = r
	}
	if r, ok := src.(ports.StakeDistributionReader); ok {
		env.StakeDists = r
	}
	if r, ok := src.(ports.EpochReader); ok {
		env.Epochs = r
	}
	if r, ok := src.(ports.VotingSummaryReader); ok {
		env.Summaries = r
	}
	for _, c := range cli.GovernanceChainCaps {
		if c == cli.CapDRepCross {
			continue // has its own reason, set in wire
		}
		env.Absent(c, why)
	}
}

// noDRepCross is why there is no second DRep-state source: no adapter pair
// gives two independent answers about a DRep today, so a read of the "harmful
// if false" class (the deposit a DRep refund rests on) rests on the one
// source, and the operator acknowledges that with --single-source (ADR 0006).
const noDRepCross = "there is no second independent DRep-state source besides the provider, so a DRep retirement is refused unless the command is given --single-source"

// wire builds the Env of a command: the local capabilities every mode has,
// then the chain capabilities the mode and provider can supply. What a mode
// cannot supply stays nil with the reason, so a command that needs it is
// refused when it starts. store may be nil: the signers then cannot release
// keys, which is enough to describe the environment. Nothing here touches
// the network.
func wire(store ports.Store, o cli.WireOptions) (*cli.Env, error) {
	return wireTo(os.Stderr, store, o)
}

// wireTo is wire with the writer the hardware wallet's progress lines go to.
func wireTo(errw io.Writer, store ports.Store, o cli.WireOptions) (*cli.Env, error) {
	env := &cli.Env{Mode: o.Mode, Endpoints: map[string]string{}}
	hw := wireHardware(env, store, o, errw)

	var vault ports.Vault
	if store != nil {
		v, ok := store.(ports.Vault)
		if !ok {
			env.Absent(cli.CapSigners, "the store cannot release signing keys to a signer")
		}
		vault = v
	}
	if store == nil || vault != nil {
		// The vault signer with the message, CIP-36 and CIP-88 capabilities
		// (ADR 0008): it also issues operational certificates and witnesses
		// transactions, so it replaces the plain vault signer.
		vs := native.VaultSignatures{VaultSigner: native.VaultSigner{Vault: vault}}
		for _, s := range []ports.Signer{vs} {
			if err := ports.CheckSigner(s); err != nil {
				return nil, err
			}
			if err := ports.CheckSignatureSigner(s); err != nil {
				return nil, err
			}
			env.SignerKinds = append(env.SignerKinds, s)
		}
		env.SignatureSigner = vs
		env.Signers = signatureDirectory{vault: vault, other: native.Signers{Vault: vault, Hardware: hw}}
	} else {
		env.Absent(cli.CapSignatures, "the store cannot release signing keys to a signer")
	}

	env.KesKeys, env.VrfKeys, env.BLSKeys = native.KeyGen{}, native.KeyGen{}, native.KeyGen{}
	soft := native.SoftwareKeys{}
	env.ColdKeys, env.PaymentKeys, env.StakeKeys = soft, soft, soft
	env.Mnemonics, env.WalletDeriver = soft, soft
	env.CalidusKeys, env.VotingKeys = soft, soft
	env.Absent(cli.CapCalidusRead, noCalidusReader)
	clock := systemclock.Clock{}
	env.Clock = clock
	led := native.Ledger{}
	env.AddressInspector, env.MinOutputCalculator, env.FeeEstimator = led, led, led
	env.TxBodyBuilder, env.TxAssembler = led, led
	env.Addresses = led
	env.Certs, env.CertDecoder = led, led
	env.PoolCerts, env.PoolCertDecoder, env.MetadataHasher, env.TxIDs = led, led, led, led
	// The transfer file exists in every mode as a bundle: `offline new`
	// creates it. One File value, so its lock is shared by every capability.
	tf := &transferfile.File{Path: o.TransferFile}
	env.Bundle = tf
	env.Sinks = func(dir string) (ports.FileSink, error) { return transferfile.DirSink{Dir: dir}, nil }
	env.TxViewer = native.TxViewer{}
	env.MetadataFiles, env.MsgEncrypter, env.PolicyIDs = fsstore.MetadataFiles{}, native.CIP83{}, led
	env.VKeyDeriver = native.VKeyDeriver{}
	wireKeyCrypto(env, o)
	env.DRepKeys, env.ComColdKeys, env.ComHotKeys, env.GovDeriver = soft, soft, soft, soft
	env.VoteFiles, env.ActionFiles = led, led
	env.NetworkID = ports.NetworkTestnet
	if o.Config.Network == "mainnet" {
		env.NetworkID = ports.NetworkMainnet
	}
	var genesis genesisfile.Shelley
	if o.Genesis.Shelley != "" {
		genesis = genesisfile.Shelley{Path: o.Genesis.Shelley}
		env.Genesis = genesis
	}

	none := func(why string) {
		for _, c := range chainCaps {
			env.Absent(c, why)
		}
	}
	switch o.Mode {
	case "":
		// No mode: every chain capability keeps the generic reason.
	case cli.ModeOffline:
		wireOffline(env, o, tf, clock, genesis)
	case cli.ModeLight:
		if o.Config.Koios == nil {
			none("no chain provider is configured: spo provider set koios")
			break
		}
		if err := wireLight(env, o); err != nil {
			return nil, err
		}
	case cli.ModeOnline:
		none("online mode needs a cardano-node socket adapter, which is not built yet; use mode light (Koios), or pass --offline")
	default:
		none(fmt.Sprintf("mode %q is not one of online, light, offline", o.Mode))
	}
	// The ticker-protection lookup is built in no mode: upstream posts the
	// ticker and the registration protection key to a hard-coded third-party
	// URL (hazard H6). A lookup will be opt-in and will never send the key.
	env.Absent(cli.CapDRepCross, noDRepCross)
	env.Absent(cli.CapAnchorFetch, "this mode downloads no anchor documents: give the anchor hash with the URL; it is recorded as given and the document is not checked")
	env.Absent(cli.CapAnchorVerify, "no CIP-100/108/119 verifier is built (it needs cardano-signer); a command that would verify an anchor document refuses unless given --anchor-unverified")
	env.Absent(cli.CapTickers, "ticker protection lookup is not built; it will be opt-in and will never send the protection key")
	env.Absent(cli.CapMetaFetch, "this mode does not download the published pool metadata: the hash of poolMetaUrl is compared when the registration runs where it can")
	env.Absent(cli.CapAttach, "this mode queues no transaction, so there is no transfer file to attach the metadata files to")
	return env, nil
}

// wireKeyCrypto gives the Env upstream's gpg envelope for signing keys, when
// the toolchain has gpg. The sealed store needs none of it: gpg is for the keys
// of an upstream-layout directory that were encrypted by upstream's scripts.
func wireKeyCrypto(env *cli.Env, o cli.WireOptions) {
	const only = "gpg is needed only to read or write upstream's encrypted signing keys; nothing else here uses it"
	if len(o.Tools) == 0 || o.Toolchain == nil {
		env.Absent(cli.CapKeyCrypto, "this binary runs without a toolchain manifest, so it cannot locate gpg: run the packaged binary (nix run .#spo). "+only)
		return
	}
	for _, t := range o.Tools {
		if t == ports.GPG {
			g := gpg.GPG{Tools: o.Toolchain, Runner: execx.OS{}}
			env.KeyEncryptor, env.KeyDecryptor = g, g
			return
		}
	}
	env.Absent(cli.CapKeyCrypto, "the release set of this binary has no gpg. "+only)
}

func wireOffline(env *cli.Env, o cli.WireOptions, f *transferfile.File, clock ports.Clock, genesis genesisfile.Shelley) {
	// A resolver that only refuses, so a handle destination fails with the
	// reason (SPO-Caddr-PRE-002) and not with "not supported".
	env.Handles = handles.Resolver{Policy: handlePolicy(o), Mainnet: o.Config.Network == "mainnet", Offline: true}
	env.Absent(cli.CapAdaHandle, handles.ErrOffline.Error()+": give the address, or run in light mode")
	env.Absent(cli.CapPollQuestion, "SPO polls are read from the chain: run in light mode")
	switch {
	case env.Genesis == nil:
		env.Absent(cli.CapTip, "offline mode computes the slot from the clock and the Shelley genesis, which is not available (see genesis)")
	default:
		tip := offline.Tip{Clock: clock, Genesis: genesis}
		switch {
		case o.Genesis.ByronEpochs > 0 && o.Genesis.Byron == "":
			env.Absent(cli.CapTip, fmt.Sprintf("the network has %d Byron epochs, so the offline slot needs a Byron genesis: none is bundled with this binary; pass --byron-genesis FILE", o.Genesis.ByronEpochs))
		case o.Genesis.ByronEpochs > 0:
			byron, err := genesisfile.ReadByron(o.Genesis.Byron, o.Genesis.ByronEpochs)
			if err != nil {
				env.Absent(cli.CapTip, err.Error())
				break
			}
			tip.Byron = &byron
			env.Tip = tip
		default:
			env.Tip = tip
		}
	}
	env.OpCertCounters = offline.Counters{}
	env.AllowUnverified = true

	env.Absent(cli.CapMetaFetch, "offline mode makes no network request: the published metadata is not compared with poolMetaHash here (the hash check runs when the registration is executed online)")
	env.Absent(cli.CapSync, "offline mode has no chain to check the sync of")
	env.Absent(cli.CapSubmit, "offline mode has no transaction submitter; queue to a transfer file instead")
	if st, err := os.Stat(o.TransferFile); err == nil && st.Mode().IsRegular() {
		env.Utxos, env.Params, env.Queue, env.Eras = f, f, f, f
		// The snapshot answers reward accounts, and whatever else the
		// transfer-file adapter implements today (type assertions, so a new
		// interface is picked up without more wiring).
		env.Rewards = f
		env.Pools, _ = any(f).(ports.PoolStateReader)
		env.DReps, _ = any(f).(ports.DRepStateReader)
		env.Attach = f
		env.Absent(cli.CapPools, "the offline transfer file holds no pool registration state; checks of a pool are skipped only when the command is given --allow-unverified")
		env.Absent(cli.CapDReps, "the offline transfer file has no DRep state")
		env.Absent(cli.CapCrossCheck, noCrossCheck(string(f.Source())))
		governanceReaders(env, f, offlineGovernance)
		return
	}
	why := fmt.Sprintf("offline mode reads this from an offline transfer file and %s does not exist; create it on the online machine (01_workOffline.sh new), copy it here, or pass --transfer-file PATH", o.TransferFile)
	env.Absent(cli.CapUtxos, why)
	env.Absent(cli.CapParams, why)
	env.Absent(cli.CapQueue, why)
	env.Absent(cli.CapRewards, why)
	env.Absent(cli.CapPools, why)
	env.Absent(cli.CapDReps, why)
	env.Absent(cli.CapCrossCheck, why)
	env.Absent(cli.CapAttach, why)
	env.Absent(cli.CapEras, why)
	governanceReaders(env, nil, offlineGovernance)
}

// offlineGovernance is why the offline mode has no governance chain reader.
const offlineGovernance = "offline mode has no governance state: the transfer file holds none, and votes, tallies and committee checks need the chain; run the command in light mode"

// noGovernanceReader is why a provider has no governance chain reader.
const noGovernanceReader = "no configured chain provider reads this governance state yet (committee, actions, constitution, last enacted action, stake distribution, epoch)"

// noCrossCheck is the reason there is no second reward-account source: no
// adapter pair gives two independent answers today, so a read of the "harmful
// if false" class rests on the one source, and the operator acknowledges that
// with --single-source (ADR 0006).
func noCrossCheck(primary string) string {
	return "there is no second independent reward-account source besides " + primary + ", so reads that need corroboration are refused unless the command is given --single-source"
}

func wireLight(env *cli.Env, o cli.WireOptions) error {
	url := o.Config.Koios.URL
	if url == "" {
		url = o.Preset.KoiosURL
	}
	if url == "" {
		return errors.New("light mode needs a Koios endpoint: the network has no public one; set url in the [koios] section of spo.toml")
	}
	k, err := koios.New(koios.Config{BaseURL: url, Network: o.Config.Network, Token: o.Token})
	if err != nil {
		return err
	}
	env.Tip, env.Sync, env.OpCertCounters = k, k, k
	env.Utxos, env.Rewards, env.Submitter = k, k, k
	// The Koios adapter reads pool and DRep state; the assertions keep the
	// wiring honest if that ever changes.
	env.Pools, _ = any(k).(ports.PoolStateReader)
	env.DReps, _ = any(k).(ports.DRepStateReader)
	// The era is the one of the Koios tip (the air-gap commands need it).
	env.Eras, _ = any(k).(ports.EraReader)
	env.AnchorFetcher = httpfetch.Fetcher{Limit: anchorLimit}
	// The published pool metadata is the one thing fetched from a server the
	// operator does not choose: https only, 512 bytes at most.
	env.Metadata = httpfetch.Fetcher{Limit: pool.MaxMetadataBytes}
	env.Absent(cli.CapCrossCheck, noCrossCheck(string(k.Source())))
	env.Endpoints[string(k.Source())] = url
	// Upstream light mode takes the protocol parameters, the constitution and
	// the last enacted action ids from the hosted light-mode parameters file,
	// not from Koios (SPO-Clight-EXT-001, SPO-25a-MODE-002).
	if o.Preset.LightParametersURL != "" {
		lp, err := koios.NewLightParameters(koios.LightConfig{URL: o.Preset.LightParametersURL, Magic: o.Preset.Magic})
		if err != nil {
			return err
		}
		env.Params = lp
		env.Constitution, _ = any(lp).(ports.ConstitutionReader)
		env.LastEnacted, _ = any(lp).(ports.LastEnactedReader)
		env.Endpoints[string(lp.Source())] = o.Preset.LightParametersURL
	} else {
		env.Params = k
		const noDoc = "light mode reads this from the hosted light-mode parameters document (as upstream does), and this network has no such document configured"
		env.Absent(cli.CapConstitution, noDoc)
		env.Absent(cli.CapLastEnacted, noDoc)
	}
	env.Polls, _ = any(k).(ports.PollQuestionReader)
	wireHandles(env, o, k, native.Ledger{})
	env.Absent(cli.CapStakeDist, "light mode computes no tally from stake distributions (upstream does not: it reads the proposal voting summary, capability voting-summary), and Koios is not asked for them here")
	governanceReaders(env, k, noGovernanceReader)
	env.Absent(cli.CapQueue, "light mode submits through the provider; there is no queue")
	env.Absent(cli.CapAttach, "light mode submits through the provider; there is no transfer file to attach to")
	return nil
}
