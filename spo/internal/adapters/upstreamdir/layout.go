// Package upstreamdir is the read-only view of a directory in the upstream
// scripts' file layout (spec/upstream/patterns/Pfiles.md).
//
// The release binary has no workspace in this layout: signing keys are never
// kept in clear (ADR 0004, SPO-Xcustody-INV-001; ADR 0011 (proposed)). The
// directory is only ever the source of `spo workspace import`, which reads it
// and never writes it. This package therefore has no method that writes: the
// writable store lives in spo/test/plainstore, which production code cannot
// import (internal/archtest). What is shared is the name mapping (the layout
// table, RefOf, FileName, ModeOf), which says which file name holds which
// artefact and at which mode a writer must create it.
package upstreamdir

import (
	"fmt"
	"os"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// ModeLocked is upstream's file_lock mode. A rewrite replaces the file by
// rename, so no unlock step is needed (SPO-Pfiles-INV-003).
const ModeLocked = 0o400

// layout maps a kind to its upstream file name.
// spec: SPO-Pfiles-OUT-010 to SPO-Pfiles-OUT-015, SPO-04c-INV-001
var layout = map[ports.Kind]func(r ports.NamedRef) string{
	ports.NodeVKey:       func(r ports.NamedRef) string { return r.Name + ".node.vkey" },
	ports.NodeSKey:       func(r ports.NamedRef) string { return r.Name + ".node.skey" },
	ports.NodeCounter:    func(r ports.NamedRef) string { return r.Name + ".node.counter" },
	ports.NodeHwsFile:    func(r ports.NamedRef) string { return r.Name + ".node.hwsfile" },
	ports.VrfVKey:        func(r ports.NamedRef) string { return r.Name + ".vrf.vkey" },
	ports.VrfSKey:        func(r ports.NamedRef) string { return r.Name + ".vrf.skey" },
	ports.KesVKey:        func(r ports.NamedRef) string { return fmt.Sprintf("%s.kes-%03d.vkey", r.Name, r.Num) },
	ports.KesSKey:        func(r ports.NamedRef) string { return fmt.Sprintf("%s.kes-%03d.skey", r.Name, r.Num) },
	ports.KesCounter:     func(r ports.NamedRef) string { return r.Name + ".kes.counter" },
	ports.KesCounterNext: func(r ports.NamedRef) string { return r.Name + ".kes.counter-next" },
	ports.OpCert:         func(r ports.NamedRef) string { return fmt.Sprintf("%s.node-%03d.opcert", r.Name, r.Num) },
	ports.KesExpire:      func(r ports.NamedRef) string { return r.Name + ".kes-expire.json" },

	// spec: SPO-Pfiles-OUT-001, SPO-Pfiles-OUT-002, SPO-Pfiles-OUT-004
	ports.AddrFile:       func(r ports.NamedRef) string { return r.Name + ".addr" },
	ports.AddrVKey:       func(r ports.NamedRef) string { return r.Name + ".vkey" },
	ports.AddrSKey:       func(r ports.NamedRef) string { return r.Name + ".skey" },
	ports.AddrHwsFile:    func(r ports.NamedRef) string { return r.Name + ".hwsfile" },
	ports.StakingAddr:    func(r ports.NamedRef) string { return r.Name + ".staking.addr" },
	ports.StakingVKey:    func(r ports.NamedRef) string { return r.Name + ".staking.vkey" },
	ports.StakingSKey:    func(r ports.NamedRef) string { return r.Name + ".staking.skey" },
	ports.StakingHwsFile: func(r ports.NamedRef) string { return r.Name + ".staking.hwsfile" },
	ports.StakingCert:    func(r ports.NamedRef) string { return r.Name + ".staking.cert" },
	// spec: SPO-Pfiles-OUT-006 to SPO-Pfiles-OUT-009 (certificates), SPO-22a-IN-002 (DRep key)
	ports.DelegCert:        func(r ports.NamedRef) string { return r.Name + ".deleg.cert" },
	ports.VoteDelegCert:    func(r ports.NamedRef) string { return r.Name + ".vote-deleg.cert" },
	ports.StakingDeregCert: func(r ports.NamedRef) string { return r.Name + ".staking.dereg-cert" },
	ports.DRepVKey:         func(r ports.NamedRef) string { return r.Name + ".drep.vkey" },
	// spec: SPO-Pfiles-OUT-005
	ports.PaymentMnemonics: func(r ports.NamedRef) string { return r.Name + ".payment.mnemonics" },

	// spec: SPO-Pfiles-OUT-017 to SPO-Pfiles-OUT-023 (the pool descriptor, ids, certificates, metadata, witness transfer files)
	ports.PoolDescriptor:         func(r ports.NamedRef) string { return r.Name + ".pool.json" },
	ports.PoolIDFile:             func(r ports.NamedRef) string { return r.Name + ".pool.id" },
	ports.PoolIDBechFile:         func(r ports.NamedRef) string { return r.Name + ".pool.id-bech" },
	ports.PoolCert:               func(r ports.NamedRef) string { return r.Name + ".pool.cert" },
	ports.PoolDeregCert:          func(r ports.NamedRef) string { return r.Name + ".pool.dereg-cert" },
	ports.PoolMetadata:           func(r ports.NamedRef) string { return r.Name + ".metadata.json" },
	ports.PoolExtendedMetadata:   func(r ports.NamedRef) string { return r.Name + ".extended-metadata.json" },
	ports.PoolAdditionalMetadata: func(r ports.NamedRef) string { return r.Name + ".additional-metadata.json" },
	ports.PoolItnSKey:            func(r ports.NamedRef) string { return r.Name + ".itn.skey" },
	ports.PoolItnVKey:            func(r ports.NamedRef) string { return r.Name + ".itn.vkey" },
	ports.PoolWitnessFile:        func(r ports.NamedRef) string { return r.Name + ".witness" },

	// spec: SPO-Xparty-INV-001, SPO-Xparty-INV-003, SPO-Xparty-OUT-001, SPO-Xparty-INV-007, SPO-Xparty-SEC-001
	ports.PartyKeys:      func(r ports.NamedRef) string { return r.Name + ".party.keys" },
	ports.PartyIdentity:  func(r ports.NamedRef) string { return r.Name + ".party.identity" },
	ports.PartyRecords:   func(r ports.NamedRef) string { return r.Name + ".party.records" },
	ports.PartyReplay:    func(r ports.NamedRef) string { return r.Name + ".party.replay" },
	ports.TailcatNodeKey: func(r ports.NamedRef) string { return r.Name + ".tailcat.nodekey" },
	ports.TailcatPSK:     func(r ports.NamedRef) string { return r.Name + ".tailcat.psk" },
	ports.TailcatAddr:    func(r ports.NamedRef) string { return r.Name + ".tailcat.addr" },
	ports.CheckpointKey:  func(r ports.NamedRef) string { return r.Name + ".checkpoint.key" },
	// spec: SPO-Xparty-SEC-003, SPO-Xparty-OUT-004
	ports.MultisigCoordinator: func(r ports.NamedRef) string { return r.Name + ".multisig.coordinator" },
	ports.MultisigSigner:      func(r ports.NamedRef) string { return r.Name + ".multisig.signer" },
	ports.MultisigOutbox:      func(r ports.NamedRef) string { return r.Name + ".multisig.outbox" },
	ports.MultisigEvents:      func(r ports.NamedRef) string { return r.Name + ".multisig.events" },
	ports.MultisigCollection:  func(r ports.NamedRef) string { return r.Name + ".multisig.collection" },
	ports.MultisigSubmitted:   func(r ports.NamedRef) string { return r.Name + ".multisig.submitted" },
}

// modes of the kinds that are not locked at 0400: the published metadata is
// 0444 so it can be copied to a web server (SPO-05a-OUT-006, OUT-007), the
// additional metadata and the witness transfer files keep the default mode
// because the operator edits the first and `05d sign` rewrites the second in
// place (SPO-05a-OUT-003, SPO-05d-OUT-001).
var modes = map[ports.Kind]os.FileMode{
	ports.PoolMetadata:           0o444,
	ports.PoolExtendedMetadata:   0o444,
	ports.PoolAdditionalMetadata: 0o644,
	ports.PoolWitnessFile:        0o644,
}

// ModeOf is the file mode upstream gives the kind: 0400 unless the kind is
// one of the few left unlocked.
func ModeOf(k ports.Kind) os.FileMode {
	if m, ok := modes[k]; ok {
		return m
	}
	return ModeLocked
}
