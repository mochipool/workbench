# ADR 0006: Chain access providers

Status: accepted, 2026-11-16. Closes N1 (first adapters), N2 and N4. The capability table is confirmed by contract tests as each adapter lands.

## Context

Upstream reads the chain through a node socket (online), Koios (light) or a snapshot (offline). Many operators, the project owner included, have no node on the machine they work from. Blink Labs and TxPipe publish Go libraries and services that expose a node over HTTP or gRPC.

## Decision

### Adapters, in build order

| Order | Adapter | Protocol | Why |
| --- | --- | --- | --- |
| 1 | `koios` | HTTPS, JSON | Upstream's light mode. [Clight](../../../spec/upstream/common/Clight.md) specifies every call, so it is the one provider with a parity contract, and it covers pool, reward and governance reads. Needed to settle the spec's open questions (C3). |
| 2 | `snapshot` | none | Offline mode: serves what an online machine captured. |
| 3 | `utxorpc` | gRPC | UTxO RPC, as served by Dolos and by Blink Labs' `cardano-node-api` and Dingo. Self-hostable without a full node socket on the operator's machine. |
| 4 | `nodesocket` | cardano-cli over the local socket | Upstream's online mode, for operators who do run a node. |
| later | Blockfrost-compatible HTTP, Ogmios, Ouroboros node-to-client over TCP (`gouroboros`) | | Added behind the same port when someone needs them. |

### Capabilities

A provider rarely answers every `ChainQuery` operation. Each adapter declares the operations it serves. Wiring compares a use case's needs with the configured adapter's capabilities and refuses before any effect when one is missing, which is how upstream treats a script that a work mode does not support.

An operator may configure a second provider for the operations the first lacks. Expected starting point, to be confirmed by the contract tests:

| Operations | `koios` | `utxorpc` | `nodesocket` | `snapshot` |
| --- | --- | --- | --- | --- |
| Tip, protocol parameters, UTxOs by address, submit | yes | yes | yes | captured (submit queues) |
| Reward account | yes | to be confirmed | yes | captured |
| Pool state, opcert counter | yes | to be confirmed | yes | no |
| DRep, committee, governance actions, votes | yes | to be confirmed | yes | DRep state only |

### Trust in answers (N2)

A provider is a third party, and transport security only proves which third party answered. Each read is classed by what a false answer leads to:

| Class | Reads | Rule |
| --- | --- | --- |
| **Self-correcting** | UTxOs, protocol parameters, tip | A false answer produces a transaction the ledger rejects. One provider is enough. |
| **Harmful if false** | Opcert counter of the last block, pool registration state, reward balance before a stake deregistration, deposit amounts used for refunds | Needs two independent providers that agree, or an explicit confirmation that names the single source and is written to the audit log. |
| **Informational** | Tallies, status views | Shown with the source named. |

Every read returns one of three results: a value, "none", or "unknown". A failed or empty response is "unknown", never "none" (this closes hazard H1).

### Privacy and credentials (N4, N3)

* There is no default provider. The operator names one per network at setup, and setup states what that provider will learn: the addresses queried and the transactions submitted.
* Provider tokens are Secret records ([ADR 0004](./0004-data-classification.md)). Adapters require TLS with certificate verification, except to a loopback address.

## Consequences

* Preview acceptance runs for this project use Koios, since no node is available.
* The first slice needs only adapters 1 and 2.
