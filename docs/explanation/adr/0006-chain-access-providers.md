# ADR 0006: Chain access providers

Status: accepted, 2026-11-16. Closes N1 (first adapters), N2 and N4. The capability table is confirmed by contract tests as each adapter lands.

## Context

Upstream reads the chain through a node socket (online), Koios (light) or a snapshot (offline). Many operators, the project owner included, have no node on the machine they work from. Blink Labs and TxPipe publish Go libraries and services that expose a node over HTTP or gRPC.

## Decision

### Adapters, in build order

Revised 2026-11-16 after a survey of the Go client libraries ([Go library coverage](../../development/go-library-coverage.md)). Every adapter is in process; none runs cardano-cli or curl.

| Order | Adapter | Protocol and library | Why |
| --- | --- | --- | --- |
| 1 | `koios` | HTTPS and JSON, our own thin client | Upstream's light mode. [Clight](../../../spec/upstream/common/Clight.md) specifies every call, so it has a parity contract, and it is the only socket-less source of the opcert counter. The community Go client has had no release since May 2024 and lacks the governance endpoints, so the adapter speaks HTTP itself. Needed to settle the spec's open questions (C3). |
| 2 | `snapshot` | none | Offline mode: serves what an online machine captured. |
| 3 | `n2c` | Ouroboros node-to-client through `gouroboros` | Upstream's online mode without cardano-cli. It answers every read we need except asset holders and transaction metadata, including rewards, pool state, the opcert counter the node enforces, DRep, committee and governance state. It needs the node's socket, or that socket forwarded over TCP by the operator. |
| 4 | `blockfrost` | Blockfrost-compatible HTTP through `blockfrost-go` | Governance, DRep, pool, account and metadata reads without a socket. Blink Labs' Dingo serves the same API, so this adapter is also the path to a self-hosted provider. It lacks the opcert counter and the constitution. |
| 5 | `utxorpc` | gRPC through `utxorpc/go-sdk` | Parameters, UTxOs by address or asset, submit and wait, tip and era summary, as served by Dolos and Dingo. It has no reward, pool or governance reads, so it is never sufficient alone for pool operations. |

Not planned: Ogmios (the Go client exposes nothing the others lack) and `cardano-node-api` (retired by Blink Labs).

### Capabilities

A provider rarely answers every read. Following [ADR 0008](./0008-capability-typed-ports.md), `ChainQuery` is a set of narrow reader interfaces, and an adapter implements only the ones it can answer. When a command starts, each reader it needs is resolved from the configured providers, in the operator's order of preference. A command whose needs no configured provider meets stops there and names the missing capability, which is how upstream treats a script that a work mode does not support.

Coverage as read from the client libraries (not yet exercised against live services):

| Read | `koios` | `n2c` | `blockfrost` | `utxorpc` | `snapshot` |
| --- | --- | --- | --- | --- | --- |
| Tip, protocol parameters, UTxOs by address, submit | yes | yes | yes | yes | captured (submit queues) |
| Era history for slot and time conversion | no | yes | partly | yes | captured |
| Reward account | yes | yes | yes | no | captured |
| Stake deposit, vote delegation | no | yes | DRep only | no | no |
| Pool state | yes | yes | yes | no | no |
| Opcert counter | last block's | the node's | no | no | no |
| DRep, committee, governance actions, votes | by raw HTTP, to be confirmed | yes | yes, except constitution | no | DRep state only |
| Asset holders (ADA Handle), transaction metadata | yes | no | yes | by asset: yes | no |
| Wait for confirmation | poll | mempool only | poll | yes | no |

The two opcert counters differ in meaning: Koios reports the counter of the last block the pool made, and the node reports the counter it will enforce. Both satisfy the rule that a new certificate's counter must exceed it, and the read is in the *harmful if false* class below.

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
