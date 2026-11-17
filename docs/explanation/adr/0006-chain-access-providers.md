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
| 3 | `n2c` | Ouroboros node-to-client through `gouroboros` (built and wired, see below) | Upstream's online mode without cardano-cli. It answers every read we need except asset holders and transaction metadata, including rewards, pool state, the opcert counter the node enforces, DRep, committee and governance state. It needs the node's socket, or that socket forwarded over TCP by the operator. |
| 4 | `blockfrost` | Blockfrost-compatible HTTP, our own thin client (built, see below) | Pool, account and DRep reads without a socket. Blink Labs' Dingo serves the same API, so this adapter is also the path to a self-hosted provider. It lacks the opcert counter and the constitution. |
| 5 | `utxorpc` | gRPC through `utxorpc/go-sdk` | Parameters, UTxOs by address or asset, submit and wait, tip and era summary, as served by Dolos and Dingo. It has no reward, pool or governance reads, so it is never sufficient alone for pool operations. |

#### Adapter 4 as built

`spo/internal/adapters/blockfrost` is written by us over HTTP and JSON, in the shape of the Koios adapter (timeouts, body limit, same-host https redirects, a token that never reaches an error, three-valued readings). `blockfrost-go` was not used: the endpoints needed are a handful, and the adapter must not turn an empty or failed answer into "none". It implements the tip, protocol parameters, UTxOs by address, UTxO resolution by reference, the reward account, pool state, DRep state and submission. It does not implement the opcert counter, the constitution, the sync check, the governance readers, asset holders or transaction metadata; that absence is visible at wiring time and in `spo capabilities`.

Configuration is `[blockfrost]` (`url`, `token_record`) and `[provider] order` in `spo.toml`; the project id is a Secret record. The kind is a section name, so a third kind (`n2c`) adds a section and a layer in `cmd/spo/providers.go` without changing the order or the cross-check.

What the cross-check does with two providers, for the reward balance and registration, the pool registration and the DRep registration: both answer and agree, the command goes on with no warning; they disagree, it is refused naming both providers and both answers, and `--single-source` does not lift that; the second does not answer, it is refused naming both and the first's answer, unless `--single-source`. Wiring one provider as both ends is rejected when the Env is built.

Confirmed and not confirmed. Confirmed: the adapter's behaviour against recorded-shape responses written from the public OpenAPI documentation, served by a local HTTP server, and the end-to-end commands against loopback stand-ins. Not confirmed against any live service (no project id was available): every response shape; the 404 answers (read as "no history" for an address's UTxOs and as unknown for an account, pool or DRep); the `consumed_by_tx` member of a transaction's outputs, on which the UTxO-by-reference answer rests; the `drep_id` format of an account; the `hex` of a DRep (28 or 29 bytes); the pool state derived from the latest certificate of `/pools/{id}/updates` and `/txs/{hash}/pool_retires`; the 200 and plain-string answer of `/tx/submit`. Not stated by the API as documented: the stake key deposit and the open governance-action deposits of an account, and a DRep's deposit. Those readings are unknown (or `DepositUnstated`), a cross-check does not compare them, and so the deposit a refund rests on is the first provider's alone and the ledger rejects a certificate that carries a wrong one. Blockfrost therefore cannot be the answering provider of `stake deregister` or `drep retire`.

#### Adapter 3 as built and wired

`spo/internal/adapters/native/n2c` speaks node-to-client through `gouroboros` v0.219.0 (local-state-query, local-tx-submission, local-tx-monitor) and implements the reader ports its README lists. `cmd/spo/online.go` connects it:

* **Configuration.** A `[node]` section in `spo.toml` (`address`: a socket path, `unix:PATH` or `tcp://host:port`; `timeout_seconds`, 1 to 600, default 30 per operation), written by `spo provider set node ADDRESS`. The kind name in `[provider] order` is `node`. A configuration with no `[node]` section is unchanged; `mode = "online"` without one leaves every chain capability absent with the reason `no node address is configured`.
* **Connection.** Dialled on the first read that needs it (`n2c.DialLazy`), once per command, and closed when the command's `Env` is closed. A command that needs no chain read never connects, and neither does the probe `Env` that checks a command's needs. A failed connection is remembered for the rest of the command, so an unreachable node costs one attempt, at most the timeout; every read is then Unknown with the address in the reason. `tcp://` to a host that is not loopback prints `n2c.WarnPlainTCP` on stderr once, when the connection is first attempted, and `spo provider set node` prints it when the address is named.
* **Online mode.** The node answers every read it implements, including the reads that were Koios-only before (the opcert counter, the governance state). Capabilities it cannot answer (asset holders and so ADA Handles, transaction metadata and so polls and Calidus registrations, the pool's last update time, a voting-summary tally, script evaluation, the era name for the air-gap commands) are absent, each with its reason in `spo capabilities`. A web provider supplies those, and is the second source of the harmful-class reads, only if it has a section **and** is named in `[provider] order`. The node is the answering provider in online mode whatever the order says; a Koios or Blockfrost section that the order does not name is never asked, so no address leaves the machine by default.
* **Light mode with a node.** If the order puts the node first it answers, as in online mode, and every configured web provider supplies what it lacks. If the order puts it right after the answering web provider it is the second source of the reward account, the pool, the DRep and the opcert counter, in place of any other second provider. Elsewhere in the order it is unused.
* **Sync refusal.** Upstream refuses a transaction or query script on a node that is not synced (SPO-Ptx-MODE-002, SPO-01queryAddress-PRE-002, SPO-04e-PRE-002). The use cases that take a `SyncChecker` do (address, opcert check, the air-gap commands, handles). Every other state read of the node (UTxOs, accounts, pool, DRep, opcert counter, governance state) passes a gate that asks the node's own sync check once per command and refuses with `query.ErrNotSynced`, so a send, a registration or a vote on an unsynced node stops before anything is built. The tip, the parameters, the genesis and the submission are not gated.

The opcert counter has a second-source rule of its own. The ledger (Praos) accepts a block whose certificate carries n when the stored counter m satisfies m <= n <= m+1, and refuses m+2. A certificate is issued with the chain's counter plus one, so a source that is one ahead of the truth, a wrong or impersonated node among them, would get the pool's blocks rejected. `chain.CompareOpCertCounters` therefore accepts only equal readings. Readings exactly one apart are not agreement, whichever side is the node, and are refused with "the two sources differ by one: the indexer may lag the node by a block; retry in a few minutes"; every other difference is a disagreement too. A disagreement is never overridden by `--single-source`; a second provider that does not answer is refused unless the command is given `--single-source`. With one provider, `pool opcert issue` (the command that signs) refuses unless `--single-source` is given (concern N7, closed); `check` and `counter` are informational and print the source. An acknowledged single source is written to the audit log and printed in the summary (below). The use cases keep upstream's rule (04d, 04e): the certificate carries the chain's counter plus one.

#### Acknowledged single sources: the audit record

Every command that accepts `--single-source` (`stake register|delegate|vote-delegate|deregister`, `pool register`, `drep retire`, `pool opcert issue|check|counter`, `pool import`) appends one record to the workspace audit log when, and only when, the answer actually rests on one source (a run that had two agreeing sources, or that was refused, writes nothing). The record holds the operation `single-source-read`, the command, what was read, the provider it rested on and that the flag was given; the sealed store keeps it in its MAC-chained audit log, an upstream-layout directory in `.spo-workspace-audit.json`. The record is written by a hook the use case calls at the point where it accepts the single source (`ports.SingleSourceHook`; the command layer passes the function that appends to the audit log), before anything is signed, submitted, queued or written. A use case that is told to accept a single source and has no hook refuses, so a caller cannot forget it. If the record cannot be written the use case stops with nothing done. One record is made per accepted read: `stake deregister` reads the account for the certificate and again for the transaction and writes two; `pool import` records just before its first write, so a dry run or a declined import records nothing. The summary of an opcert command prints a warning line.

#### Independence of the two sources

Two names are not two sources. At Env build, a cross-check pair is refused when both providers are on the same normalised host (a lower-cased host name without the port, trailing dot or brackets; a loopback address, `localhost` and a Unix socket all count as this machine), with no name resolution. `[provider] same_host_ok = true` in `spo.toml` acknowledges that two providers behind one host are independent all the same; it weakens the check, `spo capabilities` says when it is set and which cross-checks it let through, and it is not set by any command. A transaction summary whose checks rest on a cross-check that it let through says "the two sources share a host; independence acknowledged in spo.toml". The comparison is of names, not of machines: no name is resolved, so two names for one machine pass it. Numeric IPv4 forms (decimal, hexadecimal, octal, short), IPv4-mapped IPv6 addresses, IPv6 zones, case and trailing dots are one host, and all of 127.0.0.0/8 and `::1` are this machine. Independence means different operators running different chain followers; the host comparison is a floor, not a proof. A web provider that answers or corroborates a harmful-class read, as the first source or as the second, must also have a recent tip (a machine clock more than ten minutes off makes a web source look stale, so the message gives both times and says the local clock may be the wrong one): `ports.TipTimeReader` (Koios `block_time`, Blockfrost `time`) against the local clock, limit ten minutes, otherwise its answer is Unknown with the reason. A node as a second source passes the same sync gate as the node as the answering provider. The Env fields that hold the node (tip, sync, parameters, submission, genesis) hold narrow views that implement only their own port, and the state readers are one gated type, so no field can be asserted to a reader that skips the gate (`TestNodeEnvFieldsHaveNoUngatedStateReader`).

#### Pool state and retiring pools

`chain.PoolState.Status` is compared only when both sources state it (`PoolStatusUnstated` is a source that does not say), and the retiring epoch only when both say retiring. Koios (`pool_status`, `retiring_epoch`), Blockfrost (the retirement certificate and its epoch) and the node all report a retiring pool, so a retiring pool is not a disagreement. A disagreement message names the field that differs. For the deposit, where two sources agree and the second does not state deposits, the summary says "deposit N lovelace from <first> only; <second> does not state deposits; the ledger refuses a wrong amount" (stake deregistration; the DRep deposit of `drep retire` is in the governance code and not covered by this statement yet).

#### Reads that name a host on chain

Anchor documents and pool metadata are fetched from the URL a chain record gives, in every mode that fetches them, online mode included. That host is not one the operator configured. The command prints the host before the first fetch to it, and `spo capabilities` says so.

**Unverified against a real node** (from the adapter's README). Only one reply of the tests was captured from a real node: `GetDRepState`, copied from the gouroboros tests, which state it came from cardano-cli 11.0.0.0 on a devnet. Everything else rests on the library's decoders and on hand-written bytes; a round trip through the library's server proves little. `GetConstitution`, `GetCommitteeMembersState` and `GetRatifyState` are decoded by the library as bare structures, where the other Shelley-era queries are decoded from the one-element array a node wraps results in; if a real node wraps them, those three reads return Unknown (a test pins that), never a wrong value. The previous-action-id layout (four optional ids in the order parameter update, hard fork, committee, constitution) is recalled from the ledger, not checked; another shape gives Unknown. The parameter-update key names and the security group are from the key table of the library's `ConwayProtocolParameterUpdate` and CIP-1694; a key without a name leaves the security group Unknown. The slot length of the era history is read as milliseconds and bound times as picoseconds, and the era-history tests encode them that way themselves. Only the Conway era is decoded for protocol parameters; another era is `ErrUnsupportedEra`. Also unverified: that a node's consensus counter for a pool equals the counter of the pool's last block except for ingest lag (the premise of the opcert rule above), and the end-to-end wiring with a node at all: its tests use an in-process fake, not a node. The checks to run are in [the node-socket checklist](../../development/node-socket-checklist.md).

#### Addendum 2026-11-16: transaction status and waiting for confirmation

A submission that the provider accepted says nothing about a block, and `ErrSubmitOutcomeUnknown` told the operator to "query its transaction id" with no command to do it. Behaviour is specified in [Xconfirm](../../../spec/extensions/Xconfirm.md) (no upstream script has it).

* **Port.** `ports.TxStatusReader` (`TxStatus(ctx, TxStatusQuery) (chain.Reading[chain.TxStatus], error)`), one narrow reader implemented by `koios` (`tx_status`), `blockfrost` (`GET /txs/{hash}`, depth from `/blocks/latest`) and `n2c`. The value is "in a block" (height, slot and confirmations where the provider gives them) or "in the mempool" (the node only); None is "not seen"; Unknown is everything else. The name avoids `ports.Confirmer`, which is the operator's yes/no prompt. `ports.TxWatcher` pairs a status reader with a tip reader for the expiry rule.
* **None is rare and guarded.** A web provider's null or 404 is "not seen" only while its tip is under ten minutes old, and a node answers only while synced; the guard is evaluated on every call (`cmd/spo/txwatch.go`), because a wait lasts minutes. The node cannot prove absence from outputs (a spent output is gone from the UTxO set), so it answers "not seen" only from an unspent input of the transaction, which the caller supplies for a transaction without collateral, and never for a bare id.
* **Providers are combined** (`chain.Assess`): confirmed needs every configured provider; disagreement and partial answers are reported as such.
* **Wait.** `--wait` is registered with the chain flags of every submitting command (`addSubmitFlags`) and run once in `withEnv`, after the command, from the transactions a recording wrapper of `Env.Submitter` saw accepted. It never resubmits. Only "expired" says a rebuild is safe, and it is decided per provider: each provider's tip, read before its own status in the same poll, must be past the validity bound by more than the freshness window (plus a margin), and that status "not seen", on two polls in a row. Web backends behind one URL can differ in sync level, so a tip from one request is never paired with a status from another. The id waited for is computed locally; a provider's differing id is an error. Each poll is bounded by the time left of `--wait-timeout` plus 5 seconds.
* **Not confirmed against any live service:** the Koios and Blockfrost shapes (public documentation only), whether Koios' `num_confirmations` counts the holding block, and the node's answers (the fake node in `n2ctest`).

#### Pool import

`pool import` takes the reward address, the owners, the margin, cost and pledge, the relays and the opcert counter from the pool-info reader. With a second pool-info reader (the node and Koios; Blockfrost has none) the fields both state are compared (owners and relays as sets, the margin as a number, counters by the opcert rule) and a difference is refused naming both providers, whatever `--single-source` says. Without a second reader, or when it does not answer, the import needs `--single-source`. The compared fields include the metadata URL and hash and the VRF key hash, and an empty owner or relay set against a non-empty one is a difference (both readers state every field). In every case the data is shown (reward address, owners, margin, cost, pledge, relays, ticker, name, metadata URL and hash, VRF key hash, opcert counter), with the strings a provider chose escaped (`internal/platform/textsafe`), and the operator confirms (default No, `--yes` confirms) before anything is written. The chain is read once: the dry run, the confirmation and the write use one answer (`ImportPoolFromChain.Fetch`), so what is written is what was confirmed. A new pool that only Koios and Blockfrost can see, with no node, can read Unknown and then needs `--allow-unverified` to register or a node as a source. An info file is the operator's own input and is not corroborated.

#### Node answers, keyed and filtered

The node's filtered queries (reward account, vote delegation, pool state, DRep state) answer for the keys asked and no others: an empty answer is None, an answer that holds other keys but not the one asked is Unknown. The counter map is unfiltered (every pool that made a block): a missing pool is None, an empty map is Unknown. After a transaction has been sent, every error that is not a rejection is `ErrSubmitOutcomeUnknown`. The README of `n2c` lists this per query.

#### Blockfrost and phase 2

A transaction that failed phase 2 (`valid_contract` false) created no regular outputs; only its collateral return output exists. `ResolveUtxos` asks `GET /txs/{hash}` for `valid_contract` and resolves those outputs to None, using the `collateral` flag of the output (both documentation-derived, not checked against a live service). A control character, bidirectional control or line separator in a provider URL or the node address is refused when the configuration is validated.

Not planned: Ogmios (the Go client exposes nothing the others lack) and `cardano-node-api` (retired by Blink Labs).

### Capabilities

A provider rarely answers every read. Following [ADR 0008](./0008-capability-typed-ports.md), `ChainQuery` is a set of narrow reader interfaces, and an adapter implements only the ones it can answer. When a command starts, each reader it needs is resolved from the configured providers, in the operator's order of preference. A command whose needs no configured provider meets stops there and names the missing capability, which is how upstream treats a script that a work mode does not support.

Coverage as read from the client libraries (not yet exercised against live services). The `n2c` column is what [`adapters/native/n2c`](../../../spo/internal/adapters/native/n2c/README.md) implements, tested only against an in-process fake node built on the library's own server side. Its README lists, per port, the query used and whether the test bytes were hand-written or produced by the library; a single reply (`GetDRepState`) was captured from a real node. Where a reply cannot be decoded the read is Unknown.

| Read | `koios` | `n2c` | `blockfrost` | `utxorpc` | `snapshot` |
| --- | --- | --- | --- | --- | --- |
| Tip, protocol parameters, UTxOs by address, submit | yes | implemented (parameters: Conway only) | yes | yes | captured (submit queues) |
| Era history for slot and time conversion | no | implemented (sync check and genesis values use it) | partly | yes | captured |
| Reward account | yes | implemented | yes (no deposit) | no | captured |
| Stake deposit, vote delegation | no | implemented | DRep only | no | no |
| Pool state | yes | implemented (also pool info, without the last-update time) | yes (derived) | no | no |
| Opcert counter | last block's | implemented: the node's | no | no | no |
| DRep, committee, governance actions, votes | by raw HTTP, to be confirmed | implemented; constitution, committee and last-enacted decodings unverified against a node | yes, except constitution | no | DRep state only |
| Asset holders (ADA Handle), transaction metadata | yes | no | yes | by asset: yes | no |
| Transaction status and wait for confirmation (`TxStatusReader`) | built (`tx_status`) | built: presence from the outputs, absence from an unspent input, mempool; no depth | built (`/txs/{hash}`) | yes | no |

The two opcert counters differ in meaning: Koios reports the counter of the last block the pool made, and the node reports the counter it will enforce. A new certificate carries the chain's counter plus one, which the ledger accepts when the stored counter m satisfies m <= n <= m+1. The read is in the *harmful if false* class below, and two readings one apart are refused (see the opcert rule above).

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
* Provider tokens are Secret records ([ADR 0004](./0004-data-classification.md)); the Blockfrost project id is one, named by `token_record`. Adapters require TLS with certificate verification, except to a loopback address.

## Consequences

* Preview acceptance runs for this project use Koios, since no node is available.
* The first slice needs only adapters 1 and 2.
* With adapters 1 and 4 configured, the harmful-class reads that both answer need no `--single-source`. The deposits still have one source each.
* With the node (adapter 3) and Koios configured and both in the order, the opcert counter has two sources and `pool opcert issue`, `check` and `counter` corroborate it when the two readings are equal (readings one apart are refused; a second provider that is silent needs `--single-source`). With one provider `pool opcert issue` needs `--single-source`.
* Online mode has never been run against a real node. It is not evidence about a node until the node-socket checklist has been run.
