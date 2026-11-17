# n2c: the node-to-client chain adapter

Upstream's "online" mode without cardano-cli. The package talks the Ouroboros node-to-client mini-protocols (local-state-query, local-tx-submission, local-tx-monitor) through `gouroboros` v0.219.0 to a cardano-node UNIX socket, or to that socket forwarded over TCP. It is the third adapter of [ADR 0006](../../../../../docs/explanation/adr/0006-chain-access-providers.md) and follows [ADR 0008](../../../../../docs/explanation/adr/0008-capability-typed-ports.md): it implements the narrow reader ports below and nothing else.

## Use

```go
c, err := n2c.Dial(ctx, n2c.Config{
    Address:      "/run/cardano/node.socket", // or "tcp://127.0.0.1:3001"
    NetworkMagic: 2,                          // the workspace network
    Network:      "preview",                  // for Source() only
    Timeout:      30 * time.Second,           // per operation
})
if err != nil { ... }
defer c.Close()
```

* `n2c.DialLazy(cfg)` returns a `Client` that connects on its first operation (under the operation lock), once; a failed connection is remembered and returned by every later operation, so a command waits for an unreachable node once. `cmd/spo/online.go` uses it, so a command that reads nothing from the chain never connects. `Close` is harmless on a client that never connected.
* `OpCertCounterEnforced()` marks the opcert counter as the node's enforced one (`ports.OpCertCounterEnforcer`); the two-provider cross-check reads it (`chain.CompareOpCertCounters`).
* One `Client` is one connection, reused for a whole command. Operations run one at a time. Each operation acquires the ledger state at the node's tip, runs its queries against that one state, and releases it, so the next operation sees a fresh state.
* The handshake carries the configured network magic; a node on another network refuses it and `Dial` fails.
* A timeout closes the connection (the protocol state is then unknown). Later calls return `ErrClosed`. A reader that cannot ask returns Unknown, never None.
* `n2c.IsPlainTCP(address)` is true for a `tcp://` address whose host is not loopback. The wiring prints `n2c.WarnPlainTCP` for it. Node-to-client has no authentication and no encryption, so the operator is expected to tunnel the socket (SSH, VPN) and give a loopback address.
* `Submit` returns a `*RejectedError` when the mempool refuses the transaction, and an error wrapping `ErrSubmitOutcomeUnknown` when the transaction was sent and no answer arrived.
* Not ports, but exported: `EraHistory` (slot to time and back), `InMempool` (local-tx-monitor).

## Capabilities

"Bytes" says where the reply bytes of the test come from. **hand** means written by hand from the shape the library documents or the ledger CDDL, then decoded by the library; **library** means encoded by the library's own server types, so only a round trip; **captured** means bytes sent by a real node. No test uses a live node, and none exists for this project. The package is wired into the binary (online mode, ADR 0006) and its end-to-end tests in `cmd/spo` use the in-process node of `n2ctest`, which is test support built on the same library and does not make any reply more real.

| Port | Query | Bytes in tests |
| --- | --- | --- |
| `TipReader` | `GetChainPoint`, `GetEpochNo` | library |
| `EpochReader` | `GetEpochNo` | library |
| `SyncChecker` | `GetChainPoint`, `GetSystemStart`, era history; tip slot to time against the clock, tolerance 2 minutes | hand (era history, system start), library (point) |
| `GenesisReader` | `GetSystemStart`, era history (slot and epoch length), `GetGenesisConfig` (KES values) | hand, library |
| `ProtocolParametersReader` | `GetCurrentProtocolParams` (Conway only; `Raw` is a subset under cardano-cli's names) | library |
| `UtxoReader` | `GetUTxOByAddress` | hand |
| `UtxoResolver` | `GetUTxOByTxIn`; an output not returned is None | hand |
| `RewardAccountReader` | `GetFilteredDelegationsAndRewardAccounts`, `GetStakeDelegDeposits`, `GetFilteredVoteDelegatees`, `GetProposals` (deposits to refund). The first and the vote query are filtered: an empty answer is None (not registered; no vote delegation), an answer that holds other addresses but not the one asked is Unknown | hand |
| `TxSubmitter` | local-tx-submission, era from `GetCurrentEra`; id is blake2b-256 of the body. After the transaction was sent every error that is not a rejection is `ErrSubmitOutcomeUnknown` | library |
| `OpCertCounterReader` | `DebugChainDepState` (the counters the node enforces, as `kes-period-info`). The map is unfiltered (every pool that made a block): a pool absent from a non-empty map is None, an empty map is Unknown | hand (Praos layout of the library docs) |
| `PoolStateReader` | `GetPoolState`, filtered by pool id: an empty answer is None, an answer that holds other pools but not this one is Unknown | hand |
| `PoolInfoReader` | `GetPoolState` (filtered, as above) and `DebugChainDepState` (unfiltered: an empty map leaves the counter Unknown) | hand |
| `DRepStateReader` | `GetDRepState` (filtered: an empty answer is None, an answer about other DReps only is Unknown), `GetDRepStakeDistr` | captured (state), hand (stake) |
| `CommitteeStateReader` | `GetCommitteeMembersState` filtered by cold or hot credential | hand |
| `ConstitutionReader` | `GetConstitution` | hand |
| `GovActionReader` | `GetProposals`; kind, deposit, return account, anchor, votes, parameter names and security group from the proposal procedure | hand |
| `LastEnactedReader` | `GetRatifyState`, previous-action ids read as four optional ids (parameter update, hard fork, committee, constitution) | hand |
| `StakeDistributionReader` | `GetDRepStakeDistr`, `GetDRepState`, `GetSPOStakeDistr`, `GetStakePoolDefaultVote` (one query per pool), `GetCommitteeMembersState` | hand |
| (extra) `InMempool` | local-tx-monitor `HasTxForEra` | library |
| `TxStatusReader` | `GetUTxOByTxIn` on the transaction's outputs and inputs, then `InMempool`; never "not seen" from outputs | library encodes, hand-written bytes |

Not implemented, because the node cannot answer them: `AssetHolderReader`, `HandleDirectory`, `AssetDatumReader` (asset holders), `PollQuestionReader`, `CalidusKeyReader` (transaction metadata), `PoolUpdateReader` (the time of the last registration update is not ledger state), `VotingSummaryReader` (a node gives the stake distributions to tally from, not a tally), `TxEvaluator` (no script evaluation over node-to-client). `TxStatus` (spec Xconfirm) is built from `InMempool` and the by-reference UTxO query: presence from a transaction's own unspent outputs, absence only from an unspent input that the caller supplies; no block height or depth. Test bytes are hand-written.

## Unverified against a node

* Only one reply of the tests was captured from a real node: `GetDRepState`, copied from the gouroboros tests, which state it came from cardano-cli 11.0.0.0 on a devnet. Everything else rests on the library's decoders and on hand-written bytes. A round trip through the library's server proves little.
* `GetConstitution`, `GetCommitteeMembersState` and `GetRatifyState` are decoded by the library as bare structures, where the other Shelley-era queries are decoded from the one-element array a node wraps results in. If a real node wraps them, those three reads return Unknown (a test pins that); they never return a wrong value.
* The previous-action ids layout (four optional ids in the order parameter update, hard fork, committee, constitution) is recalled from the ledger, not checked. Another shape gives Unknown.
* The parameter-update key names and the security group (maxBlockBodySize, maxTxSize, maxBlockHeaderSize, maxValueSize, maxBlockExecutionUnits, txFeePerByte, txFeeFixed, utxoCostPerByte, govActionDeposit, minFeeRefScriptCostPerByte) are from the key table of the library's `ConwayProtocolParameterUpdate` and CIP-1694. A key without a name leaves the security group Unknown.
* The slot length of the era history is read as milliseconds and bound times as picoseconds. The era-history tests encode them that way themselves.
* Only the Conway era is decoded for protocol parameters; another era is `ErrUnsupportedEra`.
