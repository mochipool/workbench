# Domain model

The model a reimplementation is built on. It is derived from the upstream specs, not from the Bash: every invariant below cites the requirement ids it comes from, so a test can check the aggregate against upstream behaviour. Terms are defined in the [glossary](./glossary.md); contexts in the [context map](./context-map.md); boundaries in [ports](./ports.md).

The upstream scripts have no explicit model. State is implicit in which files exist, and every script re-derives it. The port should make that state explicit: one aggregate per consistency boundary, mutated only through its own operations, persisted atomically by the `Store` port.

## Design rules

1. **Use cases depend on ports only.** A use case never knows whether keys live in files, SQLite, PostgreSQL or a hardware wallet, nor whether chain state comes from a node, Koios or a snapshot.
2. **Work mode is adapter selection, not branching.** Upstream has `online` / `light` / `offline` branches in nearly every script. The port selects `ChainQuery`, `Submitter` and `Transport` adapters once, at composition time. A use case that cannot run without chain access declares it; the composition root refuses to wire it in offline mode.
3. **Secrets never cross a port in plaintext.** `Vault` returns handles. Only `Signer` and the explicit `Vault.exportPlaintext` touch key material. This generalises upstream's best property (SPO-Ptx-SEC-001: keys reach cardano-cli through an anonymous pipe) and removes its weakest (SPO-Pfiles-SEC-002: plaintext `.skey` files are the default).
4. **Aggregates enforce invariants; scripts only checked them.** Upstream refuses an invalid operation at run time, often after side effects (SPO-04c-OUT-001). Aggregates make the operation unrepresentable, or atomic.
5. **Parity is behavioural.** The port reproduces every normative requirement, including refusals and their meaning. It is not bound to exit codes or message text. Where upstream behaviour is an *Upstream quirk*, the port records a decision: reproduce it, fix it, or make it configurable. The decision is recorded in the use case's test, citing the id.

## Aggregates by context

### `pool-operations`

**`StakePool`** (root), identified by the pool id (hash of the cold verification key).

| Part | Kind | Notes |
| --- | --- | --- |
| `ColdKey` | key reference (vault or hardware) | never online in the recommended setup |
| `ColdCounter` | entity | the opcert issue counter (`node.counter`) |
| `VrfKey` | key reference | |
| `KesState` | value object | `current` (newest generated key number), `next` (number the next key must have) |
| `KesKey[n]` | key references, numbered | |
| `OperationalCertificate[n]` | entities | `(kesKey n, counter, startPeriod)` |
| `PoolRegistration` | entity | the descriptor (`pool.json`), see below |

Invariants:

* **KES rotation is a two-step state machine.** Generation requires `current < next` and sets `current := next` (SPO-04c-PRE-001, SPO-04c-OUT-003). Issuing an opcert for key `current` sets `next := current + 1` (SPO-04d-OUT-003). Generating twice without an opcert in between is refused.
* **Every opcert issue increments the cold counter**, so issuing is not idempotent and must not be retried blindly. See [04d](../upstream/scripts/04d_genNodeOpCert.md) and the handoff Gotchas.
* **The on-chain counter gates issue.** The new opcert's counter must exceed the counter of the last block the pool made. In light mode upstream reads an unanswered Koios query as "no block made yet" (SPO-04d-SEC-003, SPO-04d-MODE-003). The port must treat "unknown" as distinct from "none".

**`PoolRegistration`**: the pool descriptor (pledge, cost, margin, owners, reward account, relays, metadata URL and hash) and its lifecycle *Draft → CertificateIssued → (Collecting witnesses) → Registered → (Updated)* → *RetirementScheduled → Retired*. The full descriptor schema is in [05a](../upstream/scripts/05a_genStakepoolCert.md). The deposit is paid only on first registration; re-registration is detected per work mode ([05c](../upstream/scripts/05c_regStakepoolCert.md), SPO-05c-MODE-001 to SPO-05c-MODE-003).

**`WitnessCollection`**: the multi-party signing session for a pool registration (SPO-05c-OUT-002, SPO-05c-INV-005).

| State | Entered by |
| --- | --- |
| `Absent` | initial; after `Submitted` or `Discarded` |
| `OpenIncomplete` | created by `RegisterPool` with at least one slot unsigned |
| `OpenComplete` | the last slot's witness imported |
| `Expired` | the chain tip passes the body's TTL (derived, no write; SPO-05d-INV-003) |
| `Submitted` | the assembled transaction submitted or queued |
| `Discarded` | an explicit clear (SPO-05d-INV-001) |

Each slot is `(role, keyHash, signerAssignment, witness?)`. Upstream checks only textual equality of the request id, type, pool and signer (SPO-05d-INV-005). It does not check that a witness is a valid signature by the slot's key over the stored body (SPO-05d-INV-006). The port must check this on import. Only owner stake-key slots are signable through the upstream flow (SPO-05d-INV-007).

### `stake-delegation`

**`StakeAccount`** (root), identified by the stake address. State: `Unregistered → Registered(deposit) → Delegated(pool?, drep?) → Deregistered(refund)`. Registration takes the deposit from protocol parameters ([03b](../upstream/scripts/03b_regStakingAddrCert.md)); deregistration refunds the deposit recorded in the certificate ([08b](../upstream/scripts/08b_deregStakingAddrCert.md)). Pool delegation ([06](../upstream/scripts/06_regDelegationCert.md)) and vote delegation ([22b](../upstream/scripts/22b_regVoteDelegCert.md)) require `Registered`.

### `wallet`

**`PaymentAccount`** (root): a payment credential, optionally paired with a `StakeAccount` (a base address), backed by a key reference or a hardware key. Its balance is a projection of chain state, never stored as truth. Upstream spends **every UTxO** of the address in each transaction: there is no coin selection (SPO-Ptx-INV-002). Parity means reproducing this by default; a selection strategy is a port extension.

### `transaction-construction` (shared kernel)

**`TxDraft`** → **`TxBody`** → **`SignedTx`**, the pipeline of [Ptx](../upstream/patterns/Ptx.md):

* `TxDraft` gathers intent: inputs (all UTxOs, filtered by `Pparam` tokens), outputs, certificates, withdrawals, votes, proposals, metadata, mint, and the required signers.
* `TxBody` is fixed by a fee computed with a constant witness count per script (SPO-Ptx-INV-006) and a TTL of `tip + defTTL` (SPO-Ptx-INV-001). Change returns every asset to the payer (SPO-Ptx-INV-004, SPO-Ptx-INV-007).
* `SignedTx` is built from the exact body the operator confirmed (SPO-Ptx-INV-010). Nothing is rebuilt after confirmation.

Value objects: `Lovelace` (integer, never float; upstream uses `bc`), `AssetId` (policy id + hex name), `MultiAsset`, `MinOutputValue` (the Babbage+ size rule, SPO-Cutxo-INV-005 to SPO-Cutxo-INV-007; verify against the ledger before relying on it, see the open question in [Cutxo](../upstream/common/Cutxo.md)).

### `governance`

* **`DRep`**: key or script credential; `Registered(deposit, anchor) → Updated(anchor) → Retired(refund)`. The refund is the deposit in the on-chain DRep state ([21b](../upstream/scripts/21b_regDRepCert.md), [21d](../upstream/scripts/21d_retDRepCert.md)).
* **`CommitteeMember`**: a cold credential with an authorised hot credential; `Authorised(hot) → Resigned` ([23c](../upstream/scripts/23c_regComAuthCert.md), [23e](../upstream/scripts/23e_retComColdKeys.md)). Upstream refuses both operations in offline mode.
* **`Vote`**: `(voterRole, voterCredential, actionId, decision, anchor?)`. Which role may vote on which action type is a rule of [24a](../upstream/scripts/24a_genVote.md).
* **`GovernanceAction`**: one of seven kinds, with deposit, return address, anchor and a previous-action chain ([25a](../upstream/scripts/25a_genAction.md)). Treasury withdrawal and parameter change may need the guardrail script ([25b](../upstream/scripts/25b_regAction.md)).
* **`Tally`** (read model): the derived DRep, SPO and committee percentages and thresholds of [24c](../upstream/scripts/24c_queryVote.md) (SPO-24c-OUT-001 to SPO-24c-OUT-005). A projection only; it never gates a transaction.

### `native-assets`

**`Policy`** (native script: key hash, optional `before` slot) and **`Asset`** (policy + name, with a local record of minted and burned amounts and registry metadata). Upstream updates the local record when an offline transaction is queued, not when it is submitted ([11a](../upstream/scripts/11a_mintAsset.md)). The port should update on confirmation of submission, through a domain event.

### `air-gap-transfer`

**`TransferBundle`**: the chain snapshot (protocol parameters, era, tip, address UTxOs, reward accounts, DRep state), the queue of signed transactions, the history, and attached files ([Ptransfer](../upstream/patterns/Ptransfer.md)). `new` resets it entirely. `execute n` submits entry *n* and removes it on success. The bundle holds no signing keys but does hold balances and signed transactions (SPO-Ptransfer-SEC-002). Upstream rewrites it non-atomically with no lock (SPO-Ptransfer-INV-002), and `extract` trusts stored paths (SPO-Ptransfer-SEC-001).

### `key-custody`

**`KeyRef`**: a reference to a key that a `Signer` can use. Kinds: `VaultKey(sealed)`, `HardwareKey(derivationPath, vkey)`, `RemoteKey(party, keyHash)`. The upstream hardware marker is a vkey whose description contains `Hardware` (SPO-Pfiles-INV-001); upstream selects the signer from which key file exists (SPO-Pfiles-INV-002).

Upstream protection levels, in increasing order: plaintext `.skey` at mode `0400`, a gpg-wrapped envelope (SPO-Ckey-OUT-001), hardware. The port's floor is the sealed vault: the first level does not exist as a stored state, only as an audited export.

## Domain events

Events are the seam for audit, projections and multi-party coordination. Each is emitted by the aggregate that changes, after the `Store` commit.

| Event | Emitted by | Consumers |
| --- | --- | --- |
| `KesKeyGenerated(pool, n)` | `StakePool` | audit; KES expiry projection |
| `OperationalCertificateIssued(pool, n, counter, startPeriod)` | `StakePool` | export to block producer; audit |
| `WitnessRequested(collection, slot, party)` | `WitnessCollection` | `Transport` (file bag or secure channel) |
| `WitnessImported(collection, slot)` / `CollectionCompleted` / `CollectionExpired` | `WitnessCollection` | coordinator UI; submission |
| `TransactionConfirmed(body hash)` | use case | audit (the human approval record) |
| `TransactionSubmitted(txId)` / `TransactionQueued(bundle, n)` | `Submitter`, `Transport` | asset records, history |
| `KeyExported(keyRef, destination, reason)` | `Vault` | audit (mandatory) |
| `SnapshotTaken(bundle, tip)` | `TransferBundle` | offline machine |

## Read models

These are projections the UI shows and nothing writes back: balances (`01_queryAddress`), KES expiry and opcert validity (`04e`), pool, DRep and committee on-chain status (`05e`, `21c`, `23d`), vote tallies (`24c`), asset registry state (`12b`).
