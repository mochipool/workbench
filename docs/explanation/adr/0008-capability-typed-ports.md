# ADR 0008: One workflow, capability-typed adapters

Status: accepted, 2026-11-16. Refines [ADR 0002](./0002-architecture-and-dependencies.md) and the capability rule of [ADR 0006](./0006-chain-access-providers.md). Closes M5 by design and sets how M4 and X6 are met.

## Context

Upstream has two code paths through most scripts: one for key files, one for hardware wallets. A port that copied this would have a "software workflow" and a "hardware workflow" for every use case, and a third for remote parties.

Holders of keys also differ in what they can sign, and they change at different speeds. A software signer signs a body hash, so it supports a new ledger feature as soon as the body can be built. A hardware wallet parses the transaction, so it supports a feature only when its firmware does, often much later. The same is true of chain providers: each answers a different subset of queries.

If these differences surface as an error from deep inside a signing call, the operator has already built a transaction, typed a passphrase and perhaps asked other parties to sign.

## Decision

### One workflow

A use case is written once, against key references and narrow ports. It never asks where a key is held. Whether a signature comes from the vault, a hardware wallet or a remote party is decided by the signer that holds the key.

### Capability in types, at three levels

1. **Narrow ports, checked by the compiler.** A port is one small interface per capability: `KesKeyGenerator` and `VrfKeyGenerator`, not `KeyGen.Generate(kind)`; `OpCertCounterReader` and `RewardAccountReader`, not one `ChainQuery`. A use case names the interfaces it needs in its fields. Wiring it to an adapter that lacks one does not compile. No port method exists whose honest implementation is "return unsupported".

2. **Typed keys, checked by the compiler.** A key reference carries its role in its type: `custody.Key[custody.PoolCold]`. A function that issues an operational certificate takes that type and cannot be handed a payment key. The role is checked once, where the reference is made (`custody.As`).

3. **Profiles and plans, checked before any effect.** What cannot be known at compile time is which signer holds a given key today and what a given transaction contains. This is data in the domain (`spo/internal/domain/custody`):

   * A signer publishes a **`Profile`**: for each key role, the operations it supports, and for transaction witnessing either "any transaction" or the set of transaction **features** it understands (stake delegation, pool registration as owner, vote, metadata, ...).
   * A workflow states each signature it will need as a **`Demand`**: role, operation and the features of the transaction.
   * **`custody.NewPlan`** checks every demand against the profile of the signer holding the key. It returns either a `Plan` or one error that lists every slot that cannot be signed and why.
   * The step that collects signatures takes a `Plan` as its argument. A `Plan` has no exported fields and no other constructor, so signing code cannot run without the check having passed.

   The plan is made after the draft is known and before the body is finalised, shown, confirmed, sent to a party or sent to a device.

### Consequences for adapters

* A hardware adapter builds its profile from the device and app version it finds when the session opens ([Chw](../../../spec/upstream/common/Chw.md)). A firmware release that adds a feature is a change to a table in that adapter, and to nothing else.
* A remote signer's profile is what the party enrolled for (M7), further limited by policy: a pool cold key is not offered over a network transport ([ADR 0005](./0005-party-envelope-and-signing-policy.md)).
* A profile must agree with the interfaces an adapter implements. A conformance test, run for every signer adapter and again when the binary wires itself, fails when a profile claims an operation whose interface the adapter does not implement.
* Chain providers follow the same rule: narrow reader interfaces, resolved from the configured providers when a command starts. A command whose needs no provider meets stops there, with the missing capability named.
* `spo capabilities` prints the matrix for the current configuration, so an operator can see in advance what a hardware wallet or a provider can take part in.

## Consequences

* Adding a holder (a new device, a KMS) or a provider touches one adapter. No use case changes.
* Adding a ledger feature means adding a `Feature` value and listing it in the profiles that support it. Until a profile lists it, that holder is refused for it, which is the safe default.
* The number of port interfaces grows. They stay small, and each is named after what a use case needs.
