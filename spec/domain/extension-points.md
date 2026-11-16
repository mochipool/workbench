# Extension points

How the planned additions attach to the model without breaking parity. This page is design guidance, not upstream behaviour: it has no requirement ids. It cites the upstream requirements each extension replaces or must preserve. The decisions it leaves open are the Phase 0 questions of [Roadmap: native port](../../docs/development/roadmap-native-port.md#open-questions-phase-0).

The rule for every extension: **the application core does not change.** An extension is a new adapter behind an existing port, or a new use case composed from existing ones. If an extension needs a core change, the model is wrong; fix the model first.

## 1. Encryption by default

| Upstream | Port |
| --- | --- |
| Plaintext `.skey` at mode `0400` is the default; `enc` is opt-in per run (SPO-Pfiles-SEC-002) | `Vault` stores only sealed keys; "plaintext" exists only as `Vault.exportPlaintext` |
| gpg symmetric AES-256 per key, passphrase on gpg's command line (SPO-Ckey-OUT-001, SPO-Ckey-SEC-001) | Envelope encryption: a data key per record under an AEAD cipher, wrapped by a key-encryption key derived from a passphrase (Argon2id) or held by a token |
| The envelope's `type` and `description` are not authenticated (SPO-Ckey-SEC-004) | Associated data binds each ciphertext to its record id, key kind and owner |
| Mnemonics printed to stdout (SPO-Pfiles-SEC-003) | Mnemonics are sealed at creation; display is an explicit, audited export |
| Decrypted keys reach cardano-cli through an anonymous pipe (SPO-Ptx-SEC-001) | Kept: `Signer` adapters hand plaintext to cardano-cli through a pipe or `memfd`, never a file |

**Import parity.** `Vault` must read every upstream format: plaintext envelopes, gpg envelopes (SPO-Ckey-INV-003), and passwords containing backslashes as upstream `ask_pass` mangles them (see [Ckey](../upstream/common/Ckey.md) and [Cui](../upstream/common/Cui.md)). Import seals on the way in.

**Which non-secret data is sensitive** (owner relationships, wallet inventory, balances in the transfer bundle, SPO-Ptransfer-SEC-002) is Phase 0 question 3. The `Store` port is written so that sealing a table is an adapter concern.

## 2. Storage back ends

The `Store` and `Vault` ports are typed by artefact, not by file name. [Pfiles](../upstream/patterns/Pfiles.md) is the contract of one adapter.

| Adapter | Use | Notes |
| --- | --- | --- |
| File system, upstream layout | Parity tests, import and export, operators who want plain files | Reproduces names and modes (SPO-Pfiles-INV-003 to SPO-Pfiles-INV-005); `lock` maps to `chmod 400` |
| SQLite, single file | Default local workspace | Store and vault in one file; whole-database encryption (SQLCipher) or per-record sealing, a Phase 0 decision |
| PostgreSQL | Server mode, several operators, Kubernetes | Vault records sealed client-side; the database never sees a key-encryption key; row-level security per tenant |

All adapters must give the aggregates **atomic multi-artefact writes**. Upstream has none: it leaves orphans on failure (SPO-04c-PRE-004) and rewrites the transfer file with no lock (SPO-Ptransfer-INV-002). An adapter that cannot commit a `StakePool` change atomically does not satisfy the port.

The **audit log** (exports, confirmations, signatures, imports) lives in `Store` and is append-only. In PostgreSQL it can be a separate role-restricted table; in SQLite, a hash-chained table.

## 3. Multi-party and remote signing

The upstream multi-party flow is [05c](../upstream/scripts/05c_regStakepoolCert.md) plus [05d](../upstream/scripts/05d_poolWitness.md): a witness collection in the pool descriptor, and witness transfer files carried between people. The port turns it into request and response over `Transport`:

```
Coordinator (online)                         Signer client (each party; may be air-gapped or hold a HW wallet)
────────────────────                         ─────────────────────────────────────────────────────────────
RegisterPool builds body, opens
WitnessCollection (slots by key hash) ──SigningRequest{body, bodyHash, ttl, nonce, slot}──▶
                                             decode body with its own Ledger adapter (never trust a summary)
                                             show certificates, deposit, outputs, fee, TTL; operator approves
                                             Signer.witness(body, keyRef)  ← vault key or hardware wallet
                                  ◀──SigningResponse{nonce, slot, witness}──
verify witness: signature valid over body,
key hash == slot key hash; fill slot
all slots filled → assemble → Submitter
```

What the port adds over upstream, each closing a gap the specs record:

| Gap upstream | Port behaviour |
| --- | --- |
| Imported witnesses are not verified (SPO-05d-INV-006, SPO-05d-SEC-003) | Coordinator verifies signature and key hash before touching the slot |
| The signer sees no decoded transaction (SPO-05d-INV-008) | Signer decodes the body locally and requires explicit approval |
| Anyone who alters the transfer file can change what is signed (SPO-05d-SEC-002) | Requests are authenticated end to end; the signer recomputes the body hash |
| Only owner stake-key slots are signable (SPO-05d-INV-007) | Every slot (owner, payer, cold key) is a request to its assigned party |
| A clear leaves no trace (SPO-05d-INV-001) | Every transition is an audited domain event |
| The window is implicit in the TTL (SPO-05d-INV-003) | Expiry is a state; signers refuse expired requests; requests carry an expiry and a nonce, and signers keep a replay log |

**Hardware wallets on the client.** A signer client runs the `Signer` hardware adapter locally (cardano-hw-cli), so the device never leaves its owner. The body sent to the device must be in hardware-canonical form ([Ctx](../upstream/common/Ctx.md)); the coordinator canonicalises before hashing, so the hash the signer verifies is the hash the device signs.

**Air-gapped parties** keep the file `Transport`: the request and response are the same messages, serialised to a file, so remote and carried signing share one code path. Which key classes may sign remotely is Phase 0 question 6; the default keeps pool cold keys air-gapped.

**Channel.** Mutual authentication with pinned keys (Noise or mTLS) over a private network (Phase 0 question 5). The transport is untrusted for integrity even when authenticated: every response is verified as above.

## 4. Deployment shapes

The same core and ports, composed differently:

| Shape | Composition |
| --- | --- |
| Single operator, laptop | CLI or TUI `UI`, SQLite store and vault, node-socket or Koios `ChainQuery`, file `Transport` for the cold machine |
| Air-gapped cold machine | Offline: snapshot `ChainQuery`, queue-to-transport `Submitter`, SQLite vault. The composition root refuses use cases that need live chain access, as upstream does per mode |
| Coordinator service | Server API `UI`, PostgreSQL store, node-socket `ChainQuery` and `Submitter`, secure-channel `Transport`. **No vault holding party keys**: the coordinator only collects witnesses |
| Signer client | CLI or TUI, local vault or hardware `Signer`, secure-channel or file `Transport` |
| Kubernetes | Coordinator replicas over PostgreSQL. Witness collections and request state live in the store, not in memory, so any replica serves a response. The node runs as a sidecar or a separate service; secrets for the coordinator's own TLS identity come from the cluster's secret store |

## 5. Front ends

`UI` is a port; CLI, TUI and the server API are adapters over the same use cases. Prompts that gate effects are specified as `PR` requirements with their defaults (for example SPO-04c-PR-001). Each becomes a `UI.confirm` or `UI.askPassword` call. Upstream's `ENV_SKIP_PROMPT` skips only some final confirmations, in some scripts (SPO-Ptx-SEC-003). The port replaces it with an explicit, per-use-case, audited non-interactive policy.

## 6. Keeping extensions honest

* An extension may **strengthen** a requirement (verify, seal, audit) but must not silently **weaken** one. If it relaxes a refusal, record it as a decision against that id.
* Differential parity tests run with the file-system adapters and upstream key formats, so encryption and storage choices cannot hide a behavioural drift.
* Every requirement id the upgrade worksheet (`specctl hunks`) marks as changed re-runs the tests that cite it, whatever adapters an extension uses.
