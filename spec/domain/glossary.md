# Glossary

The ubiquitous language of the specs and the reimplementation. When a term has an upstream file or variable name, it is given in parentheses; the domain term is what code and docs use.

| Term | Meaning |
| --- | --- |
| **Anchor** | A URL plus the BLAKE2b-256 hash of the document it serves, attached to DRep certificates, votes and governance actions. |
| **Artefact** | Any persisted, typed piece of operator state: a key, certificate, counter, descriptor, metadata file. Catalogued in [Pfiles](../upstream/patterns/Pfiles.md). |
| **Carry bag** | The air-gap transport: the transfer bundle carried by hand between an online and an offline machine (`offlineTransfer.json`). |
| **Change output** | The output returning the remainder of all inputs, and every asset, to the paying address. |
| **Cold counter** (`<pool>.node.counter`) | The issue counter of operational certificates. It increases on every issue. |
| **Cold key** (`<pool>.node.skey`) | The stake pool's long-term identity key. It signs opcerts and pool certificates. |
| **Committee cold / hot key** (`.cc-cold.*`, `.cc-hot.*`) | A constitutional committee member's long-term credential, and the key it authorises to vote. |
| **Coordinator** | In server mode, the party that builds an unsigned body and collects witnesses. The upstream equivalent is the operator running `05c`. |
| **Deposit / refund** | Lovelaces locked by a registration (stake address, pool, DRep, governance action) and returned on deregistration or expiry. |
| **DRep** | Delegated representative, a governance voter with its own key or script credential. |
| **Envelope** | The cardano-cli *text envelope* JSON (`type`, `description`, `cborHex`). The *encrypted envelope* replaces `cborHex` with `encrHex` (SPO-Ckey-OUT-001). |
| **Era** | The ledger era transactions are built for; normally the node's current era, overridable (`ENV_USEERA`). |
| **Export** | The only way a plaintext secret leaves the vault: named, audited, with a destination. Example: the KES key and opcert bundle for a block producer. |
| **Guardrail script** | The constitution's Plutus script that treasury withdrawals and parameter changes must satisfy (`guardrails-script.plutus`). |
| **Hardware key** (`.hwsfile`) | A key held on a Ledger, Trezor or Keystone device; the file holds only the derivation path and public key. |
| **KES key / KES period** | Key-evolving signature key used by the block producer, valid for a bounded number of KES periods from the opcert's start period. |
| **KES state** | The pair `(current, next)` from `kes.counter` and `kes.counter-next`; see the [domain model](./domain-model.md#pool-operations). |
| **Light mode** | Work mode with online access but no local node: chain reads and submission go through Koios. |
| **Minimum output value** | The smallest lovelace amount an output may carry, a function of its serialised size and `coinsPerUTxOByte`. |
| **Offline mode** | Work mode on an air-gapped machine: chain state comes from a snapshot in the carry bag; transactions are queued, not submitted. |
| **Online mode** (full mode) | Work mode with a local, synced cardano-node. |
| **Operational certificate** (opcert) | A certificate in which the cold key authorises a KES key from a start period with a counter value. |
| **Parity** | The port reproduces every normative requirement of the corpus, or records a decision against an upstream quirk. |
| **Pool descriptor** (`<pool>.pool.json`) | The operator-editable pool configuration, which also stores the witness collection. |
| **Port** | A boundary interface of the application core; see [ports](./ports.md). |
| **Quirk** | Upstream behaviour that looks unintended. It is specified as observed and marked `> **Upstream quirk:**`. |
| **Requirement id** | A stable identifier `SPO-<code>-<KIND>-<NNN>` for one normative fact; see [format](../format.md). |
| **Seal / unseal** | Store secret material encrypted under the vault's key hierarchy; obtain an in-memory handle for one operation. |
| **Signer** | Anything that produces a witness: a vault key, a hardware wallet, a remote party. |
| **Signing request** | In server mode, the message a coordinator sends a signer: body, body hash, expiry, nonce, the slot to fill. Upstream's equivalent is the witness transfer file of `05d`. |
| **Slot** | (1) The chain's time unit. (2) A position in a witness collection waiting for one signer's witness. Context disambiguates. |
| **Snapshot** | The chain state an online machine writes into the carry bag for the offline machine. |
| **Transfer bundle** | The domain object behind `offlineTransfer.json`: snapshot, transaction queue, history, attachments. |
| **TTL** | The transaction's validity end (`--invalid-hereafter`), `tip + defTTL` by default. |
| **Use case** | An application-level operation, such as `RotateKes` or `RegisterPool`. See [use-cases](./use-cases.md). |
| **Witness** | A signature by one key over a transaction body. |
| **Witness collection** | The multi-party signing session for one pool-registration body. |
| **Work mode** | `online`, `light` or `offline`, which in the port becomes a choice of `ChainQuery`, `Submitter` and `Transport` adapters. |
