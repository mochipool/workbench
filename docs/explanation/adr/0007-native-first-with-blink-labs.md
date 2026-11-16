# ADR 0007: Native first, with Blink Labs' libraries

Status: accepted, 2026-11-16. Supersedes decision D2 in part and the last consequence of [ADR 0002](./0002-architecture-and-dependencies.md). Closes the X2 finding on KES and VRF key generation.

## Context

Decision D2 kept every Cardano tool external, so `spo` was one Go binary that drove cardano-cli, cardano-signer and bech32. Two things followed from that:

* Every signature meant handing a plaintext key to a child process. cardano-cli 11.2.3.0 cannot even write KES or VRF keys to a pipe, which forced a temporary file.
* The binary was only usable where the whole Haskell toolchain was installed.

Blink Labs publishes Go libraries that cover the same ground: `gouroboros` (ledger types, CBOR, KES, VRF) and `bursa` (key derivation and generation, text envelopes, witnesses, operational certificates, pool certificates, CIP-8 message signing). Both are Apache-2.0 and pre-1.0, as all Blink Labs releases are.

## Decision

* **Operations on keys and ledger data run in process**, through `bursa` and `gouroboros`, wherever those libraries cover the operation. The goal is a single static binary that needs no other Cardano tool for software-key workflows.
* **The pinned cardano-cli becomes the oracle.** It stays in the release set and in the test derivations. It is not on the path of a native operation at run time.
* **Parity is proven where it matters most**, by differential tests against the oracle, before a native operation replaces a tool:

  | Operation | Test against cardano-cli |
  | --- | --- |
  | Key generation | cardano-cli derives the same verification key from the native signing key; envelopes match what `key-gen` writes |
  | Witness and signature | cardano-cli assembles a transaction from a native witness; the witness verifies; the same body and key give the same signature |
  | Operational certificate | byte-equal to cardano-cli's for the same inputs |
  | Certificates, transaction bodies, fees, minimum output | byte-equal bodies and equal values for the same inputs, over a corpus of fixtures |
  | Hashes and identifiers | equal to cardano-cli's |

  Less than full conformance to the reference is acceptable elsewhere, when the difference is recorded in the test that finds it.
* **Confinement.** `github.com/blinklabs-io/...` is imported only by `spo/internal/adapters/native`; `archtest` enforces it. Versions are pinned through `go.sum` and the Nix `vendorHash`. An upgrade re-runs the parity checks.
* **What stays external for now:**
  * hardware wallets, through cardano-hw-cli, until a Go path to the devices is evaluated;
  * gpg, only to read and write upstream `enc` key files (X5);
  * anything the libraries do not cover yet. Such an operation keeps its tool adapter behind the same port, and the capability is reported by `spo toolchain check`.

## Consequences

* A signing key no longer leaves the process for software-key signing. This is a larger security gain than any handling rule around a child process.
* Native secrets pass through library code that uses ordinary Go memory. A key is in guarded memory at rest in the process and while it crosses a port, but the libraries hold hex strings and byte slices that cannot all be wiped. Concern E4's test on heap contents has to account for this, and the residual exposure goes in the threat model.
* A pre-1.0 library is on the signing path. The parity suite and the pinned versions are the control.
* The tool adapters that remain (`execx`, the toolchain manifest) are still needed for hardware wallets, gpg and the oracle.
