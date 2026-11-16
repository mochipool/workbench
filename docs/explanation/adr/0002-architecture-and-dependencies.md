# ADR 0002: Architecture and dependencies

Status: accepted, 2026-11-16. Closes C6 and X4; sets the structure that U1 and T1 are tested against.

## Context

The spec corpus already defines bounded contexts, aggregates and ports ([`spec/domain/`](../../../spec/domain/ports.md)). The Go code has to keep that shape checkable, so that an adapter can be replaced without touching a use case.

## Decision

### Layout

```
spo/
  cmd/spo/                 composition root: wires adapters to use cases, nothing else
  internal/
    domain/<context>/      aggregates, value objects, domain events; one package per bounded context
    app/<context>/         use cases; depend on domain and ports only
    ports/                 the port interfaces of spec/domain/ports.md, and their shared types
    adapters/
      native/                                 Blink Labs libraries (KeyGen, Signer, Ledger); ADR 0007
      hwcli/ gpg/                             external tools that remain
      fsstore/                                upstream file layout (Store, Vault)
      sqlitestore/                            sealed single-file store (Store, Vault)
      koios/ utxorpc/ nodesocket/ snapshot/   ChainQuery, Submitter
      filebag/ tailcat/                       Transport
      cli/ tui/                               UI
      toolchain/                              Toolchain
    platform/
      secret/              guarded memory for key material
      execx/               the only package allowed to start a process
      seal/                AEAD, key derivation, envelope encoding
  test/                    fixtures, stand-in tools, differential runner
```

### Dependency rule

`domain` imports nothing from this module except other `domain` packages named as shared kernel. `app` imports `domain` and `ports`. Driven adapters (stores, tools, chain providers, transports) import `ports`, `domain` and `platform`. The two driving adapters, `adapters/cli` and `adapters/tui`, also import `app`, because calling use cases is their job; they import no other adapter. Only `cmd/spo` imports driven adapters. A test (`go list` over the import graph) fails the build when the rule is broken. The same test asserts that `os/exec` is imported only by `platform/execx`, and that the tailcat module is imported only by `adapters/tailcat`.

### Rules that follow from the concerns

* **No shell (X4).** `execx` takes an argument vector. It has no function that accepts a command string.
* **Spec first (C6).** Every test of upstream behaviour cites the requirement ids it covers in a `// spec: SPO-...` comment. A discrepancy found while coding is fixed in `spec/` in the same change.
* **Work mode is wiring.** `cmd/spo` selects `ChainQuery`, `Submitter` and `Transport` adapters once. Use cases declare the capabilities they need, and wiring refuses a use case whose needs are unmet before it has any effect.
* **Errors are values.** Every failure is a returned error with a stable kind. Nothing exits 0 on failure (H3).

### Third-party modules

| Module | Used for | Confined to |
| --- | --- | --- |
| `golang.org/x/crypto` | XChaCha20-Poly1305, Argon2id, HKDF, BLAKE2b | `platform/seal`, `domain` hashing helpers |
| `filippo.io/age` | recipient encryption of exports and envelopes | `platform/seal` |
| `github.com/awnumar/memguard` | locked, guarded buffers | `platform/secret` |
| `modernc.org/sqlite` | pure-Go SQLite, no CGO | `adapters/sqlitestore` |
| `github.com/fxamacker/cbor/v2` | CBOR for envelopes and for reading transaction bodies | `platform/seal`, `adapters`, witness verification |
| `github.com/blinklabs-io/bursa`, `github.com/blinklabs-io/gouroboros` | key generation, envelopes, signing, certificates, ledger types ([ADR 0007](./0007-native-first-with-blink-labs.md)) | `adapters/native` |
| `github.com/tailscale/tailcat` v0.7.0 | first network transport | `adapters/tailcat` |
| `github.com/utxorpc/go-sdk` | UTxO RPC client | `adapters/utxorpc` |
| `github.com/spf13/cobra` | command tree | `adapters/cli`, `cmd/spo` |
| `github.com/charmbracelet/bubbletea` | TUI | `adapters/tui` |

Adding a module is a change to this table. Tailcat requires Go 1.27, so the whole module does; the Nix package takes its Go toolchain from a nixpkgs input that provides it, without moving the release set's own nixpkgs pin.

## Consequences

* The binary is built without CGO and is statically linked.
* Superseded by [ADR 0007](./0007-native-first-with-blink-labs.md): operations on keys and ledger data run in process where Blink Labs' libraries cover them, and cardano-cli is the test oracle.
