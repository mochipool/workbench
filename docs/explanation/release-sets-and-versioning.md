# Release sets and versioning

This page explains why the workbench versions its tools together as a release set, why some pins are per platform, and why the checks are built the way they are.

## The problem

An operator needs a node, a CLI, a script collection and signing tools that work together. These projects release independently. The SPO scripts refuse to run when cardano-cli, cardano-node, cardano-hw-cli or cardano-signer is outside the range they enforce, and hardware wallets need minimum firmware. A tool that was fine yesterday can be the wrong one today, and the failure shows up on the operator's machine, possibly in the middle of a key rotation.

## Lockstep

The workbench therefore treats the combination as the unit of release. A tag pins one verified-compatible set, and `versions.nix` is the single place that names it. Someone who checks out a tag gets tools that were known to work together, and never, for example, a production node paired with a script collection that rejects it.

The cost is latency. The workbench cannot move faster than its slowest verified member, and a new cardano-node release needs a deliberate bump even when nothing else changes. For software that handles keys and pool registrations, that is the intended trade.

Choices follow a simple rule. Use the node release recommended for mainnet. Use the CLI version from that node's release notes, diverging only when the scripts require a newer one and the notes do not forbid it. Choose the newest scripts tag whose requirements the pins satisfy. For prebuilt tools take the newest stable release that meets the scripts' minimum, and avoid betas.

The version number says what kind of change a user will see. A major bump signals a break in the workbench's own interface or a node major. A minor bump means a tool moved to a new feature version. A patch covers patch-level bumps, hash refreshes, docs and CI.

## Why the checks exist

Three facts are duplicated by necessity: the flake input refs, the locked revisions, and the numbers in `versions.nix`. Duplication invites drift, so each is mechanically checked.

* `version-manifest` catches an input bumped without the manifest, and the reverse.
* `spo-compat` reads the scripts' own minimum and maximum variables rather than copying them into the repository. The upstream scripts stay authoritative, and an incompatible pin fails evaluation instead of failing at run time.
* `readme-sync` keeps the published requirements table equal to what the other checks enforce.

All three read text only and never build the Haskell packages. A check that needs cardano-cli would be slow on every platform and would not complete on `aarch64-linux`, where no native upstream cache exists. Cheap checks run on every commit and every system, so they actually get run.

## Per-platform hw-cli pins

cardano-hw-cli is a prebuilt binary, so a defective upstream artifact for one platform would otherwise hold back the whole set. Releases 1.18.2 through 1.19.1 shipped a broken `linux-arm64` artifact: an incomplete `pkg` snapshot that crashed at startup. For a while the workbench pinned `linux-arm64` to 1.19.0, which worked, while the other platforms moved on. `versions.nix` records the fix as landing in 1.20.0, and all platforms are now pinned to 1.20.0.

The manifest still has one entry per platform. This keeps the next such defect from forcing a choice between dropping a platform and holding everyone back. Because the pins can diverge, `spo-compat` validates every platform's version against the scripts' minimum, not only the nominal one. The nominal `version` field is used where a single value is needed, such as the autocomplete script.

## Device requirements are outside the set

The Ledger app, Trezor firmware and Keystone firmware versions live on the hardware, and the flake cannot pin them. The workbench instead reads the scripts' minimums for display in the readme, and `workbench-doctor` compares them with the connected device. The set is thus complete for software and explicit about what remains the operator's responsibility.

## Related pages

* [Release set reference](../reference/release-set.md)
* [Cut a release](../how-to/cut-a-release.md)
* [Architecture](./architecture.md)
