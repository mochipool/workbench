# Agent notes

- **Picking up work** on `orchestrator/`, `tools/workbench.nix` or `docs/`: read [docs/development/handoff.md](docs/development/handoff.md) first. It covers the current state, verification commands, backlog, and the upstream-script gotchas the code depends on.
- **Planning the native port**, the encrypted single-file store, remote signing or the TUI: read [docs/development/roadmap-native-port.md](docs/development/roadmap-native-port.md).
- **Upstream behaviour** (what a `gitmachtl/scripts` script does, or implementing an equivalent): read [spec/README.md](spec/README.md). The corpus specifies every script with stable requirement ids; never re-derive behaviour from the Bash without updating it.
- **Bumping `spo-scripts`**: re-run the real-script e2e test described in the handoff, and check its Gotchas list against the new upstream tag. Then absorb the release into `spec/` with `specctl drift` and `specctl hunks` (see [spec/README.md](spec/README.md#absorbing-an-upstream-release)); `nix flake check` fails until the corpus matches the new tag.
