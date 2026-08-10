# Releasing

The workbench is versioned as a **release set**: a single workbench tag pins
one verified-compatible combination of every bundled tool. Users who check out
a workbench tag get tools that are guaranteed to work together — never a
production cardano-node paired with an incompatible hw-cli or script
collection.

## Versioning scheme

Workbench releases are tagged `vMAJOR.MINOR.PATCH`:

- **MAJOR** — a breaking change to the workbench interface itself (flake
  outputs, shell names, `common.inc` contract), or a cardano-node major bump.
- **MINOR** — any tool in the release set moves to a new feature version.
- **PATCH** — patch-level tool bumps, hash refreshes, docs, CI.

## The release set

`versions.nix` is the single source of truth. It declares, for every tool:
the version, the git ref/rev (for flake inputs) or artifact hashes (for
prebuilt binaries).

Two flake checks keep it honest on every system:

- `checks.<system>.version-manifest` — fails if any flake input is locked to
  a revision different from the one declared in `versions.nix` (i.e. someone
  bumped an input without updating the manifest, or vice versa).
- `checks.<system>.spo-compat` — parses the `minCliVersion`,
  `maxCliVersion`, `minNodeVersion`, `maxNodeVersion`,
  `minHardwareCliVersion` and `minCardanoSignerVersion` requirements that the
  SPO scripts enforce at runtime in `00_common.sh`, and fails evaluation if
  any pinned tool violates them.

## Picking compatible versions

1. **cardano-node**: choose the release recommended for mainnet
   (check the [release notes](https://github.com/IntersectMBO/cardano-node/releases)).
2. **cardano-cli**: use the version listed in the cardano-node release notes'
   dependency table. Only diverge to a newer CLI when the SPO scripts require
   it and node release notes do not forbid it.
3. **spo-scripts**: pick the newest `Update-*` tag whose minimum node/cli
   versions (in `cardano/mainnet/00_common.sh`) are satisfied by the pins
   above — `checks.spo-compat` verifies this mechanically.
4. **cardano-hw-cli / cardano-signer**: newest *stable* releases satisfying
   the scripts' minimums. Avoid betas/pre-releases even when newer.

## Cutting a release

```sh
# 1. Update versions.nix (versions, refs, revs, hashes) and the matching
#    input refs in flake.nix. Get artifact hashes with:
#    nix store prefetch-file <release-tarball-url>

# 2. Re-lock the changed inputs
nix flake update cardano-node cardano-cli spo-scripts

# 3. Verify the release set is internally consistent
nix flake check --accept-flake-config

# 4. Smoke-test a shell
nix develop --accept-flake-config .#preview --command bash 00_common.sh

# 5. Commit, tag, push (jj workflow)
jj describe -m "release: vX.Y.Z"
jj bookmark set main -r @
jj git push
git push origin vX.Y.Z   # after: git tag vX.Y.Z <commit>
```

CI re-runs the consistency checks on every supported system and, for tags,
publishes a GitHub release whose notes include the release-set table generated
from `versions.nix`.
