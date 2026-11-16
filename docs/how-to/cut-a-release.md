# Cut a release

This guide shows how to update the release set, verify it and publish a workbench tag.

## Prerequisites

* Push rights to the repository. The project uses [jj](https://jj-vcs.github.io/jj/) colocated with git.
* The versions you intend to pin, chosen as described in the next section.
* Background on why releases work this way: [Release sets and versioning](../explanation/release-sets-and-versioning.md).

## Choose compatible versions

1. cardano-node: pick the release recommended for mainnet in its [release notes](https://github.com/IntersectMBO/cardano-node/releases).
2. cardano-cli: use the version in the node release notes' dependency table. Diverge to a newer CLI only when the SPO scripts require it and the node release notes do not forbid it.
3. spo-scripts: pick the newest `Update-*` tag whose minimum node and CLI versions in `cardano/mainnet/00_common.sh` the pins above satisfy.
4. cardano-hw-cli and cardano-signer: the newest stable releases that satisfy the scripts' minimums. Skip betas and pre-releases.
5. trezorctl: bump `versions.nix` and refresh the hash:

   ```sh
   nix store prefetch-file https://files.pythonhosted.org/packages/source/t/trezor/trezor-<ver>.tar.gz
   ```

   Stay on a version the flake's nixpkgs can satisfy. Releases from 0.20.2 need `cryptography >= 47`.

## Pick the version number

Tags are `vMAJOR.MINOR.PATCH`.

* MAJOR: a breaking change to flake outputs, shell names or the `common.inc` contract, or a cardano-node major bump.
* MINOR: any tool in the release set moves to a new feature version.
* PATCH: patch-level tool bumps, hash refreshes, docs and CI.

## Steps

1. Update `versions.nix` (versions, refs, revs, hashes) and the matching input refs in `flake.nix`. Get artifact hashes with:

   ```sh
   nix store prefetch-file <release-tarball-url>
   ```

2. Re-lock the changed inputs:

   ```sh
   nix flake update cardano-node cardano-cli spo-scripts
   ```

3. Regenerate the requirements table in `readme.md`:

   ```sh
   nix run --accept-flake-config .#update-readme
   ```

4. Verify the release set is consistent:

   ```sh
   nix flake check --accept-flake-config
   ```

5. Smoke-test a shell:

   ```sh
   nix develop --accept-flake-config .#preview --command bash 00_common.sh
   ```

6. Commit, tag and push:

   ```sh
   jj describe -m "release: vX.Y.Z"
   jj bookmark set main -r @
   jj git push
   git tag vX.Y.Z <commit>
   git push origin vX.Y.Z
   ```

CI re-runs the consistency checks on every supported system. For tags it also publishes a GitHub release whose notes contain a release-set table (tool and version) generated from `versions.nix`.

## If a check fails

* `version-manifest`: a flake input is locked to a different revision than `versions.nix` declares. Fix the `rev` in `versions.nix` or re-lock the input.
* `spo-compat`: a pinned tool violates a minimum or maximum the scripts enforce. Pick a compatible version or a different spo-scripts tag.
* `readme-sync`: the generated block in `readme.md` is stale. Rerun step 3.

The checks are described in [Release set](../reference/release-set.md).
