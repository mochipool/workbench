# Upstream specification corpus

A behavioural specification of [gitmachtl/scripts](https://github.com/gitmachtl/scripts) at the tag pinned in [`UPSTREAM.toml`](./UPSTREAM.toml). It is written so that a person or an agent can build a functionally equivalent implementation **without reading the Bash**, and can absorb an upstream release **without redoing the analysis**.

External tools stay external: cardano-node, cardano-cli, cardano-hw-cli, cardano-signer, bech32, gpg and the HTTP services are pinned by the flake and appear here only as the contracts the scripts rely on.

This corpus is Phase 1 of [Roadmap: native port](../docs/development/roadmap-native-port.md).

## Layout

| Path | Contents |
| --- | --- |
| [`format.md`](./format.md) | The spec contract: front matter, requirement ids, source references, section order, parity scope. **Read first.** |
| [`UPSTREAM.toml`](./UPSTREAM.toml) | Pinned upstream repo, tag, rev. Must match the `spo-scripts` flake input. |
| [`upstream/common/`](./upstream/common/) | One spec per group of `00_common.sh` functions (`C*` codes). Every function is owned by exactly one group. |
| [`upstream/patterns/`](./upstream/patterns/) | Behaviour shared by many scripts: the transaction pipeline (`Ptx`), the extra-parameter grammar (`Pparam`), workspace artefacts (`Pfiles`), the transfer file (`Ptransfer`). |
| [`upstream/scripts/`](./upstream/scripts/) | One spec per upstream script, named after the script stem. |
| [`domain/`](./domain/) | The model the reimplementation is built on: bounded contexts, glossary, aggregates, ports, use cases with traceability to requirement ids, and extension points (encryption, multi-party signing, storage back ends). |
| [`tools/specctl.py`](./tools/specctl.py) | Mechanical checks and upgrade tooling. Standard library only. |

## Reading order for an implementer

1. [`domain/context-map.md`](./domain/context-map.md), then [`domain/domain-model.md`](./domain/domain-model.md) for the shape of the system.
2. [`domain/ports.md`](./domain/ports.md) for the boundary. The use cases depend on ports only.
3. [`upstream/patterns/Ptx.md`](./upstream/patterns/Ptx.md), because most scripts are an instance of it.
4. [`domain/use-cases.md`](./domain/use-cases.md) to pick a use case, then the script specs it lists.

A use case is at parity when every requirement id its specs list has a passing test that cites the id.

## How requirements map to source

Every requirement ends with `(src: Lx-Ly)` ranges into the pinned upstream file. That gives three properties:

* **Traceable.** Any statement can be checked against the exact upstream lines.
* **Diff-addressable.** An upstream hunk maps to the ids whose ranges it overlaps (`specctl hunks`).
* **Hash-pinned.** Each script spec records its file's SHA-256, and each common spec records a hash per function it owns. A change anywhere is detected without reading anything.

## Absorbing an upstream release

When `spo-scripts` moves to a new tag (see also [Cut a release](../docs/how-to/cut-a-release.md)):

```sh
export OLD=$(nix eval --raw --impure --expr '(builtins.getFlake (toString ./.)).inputs.spo-scripts.outPath')
# bump the flake input, then:
export NEW=$(nix eval --raw --impure --expr '(builtins.getFlake (toString ./.)).inputs.spo-scripts.outPath')

python3 spec/tools/specctl.py drift --upstream "$NEW"              # what is stale: files, functions, dependants, mechanical facts
python3 spec/tools/specctl.py hunks --old "$OLD" --new "$NEW" > hunks.md   # every hunk, with the ids it touches
```

Then work through `hunks.md`:

1. Classify each hunk as **behaviour**, **no-effect** or **cosmetic** (see the parity scope in [`format.md`](./format.md)).
2. For a **behaviour** hunk, edit the listed requirements. Add new ids for new behaviour. Mark removed behaviour `~~withdrawn~~ in <tag>`; never delete or renumber an id. Flag the affected tests.
3. For a hunk marked *unmapped*, decide whether it adds behaviour (new ids) or sits in a region no requirement covers (no-effect or cosmetic).
4. Run `specctl gaps <file>` on each changed file: uncited new code is either new behaviour (add ids) or display.
5. Re-run `specctl facts <file>` for every changed file and paste the new mechanical facts and hashes into its front matter.
6. Shift `(src: ...)` ranges in every changed file to the new line numbers. Ranges in unchanged files stay valid.
7. Update `UPSTREAM.toml`, and `upstream_tag` in every spec.
8. Run `specctl index` and `specctl lint`. The upgrade is done when lint is clean and no hunk is unclassified. Keep the classified `hunks.md` in the change description as the audit trail.

A `00_common.sh` function change is reported once, with every script spec that uses the function (`uses_common`). Re-check those scripts' requirements that cite the common requirement.

The worksheet is designed to be split: each changed file is an independent unit an agent can classify.

## Checks

```sh
export SPO_SCRIPTS_SRC=<path to the pinned gitmachtl/scripts tree>
python3 spec/tools/specctl.py lint       # zero errors required
python3 spec/tools/specctl.py ids        # every requirement id, for the test coverage check
python3 spec/tools/specctl.py gaps [FILE] # code lines no requirement cites (review aid; display code is expected)
python3 spec/tools/specctl.py coverage --tests spo --config spo/spec-coverage.toml  # every requirement of an implemented spec cited or waived
python3 spec/tools/specctl.py index      # regenerate domain/use-cases.md after changing front matter
```

At the pinned tag, about 95% of non-display upstream code lines are cited by some requirement. Most of the rest is display, usage text and loop scaffolding.

`nix flake check` runs `checks.<system>.spec-lint` against the pinned input, so a stale hash, a bad range, a duplicate id, an undefined cross-reference, an uncovered upstream file or an unowned common function fails the build.

`coverage` reads the specs listed under `implemented` in `spo/spec-coverage.toml` and fails when one of their requirements (withdrawn ones excepted) is cited by no `// spec: SPO-...` comment in a `*_test.go` file and has no entry under `[waived]`; `checks.<system>.spo-spec-coverage` runs it.

What lint verifies mechanically:

* front matter parses, and the tag matches `UPSTREAM.toml`, which matches the flake input;
* file SHA-256 and per-function hashes;
* the extracted facts: common functions used, cardano-cli, cardano-hw-cli and cardano-signer subcommands, HTTP endpoints, `ENV_*` variables;
* every id is well-formed, unique, and uses its spec's code;
* every source range lies inside its file;
* every cross-referenced id exists;
* every upstream script has a spec (an identical testnet twin counts as covered), and every common function has an owner.

What lint cannot verify, and review must: that the prose is true, that ranges are tight, and that nothing normative is missing.
