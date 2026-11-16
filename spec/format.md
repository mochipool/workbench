# Spec format

This is the contract every file under `spec/upstream/` follows. `spec/tools/specctl.py lint` enforces the mechanical parts. Reviewers enforce the rest.

## What a spec is for

A spec records what an upstream script **does**: the observable behaviour that a reimplementation has to reproduce to be at parity. It does not record **how** the Bash does it. Three readers use it:

1. **An implementer** builds a functionally equivalent use case behind ports (see [`domain/`](./domain/)) without reading the Bash.
2. **A test author** writes a test per requirement id and cites the id in the test.
3. **An upgrade agent** maps an upstream diff hunk to the requirement ids it touches (`specctl hunks`) and edits only those.

## Parity scope

A requirement is **normative** when getting it wrong changes one of these:

* chain effects: what is built, signed, submitted, or registered, and the values used;
* persisted state: which artefacts exist afterwards, their content and their file mode;
* refusals: every precondition that stops the script, and its exit code;
* interaction that gates an effect: confirmations and password prompts, with their defaults;
* security-relevant output: secret material written to stdout, a plaintext file, or the transfer file;
* external calls whose arguments or results change any of the above.

**Out of scope** (no requirement ids): colours, banners, ASCII art, spinner animations, exact message wording, and informational display. Write "display only" in prose where the reader would otherwise wonder. Record the gist of a refusal message, never its full wording.

When upstream behaviour looks like a bug, specify it as observed, add a `> **Upstream quirk:**` note, and propose the corrected behaviour under *Port notes*. Parity means the port knows about the quirk; it does not have to copy it.

## Separating behaviour from adapters

Upstream mixes domain behaviour with one storage layout (flat files in the working directory), one chain-access choice (the work mode), one signer (key file, hardware wallet) and one transport (`offlineTransfer.json`). A spec keeps them apart:

* **Behaviour** sections describe effects in domain terms: "the pool's KES period counter becomes N".
* **Upstream file contract** lists the concrete file names, contents and modes. This is the contract of the *file-system Store adapter*, and of the import use case. It is normative for that adapter only.
* **Mode** requirements say how online, light and offline differ. Those differences become `ChainQuery` / `Submitter` / `Transport` adapter choices (see [`domain/ports.md`](./domain/ports.md)).

## File layout

```
spec/
  UPSTREAM.toml            pinned upstream repo, tag, rev
  format.md                this file
  upstream/
    common/<group>.md      one per group of 00_common.sh functions (kind = "common")
    patterns/<name>.md     behaviour shared by many scripts (kind = "pattern")
    scripts/<stem>.md      one per upstream script (kind = "script")
  domain/                  bounded contexts, glossary, ports, use-case traceability
  tools/specctl.py
```

Script specs are named after the upstream stem: `scripts/04c_genKESKeys.md`.

## Front matter

TOML between `+++` lines, so `tomllib` parses it with no dependency.

```toml
+++
id = "04c"                                  # the spec code used in every requirement id
kind = "script"                             # script | common | pattern
title = "Generate the next KES key pair"
upstream_tag = "Update-2026-04"             # must equal spec/UPSTREAM.toml
status = "draft"                            # draft | reviewed
contexts = ["pool-operations"]              # bounded contexts, see domain/context-map.md
use_cases = ["RotateKesKey"]                # use-case names, see domain/use-cases.md
depends_on = ["Cui", "Ckey"]                # other spec codes this one relies on

# --- mechanical facts: paste the output of `specctl facts <file>`; lint verifies them ---
upstream_path = "cardano/mainnet/04c_genKESKeys.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "..."
upstream_lines = 186
uses_common = [...]
cli_commands = [...]
hwcli_commands = [...]
signer_commands = [...]
http_endpoints = [...]
env_vars = [...]
+++
```

* `kind = "common"` specs have `upstream_path = "cardano/mainnet/00_common.sh"`, `upstream_sha256`, and a `[functions]` table mapping each function they own to its hash (from `specctl facts 00_common.sh`). They omit the other mechanical lists. Every `00_common.sh` function is owned by exactly one common spec.
* `kind = "pattern"` specs have no `upstream_path`. Their requirements cite files explicitly.
* Mechanical facts are extracted by regex. When an extracted fact is wrong (a false match), keep the extracted value so lint passes, and explain it in the body. Do not edit the extractor in passing.

## Extension specs

Files under `spec/extensions/` use `kind = "extension"`. They specify behaviour the port adds, not upstream behaviour: they omit `upstream_tag` and every mechanical fact, their requirements have no `(src: ...)` references, and their code starts with `X` (`SPO-Xparty-PRE-005`). Everything else in this contract applies, including the rule that ids are never renumbered.

## Spec codes

| Kind | Code | Example id |
| --- | --- | --- |
| Script whose numeric prefix is unique | the prefix | `SPO-04c-INV-001` |
| Script whose prefix is shared (`01_*`) | prefix + first word | `SPO-01workOffline-PRE-003` |
| `0x_importHelper.sh` | `0x` | `SPO-0x-OUT-002` |
| Common group | `C` + group | `SPO-Cutxo-INV-004` |
| Pattern | `P` + name | `SPO-Ptx-MODE-002` |

Common groups: `Cconf` (configuration, networks, prologue, tool and version checks, era), `Cchain` (tip, epoch, TTL, sync), `Clight` (Koios queries and light submit), `Caddr` (address inspection, ADA Handle), `Cutxo` (UTxO parsing, filtering, minimum output value), `Cconv` (asset names, governance action ids, CBOR, ADA formatting), `Coffline` (transfer file read and display), `Chw` (hardware wallet session), `Ckey` (key encryption and reading), `Cui` (prompts, file locks, error exit), `Ctx` (transaction body correction).

Patterns: `Ptx` (the shared transaction pipeline), `Pparam` (the free-form extra-parameter grammar), `Pfiles` (workspace artefact naming and modes), `Ptransfer` (the `offlineTransfer.json` schema).

## Requirements

A requirement is one Markdown bullet that starts with a bold id and ends with one or more source references:

```markdown
- **SPO-04c-PRE-001** Refuses with exit 2 when the current KES counter already equals the next counter: a new opcert (04d) must consume the previous key first. (src: L76)
```

* **Id:** `SPO-<code>-<KIND>-<NNN>`, numbered from `001` per kind. Never renumber or reuse an id. When a requirement is deleted, keep the bullet and mark it `~~withdrawn~~ in <tag>`, so test citations still resolve.
* **Kinds:**

  | Kind | Meaning |
  | --- | --- |
  | `IF` | interface: arguments, options, accepted forms, usage errors |
  | `IN` | input: state, config settings and environment read |
  | `OUT` | output: state written, artefacts produced, transfer-file mutations |
  | `MODE` | a difference between online, light and offline work modes |
  | `PR` | a prompt that gates an effect, with its default |
  | `EXT` | an external call (cardano-cli, cardano-hw-cli, cardano-signer, HTTP) whose arguments or result matter |
  | `PRE` | a precondition or failure: the check, the refusal and the exit code |
  | `INV` | an invariant that holds over the whole operation |
  | `SEC` | security-relevant behaviour (secrets on stdout, plaintext at rest, trust decisions) |

* **Source references:** `(src: L58-L76)` cites the spec's own `upstream_path`; `(src: 00_common.sh:L1013-L1103)` cites another file in the same variant directory. Separate several ranges with commas: `(src: L40-L44, L90)`. Ranges are against the pinned tag. They are how `specctl hunks` maps a diff to ids, so cite the **tightest** range that implements the requirement, and cite every place that does.
* **One fact per bullet.** If a test would need two assertions on unrelated things, write two requirements.
* **Cross-reference** a requirement owned elsewhere by its id (`see SPO-Cutxo-INV-002`) instead of restating it. Lint fails on references to undefined ids.
* Write each requirement as a present-tense statement of observed behaviour. Do not use RFC 2119 words; the whole corpus is normative for parity by definition.

## Body sections

Script specs use these sections, in this order. Omit a section that would be empty, and say so in one line where its absence is surprising ("No prompts.").

1. `# <stem>: <title>`, then a one-paragraph **summary** of the purpose in domain terms.
2. `## Interface`: usage forms, positional arguments, options. `IF` requirements.
3. `## Inputs`: state read, config settings, environment. `IN` requirements.
4. `## Behaviour`: a numbered sequence of steps in domain terms, with `PRE`, `EXT`, `INV` requirements at the step where they happen.
5. `## Work modes`: `MODE` requirements. Say "Mode-independent" if so.
6. `## Prompts`: `PR` requirements. A table of prompt, default, effect is fine in addition to the bullets.
7. `## Outputs`: `OUT` requirements, then an **Upstream file contract** table: file, content, mode, created / updated / deleted.
8. `## Failures`: a table of condition, exit code, requirement id, collecting refusals not already given ids in Behaviour.
9. `## Security`: `SEC` requirements.
10. `## Domain mapping`: use case(s), aggregate(s) touched, and the port operations needed, as a table of port, operation, purpose. Port names come from [`domain/ports.md`](./domain/ports.md). When an operation is missing there, add it to the spec's table and flag it with *(new)*.
11. `## Port notes` (non-normative): improvements the port should make, such as encryption by default, quirks to fix, and remote-signing implications. Never give these ids.
12. `## Open questions`: anything that could not be settled from source alone, for example behaviour that depends on cardano-cli output, with what would settle it.

### Pipeline stage map (transaction scripts)

A script that follows the shared transaction pipeline ([`Ptx`](./upstream/patterns/Ptx.md)) adds a `## Pipeline stage map` section after *Behaviour*. It has one `INV` requirement per Ptx stage (1 to 12) that the script implements. The requirement says "as Ptx" or names the variation, and cites **this script's own lines** for the stage:

```markdown
- **SPO-06-INV-010** Stage 3, gather inputs: as Ptx (SPO-Ptx-MODE-001 to SPO-Ptx-MODE-003). (src: L370-L398)
- **SPO-06-INV-011** Stage 6, dummy body and fee: as Ptx, with the delegation certificate attached and witness count 2. (src: L548-L556)
```

Ptx itself cites only its canonical instance. Without the map, a change to the pipeline code of another script would reach `specctl hunks` as *unmapped*. With the map, every hunk in a pipeline stage lands on a stage requirement, and from there on the Ptx requirement it refers to. A stage the script skips is stated as skipped, with no range.

Common and pattern specs use `# <code>: <title>`, a summary, then one `##` section per function or concern, each with its requirements, followed by Domain mapping, Port notes and Open questions.
