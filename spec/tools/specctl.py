#!/usr/bin/env python3
"""specctl: mechanical tooling for the upstream specification corpus.

Standard library only (Python >= 3.11 for tomllib).

Commands
  facts  <script.sh> [--upstream DIR]  Print the mechanical front-matter facts for one upstream file.
  lint   [--upstream DIR]              Validate every spec against the pinned upstream tree.
  drift  --upstream NEWDIR             Report specs made stale by a different upstream tree.
  hunks  --old OLDDIR --new NEWDIR     Map every changed hunk to the requirement ids it touches.
  ids                                  Print every requirement id, one per line.
  gaps   [FILE...] [--upstream DIR]    List code lines no requirement cites (review aid; display-only code is expected here).
  coverage --tests DIR --config FILE   Fail when a requirement of an implemented spec has no citing Go test and no waiver.
  index  [--check]                     Regenerate domain/use-cases.md from front matter (--check: fail if stale).

DIR is the root of a gitmachtl/scripts checkout (the directory holding `cardano/`).
It defaults to $SPO_SCRIPTS_SRC.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

SPEC_ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_SPECS = SPEC_ROOT / "upstream"
EXTENSION_SPECS = SPEC_ROOT / "extensions"
VARIANT_DIRS = ("cardano/mainnet", "cardano/testnet")
COMMON = "00_common.sh"

REQ_ID = r"SPO-[A-Za-z0-9]+-(?:IF|IN|OUT|MODE|PR|EXT|PRE|INV|SEC)-\d{3}"
REQ_LINE = re.compile(r"^\s*[-*]\s+\*\*(" + REQ_ID + r")\*\*(.*)$")
REQ_ANY = re.compile(r"\b(" + REQ_ID + r")\b")
SRC_REF = re.compile(r"\(src:\s*([^)]*)\)")
SRC_PART = re.compile(r"^(?:([A-Za-z0-9_.-]+\.sh):)?L(\d+)(?:-L?(\d+))?$")

FUNC_HEAD = re.compile(r"^(?:function\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?|([A-Za-z_][A-Za-z0-9_]*)\s*\(\))\s*(\{.*)?$")
CLI_CALL = re.compile(r"\$\{?cardanocli\}?\s+((?:\$\{cliEra\}|[a-z][A-Za-z0-9-]*)(?:\s+[a-z][A-Za-z0-9-]*)*)")
HWCLI_CALL = re.compile(r"\$\{?cardanohwcli\}?\s+([a-z][a-z0-9-]*(?:\s+[a-z][a-z0-9-]*)*)")
SIGNER_CALL = re.compile(r"\$\{?cardanosigner\}?\s+([a-z][a-z0-9-]*(?:\s+[a-z][a-z0-9-]*)*)")
HTTP_CALL = re.compile(r"\$\{(koiosAPI|adahandleAPI|catalystAPI|tokenMetaServer|lightModeParametersURL)\}(/[A-Za-z0-9_./-]*)?")
ENV_VAR = re.compile(r"\b(ENV_[A-Z0-9_]+)\b")
ERA_WORDS = {"latest", "conway", "babbage", "alonzo", "mary", "allegra", "shelley", "byron", "${cliEra}"}
CLI_STOP = {"version", "help"}


# --------------------------------------------------------------------------- upstream access

def upstream_root(arg: str | None) -> Path:
    root = arg or os.environ.get("SPO_SCRIPTS_SRC")
    if not root:
        sys.exit("specctl: pass --upstream DIR or set SPO_SCRIPTS_SRC to a gitmachtl/scripts checkout")
    p = Path(root)
    if not (p / VARIANT_DIRS[0] / COMMON).is_file():
        sys.exit(f"specctl: {p} does not look like a gitmachtl/scripts tree (no {VARIANT_DIRS[0]}/{COMMON})")
    return p


def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read_lines(p: Path) -> list[str]:
    return p.read_text(encoding="utf-8", errors="replace").splitlines()


def strip_comment(line: str) -> str:
    """Drop a trailing shell comment, ignoring '#' inside ${...}, $#, quotes (heuristic)."""
    out, depth, quote = [], 0, None
    i = 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"':
                out.append(c)
                i += 1
                if i < len(line):
                    out.append(line[i])
                i += 1
                continue
        elif c in "'\"":
            quote = c
        elif c == "{" and i > 0 and line[i - 1] == "$":
            depth += 1
        elif c == "}" and depth:
            depth -= 1
        elif c == "#" and depth == 0 and (i == 0 or line[i - 1] in " \t;") :
            break
        out.append(c)
        i += 1
    return "".join(out)


@dataclass
class Function:
    name: str
    start: int  # 1-based inclusive
    end: int
    sha256: str


def shell_functions(lines: list[str]) -> list[Function]:
    """Top-level function definitions. A function ends at its one-line closing brace or at the
    next line starting with '}' (the upstream style)."""
    funcs: list[Function] = []
    i = 0
    while i < len(lines):
        m = FUNC_HEAD.match(strip_comment(lines[i]).rstrip())
        if not m:
            i += 1
            continue
        name = m.group(1) or m.group(2)
        start = i
        head = strip_comment(lines[i]).rstrip()
        if head.endswith("}") and "{" in head:
            end = i
        else:
            j = i + 1
            while j < len(lines) and not lines[j].startswith("}"):
                j += 1
            end = min(j, len(lines) - 1)
        body = "\n".join(lines[start:end + 1]) + "\n"
        funcs.append(Function(name, start + 1, end + 1, hashlib.sha256(body.encode()).hexdigest()))
        i = end + 1
    return funcs


def _words(cmd: str) -> str:
    toks = cmd.split()
    while toks and toks[0] in ERA_WORDS:
        toks = toks[1:]
    kept = []
    for t in toks:
        if not re.fullmatch(r"[a-z][A-Za-z0-9-]*", t):
            break
        kept.append(t)
        if t in CLI_STOP:
            break
    return " ".join(kept[:3])


def mechanical_facts(path: Path, common_names: set[str]) -> dict:
    lines = read_lines(path)
    code = [strip_comment(l) for l in lines]
    text = "\n".join(code)
    facts: dict = {
        "upstream_sha256": sha256_file(path),
        "upstream_lines": len(lines),
    }
    if path.name != COMMON:
        facts["uses_common"] = sorted(n for n in common_names if re.search(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])", text))
    facts["cli_commands"] = sorted({w for w in (_words(m.group(1)) for m in CLI_CALL.finditer(text)) if w})
    facts["hwcli_commands"] = sorted({w for w in (_words(m.group(1)) for m in HWCLI_CALL.finditer(text)) if w})
    facts["signer_commands"] = sorted({w for w in (_words(m.group(1)) for m in SIGNER_CALL.finditer(text)) if w})
    facts["http_endpoints"] = sorted({m.group(1) + (m.group(2) or "").rstrip("/.") for m in HTTP_CALL.finditer(text)})
    facts["env_vars"] = sorted(set(ENV_VAR.findall(text)))
    return facts


def common_function_index(root: Path) -> dict[str, Function]:
    return {f.name: f for f in shell_functions(read_lines(root / VARIANT_DIRS[0] / COMMON))}


def upstream_scripts(root: Path) -> dict[str, Path]:
    """All *.sh files keyed by the upstream relative path; mainnet wins for identical files."""
    found: dict[str, Path] = {}
    for vd in VARIANT_DIRS:
        d = root / vd
        if d.is_dir():
            for p in sorted(d.glob("*.sh")):
                found[f"{vd}/{p.name}"] = p
    return found


# --------------------------------------------------------------------------- spec parsing

@dataclass
class Requirement:
    id: str
    text: str
    refs: list[tuple[str | None, int, int]]  # (file or None = primary, start, end)
    line: int


@dataclass
class Spec:
    path: Path
    meta: dict
    body: str
    reqs: list[Requirement] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def code(self) -> str:
        return str(self.meta.get("id", ""))

    @property
    def primary(self) -> str | None:
        return self.meta.get("upstream_path")


def parse_spec(path: Path) -> Spec:
    raw = path.read_text(encoding="utf-8")
    spec = Spec(path, {}, raw)
    if not raw.startswith("+++\n"):
        spec.errors.append("missing TOML front matter (+++ ... +++)")
        return spec
    try:
        fm, body = raw[4:].split("\n+++\n", 1)
    except ValueError:
        spec.errors.append("unterminated front matter")
        return spec
    try:
        spec.meta = tomllib.loads(fm)
    except tomllib.TOMLDecodeError as e:
        spec.errors.append(f"front matter: {e}")
        return spec
    spec.body = body
    offset = fm.count("\n") + 3
    for n, line in enumerate(body.splitlines(), start=offset):
        m = REQ_LINE.match(line)
        if not m:
            continue
        rid, rest = m.group(1), m.group(2)
        refs = []
        for sm in SRC_REF.finditer(rest):
            for part in (p.strip() for p in sm.group(1).split(",")):
                pm = SRC_PART.match(part)
                if not pm:
                    spec.errors.append(f"line {n}: {rid}: bad src reference '{part}'")
                    continue
                a = int(pm.group(2))
                b = int(pm.group(3) or a)
                refs.append((pm.group(1), a, b))
        spec.reqs.append(Requirement(rid, rest.strip(), refs, n))
    return spec


def load_specs() -> list[Spec]:
    paths = sorted(UPSTREAM_SPECS.rglob("*.md")) + sorted(EXTENSION_SPECS.rglob("*.md"))
    return [parse_spec(p) for p in paths if p.name != "README.md" and not p.name.startswith("_")]


def resolve_ref_file(spec: Spec, f: str | None, scripts: dict[str, Path] | None = None) -> str | None:
    """Resolve a (src: FILE:...) reference: the spec's own variant directory first, then the
    other variants (so a pattern spec can cite a testnet-only script)."""
    if f is None:
        return spec.primary
    order = list(VARIANT_DIRS)
    if spec.primary:
        order.sort(key=lambda vd: not spec.primary.startswith(vd))
    if scripts is not None:
        for vd in order:
            if f"{vd}/{f}" in scripts:
                return f"{vd}/{f}"
    return f"{order[0]}/{f}"


# --------------------------------------------------------------------------- commands

MECH_KEYS = ("uses_common", "cli_commands", "hwcli_commands", "signer_commands", "http_endpoints", "env_vars")


def toml_value(v) -> str:
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[\n" + "".join(f'  "{x}",\n' for x in v) + "]"
    if isinstance(v, int):
        return str(v)
    return f'"{v}"'


def cmd_facts(args) -> int:
    root = upstream_root(args.upstream)
    p = Path(args.script)
    if not p.is_absolute() and not p.exists():
        for vd in VARIANT_DIRS:
            cand = root / vd / p.name
            if cand.exists():
                p = cand
                break
    names = set(common_function_index(root))
    facts = mechanical_facts(p, names)
    rel = next((f"{vd}/{p.name}" for vd in VARIANT_DIRS if (root / vd / p.name).exists()), p.name)
    variants = [vd.split("/")[-1] for vd in VARIANT_DIRS if (root / vd / p.name).exists()]
    print(f'upstream_path = "{rel}"')
    print("variants = [" + ", ".join(f'"{v}"' for v in variants) + "]")
    for k, v in facts.items():
        print(f"{k} = {toml_value(v)}")
    if p.name == COMMON:
        print("\n# per-function hashes ([functions] table)")
        for f in shell_functions(read_lines(p)):
            print(f'{f.name} = "{f.sha256}"  # L{f.start}-L{f.end}')
    return 0


def cmd_lint(args) -> int:
    root = upstream_root(args.upstream)
    pinned = tomllib.loads((SPEC_ROOT / "UPSTREAM.toml").read_text())
    errors: list[str] = []
    warnings: list[str] = []
    rev = os.environ.get("SPO_SCRIPTS_REV")
    if rev and rev != pinned["rev"]:
        errors.append(f"UPSTREAM.toml rev {pinned['rev']} != flake input rev {rev}; the corpus describes a different upstream")
    common_idx = common_function_index(root)
    names = set(common_idx)
    scripts = upstream_scripts(root)
    specs = load_specs()
    seen: dict[str, Path] = {}
    covered_paths: set[str] = set()
    covered_funcs: dict[str, str] = {}

    for s in specs:
        rel = s.path.relative_to(SPEC_ROOT)
        for e in s.errors:
            errors.append(f"{rel}: {e}")
        if not s.meta:
            continue
        kind = s.meta.get("kind")
        if kind not in ("script", "common", "pattern", "extension"):
            errors.append(f"{rel}: kind must be script|common|pattern|extension")
        in_ext = EXTENSION_SPECS in s.path.parents
        if (kind == "extension") != in_ext:
            errors.append(f"{rel}: kind \"extension\" and the extensions/ directory go together")
        # An extension specifies behaviour of the port that upstream does not have:
        # it has ids like any spec, but no upstream tag and no source ranges.
        if kind != "extension" and s.meta.get("upstream_tag") != pinned["tag"]:
            errors.append(f"{rel}: upstream_tag {s.meta.get('upstream_tag')!r} != pinned {pinned['tag']!r}")
        prim = s.primary
        if kind in ("script", "common"):
            if prim not in scripts:
                errors.append(f"{rel}: upstream_path {prim!r} not found upstream")
                continue
            covered_paths.add(prim)
            facts = mechanical_facts(scripts[prim], names)
            if s.meta.get("upstream_sha256") != facts["upstream_sha256"]:
                errors.append(f"{rel}: upstream_sha256 is stale for {prim}")
            if kind == "script":
                for k in MECH_KEYS:
                    want, have = facts.get(k, []), sorted(s.meta.get(k, []))
                    if want != have:
                        missing = sorted(set(want) - set(have))
                        extra = sorted(set(have) - set(want))
                        errors.append(f"{rel}: {k} differs from upstream (missing {missing}, extra {extra}); run `specctl facts`")
        if kind == "common":
            for fname, h in (s.meta.get("functions") or {}).items():
                if fname not in common_idx:
                    errors.append(f"{rel}: function {fname} not in {COMMON}")
                elif common_idx[fname].sha256 != h:
                    errors.append(f"{rel}: function {fname} hash is stale")
                if fname in covered_funcs:
                    errors.append(f"{rel}: function {fname} also claimed by {covered_funcs[fname]}")
                covered_funcs[fname] = str(rel)
        code = s.code
        for r in s.reqs:
            if r.id in seen:
                errors.append(f"{rel}:{r.line}: duplicate id {r.id} (also in {seen[r.id].relative_to(SPEC_ROOT)})")
            seen[r.id] = s.path
            if not r.id.startswith(f"SPO-{code}-"):
                errors.append(f"{rel}:{r.line}: id {r.id} does not use this spec's code SPO-{code}-")
            if not r.refs and kind not in ("pattern", "extension"):
                warnings.append(f"{rel}:{r.line}: {r.id} has no (src: ...) reference")
            for f, a, b in r.refs:
                target = resolve_ref_file(s, f, scripts)
                if target not in scripts:
                    errors.append(f"{rel}:{r.line}: {r.id} cites unknown file {f or target}")
                    continue
                n = len(read_lines(scripts[target]))
                if not (1 <= a <= b <= n):
                    errors.append(f"{rel}:{r.line}: {r.id} range L{a}-L{b} outside {target} (1..{n})")

    all_ids = set(seen)
    for s in specs:
        for m in REQ_ANY.finditer(s.body):
            if m.group(1) not in all_ids:
                errors.append(f"{s.path.relative_to(SPEC_ROOT)}: reference to undefined id {m.group(1)}")
    for doc in sorted(list((SPEC_ROOT / "domain").glob("*.md")) + list(SPEC_ROOT.glob("*.md"))):
        if doc.name == "format.md":
            continue  # its examples are illustrative
        for m in REQ_ANY.finditer(doc.read_text()):
            if m.group(1) not in all_ids:
                errors.append(f"{doc.relative_to(SPEC_ROOT)}: reference to undefined id {m.group(1)}")

    for prim in sorted(set(scripts) - covered_paths):
        name = prim.split("/")[-1]
        twin = [p for p in covered_paths if p.split("/")[-1] == name]
        if twin and sha256_file(scripts[prim]) == sha256_file(scripts[twin[0]]):
            continue  # identical variant, covered by the twin's spec
        (warnings if args.allow_missing else errors).append(f"no spec covers upstream {prim}")
    for fname in sorted(names - set(covered_funcs)):
        (warnings if args.allow_missing else errors).append(f"no common spec claims function {fname}")

    if render_use_cases(specs) != (USE_CASES_DOC.read_text() if USE_CASES_DOC.exists() else ""):
        errors.append("domain/use-cases.md is stale; run `specctl index`")
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    print(f"specctl lint: {len(specs)} specs, {len(all_ids)} requirements, {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


def cmd_drift(args) -> int:
    root = upstream_root(args.upstream)
    specs = load_specs()
    scripts = upstream_scripts(root)
    names = set(common_function_index(root))
    new_common = common_function_index(root)
    stale_funcs: dict[str, str] = {}
    by_path: dict[str, list[Spec]] = {}
    for s in specs:
        if s.primary:
            by_path.setdefault(s.primary, []).append(s)
        for fname, h in (s.meta.get("functions") or {}).items():
            if fname not in new_common:
                stale_funcs[fname] = "removed"
            elif new_common[fname].sha256 != h:
                stale_funcs[fname] = f"changed (now L{new_common[fname].start}-L{new_common[fname].end})"
    claimed = {f for s in specs for f in (s.meta.get("functions") or {})}
    for fname in sorted(set(new_common) - claimed):
        stale_funcs[fname] = "new (unclaimed)"

    print(f"# Drift report against {root}\n")
    print("## Files\n")
    changed = 0
    for prim in sorted(set(scripts) | set(by_path)):
        if prim not in scripts:
            print(f"- REMOVED upstream: `{prim}` (specs: {', '.join(s.path.name for s in by_path[prim])})")
            changed += 1
            continue
        if prim not in by_path:
            name = prim.split("/")[-1]
            twins = [p for p in by_path if p.split("/")[-1] == name]
            if twins and sha256_file(scripts[prim]) == by_path[twins[0]][0].meta.get("upstream_sha256"):
                continue
            print(f"- UNCOVERED: `{prim}` has no spec (new upstream file, or not yet specified)")
            changed += 1
            continue
        h = sha256_file(scripts[prim])
        for s in by_path[prim]:
            if s.meta.get("upstream_sha256") != h:
                print(f"- CHANGED: `{prim}` -> `{s.path.relative_to(SPEC_ROOT)}`")
                changed += 1
    print("\n## 00_common.sh functions\n")
    for fname, why in sorted(stale_funcs.items()):
        dependents = sorted(s.path.name for s in specs if fname in (s.meta.get("uses_common") or []))
        owner = next((s.path.name for s in specs if fname in (s.meta.get("functions") or {})), "-")
        print(f"- `{fname}`: {why}; owner `{owner}`; used by {len(dependents)} spec(s): {', '.join(dependents) or '-'}")
    print("\n## Mechanical facts\n")
    for prim, ss in sorted(by_path.items()):
        if prim not in scripts:
            continue
        for s in ss:
            if s.meta.get("kind") != "script":
                continue
            facts = mechanical_facts(scripts[prim], names)
            for k in MECH_KEYS:
                want, have = set(facts.get(k, [])), set(s.meta.get(k, []))
                if want != have:
                    print(f"- `{s.path.name}` {k}: +{sorted(want - have)} -{sorted(have - want)}")
    total = changed + len(stale_funcs)
    print(f"\n{total} item(s) need attention." if total else "\nNo drift.")
    return 1 if total else 0


def cmd_hunks(args) -> int:
    old, new = upstream_root(args.old), upstream_root(args.new)
    specs = load_specs()
    old_s, new_s = upstream_scripts(old), upstream_scripts(new)
    index: dict[str, list[tuple[int, int, str]]] = {}
    for s in specs:
        for r in s.reqs:
            for f, a, b in r.refs:
                target = resolve_ref_file(s, f, {**old_s, **new_s})
                if target:
                    index.setdefault(target, []).append((a, b, r.id))
    print(f"# Hunk worksheet\n\nold: `{old}`\nnew: `{new}`\n")
    print("Classify every hunk as `behaviour`, `no-effect` or `cosmetic`. A `behaviour` hunk needs a spec edit.\n")
    n_hunks = 0
    for prim in sorted(set(old_s) | set(new_s)):
        a = read_lines(old_s[prim]) if prim in old_s else []
        b = read_lines(new_s[prim]) if prim in new_s else []
        if a == b:
            continue
        print(f"## `{prim}`\n")
        sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            n_hunks += 1
            lo, hi = i1 + 1, max(i2, i1 + 1)
            hits = sorted({rid for (x, y, rid) in index.get(prim, []) if x <= hi and lo <= y})
            print(f"### H{n_hunks}: {tag} old L{i1 + 1}-L{i2} -> new L{j1 + 1}-L{j2}\n")
            print(f"- requirements: {', '.join(hits) if hits else '**none (unmapped: check whether it adds behaviour)**'}")
            print("- classification: _todo_\n")
            print("```diff")
            for line in difflib.unified_diff(a[max(0, i1 - 2):i2 + 2], b[max(0, j1 - 2):j2 + 2], lineterm="", n=2):
                if line.startswith(("---", "+++", "@@")):
                    continue
                print(line)
            print("```\n")
    print(f"{n_hunks} hunk(s).")
    return 0


def cmd_gaps(args) -> int:
    root = upstream_root(args.upstream)
    scripts = upstream_scripts(root)
    specs = load_specs()
    cited: dict[str, set[int]] = {}
    for s in specs:
        for r in s.reqs:
            for f, a, b in r.refs:
                t = resolve_ref_file(s, f, scripts)
                cited.setdefault(t, set()).update(range(a, b + 1))
    def twin_identical(p: str) -> bool:
        other = f"{VARIANT_DIRS[0]}/{p.split('/')[-1]}"
        return p != other and other in scripts and sha256_file(scripts[p]) == sha256_file(scripts[other])
    wanted = [p for p in scripts if not twin_identical(p) and (not args.files or any(p.endswith(f) or p.endswith(f + ".sh") for f in args.files))]
    total_code = total_gap = 0
    for prim in wanted:
        lines = read_lines(scripts[prim])
        code = [i + 1 for i, l in enumerate(lines) if strip_comment(l).strip() and not re.fullmatch(r"\s*(echo|printf)\b.*", l)
                and strip_comment(l).strip() not in ("fi", "done", "esac", "else", "}", "{", ";;", "then", "do")]
        gap = [n for n in code if n not in cited.get(prim, set())]
        total_code += len(code); total_gap += len(gap)
        ranges, start = [], None
        for n in gap:
            if start is None: start = prev = n
            elif n == prev + 1: prev = n
            else: ranges.append((start, prev)); start = prev = n
        if start is not None: ranges.append((start, prev))
        pct = 100 * (len(code) - len(gap)) / len(code) if code else 100
        print(f"{prim}: {pct:.0f}% of {len(code)} code lines cited; uncited: " + ", ".join(f"L{a}" if a == b else f"L{a}-L{b}" for a, b in ranges[:400]))
    if total_code:
        print(f"\noverall: {100 * (total_code - total_gap) / total_code:.0f}% of {total_code} code lines cited (echo/printf lines excluded)")
    return 0


USE_CASES_DOC = SPEC_ROOT / "domain" / "use-cases.md"


def render_use_cases(specs: list[Spec]) -> str:
    ctx_doc = (SPEC_ROOT / "domain" / "context-map.md").read_text()
    ctx_order = re.findall(r"^\| `([a-z-]+)` \|", ctx_doc, re.M)
    rel = lambda s: "../" + str(s.path.relative_to(SPEC_ROOT))
    by_uc: dict[str, list[Spec]] = {}
    for s in specs:
        for uc in s.meta.get("use_cases") or []:
            by_uc.setdefault(uc, []).append(s)
    out = [
        "# Use cases",
        "",
        "<!-- Generated by `specctl index` from spec front matter. Do not edit; `specctl lint` fails when stale. -->",
        "",
        "Every use case the corpus names, grouped by the bounded context of the spec that introduces it (its first `contexts` entry). "
        "A use case is at parity when every requirement in the listed specs has a passing test citing its id. "
        "Specs that support many use cases (common groups and patterns) are listed under *Shared specs*.",
        "",
    ]
    def primary_ctx(uc):
        return (by_uc[uc][0].meta.get("contexts") or ["?"])[0]
    groups: dict[str, list[str]] = {}
    for uc in by_uc:
        groups.setdefault(primary_ctx(uc), []).append(uc)
    for ctx in ctx_order + sorted(set(groups) - set(ctx_order)):
        if ctx not in groups:
            continue
        out += [f"## `{ctx}`", "", "| Use case | Specs | Requirements |", "| --- | --- | --- |"]
        for uc in sorted(groups[ctx]):
            ss = by_uc[uc]
            links = ", ".join(f"[`{x.code}`]({rel(x)})" for x in ss)
            out.append(f"| `{uc}` | {links} | {sum(len(x.reqs) for x in ss)} |")
        out.append("")
    out += ["## Shared specs", "", "| Spec | Kind | Title | Requirements | Used by (script specs) |", "| --- | --- | --- | --- | --- |"]
    for s in specs:
        if s.meta.get("kind") not in ("common", "pattern"):
            continue
        users = sorted(x.code for x in specs if x.meta.get("kind") == "script" and (
            s.code in (x.meta.get("depends_on") or []) or
            set((s.meta.get("functions") or {})) & set(x.meta.get("uses_common") or [])))
        out.append(f"| [`{s.code}`]({rel(s)}) | {s.meta['kind']} | {s.meta.get('title','')} | {len(s.reqs)} | {', '.join(users) or '-'} |")
    out += ["", "## Scripts", "", "| Script | Title | Contexts | Requirements | Status |", "| --- | --- | --- | --- | --- |"]
    for s in sorted((x for x in specs if x.meta.get("kind") == "script"), key=lambda x: x.path.name):
        out.append(f"| [`{s.path.stem}`]({rel(s)}) | {s.meta.get('title','')} | {', '.join(s.meta.get('contexts') or [])} | {len(s.reqs)} | {s.meta.get('status','')} |")
    total = sum(len(s.reqs) for s in specs)
    out += ["", f"Totals: {len(specs)} specs, {total} requirements, {len(by_uc)} use cases.", ""]
    return "\n".join(out)


def cmd_index(args) -> int:
    text = render_use_cases(load_specs())
    if args.check:
        current = USE_CASES_DOC.read_text() if USE_CASES_DOC.exists() else ""
        if current != text:
            print("domain/use-cases.md is stale; run `specctl index`")
            return 1
        return 0
    USE_CASES_DOC.write_text(text)
    print(f"wrote {USE_CASES_DOC.relative_to(SPEC_ROOT)}")
    return 0


def cmd_ids(args) -> int:
    for s in load_specs():
        for r in s.reqs:
            print(r.id)
    return 0


def cmd_coverage(args) -> int:
    specs = load_specs()
    by_id: dict[str, Requirement] = {}
    for s in specs:
        for r in s.reqs:
            by_id[r.id] = r
    codes = {s.code for s in specs}
    withdrawn = {i for i, r in by_id.items() if "~~withdrawn~~" in r.text}
    with open(args.config, "rb") as fh:
        cfg = tomllib.load(fh)
    implemented = [str(c) for c in cfg.get("implemented", [])]
    waived = {str(k): str(v) for k, v in (cfg.get("waived") or {}).items()}
    errors: list[str] = []

    cited: set[str] = set()
    root = Path(args.tests)
    for path in sorted(root.rglob("*_test.go")):
        rel = path.relative_to(root).parts
        if "vendor" in rel or "testdata" in rel:
            continue
        for n, line in enumerate(read_lines(path), 1):
            if "//" not in line:
                continue
            comment = line[line.index("//"):]
            if "spec:" not in comment:
                continue
            for rid in REQ_ANY.findall(comment):
                if rid not in by_id:
                    errors.append(f"{path}:{n}: cited id {rid} does not exist in the corpus")
                else:
                    cited.add(rid)

    for code in implemented:
        if code not in codes:
            errors.append(f"{args.config}: implemented code {code!r} is not a spec code")
    required = {r.id for c in implemented for s in specs if s.code == c for r in s.reqs if r.id not in withdrawn}
    for rid in sorted(required - cited - set(waived)):
        errors.append(f"{rid}: requirement of an implemented spec is neither cited by a test nor waived")
    for rid, reason in sorted(waived.items()):
        if rid not in by_id:
            errors.append(f"{args.config}: waived id {rid} does not exist in the corpus")
        elif not reason.strip():
            errors.append(f"{args.config}: waived id {rid} has an empty reason")
        elif rid in cited:
            errors.append(f"{args.config}: waived id {rid} is also cited by a test; remove the stale waiver")
    for e in sorted(errors):
        print(e)
    print(f"specctl coverage: {len(implemented)} implemented specs, {len(required)} requirements, "
          f"{len(required & cited)} cited, {len(required & set(waived))} waived, {len(errors)} errors")
    return 1 if errors else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="specctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("facts"); p.add_argument("script"); p.add_argument("--upstream"); p.set_defaults(fn=cmd_facts)
    p = sub.add_parser("lint"); p.add_argument("--upstream"); p.add_argument("--allow-missing", action="store_true", help="downgrade uncovered files/functions to warnings"); p.set_defaults(fn=cmd_lint)
    p = sub.add_parser("drift"); p.add_argument("--upstream", required=True); p.set_defaults(fn=cmd_drift)
    p = sub.add_parser("hunks"); p.add_argument("--old", required=True); p.add_argument("--new", required=True); p.set_defaults(fn=cmd_hunks)
    p = sub.add_parser("ids"); p.set_defaults(fn=cmd_ids)
    p = sub.add_parser("gaps"); p.add_argument("files", nargs="*"); p.add_argument("--upstream"); p.set_defaults(fn=cmd_gaps)
    p = sub.add_parser("coverage"); p.add_argument("--tests", required=True); p.add_argument("--config", required=True); p.set_defaults(fn=cmd_coverage)
    p = sub.add_parser("index"); p.add_argument("--check", action="store_true"); p.set_defaults(fn=cmd_index)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
