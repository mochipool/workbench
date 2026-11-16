"""`workbench`: command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from . import __version__, config as cfgmod, toolchain
from .engine import Engine
from .errors import (Busy, CheckFailed, ConfigError, DriftError, NeedsAttention, StepFailed,
                     WorkbenchError)
from .journal import Journal
from .report import render_plan, render_run, run_json
from .transfer import OfflineFile
from .workflows import REGISTRY
from .workspace import Workspace, unlocked

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2
EXIT_CODES = {
    ConfigError: 3, CheckFailed: 4, StepFailed: 5, NeedsAttention: 6, DriftError: 7, Busy: 8,
}
EXIT_PAUSED = 10


def _workspace(args) -> Workspace:
    return Workspace(Path(args.directory or os.environ.get("WORKBENCH_DIR") or "."))


def _engine(args, ws: Workspace) -> Engine:
    config = cfgmod.load(ws.root)
    tools = toolchain.load(args.toolchain).for_network(config.network)
    engine = Engine(ws, config, tools, REGISTRY, assume_yes=args.yes, interactive=not args.json)
    engine.scripts.stdout_to_stderr = args.json
    return engine


def _params(args, workflow) -> dict[str, str]:
    return {p.name: getattr(args, f"p_{p.name}") for p in workflow.params
            if getattr(args, f"p_{p.name}") is not None}


def _emit(args, engine: Engine, run) -> int:
    if args.json:
        print(run_json(run, engine.notes))
    else:
        print(render_run(run, engine.ws, engine.config.role, engine.notes))
    return EXIT_PAUSED if run.status == "paused" else EXIT_OK


# ---- commands -----------------------------------------------------------

def cmd_init(args) -> int:
    ws = _workspace(args)
    path = ws.root / cfgmod.FILENAME
    if path.exists():
        raise ConfigError(f"{path} already exists")
    if args.pool and not cfgmod.is_valid_name(args.pool):
        raise ConfigError(f"pool name {args.pool!r} must match {cfgmod.NAME_RE.pattern}")
    text = cfgmod.render(args.network, args.role, args.airgapped, args.pool, args.socket)
    cfgmod.parse(__import__("tomllib").loads(text))  # never write a config we would reject
    notes = ws.ensure_private()  # creates the workspace as 0700 if it is new
    path.write_text(text)
    path.chmod(0o600)
    print(f"Created {path}")
    for n in notes:
        print(f"  {n}")
    print("Next: put your key/address files in this directory, then `workbench status`.")
    return EXIT_OK


def cmd_workflows(args) -> int:
    for w in REGISTRY.values():
        print(f"{w.name:<15} {w.summary}")
        for p in w.params:
            req = "" if p.required else " (optional)"
            print(f"    --{p.name:<10} {p.help}{req}")
    return EXIT_OK


def cmd_check(args) -> int:
    ws = _workspace(args)
    engine = _engine(args, ws)
    run, plan = engine.check(args.workflow, _params(args, REGISTRY[args.workflow]))
    if args.json:
        print(json.dumps({"ok": True, "workflow": run.workflow, "data": run.data,
                          "steps": [{"id": e.step.id, "where": e.step.where, "here": e.here,
                                     "already_done": bool(e.probe)} for e in plan]}, indent=2))
    else:
        print(render_plan(run, plan))
    return EXIT_OK


def _prepare(engine: Engine) -> None:
    """Before any script runs: private permissions and a fresh common.inc."""
    if not sys.stdin.isatty() and not engine.assume_yes:
        print("warning: stdin is not a terminal; the SPO scripts prompt on the terminal, so run "
              "workbench interactively or pass --yes", file=sys.stderr)
    engine.notes += engine.ws.ensure_private()
    engine.ws.write_common_inc(engine.config, engine.tools)


def cmd_run(args) -> int:
    ws = _workspace(args)
    engine = _engine(args, ws)
    with ws.lock():
        _prepare(engine)
        run = engine.start(args.workflow, _params(args, REGISTRY[args.workflow]))
    return _emit(args, engine, run)


def cmd_resume(args) -> int:
    ws = _workspace(args)
    engine = _engine(args, ws)
    with ws.lock():
        _prepare(engine)
        run = engine.resume(args.run_id, mark_done=args.mark_done, retry=args.retry)
    return _emit(args, engine, run)


def cmd_exec(args) -> int:
    """Run one SPO script in the workspace with the managed common.inc."""
    ws = _workspace(args)
    engine = _engine(args, ws)
    if "/" in args.script:
        raise WorkbenchError("give the script name only, e.g. 04a_genNodeKeys.sh")
    with ws.lock():
        _prepare(engine)
        return engine.scripts.run(args.script, *args.args, ok_codes=tuple(range(256)))


def cmd_abandon(args) -> int:
    ws = _workspace(args)
    engine = _engine(args, ws)
    with ws.lock():
        run = engine.abandon(args.run_id)
    return _emit(args, engine, run)


def cmd_runs(args) -> int:
    ws = _workspace(args)
    runs = Journal(ws.runs_dir).all()
    if args.json:
        print(json.dumps([{"id": r.id, "workflow": r.workflow, "status": r.status,
                           "updated": r.updated} for r in runs], indent=2))
        return EXIT_OK
    if not runs:
        print("no runs yet")
    for r in runs:
        print(f"{r.id}  {r.status:<16} {r.updated}")
    return EXIT_OK


def cmd_show(args) -> int:
    ws = _workspace(args)
    run = Journal(ws.runs_dir).load(args.run_id)
    role = cfgmod.load(ws.root).role
    print(run_json(run) if args.json else render_run(run, ws, role))
    return EXIT_OK


def cmd_status(args) -> int:
    ws = _workspace(args)
    config = cfgmod.load(ws.root)
    info: dict = {"workspace": str(ws.root), "network": config.network, "role": config.role,
                  "airgapped": config.airgapped}
    if config.pool:
        pool = config.pool.name
        info["pool"] = {
            "name": pool,
            "files": {f: ws.exists(f) for f in (
                f"{pool}.node.vkey", f"{pool}.node.skey", f"{pool}.node.hwsfile",
                f"{pool}.node.counter", f"{pool}.vrf.skey", f"{pool}.pool.json")},
        }
        for c in ("kes.counter", "kes.counter-next"):
            if ws.exists(f"{pool}.{c}"):
                info["pool"][c] = ws.read_text(f"{pool}.{c}").strip()
        if ws.exists(f"{pool}.kes-expire.json"):
            try:
                info["pool"]["kes_expiry"] = json.loads(ws.read_text(f"{pool}.kes-expire.json"))
            except ValueError:
                info["pool"]["kes_expiry"] = "unreadable"
    off = OfflineFile.read(ws.offline_file)
    if off is not None:
        ticket = off.ticket()
        info["offlineTransfer"] = {
            "queued_transactions": len(off.transactions), "addresses": len(off.addresses),
            "attached_files": sorted(off.files), "workbench_run": ticket.id if ticket else None,
        }
    info["unfinished_runs"] = [{"id": r.id, "status": r.status, "waiting_for": r.waiting_for}
                               for r in Journal(ws.runs_dir).unfinished()]
    if args.json:
        print(json.dumps(info, indent=2))
        return EXIT_OK
    print(f"{info['workspace']}\n  network {config.network}, role {config.role}"
          f"{', air-gapped' if config.airgapped else ''}")
    if "pool" in info:
        p = info["pool"]
        print(f"\nPool {p['name']}")
        for f, present in p["files"].items():
            print(f"  {'present' if present else 'missing':<8} {f}")
        for c in ("kes.counter", "kes.counter-next"):
            if c in p:
                print(f"  {c} = {p[c]}")
        if isinstance(p.get("kes_expiry"), dict):
            e = p["kes_expiry"]
            print(f"  KES {e.get('latestKESfileindex')} expires {e.get('expireKESdate')} "
                  f"(period {e.get('expireKESperiod')})")
    if "offlineTransfer" in info:
        o = info["offlineTransfer"]
        print(f"\n{ws.offline_file.name}: {o['queued_transactions']} queued tx, "
              f"{o['addresses']} addresses, files: {', '.join(o['attached_files']) or 'none'}")
        if o["workbench_run"]:
            print(f"  carries run {o['workbench_run']}; continue it with `workbench resume`")
    if info["unfinished_runs"]:
        print("\nUnfinished runs")
        for r in info["unfinished_runs"]:
            wait = f" (waiting for {r['waiting_for']} machine)" if r["waiting_for"] else ""
            print(f"  {r['id']}  {r['status']}{wait}")
    return EXIT_OK


def cmd_edit(args) -> int:
    ws = _workspace(args)
    path = ws.path(args.file)
    if not path.is_file() or path.parent != ws.root:
        raise WorkbenchError(f"{args.file} is not a file in {ws.root}")
    if path.suffix in (".skey", ".hwsfile") or ".skey" in path.name:
        raise WorkbenchError("refusing to open a signing key in an editor")
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    with ws.lock(), unlocked(path):
        subprocess.call([*shlex.split(editor), str(path)])
        if path.suffix == ".json":
            try:
                json.loads(path.read_text())
            except ValueError as e:
                print(f"warning: {path.name} is no longer valid JSON: {e}", file=sys.stderr)
                return EXIT_ERROR
    print(f"{path.name} saved and locked again")
    return EXIT_OK


# ---- parser -------------------------------------------------------------

def _add_workflow_args(sub, common, name, help_text, func):
    p = sub.add_parser(name, parents=[common], help=help_text)
    wsub = p.add_subparsers(dest="workflow", required=True, metavar="WORKFLOW")
    for w in REGISTRY.values():
        wp = wsub.add_parser(w.name, parents=[common], help=w.summary, description=w.summary)
        for param in w.params:
            wp.add_argument(f"--{param.name}", dest=f"p_{param.name}", help=param.help,
                            metavar=param.name.upper(), required=False)
        wp.set_defaults(func=func)
    return p


def build_parser() -> argparse.ArgumentParser:
    # Shared options are accepted at every level (`workbench -C ws run x` and
    # `workbench run x -C ws`). SUPPRESS keeps a deeper parser from resetting a
    # value given earlier; main() fills in the defaults afterwards.
    common = argparse.ArgumentParser(add_help=False)
    S = argparse.SUPPRESS
    common.add_argument("-C", "--directory", default=S, help="workspace directory (default: $WORKBENCH_DIR or .)")
    common.add_argument("--toolchain", default=S, help=S)
    common.add_argument("--json", action="store_true", default=S, help="machine-readable output")
    common.add_argument("-y", "--yes", action="store_true", default=S,
                        help="skip the scripts' final confirmation and accept imported runs")

    parser = argparse.ArgumentParser(prog="workbench", parents=[common],
                                     description="Resumable, validated SPO workflows.")
    parser.add_argument("--version", action="version", version=f"workbench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("init", parents=[common], help="create workbench.toml in a workspace")
    p.add_argument("--network", required=True, choices=toolchain.NETWORKS)
    p.add_argument("--role", required=True, choices=cfgmod.ROLES)
    p.add_argument("--airgapped", action="store_true", help="signing keys live on a separate offline machine")
    p.add_argument("--pool", help="pool name used in the key file names")
    p.add_argument("--socket", help="node socket path (role online)")
    p.set_defaults(func=cmd_init)

    sub.add_parser("workflows", parents=[common], help="list workflows and their parameters").set_defaults(func=cmd_workflows)
    for name, text, func in (("check", "validate inputs and show the plan; changes nothing", cmd_check),
                             ("run", "check, then run a workflow", cmd_run)):
        _add_workflow_args(sub, common, name, text, func)

    p = sub.add_parser("resume", parents=[common], help="continue an unfinished or transferred run")
    p.add_argument("run_id", nargs="?")
    p.add_argument("--mark-done", metavar="STEP", help="record an interrupted step as having taken effect")
    p.add_argument("--retry", metavar="STEP", help="run an interrupted or failed step again")
    p.set_defaults(func=cmd_resume)

    p = sub.add_parser("exec", parents=[common],
                       help="run one SPO script here with the managed common.inc")
    p.add_argument("script")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_exec)

    p = sub.add_parser("abandon", parents=[common], help="give up an unfinished run (files are kept)")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_abandon)

    sub.add_parser("status", parents=[common], help="workspace, pool and transfer overview").set_defaults(func=cmd_status)
    sub.add_parser("runs", parents=[common], help="list runs").set_defaults(func=cmd_runs)
    p = sub.add_parser("show", parents=[common], help="show one run")
    p.add_argument("run_id")
    p.set_defaults(func=cmd_show)
    p = sub.add_parser("edit", parents=[common], help="unlock a locked file, edit it, lock it again")
    p.add_argument("file")
    p.set_defaults(func=cmd_edit)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for name, default in (("directory", None), ("toolchain", None), ("json", False), ("yes", False)):
        if not hasattr(args, name):
            setattr(args, name, default)
    try:
        return args.func(args)
    except CheckFailed as e:
        print("Check failed; nothing was changed:\n" + str(e), file=sys.stderr)
        return EXIT_CODES[CheckFailed]
    except WorkbenchError as e:
        print(f"error: {e}", file=sys.stderr)
        return next((c for t, c in EXIT_CODES.items() if isinstance(e, t)), EXIT_ERROR)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
