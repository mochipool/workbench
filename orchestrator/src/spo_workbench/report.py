"""Human and JSON rendering of runs and plans."""

from __future__ import annotations

import json
import stat
import sys
from dataclasses import asdict

from .engine import PlanEntry, machine_label
from .journal import Run
from .workspace import Workspace

COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


MARK = {
    "done": _c("32", "done"), "pending": _c("90", "pending"), "running": _c("33", "running"),
    "failed": _c("31", "FAILED"), "interrupted": _c("31", "interrupted"),
}
RUN_MARK = {
    "done": _c("32", "DONE"), "paused": _c("33", "PAUSED"), "failed": _c("31", "FAILED"),
    "needs-attention": _c("31", "NEEDS ATTENTION"), "active": _c("33", "ACTIVE"),
    "abandoned": _c("90", "ABANDONED"),
}


def _mode(ws: Workspace, rel: str) -> str:
    p = ws.path(rel)
    return f"{stat.S_IMODE(p.stat().st_mode):04o}" if p.exists() else "gone"


def render_run(run: Run, ws: Workspace, role: str, notes: list[str] = ()) -> str:
    lines = [f"{run.workflow}  {run.id}  [{RUN_MARK.get(run.status, run.status)}]",
             f"network {run.network}" + "".join(f", {k}={v}" for k, v in run.params.items() if v is not None)]
    if run.status == "paused" and run.waiting_for:
        lines.append(f"waiting for the {machine_label(run.waiting_for)}")
    lines.append("")
    width = max((len(r.id) for r in run.steps), default=0)
    for r in run.steps:
        extra = " (already in place)" if r.adopted else ""
        where = f" on {r.machine}" if r.machine and r.status == "done" else ""
        lines.append(f"  {MARK.get(r.status, r.status):<9} {r.id:<{width}}  {r.title}{where}{extra}")
        if r.error and r.status != "done":
            lines.append(f"            {_c('31', r.error)}")
    artefacts = [(r, a) for r in run.steps for a in r.artefacts]
    if artefacts:
        lines += ["", "Artefacts"]
        for r, a in artefacts:
            tag = _c("31", " SECRET") if a.secret else ""
            mode = _mode(ws, a.path) if r.machine == role else f"on {r.machine} machine"
            desc = f"  {a.description}" if a.description else ""
            lines.append(f"  {a.path}  sha256:{a.sha256[:16]}  {mode}{tag}{desc}")
    if notes:
        lines += ["", "Notes"] + [f"  - {n}" for n in notes]
    if run.next_actions:
        lines += ["", "Next"] + [f"  - {n}" for n in run.next_actions]
    return "\n".join(lines)


def render_plan(run: Run, plan: list[PlanEntry]) -> str:
    lines = [f"{run.workflow}: all checks passed. Plan:", ""]
    for e in plan:
        if not e.here:
            state = f"on the {machine_label(e.step.where)}"
        elif e.probe:
            state = "already in place, will be adopted"
        else:
            state = "will run here"
        lines.append(f"  {e.step.id:<15} {e.step.title}  ({state})")
    for k, v in run.data.items():
        lines.append(f"\n  {k} = {v}")
    lines.append("\nNothing was changed. Start it with `workbench run " + run.workflow + " ...`.")
    return "\n".join(lines)


def run_json(run: Run, notes: list[str] = ()) -> str:
    return json.dumps({"run": asdict(run), "notes": list(notes)}, indent=2)
