"""The run journal: one JSON file per run under .workbench/runs/.

A journal never contains secrets: it records parameters (names, amounts),
step status, and the paths and SHA-256 digests of produced files, but never
file contents or script output. That is what makes it safe to carry between
machines inside offlineTransfer.json.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .errors import WorkbenchError
from .workspace import atomic_write

FORMAT = 1
PENDING, RUNNING, DONE, FAILED, INTERRUPTED = "pending", "running", "done", "failed", "interrupted"
RUN_ACTIVE, RUN_PAUSED, RUN_DONE, RUN_FAILED, RUN_ATTENTION, RUN_ABANDONED = (
    "active", "paused", "done", "failed", "needs-attention", "abandoned")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Artefact:
    path: str
    sha256: str
    secret: bool = False
    description: str = ""


@dataclass
class StepRecord:
    id: str
    title: str
    status: str = PENDING
    started: str | None = None
    finished: str | None = None
    machine: str | None = None
    adopted: bool = False
    error: str | None = None
    artefacts: list[Artefact] = field(default_factory=list)
    data: dict = field(default_factory=dict)


@dataclass
class Run:
    id: str
    workflow: str
    network: str
    params: dict
    created: str
    updated: str
    status: str = RUN_ACTIVE
    waiting_for: str | None = None
    seq: int = 0
    data: dict = field(default_factory=dict)
    steps: list[StepRecord] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    format: int = FORMAT

    def step(self, step_id: str) -> StepRecord:
        for rec in self.steps:
            if rec.id == step_id:
                return rec
        raise KeyError(step_id)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=False) + "\n"

    @classmethod
    def from_dict(cls, d: dict) -> "Run":
        if d.get("format") != FORMAT:
            raise WorkbenchError(f"run {d.get('id')}: unsupported journal format {d.get('format')}")
        steps = [
            StepRecord(**{**s, "artefacts": [Artefact(**a) for a in s.get("artefacts", [])]})
            for s in d.get("steps", [])
        ]
        return cls(**{**d, "steps": steps})


def new_id(workflow: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{workflow}-{secrets.token_hex(2)}"


class Journal:
    def __init__(self, runs_dir: Path):
        self.dir = runs_dir

    def path(self, run_id: str) -> Path:
        return self.dir / f"{run_id}.json"

    def save(self, run: Run) -> None:
        run.updated = now()
        atomic_write(self.path(run.id), run.to_json(), mode=0o600)

    def load(self, run_id: str) -> Run:
        try:
            return Run.from_dict(json.loads(self.path(run_id).read_text()))
        except FileNotFoundError:
            raise WorkbenchError(f"no run with id {run_id}") from None

    def exists(self, run_id: str) -> bool:
        return self.path(run_id).exists()

    def all(self) -> list[Run]:
        if not self.dir.is_dir():
            return []
        runs = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                runs.append(Run.from_dict(json.loads(p.read_text())))
            except (ValueError, TypeError, WorkbenchError):
                continue
        return runs

    def unfinished(self) -> list[Run]:
        return [r for r in self.all() if r.status not in (RUN_DONE, RUN_ABANDONED)]
