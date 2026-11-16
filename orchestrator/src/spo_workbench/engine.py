"""Workflow model and the resumable step engine.

A workflow is an ordered list of steps. Each step declares *where* it can
run:

  chain  needs chain access (role online or light)
  keys   needs signing keys (the offline machine when airgapped, else here)
  any    can run anywhere

and, where possible, a `done` probe that inspects the workspace to decide
whether the step's effect already exists. Probes are what make resume safe:
after a crash the engine asks the filesystem, not just the journal.

When the next step cannot run on this machine, the run pauses. In an
air-gapped setup the journal (the "ticket") and any non-secret files the
other side needs are attached to offlineTransfer.json with the upstream
`01_workOffline.sh attach`, so the operator still moves exactly one file.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable

from . import journal as J
from .config import Config
from .errors import CheckFailed, DriftError, NeedsAttention, StepFailed, WorkbenchError
from .journal import Artefact, Journal, Run, StepRecord
from .scripts import ScriptRunner
from .toolchain import NetworkTools
from .transfer import TICKET, OfflineFile, unpack_carried, write_ticket
from .workspace import Workspace, sha256_file

CHAIN, KEYS, ANY = "chain", "keys", "any"


@dataclass(frozen=True)
class Output:
    name: str
    secret: bool = False
    description: str = ""


@dataclass
class Step:
    id: str
    title: str
    where: str
    action: Callable[["Context", StepRecord], None]
    done: Callable[["Context", StepRecord], bool] | None = None
    outputs: Callable[["Context", StepRecord], list[Output]] = lambda ctx, rec: []
    precheck: Callable[["Context"], list[str]] = lambda ctx: []
    before: Callable[["Context", StepRecord], None] | None = None
    # Files (never secrets) the machine on the other side of a pause needs.
    carry: Callable[["Context", StepRecord], list[str]] = lambda ctx, rec: []
    # Safe to run again after an interruption whose outcome the probe can't see.
    rerunnable: bool = True


@dataclass(frozen=True)
class Param:
    name: str
    help: str
    required: bool = True
    parse: Callable[[str], object] = str
    default: object = None


class Workflow:
    name = ""
    summary = ""
    params: tuple[Param, ...] = ()
    needs_pool = False

    def validate(self, ctx: "Context") -> list[str]:
        """Check-time validation for *this* machine. Must not change anything."""
        return []

    def plan(self, ctx: "Context") -> list[Step]:
        raise NotImplementedError

    def init_run(self, ctx: "Context") -> None:
        """Pin run-wide data (e.g. the KES index) once, when a run starts."""

    def next_actions(self, ctx: "Context") -> list[str]:
        return []


@dataclass
class Context:
    ws: Workspace
    config: Config
    tools: NetworkTools
    scripts: ScriptRunner
    run: Run
    interactive: bool = True

    @property
    def params(self) -> dict:
        return self.run.params

    @property
    def pool(self) -> str:
        assert self.config.pool is not None
        return self.config.pool.name

    def offline_file(self) -> OfflineFile | None:
        return OfflineFile.read(self.ws.offline_file)


def can_run_here(config: Config, where: str) -> bool:
    if where == ANY:
        return True
    if where == CHAIN:
        return config.has_chain_access
    if where == KEYS:
        return config.role == "offline" if config.airgapped else True
    raise ValueError(where)


def machine_label(where: str) -> str:
    return {CHAIN: "online (or light) machine", KEYS: "offline signing machine"}.get(where, where)


def parse_params(workflow: Workflow, raw: dict[str, str]) -> dict:
    problems, values = [], {}
    known = {p.name for p in workflow.params}
    for key in raw:
        if key not in known:
            problems.append(f"unknown parameter --{key} for {workflow.name}")
    for p in workflow.params:
        if p.name in raw and raw[p.name] is not None:
            try:
                values[p.name] = p.parse(raw[p.name])
            except ValueError as e:
                problems.append(f"--{p.name}: {e}")
        elif p.required:
            problems.append(f"--{p.name} is required ({p.help})")
        else:
            values[p.name] = p.default
    if problems:
        raise CheckFailed(problems)
    return values


def base_problems(workflow: Workflow, ctx: Context) -> list[str]:
    problems = []
    if workflow.needs_pool and ctx.config.pool is None:
        problems.append(f"{workflow.name} needs a [pool] section in workbench.toml")
    if ctx.config.role == "online" and ctx.config.socket:
        sock = ctx.ws.root / ctx.config.socket  # an absolute socket path replaces the root
        if not sock.exists():
            problems.append(f"node socket {ctx.config.socket} does not exist (is cardano-node running?)")
    if ctx.config.network != ctx.run.network:
        problems.append(
            f"this run is for {ctx.run.network} but workbench.toml says {ctx.config.network}")
    return problems


@dataclass
class PlanEntry:
    step: Step
    record: StepRecord
    here: bool
    probe: bool | None


@dataclass
class Engine:
    ws: Workspace
    config: Config
    tools: NetworkTools
    workflows: dict[str, Workflow]
    assume_yes: bool = False
    interactive: bool = True
    notes: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.journal = Journal(self.ws.runs_dir)
        self.scripts = ScriptRunner(self.tools, self.ws.root, assume_yes=self.assume_yes)

    # ---- construction -------------------------------------------------

    def _context(self, run: Run) -> Context:
        return Context(self.ws, self.config, self.tools, self.scripts, run, self.interactive)

    def _workflow(self, name: str) -> Workflow:
        try:
            return self.workflows[name]
        except KeyError:
            raise WorkbenchError(
                f"unknown workflow '{name}'. Known: {', '.join(sorted(self.workflows))}") from None

    def _new_run(self, workflow: Workflow, raw: dict[str, str]) -> tuple[Run, Context]:
        params = parse_params(workflow, raw)
        stamp = J.now()
        run = Run(id=J.new_id(workflow.name), workflow=workflow.name, network=self.config.network,
                  params=params, created=stamp, updated=stamp)
        ctx = self._context(run)
        return run, ctx

    def _validate(self, workflow: Workflow, ctx: Context) -> list[Step]:
        problems = base_problems(workflow, ctx)
        if problems:
            raise CheckFailed(problems)
        # Records first: validate() looks at step status to tell a fresh run
        # from one resumed half-way (on possibly the other machine).
        steps = workflow.plan(ctx)
        known = {r.id for r in ctx.run.steps}
        for s in steps:
            if s.id not in known:
                ctx.run.steps.append(StepRecord(id=s.id, title=s.title))
        problems = workflow.validate(ctx) + self._handoff_problems(ctx, steps)
        if problems:
            raise CheckFailed(problems)
        return steps

    def _handoff_problems(self, ctx: Context, steps: list[Step]) -> list[str]:
        """An offline machine can only hand work back through an
        offlineTransfer.json that originated online: in offline mode
        01_workOffline.sh (attach included) refuses a file without protocol
        parameters. Check that before generating anything."""
        if not (self.config.airgapped and self.config.role == "offline"):
            return []
        hands_back = any(ctx.run.step(s.id).status != J.DONE and not can_run_here(self.config, s.where)
                         for s in steps)
        if not hands_back:
            return []
        off = OfflineFile.read(self.ws.offline_file)
        if off is None or not (off.data.get("protocol") or {}).get("parameters"):
            return [f"this run hands back to the online machine via {self.ws.offline_file.name}, "
                    "which must be created there first: run `workbench exec 01_workOffline.sh new` "
                    "on the online machine and copy the file here"]
        return []

    # ---- public API ---------------------------------------------------

    def check(self, name: str, raw: dict[str, str]) -> tuple[Run, list[PlanEntry]]:
        """Validate everything and describe the plan. Changes nothing."""
        workflow = self._workflow(name)
        self._require_no_unfinished(name)
        run, ctx = self._new_run(workflow, raw)
        workflow.init_run(ctx)
        steps = self._validate(workflow, ctx)
        self._require_first_step_here(steps)
        return run, self._describe(ctx, steps)

    def start(self, name: str, raw: dict[str, str]) -> Run:
        workflow = self._workflow(name)
        self._require_no_unfinished(name)
        run, ctx = self._new_run(workflow, raw)
        workflow.init_run(ctx)
        steps = self._validate(workflow, ctx)
        self._require_first_step_here(steps)
        self.journal.save(run)
        return self._execute(workflow, ctx, steps)

    def resume(self, run_id: str | None = None, mark_done: str | None = None,
               retry: str | None = None) -> Run:
        run = self._find_resumable(run_id)
        workflow = self._workflow(run.workflow)
        ctx = self._context(run)
        steps = self._validate(workflow, ctx)
        ids = {s.id for s in steps}
        for flag, sid in (("--mark-done", mark_done), ("--retry", retry)):
            if sid and sid not in ids:
                raise WorkbenchError(f"{flag}: {run.workflow} has no step '{sid}' ({', '.join(ids)})")
        if mark_done:
            rec = run.step(mark_done)
            rec.status, rec.adopted, rec.error = J.DONE, True, None
            rec.finished, rec.machine = J.now(), self.config.role
            rec.data["marked_done_by_operator"] = True
        if retry:
            rec = run.step(retry)
            rec.status, rec.error = J.PENDING, None
        run.status = J.RUN_ACTIVE
        self.journal.save(run)
        return self._execute(workflow, ctx, steps)

    def abandon(self, run_id: str) -> Run:
        """Mark a run as given up. Its files stay where they are."""
        run = self.journal.load(run_id)
        if run.status == J.RUN_DONE:
            raise WorkbenchError(f"run {run_id} already finished")
        run.status, run.waiting_for = J.RUN_ABANDONED, None
        run.next_actions = ["Files produced so far were left in place; inspect them before "
                            "starting the workflow again."]
        self.journal.save(run)
        return run

    # ---- internals ----------------------------------------------------

    def _require_no_unfinished(self, name: str) -> None:
        # Two interleaved runs of one workflow would fight over the same files
        # (KES counters, the offlineTransfer.json queue).
        open_runs = [r for r in self.journal.unfinished() if r.workflow == name]
        if open_runs:
            raise CheckFailed([
                f"run {r.id} of {name} is unfinished ({r.status}); continue it with "
                f"`workbench resume {r.id}` or drop it with `workbench abandon {r.id}`"
                for r in open_runs])

    def _require_first_step_here(self, steps: list[Step]) -> None:
        if steps and not can_run_here(self.config, steps[0].where):
            raise CheckFailed([
                f"this workflow starts with '{steps[0].title}', which runs on the "
                f"{machine_label(steps[0].where)}; start it there"
            ])

    def _describe(self, ctx: Context, steps: list[Step]) -> list[PlanEntry]:
        out = []
        for s in steps:
            rec = ctx.run.step(s.id)
            here = can_run_here(self.config, s.where)
            probe = None
            if s.done is not None and here:
                try:
                    probe = bool(s.done(ctx, rec))
                except (OSError, WorkbenchError):
                    probe = None
            out.append(PlanEntry(s, rec, here, probe))
        return out

    def _find_resumable(self, run_id: str | None) -> Run:
        offline = OfflineFile.read(self.ws.offline_file)
        ticket = offline.ticket() if offline else None

        if ticket and (run_id is None or ticket.id == run_id):
            local = self.journal.load(ticket.id) if self.journal.exists(ticket.id) else None
            if local is None or ticket.seq > local.seq:
                return self._import_ticket(ticket, offline)

        if run_id:
            return self.journal.load(run_id)
        candidates = self.journal.unfinished()
        if not candidates:
            raise WorkbenchError("nothing to resume: no unfinished runs and no workbench "
                                 f"ticket in {self.ws.offline_file.name}")
        if len(candidates) > 1:
            listing = "\n".join(f"  {r.id}  ({r.status})" for r in candidates)
            raise WorkbenchError(f"several unfinished runs; pass one id:\n{listing}")
        return candidates[0]

    def _import_ticket(self, ticket: Run, offline: OfflineFile) -> Run:
        if ticket.network != self.config.network:
            raise WorkbenchError(
                f"the ticket in {offline.path.name} is for {ticket.network}, "
                f"but this workspace is {self.config.network}")
        print(f"Found run {ticket.id} ({ticket.workflow}) in {offline.path.name}", file=sys.stderr)
        for k, v in ticket.params.items():
            print(f"  {k} = {v}", file=sys.stderr)
        if not self.assume_yes:
            if not (self.interactive and sys.stdin.isatty()):
                raise NeedsAttention("re-run with --yes to accept the imported run non-interactively")
            if input("Continue this run on this machine? [y/N] ").strip().lower() not in ("y", "yes"):
                raise NeedsAttention("import declined; nothing was changed")
        written = unpack_carried(self.ws.root, offline, ticket.data.get("carried", []))
        for name in written:
            self.notes.append(f"unpacked {name} from {offline.path.name}")
        ticket.status, ticket.waiting_for = J.RUN_ACTIVE, None
        self.journal.save(ticket)
        return ticket

    def _verify_artefacts(self, rec: StepRecord) -> None:
        if rec.machine != self.config.role:
            return
        changed = []
        for a in rec.artefacts:
            p = self.ws.path(a.path)
            if not p.exists():
                changed.append(f"{a.path} (missing)")
            elif sha256_file(p) != a.sha256:
                changed.append(f"{a.path} (content changed)")
        if changed:
            raise DriftError(
                f"step '{rec.title}' finished earlier, but its files changed since:\n"
                + "\n".join(f"  - {c}" for c in changed)
                + "\nRestore them, or start a new run if the change was intended.")

    def _record_outputs(self, step: Step, ctx: Context, rec: StepRecord) -> None:
        rec.artefacts = []
        missing = []
        for o in step.outputs(ctx, rec):
            p = self.ws.path(o.name)
            if not p.is_file():
                missing.append(o.name)
                continue
            rec.artefacts.append(Artefact(o.name, sha256_file(p), o.secret, o.description))
        if missing:
            raise StepFailed(f"'{step.title}' finished but did not produce: {', '.join(missing)}")

    def _pause(self, workflow: Workflow, ctx: Context, steps: list[Step], step: Step) -> Run:
        run = ctx.run
        run.status, run.waiting_for = J.RUN_PAUSED, step.where
        if not self.config.airgapped:
            raise NeedsAttention(
                f"step '{step.title}' must run on the {machine_label(step.where)}, "
                "but this workspace is not air-gapped (check role/airgapped in workbench.toml)")
        carried = []
        secrets = {a.path for r in run.steps for a in r.artefacts if a.secret}
        for s in steps:
            rec = run.step(s.id)
            if rec.status != J.DONE or rec.machine != self.config.role:
                continue
            for name in s.carry(ctx, rec):
                if name in secrets:
                    raise WorkbenchError(f"refusing to carry secret file {name}")
                carried.append({"path": name, "sha256": sha256_file(self.ws.path(name))})
        run.data["carried"] = carried
        run.seq += 1
        run.next_actions = [
            f"Move {self.ws.offline_file.name} to the workspace on your "
            f"{machine_label(step.where)} and run: workbench resume",
            *workflow.next_actions(ctx),
        ]
        for item in carried:
            self.scripts.run("01_workOffline.sh", "attach", item["path"])
        write_ticket(self.ws.root, run)
        try:
            self.scripts.run("01_workOffline.sh", "attach", TICKET)
        finally:
            self.ws.path(TICKET).unlink(missing_ok=True)
        self.journal.save(run)
        return run

    def _execute(self, workflow: Workflow, ctx: Context, steps: list[Step]) -> Run:
        run = ctx.run
        for step in steps:
            rec = run.step(step.id)
            if rec.status == J.DONE:
                self._verify_artefacts(rec)
                continue
            if not can_run_here(self.config, step.where):
                return self._pause(workflow, ctx, steps, step)

            if rec.status in (J.RUNNING, J.INTERRUPTED, J.FAILED):
                if step.done is not None and step.done(ctx, rec):
                    self._finish(step, ctx, rec, adopted=False)
                    continue
                if not step.rerunnable:
                    run.status = J.RUN_ATTENTION
                    self.journal.save(run)
                    raise NeedsAttention(
                        f"step '{step.title}' was {rec.status} and cannot be repeated blindly "
                        "(it may already have reached the chain).\nCheck what happened, then run "
                        f"`workbench resume {run.id} --mark-done {step.id}` if it took effect, "
                        f"or `--retry {step.id}` to run it again.")
            elif step.done is not None and step.done(ctx, rec):
                # The effect already exists before this run touched it.
                self._finish(step, ctx, rec, adopted=True)
                continue

            problems = step.precheck(ctx)
            if problems:
                raise CheckFailed(problems)
            rec.status, rec.started, rec.machine, rec.error = J.RUNNING, J.now(), self.config.role, None
            if step.before:
                step.before(ctx, rec)
            self.journal.save(run)
            try:
                step.action(ctx, rec)
                if step.done is not None and not step.done(ctx, rec):
                    raise StepFailed(f"'{step.title}' exited cleanly but its expected result is missing")
                self._finish(step, ctx, rec, adopted=False)
            except KeyboardInterrupt:
                rec.status, rec.error = J.INTERRUPTED, "interrupted by operator"
                run.status = J.RUN_FAILED
                self.journal.save(run)
                raise NeedsAttention(f"interrupted during '{step.title}'; run `workbench resume` to continue") from None
            except WorkbenchError as e:
                rec.status, rec.error = J.FAILED, str(e)
                run.status = J.RUN_FAILED
                self.journal.save(run)
                raise
        run.status, run.waiting_for = J.RUN_DONE, None
        run.next_actions = workflow.next_actions(ctx)
        self.journal.save(run)
        return run

    def _finish(self, step: Step, ctx: Context, rec: StepRecord, adopted: bool) -> None:
        rec.machine = rec.machine or self.config.role
        if adopted:
            rec.machine = self.config.role
        self._record_outputs(step, ctx, rec)
        rec.status, rec.finished, rec.adopted, rec.error = J.DONE, J.now(), adopted, None
        self.journal.save(ctx.run)
