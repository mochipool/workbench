"""Error types. Each maps to a distinct process exit code (see cli.EXIT_CODES)."""


class WorkbenchError(Exception):
    """Base class; the message is shown to the operator verbatim."""


class ConfigError(WorkbenchError):
    """workbench.toml or the toolchain manifest is invalid."""


class CheckFailed(WorkbenchError):
    """Check-time validation found problems; nothing was changed."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("\n".join(f"  - {p}" for p in problems))


class StepFailed(WorkbenchError):
    """A step ran and failed; the run is resumable once the cause is fixed."""


class NeedsAttention(WorkbenchError):
    """The run cannot safely continue without an operator decision."""


class DriftError(WorkbenchError):
    """A file recorded by a finished step changed after the step completed."""


class Busy(WorkbenchError):
    """Another workbench process holds the workspace lock."""
