"""The workspace: the flat directory the SPO scripts run in, plus .workbench/.

The scripts address every file by bare name relative to the current
directory, so the workspace root *is* the scripts' working directory. The
workbench keeps its own state under .workbench/ and owns ./common.inc, which
the scripts source last and which therefore wins over ~/.common.inc.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import stat
import tempfile
from pathlib import Path

from .config import Config
from .errors import Busy, ConfigError
from .toolchain import NetworkTools

STATE_DIR = ".workbench"
COMMON_INC = "common.inc"
OFFLINE_FILE = "offlineTransfer.json"
MANAGED_MARKER = "# managed-by: spo-workbench"

WORK_MODE = {"online": "online", "light": "light", "offline": "offline"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: Path, data: str | bytes, mode: int = 0o600) -> None:
    """Write via a same-directory temp file, fsync, then rename into place."""
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700)
        path.parent.chmod(0o700)  # mkdir's mode is filtered through the umask
    raw = data.encode() if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def is_locked(path: Path) -> bool:
    """True when the file is read-only for its owner (the scripts' file_lock)."""
    return not (path.stat().st_mode & stat.S_IWUSR)


@contextlib.contextmanager
def unlocked(path: Path):
    """Temporarily make a script-locked file writable, then restore its mode."""
    original = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0o600)
    try:
        yield path
    finally:
        path.chmod(original)


class Workspace:
    def __init__(self, root: Path):
        self.root = root.resolve()

    @property
    def state_dir(self) -> Path:
        return self.root / STATE_DIR

    @property
    def runs_dir(self) -> Path:
        return self.state_dir / "runs"

    @property
    def out_dir(self) -> Path:
        return self.state_dir / "out"

    @property
    def offline_file(self) -> Path:
        return self.root / OFFLINE_FILE

    def path(self, name: str) -> Path:
        return self.root / name

    def exists(self, name: str) -> bool:
        return (self.root / name).is_file()

    def read_text(self, name: str) -> str:
        return (self.root / name).read_text()

    def ensure_private(self) -> list[str]:
        """Tighten permissions of the workspace and its state directory.

        Returns notes about what was changed, for the run report.
        """
        notes = []
        for d in (self.root, self.state_dir, self.runs_dir, self.out_dir):
            if not d.exists():
                d.mkdir(parents=True, mode=0o700)
                d.chmod(0o700)  # mkdir's mode is filtered through the umask
                continue
            mode = stat.S_IMODE(d.stat().st_mode)
            if mode & 0o077:
                d.chmod(0o700)
                notes.append(f"tightened {d} from {mode:o} to 700")
        return notes

    @contextlib.contextmanager
    def lock(self):
        """Exclusive advisory lock so two workbench processes never interleave."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.state_dir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy(f"another workbench process is using {self.root}") from None
            yield
        finally:
            os.close(fd)

    def write_common_inc(self, config: Config, tools: NetworkTools) -> Path:
        """(Re)generate ./common.inc from the release set and workbench.toml.

        Refuses to replace a common.inc the operator wrote by hand.
        """
        path = self.root / COMMON_INC
        if path.exists():
            first = path.read_text().splitlines()[:1]
            if first != [MANAGED_MARKER]:
                raise ConfigError(
                    f"{path} exists and was not written by the workbench. Move its "
                    "settings into the [scripts] table of workbench.toml, then delete it."
                )
        settings = dict(tools.common)
        settings["workMode"] = WORK_MODE[config.role]
        settings["offlineFile"] = f"./{OFFLINE_FILE}"
        if config.socket:
            settings["socket"] = config.socket
        settings.update(config.scripts)
        body = [
            MANAGED_MARKER,
            "# Generated by `workbench` on every run from the pinned release set and",
            "# workbench.toml. Edits here are overwritten; use [scripts] in workbench.toml.",
        ]
        for key in sorted(settings):
            value = settings[key].replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
            body.append(f'{key}="{value}"')
        atomic_write(path, "\n".join(body) + "\n", mode=0o600)
        return path
