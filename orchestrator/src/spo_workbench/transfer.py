"""offlineTransfer.json: read-only parsing plus the workbench run ticket.

Writes to offlineTransfer.json always go through the upstream
`01_workOffline.sh` so its format and history stay authoritative. The
workbench only *reads* it directly: to inspect pending transactions, and to
decode its own ticket and carried files on the receiving machine.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .errors import WorkbenchError
from .journal import Run
from .workspace import atomic_write, sha256_file

TICKET = "workbench-ticket.json"


def tx_fingerprint(tx: dict) -> str:
    """Stable identity of a queued transaction: the digest of its signed body."""
    return hashlib.sha256(json.dumps(tx.get("txJSON"), sort_keys=True).encode()).hexdigest()


@dataclass
class OfflineFile:
    path: Path
    data: dict

    @classmethod
    def read(cls, path: Path) -> "OfflineFile | None":
        if not path.is_file():
            return None
        text = path.read_text().strip()
        if not text:
            return cls(path, {})
        try:
            data = json.loads(text)
        except ValueError as e:
            raise WorkbenchError(f"{path} is not valid JSON: {e}") from None
        if not isinstance(data, dict):
            raise WorkbenchError(f"{path} does not contain a JSON object")
        return cls(path, data)

    @property
    def transactions(self) -> list[dict]:
        return list(self.data.get("transactions") or [])

    @property
    def files(self) -> dict[str, dict]:
        return dict(self.data.get("files") or {})

    @property
    def addresses(self) -> dict:
        return dict(self.data.get("address") or {})

    def fingerprints(self) -> list[str]:
        return [tx_fingerprint(t) for t in self.transactions]

    def foreign_files(self) -> list[str]:
        return [name for name in self.files if name != TICKET]

    def decode_file(self, name: str) -> bytes:
        entry = self.files.get(name)
        if not entry or "base64" not in entry:
            raise WorkbenchError(f"{self.path.name} has no attached file '{name}'")
        return base64.b64decode(entry["base64"])

    def ticket(self) -> Run | None:
        if TICKET not in self.files:
            return None
        try:
            return Run.from_dict(json.loads(self.decode_file(TICKET)))
        except (ValueError, TypeError) as e:
            raise WorkbenchError(f"workbench ticket in {self.path.name} is corrupt: {e}") from None


def write_ticket(root: Path, run: Run) -> Path:
    path = root / TICKET
    atomic_write(path, run.to_json(), mode=0o600)
    return path


def unpack_carried(root: Path, offline: OfflineFile, carried: list[dict]) -> list[str]:
    """Write carried files next to the scripts, verifying their digests.

    An existing file with the same digest is left alone; a different one is
    an error, never overwritten.
    """
    written = []
    for item in carried:
        name, digest = item["path"], item["sha256"]
        if "/" in name or name.startswith("."):
            raise WorkbenchError(f"refusing to unpack carried file with unsafe name {name!r}")
        blob = offline.decode_file(name)
        if hashlib.sha256(blob).hexdigest() != digest:
            raise WorkbenchError(f"carried file {name} does not match the digest in the ticket")
        target = root / name
        if target.exists():
            if sha256_file(target) != digest:
                raise WorkbenchError(
                    f"{name} already exists here with different content; "
                    "move it aside and resume again"
                )
            continue
        atomic_write(target, blob, mode=0o400)
        written.append(name)
    return written
