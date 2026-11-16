"""workbench.toml: the operator's declaration of what this machine is.

Validation is strict on purpose: unknown sections and keys are errors, so a
typo (`airgaped = true`) fails loudly instead of silently running a signing
step on an online machine.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError
from .toolchain import NETWORKS

FILENAME = "workbench.toml"
ROLES = ("online", "light", "offline")
KEY_TYPES = ("cli", "enc")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SCRIPT_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# common.inc keys the workbench owns. Letting workbench.toml override them
# would break the release-set guarantee (binaries) or the role model (mode).
MANAGED_SCRIPT_KEYS = frozenset({
    "network", "workMode", "workmode", "socket", "offlineFile",
    "cardanocli", "cardanonode", "cardanohwcli", "cardanosigner", "bech32_bin",
    "genesisfile", "genesisfile_byron",
})


@dataclass(frozen=True)
class PoolConfig:
    name: str
    kes_key: str = "cli"


@dataclass(frozen=True)
class BundleConfig:
    kes_skey: str = "kes.skey"
    opcert: str = "node.opcert"
    include_vrf: bool = False


@dataclass(frozen=True)
class Config:
    network: str
    role: str
    airgapped: bool
    socket: str | None
    pool: PoolConfig | None
    bundle: BundleConfig
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def has_chain_access(self) -> bool:
        return self.role in ("online", "light")


def is_valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


class _Table:
    """Reads one TOML table, recording problems instead of raising early."""

    def __init__(self, data: dict, section: str, problems: list[str]):
        self.data = dict(data)
        self.section = section
        self.problems = problems

    def take(self, key, kind, default=None, required=False, choices=None):
        where = f"[{self.section}] {key}"
        if key not in self.data:
            if required:
                self.problems.append(f"{where} is required")
            return default
        value = self.data.pop(key)
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            self.problems.append(f"{where} must be a {kind.__name__}, got {value!r}")
            return default
        if choices and value not in choices:
            self.problems.append(f"{where} must be one of {', '.join(choices)}; got {value!r}")
            return default
        return value

    def finish(self):
        for key in self.data:
            self.problems.append(f"[{self.section}] unknown key '{key}'")


def parse(data: dict, source: str = FILENAME) -> Config:
    problems: list[str] = []
    data = dict(data)

    wb = _Table(data.pop("workbench", {}), "workbench", problems)
    network = wb.take("network", str, required=True, choices=NETWORKS)
    role = wb.take("role", str, required=True, choices=ROLES)
    airgapped = wb.take("airgapped", bool, default=False)
    socket = wb.take("socket", str)
    wb.finish()

    if role == "online" and not socket:
        problems.append("[workbench] socket is required when role = \"online\"")
    if role != "online" and socket:
        problems.append("[workbench] socket only applies when role = \"online\"")
    if role == "offline" and not airgapped:
        problems.append(
            "[workbench] role = \"offline\" requires airgapped = true "
            "(an offline machine cannot submit transactions by itself)"
        )

    pool = None
    if "pool" in data:
        pt = _Table(data.pop("pool"), "pool", problems)
        name = pt.take("name", str, required=True)
        kes_key = pt.take("kes_key", str, default="cli", choices=KEY_TYPES)
        pt.finish()
        if name is not None and not is_valid_name(name):
            problems.append(f"[pool] name {name!r} must match {NAME_RE.pattern}")
        if name is not None:
            pool = PoolConfig(name=name, kes_key=kes_key)

    bt = _Table(data.pop("bundle", {}), "bundle", problems)
    bundle = BundleConfig(
        kes_skey=bt.take("kes_skey", str, default="kes.skey"),
        opcert=bt.take("opcert", str, default="node.opcert"),
        include_vrf=bt.take("include_vrf", bool, default=False),
    )
    bt.finish()
    for label, value in (("kes_skey", bundle.kes_skey), ("opcert", bundle.opcert)):
        if "/" in value or value.startswith("."):
            problems.append(f"[bundle] {label} must be a plain file name, got {value!r}")

    scripts = {}
    for key, value in data.pop("scripts", {}).items():
        if not SCRIPT_KEY_RE.match(key):
            problems.append(f"[scripts] {key!r} is not a valid shell variable name")
        elif key in MANAGED_SCRIPT_KEYS:
            problems.append(f"[scripts] {key} is managed by the workbench and cannot be overridden")
        elif not isinstance(value, (str, int, bool)) or isinstance(value, float):
            problems.append(f"[scripts] {key} must be a string, integer or boolean")
        else:
            scripts[key] = str(value).lower() if isinstance(value, bool) else str(value)

    for section in data:
        problems.append(f"unknown section [{section}]")

    if problems:
        raise ConfigError(f"{source} is invalid:\n" + "\n".join(f"  - {p}" for p in problems))
    return Config(
        network=network, role=role, airgapped=airgapped, socket=socket,
        pool=pool, bundle=bundle, scripts=scripts,
    )


def load(workspace: Path) -> Config:
    path = workspace / FILENAME
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(
            f"{path} not found. Create a workspace with `workbench init`."
        ) from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    return parse(data, str(path))


def render(network: str, role: str, airgapped: bool, pool: str | None,
           socket: str | None = None) -> str:
    """The workbench.toml written by `workbench init`."""
    lines = [
        "# Workbench workspace configuration. See docs/reference/workbench-toml.md.",
        "[workbench]",
        f'network = "{network}"',
        f'role = "{role}"            # what THIS machine is: online | light | offline',
        f"airgapped = {'true' if airgapped else 'false'}       # signing keys live on a separate offline machine",
    ]
    if socket:
        lines.append(f'socket = "{socket}"')
    if pool:
        lines += ["", "[pool]", f'name = "{pool}"', 'kes_key = "cli"          # cli | enc']
    lines += [
        "",
        "# Names used inside the block-producer bundle made by kes-rotate.",
        "[bundle]",
        'kes_skey = "kes.skey"',
        'opcert = "node.opcert"',
        "include_vrf = false",
        "",
    ]
    return "\n".join(lines)
