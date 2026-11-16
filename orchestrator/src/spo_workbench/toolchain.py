"""The pinned toolchain, as described by the JSON manifest that Nix generates.

The manifest maps each network to the SPO scripts variant built for it and to
the common.inc settings (binary paths, genesis files) of the release set. The
Nix wrapper exports its path in SPO_WB_TOOLCHAIN; nothing here searches PATH,
so a workbench run always uses the binaries of the release set it was built
with.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigError

NETWORKS = ("mainnet", "preprod", "preview")
ENV_VAR = "SPO_WB_TOOLCHAIN"


@dataclass(frozen=True)
class NetworkTools:
    name: str
    scripts_dir: Path
    common: dict[str, str]

    def script(self, name: str) -> Path:
        return self.scripts_dir / name

    @property
    def shelley_genesis(self) -> Path:
        return Path(self.common["genesisfile"])


@dataclass(frozen=True)
class Toolchain:
    source: Path
    release: dict[str, str]
    networks: dict[str, NetworkTools]

    def for_network(self, network: str) -> NetworkTools:
        try:
            return self.networks[network]
        except KeyError:
            raise ConfigError(
                f"toolchain {self.source} has no tools for network '{network}'"
            ) from None


def load(path: str | os.PathLike | None = None) -> Toolchain:
    raw_path = path or os.environ.get(ENV_VAR)
    if not raw_path:
        raise ConfigError(
            f"{ENV_VAR} is not set. Run workbench through the Nix package "
            "(nix run .#workbench) or from inside `nix develop`."
        )
    source = Path(raw_path)
    try:
        data = json.loads(source.read_text())
    except (OSError, ValueError) as e:
        raise ConfigError(f"cannot read toolchain manifest {source}: {e}") from None

    networks = {}
    for name, entry in data.get("networks", {}).items():
        try:
            networks[name] = NetworkTools(
                name=name,
                scripts_dir=Path(entry["scriptsDir"]),
                common={k: str(v) for k, v in entry["common"].items()},
            )
        except (KeyError, TypeError, AttributeError):
            raise ConfigError(f"toolchain {source}: malformed entry for '{name}'") from None
    if not networks:
        raise ConfigError(f"toolchain {source} lists no networks")
    return Toolchain(source=source, release=dict(data.get("release", {})), networks=networks)
