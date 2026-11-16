import json
import shutil
import sys
from pathlib import Path

import pytest

from spo_workbench import config as cfgmod
from spo_workbench.engine import Engine
from spo_workbench.toolchain import load as load_toolchain
from spo_workbench.workflows import REGISTRY
from spo_workbench.workspace import Workspace

HERE = Path(__file__).parent
SCRIPTS = ["04c_genKESKeys.sh", "04d_genNodeOpCert.sh", "04e_checkNodeOpCert.sh",
           "01_workOffline.sh", "01_claimRewards.sh", "01_sendLovelaces.sh",
           "05a_genStakepoolCert.sh", "05c_regStakepoolCert.sh"]

TEST_ADDR = "addr_test1vz" + "q" * 50
TEST_STAKE = "stake_test1uz" + "q" * 48


@pytest.fixture
def toolchain_path(tmp_path) -> Path:
    bindir = tmp_path / "toolchain" / "bin"
    bindir.mkdir(parents=True)
    fake = HERE / "fake_scripts.py"
    for name in SCRIPTS:
        p = bindir / name
        p.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$(basename "$0")" "$@"\n')
        p.chmod(0o755)
    genesis = tmp_path / "toolchain" / "shelley-genesis.json"
    genesis.write_text("{}")
    common = {"network": "Preview", "workMode": "light", "cardanocli": "/fake/cardano-cli",
              "genesisfile": str(genesis), "genesisfile_byron": str(genesis)}
    manifest = tmp_path / "toolchain" / "toolchain.json"
    manifest.write_text(json.dumps({
        "release": {"spo-scripts": "fake"},
        "networks": {n: {"scriptsDir": str(bindir), "common": common} for n in ("preview", "preprod", "mainnet")},
    }))
    return manifest


class Machine:
    """One workspace + engine, i.e. one physical machine in a test."""

    def __init__(self, root: Path, toolchain: Path, role: str, airgapped: bool, pool="mypool"):
        root.mkdir(parents=True, exist_ok=True)
        (root / cfgmod.FILENAME).write_text(cfgmod.render("preview", role, airgapped, pool))
        self.root, self.toolchain, self.ws = root, toolchain, Workspace(root)

    def engine(self, **kw) -> Engine:
        config = cfgmod.load(self.root)
        tools = load_toolchain(self.toolchain).for_network(config.network)
        self.ws.ensure_private()
        self.ws.write_common_inc(config, tools)
        e = Engine(self.ws, config, tools, REGISTRY, assume_yes=True, interactive=False, **kw)
        e.scripts.echo = False
        return e

    def file(self, name, text, mode=0o400):
        p = self.root / name
        if p.exists():
            p.chmod(0o600)
        p.write_text(text)
        p.chmod(mode)
        return p

    def calls(self) -> list[list[str]]:
        p = self.root / ".fake-calls"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def chain(self) -> list[dict]:
        p = self.root / ".fake-chain"
        return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []

    def cold_keys(self, pool="mypool"):
        self.file(f"{pool}.node.vkey", '{"type":"StakePoolVerificationKey"}')
        self.file(f"{pool}.node.skey", '{"type":"StakePoolSigningKey","cborHex":"COLDSECRET"}')
        self.file(f"{pool}.node.counter", json.dumps({"next": 0}))
        self.file(f"{pool}.vrf.skey", '{"type":"VrfSigningKey","cborHex":"VRFSECRET"}')

    def wallet(self, name, addr=TEST_ADDR, keys=True):
        self.file(f"{name}.addr", addr + "\n")
        if keys:
            self.file(f"{name}.skey", '{"cborHex":"WALLETSECRET"}')

    def stake(self, name, keys=True):
        self.file(f"{name}.staking.addr", TEST_STAKE + "\n")
        if keys:
            self.file(f"{name}.staking.skey", '{"cborHex":"STAKESECRET"}')


@pytest.fixture
def machine(tmp_path, toolchain_path):
    def make(name="ws", role="light", airgapped=False, pool="mypool"):
        return Machine(tmp_path / name, toolchain_path, role, airgapped, pool)
    return make


def carry(src: Machine, dst: Machine) -> None:
    """The operator walking offlineTransfer.json across on a USB stick."""
    shutil.copy(src.root / "offlineTransfer.json", dst.root / "offlineTransfer.json")
