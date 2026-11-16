"""Drives the packaged `workbench` against the real SPO scripts and cardano-cli.

Opt-in, because it needs the full release-set toolchain:

    nix build .#workbench -o result-workbench
    SPO_WB_E2E_WORKBENCH=$PWD/result-workbench/bin/workbench pytest -m e2e

Everything runs in offline mode on preview, so no node or network is needed
until the final (optional) light-mode verification step.
"""

import json
import os
import shutil
import subprocess
import tarfile

import pytest

pytestmark = pytest.mark.e2e
WB = os.environ.get("SPO_WB_E2E_WORKBENCH")


def wb(*args, cwd, ok=(0,)):
    proc = subprocess.run([WB, "-C", str(cwd), *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode in ok, f"{args}: exit {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return proc


@pytest.mark.skipif(not WB, reason="set SPO_WB_E2E_WORKBENCH to the packaged workbench")
def test_real_kes_rotation_offline(tmp_path):
    cold, hot = tmp_path / "cold", tmp_path / "hot"
    wb("init", "--network", "preview", "--role", "offline", "--airgapped", "--pool", "mypool", cwd=cold)
    wb("init", "--network", "preview", "--role", "light", "--airgapped", "--pool", "mypool", cwd=hot)

    wb("exec", "04a_genNodeKeys.sh", "mypool", "cli", cwd=cold)
    wb("exec", "04b_genVRFKeys.sh", "mypool", "cli", cwd=cold)
    # The hand-off needs an offlineTransfer.json that originated online.
    assert "must be created there first" in wb("run", "kes-rotate", cwd=cold, ok=(4,)).stderr
    assert not (cold / "mypool.kes.counter").exists()
    wb("exec", "01_workOffline.sh", "new", cwd=hot)
    shutil.copy(hot / "offlineTransfer.json", cold / "offlineTransfer.json")
    plan = json.loads(wb("check", "kes-rotate", "--json", cwd=cold).stdout)
    assert [s["id"] for s in plan["steps"]] == ["gen-kes", "gen-opcert", "package", "verify-opcert"]

    out = json.loads(wb("run", "kes-rotate", "--json", cwd=cold, ok=(10,)).stdout)["run"]
    assert out["status"] == "paused" and out["waiting_for"] == "chain"
    assert (cold / "mypool.node-000.opcert").stat().st_mode & 0o777 == 0o400
    assert (cold / "mypool.kes.counter-next").read_text().strip() == "001"

    skey = json.loads((cold / "mypool.kes-000.skey").read_text())["cborHex"]
    transfer = (cold / "offlineTransfer.json").read_text()
    assert skey not in transfer
    assert set(json.loads(transfer)["files"]) == {"mypool.node-000.opcert", "workbench-ticket.json"}
    for run_file in (cold / ".workbench/runs").iterdir():
        assert skey not in run_file.read_text()

    bundle = cold / ".workbench/out" / out["id"] / "mypool-kes-000-bp.tar"
    with tarfile.open(bundle) as tar:
        assert json.loads(tar.extractfile("kes.skey").read())["cborHex"] == skey
        sums = tar.extractfile("SHA256SUMS").read().decode()
    assert "kes.skey" in sums and "node.opcert" in sums

    # A second rotation cannot start while the first waits for verification.
    assert "unfinished" in wb("run", "kes-rotate", cwd=cold, ok=(4,)).stderr

    shutil.copy(cold / "offlineTransfer.json", hot / "offlineTransfer.json")
    # Light mode asks Koios about the (unregistered) pool, so the check itself
    # fails, but the opcert must have been unpacked and verified by digest.
    wb("resume", "--yes", cwd=hot, ok=(0, 5))
    assert (hot / "mypool.node-000.opcert").read_bytes() == (cold / "mypool.node-000.opcert").read_bytes()
    assert not (hot / "mypool.kes-000.skey").exists()
