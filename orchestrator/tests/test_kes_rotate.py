import json
import stat
import tarfile

import pytest

from spo_workbench.errors import CheckFailed, DriftError, NeedsAttention, StepFailed
from spo_workbench.journal import Journal

from conftest import carry


def mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def test_single_machine_rotation_produces_bundle(machine):
    m = machine(role="light")
    m.cold_keys()
    run = m.engine().start("kes-rotate", {})

    assert run.status == "done"
    assert [s.status for s in run.steps] == ["done"] * 4
    assert run.data["kes_index"] == 0
    assert [c[0] for c in m.calls()] == ["04c_genKESKeys.sh", "04d_genNodeOpCert.sh", "04e_checkNodeOpCert.sh"]

    bundle = m.root / f".workbench/out/{run.id}/mypool-kes-000-bp.tar"
    assert mode(bundle) == 0o600 and mode(bundle.parent) == 0o700
    with tarfile.open(bundle) as tar:
        assert sorted(tar.getnames()) == ["MANIFEST.json", "SHA256SUMS", "kes.skey", "node.opcert"]
        assert tar.extractfile("kes.skey").read() == (m.root / "mypool.kes-000.skey").read_bytes()
        assert all(i.mode == 0o400 for i in tar.getmembers())
        manifest = json.loads(tar.extractfile("MANIFEST.json").read())
    assert manifest["kesIndex"] == 0 and manifest["network"] == "preview"
    assert any("restart cardano-node" in a for a in run.next_actions)


def test_journal_never_contains_key_material(machine):
    m = machine(role="light")
    m.cold_keys()
    run = m.engine().start("kes-rotate", {})
    text = Journal(m.ws.runs_dir).path(run.id).read_text()
    assert "SECRET" not in text
    skey = next(a for s in run.steps for a in s.artefacts if a.path.endswith(".skey"))
    assert skey.secret


def test_workspace_and_state_are_private(machine):
    m = machine(role="light")
    m.root.chmod(0o755)
    m.cold_keys()
    e = m.engine()
    e.start("kes-rotate", {})
    assert mode(m.root) == 0o700
    assert mode(m.ws.state_dir) == 0o700
    assert all(mode(p) == 0o600 for p in m.ws.runs_dir.glob("*.json"))


def test_second_rotation_uses_next_index(machine):
    m = machine(role="light")
    m.cold_keys()
    m.engine().start("kes-rotate", {})
    run = m.engine().start("kes-rotate", {})
    assert run.data["kes_index"] == 1
    assert (m.root / "mypool.node-001.opcert").exists()
    assert (m.root / "mypool.kes.counter-next").read_text().strip() == "002"


def test_check_changes_nothing(machine):
    m = machine(role="light")
    m.cold_keys()
    engine = m.engine()  # (the fixture itself writes common.inc and .workbench/)
    before = sorted(p.name for p in m.root.iterdir())
    run, plan = engine.check("kes-rotate", {})
    assert [e.step.id for e in plan] == ["gen-kes", "gen-opcert", "package", "verify-opcert"]
    assert not m.calls()
    assert not list(m.ws.runs_dir.glob("*.json"))
    assert sorted(p.name for p in m.root.iterdir()) == before


@pytest.mark.parametrize("missing, message", [
    ("mypool.node.counter", "node.counter not found"),
    ("mypool.node.skey", "no signing key for mypool.node"),
    ("mypool.node.vkey", "node.vkey not found"),
])
def test_check_time_rejects_missing_inputs(machine, missing, message):
    m = machine(role="light")
    m.cold_keys()
    (m.root / missing).unlink()
    with pytest.raises(CheckFailed) as e:
        m.engine().start("kes-rotate", {})
    assert message in str(e.value)
    assert not m.calls()


def test_check_time_rejects_inconsistent_counters(machine):
    m = machine(role="light")
    m.cold_keys()
    m.file("mypool.kes.counter", "003\n")
    m.file("mypool.kes.counter-next", "007\n")
    with pytest.raises(CheckFailed, match="KES counters disagree"):
        m.engine().start("kes-rotate", {})


def test_half_done_manual_rotation_is_adopted(machine):
    m = machine(role="light")
    m.cold_keys()
    e = m.engine()
    e.scripts.run("04c_genKESKeys.sh", "mypool", "cli")  # operator ran 04c by hand earlier
    run = m.engine().start("kes-rotate", {})
    assert run.step("gen-kes").adopted
    assert run.status == "done"
    assert [c[0] for c in m.calls()].count("04c_genKESKeys.sh") == 1


def test_interrupted_opcert_needs_operator_decision(machine, monkeypatch):
    m = machine(role="light")
    m.cold_keys()
    monkeypatch.setenv("FAKE_FAIL_AFTER", "04d-partial")
    with pytest.raises(StepFailed):
        m.engine().start("kes-rotate", {})
    monkeypatch.delenv("FAKE_FAIL_AFTER")

    # 04d bumps the cold counter; repeating it blindly could skip a counter.
    with pytest.raises(NeedsAttention, match="--mark-done gen-opcert"):
        m.engine().resume()
    assert [c[0] for c in m.calls()].count("04d_genNodeOpCert.sh") == 1


def test_failed_step_with_clean_state_resumes(machine, monkeypatch):
    m = machine(role="light")
    m.cold_keys()
    monkeypatch.setenv("FAKE_FAIL", "04e_checkNodeOpCert.sh")
    with pytest.raises(StepFailed):
        m.engine().start("kes-rotate", {})
    monkeypatch.delenv("FAKE_FAIL")
    run = m.engine().resume()
    assert run.status == "done"
    calls = [c[0] for c in m.calls()]
    assert calls.count("04c_genKESKeys.sh") == 1 and calls.count("04d_genNodeOpCert.sh") == 1


def test_drift_in_finished_step_blocks_resume(machine, monkeypatch):
    m = machine(role="light")
    m.cold_keys()
    monkeypatch.setenv("FAKE_FAIL", "04d_genNodeOpCert.sh")
    with pytest.raises(StepFailed):
        m.engine().start("kes-rotate", {})
    monkeypatch.delenv("FAKE_FAIL")
    m.file("mypool.kes-000.vkey", "tampered")
    with pytest.raises(DriftError, match="mypool.kes-000.vkey"):
        m.engine().resume()


def test_airgapped_rotation_carries_only_the_opcert(machine):
    cold = machine("cold", role="offline", airgapped=True)
    hot = machine("hot", role="light", airgapped=True)
    cold.cold_keys()
    with pytest.raises(CheckFailed, match="must be created there first"):
        cold.engine().start("kes-rotate", {})
    assert not cold.calls()

    hot.engine().scripts.run("01_workOffline.sh", "new")
    carry(hot, cold)
    run = cold.engine().start("kes-rotate", {})
    assert run.status == "paused" and run.waiting_for == "chain"
    transfer = (cold.root / "offlineTransfer.json").read_text()
    assert "SECRET" not in transfer
    files = json.loads(transfer)["files"]
    assert set(files) == {"mypool.node-000.opcert", "workbench-ticket.json"}
    assert not (cold.root / "workbench-ticket.json").exists()

    carry(cold, hot)
    run = hot.engine().resume()
    assert run.status == "done"
    assert mode(hot.root / "mypool.node-000.opcert") == 0o400
    assert not (hot.root / "mypool.kes-000.skey").exists()
    assert hot.calls()[-1] == ["04e_checkNodeOpCert.sh", "mypool.node-000.opcert", "next"]


def test_kes_rotate_must_start_on_the_key_machine(machine):
    hot = machine("hot", role="light", airgapped=True)
    with pytest.raises(CheckFailed, match="offline signing machine"):
        hot.engine().start("kes-rotate", {})


def test_one_open_run_per_workflow(machine, monkeypatch):
    m = machine(role="light")
    m.cold_keys()
    monkeypatch.setenv("FAKE_FAIL", "04e_checkNodeOpCert.sh")
    with pytest.raises(StepFailed):
        m.engine().start("kes-rotate", {})
    monkeypatch.delenv("FAKE_FAIL")
    with pytest.raises(CheckFailed, match="unfinished"):
        m.engine().start("kes-rotate", {})
    (first,) = Journal(m.ws.runs_dir).unfinished()
    m.engine().abandon(first.id)
    assert m.engine().start("kes-rotate", {}).data["kes_index"] == 1


def test_new_run_refuses_to_reissue_after_partial_opcert(machine, monkeypatch):
    m = machine(role="light")
    m.cold_keys()
    monkeypatch.setenv("FAKE_FAIL_AFTER", "04d-partial")
    with pytest.raises(StepFailed):
        m.engine().start("kes-rotate", {})
    monkeypatch.delenv("FAKE_FAIL_AFTER")
    (first,) = Journal(m.ws.runs_dir).unfinished()
    m.engine().abandon(first.id)
    with pytest.raises(CheckFailed, match="Issuing again would skip a cold counter"):
        m.engine().start("kes-rotate", {})
    assert [c[0] for c in m.calls()].count("04d_genNodeOpCert.sh") == 1
