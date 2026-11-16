import json

import pytest

from spo_workbench.errors import CheckFailed, NeedsAttention, StepFailed

from conftest import TEST_ADDR, carry

CLAIM = {"stake": "owner", "to": "owner.payment", "payer": "smallwallet1"}


def airgapped_pair(machine):
    hot = machine("hot", role="light", airgapped=True)
    cold = machine("cold", role="offline", airgapped=True)
    for m in (hot, cold):
        m.stake("owner", keys=m is cold)
        m.wallet("owner.payment", keys=False)
        m.wallet("smallwallet1", keys=m is cold)
    return hot, cold


def test_claim_rewards_round_trip(machine):
    hot, cold = airgapped_pair(machine)

    run = hot.engine().start("claim-rewards", CLAIM)
    assert run.status == "paused" and run.waiting_for == "keys"
    assert hot.calls() == [["01_workOffline.sh", "new"],
                           ["01_workOffline.sh", "add", "owner.staking"],
                           ["01_workOffline.sh", "add", "smallwallet1"],
                           ["01_workOffline.sh", "attach", "workbench-ticket.json"]]

    carry(hot, cold)
    run = cold.engine().resume()
    assert run.status == "paused" and run.waiting_for == "chain"
    assert cold.calls()[0] == ["01_claimRewards.sh", "owner.staking", "owner.payment", "smallwallet1"]

    carry(cold, hot)
    run = hot.engine().resume()
    assert run.status == "done"
    assert [s.machine for s in run.steps] == ["light", "offline", "light"]
    assert hot.chain()[0]["type"] == "Withdrawal"
    assert not json.loads((hot.root / "offlineTransfer.json").read_text())["transactions"]


def test_resuming_with_a_stale_ticket_does_not_rerun(machine):
    hot, cold = airgapped_pair(machine)
    hot.engine().start("claim-rewards", CLAIM)
    # Operator forgets to carry the file and resumes on the online machine.
    run = hot.engine().resume()
    assert run.status == "paused"
    assert [c[1] for c in hot.calls()].count("new") == 1


def test_execute_targets_our_transaction_among_others(machine):
    hot, cold = airgapped_pair(machine)
    cold.wallet("smallwallet2")
    hot.engine().start("claim-rewards", CLAIM)
    carry(hot, cold)
    cold.engine().resume()
    # A second, unrelated transaction queued by hand ahead of ours.
    data = json.loads((cold.root / "offlineTransfer.json").read_text())
    data["transactions"].insert(0, {"type": "Transaction", "txJSON": {"cborHex": "other"}})
    (cold.root / "offlineTransfer.json").write_text(json.dumps(data))
    carry(cold, hot)
    hot.engine().resume()
    assert hot.calls()[-1] == ["01_workOffline.sh", "execute", "2"]
    left = json.loads((hot.root / "offlineTransfer.json").read_text())["transactions"]
    assert left == [{"type": "Transaction", "txJSON": {"cborHex": "other"}}]


def test_refuses_to_reset_a_transfer_file_with_queued_work(machine):
    hot, _ = airgapped_pair(machine)
    hot.file("offlineTransfer.json", json.dumps({"transactions": [{"txJSON": {}}]}), mode=0o600)
    with pytest.raises(CheckFailed, match="queued transaction"):
        hot.engine().start("claim-rewards", CLAIM)
    assert not hot.calls()


def test_rejects_addresses_for_the_wrong_network(machine):
    hot, _ = airgapped_pair(machine)
    hot.wallet("smallwallet1", addr="addr1q" + "x" * 50, keys=False)
    with pytest.raises(CheckFailed, match="does not hold a preview payment address"):
        hot.engine().start("claim-rewards", CLAIM)


def test_offline_side_requires_its_keys(machine):
    hot, cold = airgapped_pair(machine)
    (cold.root / "owner.staking.skey").unlink()
    hot.engine().start("claim-rewards", CLAIM)
    carry(hot, cold)
    with pytest.raises(CheckFailed, match="owner.staking"):
        cold.engine().resume()


def test_imported_ticket_for_another_network_is_refused(machine):
    hot, cold = airgapped_pair(machine)
    hot.engine().start("claim-rewards", CLAIM)
    carry(hot, cold)
    toml = (cold.root / "workbench.toml").read_text().replace('"preview"', '"preprod"')
    (cold.root / "workbench.toml").write_text(toml)
    with pytest.raises(Exception, match="for preview"):
        cold.engine().resume()


def test_local_submit_is_never_repeated_blindly(machine, monkeypatch):
    m = machine(role="light")
    m.wallet("smallwallet1")
    m.wallet("friend", keys=False)
    monkeypatch.setenv("FAKE_FAIL_AFTER", "01_sendLovelaces.sh")
    with pytest.raises(StepFailed):
        m.engine().start("send-ada", {"from": "smallwallet1", "to": "friend", "amount": "5ada"})
    monkeypatch.delenv("FAKE_FAIL_AFTER")
    with pytest.raises(NeedsAttention, match="--mark-done sign"):
        m.engine().resume()
    run = m.engine().resume(mark_done="sign")
    assert run.status == "done" and run.step("sign").data["marked_done_by_operator"]
    assert len(m.chain()) == 1


def test_send_ada_converts_and_validates_amount(machine):
    m = machine(role="light")
    m.wallet("smallwallet1")
    run = m.engine().start("send-ada", {"from": "smallwallet1", "to": TEST_ADDR, "amount": "2.5ada"})
    assert run.params["amount"] == "2500000"
    assert m.calls()[0] == ["01_sendLovelaces.sh", "smallwallet1", TEST_ADDR, "2500000"]
    with pytest.raises(CheckFailed, match="below 1 ADA"):
        m.engine().start("send-ada", {"from": "smallwallet1", "to": TEST_ADDR, "amount": "1000"})
    with pytest.raises(CheckFailed, match="not a preview address"):
        m.engine().start("send-ada", {"from": "smallwallet1", "to": "addr1qxyz", "amount": "MIN"})


def test_unknown_and_missing_parameters(machine):
    m = machine(role="light")
    with pytest.raises(CheckFailed) as e:
        m.engine().start("send-ada", {"from": "a", "colour": "blue"})
    assert "--to is required" in str(e.value) and "unknown parameter --colour" in str(e.value)


POOL = {
    "poolName": "mypool", "poolOwner": [{"ownerName": "owner", "ownerWitness": "local"}],
    "poolRewards": "owner", "poolPledge": "100000000", "poolCost": "340000000", "poolMargin": "0.02",
    "poolRelays": [{"relayType": "dns", "relayEntry": "relay.example.org", "relayPort": "3001"}],
    "poolMetaName": "Example", "poolMetaDescription": "x", "poolMetaTicker": "EXMPL",
    "poolMetaHomepage": "https://example.org", "poolMetaUrl": "https://example.org/m.json",
    "poolExtendedMetaUrl": "",
}


@pytest.mark.parametrize("patch, message", [
    ({"poolMargin": "1.5"}, "poolMargin"),
    ({"poolMetaTicker": "TOOLONG"}, "3-5 characters"),
    ({"poolPledge": "100 ada"}, "whole number"),
    ({"poolRelays": [{"relayType": "dns", "relayEntry": "r", "relayPort": "99999"}]}, "relayPort"),
    ({"poolOwner": [{"ownerName": "owner", "ownerWitness": "external"}]}, "external witness"),
    ({"poolMetaUrl": "ftp://x"}, "poolMetaUrl"),
])
def test_pool_json_is_validated_before_anything_runs(machine, patch, message):
    m = machine(role="light")
    m.cold_keys()
    m.wallet("smallwallet1")
    m.stake("owner")
    m.file("mypool.pool.json", json.dumps({**POOL, **patch}), mode=0o400)
    with pytest.raises(CheckFailed, match=message):
        m.engine().start("pool-update", {"payer": "smallwallet1"})
    assert not m.calls()


def test_pool_update_stops_until_metadata_is_published(machine, monkeypatch):
    m = machine(role="light")
    m.cold_keys()
    m.wallet("smallwallet1")
    m.stake("owner")
    m.file("mypool.pool.json", json.dumps(POOL), mode=0o400)

    served = {"body": b"old"}

    class Resp:
        def __init__(self):
            self.body = served["body"]
        def read(self, n):
            return self.body
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout: Resp())
    with pytest.raises(StepFailed, match="does not serve the new mypool.metadata.json"):
        m.engine().start("pool-update", {"payer": "smallwallet1"})
    assert not m.chain()

    served["body"] = (m.root / "mypool.metadata.json").read_bytes()
    run = m.engine().resume()
    assert run.status == "done"
    assert m.chain()[0]["type"] == "PoolReRegistration"
