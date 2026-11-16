import tomllib

import pytest

from spo_workbench import config as cfgmod
from spo_workbench.cli import main
from spo_workbench.errors import Busy, ConfigError
from spo_workbench.validate import amount
from spo_workbench.workspace import MANAGED_MARKER


def parse(text):
    return cfgmod.parse(tomllib.loads(text))


def test_rendered_config_round_trips():
    for role, airgapped in (("light", False), ("offline", True), ("online", True)):
        cfg = parse(cfgmod.render("preview", role, airgapped, "mypool",
                                  socket="db/node.socket" if role == "online" else None))
        assert cfg.role == role and cfg.pool.name == "mypool"


@pytest.mark.parametrize("text, message", [
    ('[workbench]\nnetwork="preview"\nrole="light"\nairgaped=true', "unknown key 'airgaped'"),
    ('[workbench]\nnetwork="testnet"\nrole="light"', "must be one of"),
    ('[workbench]\nnetwork="preview"\nrole="offline"', "requires airgapped = true"),
    ('[workbench]\nnetwork="preview"\nrole="online"', "socket is required"),
    ('[workbench]\nnetwork="preview"\nrole="light"\n[scripts]\ncardanocli="/tmp/evil"', "managed by the workbench"),
    ('[workbench]\nnetwork="preview"\nrole="light"\n[pool]\nname="../x"', "must match"),
    ('[workbench]\nnetwork="preview"\nrole="light"\n[extra]', "unknown section"),
])
def test_config_rejects(text, message):
    with pytest.raises(ConfigError, match=message):
        parse(text)


def test_common_inc_is_generated_and_owned(machine):
    m = machine(role="offline", airgapped=True)
    m.engine()
    text = (m.root / "common.inc").read_text()
    assert text.startswith(MANAGED_MARKER)
    assert 'workMode="offline"' in text and 'offlineFile="./offlineTransfer.json"' in text


def test_hand_written_common_inc_is_not_clobbered(machine):
    m = machine()
    (m.root / "common.inc").write_text('workMode="online"\n')
    with pytest.raises(ConfigError, match="not written by the workbench"):
        m.engine()


def test_scripts_table_values_are_shell_escaped(machine):
    m = machine()
    with open(m.root / "workbench.toml", "a") as f:
        f.write('\n[scripts]\nkoiosApiToken = "a\\"$(touch pwned)`x`"\n')
    m.engine()
    line = next(l for l in (m.root / "common.inc").read_text().splitlines() if l.startswith("koios"))
    assert line == 'koiosApiToken="a\\"\\$(touch pwned)\\`x\\`"'


def test_workspace_lock_is_exclusive(machine):
    m = machine()
    with m.ws.lock():
        with pytest.raises(Busy):
            with m.ws.lock():
                pass


@pytest.mark.parametrize("given, lovelace", [("1000000", "1000000"), ("2ada", "2000000"),
                                             ("1.5 ADA", "1500000"), ("all", "ALL")])
def test_amounts(given, lovelace):
    assert amount(given) == lovelace


def test_cli_end_to_end(tmp_path, toolchain_path, capsys):
    ws = tmp_path / "pool"
    assert main(["init", "-C", str(ws), "--network", "preview", "--role", "light", "--pool", "mypool"]) == 0
    assert main(["init", "-C", str(ws), "--network", "preview", "--role", "light"]) == 3
    tc = ["--toolchain", str(toolchain_path)]
    assert main(["check", "kes-rotate", "-C", str(ws), *tc]) == 4  # no cold keys yet
    assert "node.vkey not found" in capsys.readouterr().err
    for name, body in (("mypool.node.vkey", "{}"), ("mypool.node.skey", "{}"),
                       ("mypool.node.counter", '{"next": 0}')):
        (ws / name).write_text(body)
    assert main(["check", "kes-rotate", "-C", str(ws), *tc]) == 0
    assert main(["-C", str(ws), *tc, "run", "kes-rotate"]) == 0
    out = capsys.readouterr().out
    assert "DONE" in out and "SECRET" in out and "Artefacts" in out
    assert main(["status", "-C", str(ws), "--json"]) == 0
    assert main(["runs", "-C", str(ws)]) == 0


def test_exec_runs_a_script_with_managed_config(tmp_path, toolchain_path):
    ws = tmp_path / "pool"
    main(["init", "-C", str(ws), "--network", "preview", "--role", "light"])
    code = main(["exec", "-C", str(ws), "--toolchain", str(toolchain_path), "04e_checkNodeOpCert.sh", "x", "next"])
    assert code == 0
    assert (ws / "common.inc").read_text().startswith("# managed-by")
    assert main(["exec", "-C", str(ws), "--toolchain", str(toolchain_path), "../evil.sh"]) == 1
