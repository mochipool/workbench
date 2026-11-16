"""Stand-ins for the SPO scripts, reproducing their file contracts.

Each fake behaves like the real script as far as the workbench can observe:
which files it creates, how it moves the KES counters, how it queues
transactions in offlineTransfer.json, and which modes it refuses. Failure
injection: FAKE_FAIL=<script> exits 1 before doing anything;
FAKE_FAIL_AFTER=<script> exits 1 after doing its work (an interruption whose
effect the probe may or may not see).
"""

import base64
import json
import os
import secrets
import sys
from pathlib import Path

script, args = sys.argv[1], sys.argv[2:]
cwd = Path.cwd()


def common():
    vals = {}
    for line in (cwd / "common.inc").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            vals[k] = v.strip('"')
    return vals


MODE = common()["workMode"]


def log():
    with open(cwd / ".fake-calls", "a") as f:
        f.write(json.dumps([script, *args]) + "\n")


def lock(name):
    os.chmod(cwd / name, 0o400)


def write(name, text):
    p = cwd / name
    if p.exists():
        os.chmod(p, 0o600)
    p.write_text(text)
    lock(name)


def read_int(name):
    p = cwd / name
    return int(p.read_text()) if p.exists() else None


def offline():
    p = cwd / "offlineTransfer.json"
    return json.loads(p.read_text()) if p.exists() and p.read_text().strip() else {}


def save_offline(d):
    (cwd / "offlineTransfer.json").write_text(json.dumps(d, indent=2))


def queue_or_submit(tx_type, **fields):
    tx = {"type": tx_type, "txJSON": {"cborHex": secrets.token_hex(16)}, **fields}
    if MODE == "offline":
        d = offline()
        d.setdefault("transactions", []).append(tx)
        save_offline(d)
    else:
        with open(cwd / ".fake-chain", "a") as f:
            f.write(json.dumps(tx) + "\n")


def done():
    if os.environ.get("FAKE_FAIL_AFTER") == script:
        sys.exit(1)
    sys.exit(0)


log()
if os.environ.get("FAKE_FAIL") == script:
    sys.exit(1)

if script == "04c_genKESKeys.sh":
    pool = args[0]
    cur, nxt = read_int(f"{pool}.kes.counter"), read_int(f"{pool}.kes.counter-next")
    if nxt is None:
        nxt = 0 if cur is None else cur + 1
        write(f"{pool}.kes.counter-next", f"{nxt:03d}\n")
    if nxt == cur:
        sys.exit(2)
    for ext in ("vkey", "skey"):
        if (cwd / f"{pool}.kes-{nxt:03d}.{ext}").exists():
            sys.exit(2)
    write(f"{pool}.kes-{nxt:03d}.vkey", json.dumps({"type": "KesVerificationKey", "cborHex": secrets.token_hex(8)}))
    write(f"{pool}.kes-{nxt:03d}.skey", json.dumps({"type": "KesSigningKey", "cborHex": "SECRET" + secrets.token_hex(8)}))
    write(f"{pool}.kes.counter", f"{nxt:03d}\n")
    done()

elif script == "04d_genNodeOpCert.sh":
    pool = args[0]
    cur, nxt = read_int(f"{pool}.kes.counter"), read_int(f"{pool}.kes.counter-next")
    if cur is None or cur != nxt:
        sys.exit(2)
    if not (cwd / f"{pool}.node.counter").exists():
        sys.exit(2)
    counter = json.loads((cwd / f"{pool}.node.counter").read_text())
    issue = counter.get("next", 0)
    write(f"{pool}.node-{cur:03d}.opcert", json.dumps({"type": "NodeOperationalCertificate", "issue": issue}))
    if os.environ.get("FAKE_FAIL_AFTER") == "04d-partial":
        sys.exit(1)
    write(f"{pool}.node.counter", json.dumps({"next": issue + 1}))
    write(f"{pool}.kes-expire.json", json.dumps({"latestKESfileindex": f"{cur:03d}",
                                                  "expireKESperiod": "1050",
                                                  "expireKESdate": "Tue 16 Feb 2027"}))
    write(f"{pool}.kes.counter-next", f"{cur + 1:03d}\n")
    done()

elif script == "04e_checkNodeOpCert.sh":
    sys.exit(1 if MODE == "offline" else 0)

elif script == "01_workOffline.sh":
    action = args[0]
    if action in ("new", "add", "execute") and MODE == "offline":
        sys.exit(1)
    d = offline()
    # readOfflineFile in 00_common.sh: offline mode needs a file made online.
    if MODE == "offline" and not (d.get("protocol") or {}).get("parameters"):
        sys.exit(1)
    if action == "new":
        save_offline({"protocol": {"era": "conway", "parameters": {"txFeePerByte": 44}}, "history": []})
    elif action == "add":
        addr = (cwd / f"{args[1]}.addr").read_text().strip()
        d.setdefault("address", {})[addr] = {"name": args[1], "totalamount": 10_000_000}
        save_offline(d)
    elif action == "attach":
        blob = (cwd / args[1]).read_bytes()
        d.setdefault("files", {})[args[1]] = {"size": str(len(blob)), "base64": base64.b64encode(blob).decode()}
        save_offline(d)
    elif action == "execute":
        idx = int(args[1]) - 1 if len(args) > 1 else 0
        tx = d["transactions"].pop(idx)
        with open(cwd / ".fake-chain", "a") as f:
            f.write(json.dumps(tx) + "\n")
        save_offline(d)
    done()

elif script == "01_claimRewards.sh":
    queue_or_submit("Withdrawal", stakeAddr=args[0], toAddr=args[1])
    done()

elif script == "01_sendLovelaces.sh":
    queue_or_submit("Transaction", fromAddr=args[0], toAddr=args[1], amount=args[2])
    done()

elif script == "05a_genStakepoolCert.sh":
    pool = args[0]
    cfg = json.loads((cwd / f"{pool}.pool.json").read_text())
    write(f"{pool}.pool.cert", json.dumps({"type": "CertificateShelley", "pledge": cfg["poolPledge"]}))
    write(f"{pool}.metadata.json", json.dumps({"name": cfg["poolMetaName"], "ticker": cfg["poolMetaTicker"]}))
    done()

elif script == "05c_regStakepoolCert.sh":
    queue_or_submit("PoolReRegistration", poolMetaTicker="TEST")
    done()

else:
    sys.exit(f"fake: no stand-in for {script}")
