"""Check-time validators shared by workflows.

These mirror rules the SPO scripts enforce part-way through a run, so a bad
input fails before anything is generated, signed or queued.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation

from .config import is_valid_name
from .workspace import Workspace

LOVELACE_PER_ADA = 1_000_000
SPECIAL_AMOUNTS = ("ALL", "ALLFUNDS", "MIN")


def strip_suffix(name: str, *suffixes: str) -> str:
    for s in suffixes:
        if name.endswith(s):
            return name[: -len(s)]
    return name


def wallet_name(value: str) -> str:
    """A payment wallet name as the scripts take it (`owner.payment`, `smallwallet1`)."""
    name = strip_suffix(value, ".addr")
    for part in name.split("."):
        if not is_valid_name(part):
            raise ValueError(f"{value!r} is not a valid wallet name")
    return name


def stake_name(value: str) -> str:
    """A stake account base name; `owner` and `owner.staking` both mean owner."""
    name = strip_suffix(strip_suffix(value, ".addr"), ".staking")
    if not is_valid_name(name):
        raise ValueError(f"{value!r} is not a valid stake account name")
    return name


def amount(value: str) -> str:
    """Lovelace as an integer string, `<n>ada`, or ALL / ALLFUNDS / MIN."""
    v = value.strip()
    if v.upper() in SPECIAL_AMOUNTS:
        return v.upper()
    m = re.fullmatch(r"([0-9]+(?:\.[0-9]{1,6})?)\s*(ada|ADA|₳)", v)
    try:
        lovelace = int(Decimal(m.group(1)) * LOVELACE_PER_ADA) if m else int(v)
    except (ValueError, InvalidOperation):
        raise ValueError(f"{value!r} is not an amount (lovelace, '<n>ada', ALL, ALLFUNDS or MIN)") from None
    if lovelace < LOVELACE_PER_ADA:
        raise ValueError(f"{value!r} is below 1 ADA, which no output can carry")
    return str(lovelace)


def message(value: str) -> str:
    for line in value.split("|"):
        if len(line.encode()) > 64:
            raise ValueError("each message line (separated by |) must be at most 64 bytes")
    return value


def address_prefixes(network: str, stake: bool) -> tuple[str, ...]:
    if network == "mainnet":
        return ("stake1",) if stake else ("addr1", "Ae2", "DdzFF")
    return ("stake_test1",) if stake else ("addr_test1",)


def check_address_file(ws: Workspace, network: str, file: str, stake: bool = False) -> list[str]:
    if not ws.exists(file):
        return [f"{file} not found in {ws.root}"]
    addr = ws.read_text(file).strip()
    if not addr.startswith(address_prefixes(network, stake)):
        kind = "stake address" if stake else "payment address"
        return [f"{file} does not hold a {network} {kind} (starts {addr[:12]!r})"]
    return []


def check_signing_key(ws: Workspace, base: str) -> list[str]:
    if ws.exists(f"{base}.skey") or ws.exists(f"{base}.hwsfile"):
        return []
    return [f"no signing key for {base}: expected {base}.skey or {base}.hwsfile"]


def check_pool_json(ws: Workspace, pool: str) -> list[str]:
    """The checks 05a_genStakepoolCert.sh would make, done up front."""
    file = f"{pool}.pool.json"
    if not ws.exists(file):
        return [f"{file} not found; generate a template with 05a_genStakepoolCert.sh {pool}"]
    try:
        cfg = json.loads(ws.read_text(file))
    except ValueError as e:
        return [f"{file} is not valid JSON: {e}"]
    p = []

    def field(key):
        v = cfg.get(key)
        return "" if v is None else str(v)

    if field("poolName") != pool:
        p.append(f"{file}: poolName is {field('poolName')!r}, expected {pool!r}")
    for key in ("poolPledge", "poolCost"):
        if not field(key).isdigit():
            p.append(f"{file}: {key} must be a whole number of lovelace, got {field(key)!r}")
    try:
        margin = Decimal(field("poolMargin"))
        if not (0 <= margin <= 1):
            raise InvalidOperation
    except InvalidOperation:
        p.append(f"{file}: poolMargin must be between 0.00 and 1.00, got {field('poolMargin')!r}")
    owners = cfg.get("poolOwner") or []
    if not owners:
        p.append(f"{file}: poolOwner lists no owners")
    for o in owners:
        if o.get("ownerWitness", "local") not in ("local", ""):
            p.append(f"{file}: owner {o.get('ownerName')!r} uses an external witness; "
                     "collect it with 05d_poolWitness.sh, this workflow handles local witnesses only")
    relays = cfg.get("poolRelays") or []
    if not relays:
        p.append(f"{file}: poolRelays lists no relays")
    for r in relays:
        if r.get("relayType") not in ("ip", "ip6", "dns", "srv"):
            p.append(f"{file}: relay {r.get('relayEntry')!r} has unknown relayType {r.get('relayType')!r}")
        port = str(r.get("relayPort", ""))
        if r.get("relayType") != "srv" and not (port.isdigit() and 0 < int(port) < 65536):
            p.append(f"{file}: relay {r.get('relayEntry')!r} has invalid relayPort {port!r}")
    if len(field("poolMetaName")) > 50:
        p.append(f"{file}: poolMetaName is longer than 50 characters")
    if not 3 <= len(field("poolMetaTicker")) <= 5:
        p.append(f"{file}: poolMetaTicker must be 3-5 characters")
    if len(field("poolMetaDescription")) > 255:
        p.append(f"{file}: poolMetaDescription is longer than 255 characters")
    for key in ("poolMetaHomepage", "poolMetaUrl"):
        v = field(key)
        if not re.match(r"https?://", v) or len(v) > 128:
            p.append(f"{file}: {key} must be an http(s) URL of at most 128 characters")
    return p
