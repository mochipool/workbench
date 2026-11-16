"""claim-rewards, send-ada and pool-update."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request

from ..engine import CHAIN, KEYS, Context, Output, Param, Step, can_run_here
from ..errors import StepFailed
from ..journal import DONE
from ..validate import (amount, check_pool_json, message, stake_name, wallet_name)
from .tx import TxWorkflow


def _msg(ctx) -> list[str]:
    return [f"msg: {ctx.params['message']}"] if ctx.params.get("message") else []


MESSAGE = Param("message", "transaction message; | separates lines (max 64 bytes each)",
                required=False, parse=message)


class ClaimRewards(TxWorkflow):
    name = "claim-rewards"
    summary = "Withdraw staking rewards to a payment address"
    params = (
        Param("stake", "stake account name, e.g. owner (uses owner.staking.*)", parse=stake_name),
        Param("to", "destination wallet name, e.g. owner.payment", parse=wallet_name),
        Param("payer", "wallet that pays the fee (default: the destination)",
              required=False, parse=wallet_name),
        MESSAGE,
    )

    def fee_payer(self, ctx):
        return ctx.params.get("payer") or ctx.params["to"]

    def chain_addresses(self, ctx):
        return [(f"{ctx.params['stake']}.staking.addr", True), (f"{self.fee_payer(ctx)}.addr", False)]

    def signing_keys(self, ctx):
        return [f"{ctx.params['stake']}.staking", self.fee_payer(ctx)]

    def extra_validate(self, ctx):
        p = []
        if can_run_here(ctx.config, KEYS) and not ctx.ws.exists(f"{ctx.params['to']}.addr"):
            p.append(f"{ctx.params['to']}.addr not found in {ctx.ws.root}")
        return p

    def command(self, ctx):
        args = [f"{ctx.params['stake']}.staking", ctx.params["to"]]
        if ctx.params.get("payer"):
            args.append(ctx.params["payer"])
        return "01_claimRewards.sh", args + _msg(ctx)


def recipient(value: str) -> str:
    v = value.strip()
    if v.startswith(("addr1", "addr_test1", "$")):
        return v
    return wallet_name(v)


class SendAda(TxWorkflow):
    name = "send-ada"
    summary = "Send ADA from one of your wallets"
    params = (
        Param("from", "source wallet name", parse=wallet_name),
        Param("to", "destination: wallet name, bech32 address or $adahandle", parse=recipient),
        Param("amount", "lovelace, '<n>ada', ALL, ALLFUNDS or MIN", parse=amount),
        MESSAGE,
    )

    def _to_is_name(self, ctx):
        return not ctx.params["to"].startswith(("addr", "$"))

    def chain_addresses(self, ctx):
        return [(f"{ctx.params['from']}.addr", False)]

    def signing_keys(self, ctx):
        return [ctx.params["from"]]

    def extra_validate(self, ctx):
        p = []
        to = ctx.params["to"]
        if self._to_is_name(ctx) and can_run_here(ctx.config, KEYS) and not ctx.ws.exists(f"{to}.addr"):
            p.append(f"{to}.addr not found in {ctx.ws.root}")
        if to.startswith("addr"):
            testnet = to.startswith("addr_test1")
            if testnet != (ctx.config.network != "mainnet"):
                p.append(f"destination address is not a {ctx.config.network} address")
        if to.startswith("$") and ctx.config.airgapped:
            p.append("$adahandle destinations need chain access to resolve; use a bech32 address offline")
        return p

    def command(self, ctx):
        return "01_sendLovelaces.sh", [ctx.params["from"], ctx.params["to"], ctx.params["amount"], *_msg(ctx)]


class PoolUpdate(TxWorkflow):
    name = "pool-update"
    summary = "Re-register the pool after editing <pool>.pool.json (pledge, cost, margin, relays, metadata)"
    needs_pool = True
    params = (Param("payer", "wallet that pays the fee and deposit", parse=wallet_name),)

    def _pool_json(self, ctx) -> dict:
        try:
            return json.loads(ctx.ws.read_text(f"{ctx.pool}.pool.json"))
        except (OSError, ValueError):
            return {}

    def chain_addresses(self, ctx):
        return [(f"{ctx.params['payer']}.addr", False)]

    def signing_keys(self, ctx):
        owners = [o.get("ownerName") for o in self._pool_json(ctx).get("poolOwner", [])]
        return [ctx.params["payer"], f"{ctx.pool}.node", *[f"{o}.staking" for o in owners if o]]

    def extra_validate(self, ctx):
        if can_run_here(ctx.config, KEYS) and ctx.run.step("gen-cert").status != DONE:
            return check_pool_json(ctx.ws, ctx.pool)
        return []

    def command(self, ctx):
        return "05c_regStakepoolCert.sh", [ctx.pool, ctx.params["payer"]]

    def _metadata(self, ctx):
        return f"{ctx.pool}.metadata.json"

    def _gen_cert(self, ctx) -> Step:
        def run(ctx, rec):
            ctx.scripts.run("05a_genStakepoolCert.sh", ctx.pool)
            rec.data["metadata_url"] = self._pool_json(ctx).get("poolMetaUrl")

        return Step(
            "gen-cert", "Generate pool certificate and metadata (05a)", KEYS, run,
            outputs=lambda ctx, rec: [Output(f"{ctx.pool}.pool.cert", description="pool certificate"),
                                      Output(self._metadata(ctx), description="pool metadata")],
            carry=lambda ctx, rec: [self._metadata(ctx)])

    def _check_metadata(self, ctx) -> Step:
        def run(ctx, rec):
            url = ctx.run.step("gen-cert").data.get("metadata_url")
            local = ctx.ws.path(self._metadata(ctx))
            if not url or not re.match(r"https?://", url):
                raise StepFailed("no poolMetaUrl recorded for this run")
            try:
                with urllib.request.urlopen(url, timeout=30) as resp:
                    remote = resp.read(1 << 16)
            except (urllib.error.URLError, OSError) as e:
                raise StepFailed(f"could not fetch {url}: {e}. Upload {local.name} there, "
                                 "then run `workbench resume`") from None
            if hashlib.sha256(remote).digest() != hashlib.sha256(local.read_bytes()).digest():
                raise StepFailed(
                    f"{url} does not serve the new {local.name} byte-for-byte. Upload "
                    f"{local} to that URL, then run `workbench resume`. (The registration "
                    "commits to the metadata hash, so wallets would reject a mismatch.)")

        return Step("check-metadata", "Check the published metadata matches", CHAIN, run)

    def extra_steps_before_sign(self, ctx):
        steps = [self._gen_cert(ctx)]
        if not ctx.config.airgapped:
            steps.append(self._check_metadata(ctx))
        return steps

    def extra_steps_after_sign(self, ctx):
        return [self._check_metadata(ctx)] if ctx.config.airgapped else []
