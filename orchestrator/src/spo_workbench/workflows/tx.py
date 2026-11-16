"""Shared shape of transaction workflows (claim-rewards, send-ada, pool-update).

Not air-gapped: one step runs the script, which builds, signs and submits.
It can reach the chain, so it is never repeated blindly after an
interruption.

Air-gapped:
  prepare  (online)   01_workOffline.sh new + add <each address>
  sign     (offline)  the script, which queues the signed tx in offlineTransfer.json
  execute  (online)   01_workOffline.sh execute <our tx>

The signed transaction is identified by the digest of its body, recorded
when signing; execute is done when that transaction has left the queue.
"""

from __future__ import annotations

from ..errors import StepFailed
from ..engine import CHAIN, KEYS, Context, Step, Workflow, can_run_here
from ..journal import DONE
from ..validate import check_address_file


class TxWorkflow(Workflow):
    # Subclasses provide these ------------------------------------------
    def chain_addresses(self, ctx: Context) -> list[tuple[str, bool]]:
        """(.addr file, is_stake) pairs whose state the offline side needs."""
        raise NotImplementedError

    def signing_keys(self, ctx: Context) -> list[str]:
        """Key base names (without .skey/.hwsfile) the signing step needs."""
        raise NotImplementedError

    def command(self, ctx: Context) -> tuple[str, list[str]]:
        raise NotImplementedError

    def extra_steps_before_sign(self, ctx: Context) -> list[Step]:
        return []

    def extra_steps_after_sign(self, ctx: Context) -> list[Step]:
        return []

    def extra_validate(self, ctx: Context) -> list[str]:
        return []

    # Shared -------------------------------------------------------------
    def validate(self, ctx: Context) -> list[str]:
        from ..validate import check_signing_key
        p = []
        if can_run_here(ctx.config, CHAIN):
            for file, stake in self.chain_addresses(ctx):
                p += check_address_file(ctx.ws, ctx.config.network, file, stake)
            if ctx.config.airgapped and self._fresh(ctx):
                p += self._queue_problems(ctx)
        if can_run_here(ctx.config, KEYS) and ctx.run.step("sign").status != DONE:
            for base in self.signing_keys(ctx):
                p += check_signing_key(ctx.ws, base)
        return p + self.extra_validate(ctx)

    def _fresh(self, ctx: Context) -> bool:
        return all(r.status != DONE for r in ctx.run.steps)

    def _queue_problems(self, ctx: Context) -> list[str]:
        off = ctx.offline_file()
        if off is None:
            return []
        p = []
        if off.transactions:
            p.append(f"{off.path.name} still has {len(off.transactions)} queued transaction(s); "
                     "submit them (01_workOffline.sh execute) or clear them (cleartx) first")
        if off.foreign_files():
            p.append(f"{off.path.name} has attached files ({', '.join(off.foreign_files())}); "
                     "extract them (01_workOffline.sh extract) first")
        return p

    def _addr(self, ctx, file):
        return ctx.ws.read_text(file).strip()

    def plan(self, ctx: Context) -> list[Step]:
        script, args = self.command(ctx)
        if not ctx.config.airgapped:
            def submit(ctx, rec):
                ctx.scripts.run(script, *args)
            return [*self.extra_steps_before_sign(ctx),
                    Step("sign", f"Build, sign and submit ({script})", KEYS, submit, rerunnable=False),
                    *self.extra_steps_after_sign(ctx)]

        # No done-probe: balances must be fresh, so a prepared file is never
        # adopted from before this run. Re-running it is harmless.
        def prepare(ctx, rec):
            ctx.scripts.run("01_workOffline.sh", "new")
            for file, _ in self.chain_addresses(ctx):
                ctx.scripts.run("01_workOffline.sh", "add", file.removesuffix(".addr"))
            off = ctx.offline_file()
            missing = [f for f, _ in self.chain_addresses(ctx)
                       if off is None or self._addr(ctx, f) not in off.addresses]
            if missing:
                raise StepFailed(f"offlineTransfer.json lacks entries for: {', '.join(missing)}")

        def snapshot(ctx, rec):
            off = ctx.offline_file()
            rec.data["before"] = off.fingerprints() if off else []

        def sign(ctx, rec):
            ctx.scripts.run(script, *args)

        def signed(ctx, rec):
            off = ctx.offline_file()
            if off is None or "before" not in rec.data:
                return False
            new = [fp for fp in off.fingerprints() if fp not in rec.data["before"]]
            if len(new) == 1:
                rec.data["tx"] = new[0]
                return True
            return False

        def tx_of(ctx):
            return ctx.run.step("sign").data.get("tx")

        def execute(ctx, rec):
            off = ctx.offline_file()
            fps = off.fingerprints() if off else []
            if tx_of(ctx) not in fps:
                raise StepFailed("the signed transaction is no longer queued in offlineTransfer.json")
            ctx.scripts.run("01_workOffline.sh", "execute", str(fps.index(tx_of(ctx)) + 1))

        def executed(ctx, rec):
            off = ctx.offline_file()
            return bool(tx_of(ctx)) and off is not None and tx_of(ctx) not in off.fingerprints()

        return [
            Step("prepare", "Load balances into offlineTransfer.json", CHAIN, prepare),
            *self.extra_steps_before_sign(ctx),
            Step("sign", f"Build and sign offline ({script})", KEYS, sign, done=signed, before=snapshot),
            *self.extra_steps_after_sign(ctx),
            Step("execute", "Submit the signed transaction", CHAIN, execute, done=executed),
        ]
