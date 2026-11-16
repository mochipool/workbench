"""kes-rotate: new KES keys, a new operational certificate, and a bundle for
the block producer.

The rotation index N is pinned when the run starts, so every probe asks
"does rotation N exist?" rather than reading counters that the steps
themselves move:

  gen-kes     done when <pool>.kes.counter == N and <pool>.kes-N.skey exists
  gen-opcert  done when <pool>.node-N.opcert exists and kes.counter-next == N+1
"""

from __future__ import annotations

import io
import json
import tarfile
import time

from ..engine import ANY, CHAIN, KEYS, Context, Output, Step, Workflow, can_run_here
from ..journal import StepRecord
from ..validate import check_signing_key
from ..workspace import atomic_write, sha256_file


def _read_counter(ctx: Context, name: str) -> int | None:
    if not ctx.ws.exists(name):
        return None
    text = ctx.ws.read_text(name).strip()
    if not text.isdigit():
        raise ValueError(f"{name} does not contain a number: {text!r}")
    return int(text)


class KesRotate(Workflow):
    name = "kes-rotate"
    summary = "Rotate the KES keys and issue a new opcert; package them for the block producer"
    needs_pool = True

    # -- names ------------------------------------------------------------
    def n(self, ctx: Context) -> int:
        return ctx.run.data["kes_index"]

    def kes(self, ctx, ext):
        return f"{ctx.pool}.kes-{self.n(ctx):03d}.{ext}"

    def opcert(self, ctx):
        return f"{ctx.pool}.node-{self.n(ctx):03d}.opcert"

    def bundle(self, ctx):
        return f".workbench/out/{ctx.run.id}/{ctx.pool}-kes-{self.n(ctx):03d}-bp.tar"

    # -- lifecycle --------------------------------------------------------
    def init_run(self, ctx: Context) -> None:
        if not can_run_here(ctx.config, KEYS) or ctx.config.pool is None:
            return
        try:
            nxt = _read_counter(ctx, f"{ctx.pool}.kes.counter-next")
            cur = _read_counter(ctx, f"{ctx.pool}.kes.counter")
        except ValueError:
            nxt = cur = None  # reported by validate()
        if nxt is not None:
            ctx.run.data["kes_index"] = nxt
        else:
            ctx.run.data["kes_index"] = 0 if cur is None else cur + 1

    def validate(self, ctx: Context) -> list[str]:
        p = []
        pool = ctx.pool
        if not can_run_here(ctx.config, KEYS):
            # Resumed on the online machine: only the verification step is left.
            if "kes_index" in ctx.run.data and not ctx.ws.exists(self.opcert(ctx)):
                p.append(f"{self.opcert(ctx)} is missing on this machine")
            return p
        p += [f"{pool}.node.vkey not found (generate cold keys with 04a_genNodeKeys.sh)"] \
            if not ctx.ws.exists(f"{pool}.node.vkey") else []
        p += check_signing_key(ctx.ws, f"{pool}.node")
        if not ctx.ws.exists(f"{pool}.node.counter"):
            p.append(f"{pool}.node.counter not found; 04d would stop to ask about creating one. "
                     "Create it deliberately with the on-chain counter value first")
        if not ctx.tools.shelley_genesis.is_file():
            p.append(f"shelley genesis {ctx.tools.shelley_genesis} is missing from the toolchain")
        try:
            cur = _read_counter(ctx, f"{pool}.kes.counter")
            nxt = _read_counter(ctx, f"{pool}.kes.counter-next")
        except ValueError as e:
            return p + [str(e)]
        if cur is not None and nxt is not None and nxt not in (cur, cur + 1):
            p.append(f"KES counters disagree: kes.counter={cur}, kes.counter-next={nxt}; "
                     "resolve this by hand before rotating")
        if "kes_index" in ctx.run.data and ctx.run.step("gen-kes").status == "pending":
            n = self.n(ctx)
            if cur != n:
                for ext in ("skey", "vkey"):
                    if ctx.ws.exists(self.kes(ctx, ext)):
                        p.append(f"{self.kes(ctx, ext)} already exists but kes.counter is not {n}; "
                                 "a previous rotation was left half-done")
        if "kes_index" in ctx.run.data and ctx.run.step("gen-opcert").status == "pending":
            n = self.n(ctx)
            if ctx.ws.exists(self.opcert(ctx)) and nxt != n + 1:
                p.append(f"{self.opcert(ctx)} exists but kes.counter-next is not {n + 1}: an earlier "
                         "04d was interrupted after issuing it. Issuing again would skip a cold "
                         f"counter; check {pool}.node.counter against the opcert before continuing")
        return p

    def plan(self, ctx: Context) -> list[Step]:
        pool = ctx.pool
        key_type = ctx.config.pool.kes_key
        cfg = ctx.config.bundle

        def gen_kes(ctx, rec):
            ctx.scripts.run("04c_genKESKeys.sh", pool, key_type)

        def kes_done(ctx, rec):
            return (_read_counter(ctx, f"{pool}.kes.counter") == self.n(ctx)
                    and ctx.ws.exists(self.kes(ctx, "skey")) and ctx.ws.exists(self.kes(ctx, "vkey")))

        def gen_opcert(ctx, rec):
            ctx.scripts.run("04d_genNodeOpCert.sh", pool)

        def opcert_done(ctx, rec):
            return (ctx.ws.exists(self.opcert(ctx))
                    and _read_counter(ctx, f"{pool}.kes.counter-next") == self.n(ctx) + 1)

        def members(ctx):
            m = [(cfg.kes_skey, self.kes(ctx, "skey")), (cfg.opcert, self.opcert(ctx))]
            if cfg.include_vrf:
                m.append(("vrf.skey", f"{pool}.vrf.skey"))
            return m

        def package(ctx, rec):
            sums, manifest_files = [], {}
            buf = io.BytesIO()
            stamp = int(time.time())
            with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
                def add(arcname, data):
                    info = tarfile.TarInfo(arcname)
                    info.size, info.mode, info.mtime = len(data), 0o400, stamp
                    tar.addfile(info, io.BytesIO(data))
                for arcname, src in members(ctx):
                    data = ctx.ws.path(src).read_bytes()
                    add(arcname, data)
                    digest = sha256_file(ctx.ws.path(src))
                    sums.append(f"{digest}  {arcname}")
                    manifest_files[arcname] = {"source": src, "sha256": digest}
                expire = {}
                if ctx.ws.exists(f"{pool}.kes-expire.json"):
                    expire = json.loads(ctx.ws.read_text(f"{pool}.kes-expire.json"))
                manifest = {
                    "pool": pool, "network": ctx.config.network, "kesIndex": self.n(ctx),
                    "kesKeyType": key_type, "run": ctx.run.id, "files": manifest_files,
                    "kesExpiry": expire,
                }
                add("MANIFEST.json", (json.dumps(manifest, indent=2) + "\n").encode())
                add("SHA256SUMS", ("\n".join(sums) + "\n").encode())
            atomic_write(ctx.ws.path(self.bundle(ctx)), buf.getvalue(), mode=0o600)
            rec.data["members"] = {a: s for a, s in members(ctx)}

        def package_done(ctx, rec):
            path = ctx.ws.path(self.bundle(ctx))
            if not path.is_file():
                return False
            with tarfile.open(path) as tar:
                names = set(tar.getnames())
            return all(a in names for a, _ in members(ctx))

        def verify(ctx, rec):
            ctx.scripts.run("04e_checkNodeOpCert.sh", self.opcert(ctx), "next")

        return [
            Step("gen-kes", "Generate KES key pair (04c)", KEYS, gen_kes, done=kes_done,
                 outputs=lambda ctx, rec: [
                     Output(self.kes(ctx, "vkey"), description="KES verification key"),
                     Output(self.kes(ctx, "skey"), secret=True, description="KES signing key"),
                     Output(f"{pool}.kes.counter")],
                 rerunnable=False),
            Step("gen-opcert", "Issue operational certificate (04d)", KEYS, gen_opcert, done=opcert_done,
                 outputs=lambda ctx, rec: [
                     Output(self.opcert(ctx), description="operational certificate"),
                     Output(f"{pool}.node.counter", description="cold key issue counter"),
                     Output(f"{pool}.kes-expire.json", description="KES expiry")],
                 carry=lambda ctx, rec: [self.opcert(ctx)],
                 rerunnable=False),
            Step("package", "Package block-producer bundle", KEYS, package, done=package_done,
                 outputs=lambda ctx, rec: [
                     Output(self.bundle(ctx), secret=True, description="bundle for the block producer")]),
            Step("verify-opcert", "Check opcert counter against the chain (04e)", CHAIN, verify),
        ]

    def next_actions(self, ctx: Context) -> list[str]:
        if "kes_index" not in ctx.run.data:
            return []
        cfg = ctx.config.bundle
        out = []
        if ctx.run.step("package").status == "done" and ctx.ws.path(self.bundle(ctx)).exists():
            out.append(
                f"Copy {self.bundle(ctx)} to the block producer, unpack it into the node's key "
                f"directory (tar -xf), point --shelley-kes-key at {cfg.kes_skey} and "
                f"--shelley-operational-certificate at {cfg.opcert}, then restart cardano-node.")
            if ctx.config.pool.kes_key == "enc":
                out.append(f"{cfg.kes_skey} is password-encrypted; decrypt it with "
                           "01_protectKey.sh before the node can load it.")
        if ctx.ws.exists(f"{ctx.pool}.kes-expire.json"):
            exp = json.loads(ctx.ws.read_text(f"{ctx.pool}.kes-expire.json"))
            out.append(f"The new KES keys expire {exp.get('expireKESdate')} "
                       f"(KES period {exp.get('expireKESperiod')}); rotate before then.")
        return out
