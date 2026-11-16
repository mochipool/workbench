"""Invokes the SPO scripts with the operator's terminal attached.

Output is never captured or logged: the scripts print signing-key cborHex
(for example 04c prints the new KES .skey), so anything that tees their
output to disk would leak keys. The terminal is inherited so the scripts'
own prompts, password entry and hardware-wallet confirmations work as usual.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .errors import StepFailed
from .toolchain import NetworkTools


@dataclass
class ScriptRunner:
    tools: NetworkTools
    cwd: Path
    assume_yes: bool = False
    echo: bool = True
    # With --json, stdout must carry only the JSON document; the scripts'
    # chatter then goes to stderr (still the operator's terminal).
    stdout_to_stderr: bool = False
    calls: list[list[str]] = field(default_factory=list)

    def env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["PATH"] = f"{self.tools.scripts_dir}{os.pathsep}{env.get('PATH', '')}"
        if self.assume_yes:
            # Skips only the scripts' final "submit/continue?" confirmation.
            env["ENV_SKIP_PROMPT"] = "YES"
        # Never forward a password through the environment of child scripts.
        env.pop("ENV_DECRYPT_PASSWORD", None)
        return env

    def run(self, script: str, *args: str, ok_codes: tuple[int, ...] = (0,)) -> int:
        path = self.tools.script(script)
        if not path.is_file():
            raise StepFailed(f"script {script} is not part of the toolchain ({self.tools.scripts_dir})")
        argv = [str(path), *args]
        self.calls.append([script, *args])
        if self.echo:
            print(f"\n\033[36m$ {shlex.join([script, *args])}\033[0m", file=sys.stderr, flush=True)
        code = subprocess.call(argv, cwd=self.cwd, env=self.env(),
                               stdout=sys.stderr if self.stdout_to_stderr else None)
        if code not in ok_codes:
            raise StepFailed(f"{script} exited with status {code}")
        return code
