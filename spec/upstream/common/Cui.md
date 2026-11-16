+++
id = "Cui"
kind = "common"
title = "Prompts, file locks and error exit"
upstream_tag = "Update-2026-04"
status = "draft"
contexts = ["key-custody", "configuration"]
use_cases = []
depends_on = ["Cconf"]

upstream_path = "cardano/mainnet/00_common.sh"
variants = ["mainnet", "testnet"]
upstream_sha256 = "9490fae84352a491bbded9bd4a14587521336364f9814a2df5aff6b86266bfba"
upstream_lines = 2966

[functions]
ask = "ee761643a3a631522e3c60ba27ff92fd652cb149d68b8e9959fd2f3eb570573e"
ask_pass = "b26da531d97806b75f0d0fb9e7349c20e530fef766fe9d78ccde730cfd7a5573"
file_lock = "f342286872fcd7343537222f61ab1b4601eb6ac0a26429a73406244abe58d7fa"
file_unlock = "0c74f12eddc0639cff70d8a50f58e48309e50b1f1b5d6a31da6bccd1139e60d6"
checkError = "e11976bade08f7726d3bd0b4e347226a7a0fdc37dcc0c71677b957ec426f7584"
showProcessAnimation = "161b3a477f317c90d5363c794c66e3c1e8d45cc59c9457124daddd56826fcf56"
stopProcessAnimation = "36ad02bf464980634e8300a51826a9522e8ac1f88367b9eb2b005173e55034ce"
+++

# Cui: prompts, file locks and error exit

The terminal-facing primitives every script uses: a yes/no question (`ask`), a hidden password read (`ask_pass`), write protection for key and counter files (`file_lock`, `file_unlock`), the error-exit helper (`checkError`), and a busy indicator (`showProcessAnimation`, `stopProcessAnimation`). The prompts gate effects, so their defaults are normative. The animation is display only.

## checkError

- **SPO-Cui-INV-001** `checkError <code>`: when the argument is non-zero it prints an error banner with the code on stdout and calls `exit <code>`, which ends the whole script, or only the enclosing `$(...)` subshell when called inside one. The idiom that follows nearly every call in the scripts, `checkError "$?"; if [ $? -ne 0 ]; then exit $?; fi`, therefore has a dead second half: after a failing `checkError` control never reaches the `if`, and after a passing one `$?` is 0. A failure that is detected is always a hard stop with the original code. (src: L1003-L1006)
- **SPO-Cui-IF-001** The argument is evaluated as a shell arithmetic expression (`[[ $1 -ne 0 ]]`). A zero, empty or non-numeric word counts as success, and the function returns 0 with no output. Exit statuses are taken modulo 256, so a code of 256 would exit 0. (src: L1005)

## ask

- **SPO-Cui-IF-002** `ask <prompt> [Y|N]` asks a yes/no question and returns status 0 for yes and 1 for no. The second argument sets the default and must be exactly `Y` or `N`; any other value, or none, means **no default**. (src: L754-L766)
- **SPO-Cui-IN-001** Reads the answer from the terminal device `termTTY`, not from stdin, so it works while stdin is redirected. `termTTY` is `$(tty)` when that device can be written to, else `/dev/tty` (L157). (src: L775, L157)
- **SPO-Cui-PR-001** Prints `<prompt> [Y/n] ` for default `Y`, `[y/N] ` for default `N`, `[y/n] ` otherwise, on stdout, and reads one line. An empty line takes the default. (src: L768-L780)
- **SPO-Cui-PR-002** An answer is yes when it begins with `Y` or `y` (so `yes` and `Yeah` count) and no when it begins with `N` or `n`. Any other answer, and an empty answer when there is no default, asks again. The loop has no limit and no exit path other than a valid answer. (src: L781-L788)
- **SPO-Cui-INV-002** `ask` never calls `exit`; its only results are the statuses 0 and 1. Callers that need a refusal on "no" call `exit` themselves, typically with 1 or 2. (src: L754-L789)

> **Upstream quirk:** `read` is used without `-r`, so a backslash in the answer is dropped. This changes nothing, since only the first letter matters. At end of input on the terminal, the empty reply picks the default, or loops forever without one. The prompt goes to stdout, so an `ask` called inside `$(...)` would hide its prompt in the capture. (src: L771, L775)

## ask_pass

- **SPO-Cui-IF-003** `ask_pass <prompt>` writes `<prompt>: ` to `termTTY`, reads one line **from stdin** with echo off (`read -s`), writes one `*` per character of the line to `termTTY`, and prints the password on **stdout** without a trailing newline. Callers capture it with `$(...)`. (src: L795-L805)
- **SPO-Cui-INV-003** It never calls `exit` and returns 0. An empty line returns an empty password, which callers treat as "abort". (src: L795-L805)
- **SPO-Cui-SEC-001** The password is returned in clear on stdout and lives in the caller's shell variable. It is not echoed to the terminal (stars only). (src: L799-L803)

> **Upstream quirk:** `IFS= read -s` is used without `-r`. Backslashes in the typed password are **consumed as escapes**: `ab\cd` is read as `abcd`, and a trailing backslash joins the next input line. Passwords are only ever typed through this function, both for encryption and decryption, so a password with a backslash still works consistently. A reimplementation that must open files encrypted by the upstream scripts has to apply the same unescaping to a password containing a backslash. A raw reader would derive a different key. (src: L799)
>
> *Observed 2026-11-16* (`spo/test/parity/workspace_test.go`, real `01_protectKey enc` on a pseudo terminal): typing `Abc\def-12345` encrypts with `Abcdef-12345`; the typed text does not open the file. Leading and trailing spaces are kept. The rule as ported (`keyfile.UpstreamRead`): a backslash is dropped and the next byte kept, backslash-newline joins lines, a final backslash is dropped.

> **Upstream quirk:** The password is read from stdin while the prompt uses `termTTY`. If stdin is redirected, the password is taken from the redirected input, and with stdin at end of input it is empty (an abort for the callers). (src: L798-L799)

## file_lock and file_unlock

- **SPO-Cui-OUT-001** `file_lock <path>` changes the mode of the file to `0400` (owner read only) when `<path>` is an existing regular file; otherwise it does nothing and returns 0. (src: L811-L814)
- **SPO-Cui-OUT-002** `file_unlock <path>` changes the mode of the file to `0600` (owner read and write) when `<path>` is an existing regular file; otherwise it does nothing and returns 0. (src: L816-L819)
- **SPO-Cui-INV-004** Neither function calls `exit`, and neither checks the result: the status is that of `chmod` when it ran. Scripts unlock a file before rewriting it and lock it again afterwards, so a crash between the two steps leaves a `0600` secret or counter file. (src: L811-L819)

## showProcessAnimation and stopProcessAnimation

- **SPO-Cui-INV-005** `showProcessAnimation <text>` is display only. It is started as a background job (`... &`) and redraws a moving bar after the text every 0.2 s until it receives SIGINT, which sets a flag that ends its loop. It reads no input and has no result. It installs its SIGINT trap only inside the background job. (src: L2779-L2793)
- **SPO-Cui-INV-006** `stopProcessAnimation` sends SIGINT to **every direct child of the main script process** (`pkill -SIGINT -P $$`; `$$` stays the main script's id inside subshells) and then clears the line. Its status is `pkill`'s: non-zero when there was no child, which is harmless because callers ignore it. It never calls `exit`. Any other background child of the script would receive the same SIGINT. (src: L2795-L2797)

## Domain mapping

| Port | Operation | Purpose |
| --- | --- | --- |
| `UI` | `confirm(prompt, default)` | `ask`; `default` is `yes`, `no` or none (re-ask) |
| `UI` | `askPassword(prompt)` | `ask_pass`; the CLI adapter reads without echo |
| `Store` | `lock(artefact)` / `unlock(artefact)` | `file_lock` / `file_unlock` |
| `UI` | `show(view)` | Progress indication in place of the animation |

Errors that upstream reports with `checkError` are typed failures of the use case, and the adapter that owns the process (CLI) turns them into an exit code.

## Port notes

* `confirm` with no default should still re-ask, but a non-interactive adapter (server, test) must fail the request rather than loop forever.
* Passwords must be handled as secrets (never logged); see SPO-Ckey-SEC-001 for where upstream leaks them.
* The lock/unlock dance should be an atomic write with the final mode set up front, which removes the window of SPO-Cui-INV-004.
* A port that reads passwords raw must apply the unescaping quirk when opening legacy encrypted keys (see the upstream quirk under `ask_pass`).

## Open questions

None.
