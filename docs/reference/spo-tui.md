# spo TUI

`spo tui` opens a full-screen terminal UI over the same commands as [the CLI](./spo-cli.md). The design is in [ADR 0009](../explanation/adr/0009-tui.md). The TUI has no behaviour of its own: every command is the command line's, with its refusals, confirmations and audit records. A command added to the CLI appears in the TUI.

## Start

```
spo [-C DIR] [--accept-rollback] tui
```

The global options apply to the whole session. `--passphrase-fd` is refused: the TUI asks for the passphrase when a command needs it. `spo tui` needs a terminal on standard input and output of at least 40 columns by 10 rows; a smaller terminal shows only a notice (keys still work, so a prompt can be cancelled with `ctrl+c`) until it is resized. Bare `spo` still prints help.

The header shows the workspace directory, the network and mode from `spo.toml`, and whether the workspace is sealed. Nothing is opened to show it. The passphrase is asked for only when a command asks, and the workspace is open only while that command runs.

## Screens

**Menu.** The commands, grouped as in `spo --help`. Entries with `>` are groups.

| Key | Action |
| --- | --- |
| `up` `down`, `k` `j` | Move. `PgUp`, `PgDn`, `g`, `G` jump. |
| `enter`, `right`, `l` | Open a group, or the form of a command. |
| `esc`, `left`, `h`, `backspace` | Up one level. |
| `/` | Search every command by name and description. `esc` ends it. |
| `q`, `ctrl+c` | Quit (a relay session is logged out first). |

**Form.** Generated from the command's usage line and flags. Required arguments are marked; flags show their default as a hint and their usage text when focused. The command line the form stands for is shown under it. Only what you change is passed.

| Key | Action |
| --- | --- |
| `tab`, `down` / `shift+tab`, `up` | Next, previous field. |
| `space` | Switch a yes/no field. |
| `enter` | Next field. In a repeatable field it adds the value; `backspace` on an empty one removes the last. On `[ Run ]` it runs. |
| `ctrl+r` | Run. |
| `ctrl+u` | Clear the field. |
| `esc` | Back to the menu; secret fields are wiped. |

### Names, files and exclusions

These are driven by metadata on the commands (see [ADR 0009](../explanation/adr/0009-tui.md)), not by TUI code.

* **Name completion.** A field that names a workspace object (a wallet, pool, stake key, policy, asset, DRep, committee key, voting key, Calidus key or party) shows the matching names under it. `tab` completes to the common prefix, then steps through the candidates; with no candidate or an exact match it moves to the next field. Names only: no record content is read for this.
* **Sealed workspaces.** Listing names needs the workspace open. The TUI does not open it to draw a form: with a sealed workspace the field says `names are sealed`, and `ctrl+n` asks for the passphrase once, in a hidden modal, lists the names, closes the workspace and forgets the passphrase. The names stay in memory until a command is run (it may change them) or the TUI ends.
* **File picker.** `ctrl+o` on a field that takes a path opens a keyboard picker that starts in the workspace directory. `up` `down` `enter` move and open, `left` goes up, `.` (`ctrl+a` when typing a new file name) shows or hides hidden entries, `s` chooses the current directory when a directory is wanted, `esc` cancels. A field that takes a new file also takes a typed name. Where the command names an extension, other files are not listed. A symbolic link is listed with its target (`name -> target`); it is followed or chosen only on a second `enter`, after the target was shown. The picker lists names; it never opens or reads a file.
* **Exclusions.** Where a command declares flags mutually exclusive, required together, or one required (cobra's `MarkFlags...`), the form marks the flags: a field that conflicts with one already given is greyed (`not with --x`) and takes no input until the other is cleared, a flag that needs a partner says `needed with --x`, and `Run` is refused with the reason before the command starts. Cobra still validates when the command runs.

### Guided import

`workspace import` has a guided flow, opened with `ctrl+g` on its form. It builds the same request the command line builds; it holds no import logic (the screens show what the command's own `--dry-run --format json` prints). Spec: [Xmulti](../../spec/extensions/Xmulti.md), IF-003.

1. **Folders.** `a` types a path, `o` or `ctrl+o` opens the picker (directories only; `s` chooses the folder shown), `d` removes the folder under the cursor, `+` and `-` set the depth (0 to 4), `enter` reads the folders. More than one folder can be added.
2. **Owners found**, per folder, with their kind and whether they would be imported or why not (`[-]` cannot be selected). Nothing is selected at first. `space` toggles, `a` selects every owner that can be imported, `n` none, `r` gives the owner another name, `enter` asks the command for the plan.
3. **Summary.** The owners with the name each is stored under, every change to a pool descriptor (pool, field, old to new), and the equivalent `spo workspace import ...` command line. `enter` or `y` runs the import (disabled while the plan would fail), `m` asks for a path and has the command write the manifest of the choices to a new file, `esc` goes back. When two selected owners would be stored under one name the command refuses the selection and the flow asks for a new name for one of them.

The passphrase, and the password of upstream-encrypted keys, are asked in the same hidden modals as for any command (the passphrase once for the plan and again for the import: each is a separate command run). The two runs do not share an opened workspace: the TUI keeps neither the passphrase nor an open session between commands (the workspace is open only while a command runs), so reusing one would mean the TUI holding the passphrase or the session, which it does not do.

**Run.** The command's output streams into a scrolling pane, with its questions answered in a modal. When it returns, the pane shows `done` or `spo: <error>`, exactly the message the CLI prints. `esc` goes back to the menu, `e` back to the form with your values, `up` `down` `PgUp` `PgDn` scroll, `q` quits.

## Relay session

The one exception to "one command at a time" (ADR 0014 decision 9). Spec: [Xmailbox](../../spec/extensions/Xmailbox.md), "The relay session of the TUI, login and logout" (IF-027 to IF-029, OUT-114 to OUT-121, PRE-065 to PRE-067, SEC-082 to SEC-084, INV-040).

* **Log in.** Run `party relay login` from the menu like any command: it asks for the passphrase and connects to every listed relay with this device's binding. Once it is logged in, its run leaves the screen (`esc` returns to the menu) and goes on in the background: it sends what waits in the outbox, fetches what waits at the relays and hands it to this machine's coordinator or signer. It approves nothing: a signing request waits for `party requests`, `party review` and `party approve`, which you run as usual. One session at a time.
* **Status.** The header says `relays: logged in (N of M connected)`, `logging out` or `TUNNEL DID NOT STOP`, and, for a signer's login, `requests waiting for review: N` (counted from the workspace, never from a peer's text). The root menu's **Relay session** entry shows each relay (`waiting` until its first exchange, `connected` after one, `backing off` with the pause, `identity refused`, `pinned key mismatch`), when the binding ends (and the reminder to renew it within 14 days), the revokes a relay has not recorded yet, the envelopes received, handled and sent, the last one handled, the requests waiting for review as `spo party review ID` lines, the remedy of a refused identity (once per binding), and the session's last lines. Everything shown is cleaned of terminal escapes and control characters. `o` on that screen logs out.
* **Log out of relays** (a root menu entry while a session runs or is stuck) ends a logged-in session and leaves the TUI open: the connections and every tunnel are closed and the identity in memory is destroyed. An envelope fetched but not acknowledged comes back at the next login. You read "Logged out of the relays." only when all of that succeeded. While a logout runs or is stuck, the entry shows where it stands and what to do. Logging out while the login still asks for its passphrase says that the login was cancelled. Log in again whenever you like: the passphrase is asked again and no wallet is touched.
* **When the teardown fails.** If a tunnel did not stop, or the session has not ended within 15 s, you read "tunnel did not stop" and that the device may still be online at the relays: quit `spo` and start it again. If the tunnels did stop and only the command's own end is slow, the TUI says that instead. A new login is refused until then (or until the late teardown completes cleanly, which the TUI then says). A foreground command whose own tunnel did not stop (a revoke-only send, the logout of `forget`) makes the TUI stuck the same way.
* **It ends itself** after `relay_login_max` (`spo.toml`, default 12 hours; on the earlier of the monotonic and the wall clock, so a suspend counts), when the binding ends, when the workspace can no longer be used by it, and when one of its steps fails with an internal error; each is the same logout, the TUI shows `logging out` and then the outcome, which names the reason. A foreground command waiting at a prompt does not hold the session past its limit. There is no idle logout.
* **Quit.** `q` while a session runs logs it out first; a second `q` does not wait. After the screen is restored `spo tui` says what it still waits for (at most what is left of the 15 s; nothing for a session already stuck), and exits non-zero with "tunnel did not stop" if the session did not end cleanly.
* **Forget this device.** Running `party relay forget` while a session runs logs the session out first and then runs the command, which logs in again, handles the queue, revokes this device at every relay, logs out and deletes the binding, and says per relay whether it recorded the revoke. If the logout is stuck, forget is not run. `party relay forget --lost DEVICE` (another device) does not log out: its revoke goes over the session's connections.
* **Foreground commands and the session.** Commands run while the session runs; a step of the session that writes the workspace waits until the command has finished, and a command started while such a step runs waits for it (the run says so). `party request queue`, `party approve`, `party refuse` and `party outbox status`/`retry` queue mail; after them the TUI says what happens to what waits in the outbox: the session sends it while logged in, it waits while the session logs out or is stuck, and it is sent at the next login otherwise. `party relay send-revokes`, and the revoke sending of `forget --lost` and `revoke --import`, go over the logged-in session's connections. `party serve --transport mailbox` and `party connect --transport mailbox` refuse while the session is logged in, and every command that would dial a relay refuses while it logs in, logs out or is stuck. A revoke stored while the session runs (`party relay revoke`) is sent by it within seconds. A pool cold key request is never sent over the session: it stays on the file transport. The session holds the workspace open, so a command that needs it alone (a passphrase rekey, a restore) is refused with "log out of the relays first".
* **One login per workspace.** A second `spo` process (another TUI, `serve`, `connect`, `login`, `forget`, `send-revokes`) is refused while one is logged in to the relays with the same workspace: the relay-login lock, `workspace.spo.relay.lock`, ends with the process that holds it.
* **No questions in the background.** The session never asks anything once it runs in the background. A failure inside a step of the session ends the session with its logout; the TUI goes on.

## Prompts and secrets

* A passphrase or confirmation the command asks for appears in a modal with the command's own text, for example `Passphrase: ` or `Sign and submit this transaction? [y/N] `. Typing is hidden for a secret. `enter` answers. A confirmation's default is the command's: an empty answer is its default (no).
* `esc` or `ctrl+c` at a prompt cancels the command, with the same effect as the CLI's cancel. While a command runs, they cancel it too; a second `ctrl+c` quits.
* Options that name a file descriptor of a secret (`--password-fd`, `--mnemonic-in-fd`, `--token-fd`, `--message-passphrase-fd`, `--protection-key-fd`, `--new-passphrase-fd`, `--recovery-key-in-fd`) appear as masked fields. A value you type is sent to the command on a private pipe and wiped; leave it empty and the command asks itself. You never type a descriptor number.
* Options that write a secret to a descriptor (`--recovery-key-fd`) are not offered. The command shows the secret once instead, and the output is cleared from the screen's memory when you leave it. The pane says so while it is shown.
* The TUI uses the alternate screen: nothing of it stays in the terminal's scrollback. It turns on neither mouse reporting nor a debug log, and restores the terminal on exit and on a crash. Pasted text goes into the field like typed text.
* Everything drawn is stripped of terminal control sequences, carriage returns, bidirectional controls and invisible characters, so a peer name or on-chain text cannot move the cursor, restyle the screen or reorder text.

## What it deliberately does not do

* It has no workflow of its own and no command the CLI lacks.
* It does not open the workspace to draw a screen, and keeps nothing between commands, except the relay session's own open workspace while it is logged in.
* It runs one command at a time in the foreground; the relay session is the only command that runs in the background.
* It does not offer file-descriptor options as numbers, and does not read the passphrase from `--passphrase-fd`.
* It keeps no cache beyond the session's name list (see above), and nothing of it is written anywhere.
* It has no mouse support, no themes and no configuration file.
