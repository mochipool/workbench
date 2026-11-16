# spo TUI

`spo tui` opens a full-screen terminal UI over the same commands as [the CLI](./spo-cli.md). The design is in [ADR 0009](../explanation/adr/0009-tui.md). The TUI has no behaviour of its own: every command is the command line's, with its refusals, confirmations and audit records. A command added to the CLI appears in the TUI.

## Start

```
spo [-C DIR] [--upstream-layout] [--accept-rollback] tui
```

The global options apply to the whole session. `--passphrase-fd` is refused: the TUI asks for the passphrase when a command needs it. `spo tui` needs a terminal on standard input and output. Bare `spo` still prints help.

The header shows the workspace directory, the network and mode from `spo.toml`, and whether the workspace is sealed. Nothing is opened to show it. The passphrase is asked for only when a command asks, and the workspace is open only while that command runs.

## Screens

**Menu.** The commands, grouped as in `spo --help`. Entries with `>` are groups.

| Key | Action |
| --- | --- |
| `up` `down`, `k` `j` | Move. `PgUp`, `PgDn`, `g`, `G` jump. |
| `enter`, `right`, `l` | Open a group, or the form of a command. |
| `esc`, `left`, `h`, `backspace` | Up one level. |
| `/` | Search every command by name and description. `esc` ends it. |
| `q`, `ctrl+c` | Quit. |

**Form.** Generated from the command's usage line and flags. Required arguments are marked; flags show their default as a hint and their usage text when focused. The command line the form stands for is shown under it. Only what you change is passed.

| Key | Action |
| --- | --- |
| `tab`, `down` / `shift+tab`, `up` | Next, previous field. |
| `space` | Switch a yes/no field. |
| `enter` | Next field. In a repeatable field it adds the value; `backspace` on an empty one removes the last. On `[ Run ]` it runs. |
| `ctrl+r` | Run. |
| `ctrl+u` | Clear the field. |
| `esc` | Back to the menu; secret fields are wiped. |

**Run.** The command's output streams into a scrolling pane, with its questions answered in a modal. When it returns, the pane shows `done` or `spo: <error>`, exactly the message the CLI prints. `esc` goes back to the menu, `e` back to the form with your values, `up` `down` `PgUp` `PgDn` scroll, `q` quits.

## Prompts and secrets

* A passphrase or confirmation the command asks for appears in a modal with the command's own text, for example `Passphrase: ` or `Sign and submit this transaction? [y/N] `. Typing is hidden for a secret. `enter` answers. A confirmation's default is the command's: an empty answer is its default (no).
* `esc` or `ctrl+c` at a prompt cancels the command, with the same effect as the CLI's cancel. While a command runs, they cancel it too; a second `ctrl+c` quits.
* Options that name a file descriptor of a secret (`--password-fd`, `--mnemonic-in-fd`, `--token-fd`, `--message-passphrase-fd`, `--protection-key-fd`, `--new-passphrase-fd`, `--recovery-key-in-fd`) appear as masked fields. A value you type is sent to the command on a private pipe and wiped; leave it empty and the command asks itself. You never type a descriptor number.
* Options that write a secret to a descriptor (`--recovery-key-fd`) are not offered. The command shows the secret once instead, and the output is cleared from the screen's memory when you leave it. The pane says so while it is shown.
* The TUI uses the alternate screen: nothing of it stays in the terminal's scrollback. It turns on neither mouse reporting nor a debug log, and restores the terminal on exit and on a crash. Pasted text goes into the field like typed text.
* Everything drawn is stripped of terminal control sequences, carriage returns, bidirectional controls and invisible characters, so a peer name or on-chain text cannot move the cursor, restyle the screen or reorder text.

## What it deliberately does not do

* It has no workflow of its own, no command the CLI lacks and no cache of what the workspace holds.
* It does not open the workspace to draw a screen, and keeps nothing between commands.
* It runs one command at a time.
* It does not offer file-descriptor options as numbers, and does not read the passphrase from `--passphrase-fd`.
* It does not complete wallet, pool or policy names; type them. A read-only completion through the existing ports is possible and is not built.
* It has no mouse support, no themes and no configuration file.
