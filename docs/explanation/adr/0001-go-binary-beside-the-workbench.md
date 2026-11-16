# ADR 0001: The Go binary sits beside the Python workbench

Status: accepted, 2026-11-16. Closes concern C1.

## Context

The repository ships `workbench`, a Python orchestrator that sequences the upstream Bash scripts. The native port is written in Go as one binary. The two could be merged, layered or kept apart.

## Decision

* The Go implementation is a new binary, `spo`, in the Go module `spo/` at the repository root. It does not call `workbench`, and `workbench` does not call it.
* `orchestrator/` is frozen: it takes bug fixes only. Its real-script end-to-end test stays, because the parity harness uses the pinned upstream scripts as its oracle.
* `workbench` is retired when `spo` passes differential tests for the four workflows it wraps (`kes-rotate`, `claim-rewards`, `send-ada`, `pool-update`). Retirement removes `orchestrator/`, `tools/workbench.nix` and the workbench pages under `docs/`, in one change.
* There is no migration of `workbench.toml` or `.workbench/` run state. An operator moves to `spo` by importing the scripts workspace (the directory of upstream files), which is the state that matters. Open `workbench` runs are finished or abandoned first.

## Consequences

* Operators have two entry points until retirement. The docs say which to use for what.
* Engine ideas worth keeping (done-probes, non-repeatable steps, one open run per workflow) are reimplemented over the store, not ported line by line.
