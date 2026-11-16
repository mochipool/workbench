# Resume an interrupted run

This guide continues a workflow that stopped because of an error, a Ctrl-C, a closed terminal or a crash.

## Find the run

```sh
workbench status
workbench runs
workbench show <run-id>
```

`show` lists each step's status and the error of the step that stopped.

## Decide by what stopped it

### A check failed (exit code 4)

Nothing was changed. Fix the listed problem and start the workflow again with `run`.

### A step failed (exit code 5)

The script exited with an error, or finished without producing what the step expects. Fix the cause, for example upload the pool metadata, top up the payer, or start the node, then:

```sh
workbench resume
```

Steps already done are not repeated. Before continuing, the workbench re-checks each of them by probing the files and comparing digests.

### Needs attention (exit code 6)

The step was interrupted, or failed, and it is one that must not be repeated blindly:

* `04c`/`04d` in `kes-rotate`, because a second `04d` skips a cold counter;
* direct submission when not air-gapped, because a second send could pay twice.

Find out what happened:

* `kes-rotate`: look at `<pool>.kes.counter`, `<pool>.kes.counter-next` and whether `<pool>.node-NNN.opcert` exists.
* Payments and claims: query the source address (`workbench exec 01_queryAddress.sh smallwallet1`) or look at it in an explorer.

Then tell the workbench:

```sh
# it took effect: record it and continue with the next step
workbench resume <run-id> --mark-done <step>

# it did not take effect: run it again
workbench resume <run-id> --retry <step>
```

### Drift (exit code 7)

A file that a finished step produced has changed or disappeared since. The message names the files. Restore them, for example from the bundle in `.workbench/out/`, and resume. If the change was intended, abandon the run and start again.

### Paused (exit code 10)

This is not an error: the next step belongs to the other machine. Move `offlineTransfer.json` across and run `workbench resume` there.

If you resume on the same machine by mistake, the workbench notices the ticket is not newer than its own copy and stays paused.

## Start over

```sh
workbench abandon <run-id>
```

The run is closed and its files are left in place. A new run of the same workflow adopts whatever is already complete: for example, KES keys generated before the interruption are kept, and only the opcert is issued.

There is one exception. If `04d` was interrupted after writing `<pool>.node-NNN.opcert` but before advancing `kes.counter-next`, a new run refuses to start, because issuing again would skip a cold counter. Compare `<pool>.node.counter` with the opcert (`workbench exec 04e_checkNodeOpCert.sh <pool>.node-NNN.opcert next` on an online machine), fix the counter files by hand, and start again.

Related: [Run state](../reference/run-state.md), [Orchestrator design](../explanation/orchestrator-design.md#probes-make-resume-truthful).
