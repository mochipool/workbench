# Run state

This page describes the files `workbench` keeps in a workspace and the format of the run journal and ticket.

## Files

| Path | Mode | Purpose |
| --- | --- | --- |
| `workbench.toml` | `0600` | Configuration ([reference](./workbench-toml.md)). |
| `common.inc` | `0600` | Generated script settings; first line `# managed-by: spo-workbench`. |
| `.workbench/` | `0700` | State directory. |
| `.workbench/lock` | `0600` | `flock` target; held for the duration of `run`, `resume`, `exec`, `abandon` and `edit`. |
| `.workbench/runs/<run-id>.json` | `0600` | One journal per run. |
| `.workbench/out/<run-id>/` | `0700` | Outputs the workbench builds itself (the KES bundle). |

Journals are written atomically: to a temporary file in the same directory, `fsync`ed, then renamed into place.

Run ids have the form `<UTC timestamp>-<workflow>-<4 hex digits>`, for example `20261116T013504Z-kes-rotate-c073`.

## Journal format (format 1)

```json
{
  "id": "20261116T013504Z-kes-rotate-c073",
  "workflow": "kes-rotate",
  "network": "preview",
  "params": {},
  "created": "2026-11-16T01:35:04+00:00",
  "updated": "2026-11-16T01:35:04+00:00",
  "status": "paused",
  "waiting_for": "chain",
  "seq": 1,
  "data": {"kes_index": 0, "carried": [{"path": "mypool.node-000.opcert", "sha256": "..."}]},
  "steps": [
    {
      "id": "gen-kes",
      "title": "Generate KES key pair (04c)",
      "status": "done",
      "started": "...", "finished": "...",
      "machine": "offline",
      "adopted": false,
      "error": null,
      "artefacts": [
        {"path": "mypool.kes-000.skey", "sha256": "...", "secret": true, "description": "KES signing key"}
      ],
      "data": {}
    }
  ],
  "next_actions": ["..."],
  "format": 1
}
```

| Field | Meaning |
| --- | --- |
| `status` | `active`, `paused`, `done`, `failed`, `needs-attention` or `abandoned`. |
| `waiting_for` | When paused: `chain` (online/light machine) or `keys` (offline machine). |
| `seq` | Incremented at each hand-off; a ticket is imported only if its `seq` is higher than the local copy's. |
| `data` | Run-wide pinned facts (`kes_index`) and the `carried` file list of the last hand-off. |
| `steps[].status` | `pending`, `running`, `done`, `failed` or `interrupted`. |
| `steps[].machine` | Role of the machine that ran the step. Artefact digests are re-verified only on that machine. |
| `steps[].adopted` | The step's effect already existed when the run reached it; the script was not run. |
| `steps[].data` | Step facts, for example the digest of the signed transaction (`sign.data.tx`) and the queue snapshot before signing (`sign.data.before`), the `metadata_url` (`gen-cert`), or `marked_done_by_operator`. |
| `artefacts[].secret` | The file holds key material. Secret files are never carried. |

A journal never contains file contents or script output.

## The ticket

At a hand-off, the journal is written to `workbench-ticket.json`, attached to `offlineTransfer.json` with `01_workOffline.sh attach`, and the local copy of that file is deleted. Carried files are attached the same way, under their own names. In `offlineTransfer.json` they appear in the upstream format:

```json
"files": {
  "workbench-ticket.json": {"date": "...", "size": "...", "base64": "..."},
  "mypool.node-000.opcert": {"date": "...", "size": "...", "base64": "..."}
}
```

`01_workOffline.sh extract` on either machine extracts them like any attached file. `01_workOffline.sh new` discards them.

## Transaction identity

A queued transaction is identified by the SHA-256 of its `txJSON` member, serialised as JSON with sorted keys. `sign` records the one digest that appeared during the step. `execute` passes that transaction's 1-based position in the queue to `01_workOffline.sh execute`.
