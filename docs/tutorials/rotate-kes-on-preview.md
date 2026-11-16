# Rotate KES keys on preview

In this tutorial you run a complete air-gapped KES rotation on the preview testnet with `workbench`. You use two directories on one computer, one standing in for your offline machine and one for your online machine. Along the way you meet every part of a workflow: check-time validation, a run that pauses for the other machine, the hand-off through `offlineTransfer.json`, resume, and the final report.

Nothing here touches mainnet, and the keys you make are throw-away.

## Before you start

Finish [Set up the workbench](./set-up-the-workbench.md) first. You need an internet connection for the online half: light mode talks to Koios.

Enter the preview shell and stay in it for the whole tutorial:

```sh
nix develop --accept-flake-config .#preview
```

## 1. Create the two machines

```sh
mkdir -p ~/wb-tutorial && cd ~/wb-tutorial
workbench init -C cold --network preview --role offline --airgapped --pool mypool
workbench init -C hot  --network preview --role light   --airgapped --pool mypool
```

Each directory now has a `workbench.toml` that says what that machine is. Look at one:

```sh
cat cold/workbench.toml
```

`role = "offline"` means the scripts will run in offline mode there. `airgapped = true` tells the workbench that signing keys live only on the offline machine.

## 2. Make some cold keys

A real pool already has cold keys. For the tutorial, generate them on the offline machine with the SPO scripts themselves. `workbench exec` runs any script in the workspace with the right settings:

```sh
workbench exec -C cold 04a_genNodeKeys.sh mypool cli
workbench exec -C cold 04b_genVRFKeys.sh mypool cli
```

The scripts print the keys they made and lock them read-only. You now have `mypool.node.skey`, `mypool.node.vkey`, `mypool.node.counter` and the VRF keys in `cold/`.

## 3. Ask the workbench to check the rotation

```sh
workbench check -C cold kes-rotate
```

The check fails, and tells you why:

```
Check failed; nothing was changed:
  - this run hands back to the online machine via offlineTransfer.json, which must be created there first: ...
```

The last step of a rotation checks the new certificate against the chain. That has to happen online, and the only thing that crosses an air gap is `offlineTransfer.json`, which the online machine must create. The workbench noticed this before generating anything.

Create the file on the online machine and carry it over:

```sh
workbench exec -C hot 01_workOffline.sh new
cp hot/offlineTransfer.json cold/
```

Check again:

```sh
workbench check -C cold kes-rotate
```

This time you see the plan: three steps run here, and `verify-opcert` runs on the online machine. `kes_index = 0` is the rotation number the run will use.

## 4. Run it on the offline machine

```sh
workbench run -C cold kes-rotate
```

You see each script run (`04c_genKESKeys.sh`, `04d_genNodeOpCert.sh`), then a report:

```
kes-rotate  2026...-kes-rotate-....  [PAUSED]
network preview
waiting for the online (or light) machine

  done      gen-kes        Generate KES key pair (04c) on offline
  done      gen-opcert     Issue operational certificate (04d) on offline
  done      package        Package block-producer bundle on offline
  pending   verify-opcert  Check opcert counter against the chain (04e)

Artefacts
  mypool.kes-000.skey  sha256:...  0400 SECRET  KES signing key
  ...
Next
  - Move offlineTransfer.json to the workspace on your online (or light) machine and run: workbench resume
  - Copy .workbench/out/.../mypool-kes-000-bp.tar to the block producer, ...
```

Notice what happened:

* Every file is listed with its digest, and the secret ones are marked.
* The bundle for the block producer is ready under `.workbench/out/`.
* The run paused, because the next step needs the chain.

Look inside the bundle:

```sh
tar -tvf cold/.workbench/out/*/mypool-kes-000-bp.tar
```

It holds `kes.skey`, `node.opcert`, a `MANIFEST.json` and a `SHA256SUMS`.

## 5. Carry the file back and finish online

```sh
cp cold/offlineTransfer.json hot/
workbench status -C hot
```

`status` reports that `offlineTransfer.json` carries your run. Resume it:

```sh
workbench resume -C hot
```

The workbench shows the run it found and asks whether to continue it here. Answer `y`. It unpacks `mypool.node-000.opcert` and checks it against the digest recorded on the offline machine. Then it runs `04e_checkNodeOpCert.sh` against preview through Koios.

Your tutorial pool was never registered, so there is no counter on chain yet. The script expects counter 0, finds 0 in the certificate, and reports:

```
KES-Interval Check: OK, within range
...
OpCertCounter Check - For NEXT usage: OK, is latest+1
```

The run ends `[DONE]`.

The signing key never left `cold/`:

```sh
ls hot/ | grep kes     # nothing: only the opcert was carried
grep -c "$(jq -r .cborHex cold/mypool.kes-000.skey)" hot/offlineTransfer.json   # 0
```

The second command searches the transfer file for the KES signing key itself and finds nothing.

## 6. Try to break it

Start another rotation straight away:

```sh
workbench run -C cold kes-rotate
```

It refuses: the first run is still waiting, as far as the offline machine knows. Two rotations at once would fight over the KES counters.

On the cold side, the run is paused for good, because the hot side finished it. Close it:

```sh
workbench runs -C cold
workbench abandon -C cold <run-id>
```

Run the rotation again and watch `kes_index` become 1 and the files become `mypool.kes-001.*`.

## What you learned

* `check` validates everything, including cross-machine requirements, without changing anything.
* A workflow's steps run where they belong, and the run pauses at the air gap.
* Only `offlineTransfer.json` crosses the gap, and it never carries secrets.
* The report tells you what was done, which files were produced, and what to do next.

Next, use the same flow for real: [Rotate KES keys](../how-to/rotate-kes-keys.md). Read [Orchestrator design](../explanation/orchestrator-design.md) to understand how resume works.

Clean up with `rm -rf ~/wb-tutorial` (the files are read-only, so use `chmod -R u+w ~/wb-tutorial` first if `rm` complains).
