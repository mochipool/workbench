# Documentation

This directory documents the Cardano SPO Workbench, a Nix flake that bundles cardano-node, cardano-cli, gitmachtl's SPO scripts, cardano-hw-cli, cardano-signer, trezorctl, a `workbench-doctor` health check, udev rules and a release-set manifest, together with the `workbench` orchestrator that runs multi-step operator workflows over the scripts.

The pages are organised using the Diataxis framework, which separates documentation by what the reader is trying to do.

| Quadrant | Reader's goal | How it is written here |
| --- | --- | --- |
| Tutorials | Learn by doing | A guided path with a known result. You follow it from start to end. |
| How-to guides | Get a specific task done | Prerequisites, then steps. Assumes you know what you want. |
| Reference | Look up a fact | Dry, complete and structured like the code. No advice. |
| Explanation | Understand why | Discussion of design and trade-offs. No step-by-step instructions. |

## Tutorials

* [Set up the workbench](./tutorials/set-up-the-workbench.md)
* [Rotate KES keys on preview](./tutorials/rotate-kes-on-preview.md)

## How-to guides

Environment and tooling:

* [Check your environment](./how-to/check-your-environment.md)
* [Configure Determinate Nix](./how-to/configure-determinate-nix.md)
* [Use on NixOS](./how-to/use-on-nixos.md)
* [Customise script settings](./how-to/customise-script-settings.md)
* [Cut a release](./how-to/cut-a-release.md)

Hardware wallets:

* [Give USB access to hardware wallets](./how-to/give-usb-access-to-hardware-wallets.md)
* [Update Trezor firmware](./how-to/update-trezor-firmware.md)
* [Update Keystone firmware](./how-to/update-keystone-firmware.md)
* [Update the Ledger Cardano app](./how-to/update-ledger-cardano-app.md)

Operator workflows:

* [Rotate KES keys](./how-to/rotate-kes-keys.md)
* [Unlock slots, the unlock policy, rotation and node export](./how-to/slots-policy-and-rotation.md)
* [Unlock with a Vault or KMS key](./how-to/unlock-with-vault-or-kms.md)
* [Back up to a sink: a directory or an S3 bucket](./how-to/back-up-to-a-sink.md)
* [Run a relay](./how-to/run-a-relay.md) and [run a relay on Kubernetes](./how-to/run-a-relay-on-kubernetes.md)
* [Initialise, verify, repair and migrate a relay store](./how-to/initialise-and-migrate-a-relay-store.md)
* [Convert a workspace to a sealed layout](./how-to/convert-to-a-sealed-layout.md)
* [Claim rewards air-gapped](./how-to/claim-rewards-air-gapped.md)
* [Update pool parameters](./how-to/update-pool-parameters.md)
* [Import pools and wallets kept in separate folders](./how-to/import-multi-folder-layout.md)
* [Send ADA](./how-to/send-ada.md)
* [Resume an interrupted run](./how-to/resume-an-interrupted-run.md)

## Reference

* [Flake outputs](./reference/flake-outputs.md)
* [Release set](./reference/release-set.md)
* [Supported systems and networks](./reference/supported-systems-and-networks.md)
* [workbench CLI](./reference/workbench-cli.md)
* [workbench.toml](./reference/workbench-toml.md)
* [spo CLI](./reference/spo-cli.md)
* [spo.toml](./reference/spo-toml.md)
* [Workflows](./reference/workflows.md)
* [Run state](./reference/run-state.md)

## Explanation

* [Architecture](./explanation/architecture.md)
* [Release sets and versioning](./explanation/release-sets-and-versioning.md)
* [Work modes](./explanation/work-modes.md)
* [Orchestrator design](./explanation/orchestrator-design.md)
* [Architecture decision records](./explanation/adr/README.md) for the Go reference implementation
* [Security model](./explanation/security-model.md)

## Development

For contributors and agents, outside the four quadrants above:

* [Handoff: state of the workbench](./development/handoff.md)
* [Roadmap: native port of the SPO scripts](./development/roadmap-native-port.md)
