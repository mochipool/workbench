# Update Trezor firmware

This guide shows how to update a Trezor to firmware that supports Cardano at the version the SPO scripts require.

## Prerequisites

* A workbench shell (`trezorctl` is bundled).
* Your recovery seed backed up.
* The device connected with a good cable.
* USB access set up on Linux: [Give USB access to hardware wallets](./give-usb-access-to-hardware-wallets.md).

Cardano is only available in the universal firmware, not the Bitcoin-only variant. Do not pass `--bitcoin-only`.

## Steps

1. Reboot the device into bootloader mode:

   ```sh
   trezorctl device reboot-to-bootloader
   ```

   If your model does not support this, enter the bootloader with the key combination in Trezor's documentation for your model.

2. Preview what would be installed. This downloads the firmware and verifies its fingerprint but writes nothing:

   ```sh
   trezorctl firmware-update --dry-run
   ```

3. Install it and confirm on the device when prompted:

   ```sh
   trezorctl firmware-update
   # or a specific release:
   trezorctl firmware-update --version <x.y.z>
   ```

4. After the device restarts, check the version:

   ```sh
   workbench-doctor
   ```

`trezorctl` verifies the firmware fingerprint against `data.trezor.io` by default. To pin it yourself, pass `--fingerprint <hex>`.

The required minimum firmware version is in the [readme requirements table](../../readme.md#-requirements--compatibility).
