# Update Keystone firmware

This guide shows how to update a Keystone 3 Pro through its microSD route.

## Prerequisites

* The device charged (Keystone recommends at least 70%).
* A FAT32 microSD card.
* A computer with `sha256sum`.

Keystone firmware cannot be updated from the command line: the USB route is browser-only (WebUSB). The microSD route needs only a download and a file copy and works on any OS. For other models see [Keystone's firmware guide](https://guide.keyst.one/docs/firmware-upgrade).

## Steps

1. Download the firmware for your model from Keystone's official firmware page and note the published checksum.
2. Verify the download, then copy it to the root of the card as `keystone3.bin`:

   ```sh
   sha256sum keystone3.bin    # compare with the checksum Keystone publishes
   cp keystone3.bin /path/to/mounted/sdcard/keystone3.bin
   sync
   ```

3. Insert the card into the device. Tap **Update** on the "New firmware detected" prompt (or go to Device Settings, About, Firmware, Via MicroSD Card) and enter your PIN.
4. After the device reboots, check the version:

   ```sh
   workbench-doctor
   ```

The required minimum firmware version is in the [readme requirements table](../../readme.md#-requirements--compatibility).
