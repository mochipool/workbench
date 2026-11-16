# Update the Ledger Cardano app

This guide shows how to bring a Ledger's Cardano app up to the version the SPO scripts require.

## Prerequisites

* [Ledger Live](https://www.ledger.com/ledger-live) installed. Ledger's tooling is not packaged in this flake.
* The device connected and unlocked.

## Steps

1. Update the device firmware first in Ledger Live, then update or install the **Cardano** app in the *My Ledger* tab.
2. If the Cardano app version you need is not offered yet, the SPO scripts suggest enabling *Settings, Experimental Features, My Ledger provider* and setting it to `4`. This is at your own risk.
3. Open the Cardano app on the device and check the version:

   ```sh
   workbench-doctor
   ```

The device check only works while the Cardano app is open. The required minimum app version is in the [readme requirements table](../../readme.md#-requirements--compatibility).
