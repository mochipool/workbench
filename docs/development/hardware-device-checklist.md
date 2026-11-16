# Hardware wallet: what only a real device can confirm

The hardware signer (`spo/internal/adapters/hwcli`) drives the pinned `cardano-hw-cli`. It was built from the spec corpus and the tool's `--help`, and is tested against one stand-in tool (`spo/test/hardware/fakehw`, built by the adapter's own tests, `test/world` and `test/hardware`). The fake signs the real transaction id and hashes the real script (it uses `adapters/native`), so the adapter is driven with bodies and scripts the native ledger builds; it also has a `misbehave` setting (wrong key, wrong body id, wrong counter or KES key, wrong policy id, truncated output, failure after writing) so each check the adapter makes of the tool's output has a test where it refuses. The one test against the real tool needs no device: it reads the tool's version and confirms that a missing device ends in a clean timeout.

**Nothing here has run against a Ledger, Trezor or Keystone.** Each item below is an assumption to confirm with a device, on preview, with throw-away keys. Record the result and the device and app version next to the item; fix the adapter or the profile table (`spo/internal/domain/custody/hardware.go`) where reality differs.

| # | Check | How |
| --- | --- | --- |
| 1 | `device version` prints `<Vendor> app version X` on its first line, with the version as the fourth word | Run the tool directly with each vendor's device unlocked and the Cardano app open |
| 2 | `address key-gen` and `node key-gen` write a signing file whose `cborXPubKeyHex` is `5840` + 32-byte public key + 32-byte chain code, and whose `path` is a list of strings such as `1852H`; the verification key equals the first 32 bytes. The two output flags appear swapped in `--help`: confirm which is which | Export a payment key and a pool cold key; compare with the adapter's parsed result |
| 3 | `transaction witness` writes a `TxWitness ConwayEra` envelope of `[vkey, signature]` whose signature verifies over the body id; behaviour with one and with two `--hw-signing-file` arguments | Witness a small send transaction; the adapter verifies the result itself |
| 4 | `transaction transform` runs with no device attached and returns a canonical body unchanged, byte for byte | Run it on a body built by `spo` with the device unplugged |
| 5 | `node issue-op-cert` accepts the counter file the adapter writes and issues exactly the counter asked for | Issue an opcert; the adapter checks KES key, counter, period and the cold signature |
| 6 | `message sign` output carries `COSE_Sign1_hex` and `COSE_Key_hex`, and the key holds the pool cold public key | Sign the Calidus registration payload path with a cold key |
| 7 | `vote registration-metadata` accepts the bech32 voting key and the `addr` / `addr_test` forms, and emits the CIP-36 layout the native code produces | Generate a Catalyst registration; the adapter errors on purpose if the layout differs |
| 8 | `transaction policyid` prints a 56-character hex id on stdout | Export a policy key and ask for the id of a script |
| 9 | The words the adapter looks for (`REJECTED`, `DISCONNECT`, the expert-mode warning) appear in the real output | Decline on the device; unplug mid-operation; try a restricted operation with expert mode off |
| 10 | Minimum versions: Ledger app 8.0.0 for unrestricted mode, 6.0.3 for the voting key and CIP-36; whether Trezor and Keystone support the Conway features at all | Try each operation on each vendor; add or remove rows in the profile table |
| 11 | `--allow-unrestricted-mode` changes the transform result for a body that needs it | Transform a body with a foreign certificate with and without the flag |
| 12 | The packaged tool needs no environment beyond `PATH`, `HOME`, `LANG`, `LC_ALL` and `XDG_RUNTIME_DIR` | Run through `nix run .#spo` with a device; the adapter passes only those |
| 13 | A DRep update certificate (`drep-update`, certificate type 18) is signed by the device with the same `transaction witness` call as a registration; the profile table grants it on Ledger and Keystone from the session minimum | Update a registered DRep on each device; if one refuses, remove the feature from its row |

## What the profile table deliberately does not claim

A device is refused, before anything is built or shown, for anything the table does not list (ADR 0008). These are unlisted because the specs do not establish them:

* DRep, committee, vote-delegation and CIP-36 features on Trezor or Keystone;
* a DRep update certificate is granted with the registration on Ledger and Keystone (`SPO-21b-INV-006` has one signing form for both kinds, `SPO-21b-EXT-006`), but no spec names the app or firmware version that first signs it: check item 13;
* message signing with payment, stake or DRep keys on any device (the specs use it only for the pool cold key);
* which firmware version introduced which feature, beyond the minimum versions upstream enforces;
* Calidus keys on a device, CIP-88 signing on a device, governance actions, Plutus scripts.

Adding a capability is one row in the table, with its source in a comment.

## What is wired

Commands select a hardware holder with `--hardware` on the key-generation commands (`wallet new`, `pool keys generate`, `drep keys generate`, `committee keys generate-cold|generate-hot`, `policy new`); transaction commands need no flag, because the signing plan sees who holds each key. `cmd/spo` builds a lazy device session when the toolchain manifest provides `cardano-hw-cli`; the device is first contacted when a command's plan needs it. Unrestricted mode is asked for with `--allow-unrestricted` and a yes/no question that no flag answers. See [the command reference](../reference/spo-cli.md).

Underneath:

* key generation plans against the signer's profile and exports through it (`app/hwkeys`, with the exporters of `app/wallet`, `app/poolops` and `app/governance`);
* transaction use cases bring the body to hardware-canonical form (`txflow`, `ports.HardwareCanonicalizer`) before the body is fixed and shown, then ask the device for each witness.

Not wired: Calidus and Catalyst keys on a device (the commands refuse a hardware holder).

End-to-end tests against the fake exist (`spo/test/hardware`, through the real use cases, the native ledger and the real adapter) for:

* payment account, wallet (hardware and hybrid), cold key, DRep, committee hot and cold keys, policy key and policy id: generation (`keys_test.go`);
* operational certificate with a hardware cold key (`TestOpCertWithHardwareColdKey`);
* 01 send from a hardware payer, with the body canonicalised before display and the change keys declared; a hardware payer without a canonicalizer is refused;
* stake registration and delegation; a poll answer with a hardware payer and a key-file cold key (13a); a hybrid wallet's stake registration is refused;
* DRep registration and DRep update (21b), both keys on a Ledger; the unrestricted-mode consent; votes on a Ledger (refused on other vendors; several votes need consent); the kept refusals;
* pool registration (05c) with the cold key, the payer and the owner on one Ledger (`pool_test.go`): three witnesses, only the registration certificate attached.

No end-to-end test exists for: 05c with a hardware owner and a key-file cold key, or a remote owner; 07b (re-registration and pool retirement); 08b; 22b; 23c and 23e (committee authorisation and cold key resignation); 21d (DRep retirement); 11a and 11b (mint and burn), 01 send assets and claim rewards; a Catalyst voting key and CIP-36 registration through the device (09a); Calidus and CIP-88 (15, refused). The adapter's own tests cover the tool calls for message signing, CIP-36 and the policy id, not the use cases that would call them.
