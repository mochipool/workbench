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
| 14 | `message sign --message-hex <blake2b-256 of the CIP-88 payload> --signing-path-hwsfile <pool.node.hwsfile> --out-file F` (no `--hashed`) writes `COSE_Sign1_hex` whose payload is exactly that 32-byte hash, whose unprotected `hashed` flag is false, and whose protected header is `{1: -8, "address": <the 28-byte pool id>}`; `COSE_Key_hex` is the cold public key. `SignCip88` refuses anything else | Sign a Calidus registration on a Ledger and on a Keystone with a throw-away pool cold key; decode the file. If the tool writes the address as something else (the key hash with a header byte, no address, `hashed` true), the registration is refused with `bad output`: adapt `SignCip88` in `hwcli/messages.go` to build the witness the way CIP-88 verifiers expect, then repeat |
| 15 | The hash a Ledger displays for that `message sign` is the blake2b-224 of the message (`SPO-15-INV-006`), the value `pool calidus register-metadata` prints as `hash on device`; Keystone shows the same or something the operator can compare | Compare the device screen with the printed hash on each device. If it differs, the text of the question misleads: change what `BeforeDevice` prints |
| 16 | `vote registration-metadata` takes `--vote-weight` once per `--vote-public-key-string`, `--voting-purpose N` (only passed when not 0), `--payment-address-signing-key-hwsfile` and `--stake-signing-key-hwsfile` together as the adapter passes them, and writes the metadata the adapter then compares byte for byte with its own; passing the rewards key (`SPO-09a-INV-004`) stops the "unusual request" warning | Register with the payment key of the same wallet as rewards address and with another address; note the warning on the device. If the tool has no `--voting-purpose`, the purpose is fixed at 0 and the flag must go |
| 17 | The Ledger app minimum for the Catalyst voting key and CIP-36 signing is 6.0.3 (`SPO-09a-EXT-002`, `SPO-09a-EXT-004`), but the session minimum (`[hardware] min_ledger`, 8.0.8 by default) is applied to every call, so the table row `Min: 6.0.3` of `HardwareTable` never selects anything the session has not already required. The per-call lowering of upstream (`SPO-Chw-IF-001`, argument 2) is not built | Try the voting key and a registration on a Ledger app between 6.0.3 and the session minimum. If it works, build the per-call minimum; if it fails, nothing changes |
| 18 | A Keystone and a Trezor cannot make a Catalyst voting key or sign a CIP-36 registration (the table says Ledger only, because the specs name only the Ledger version) | Try both on each; if one can, add its vendor to the row |
| 19 | One `transaction witness` call with several `--hw-signing-file` and as many `--out-file` arguments writes one witness per key, in the order given, each verifying over the body id. `WitnessMany` (the combined node and payment witness of `SPO-05c-EXT-004`) exists in the adapter and is tested against the stand-in, but no use case calls it yet: 05c still asks the device once per key | Witness one body with the cold key and the payment key in one call. If the tool refuses or reorders, remove `WitnessMany`; if it works, 05c can use it and show one device prompt instead of two |
| 20 | `cardano-hw-cli` key generation on a Trezor derives with the tool's default derivation type, and the addresses match what a Ledger with the same seed would derive. The tool's `--derivation-type` option (Icarus, Icarus-Trezor, Ledger) is not passed and not mentioned by any spec | Make a payment key at account 0 on a Trezor and on a Ledger restored from the same words and compare the addresses. If they differ, decide which the workspace wants and set the option; until then a Trezor key is whatever the tool's default makes |
| 21 | A Calidus key cannot be made on any device: upstream suspends it until CIP-151 has a path (`SPO-15-PRE-002`), and `spo` refuses `--hardware` for it without calling the tool | Nothing to run. When upstream enables it, the path and the vendor restriction come from the new spec; add a `RoleCalidus` row then |

## What the profile table deliberately does not claim

A device is refused, before anything is built or shown, for anything the table does not list (ADR 0008). These are unlisted because the specs do not establish them:

* DRep, committee, vote-delegation and CIP-36 features on Trezor or Keystone;
* a DRep update certificate is granted with the registration on Ledger and Keystone (`SPO-21b-INV-006` has one signing form for both kinds, `SPO-21b-EXT-006`), but no spec names the app or firmware version that first signs it: check item 13;
* message signing with payment, stake or DRep keys on any device (the specs use it only for the pool cold key);
* which firmware version introduced which feature, beyond the minimum versions upstream enforces;
* Calidus keys on a device (suspended upstream, `SPO-15-PRE-002`: refused with that message, item 21), the Catalyst voting key and CIP-36 signing on a Keystone or a Trezor (items 17 and 18), a Trezor derivation type (item 20), governance actions, Plutus scripts.

CIP-88 signing by a pool cold key on a Ledger or a Keystone is granted (`SPO-15-EXT-004`, items 14 and 15), and so is the Catalyst voting key and CIP-36 signing on a Ledger.

Adding a capability is one row in the table, with its source in a comment.

## What is wired

Commands select a hardware holder with `--hardware` on the key-generation commands (`wallet new`, `pool keys generate`, `drep keys generate`, `committee keys generate-cold|generate-hot`, `policy new`, `catalyst key new`; `pool calidus new --hardware` only refuses); transaction commands need no flag, because the signing plan sees who holds each key. `cmd/spo` builds a lazy device session when the toolchain manifest provides `cardano-hw-cli`; the device is first contacted when a command's plan needs it. Unrestricted mode is asked for with `--allow-unrestricted` and a yes/no question that no flag answers. See [the command reference](../reference/spo-cli.md).

Underneath:

* key generation plans against the signer's profile and exports through it (`app/hwkeys`, with the exporters of `app/wallet`, `app/poolops` and `app/governance`);
* transaction use cases bring the body to hardware-canonical form (`txflow`, `ports.HardwareCanonicalizer`) before the body is fixed and shown, then ask the device for each witness.

Also wired: the Calidus registration signed by a hardware pool cold key (`pool calidus register-metadata`, after a confirmation that shows the hash the device displays), the Catalyst voting key made on a Ledger, and the CIP-36 registration signed by a hardware stake key with the same wallet's payment key passed as the rewards key. `WitnessMany` (one device call for several keys) is in the adapter and tested, not used by a use case.

Not wired: a Calidus key on a device (refused, item 21), a per-call Ledger minimum for the Catalyst calls (item 17), a Trezor derivation type (item 20).

End-to-end tests against the fake exist (`spo/test/hardware`, through the real use cases, the native ledger and the real adapter) for:

* payment account, wallet (hardware and hybrid), cold key, DRep, committee hot and cold keys, policy key and policy id: generation (`keys_test.go`);
* operational certificate with a hardware cold key (`TestOpCertWithHardwareColdKey`);
* 01 send from a hardware payer, with the body canonicalised before display and the change keys declared; a hardware payer without a canonicalizer is refused;
* stake registration and delegation; a poll answer with a hardware payer and a key-file cold key (13a); a hybrid wallet's stake registration is refused;
* DRep registration and DRep update (21b), both keys on a Ledger; the unrestricted-mode consent; votes on a Ledger (refused on other vendors; several votes need consent); the kept refusals;
* pool registration (05c) with the cold key, the payer and the owner on one Ledger (`pool_test.go`): three witnesses, only the registration certificate attached.

Also tested end to end (`ops_test.go`, `registration_test.go`; `cmd/spo/hardware_registration_e2e_test.go` through the command tree): 07b pool retirement (Ledger, Keystone), 08b stake deregistration, 22b vote delegation, 23c and 23e committee authorisation and resignation (Ledger, Keystone; a Trezor refused), 11a mint with a hardware policy key, 01 send assets, 01 claim rewards, the Calidus registration with a hardware pool cold key (Ledger, Keystone; Trezor, a declined confirmation and five misbehaviours of the tool refused), the Catalyst voting key on a Ledger (Keystone and Trezor refused) and the CIP-36 registration with a hardware stake key (with and without the rewards key; four misbehaviours refused). Each witness test checks that the submitted transaction has the id the operator was shown and that every witness verifies over it, and that a tool that signs with another key, signs another body, truncates its output or fails after writing is refused with nothing submitted.

No end-to-end test exists for: 05c with a hardware owner and a key-file cold key, or a remote owner; 05c/07b re-registration; 21d (DRep retirement); 11b (burn) and an asset send with a hardware policy key.
