# Generates the "Requirements & compatibility" markdown that is embedded in
# readme.md, from the same data the flake enforces (versions.nix + the
# requirements parsed out of the SPO scripts' 00_common.sh). A flake check
# (checks.<system>.readme-sync) fails when the readme drifts; regenerate with
# `nix run .#update-readme`.
{ lib
, versions # versions.nix
, requirements # tools/spo-compat.nix `requirements`
}:
let
  inherit (versions) tools;

  noLimit = v: v == null || lib.hasPrefix "99." v;
  min = v: if v == null then "—" else "≥ ${v}";
  max = v: if noLimit v then "—" else "≤ ${v}";

  hwVersions = lib.unique (map (p: p.version) (builtins.attrValues tools.cardano-hw-cli.platforms));

  row = cols: "| ${lib.concatStringsSep " | " cols} |";

  toolRows = [
    [ "cardano-node" tools.cardano-node.version (min requirements.minNodeVersion) (max requirements.maxNodeVersion) ]
    [ "cardano-cli" tools.cardano-cli.version (min requirements.minCliVersion) (max requirements.maxCliVersion) ]
    [ "cardano-hw-cli" (lib.concatStringsSep " / " hwVersions) (min requirements.minHardwareCliVersion) "—" ]
    [ "cardano-signer" tools.cardano-signer.version (min requirements.minCardanoSignerVersion) "—" ]
  ];

  deviceRows = [
    [ "Ledger Cardano app" (min requirements.minLedgerCardanoAppVersion) ]
    [ "Trezor firmware" (min requirements.minTrezorCardanoAppVersion) ]
    [ "Keystone firmware" (min requirements.minKeystoneCardanoAppVersion) ]
  ];
in
lib.concatStringsSep "\n" ([
  "Pinned versions and the minimum/maximum versions the SPO scripts (`${tools.spo-scripts.version}`) enforce at runtime:"
  ""
  "| Tool | Pinned | Required min | Required max |"
  "| --- | --- | --- | --- |"
] ++ map row toolRows ++ [
  ""
  "Hardware wallet device requirements (managed on the device, not by this flake):"
  ""
  "| Device | Required min |"
  "| --- | --- |"
] ++ map row deviceRows ++ [
  ""
  "Supported systems: ${lib.concatMapStringsSep ", " (s: "`${s}`") versions.supportedSystems}."
  ""
  "_This section is generated from `versions.nix` and the scripts' `00_common.sh` — do not edit by hand; run `nix run .#update-readme`._"
])
