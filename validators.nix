# validators.nix provides helper functions to validate network inputs
{ lib }:

let
  # Maps normalized (lowercase) names to the canonical network name.
  validNetworks = {
    mainnet = "Mainnet";
    preprod = "PreProd";
    preview = "Preview";
  };

  # Validates the network input (case-insensitive) and returns its
  # canonical name.
  validateNetwork = network:
    validNetworks.${lib.toLower (toString network)} or (throw ''
      Invalid network: '${toString network}'
      Valid networks are:
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "- ${v}") validNetworks)}
    '');

  normalize = network: lib.toLower (toString (validateNetwork network));
  isMainnet = network: (validateNetwork network) == "Mainnet";

in {
  network = {
    inherit validateNetwork normalize isMainnet;
  };
}
