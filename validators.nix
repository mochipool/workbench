# validation.nix provides helper functions to validate network inputs

{ lib }:

let
  validNetworks = {
    mainnet = "Mainnet";
    preprod = "PreProd";
    preview = "Preview";
    sancho = "Sancho";
    legacy = "Legacy";
    guildnet = "GuildNet";
  };

  # Validates that the network input is part of `validNetworks`
  validateNetwork = network:
    let
      matchingNetwork = lib.findFirst
        (valid: valid == toString network)
        null
        (lib.attrValues validNetworks);
    in
      if matchingNetwork != null then matchingNetwork
      else throw ''
        Invalid network: '${toString network}'
        Valid networks are:
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "- ${v}") validNetworks)}
      '';

in {
  network = {
    inherit validateNetwork;
    # normalize = validateNetwork;
    isMainnet = network: (validateNetwork network) == "Mainnet";
  };
}
