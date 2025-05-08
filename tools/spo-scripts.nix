# spo-scripts.nix
{ pkgs, lib, cardano-pkgs, cardano-hw-cli }:
let
# Debug spo-scripts input
  validators = import ../validators.nix{
    inherit lib;
  };

  spo-scripts = builtins.fetchGit {
    url = "https://github.com/gitmachtl/scripts";
    rev = "c0225dc9fae42f6b6816afb3837f49e2bff79b9e";
  };

  # Default params (can be overridden)
  defaultParams = {
    network = null;  # Required (no default)
    workMode = "light";
    # ... other params with defaults
  };

  # Executables configuration
  exes = {
    cardanonode = cardano-pkgs.cardano-node;
    cardanocli = cardano-pkgs.cardano-cli;
    bech32_bin = cardano-pkgs.bech32;
    cardanohwcli = cardano-hw-cli.cli;
  };

  buildInputs = [
    pkgs.jq
    pkgs.curl
    pkgs.bc
    pkgs.xxd
  ];

  mkScripts = params:
    let commonNetwork = getCommonNetwork params;
    in pkgs.stdenv.mkDerivation {
      name = "spo-scripts-${commonNetwork}";
      src = spo-scripts;
      
      networkPath = "cardano/${commonNetwork}";

      installPhase = ''
        mkdir -p $out/bin
        cp $networkPath/* $out/bin/
        chmod +x $out/bin/*
      '';
    };

  # Merge user params with defaults
  mkParams = userParams: defaultParams // userParams;

  # Complete configuration builder
  mkConfig = params:
    let finalParams = mkParams params;
    in finalParams // lib.mapAttrs (name: pkg: lib.getExe pkg) exes;

  # Configuration file generator
  mkCommonInc = params:
    let cfg = mkConfig params;
    in pkgs.writeText "common.inc" (
      lib.concatStringsSep "\n" (
        lib.mapAttrsToList (name: value: ''${name}="${value}"'') cfg
      )
    );

  getCommonNetwork = params:
    if validators.network.isMainnet (params.network) then "mainnet" else "testnet";

in {
  mkCommon = params: {
    # Generates common.inc
    commonInc = mkCommonInc params;
    derivation = mkScripts params;
  };

  # Provides a common set of buildInputs to run the scripts
  buildInputs = buildInputs ++ builtins.attrValues exes;

}
