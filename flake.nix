{
  description = "Cardano SPO Workbench";

  # This uses IOG cache to avoid rebuilding all artifacts
  # see: https://github.com/input-output-hk/iogx/blob/main/doc/api.md#flakenixnixconfig
  nixConfig = {
    extra-substituters = [
      "https://cache.iog.io"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    cardano-node = {
      url = "github:IntersectMBO/cardano-node?ref=master";
      flake = true;
    };
    spo-scripts = {
      url = "github:gitmachtl/scripts";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, cardano-node, spo-scripts, ... } @ inputs:
    let
      system = "x86_64-linux"; # Change if needed for your system

      # Import nixpkgs with our overlay
      pkgs = import nixpkgs {
        inherit system;
      };

      # Cardano Packages
      cardano-pkgs = import cardano-node {
        inherit system;
      };

      # Cardano HW CLI
      cardano-hw-cli = import ./tools/cardano-hw-cli.nix {
          inherit (pkgs) pkgs lib stdenv fetchurl autoPatchelfHook;
          inherit system;
          version = "1.18.2";
        };

      # Cardano Network Validator Functions
      validators = import ./validators.nix { lib = pkgs.lib; };

      # Base system packages to include
      basePkgs = [
        pkgs.jq
        pkgs.curl
        pkgs.bc
        pkgs.xxd
        cardano-hw-cli.cli
      ];

      # NOTE: There are two types of network variables following:
      # `network`: the actual network name, e.g. "Mainnet", "PreProd", "Preview"
      # `commonNetwork`: the type of network the `network` belongs to ["mainnet", "testnet"]
      # This is included because the spo scripts are separated based on the paths of the `commonNetwork`
      # but the configuration still depends on the names of the actual `network`

      # This provides the common network name, i.e. "mainnet" or "testnet", validating the inputs
      commonNetwork = network: if validators.network.isMainnet network then "mainnet" else "testnet";

      spoScriptsCfgTemplate = network: rec {
        # Define all required packages here. These will be added to the PATH.
        exes = {
          cardanonode = cardano-pkgs.cardano-node;
          cardanocli = cardano-pkgs.cardano-cli;
          bech32_bin = cardano-pkgs.bech32;
          # TODO: cardano-signer = CHANGE_ME
          # TODO: cardano-hw-cli = CHANGE_ME
        };
        
        # Define all other parameters here.
        # see: https://github.com/gitmachtl/scripts/blob/master/cardano/mainnet/00_common.sh
        cfg = {
          workMode = "light";
          network = "${network}";
        } // pkgs.lib.mapAttrs (name: pkg: pkgs.lib.getExe pkg) exes;

        # Automatically generate quoted key="value" lines
        # This file wil be linked to ~/.common.inc and removed on exit of dev shell
        commonInc = pkgs.writeText "common.inc" (
          pkgs.lib.concatStringsSep "\n" (
            pkgs.lib.mapAttrsToList (name: value: ''${name}="${value}"'') cfg
          )
        );
      };

      # Shell generator function
       mkNetworkShell = network:
          let cfg = spoScriptsCfgTemplate network;
          in pkgs.mkShell {
            name = "workspace-${network}";
            buildInputs = basePkgs ++ builtins.attrValues cfg.exes;
            
            shellHook = ''
              # autocomplete for cardano-hw-cli
              source ${cardano-hw-cli.autocomplete}/share/cardano-hw-cli/autocomplete.sh

              # Set up common.inc
              ln -sf ${cfg.commonInc} ~/.common.inc
              
              # Add scripts to PATH
              export PATH="$PATH:${spo-scripts}/cardano/${commonNetwork network}"
              
              # Clean up on exit
              trap "rm -f ~/.common.inc" EXIT 0
              
              echo "Configured for ${network} network"
            '';
          };

    in
    {
      packages.${system} = {
        cardano-hw-cli = cardano-hw-cli.cli;
        # cardano-hw-cli = cardano-hw-cli.autocomplete;
      };

      devShells.${system} = {
        default = self.devShells.${system}.mainnet;
        mainnet = mkNetworkShell "Mainnet";
        preprod = mkNetworkShell "PreProd";
        preview = mkNetworkShell "Preview";
        sancho = mkNetworkShell "Sancho";
      };

    };
}
