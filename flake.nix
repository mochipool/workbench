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
          inherit system;
          inherit (pkgs) pkgs lib stdenv fetchurl autoPatchelfHook;
          version = "1.18.2";
      };

      # SPO Scripts
      spo-scripts = import ./tools/spo-scripts.nix {
        inherit (pkgs) pkgs lib;
        inherit cardano-pkgs cardano-hw-cli;
      };

      # Cardano Network Validator Functions
      validators = import ./validators.nix { 
        inherit (pkgs) lib;
      };

      # Base system packages to include
      basePkgs = [
        cardano-hw-cli.cli
      ];

      # Shell generator function
       mkNetworkShell = network:
          let 
            spoConfig = spo-scripts.mkCommon {
              inherit network;
              workMode = "light";
            };
            
          in pkgs.mkShell {
            name = "workspace-${network}";
            buildInputs = basePkgs ++ spo-scripts.buildInputs ++ [
              spoConfig.derivation
            ];
            
            shellHook = ''
              # autocomplete for cardano-hw-cli
              source ${cardano-hw-cli.autocomplete}/share/cardano-hw-cli/autocomplete.sh

              # Set up common.inc
              ln -sf ${spoConfig.commonInc} ~/.common.inc
              
              # Clean up on exit
              trap "rm -f ~/.common.inc" EXIT 0
              
              echo "Configured for ${network} network"
            '';
          };

    in
    {
      # packages.${system} = spo-scripts.derivations;
      devShells.${system} = {
        default = self.devShells.${system}.mainnet;
        mainnet = mkNetworkShell "Mainnet";
        preprod = mkNetworkShell "PreProd";
        preview = mkNetworkShell "Preview";
        sancho = mkNetworkShell "Sancho";
      };

    };
}
