{
  description = "Cardano Node SPO Workbench";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = {self, nixpkgs, ...} @ inputs:
    let
      # Auto-detect the current system
      system = builtins.currentSystem or "x86_64-linux";
      
      # Instantiate pkgs for the current system
      pkgs = import nixpkgs { inherit system; };

      # By default files will be fetched from book.world.dev
      # NOTE: this can be overridden by providing an override attribute set
      network = "mainnet";
      defaultConfigs = {
        byron = {
          url = "https://book.world.dev.cardano.org/environments/${network}/byron-genesis.json";
          sha256 = "1ahkdhqh07096law629r1d5jf6jz795rcw6c4vpgdi5j6ysb6a2g";
        };
        shelley = {
          url = "https://book.world.dev.cardano.org/environments/${network}/shelley-genesis.json";
          sha256 = "0qb9qgpgckgz8g8wg3aa9vgapym8cih378qc0b2jnyfxqqr3kkar";
        };
        alonzo = {
          url = "https://book.world.dev.cardano.org/environments/${network}/alonzo-genesis.json";
          sha256 = "0234ck3x5485h308qx00kyas318dxi3rmxcbksh9yn0iwfpvycvk";
        };
        conway = {
          url = "https://book.world.dev.cardano.org/environments/${network}/conway-genesis.json";
          sha256 = "1nzxzx8l2g0z4vqimqaya8jksmr3a6g5gim3la51fbkk2x9zqw0f";
        };
      };

      # Function to build the final configs with overrides
      mkConfigs = { overrides ? {} }: 
        let
          applyOverride = name: default:
            if overrides ? ${name}
            then (default // overrides.${name})
            else default;
        in
          builtins.mapAttrs applyOverride defaultConfigs;

      # Function to create a derivation for a config file
      mkConfigDerivation = name: { url, sha256 }:
        pkgs.stdenv.mkDerivation {
          name = "${name}-genesis";
          src = builtins.fetchurl { inherit url sha256; };
          dontUnpack = true;
          installPhase = ''
            mkdir -p $out
            cp $src $out/${name}-genesis.json
          '';
        };

      configs = mkConfigs {};
      configDerivations = builtins.mapAttrs mkConfigDerivation configs;

      # Expose the config creation function via flake output
      # overrides = {
      #   conway = {
      #     url = "https://custom.url/conway-genesis.json";
      #     sha256 = "CHANGEME";
      #   };
      # };
      lib = {
        mkCardanoConfigs = { overrides ? {} }:
          let
            finalConfigs = mkConfigs { inherit overrides; };
          in
            builtins.mapAttrs mkConfigDerivation finalConfigs;
      };

  in {
      # Expose packages
      packages.${system} = configDerivations // {
        # Composite package containing all configs
        all = pkgs.symlinkJoin {
          name = "cardano-configs";
          paths = builtins.attrValues configDerivations;
        };
        
        # Default package (can choose one or make composite)
        default = self.packages.${system}.all;
      };

      # Expose the library function
      inherit lib;
  };
}
