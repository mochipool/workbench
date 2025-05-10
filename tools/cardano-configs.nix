# cardano-configs.nix
{ pkgs }:
let
  configPaths = {
    # mainnet
    mainnet = {
      byron = {
        url = "https://book.world.dev.cardano.org/environments/mainnet/byron-genesis.json";
        sha256 = "1ahkdhqh07096law629r1d5jf6jz795rcw6c4vpgdi5j6ysb6a2g";
      };
      shelley = {
        url = "https://book.world.dev.cardano.org/environments/mainnet/shelley-genesis.json";
        sha256 = "0qb9qgpgckgz8g8wg3aa9vgapym8cih378qc0b2jnyfxqqr3kkar";
      };
      alonzo = {
        url = "https://book.world.dev.cardano.org/environments/mainnet/alonzo-genesis.json";
        sha256 = "0234ck3x5485h308qx00kyas318dxi3rmxcbksh9yn0iwfpvycvk";
      };
      conway = {
        url = "https://book.world.dev.cardano.org/environments/mainnet/conway-genesis.json";
        sha256 = "1nzxzx8l2g0z4vqimqaya8jksmr3a6g5gim3la51fbkk2x9zqw0f";
      };
    };
    preprod = {
      byron = {
        url = "https://book.world.dev.cardano.org/environments/preprod/byron-genesis.json";
        sha256 = "1vqcq28kypdmxw51993gq0kyag6781cfj17mvpxcraldyzyvz3yq";
      };
      shelley = {
        url = "https://book.world.dev.cardano.org/environments/preprod/shelley-genesis.json";
        sha256 = "1plm01jmwilg6vcdz11vnj4rl92svdcizfl68f799hjrj70357ab";
      };
      alonzo = {
        url = "https://book.world.dev.cardano.org/environments/preprod/alonzo-genesis.json";
        sha256 = "0234ck3x5485h308qx00kyas318dxi3rmxcbksh9yn0iwfpvycvk";
      };
      conway = {
        url = "https://book.world.dev.cardano.org/environments/preprod/conway-genesis.json";
        sha256 = "1y73kca4xhslqd7svrr9fxjkj0wphiqjhp0fj78nmwz8w97q35n1";
      };
    };
    preview = {
      byron = {
        url = "https://book.world.dev.cardano.org/environments/preview/byron-genesis.json";
        sha256 = "0ka5ih5qfnq3z3jfd4r9p606k0qw81758c82ldxknqav9j2a1lki";
      };
      shelley = {
        url = "https://book.world.dev.cardano.org/environments/preview/shelley-genesis.json";
        sha256 = "0sklb9if9wzhmjpyqfhjzlbfbkpj3vn644wbq2l1hrv7c58v9k65";
      };
      alonzo = {
        url = "https://book.world.dev.cardano.org/environments/preview/alonzo-genesis.json";
        sha256 = "0234ck3x5485h308qx00kyas318dxi3rmxcbksh9yn0iwfpvycvk";
      };
      conway = {
        url = "https://book.world.dev.cardano.org/environments/preview/conway-genesis.json";
        sha256 = "15ww8didys69s40kcf4qryvysiz3fnj3kki8lzkk9d93y51gd140";
      };
    };
  };

  # Accepts a network name and an override for the paths to the config files
  mkConfigs = { overrides ? {} }:
    let
      applyOverride = name: default:
        if overrides ? ${name}
        then (default // overrides.${name})
        else default;
    in
      builtins.mapAttrs applyOverride configPaths;

  # Create a derivation for each file
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

  # This lib provides a way to override the config file locations and hashes
  # This is useful when switching networks or using a custom file host
  lib = {
    mkCardanoConfigs = { network, overrides ? {} }:
      let
        # Create a derivation for each file
        # and one which contains all files
        base = mkConfigs { inherit overrides; };
        composite = {
          all = (pkgs.symlinkJoin {
            name = "cardano-configs";
            paths = builtins.attrValues base;
          });
        };
        finalConfigs = base // composite;
      in
        builtins.mapAttrs mkConfigDerivation finalConfigs.${network};
  };

  # Create derivations for each default network
  # TODO: expand this to allow for custom network overrides
  configs = builtins.listToAttrs (map (net: {
    name = net;
    value = lib.mkCardanoConfigs {
      network = net;
      overrides = {};
    };
  }) ["mainnet" "preview" "preprod"]);
in
{
  inherit lib configs;
}
