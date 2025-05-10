# cardano-hw-cli.nix
{ pkgs 
, system ? builtins.currentSystem
, version ? "1.18.2"
}:

let
  inherit (pkgs) lib stdenv fetchurl autoPatchelfHook;
  platforms = {
    x86_64-linux = "linux-x64";
    aarch64-linux = "linux-arm64";
    x86_64-darwin = "mac-x64";
  };

  platform = platforms.${system} or (throw "Unsupported system: ${system}");

  baseUrl = "https://github.com/vacuumlabs/cardano-hw-cli/releases/download/v${version}";

  binaryTarball = "${baseUrl}/cardano-hw-cli-${version}_${platform}.tar.gz";
  autocompleteScript = "${baseUrl}/autocomplete.sh";

  # You'll need to replace these with actual hashes
  binaryHashes = {
    "linux-x64" = "Ly4+CS0w3FBqZZQucE+YICA0hkP0sKel/w9pU8PEjGU=";
    "linux-arm64" = "14511bk0qb8sif5v6dx3ici497v28l8phdfw2kbhr1c0l4rl61jr";
    "mac-x64" = "1fp9y9pdqzkv6qwpzx7hcahfrf52bh8nxknksy6panzkh1fiy6gi";
  };

  autocompleteHash = "14yj7g6n5idxrjskk32krn9zphsiidhprh4xm3l7s6q599cb3nnl";

in {
  cli = stdenv.mkDerivation {
    pname = "cardano-hw-cli";
    inherit version;
    src = fetchurl {
      url = binaryTarball;
      sha256 = binaryHashes.${platform};
    };

    # File stripping causes errors
    dontStrip = true;         # Skip stripping binaries
    installPhase = ''
      mkdir -p $out/bin
      cp ./* $out/bin
      chmod +x $out/bin/cardano-hw-cli
    '';

    meta = {
      description = "CLI for Cardano Hardware Wallets";
      homepage = "https://github.com/vacuumlabs/cardano-hw-cli";
      platforms = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" ];
      mainProgram = "cardano-hw-cli";
    };
  };

  autocomplete = stdenv.mkDerivation {
    pname = "cardano-hw-cli-autocomplete";
    inherit version;
    src = fetchurl {
      url = autocompleteScript;
      sha256 = autocompleteHash;
    };
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out/share/cardano-hw-cli
      install -m644 $src $out/share/cardano-hw-cli/autocomplete.sh
    '';
  };
}
