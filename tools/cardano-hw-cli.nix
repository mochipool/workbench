# cardano-hw-cli.nix
{ pkgs 
, system ? builtins.currentSystem
, version ? "1.19.1"
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
    "linux-x64" = "0x34nyam4ckg4mpvbaljks2xpxlll1zhgbzs07inb972rzmlk4q8";
    "linux-arm64" = "0sv8mpzs8mc89cfdgqvy0cfgs2i8h7npj2kgx98ckhlngh7j105r";
    "mac-x64" = "0m0i3xn5krqiap83cj2dj7qncaz6sfwbkj66fm6df5x56nqvhi9a";
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
