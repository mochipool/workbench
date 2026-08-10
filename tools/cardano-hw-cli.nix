# Packages the official cardano-hw-cli release binaries (vacuumlabs).
# Upstream has no nix support; artifacts are pkg'd node binaries per platform.
{ pkgs
, version
, hashes
, autocompleteHash
}:

let
  inherit (pkgs) lib stdenvNoCC fetchurl;
  system = stdenvNoCC.hostPlatform.system;

  # Map nix systems to release artifact platform names. No native mac-arm64
  # artifact exists (as of 1.19.1); Apple Silicon runs mac-x64 via Rosetta 2.
  platforms = {
    x86_64-linux = "linux-x64";
    aarch64-linux = "linux-arm64";
    x86_64-darwin = "mac-x64";
    aarch64-darwin = "mac-x64";
  };

  platform = platforms.${system} or (throw "cardano-hw-cli: unsupported system: ${system}");

  hash = hashes.${platform} or (throw "cardano-hw-cli: no hash recorded for ${platform} at version ${version} — update versions.nix");

  baseUrl = "https://github.com/vacuumlabs/cardano-hw-cli/releases/download/v${version}";

in {
  cli = stdenvNoCC.mkDerivation {
    pname = "cardano-hw-cli";
    inherit version;

    src = fetchurl {
      url = "${baseUrl}/cardano-hw-cli-${version}_${platform}.tar.gz";
      inherit hash;
    };

    # The executable is a pkg-bundled node binary with its JS payload appended
    # to the ELF image: patchelf/strip shift the payload offsets and corrupt
    # it, so the binary must be shipped exactly as released. On NixOS (no FHS
    # loader paths) run it via nix-ld; regular distros work as-is.
    dontStrip = true;
    dontPatchELF = true;
    installPhase = ''
      runHook preInstall
      mkdir -p $out/bin
      cp -r ./* $out/bin/
      chmod +x $out/bin/cardano-hw-cli
      runHook postInstall
    '';

    meta = {
      description = "Command-line tool for signing Cardano transactions with Ledger, Trezor and Keystone hardware wallets";
      homepage = "https://github.com/vacuumlabs/cardano-hw-cli";
      license = lib.licenses.isc;
      platforms = builtins.attrNames platforms;
      sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
      mainProgram = "cardano-hw-cli";
    };
  };

  autocomplete = stdenvNoCC.mkDerivation {
    pname = "cardano-hw-cli-autocomplete";
    inherit version;

    src = fetchurl {
      url = "${baseUrl}/autocomplete.sh";
      hash = autocompleteHash;
    };

    dontUnpack = true;
    installPhase = ''
      runHook preInstall
      install -Dm644 $src $out/share/cardano-hw-cli/autocomplete.sh
      runHook postInstall
    '';

    meta = {
      description = "Shell autocompletion for cardano-hw-cli";
      homepage = "https://github.com/vacuumlabs/cardano-hw-cli";
      license = lib.licenses.isc;
    };
  };
}
