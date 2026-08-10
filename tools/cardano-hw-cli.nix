# Packages the official cardano-hw-cli release binaries (vacuumlabs).
# Upstream has no nix support; artifacts are pkg'd node binaries per platform.
{ pkgs
, version # nominal release-set version (used for the autocomplete script)
, platforms # per-platform artifact pins: { <platform> = { version, hash }; }
, autocompleteHash
}:

let
  inherit (pkgs) lib stdenvNoCC fetchurl;
  system = stdenvNoCC.hostPlatform.system;

  # Map nix systems to release artifact platform names. No native mac-arm64
  # artifact exists (as of 1.19.1); Apple Silicon runs mac-x64 via Rosetta 2.
  systemPlatforms = {
    x86_64-linux = "linux-x64";
    aarch64-linux = "linux-arm64";
    x86_64-darwin = "mac-x64";
    aarch64-darwin = "mac-x64";
  };

  platform = systemPlatforms.${system} or (throw "cardano-hw-cli: unsupported system: ${system}");

  artifact = platforms.${platform} or (throw "cardano-hw-cli: no artifact pin recorded for ${platform} — update versions.nix");

in {
  cli = stdenvNoCC.mkDerivation {
    pname = "cardano-hw-cli";
    version = artifact.version;

    src = fetchurl {
      url = "https://github.com/vacuumlabs/cardano-hw-cli/releases/download/v${artifact.version}/cardano-hw-cli-${artifact.version}_${platform}.tar.gz";
      inherit (artifact) hash;
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
      platforms = builtins.attrNames systemPlatforms;
      sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
      mainProgram = "cardano-hw-cli";
    };
  };

  autocomplete = stdenvNoCC.mkDerivation {
    pname = "cardano-hw-cli-autocomplete";
    inherit version;

    src = fetchurl {
      url = "https://github.com/vacuumlabs/cardano-hw-cli/releases/download/v${version}/autocomplete.sh";
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
