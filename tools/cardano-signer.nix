# Packages the official cardano-signer release binaries (gitmachtl).
# Required by the SPO scripts (minCardanoSignerVersion in 00_common.sh).
{ pkgs
, version
, hashes
}:

let
  inherit (pkgs) lib stdenvNoCC fetchurl;
  system = stdenvNoCC.hostPlatform.system;

  # No native mac-arm64 artifact; Apple Silicon runs mac-x64 via Rosetta 2.
  platforms = {
    x86_64-linux = "linux-x64";
    aarch64-linux = "linux-arm64";
    x86_64-darwin = "mac-x64";
    aarch64-darwin = "mac-x64";
  };

  platform = platforms.${system} or (throw "cardano-signer: unsupported system: ${system}");

  hash = hashes.${platform} or (throw "cardano-signer: no hash recorded for ${platform} at version ${version} — update versions.nix");

in stdenvNoCC.mkDerivation {
  pname = "cardano-signer";
  inherit version;

  src = fetchurl {
    url = "https://github.com/gitmachtl/cardano-signer/releases/download/v${version}/cardano-signer-${version}_${platform}.tar.gz";
    inherit hash;
  };

  sourceRoot = ".";

  # pkg-bundled node binary: the JS payload is appended to the ELF image and
  # patchelf/strip corrupt it, so ship it exactly as released. On NixOS run
  # via nix-ld; regular distros work as-is.
  dontStrip = true;
  dontPatchELF = true;
  installPhase = ''
    runHook preInstall
    install -Dm755 cardano-signer $out/bin/cardano-signer
    runHook postInstall
  '';

  meta = {
    description = "Signing and verification tool for the Cardano blockchain (CIP-8, CIP-36, and more)";
    homepage = "https://github.com/gitmachtl/cardano-signer";
    license = lib.licenses.gpl3Only;
    platforms = builtins.attrNames platforms;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    mainProgram = "cardano-signer";
  };
}
