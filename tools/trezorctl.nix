# trezorctl (Trezor's official CLI, used here for firmware updates).
#
# nixpkgs lags upstream (0.13.10 at the time of writing, which predates newer
# Trezor models), so the release is pinned here from PyPI. The 0.20 line also
# dropped the python-ecdsa dependency that nixpkgs flags as insecure.
{ pkgs
, version
, hash
}:
let
  py = pkgs.python3Packages;

  # slip10 1.0.1 (nixpkgs) pulls in python-ecdsa; 1.1.0 depends only on
  # cryptography.
  slip10 = py.slip10.overridePythonAttrs (_: {
    version = "1.1.0";
    src = pkgs.fetchPypi {
      pname = "slip10";
      version = "1.1.0";
      hash = "sha256-0kjT3ybxI/CEdDOcRfDyZCVPdK6aVlcjSh1euR8MTVQ=";
    };
    propagatedBuildInputs = [ py.cryptography ];
    dependencies = [ py.cryptography ];
  });
in
(py.trezor.override {
  # no longer a dependency from 0.20 onwards
  ecdsa = null;
  inherit slip10;
}).overridePythonAttrs (old: {
  inherit version;
  src = pkgs.fetchPypi {
    pname = "trezor";
    inherit version hash;
  };
  dependencies =
    (builtins.filter (d: d != null) (old.dependencies or [ ]))
    ++ [ py.noiseprotocol py.platformdirs py.keyring ];
  # tests need network access / extra deps
  build-system = [ py.flit-core ];
  doCheck = false;
  pythonRelaxDeps = true;
})
