{ lib
, buildPythonPackage
, src
, version
, pkg-config
, rustPlatform
, cargo
, rustc
, bzip2
, nettle
, openssl
, pcsclite
, stdenv
, darwin
, libiconv
}:

buildPythonPackage rec {
  pname = "pysequoia";
  inherit src version;
  pyproject = true;

  # This attribute is defined differently in Nixpkgs - using
  # `rustPlatform.fetchCargoTarball`. Since we have a Cargo.lock file available
  # here, we can use it instead.
  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
    rustPlatform.cargoSetupHook
    rustPlatform.maturinBuildHook
    cargo
    rustc
  ];

  buildInputs = [
    bzip2
    nettle
    pcsclite
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.CoreFoundation
    darwin.apple_sdk.frameworks.Security
    darwin.apple_sdk.frameworks.PCSC
    libiconv
  ];

  pythonImportsCheck = [ "pysequoia" ];

  meta = with lib; {
    description = "This library provides OpenPGP facilities in Python through the Sequoia PGP library";
    downloadPage = "https://codeberg.org/wiktor/pysequoia";
    homepage = "https://sequoia-pgp.gitlab.io/pysequoia";
    license = licenses.asl20;
    maintainers = with maintainers; [ doronbehar ];
  };
}
