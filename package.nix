{ lib
, buildPythonPackage
, src
, cargoTomlPkg
, pkg-config
, rustPlatform
, cargo
, rustc
, bzip2
, nettle
, openssl
, stdenv
, darwin
, libiconv
}:

buildPythonPackage rec {
  pname = "pysequoia";
  inherit src;
  inherit (cargoTomlPkg) version;
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
  ] ++ lib.optionals stdenv.isDarwin [
    darwin.apple_sdk.frameworks.CoreFoundation
    darwin.apple_sdk.frameworks.Security
    libiconv
  ] ++ lib.optionals stdenv.isLinux [
    nettle
  ];

  pythonImportsCheck = [ "pysequoia" ];

  meta = {
    inherit (cargoTomlPkg)
      description
      homepage
    ;
    downloadPage = cargoTomlPkg.repository;
    license = lib.licenses.asl20;
    maintainers = with lib.maintainers; [ doronbehar ];
  };
}
