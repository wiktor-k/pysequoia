{
  description = "Flake for PySequoia Python package";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self
  , nixpkgs
  , flake-utils
  }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        devShells = {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.python3
              pkgs.python3.pkgs.virtualenv
              pkgs.python3.pkgs.pip
            ];
          };
        };
        packages = {
          # Besides the `src` and `cargoTomlPkg` arguments, this package.nix could
          # be copied as is to Nixpkgs'
          # pkgs/development/python-modules/pysequoia/default.nix, and should be
          # maintained in parallel to this local version of it.
          pysequoia = pkgs.python3.pkgs.callPackage ./package.nix {
            src = self;
            cargoTomlPkg = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
          };
        };
      }
    );
}
