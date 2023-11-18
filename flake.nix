{
  # See https://github.com/mhwombat/nix-for-numbskulls/blob/main/flakes.md
  # for a brief overview of what each section in a flake should or can contain.

  # TODO: Fix this to something better
  description = "a very simple and friendly flake";

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
          # Besides the `src` and `version` arguments, this package.nix could
          # be copied as is to Nixpkgs'
          # pkgs/development/python-modules/pysequoia/default.nix, and should be
          # maintained in parallel to this local version of it.
          pysequoia = pkgs.python3.pkgs.callPackage ./package.nix {
            src = self;
            # Get the version defined in pyproject.toml
            version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
          };
        };
      }
    );
}
