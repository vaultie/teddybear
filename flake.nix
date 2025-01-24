{
  inputs = {
    nixpkgs = {
      type = "github";
      owner = "nixos";
      repo = "nixpkgs";
      ref = "nixos-unstable";
    };

    crane = {
      type = "github";
      owner = "ipetkov";
      repo = "crane";
      ref = "v0.19.1";
    };

    fenix = {
      type = "github";
      owner = "nix-community";
      repo = "fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nix-filter = {
      type = "github";
      owner = "numtide";
      repo = "nix-filter";
    };

    flake-utils = {
      type = "github";
      owner = "numtide";
      repo = "flake-utils";
    };

    identity-context = {
      url = "https://w3c.credential.nexus/identity.jsonld";
      flake = false;
    };

    placeholder-image = {
      url = "https:/picsum.photos/id/0/200/300";
      flake = false;
    };

    thumbnail-image = {
      url = "https:/picsum.photos/id/1/128/128";
      flake = false;
    };
  };

  outputs = {
    nixpkgs,
    crane,
    fenix,
    nix-filter,
    flake-utils,
    identity-context,
    placeholder-image,
    thumbnail-image,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };

        src = nix-filter.lib.filter {
          root = ./.;

          include = [
            "crates"
            "Cargo.toml"
            "Cargo.lock"
          ];
        };

        yarnLockHash = "sha256-fgkXn/ffjDZ+l0jha6O1EYlM0Gc5JXOnbsdcu04y1eM=";
        testSrc = ./tests;

        teddybearPkgs = pkgs.callPackage ./nix/scope.nix {
          inherit crane fenix identity-context placeholder-image src testSrc thumbnail-image yarnLockHash;
        };
      in {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [teddybearPkgs.rustToolchain pkgs.nodejs pkgs.yarn pkgs.twiggy];
            inputsFrom = [teddybearPkgs.esm];
          };

          ci = pkgs.mkShell {
            buildInputs = [teddybearPkgs.rustToolchain pkgs.cargo-edit];
          };
        };

        packages = {
          inherit (teddybearPkgs) cjs esm docs;

          default = teddybearPkgs.uni;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = teddybearPkgs.repl;
        };

        checks = {
          inherit (teddybearPkgs) cjs esm uni docs e2e-test unit-test clippy fmt;
        };

        formatter = pkgs.alejandra;
      }
    );
}
