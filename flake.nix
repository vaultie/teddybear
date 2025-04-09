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
  };

  outputs = {
    nixpkgs,
    crane,
    fenix,
    nix-filter,
    flake-utils,
    identity-context,
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

        yarnLockHash = "sha256-s7dop16Msfcqp+hd/8GDxlQEM7VNfvAPrYBwPoSHJUE=";
        testSrc = ./tests;

        teddybearPkgs = pkgs.callPackage ./nix/scope.nix {
          inherit crane fenix identity-context src testSrc yarnLockHash;
        };

        pkgConfigPath = pkgs.lib.makeSearchPathOutput "dev" "lib/pkgconfig" [
          pkgs.openssl
        ];
      in {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [teddybearPkgs.rustToolchain pkgs.pkg-config pkgs.openssl pkgs.nodejs pkgs.yarn pkgs.twiggy];
            inputsFrom = [teddybearPkgs.esm];
            OPENSSL_NO_VENDOR = "1";
            PKG_CONFIG_PATH = pkgConfigPath;
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
