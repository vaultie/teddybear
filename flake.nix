{
  inputs = {
    nixpkgs = {
      type = "github";
      owner = "nixos";
      repo = "nixpkgs";
      ref = "nixos-unstable";
    };

    rust-overlay = {
      type = "github";
      owner = "oxalica";
      repo = "rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane = {
      type = "github";
      owner = "ipetkov";
      repo = "crane";
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
  };

  outputs =
    {
      nixpkgs,
      rust-overlay,
      flake-utils,
      ...
    }@inputs:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;

          overlays = [ rust-overlay.overlays.default ];
        };

        teddybearPkgs = pkgs.callPackage ./nix/scope.nix {
          inherit inputs;
        };
      in
      {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [
              teddybearPkgs.rustToolchain
              pkgs.yarn
              pkgs.nodejs-slim
              pkgs.openssl
              pkgs.pkg-config
            ];

            inputsFrom = [ teddybearPkgs.esm ];

            OPENSSL_NO_VENDOR = "1";
          };

          ci = pkgs.mkShell {
            buildInputs = [
              teddybearPkgs.rustToolchain
              pkgs.cargo-edit
            ];
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
          inherit (teddybearPkgs)
            cjs
            esm
            uni
            docs
            e2e-test
            unit-test
            clippy
            fmt
            ;
        };

        formatter = pkgs.nixfmt-tree;
      }
    );
}
