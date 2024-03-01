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
      inputs.nixpkgs.follows = "nixpkgs";
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
  };

  outputs = {
    nixpkgs,
    crane,
    fenix,
    nix-filter,
    flake-utils,
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
            ./crates
            ./Cargo.toml
            ./Cargo.lock
          ];
        };

        rustToolchain = with fenix.packages.${system};
          combine [
            stable.rustc
            stable.cargo
            stable.clippy
            stable.rustfmt

            targets.wasm32-unknown-unknown.stable.rust-std
          ];

        craneLib = crane.lib.${system}.overrideToolchain rustToolchain;

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        wasm-pack = pkgs.callPackage ./nix/wasm-pack.nix {
          inherit rustPlatform;
        };

        commonArgs = {
          inherit src;

          pname = "teddybear";

          strictDeps = true;

          RUSTFLAGS = "-Ctarget-feature=+simd128";
          CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
          CARGO_NET_GIT_FETCH_WITH_CLI = "true";
        };

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs
          // {
            pname = "teddybear";

            doCheck = false;

            cargoExtraArgs = "-p teddybear-js";
          });

        esm = pkgs.callPackage ./nix/package.nix {
          inherit cargoArtifacts commonArgs craneLib wasm-pack;
        };

        cjs = pkgs.callPackage ./nix/package.nix {
          inherit cargoArtifacts commonArgs craneLib wasm-pack;

          buildForNode = true;
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [rustToolchain pkgs.nodejs pkgs.yarn];
          inputsFrom = [esm];
        };

        packages = {
          inherit cargoArtifacts cjs esm;

          docs = craneLib.cargoDoc (commonArgs
            // {
              inherit cargoArtifacts;

              # Fix incorrect doc directory location due to CARGO_BUILD_TARGET.
              preInstall = ''
                mv "target/''${CARGO_BUILD_TARGET}/doc" target/doc
              '';
            });
        };

        checks = {
          inherit cjs esm;

          node = pkgs.callPackage ./nix/node-testing.nix {
            inherit cjs;

            src = nix-filter.lib.filter {
              root = ./tests;

              include = [
                "src"
                "package.json"
                "tsconfig.json"
                "yarn.lock"
              ];
            };

            yarnLockHash = "sha256-F9NTbhs0zKi+A+eXFh3rpZrmicADy3c+rgxMaevDY4s=";
          };

          my-crate-clippy = craneLib.cargoClippy (commonArgs
            // {
              inherit cargoArtifacts;

              cargoClippyExtraArgs = "-- --deny warnings";
            });

          fmt = craneLib.cargoFmt (commonArgs
            // {
              inherit src;
            });
        };

        formatter = pkgs.alejandra;
      }
    );
}
