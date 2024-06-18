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

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

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

          CARGO_NET_GIT_FETCH_WITH_CLI = "true";
        };

        nativeArgs =
          commonArgs
          // {
            cargoExtraArgs = "--all-features --locked";
          };

        cargoArtifacts = craneLib.buildDepsOnly nativeArgs;

        wasmArgs =
          commonArgs
          // {
            RUSTFLAGS = "-Ctarget-feature=+simd128";
            CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
          };

        wasmCargoArtifacts = craneLib.buildDepsOnly (wasmArgs
          // {
            doCheck = false;

            cargoExtraArgs = "-p teddybear-js --locked";
          });

        esm = pkgs.callPackage ./nix/package.nix {
          inherit craneLib wasmArgs wasmCargoArtifacts wasm-pack;
        };

        cjs = pkgs.callPackage ./nix/package.nix {
          inherit craneLib wasmArgs wasmCargoArtifacts wasm-pack;

          buildForNode = true;
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [rustToolchain pkgs.nodejs pkgs.yarn];
          inputsFrom = [esm];
        };

        packages = {
          inherit cjs esm;

          docs = craneLib.cargoDoc (nativeArgs
            // {
              inherit cargoArtifacts;

              RUSTDOCFLAGS = "-D warnings";
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

            yarnLockHash = "sha256-AE13eTQkwPvlMb4csouxjfwxbjSyDMkFwS5NQZjDG4M=";
          };

          test = craneLib.cargoTest (nativeArgs
            // {
              inherit cargoArtifacts;
            });

          clippy = craneLib.cargoClippy (nativeArgs
            // {
              inherit cargoArtifacts;

              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            });

          fmt = craneLib.cargoFmt commonArgs;
        };

        formatter = pkgs.alejandra;
      }
    );
}
