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
      ref = "v0.18.0";
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

        # https://webassembly.org/features
        # https://github.com/rust-lang/rust/blob/master/compiler/rustc_target/src/target_features.rs#L323-L337
        enabledWasmFeatures = [
          "bulk-memory"
          "mutable-globals"
          "nontrapping-fptoint"
          "sign-ext"
          "simd128"
        ];

        wasmArgs =
          commonArgs
          // {
            RUSTFLAGS = let
              fmt = pkgs.lib.concatMapStringsSep "," (f: "+${f}") enabledWasmFeatures;
            in "-C target-feature=${fmt}";

            CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
          };

        wasmCargoArtifacts = craneLib.buildDepsOnly (wasmArgs
          // {
            doCheck = false;

            cargoExtraArgs = "-p teddybear-js --locked";
          });

        mkPackage = buildForNode:
          pkgs.callPackage ./nix/package.nix {
            inherit
              buildForNode
              craneLib
              wasmArgs
              wasmCargoArtifacts
              wasm-pack
              ;
          };

        esm = mkPackage false;
        cjs = mkPackage true;

        uni = pkgs.callPackage ./nix/uni.nix {
          inherit cjs esm;
        };
      in {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [rustToolchain pkgs.nodejs pkgs.yarn];
            inputsFrom = [esm];
          };

          ci = pkgs.mkShell {
            buildInputs = [rustToolchain pkgs.cargo-edit];
          };
        };

        packages = {
          inherit cjs esm;

          default = uni;

          docs = pkgs.callPackage ./nix/docs.nix {
            src = uni;
          };
        };

        checks = {
          inherit cjs esm uni;

          e2e-test = pkgs.callPackage ./nix/node-testing.nix {
            inherit uni;

            src = nix-filter.lib.filter {
              root = ./tests;

              include = [
                "src"
                "package.json"
                "tsconfig.json"
                "yarn.lock"
              ];
            };

            yarnLockHash = "sha256-LTKJdshmknuSy2hC3SfYRBR5SfDamoMVH+aeC/aKwyA=";
          };

          unit-test = craneLib.cargoTest (nativeArgs
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
