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

        wasm-snip = pkgs.callPackage ./nix/wasm-snip.nix {
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

        # Potentially, some unused code may be introduced into the resulting WASM blob,
        # unnecessarily increasing its size. Using `wasm-snip` it's possible to replace
        # function bodies with a trap opcode, optimizing out both the function itself
        # and its callers.
        wasmSnipPatterns = [
          ".*bmff_io.*"
          ".*gif_io.*"
          ".*svg_io.*"
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
              wasmSnipPatterns
              wasm-pack
              wasm-snip
              ;
          };

        esm = mkPackage false;
        cjs = mkPackage true;

        uni = pkgs.callPackage ./nix/uni.nix {
          inherit cjs esm;
        };

        docs = pkgs.callPackage ./nix/docs.nix {
          src = uni;
        };
      in {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [rustToolchain pkgs.nodejs pkgs.yarn pkgs.twiggy];
            inputsFrom = [esm];
          };

          ci = pkgs.mkShell {
            buildInputs = [rustToolchain pkgs.cargo-edit];
          };
        };

        packages = {
          inherit cjs esm docs;

          default = uni;
        };

        checks = {
          inherit cjs esm uni docs;

          e2e-test = pkgs.callPackage ./nix/e2e-testing/vm.nix {
            inherit identity-context placeholder-image thumbnail-image;

            certificate = ./nix/e2e-testing/crt.der;
            placeholder-pdf = ./nix/e2e-testing/blank.pdf;

            runner = pkgs.callPackage ./nix/e2e-testing/runner.nix {
              inherit uni;

              src = ./tests;
              yarnLockHash = "sha256-Om6VzFh/qKP7rYs0ihW66sq7fOv0oqA956wpIMDavg8=";
            };
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
