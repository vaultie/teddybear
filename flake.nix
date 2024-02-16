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
          CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "wasm-ld";

          nativeBuildInputs = [
            wasm-pack
            pkgs.wasm-bindgen-cli
            pkgs.binaryen
            pkgs.llvmPackages.lld

            # Testing
            pkgs.nodejs-slim
          ];
        };

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs
          // {
            pname = "teddybear";

            doCheck = false;

            cargoExtraArgs = "-p teddybear-js";
          });

        esm = pkgs.callPackage ./nix/package.nix {
          inherit cargoArtifacts commonArgs craneLib;
        };

        cjs = pkgs.callPackage ./nix/package.nix {
          inherit cargoArtifacts commonArgs craneLib;

          buildForNode = true;
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [rustToolchain];
        };

        packages = {
          inherit cargoArtifacts cjs esm;
        };

        checks = {
          inherit cjs esm;

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
