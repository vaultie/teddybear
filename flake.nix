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
            stable.toolchain
            targets.wasm32-unknown-unknown.stable.rust-std
          ];

        craneLib = crane.lib.${system}.overrideToolchain rustToolchain;

        wasm-pack = let
          src = pkgs.fetchFromGitHub {
            owner = "rustwasm";
            repo = "wasm-pack";
            rev = "77b8ced6bcaac42376d198c968b46f0d3bdbd359";
            hash = "sha256-djGVseo907/qLkY78nLfnbQeQ3q05AvZg0ALalFXE+M=";
          };
        in
          pkgs.wasm-pack.overrideAttrs (prev: {
            inherit src;

            cargoDeps = prev.cargoDeps.overrideAttrs (pkgs.lib.const {
              inherit src;

              name = "${prev.pname}-vendor.tar.gz";
              outputHash = "sha256-aQdehtSaNtz7BvvOX+XqqfNDbVVa6/1VEPkiPbcqmL4=";
            });
          });

        wasm-bindgen-cli = pkgs.wasm-bindgen-cli.override {
          version = "0.2.90";
          hash = "sha256-X8+DVX7dmKh7BgXqP7Fp0smhup5OO8eWEhn26ODYbkQ=";
          cargoHash = "sha256-ckJxAR20GuVGstzXzIj1M0WBFj5eJjrO2/DRMUK5dwM=";
        };

        commonArgs = {
          inherit src;

          pname = "teddybear";

          strictDeps = true;

          CARGO_NET_GIT_FETCH_WITH_CLI = "true";
          CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "wasm-ld";

          nativeBuildInputs = [
            wasm-pack
            wasm-bindgen-cli
            pkgs.binaryen
            pkgs.llvmPackages.lld
          ];
        };

        npmrc = pkgs.writeText "gh-registry" ''
          @vaultie:registry=https://npm.pkg.github.com
        '';

        package = craneLib.buildPackage (commonArgs
          // {
            cargoArtifacts = null;

            RUSTFLAGS = "-Ctarget-feature=+simd128";

            buildPhaseCargoCommand = ''
              HOME=$(mktemp -d)

              wasm-pack build \
                crates/teddybear-js \
                --out-dir build \
                --out-name index \
                --target bundler \
                --release
            '';

            doInstallCargoArtifacts = false;
            doCheck = false;

            preInstall = ''
              sed -i "s/teddybear-js/\@vaultie\/teddybear/g" \
                crates/teddybear-js/build/package.json
            '';

            installPhaseCommand = ''
              mv crates/teddybear-js/build $out
              cp ${npmrc} $out/.npmrc
            '';
          });
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [rustToolchain];
        };

        packages.default = package;

        formatter = pkgs.alejandra;
      }
    );
}
