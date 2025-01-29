{
  crane,
  fenix,
  identity-context,
  lib,
  makeRustPlatform,
  newScope,
  placeholder-image,
  src,
  system,
  testSrc,
  thumbnail-image,
  yarnLockHash,
}:
lib.makeScope newScope (self: {
  # https://webassembly.org/features
  # https://github.com/rust-lang/rust/blob/a1d7676d6a8c6ff13f9165e98cc25eeec66cb592/compiler/rustc_target/src/target_features.rs#L520-L536
  wasmFeatures = [
    "+bulk-memory"
    "+multivalue"
    "+mutable-globals"
    "+nontrapping-fptoint"
    "+sign-ext"
    "+simd128"
    "-reference-types"
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

  commonArgs = {
    inherit src;

    pname = "teddybear";

    strictDeps = true;

    CARGO_NET_GIT_FETCH_WITH_CLI = "true";
  };

  nativeArgs =
    self.commonArgs
    // {
      cargoExtraArgs = "--all-features --locked";
    };

  wasmArgs =
    self.commonArgs
    // {
      cargoVendorDir = self.craneLib.vendorMultipleCargoDeps {
        inherit (self.craneLib.findCargoFiles src) cargoConfigs;

        cargoLockList = [
          "${src}/Cargo.lock"
          "${self.fenix.complete.rust-src}/lib/rustlib/src/rust/library/Cargo.lock"
        ];
      };

      RUSTFLAGS = "-Ctarget-cpu=mvp -C target-feature=${lib.concatStringsSep "," self.wasmFeatures}";
      CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
    };

  fenix = fenix.packages.${system};
  rustToolchain = with self.fenix;
    combine [
      complete.rustc
      complete.cargo
      complete.clippy
      complete.rustfmt
      complete.rust-src
    ];

  craneLib = (crane.mkLib self).overrideToolchain self.rustToolchain;

  cargoArtifacts = self.craneLib.buildDepsOnly self.nativeArgs;

  wasmCargoArtifacts = self.craneLib.buildDepsOnly (self.wasmArgs
    // {
      doCheck = false;
      cargoExtraArgs = "-Z build-std=std,panic_abort -p teddybear-js --locked";
    });

  esm = self.callPackage ./package.nix {buildForNode = false;};
  cjs = self.callPackage ./package.nix {buildForNode = true;};
  uni = self.callPackage ./uni.nix {};
  docs = self.callPackage ./docs.nix {};

  repl = self.callPackage ./repl.nix {};

  clippy = self.callPackage ./clippy.nix {};
  unit-test = self.callPackage ./unit-test.nix {};
  fmt = self.craneLib.cargoFmt self.commonArgs;

  runner = self.callPackage ./e2e-testing/runner.nix {
    inherit testSrc yarnLockHash;
  };

  e2e-test = self.callPackage ./e2e-testing/vm.nix {
    inherit identity-context placeholder-image thumbnail-image;

    certificate = ./e2e-testing/crt.der;
    mdoc-certificate = ./e2e-testing/mdoc.der;
    placeholder-pdf = ./e2e-testing/blank.pdf;
  };

  wasm-snip = self.callPackage ./wasm-snip.nix {
    rustPlatform = makeRustPlatform {
      cargo = self.rustToolchain;
      rustc = self.rustToolchain;
    };
  };
})
