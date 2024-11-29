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
      RUSTFLAGS = let
        fmt = lib.concatMapStringsSep "," (f: "+${f}") self.enabledWasmFeatures;
      in "-C target-feature=${fmt}";

      CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
    };

  rustToolchain = with fenix.packages.${system};
    combine [
      stable.rustc
      stable.cargo
      stable.clippy
      stable.rustfmt

      targets.wasm32-unknown-unknown.stable.rust-std
    ];

  craneLib = (crane.mkLib self).overrideToolchain self.rustToolchain;

  cargoArtifacts = self.craneLib.buildDepsOnly self.nativeArgs;
  wasmCargoArtifacts = self.craneLib.buildDepsOnly (self.wasmArgs
    // {
      doCheck = false;

      cargoExtraArgs = "-p teddybear-js --locked";
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
