{
  crane,
  fenix,
  identity-context,
  lib,
  makeRustPlatform,
  newScope,
  openssl,
  pkg-config,
  src,
  system,
  testSrc,
  yarnLockHash,
}:
lib.makeScope newScope (self: {
  # https://webassembly.org/features
  # https://github.com/rust-lang/rust/blob/a1d7676d6a8c6ff13f9165e98cc25eeec66cb592/compiler/rustc_target/src/target_features.rs#L520-L536
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

      buildInputs = [openssl];
      nativeBuildInputs = [pkg-config];

      OPENSSL_NO_VENDOR = "true";
    };

  wasmArgs =
    self.commonArgs
    // {
      # https://github.com/briansmith/ring/issues/2345
      stdenv = p: p.clangMultiStdenv;
      hardeningDisable = ["zerocallusedregs"];

      RUSTFLAGS = let
        fmt = lib.concatMapStringsSep "," (f: "+${f}") self.enabledWasmFeatures;
      in "-C target-feature=${fmt}";

      CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
    };

  fenix = fenix.packages.${system};
  rustToolchain = with self.fenix;
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
    inherit identity-context;

    mdoc-certificate = ./e2e-testing/mdoc.der;
  };

  wasm-snip = self.callPackage ./wasm-snip.nix {
    rustPlatform = makeRustPlatform {
      cargo = self.rustToolchain;
      rustc = self.rustToolchain;
    };
  };
})
