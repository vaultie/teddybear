{
  buildForNode,
  # Deps
  binaryen,
  commonArgs,
  craneLib,
  lib,
  moreutils,
  wabt,
  wasm-bindgen-cli_0_2_100,
  wasm-pack,
}:
let
  target = if buildForNode then "nodejs" else "bundler";

  # https://webassembly.org/features
  # https://github.com/rust-lang/rust/blob/a1d7676d6a8c6ff13f9165e98cc25eeec66cb592/compiler/rustc_target/src/target_features.rs#L520-L536
  enabledWasmFeatures = [
    "bulk-memory"
    "extended-const"
    "multivalue"
    "mutable-globals"
    "nontrapping-fptoint"
    "reference-types"
    "sign-ext"
    "simd128"
  ];

  wasmArgs = commonArgs // {
    # https://github.com/briansmith/ring/issues/2345
    stdenv = p: p.clangMultiStdenv;
    hardeningDisable = [ "zerocallusedregs" ];

    cargoExtraArgs = "-p teddybear-js";

    RUSTFLAGS =
      let
        fmt = lib.concatMapStringsSep "," (f: "+${f}") enabledWasmFeatures;
      in
      "-C target-feature=${fmt}";

    CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
  };
in
craneLib.buildPackage (
  wasmArgs
  // {
    cargoArtifacts = craneLib.buildDepsOnly wasmArgs;

    nativeBuildInputs = [
      binaryen
      moreutils
      wabt
      wasm-bindgen-cli_0_2_100
      wasm-pack
    ];

    buildPhaseCargoCommand = ''
      HOME=$(mktemp -d)

      wasm-pack build \
        crates/teddybear-js \
        --mode force \
        --out-dir build \
        --out-name index \
        --target ${target} \
        --no-opt \
        --release

      wasm-opt -Oz \
        --output crates/teddybear-js/build/index_bg.wasm \
        --enable-bulk-memory \
        --enable-extended-const \
        --enable-multivalue \
        --enable-mutable-globals \
        --enable-nontrapping-float-to-int \
        --enable-reference-types \
        --enable-sign-ext \
        --enable-simd \
        --converge \
        --strip-debug \
        crates/teddybear-js/build/index_bg.wasm

      wasm-strip crates/teddybear-js/build/index_bg.wasm
    '';

    checkPhaseCargoCommand = ''
      wasm-validate crates/teddybear-js/build/index_bg.wasm \
        --enable-all
    '';

    doInstallCargoArtifacts = false;
    doNotPostBuildInstallCargoBinaries = true;

    preInstall = ''
      substituteInPlace crates/teddybear-js/build/package.json \
        --replace-fail "teddybear-js" "@vaultie/teddybear${lib.optionalString buildForNode "-node"}"

      # wasm-bindgen's custom TypeScript sections are merged into random d.ts file locations,
      # so to generate the module documentation we have to use a separate file and merge
      # it manually
      substituteInPlace crates/teddybear-js/build/index.d.ts \
        --replace-fail "/* tslint:disable */''\n/* eslint-disable */" ""
    '';

    installPhaseCommand = ''
      mv crates/teddybear-js/build $out
    '';
  }
)
