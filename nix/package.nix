{
  binaryen,
  buildForNode,
  craneLib,
  lib,
  moreutils,
  wabt,
  wasmArgs,
  wasmCargoArtifacts,
  wasmSnipPatterns,
  wasm-bindgen-cli,
  wasm-pack,
  wasm-snip
}: let
  target =
    if buildForNode
    then "nodejs"
    else "bundler";
in
  craneLib.buildPackage (wasmArgs
    // {
      cargoArtifacts = wasmCargoArtifacts;

      nativeBuildInputs = [
        binaryen
        moreutils
        wabt
        wasm-bindgen-cli
        wasm-pack
        wasm-snip
      ];

      buildPhaseCargoCommand = ''
        HOME=$(mktemp -d)

        wasm-pack build \
          crates/teddybear-js \
          --out-dir build \
          --out-name index \
          --target ${target} \
          --no-opt \
          --release

        ${lib.optionalString (wasmSnipPatterns != []) ''
          wasm-snip crates/teddybear-js/build/index_bg.wasm \
            --output crates/teddybear-js/build/index_bg.wasm \
            ${lib.concatMapStringsSep " " (p: "-p ${lib.escapeShellArg p}") wasmSnipPatterns}
        ''}

        wasm-opt -Oz \
          --output crates/teddybear-js/build/index_bg.wasm \
          --enable-bulk-memory \
          --enable-mutable-globals \
          --enable-nontrapping-float-to-int \
          --enable-sign-ext \
          --enable-simd \
          --converge \
          --strip-debug \
          crates/teddybear-js/build/index_bg.wasm

        wasm-strip crates/teddybear-js/build/index_bg.wasm
      '';

      checkPhaseCargoCommand = ''
        wasm-validate crates/teddybear-js/build/index_bg.wasm
      '';

      doInstallCargoArtifacts = false;

      preInstall = ''
        substituteInPlace crates/teddybear-js/build/package.json \
          --replace-fail "teddybear-js" "@vaultie/teddybear${lib.optionalString buildForNode "-node"}"

        # wasm-bindgen's custom TypeScript sections are merged into random d.ts file locations,
        # so to generate the module documentation we have to use a separate file and merge
        # it manually
        substituteInPlace crates/teddybear-js/build/index.d.ts \
          --replace-fail "/* tslint:disable */''\n/* eslint-disable */" ""

        cat crates/teddybear-js/module.d.ts crates/teddybear-js/build/index.d.ts \
          | sponge crates/teddybear-js/build/index.d.ts
      '';

      installPhaseCommand = ''
        mv crates/teddybear-js/build $out
      '';
    })
