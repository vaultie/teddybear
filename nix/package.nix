{
  craneLib,
  lib,
  binaryen,
  wasmArgs,
  wasmCargoArtifacts,
  wabt,
  wasm-bindgen-cli,
  wasm-pack,
  buildForNode ? false,
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
        wabt
        wasm-bindgen-cli
        wasm-pack
      ];

      buildPhaseCargoCommand = ''
        HOME=$(mktemp -d)

        wasm-pack build \
          crates/teddybear-js \
          --out-dir build \
          --out-name index \
          --target ${target} \
          --release

        wasm-strip crates/teddybear-js/build/index_bg.wasm
      '';

      checkPhaseCargoCommand = ''
        wasm-validate crates/teddybear-js/build/index_bg.wasm
      '';

      doInstallCargoArtifacts = false;

      preInstall = ''
        substituteInPlace crates/teddybear-js/build/package.json \
          --replace-fail "teddybear-js" "@vaultie/teddybear${lib.optionalString buildForNode "-node"}"
      '';

      installPhaseCommand = ''
        mv crates/teddybear-js/build $out
      '';
    })
