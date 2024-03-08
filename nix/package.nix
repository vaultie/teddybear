{
  craneLib,
  lib,
  binaryen,
  wasmArgs,
  wasmCargoArtifacts,
  wasm-bindgen-cli,
  wasm-pack,
  # FIXME: Unify two separate packages into one.
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
      '';

      doCheck = false;

      doInstallCargoArtifacts = false;

      preInstall = ''
        sed -i "s/teddybear-js/\@vaultie\/teddybear${lib.optionalString buildForNode "-node"}/g" \
          crates/teddybear-js/build/package.json
      '';

      installPhaseCommand = ''
        mv crates/teddybear-js/build $out
      '';
    })
