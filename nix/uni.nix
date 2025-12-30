{
  cjs,
  esm,
  jq,
  moreutils,
  stdenvNoCC,
  wabt,
}:
stdenvNoCC.mkDerivation {
  inherit (esm) pname version;

  nativeBuildInputs = [
    jq
    moreutils
    wabt
  ];

  dontUnpack = true;

  buildPhase = ''
    runHook preBuild

    jq '.files = ["index_bg.js", "index_bg.wasm", "index.cjs", "index.mjs", "index.d.ts"]' \
      ${esm}/package.json > package.json

    jq '.main = "index.cjs"' package.json \
      | jq '.module = "index.mjs"' \
      | jq '.sideEffects = ["./index.cjs", "./index.mjs"]' \
      | sponge package.json

    # CJS
    cp ${cjs}/index.js index.cjs

    substituteInPlace index.cjs \
      --replace-fail "__wbindgen_placeholder__" "./index_bg.js"

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out

    # Generic
    cp ${esm}/index.d.ts $out
    cp ${esm}/index_bg.wasm $out
    cp package.json $out

    # CJS
    cp index.cjs $out

    # ESM
    cp ${esm}/index.js $out/index.mjs
    cp ${esm}/index_bg.js $out

    runHook postInstall
  '';

  doCheck = true;

  # Check that ESM and CJS WASM blobs are equivalent in everything
  # when ignoring "__wbindgen_placeholder__" and "./index_bg.js",
  # which are target-specific.
  checkPhase = ''
    runHook preCheck

    wasm2wat ${esm}/index_bg.wasm > esm.wat
    wasm2wat ${cjs}/index_bg.wasm > cjs.wat

    diff -b \
      -I "^.*__wbindgen_placeholder__.*$" \
      -I "^.*\.\/index_bg\.js.*$" \
      --suppress-common-lines \
      esm.wat cjs.wat

    runHook postCheck
  '';
}
