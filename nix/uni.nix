{
  cjs,
  esm,
  jq,
  moreutils,
  stdenvNoCC,
}:
stdenvNoCC.mkDerivation {
  inherit (esm) pname version;

  nativeBuildInputs = [jq moreutils];

  dontUnpack = true;

  buildPhase = ''
    runHook preBuild

    jq '.files = ["index_bg.js", "index_bg.wasm", "index.cjs", "index.mjs", "index.d.ts"]' \
      ${esm}/package.json \
      > package.json

    jq '.main = "index.cjs"' package.json | sponge package.json
    jq '.module = "index.mjs"' package.json | sponge package.json
    jq '.sideEffects = ["./index.js", "./snippets/*"]' package.json | sponge package.json

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
}
