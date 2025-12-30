{
  fetchYarnDeps,
  fixup-yarn-lock,
  lib,
  makeWrapper,
  nodejs-slim,
  stdenvNoCC,
  yarn,
  uni,
}:
stdenvNoCC.mkDerivation (finalAttrs: {
  inherit (uni) version;

  pname = "teddybear-tests";

  src = ../../tests;

  offlineCache = fetchYarnDeps {
    yarnLock = "${finalAttrs.src}/yarn.lock";
    hash = "sha256-FFe4q1xjo5SqmtBg3YCX1jeE9HavwUDJAqNdaEhag5A=";
  };

  nativeBuildInputs = [
    nodejs-slim
    yarn
    fixup-yarn-lock
    makeWrapper
  ];

  buildPhase = ''
    runHook preBuild

    export HOME=$(mktemp -d)

    yarn config --offline set yarn-offline-mirror $offlineCache

    fixup-yarn-lock yarn.lock

    # For easier test development, "teddybear-tests" package contains pre-installed
    # Teddybear from NPM. However, the NPM version obviously does not correspond to the
    # Teddybear version that is meant to be tested, so we dynamically replace it here.
    #
    # This will only work if Teddybear continues to not require any third-party dependencies.
    yarn remove @vaultie/teddybear
    yarn add file:${uni}

    yarn install \
      --offline \
      --ignore-scripts \
      --no-progress \
      --non-interactive

    patchShebangs node_modules/

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir $out

    cp -R $src/. $out/

    makeWrapper ${lib.getExe yarn} "$out/bin/test" \
      --chdir $out \
      --add-flags "test --no-cache"

    mv node_modules $out

    runHook postInstall
  '';

  meta.mainProgram = "test";
})
