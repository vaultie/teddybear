{
  fetchurl,
  fetchYarnDeps,
  fixup-yarn-lock,
  nodejs-slim,
  src,
  stdenvNoCC,
  yarn,
  yarnLockHash,
  uni,
}:
stdenvNoCC.mkDerivation {
  inherit src;
  inherit (uni) version;

  pname = "teddybear-tests";

  offlineCache = fetchYarnDeps {
    yarnLock = "${src}/yarn.lock";
    hash = yarnLockHash;
  };

  nativeBuildInputs = [
    nodejs-slim
    yarn
    fixup-yarn-lock
  ];

  placeholderImage = fetchurl {
    url = "https:/picsum.photos/id/0/200/300";
    hash = "sha256-tpipFiATKzL4Q7dtB+0wLygdDPoAp5bF6X095Xk++GI=";
  };

  thumbnailImage = fetchurl {
    url = "https:/picsum.photos/id/1/128/128";
    hash = "sha256-8KIDrMuw8PYGyMGSYvK6JF4t/MJhWhrwmyRgbY0Qre8=";
  };

  placeholderPdf = ./data/blank.pdf;

  certificate = ./data/crt.der;

  postPatch = ''
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
  '';

  buildPhase = ''
    yarn test
    touch $out
  '';
}
