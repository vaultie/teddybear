{
  cjs,
  fetchYarnDeps,
  src,
  stdenvNoCC,
  nodejs,
  prefetch-yarn-deps,
  yarn,
  yarnLockHash,
}:
stdenvNoCC.mkDerivation {
  inherit src;
  inherit (cjs) version;

  pname = "teddybear-tests";

  offlineCache = fetchYarnDeps {
    yarnLock = "${src}/yarn.lock";
    hash = yarnLockHash;
  };

  nativeBuildInputs = [
    nodejs
    yarn
    prefetch-yarn-deps
  ];

  postPatch = ''
    export HOME=$(mktemp -d)

    yarn config --offline set yarn-offline-mirror $offlineCache

    fixup-yarn-lock yarn.lock

    # For easier test development, "teddybear-tests" package contains pre-installed
    # Teddybear from NPM. However, the NPM version obviously does not correspond to the
    # Teddybear version that is meant to be tested, so we dynamically replace it here.
    #
    # This will only work if Teddybear continues to not require any third-party dependencies.
    yarn remove @vaultie/teddybear-node
    yarn add file:${cjs}

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
