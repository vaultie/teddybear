{
  deno,
  stdenvNoCC,
  src,
}:
stdenvNoCC.mkDerivation {
  inherit src;
  inherit (src) version;

  pname = "teddybear-docs";

  nativeBuildInputs = [deno];

  buildPhase = ''
    runHook preBuild

    deno doc \
      --html \
      --name="Teddybear" \
      $src/index.d.ts

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out

    # Current deno-doc version ships with a broken CSS on mobile devices
    substituteInPlace docs/styles.css \
      --replace-fail "@media not all and (min-width:1024px){.ddoc .toc .documentNavigation{display:none}}" ""

    cp -r docs/. $out

    runHook postInstall
  '';
}
