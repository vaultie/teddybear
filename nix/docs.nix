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
      --output="$out" \
      $src/index.d.ts

    runHook postBuild
  '';
}
