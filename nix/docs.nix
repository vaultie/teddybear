{
  deno,
  stdenvNoCC,
  uni,
}:
stdenvNoCC.mkDerivation {
  inherit (uni) version;

  pname = "teddybear-docs";

  src = uni;

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
