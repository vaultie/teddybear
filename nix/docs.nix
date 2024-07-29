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
    deno doc \
      --html \
      --output="$out" \
      --name="Teddybear" \
      $src/index.d.ts
  '';
}
