{
  cmake,
  fetchFromGitHub,
  lib,
  rustPlatform,
  wasm-pack,
}: let
  src = fetchFromGitHub {
    owner = "rustwasm";
    repo = "wasm-pack";
    rev = "62ab39cf82ec4d358c1f08f348cd0dc44768f412";
    hash = "sha256-tShJXrz9HHZVweNjMKi2JuatsORicWdkJzvQmFvFCrw=";
  };
in
  (wasm-pack.override {inherit rustPlatform;}).overrideAttrs (prev: {
    inherit src;

    version = "0.13.0";

    cargoDeps = prev.cargoDeps.overrideAttrs (lib.const {
      inherit src;

      name = "${prev.pname}-vendor.tar.gz";
      outputHash = "sha256-7qPtB1I71DKr58wBk04fSdxOTMdBEeP287XvNR7vjJs=";
    });
  })
