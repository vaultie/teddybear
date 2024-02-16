{
  fetchFromGitHub,
  lib,
  rustPlatform,
  wasm-pack,
}: let
  src = fetchFromGitHub {
    owner = "rustwasm";
    repo = "wasm-pack";
    rev = "77b8ced6bcaac42376d198c968b46f0d3bdbd359";
    hash = "sha256-djGVseo907/qLkY78nLfnbQeQ3q05AvZg0ALalFXE+M=";
  };
in
  (wasm-pack.override {inherit rustPlatform;}).overrideAttrs (prev: {
    inherit src;

    cargoDeps = prev.cargoDeps.overrideAttrs (lib.const {
      inherit src;

      name = "${prev.pname}-vendor.tar.gz";
      outputHash = "sha256-aQdehtSaNtz7BvvOX+XqqfNDbVVa6/1VEPkiPbcqmL4=";
    });
  })
