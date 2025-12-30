{
  inputs,
  lib,
  newScope,
  openssl,
  pkg-config,
  rust-bin,
}:
lib.makeScope newScope (self: {
  commonArgs = {
    pname = "teddybear";

    src = inputs.nix-filter.lib.filter {
      root = ../.;

      include = [
        "crates"
        "Cargo.toml"
        "Cargo.lock"
      ];
    };

    strictDeps = true;
  };

  nativeArgs = self.commonArgs // {
    buildInputs = [ openssl ];

    nativeBuildInputs = [ pkg-config ];

    OPENSSL_NO_VENDOR = "true";
  };

  rustToolchain = rust-bin.stable.latest.default.override {
    targets = [ "wasm32-unknown-unknown" ];
  };

  craneLib = (inputs.crane.mkLib self).overrideToolchain self.rustToolchain;

  cargoArtifacts = self.craneLib.buildDepsOnly self.nativeArgs;

  esm = self.callPackage ./package.nix { buildForNode = false; };
  cjs = self.callPackage ./package.nix { buildForNode = true; };
  uni = self.callPackage ./uni.nix { };

  docs = self.callPackage ./docs.nix { };
  repl = self.callPackage ./repl.nix { };
  fmt = self.callPackage ./fmt.nix { };
  clippy = self.callPackage ./clippy.nix { };
  unit-test = self.callPackage ./unit-test.nix { };

  runner = self.callPackage ./e2e-testing/runner.nix { };
  e2e-test = self.callPackage ./e2e-testing/vm.nix { };
})
