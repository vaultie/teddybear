{
  fetchFromGitHub,
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage rec {
  pname = "wasm-snip";
  version = "0.4.0";

  src = fetchFromGitHub {
    owner = "vaultie";
    repo = "wasm-snip";
    rev = "6fa20cac6751c1d66ce653f6b1a912f86980a30e";
    hash = "sha256-/VdtcpvrSodgu1RK+IQEabCxsRkWjurCcA5LEgxgZ/k=";
  };

  useFetchCargoVendor = true;
  cargoHash = "sha256-XdN3xK6BxFDg7Vb+EgEYY2bGCMW8J9oFns579pQyIb8=";

  # Tests require cargo-readme
  doCheck = false;
}
