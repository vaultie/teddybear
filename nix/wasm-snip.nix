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

  cargoHash = "sha256-bHGngJ4mngsnhkvv4LE2f6t+lKIesLvoAwDgEKUGjJo=";

  # Tests require cargo-readme
  doCheck = false;
}
