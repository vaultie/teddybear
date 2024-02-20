# Teddybear

Verifiable credentials toolkit for JS-based platforms and Rust.

## Features

* Ed25519/X25519 key generation, import/export
* `did:key` DID resolver
* JWE encryption/decryption
* Bitstring-based status lists
* Browser/Node wrapper based on WebAssembly

## Installation

### Browser

```sh
yarn add @vaultie/teddybear
```

### Node

```sh
yarn add @vaultie/teddybear-node
```

## Build from source

Ensure that you have Nix installed with flakes support enabled.

### ESM version

```sh
nix build .#esm
```

### CommonJS version

```sh
nix build .#cjs
```

## License

You may choose either MIT license or Apache License, Version 2.0.
