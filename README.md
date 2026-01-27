# Teddybear

![GHA Status](https://img.shields.io/github/actions/workflow/status/vaultie/teddybear/build.yaml)
[![NPM Version](https://img.shields.io/npm/v/%40vaultie%2Fteddybear)](https://www.npmjs.com/package/@vaultie/teddybear)
[![Documentation](https://img.shields.io/badge/documentation-blue)](https://vaultie.github.io/teddybear/index.html)

Verifiable credentials toolkit for JavaScript/TypeScript.

This library is tailored specifically for verification-only.

## Features

* W3C and C2PA verification API

* `did:key` and `did:web` support

* Revocation checks support

* Customizable hooks for fetching external data

## Installation

```sh
npm i @vaultie/teddybear
```

## Build from source

Ensure that you have Nix installed with flakes support enabled.

```sh
nix build
```

## License

You may choose either MIT license or Apache License, Version 2.0.
