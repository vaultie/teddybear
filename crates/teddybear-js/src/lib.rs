#![allow(
    // This crate is not meant to be used in Rust at all,
    // so some Rust-specific lints are disabled.
    clippy::inherent_to_string,
    clippy::new_without_default,
    clippy::upper_case_acronyms,
)]

extern crate alloc;

mod c2pa;
mod document;
mod ed25519;
mod jwe;
mod jwk;
mod jws;
mod mdoc;
mod p256;
mod sd_jwt;
mod w3c;
mod x25519;

use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_SECTION: &'static str = r#"
/**
 * A single X25519 JWE recipient.
 *
 * @category JOSE
 */
export type JWERecipient = {
    header: {
        kid: string;
        alg: "ECDH-ES+A256KW";
        epk: {
            kty: "OKP";
            crv: "X25519";
            x: string;
        };
        apu: string;
        apv: string;
    };
    encrypted_key: string;
};

/**
 * JWE object.
 *
 * @category JOSE
 */
export type JWE = {
    protected: string;
    recipients: JWERecipient[];
    iv: string;
    ciphertext: string;
    tag: string;
};

/**
 * JWS signing options.
 *
 * @category JOSE
 */
export type JWSOptions = {
    embedSigningKey?: boolean;
    keyIdentifier?: string;
};
"#;
