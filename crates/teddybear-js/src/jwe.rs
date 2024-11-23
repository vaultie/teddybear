use js_sys::Uint8Array;
use serde::Serialize;
use teddybear_jwe::{A256Gcm, XC20P};
use wasm_bindgen::prelude::*;

use crate::{x25519::PublicX25519, OBJECT_SERIALIZER};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "JWERecipient")]
    pub type JweRecipient;

    #[wasm_bindgen(typescript_type = "JWE")]
    pub type Jwe;
}

/// Encrypt the provided payload for the provided recipient array using A256GCM algorithm.
///
/// @category JOSE
#[wasm_bindgen(js_name = "encryptAES")]
pub fn encrypt_aes(payload: Uint8Array, recipients: Vec<PublicX25519>) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<A256Gcm, _>(
        &payload.to_vec(),
        recipients
            .iter()
            .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

/// Encrypt the provided payload for the provided recipient array using XC20P algorithm.
///
/// @category JOSE
#[wasm_bindgen(js_name = "encryptChaCha20")]
pub fn encrypt_chacha20(
    payload: Uint8Array,
    recipients: Vec<PublicX25519>,
) -> Result<Jwe, JsError> {
    let jwe = teddybear_jwe::encrypt::<XC20P, _>(
        &payload.to_vec(),
        recipients
            .iter()
            .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}
