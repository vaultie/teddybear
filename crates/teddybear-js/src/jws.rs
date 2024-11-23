use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::jwk::JWK;

/// JWS verification result.
///
/// @category JOSE
#[wasm_bindgen(js_name = "JWSVerificationResult")]
pub struct JwsVerificationResult(Option<teddybear_crypto::JWK>, Option<String>, Uint8Array);

#[wasm_bindgen(js_class = "JWSVerificationResult")]
impl JwsVerificationResult {
    /// Embedded JWK key.
    ///
    /// Corresponds to the `jwk` field within the JWS header.
    ///
    /// [`None`] if the JWS signing process had been completed without embedding the JWK value.
    #[wasm_bindgen(getter)]
    pub fn jwk(&self) -> Option<JWK> {
        self.0.clone().map(JWK)
    }

    /// Key identifier.
    ///
    /// [`None`] if the JWS signing process had been completed without embedding the key identifier.
    #[wasm_bindgen(getter, js_name = "keyID")]
    pub fn key_id(&self) -> Option<String> {
        self.1.clone()
    }

    /// JWS payload.
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        self.2.clone()
    }
}

/// Verify JWS signature against the embedded JWK key.
///
/// Returns both the signed payload and the embedded JWK key used to sign the payload.
///
/// @category JOSE
#[wasm_bindgen(js_name = "verifyJWS")]
pub fn verify_jws(jws: &str, key: Option<JWK>) -> Result<JwsVerificationResult, JsError> {
    let (jwk, key_id, payload) = if let Some(key) = key {
        let (key_id, payload) = teddybear_crypto::verify_jws(jws, &key.0)?;
        (None, key_id, payload)
    } else {
        let (jwk, key_id, payload) = teddybear_crypto::verify_jws_with_embedded_jwk(jws)?;
        (Some(jwk), key_id, payload)
    };

    Ok(JwsVerificationResult(
        jwk,
        key_id,
        payload.as_slice().into(),
    ))
}
