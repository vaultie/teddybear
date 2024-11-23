use js_sys::Object;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{ed25519::PublicEd25519, p256::PublicSecp256r1, OBJECT_SERIALIZER};

/// Wrapped JWK value.
///
/// @category JOSE
#[wasm_bindgen]
pub struct JWK(pub(crate) teddybear_crypto::JWK);

#[wasm_bindgen]
impl JWK {
    /// Create a new wrapped JWK value from the provided JWK object.
    #[wasm_bindgen(constructor)]
    pub fn new(object: &Object) -> Result<JWK, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    /// Try to convert the current wrapped JWK to a dynamic verification method.
    #[wasm_bindgen(js_name = "toDynamicVerificationMethod")]
    pub fn to_dynamic_verification_method(&self) -> Result<DynamicVerificationMethod, JsError> {
        Ok(DynamicVerificationMethod(
            teddybear_crypto::jwk_to_verification_method(&self.0)?,
        ))
    }

    /// Serialize the current wrapped JWK as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Dynamic verification method acquired from a JWK.
///
/// @category JOSE
#[wasm_bindgen]
pub struct DynamicVerificationMethod(teddybear_crypto::DynamicVerificationMethod);

#[wasm_bindgen]
impl DynamicVerificationMethod {
    /// Get the Ed25519 verification method.
    pub fn ed25519(&self) -> Option<PublicEd25519> {
        match &self.0 {
            teddybear_crypto::DynamicVerificationMethod::Ed25519VerificationKey2020(key) => {
                Some(PublicEd25519(key.clone()))
            }
            _ => None,
        }
    }

    /// Get the Secp256r1 verification method.
    pub fn secp256r1(&self) -> Option<PublicSecp256r1> {
        match &self.0 {
            teddybear_crypto::DynamicVerificationMethod::EcdsaSecp256r1VerificationKey2019(key) => {
                Some(PublicSecp256r1(key.clone()))
            }
            _ => None,
        }
    }
}
