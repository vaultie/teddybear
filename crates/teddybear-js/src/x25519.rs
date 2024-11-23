use std::str::FromStr;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use teddybear_crypto::{DIDBuf, DIDURLBuf, JwkVerificationMethod, X25519KeyAgreementKey2020};
use teddybear_jwe::{A256Gcm, XC20P};
use wasm_bindgen::prelude::*;

use crate::{
    document::{DID, DIDURL},
    jwe::{Jwe, JweRecipient},
    jwk::JWK,
    OBJECT_SERIALIZER,
};

/// Private X25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PrivateX25519(pub(crate) teddybear_crypto::PrivateX25519);

#[wasm_bindgen]
impl PrivateX25519 {
    /// Get the JWK value (without the private key) of the X25519 key.
    #[wasm_bindgen(js_name = "toPublicJWK")]
    pub fn to_public_jwk(&self) -> JWK {
        JWK(self.0.to_public_jwk())
    }

    /// Get the JWK value (with the private key) of the X25519 key.
    #[wasm_bindgen(js_name = "toPrivateJWK")]
    pub fn to_private_jwk(&self) -> JWK {
        JWK(self.0.to_private_jwk())
    }

    /// Get the did:key DID URL fragment value of the X25519 key.
    #[wasm_bindgen(js_name = "toDIDKeyURLFragment")]
    pub fn to_did_key_url_fragment(&self) -> String {
        self.0.to_did_key_url_fragment().to_string()
    }

    /// Derive an X25519 public key from the private key.
    #[wasm_bindgen(js_name = "toPublicKey")]
    pub fn to_public_key(&self, id: &DIDURL, controller: &DID) -> Result<PublicX25519, JsError> {
        let verification_method = self
            .0
            .to_verification_method(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicX25519(verification_method))
    }

    /// Decrypt the provided JWE object using the X25519 key and the A256GCM algorithm.
    #[wasm_bindgen(js_name = "decryptAES")]
    pub fn decrypt_aes(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload =
            &*teddybear_jwe::decrypt::<A256Gcm>(&jwe, &verification_method.0, self.0.inner())?;
        Ok(payload.into())
    }

    /// Decrypt the provided JWE object using the X25519 key and the XC20P algorithm.
    #[wasm_bindgen(js_name = "decryptChaCha20")]
    pub fn decrypt_chacha20(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload =
            &*teddybear_jwe::decrypt::<XC20P>(&jwe, &verification_method.0, self.0.inner())?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
        recipient: PublicX25519,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<A256Gcm>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
            recipient.0.id.as_str().to_owned(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "addChaCha20Recipient")]
    pub fn add_chacha20_recipient(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
        recipient: PublicX25519,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<XC20P>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
            recipient.0.id.as_str().to_owned(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Public X25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PublicX25519(pub(crate) X25519KeyAgreementKey2020);

#[wasm_bindgen]
impl PublicX25519 {
    /// Get the verification method identifier.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Result<DIDURL, JsError> {
        // FIXME: Remove the unnecessary double-conversion
        Ok(DIDURL(DIDURLBuf::from_str(&self.0.id)?))
    }

    /// Get the verification method controller.
    #[wasm_bindgen(getter)]
    pub fn controller(&self) -> Result<DID, JsError> {
        // FIXME: Remove the unnecessary double-conversion
        Ok(DID(DIDBuf::from_str(&self.0.controller)?))
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }

    /// Serialize the current public key as a verification method object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}
