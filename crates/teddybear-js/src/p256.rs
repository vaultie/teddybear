use std::str::FromStr;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use teddybear_crypto::{DIDBuf, DIDURLBuf, JwkVerificationMethod};
use teddybear_jwe::{A256Gcm, P256KeyPair, XC20P};
use teddybear_vc::ssi_verification_methods::EcdsaSecp256r1VerificationKey2019;
use wasm_bindgen::prelude::*;

use crate::{
    document::{DID, DIDURL},
    jwe::{Jwe, JweRecipient},
    jwk::JWK,
    OBJECT_SERIALIZER,
};

/// Private Secp256r1 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PrivateSecp256r1(pub(crate) teddybear_crypto::PrivateSecp256r1);

#[wasm_bindgen]
impl PrivateSecp256r1 {
    /// Create a new random keypair.
    pub fn generate() -> PrivateSecp256r1 {
        PrivateSecp256r1(teddybear_crypto::PrivateSecp256r1::generate())
    }

    /// Convert private key bytes into a public/private Secp256r1 keypair.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(value: Uint8Array) -> Result<PrivateSecp256r1, JsError> {
        let mut dst = [0; 32];
        value.copy_to(&mut dst);
        Ok(PrivateSecp256r1(
            teddybear_crypto::PrivateSecp256r1::from_bytes(&dst)?,
        ))
    }

    /// Get Secp256r1 private key bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Uint8Array {
        self.0.inner().to_bytes().as_slice().into()
    }

    /// Get the JWK value (without the private key) of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toPublicJWK")]
    pub fn to_public_jwk(&self) -> JWK {
        JWK(self.0.to_public_jwk())
    }

    /// Get the JWK value (with the private key) of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toPrivateJWK")]
    pub fn to_private_jwk(&self) -> JWK {
        JWK(self.0.to_private_jwk())
    }

    /// Get the did:key document DID value of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toDIDKey")]
    pub fn to_did_key(&self) -> DID {
        DID(self.0.to_did_key())
    }

    /// Get the did:key DID URL fragment value of the Secp256r1 key.
    #[wasm_bindgen(js_name = "toDIDKeyURLFragment")]
    pub fn to_did_key_url_fragment(&self) -> String {
        self.0.to_did_key_url_fragment().to_string()
    }

    /// Derive a Secp256r1 public key from the private key.
    #[wasm_bindgen(js_name = "toPublicKey")]
    pub fn to_public_key(&self, id: &DIDURL, controller: &DID) -> Result<PublicSecp256r1, JsError> {
        let verification_method = self
            .0
            .to_verification_method(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicSecp256r1(verification_method))
    }

    /// Decrypt the provided JWE object using the X25519 key and the A256GCM algorithm.
    #[wasm_bindgen(js_name = "decryptAES")]
    pub fn decrypt_aes(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
    ) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*teddybear_jwe::decrypt::<A256Gcm, P256KeyPair>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
        )?;
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
        let payload = &*teddybear_jwe::decrypt::<XC20P, P256KeyPair>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
        )?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "addAESRecipient")]
    pub fn add_aes_recipient(
        &self,
        verification_method: &DIDURL,
        jwe: Jwe,
        recipient: PublicSecp256r1,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<A256Gcm, P256KeyPair>(
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
        recipient: PublicSecp256r1,
    ) -> Result<JweRecipient, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let recipient = teddybear_jwe::add_recipient::<XC20P, P256KeyPair>(
            &jwe,
            &verification_method.0,
            self.0.inner(),
            recipient.0.id.as_str().to_owned(),
            recipient.0.public_key.decoded(),
        )?;
        Ok(recipient.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Public Secp256r1 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PublicSecp256r1(pub(crate) EcdsaSecp256r1VerificationKey2019);

#[wasm_bindgen]
impl PublicSecp256r1 {
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

    /// Get the JWK value (without the private key) of the Secp256r1 key within the current keypair.
    #[wasm_bindgen(js_name = "toJWK")]
    pub fn to_jwk(&self) -> JWK {
        JWK(self.0.to_jwk().into_owned())
    }

    /// Serialize the current public key as a verification method object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Encrypt the provided payload for the provided recipient array using A256GCM algorithm.
    #[wasm_bindgen(js_name = "encryptAES")]
    pub fn encrypt_aes(
        payload: Uint8Array,
        recipients: Vec<PublicSecp256r1>,
    ) -> Result<Jwe, JsError> {
        let jwe = teddybear_jwe::encrypt::<A256Gcm, P256KeyPair, _>(
            &payload.to_vec(),
            recipients
                .iter()
                .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
        )?;

        Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Encrypt the provided payload for the provided recipient array using XC20P algorithm.
    #[wasm_bindgen(js_name = "encryptChaCha20")]
    pub fn encrypt_chacha20(
        payload: Uint8Array,
        recipients: Vec<PublicSecp256r1>,
    ) -> Result<Jwe, JsError> {
        let jwe = teddybear_jwe::encrypt::<XC20P, P256KeyPair, _>(
            &payload.to_vec(),
            recipients
                .iter()
                .map(|val| (val.0.id.as_str().to_owned(), val.0.public_key.decoded())),
        )?;

        Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
    }
}
