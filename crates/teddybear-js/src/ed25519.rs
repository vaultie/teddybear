use std::str::FromStr;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use teddybear_crypto::{
    DIDBuf, DIDURLBuf, Ed25519VerificationKey2020, JwkVerificationMethod,
    SignOptions,
};
use wasm_bindgen::prelude::*;

use teddybear_vc::{
    issue_vc, present_vp,
    ssi_vc::v2::syntax::{JsonPresentation, SpecializedJsonCredential},
};

use crate::{
    document::{DID, DIDURL},
    jwk::JWK,
    jws::JwsOptions,
    w3c::ContextLoader,
    x25519::PrivateX25519,
    OBJECT_SERIALIZER,
};

/// Private Ed25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PrivateEd25519(pub(crate) teddybear_crypto::PrivateEd25519);

#[wasm_bindgen]
impl PrivateEd25519 {
    /// Create a new random keypair.
    pub fn generate() -> PrivateEd25519 {
        PrivateEd25519(teddybear_crypto::PrivateEd25519::generate())
    }

    /// Convert private key bytes into a public/private Ed25519 keypair.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(value: Uint8Array) -> PrivateEd25519 {
        let mut dst = [0; 32];
        value.copy_to(&mut dst);
        PrivateEd25519(teddybear_crypto::PrivateEd25519::from_bytes(&dst))
    }

    /// Convert private key PKCS#8 PEM value into a public/private Ed25519 keypair.
    #[wasm_bindgen(js_name = "fromPKCS8PEM")]
    pub fn from_pkcs8_pem(value: &str) -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(
            teddybear_crypto::PrivateEd25519::from_pkcs8_pem(value)?,
        ))
    }

    /// Get Ed25519 private key bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Uint8Array {
        self.0.inner().as_bytes().as_slice().into()
    }

    /// Convert Ed25519 private key to X25519 private key.
    #[wasm_bindgen(js_name = "toX25519PrivateKey")]
    pub fn to_x25519_private_key(&self) -> PrivateX25519 {
        PrivateX25519(self.0.to_x25519_private_key())
    }

    /// Get the JWK value (without the private key) of the Ed25519 key.
    #[wasm_bindgen(js_name = "toPublicJWK")]
    pub fn to_public_jwk(&self) -> JWK {
        JWK(self.0.to_public_jwk())
    }

    /// Get the JWK value (with the private key) of the Ed25519 key.
    #[wasm_bindgen(js_name = "toPrivateJWK")]
    pub fn to_private_jwk(&self) -> JWK {
        JWK(self.0.to_private_jwk())
    }

    /// Get the did:key document DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "toDIDKey")]
    pub fn to_did_key(&self) -> DID {
        DID(self.0.to_did_key())
    }

    /// Get the did:key DID URL fragment value of the Ed25519 key.
    #[wasm_bindgen(js_name = "toDIDKeyURLFragment")]
    pub fn to_did_key_url_fragment(&self) -> String {
        self.0.to_did_key_url_fragment().to_string()
    }

    /// Derive an Ed25519 public key from the private key.
    #[wasm_bindgen(js_name = "toPublicKey")]
    pub fn to_public_key(&self, id: &DIDURL, controller: &DID) -> Result<PublicEd25519, JsError> {
        let verification_method = self
            .0
            .to_verification_method(id.0.as_iri().to_owned(), controller.0.as_uri().to_owned());

        Ok(PublicEd25519(verification_method))
    }

    /// Sign the provided payload using the Ed25519 key.
    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str, options: Option<JwsOptions>) -> Result<String, JsError> {
        let options: SignOptions = options
            .map(Into::into)
            .map(serde_wasm_bindgen::from_value)
            .transpose()?
            .unwrap_or_default();

        Ok(self.0.sign(payload, options)?)
    }

    /// Create a new verifiable credential.
    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(
        &self,
        verification_method: &DIDURL,
        vc: Object,
        context_loader: &mut ContextLoader,
    ) -> Result<Object, JsError> {
        let credential: SpecializedJsonCredential = serde_wasm_bindgen::from_value(vc.into())?;

        Ok(issue_vc(
            self.0.inner().clone(),
            verification_method.0.as_iri().to_owned(),
            &credential,
            &mut context_loader.0,
        )
        .await?
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }

    /// Create a new verifiable presentation.
    #[wasm_bindgen(js_name = "presentVP")]
    pub async fn present_vp(
        &self,
        verification_method: &DIDURL,
        vp: Object,
        context_loader: &mut ContextLoader,
        domain: Option<String>,
        challenge: Option<String>,
    ) -> Result<Object, JsError> {
        let presentation: JsonPresentation<SpecializedJsonCredential> =
            serde_wasm_bindgen::from_value(vp.into())?;

        Ok(present_vp(
            self.0.inner().clone(),
            verification_method.0.as_iri().to_owned(),
            &presentation,
            domain,
            challenge,
            &mut context_loader.0,
        )
        .await?
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }
}

/// Public Ed25519 key.
///
/// @category Keys
#[wasm_bindgen]
pub struct PublicEd25519(pub(crate) Ed25519VerificationKey2020);

#[wasm_bindgen]
impl PublicEd25519 {
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

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
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
