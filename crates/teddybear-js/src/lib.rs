extern crate alloc;

mod credential;

use credential::CredentialError;
use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use teddybear_crypto::{Ed25519, Private, Public, JWK};
use teddybear_jwe::decrypt;
use wasm_bindgen::prelude::*;
use wee_alloc::WeeAlloc;

use crate::credential::{issue_vc, issue_vp, verify_credential, verify_presentation, Level};

#[global_allocator]
static ALLOC: WeeAlloc = WeeAlloc::INIT;

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

/// A collection of errors gathered during the validation process.
#[wasm_bindgen]
pub struct ErrorBag(Vec<CredentialError>);

#[wasm_bindgen]
impl ErrorBag {
    /// Get human-readable details of all errors and warnings that occured during the validation process.
    pub fn details(&self) -> Vec<String> {
        self.0.iter().map(|error| error.to_string()).collect()
    }

    /// Check if no errors of warnings occured during the validation process.
    pub fn is_ok(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if the current error bag contains at least one critical error.
    pub fn is_error(&self) -> bool {
        self.0.iter().any(|error| error.level() == Level::Error)
    }
}

/// A public/private Ed25519/X25519 keypair.
#[wasm_bindgen]
pub struct PrivateEd25519(Ed25519<Private>);

#[wasm_bindgen]
impl PrivateEd25519 {
    /// Create a new random keypair.
    pub async fn generate() -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::generate().await?))
    }

    /// Convert an Ed25519 JWK value to a public/private keypair.
    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: WrappedJWK) -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::from_private_jwk(jwk.0).await?))
    }

    /// Get the JWK value (with the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PrivateJWK")]
    pub fn to_ed25519_private_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.as_ed25519_private_jwk().clone())
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_public_jwk())
    }

    /// Get the JWK value (with the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PrivateJWK")]
    pub fn to_x25519_private_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.as_x25519_private_jwk().clone())
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_x25519_public_jwk())
    }

    /// Get the document DID value.
    ///
    /// This value is usually used to idenfity an entity as a whole.
    ///
    /// If you want to refer to a specific key see `ed25519DID` and `x25519DID`
    /// methods instead.
    #[wasm_bindgen(js_name = "documentDID")]
    pub fn document_did(&self) -> String {
        self.0.document_did().to_string()
    }

    /// Get the DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    /// Get the DID value of the X25519 key.
    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }

    /// Decrypt the provided JWE object using the X25519 key.
    pub fn decrypt(&self, jwe: Object) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*decrypt(&jwe, self.0.as_x25519_private_jwk())?;
        Ok(payload.into())
    }

    /// Sign the provided payload using the Ed25519 key.
    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str) -> Result<String, JsError> {
        Ok(self.0.sign(payload)?)
    }

    /// Create a new verifiable credential.
    ///
    /// The `vc` object should contain all the necessary information except
    /// for the issuer and proof values, which will be filled automatically.
    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(&self, vc: Object) -> Result<Object, JsError> {
        let mut credential = serde_wasm_bindgen::from_value(vc.into())?;
        issue_vc(&self.0, &mut credential).await?;
        Ok(credential.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Create a new verifiable presentation.
    ///
    /// The `vp` object should contain all the necessary information except
    /// for the holder and proof values, which will be filled automatically.
    #[wasm_bindgen(js_name = "issueVP")]
    pub async fn issue_vp(&self, folio_id: &str, vp: Object) -> Result<Object, JsError> {
        let mut presentation = serde_wasm_bindgen::from_value(vp.into())?;
        issue_vp(&self.0, folio_id, &mut presentation).await?;
        Ok(presentation.serialize(&OBJECT_SERIALIZER)?.into())
    }

    /// Verify the provided verifiable presentation against the current keypair.
    ///
    /// See the `ErrorBag` documentation for more details on how to handle errors
    /// that may occur during the validation process.
    #[wasm_bindgen(js_name = "verifyPresentation")]
    pub async fn verify_presentation(&self, document: Object) -> Result<ErrorBag, JsError> {
        let presentation = serde_wasm_bindgen::from_value(document.into())?;
        Ok(ErrorBag(verify_presentation(&self.0, &presentation).await?))
    }
}

/// A public Ed25519/X25519 keypair.
#[wasm_bindgen]
pub struct PublicEd25519(Ed25519<Public>);

#[wasm_bindgen]
impl PublicEd25519 {
    /// Convert an Ed25519 JWK value to a public keypair.
    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: WrappedJWK) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_jwk(jwk.0).await?))
    }

    /// Convert a `did:key` document value to a public keypair.
    #[wasm_bindgen(js_name = "fromDID")]
    pub async fn from_did(did: &str) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_did(did).await?))
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_public_jwk())
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_x25519_public_jwk())
    }

    /// Get the document DID value.
    ///
    /// This value is usually used to idenfity an entity as a whole.
    ///
    /// If you want to refer to a specific key see `ed25519DID` and `x25519DID`
    /// methods instead.
    #[wasm_bindgen(js_name = "documentDID")]
    pub fn document_did(&self) -> String {
        self.0.document_did().to_string()
    }

    /// Get the DID value of the Ed25519 key.
    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    /// Get the DID value of the X25519 key.
    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }

    /// Verify the provided verifiable presentation against the current keypair.
    ///
    /// See the `ErrorBag` documentation for more details on how to handle errors
    /// that may occur during the validation process.
    #[wasm_bindgen(js_name = "verifyPresentation")]
    pub async fn verify_presentation(&self, document: Object) -> Result<ErrorBag, JsError> {
        let presentation = serde_wasm_bindgen::from_value(document.into())?;
        Ok(ErrorBag(verify_presentation(&self.0, &presentation).await?))
    }
}

/// Verify the provided verifiable credential.
///
/// See the `ErrorBag` documentation for more details on how to handle errors
/// that may occur during the validation process.
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(document: Object) -> Result<ErrorBag, JsError> {
    let credential = serde_wasm_bindgen::from_value(document.into())?;
    Ok(ErrorBag(verify_credential(&credential).await?))
}

/// Wrapped JWK value.
#[wasm_bindgen]
pub struct WrappedJWK(JWK);

#[wasm_bindgen]
impl WrappedJWK {
    /// Create a new wrapped JWK value from the provided JWK object.
    #[wasm_bindgen(js_name = "fromObject")]
    pub fn from_object(object: &Object) -> Result<WrappedJWK, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    /// Serialize the current wrapped JWK as an object.
    #[wasm_bindgen(js_name = "asObject")]
    pub fn as_object(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Encrypt the provided payload for the provided recipient array.
///
/// The provided recipients array must contain only wrapped X25519 JWK values.
///
/// You may acquire X25519 JWK values using the `toX25519PublicJWK` method on the keypair structs.
#[wasm_bindgen]
pub fn encrypt(payload: Uint8Array, recipients: Vec<WrappedJWK>) -> Result<Object, JsError> {
    let jwe = teddybear_jwe::encrypt(
        &payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}
