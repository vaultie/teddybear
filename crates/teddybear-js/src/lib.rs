extern crate alloc;

mod credential;

use credential::CredentialError;
use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use teddybear_crypto::{Ed25519, Private, Public, JWK};
use teddybear_jwe::decrypt;
use wasm_bindgen::prelude::*;

use crate::credential::{issue_vc, issue_vp, verify_credential, verify_presentation, Level};

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

#[wasm_bindgen]
pub struct ErrorBag(Vec<CredentialError>);

#[wasm_bindgen]
impl ErrorBag {
    pub fn errors(&self) -> Vec<String> {
        self.0.iter().map(|error| error.to_string()).collect()
    }

    pub fn is_ok(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_warning(&self) -> bool {
        !self.0.iter().any(|error| error.level() == Level::Error)
    }
}

#[wasm_bindgen]
pub struct PrivateEd25519(Ed25519<Private>);

#[wasm_bindgen]
impl PrivateEd25519 {
    pub async fn generate() -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::generate().await?))
    }

    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: WrappedJWK) -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::from_private_jwk(jwk.0).await?))
    }

    #[wasm_bindgen(js_name = "toEd25519PrivateJWK")]
    pub fn to_ed25519_private_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.as_ed25519_private_jwk().clone())
    }

    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_public_jwk())
    }

    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_x25519_public_jwk())
    }

    #[wasm_bindgen(js_name = "documentDID")]
    pub fn document_did(&self) -> String {
        self.0.document_did().to_string()
    }

    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }

    pub fn decrypt(&self, jwe: Object) -> Result<Uint8Array, JsError> {
        let jwe = serde_wasm_bindgen::from_value(jwe.into())?;
        let payload = &*decrypt(&jwe, self.0.as_x25519_private_jwk())?;
        Ok(payload.into())
    }

    #[wasm_bindgen(js_name = "signJWS")]
    pub fn sign_jws(&self, payload: &str) -> Result<String, JsError> {
        Ok(self.0.sign(payload)?)
    }

    #[wasm_bindgen(js_name = "issueVC")]
    pub async fn issue_vc(&self, vc: Object) -> Result<Object, JsError> {
        let mut credential = serde_wasm_bindgen::from_value(vc.into())?;
        issue_vc(&self.0, &mut credential).await;
        Ok(credential.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "issueVP")]
    pub async fn issue_vp(&self, folio_id: &str, vp: Object) -> Result<Object, JsError> {
        let mut presentation = serde_wasm_bindgen::from_value(vp.into())?;
        issue_vp(&self.0, folio_id, &mut presentation).await;
        Ok(presentation.serialize(&OBJECT_SERIALIZER)?.into())
    }

    #[wasm_bindgen(js_name = "verifyPresentation")]
    pub async fn verify_presentation(&self, document: Object) -> Result<ErrorBag, JsError> {
        let presentation = serde_wasm_bindgen::from_value(document.into())?;
        Ok(ErrorBag(verify_presentation(&self.0, &presentation).await?))
    }
}

#[wasm_bindgen]
pub struct PublicEd25519(Ed25519<Public>);

#[wasm_bindgen]
impl PublicEd25519 {
    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: WrappedJWK) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_jwk(jwk.0).await?))
    }

    #[wasm_bindgen(js_name = "fromDID")]
    pub async fn from_did(did: &str) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_did(did).await?))
    }

    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_ed25519_public_jwk())
    }

    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> WrappedJWK {
        WrappedJWK(self.0.to_x25519_public_jwk())
    }

    #[wasm_bindgen(js_name = "documentDID")]
    pub fn document_did(&self) -> String {
        self.0.document_did().to_string()
    }

    #[wasm_bindgen(js_name = "ed25519DID")]
    pub fn ed25519_did(&self) -> String {
        self.0.ed25519_did().to_string()
    }

    #[wasm_bindgen(js_name = "x25519DID")]
    pub fn x25519_did(&self) -> String {
        self.0.x25519_did().to_string()
    }

    #[wasm_bindgen(js_name = "verifyPresentation")]
    pub async fn verify_presentation(&self, document: Object) -> Result<ErrorBag, JsError> {
        let presentation = serde_wasm_bindgen::from_value(document.into())?;
        Ok(ErrorBag(verify_presentation(&self.0, &presentation).await?))
    }
}

#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(document: Object) -> Result<ErrorBag, JsError> {
    let credential = serde_wasm_bindgen::from_value(document.into())?;
    Ok(ErrorBag(verify_credential(&credential).await?))
}

#[wasm_bindgen]
pub struct WrappedJWK(JWK);

#[wasm_bindgen]
impl WrappedJWK {
    #[wasm_bindgen(js_name = "fromObject")]
    pub fn from_object(object: &Object) -> Result<WrappedJWK, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    #[wasm_bindgen(js_name = "asObject")]
    pub fn as_object(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

#[wasm_bindgen]
pub fn encrypt(payload: Uint8Array, recipients: Vec<WrappedJWK>) -> Result<Object, JsError> {
    let jwe = teddybear_jwe::encrypt(
        &payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}
