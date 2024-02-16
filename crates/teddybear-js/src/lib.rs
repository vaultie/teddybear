extern crate alloc;

use js_sys::{Object, Uint8Array};
use serde::Serialize;
use serde_json::json;
use serde_wasm_bindgen::Serializer;
use teddybear_crypto::{Ed25519, Private, Public, JWK as InnerJWK};
use teddybear_jwe::decrypt;
use teddybear_status_list::{
    credential::{BitstringStatusListCredentialSubject, StatusPurpose},
    StatusList,
};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wee_alloc::WeeAlloc;

use teddybear_vc::{
    issue_vc, issue_vp,
    validation::{
        Constraint as InnerConstraint, PresentationDefinition as InnerPresentationDefinition,
    },
    verify_credential, verify_presentation,
};

#[global_allocator]
static ALLOC: WeeAlloc = WeeAlloc::INIT;

const OBJECT_SERIALIZER: Serializer = Serializer::new().serialize_maps_as_objects(true);

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
    pub async fn from_jwk(jwk: JWK) -> Result<PrivateEd25519, JsError> {
        Ok(PrivateEd25519(Ed25519::from_private_jwk(jwk.0).await?))
    }

    /// Get the JWK value (with the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PrivateJWK")]
    pub fn to_ed25519_private_jwk(&self) -> JWK {
        JWK(self.0.as_ed25519_private_jwk().clone())
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_ed25519_public_jwk())
    }

    /// Get the JWK value (with the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PrivateJWK")]
    pub fn to_x25519_private_jwk(&self) -> JWK {
        JWK(self.0.as_x25519_private_jwk().clone())
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_x25519_public_jwk())
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
        issue_vp(
            &self.0,
            folio_id,
            Some(Uuid::new_v4().to_string()),
            &mut presentation,
        )
        .await?;
        Ok(presentation.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// A public Ed25519/X25519 keypair.
#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicEd25519(Ed25519<Public>);

#[wasm_bindgen]
impl PublicEd25519 {
    /// Convert an Ed25519 JWK value to a public keypair.
    #[wasm_bindgen(js_name = "fromJWK")]
    pub async fn from_jwk(jwk: JWK) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_jwk(jwk.0).await?))
    }

    /// Convert a `did:key` document value to a public keypair.
    #[wasm_bindgen(js_name = "fromDID")]
    pub async fn from_did(did: &str) -> Result<PublicEd25519, JsError> {
        Ok(PublicEd25519(Ed25519::from_did(did).await?))
    }

    /// Get the JWK value (without the private key) of the Ed25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toEd25519PublicJWK")]
    pub fn to_ed25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_ed25519_public_jwk())
    }

    /// Get the JWK value (without the private key) of the X25519 key within the current keypair.
    #[wasm_bindgen(js_name = "toX25519PublicJWK")]
    pub fn to_x25519_public_jwk(&self) -> JWK {
        JWK(self.0.to_x25519_public_jwk())
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
}

/// Verify the provided verifiable credential.
///
/// See the `ErrorBag` documentation for more details on how to handle errors
/// that may occur during the validation process.
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(document: Object) -> Result<(), JsError> {
    let credential = serde_wasm_bindgen::from_value(document.into())?;
    Ok(verify_credential(&credential).await?)
}

#[wasm_bindgen]
pub struct PresentationVerificationResult {
    key: PublicEd25519,
    challenge: Option<String>,
}

#[wasm_bindgen]
impl PresentationVerificationResult {
    pub fn key(self) -> PublicEd25519 {
        self.key
    }

    pub fn challenge(self) -> Option<String> {
        self.challenge
    }
}

/// Verify the provided verifiable presentation against the current keypair.
///
/// See the `ErrorBag` documentation for more details on how to handle errors
/// that may occur during the validation process.
#[wasm_bindgen(js_name = "verifyPresentation")]
pub async fn js_verify_presentation(
    document: Object,
) -> Result<PresentationVerificationResult, JsError> {
    let presentation = serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify_presentation(&presentation).await?;

    Ok(PresentationVerificationResult {
        key: PublicEd25519(key),
        challenge: challenge.map(ToString::to_string),
    })
}

/// Wrapped JWK value.
#[wasm_bindgen]
pub struct JWK(InnerJWK);

#[wasm_bindgen]
impl JWK {
    /// Create a new wrapped JWK value from the provided JWK object.
    #[wasm_bindgen(constructor)]
    pub fn new(object: &Object) -> Result<JWK, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    /// Serialize the current wrapped JWK as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// Encoded W3C-compatible status list credential.
#[wasm_bindgen]
pub struct StatusListCredential(StatusList);

#[wasm_bindgen]
impl StatusListCredential {
    /// Create new StatusListCredential with all bits set to 0.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        StatusListCredential(StatusList::default())
    }

    /// Create new StatusListCredential from a credential subject object.
    #[wasm_bindgen(js_name = "fromCredentialSubject")]
    pub fn from_credential_subject(
        credential_subject: &Object,
    ) -> Result<StatusListCredential, JsError> {
        let credential: BitstringStatusListCredentialSubject =
            serde_wasm_bindgen::from_value(credential_subject.into())?;

        Ok(StatusListCredential(credential.encoded_list))
    }

    /// Check if a given index is revoked (bit set to 1).
    pub fn is_revoked(&self, idx: usize) -> bool {
        self.0.is_set(idx)
    }

    /// Revoke a given index (set bit to 1).
    pub fn revoke(&mut self, idx: usize) {
        self.0.set(idx);
    }

    /// Serialize the current status list as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(json!({
            "status_purpose": StatusPurpose::Revocation,
            "encoded_list": self.0,
        })
        .serialize(&OBJECT_SERIALIZER)?
        .into())
    }
}

impl Default for StatusListCredential {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct PresentationDefinition(InnerPresentationDefinition);

#[wasm_bindgen]
impl PresentationDefinition {
    /// Create a new presentation definition from the provided object.
    #[wasm_bindgen(constructor)]
    pub fn from_object(object: &Object) -> Result<PresentationDefinition, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    /// Validate the provided object against the presentation definition.
    pub fn validate(&self, object: &Object) -> Result<bool, JsError> {
        let value = serde_wasm_bindgen::from_value(object.into())?;
        Ok(self.0.validate(&value))
    }
}

#[wasm_bindgen]
pub struct Constraint(InnerConstraint);

#[wasm_bindgen]
impl Constraint {
    /// Create a new constraint from the provided object.
    #[wasm_bindgen(constructor)]
    pub fn from_object(object: &Object) -> Result<Constraint, JsError> {
        Ok(Self(serde_wasm_bindgen::from_value(object.into())?))
    }

    /// Validate the provided object against the constraint.
    pub fn validate(&self, object: &Object) -> Result<bool, JsError> {
        let value = serde_wasm_bindgen::from_value(object.into())?;
        Ok(self.0.validate(&value))
    }
}

/// Encrypt the provided payload for the provided recipient array.
///
/// The provided recipients array must contain only wrapped X25519 JWK values.
///
/// You may acquire X25519 JWK values using the `toX25519PublicJWK` method on the keypair structs.
#[wasm_bindgen]
pub fn encrypt(payload: Uint8Array, recipients: Vec<JWK>) -> Result<Object, JsError> {
    let jwe = teddybear_jwe::encrypt(
        &payload.to_vec(),
        &recipients.iter().map(|val| &val.0).collect::<Vec<_>>(),
    )?;

    Ok(jwe.serialize(&OBJECT_SERIALIZER)?.into())
}

#[cfg(test)]
mod tests {
    use js_sys::Uint8Array;
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::{encrypt, PrivateEd25519};

    #[wasm_bindgen_test]
    async fn encrypt_and_decrypt() {
        let key = PrivateEd25519::generate()
            .await
            .unwrap_or_else(|_| panic!());

        let encrypted = encrypt(
            Uint8Array::from(b"Hello, world".as_slice()),
            vec![key.to_x25519_public_jwk()],
        )
        .unwrap_or_else(|_| panic!());

        let decrypted = key.decrypt(encrypted).unwrap_or_else(|_| panic!());

        let mut buf = [0; 12];
        decrypted.copy_to(&mut buf);
        assert_eq!(buf.as_slice(), b"Hello, world");
    }
}
