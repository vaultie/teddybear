use std::collections::HashMap;

use js_sys::Object;
use serde::Serialize;
use ssi_status::bitstring_status_list::{
    BitstringStatusList, StatusList, StatusPurpose, StatusSize, TimeToLive,
};
use teddybear_crypto::Ed25519VerificationKey2020;
use wasm_bindgen::prelude::*;

use teddybear_vc::{
    ssi_json_ld::ContextLoader as InnerContextLoader,
    ssi_vc::v2::syntax::{JsonPresentation, SpecializedJsonCredential},
    verify, DI,
};

use crate::{ed25519::PublicEd25519, OBJECT_SERIALIZER};

/// JSON-LD context loader.
///
/// @category W3C VC
#[wasm_bindgen]
pub struct ContextLoader(pub(crate) InnerContextLoader);

#[wasm_bindgen]
impl ContextLoader {
    #[wasm_bindgen(constructor)]
    pub fn new(contexts: Option<Object>) -> Result<ContextLoader, JsError> {
        let context_loader = InnerContextLoader::default();

        let contexts: Option<HashMap<String, String>> = contexts
            .map(|obj| serde_wasm_bindgen::from_value(obj.into()))
            .transpose()?;

        Ok(ContextLoader(if let Some(contexts) = contexts {
            context_loader.with_context_map_from(contexts)?
        } else {
            context_loader
        }))
    }
}

/// Verifiable presentation verification result.
///
/// @category W3C VC
#[wasm_bindgen]
pub struct VerificationResult {
    key: Ed25519VerificationKey2020,
    challenge: Option<String>,
}

#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> PublicEd25519 {
        PublicEd25519(self.key.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn challenge(&self) -> Option<String> {
        self.challenge.clone()
    }
}

/// Verify the provided verifiable credential.
///
/// @category W3C VC
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<VerificationResult, JsError> {
    let credential: DI<SpecializedJsonCredential> =
        serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify(&credential, &mut context_loader.0).await?;

    Ok(VerificationResult {
        key,
        challenge: challenge.map(ToString::to_string),
    })
}

/// Verify the provided verifiable presentation.
///
/// @category W3C VC
#[wasm_bindgen(js_name = "verifyPresentation")]
pub async fn js_verify_presentation(
    document: Object,
    context_loader: &mut ContextLoader,
) -> Result<VerificationResult, JsError> {
    let presentation: DI<JsonPresentation> = serde_wasm_bindgen::from_value(document.into())?;

    let (key, challenge) = verify(&presentation, &mut context_loader.0).await?;

    Ok(VerificationResult {
        key,
        challenge: challenge.map(ToString::to_string),
    })
}

/// Encoded W3C-compatible status list credential.
///
/// @category W3C VC
#[wasm_bindgen]
pub struct StatusListCredential(StatusList);

#[wasm_bindgen]
impl StatusListCredential {
    /// Create new StatusListCredential with all bits set to 0.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        StatusListCredential(StatusList::new(StatusSize::DEFAULT, TimeToLive::DEFAULT))
    }

    /// Create new StatusListCredential from a credential subject object.
    #[wasm_bindgen(js_name = "fromCredentialSubject")]
    pub fn from_credential_subject(
        credential_subject: &Object,
    ) -> Result<StatusListCredential, JsError> {
        let credential: BitstringStatusList =
            serde_wasm_bindgen::from_value(credential_subject.into())?;

        Ok(StatusListCredential(credential.decode()?))
    }

    #[wasm_bindgen]
    pub fn allocate(&mut self) -> Result<usize, JsError> {
        Ok(self.0.push(0)?)
    }

    /// Check if a given index is revoked (bit set to 1).
    #[wasm_bindgen(js_name = "isRevoked")]
    pub fn is_revoked(&self, idx: usize) -> bool {
        self.0.get(idx).map(|val| val == 1).unwrap_or(false)
    }

    /// Revoke a given index (set bit to 1).
    pub fn revoke(&mut self, idx: usize) -> Result<(), JsError> {
        self.0.set(idx, 1)?;
        Ok(())
    }

    /// Serialize the current status list as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self
            .0
            .to_credential_subject(None, StatusPurpose::Revocation, Vec::new())
            .serialize(&OBJECT_SERIALIZER)?
            .into())
    }
}
