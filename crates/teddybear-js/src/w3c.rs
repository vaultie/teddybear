use std::collections::HashMap;

use js_sys::Object;
use wasm_bindgen::prelude::*;

use teddybear_vc::{
    DIAny, VerifyOptions,
    ssi_json_ld::ContextLoader as InnerContextLoader,
    ssi_vc::v2::syntax::{JsonPresentation, SpecializedJsonCredential},
    status_list::StatusList,
    verify,
};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "W3CVerifyOptions")]
    pub type W3CVerifyOptions;
}

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
    challenge: Option<String>,
}

#[wasm_bindgen]
impl VerificationResult {
    #[wasm_bindgen(getter)]
    pub fn challenge(&self) -> Option<String> {
        self.challenge.clone()
    }
}

/// Bitstring status list credential subject.
///
/// @category W3C VC
#[wasm_bindgen]
pub struct BitstringStatusList(StatusList);

#[wasm_bindgen]
impl BitstringStatusList {
    #[wasm_bindgen(constructor)]
    pub fn new(credential_subject: Object) -> Result<Self, JsError> {
        let credential: teddybear_vc::status_list::BitstringStatusList =
            serde_wasm_bindgen::from_value(credential_subject.into())?;

        Ok(Self(credential.decode()?))
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        self.0.get(index)
    }
}

/// Verify the provided verifiable credential.
///
/// @category W3C VC
#[wasm_bindgen(js_name = "verifyCredential")]
pub async fn js_verify_credential(
    document: Object,
    context_loader: &mut ContextLoader,
    options: Option<W3CVerifyOptions>,
) -> Result<VerificationResult, JsError> {
    let credential: DIAny<SpecializedJsonCredential> =
        serde_wasm_bindgen::from_value(document.into())?;

    let options: VerifyOptions = options
        .map(Into::into)
        .map(serde_wasm_bindgen::from_value)
        .transpose()?
        .unwrap_or_default();

    let challenge = verify(&credential, &mut context_loader.0, options.cached_documents).await?;

    Ok(VerificationResult {
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
    options: Option<W3CVerifyOptions>,
) -> Result<VerificationResult, JsError> {
    let presentation: DIAny<JsonPresentation> = serde_wasm_bindgen::from_value(document.into())?;

    let options: VerifyOptions = options
        .map(Into::into)
        .map(serde_wasm_bindgen::from_value)
        .transpose()?
        .unwrap_or_default();

    let challenge = verify(
        &presentation,
        &mut context_loader.0,
        options.cached_documents,
    )
    .await?;

    Ok(VerificationResult {
        challenge: challenge.map(ToString::to_string),
    })
}
