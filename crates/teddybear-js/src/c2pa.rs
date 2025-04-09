use std::io::Cursor;

use c2pa::{Reader, SignatureInfo, validation_status::ValidationStatus};
use itertools::Itertools;
use js_sys::{Object, Uint8Array};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::OBJECT_SERIALIZER;

/// C2PA validation error.
///
/// @category C2PA
#[derive(Clone)]
#[wasm_bindgen(js_name = "C2PAValidationError")]
pub struct C2paValidationError(ValidationStatus);

#[wasm_bindgen(js_class = "C2PAValidationError")]
impl C2paValidationError {
    /// Validation error code.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String {
        self.0.code().to_owned()
    }

    /// Related resource URL.
    #[wasm_bindgen(getter)]
    pub fn url(&self) -> Option<String> {
        self.0.url().map(ToOwned::to_owned)
    }

    /// Human-readable error explanation.
    #[wasm_bindgen(getter)]
    pub fn explanation(&self) -> Option<String> {
        self.0.explanation().map(ToOwned::to_owned)
    }

    /// Serialize the current error as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Result<Object, JsError> {
        Ok(self.0.serialize(&OBJECT_SERIALIZER)?.into())
    }
}

/// C2PA manifest information.
///
/// @category C2PA
#[derive(Clone)]
#[wasm_bindgen]
pub struct ManifestInfo {
    data: Object,
    signature_info: Option<SignatureInfo>,
}

#[wasm_bindgen]
impl ManifestInfo {
    #[wasm_bindgen(js_name = "certificateChain")]
    pub fn certificate_chain(&self) -> Option<String> {
        self.signature_info
            .as_ref()
            .map(|info| info.cert_chain().to_owned())
    }

    /// Serialize the current manifest as an object.
    #[wasm_bindgen(js_name = "toJSON")]
    pub fn to_json(&self) -> Object {
        self.data.clone()
    }
}

/// C2PA signature verification result.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PAVerificationResult")]
pub struct C2paVerificationResult {
    manifests: Vec<ManifestInfo>,
    validation_errors: Vec<C2paValidationError>,
}

#[wasm_bindgen(js_class = "C2PAVerificationResult")]
impl C2paVerificationResult {
    /// Embedded C2PA manifests.
    #[wasm_bindgen(getter)]
    pub fn manifests(&self) -> Vec<ManifestInfo> {
        self.manifests.clone()
    }

    /// Validation error code.
    #[wasm_bindgen(getter, js_name = "validationErrors")]
    pub fn validation_errors(&self) -> Vec<C2paValidationError> {
        self.validation_errors.clone()
    }
}

/// Verify C2PA signatures within a file.
///
/// @category C2PA
#[wasm_bindgen(js_name = "verifyC2PA")]
pub async fn verify_c2pa(
    source: Uint8Array,
    format: &str,
) -> Result<C2paVerificationResult, JsError> {
    let source = Cursor::new(source.to_vec());
    let reader = Reader::from_stream(format, source)?;

    let validation_errors = reader
        .validation_status()
        .unwrap_or(&[])
        .iter()
        .filter(|v| !v.passed())
        .map(|v| C2paValidationError(v.clone()))
        .collect();

    let manifests = reader
        .iter_manifests()
        .map(|manifest| {
            Ok::<_, JsError>(ManifestInfo {
                data: manifest.serialize(&OBJECT_SERIALIZER).map(Into::into)?,
                signature_info: manifest.signature_info().cloned(),
            })
        })
        .try_collect()?;

    Ok(C2paVerificationResult {
        manifests,
        validation_errors,
    })
}
