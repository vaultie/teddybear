use std::io::Cursor;

use itertools::Itertools;
use js_sys::{Object, Uint8Array};
use serde::Serialize;
use teddybear_c2pa::{Ed25519Signer, Manifest, Reader, ValidationStatus};
use wasm_bindgen::prelude::*;

use crate::{ed25519::PrivateEd25519, OBJECT_SERIALIZER};

/// C2PA signing result.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PASignatureResult")]
pub struct C2paSignatureResult(Vec<u8>, Vec<u8>);

#[wasm_bindgen(js_class = "C2PASignatureResult")]
impl C2paSignatureResult {
    /// Payload with C2PA manifest embedded within.
    #[wasm_bindgen(getter, js_name = "signedPayload")]
    pub fn signed_payload(&self) -> Uint8Array {
        self.0.as_slice().into()
    }

    /// C2PA manifest value.
    #[wasm_bindgen(getter)]
    pub fn manifest(&self) -> Uint8Array {
        self.1.as_slice().into()
    }
}

/// C2PA signature builder.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PABuilder")]
pub struct C2paBuilder(Manifest);

#[wasm_bindgen(js_class = "C2PABuilder")]
impl C2paBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Manifest::default())
    }

    #[wasm_bindgen(js_name = "setManifestDefinition")]
    pub fn set_manifest_definition(mut self, definition: Object) -> Result<C2paBuilder, JsError> {
        self.0 = serde_wasm_bindgen::from_value(definition.into())?;
        Ok(self)
    }

    #[wasm_bindgen(js_name = "setThumbnail")]
    pub fn set_thumbnail(
        mut self,
        source: Uint8Array,
        format: &str,
    ) -> Result<C2paBuilder, JsError> {
        self.0.set_thumbnail(format, source.to_vec())?;
        Ok(self)
    }

    #[wasm_bindgen(js_name = "addVerifiableCredential")]
    pub fn add_verifiable_credential(mut self, credential: Object) -> Result<C2paBuilder, JsError> {
        let value: serde_json::Value = serde_wasm_bindgen::from_value(credential.into())?;
        self.0.add_verifiable_credential(&value)?;
        Ok(self)
    }

    pub async fn sign(
        mut self,
        key: &PrivateEd25519,
        certificates: Vec<Uint8Array>,
        source: Uint8Array,
        format: &str,
    ) -> Result<C2paSignatureResult, JsError> {
        let mut source = Cursor::new(source.to_vec());
        let mut dest = Cursor::new(Vec::new());

        let signer = Ed25519Signer::new(
            key.0.inner().clone(),
            certificates.into_iter().map(|val| val.to_vec()).collect(),
        );

        let manifest = self
            .0
            .embed_to_stream(format, &mut source, &mut dest, &signer)?;

        Ok(C2paSignatureResult(dest.into_inner(), manifest))
    }
}

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

/// C2PA signature verification result.
///
/// @category C2PA
#[wasm_bindgen(js_name = "C2PAVerificationResult")]
pub struct C2paVerificationResult {
    manifests: Vec<Object>,
    validation_errors: Vec<C2paValidationError>,
}

#[wasm_bindgen(js_class = "C2PAVerificationResult")]
impl C2paVerificationResult {
    /// Embedded C2PA manifests.
    #[wasm_bindgen(getter)]
    pub fn manifests(&self) -> Vec<Object> {
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
        .map(|manifest| manifest.serialize(&OBJECT_SERIALIZER))
        .map_ok(Into::into)
        .try_collect()?;

    Ok(C2paVerificationResult {
        manifests,
        validation_errors,
    })
}
